import { createHash } from "node:crypto";
import { createCache, createRedisClient, closeRedis } from "@qmentisai/infra";
import { REPORTING_CACHE_PREFIX, buildTenantKey } from "@qmentisai/shared";

/**
 * The tenant-scoped read cache of the reporting API (docs/modules/reporting-dashboards/SPEC.md 7.1, 17 D-4, RPT-014).
 *
 *  - Entries go through `createCache` (namespace `rpt`): the key is `qmentis:t:<tenant>:cache:rpt:<workspace>.<metric>.<epoch>.<paramsHash>`,
 *    so a tenant, a workspace, a metric and the validated parameters can never share an entry, and the tenant segment comes from the
 *    caller's SESSION. A value is the finished DTO plus its `meta`; nothing secret and nothing tenant-crossing is ever cached.
 *  - The EPOCH is a Redis counter per (tenant, workspace), incremented by the API's handler of the `finding.changed` hint
 *    ({@link createReportingEpochBumper}); it is read BEFORE the key is built, so one `INCR` invalidates every live key of that workspace
 *    without scanning. Live entries live 30 s, rollup entries 300 s.
 *  - Redis unavailable (no URL, an error, a slow answer) means the request is served UNCACHED: a cache problem never fails a request,
 *    and an unreadable epoch means no cache at all (never a stale hit under a guessed epoch).
 */

export const REPORTING_CACHE_NAMESPACE = REPORTING_CACHE_PREFIX;
/** The workspace segment of tenant-wide entries (the overview). */
export const TENANT_WIDE = "tenant";
const EPOCH_NAMESPACE = "rptepoch";
/** The epoch key outlives every entry (300 s at most) by a wide margin. */
const EPOCH_TTL_SECONDS = 7 * 24 * 3600;
const REDIS_TIMEOUT_MS = 500;
const KEY = Symbol.for("qmentisai.reporting.read.cache");

/** @param {string} tenantId @param {string} workspaceId */
const epochKey = (tenantId, workspaceId) =>
  buildTenantKey({ tenantId, namespace: EPOCH_NAMESPACE, parts: [workspaceId] });

/** Rejects after `ms` so a hanging Redis cannot hold a request. @template T @param {Promise<T>} promise @param {number} [ms] */
function within(promise, ms = REDIS_TIMEOUT_MS) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error("redis timeout")), ms);
    timer.unref?.();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Canonical (key-sorted) JSON, so equal parameters hash equally in any key order.
 * @param {unknown} value
 */
function canonical(value) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === "object")
      return Object.fromEntries(
        Object.keys(v)
          .sort()
          .map((k) => [k, sort(v[k])]),
      );
    return v;
  };
  return JSON.stringify(sort(JSON.parse(JSON.stringify(value ?? null))));
}

/** @param {unknown} params @returns {string} 24 hex characters */
export const hashParams = (params) =>
  createHash("sha256").update(canonical(params)).digest("hex").slice(0, 24);

/**
 * @param {{ redis: import("ioredis").Redis | null, log?: import("pino").Logger }} deps
 */
export function createReportingReadCache({ redis, log }) {
  const cache = redis ? createCache({ redis, defaultTtlSeconds: 30, maxTtlSeconds: 600 }) : null;
  const warn = (error, what) => log?.warn?.({ err: error, what }, "reporting cache unavailable");
  const stats = { hits: 0, misses: 0, bypassed: 0 };

  /** The current epoch, or null when it cannot be read. */
  async function readEpoch(tenantId, workspaceId) {
    if (!redis) return null;
    try {
      const raw = await within(redis.get(epochKey(tenantId, workspaceId)));
      const n = raw === null ? 0 : Number(raw);
      return Number.isSafeInteger(n) && n >= 0 ? n : null;
    } catch (error) {
      warn(error, "epoch");
      return null;
    }
  }

  return Object.freeze({
    stats,
    readEpoch,
    /**
     * Returns the cached `{ data, meta }` or computes, stores and returns it. `load` errors propagate (nothing is cached for them).
     * @template T
     * @param {{ tenantId: string, workspaceId: string, metric: string, params: unknown, ttlSeconds: number }} key
     * @param {() => Promise<T>} load
     * @returns {Promise<T>}
     */
    async wrap({ tenantId, workspaceId, metric, params, ttlSeconds }, load) {
      const epoch = cache ? await readEpoch(tenantId, workspaceId) : null; // BEFORE the key is built
      if (epoch === null) {
        stats.bypassed += 1;
        return load();
      }
      const scope = {
        tenantId,
        namespace: REPORTING_CACHE_NAMESPACE,
        id: `${workspaceId}.${metric}.${epoch}.${hashParams(params)}`,
      };
      try {
        const hit = await within(cache.get(scope));
        if (hit !== undefined) {
          stats.hits += 1;
          return /** @type {T} */ (hit);
        }
      } catch (error) {
        warn(error, "get");
      }
      stats.misses += 1;
      const value = await load();
      try {
        await within(cache.set(scope, value, { ttlSeconds }));
      } catch (error) {
        warn(error, "set");
      }
      return value;
    },
  });
}

/**
 * The reporting read cache of the running application: a dedicated lazy Redis connection (`config.infra.redisUrl`), created on first use and
 * only while the module is on; `config.reporting.cacheRedis` is a test seam (an injected client). With no URL the cache is a pass-through.
 * @param {{ config: any, log: import("pino").Logger }} deps
 */
export function getReportingReadCache({ config, log }) {
  if (config?.reporting && Object.hasOwn(config.reporting, "cacheRedis"))
    return createReportingReadCache({ redis: config.reporting.cacheRedis ?? null, log });
  if (globalThis[KEY]?.cache) return globalThis[KEY].cache;
  const url = config?.infra?.redisUrl ?? null;
  const redis = url
    ? createRedisClient({ url, name: "qmentisai-reporting-cache", logger: log })
    : null;
  const cache = createReportingReadCache({ redis, log });
  globalThis[KEY] = { cache, redis };
  return cache;
}

/** Closes the cache connection (the application's close hook calls it next to `disconnectReportingReadClient`). */
export async function disconnectReportingReadCache() {
  const redis = globalThis[KEY]?.redis;
  delete globalThis[KEY];
  if (redis) await closeRedis(redis);
}

/**
 * The handler the API runs for a verified `finding.changed` hint: increments the epoch of the finding's (tenant, workspace) and of the
 * tenant-wide overview. The target comes from the database row of the verified message, never from a client string. A failure is logged and
 * swallowed (the entries expire by TTL within 30 seconds at the latest).
 * @param {{ redis: import("ioredis").Redis | null, enabled: boolean, log?: import("pino").Logger }} deps
 * @returns {(target: { tenantId: string, workspaceId: string }) => Promise<void>}
 */
export function createReportingEpochBumper({ redis, enabled, log }) {
  return async function bump({ tenantId, workspaceId }) {
    if (!enabled || !redis) return;
    try {
      const a = epochKey(tenantId, workspaceId);
      const b = epochKey(tenantId, TENANT_WIDE);
      await within(
        redis
          .multi()
          .incr(a)
          .expire(a, EPOCH_TTL_SECONDS)
          .incr(b)
          .expire(b, EPOCH_TTL_SECONDS)
          .exec(),
      );
    } catch (error) {
      log?.warn?.({ err: error }, "reporting cache epoch could not be bumped");
    }
  };
}

/**
 * Invalidates every cached reporting read of a tenant (the time-zone change: the cached days were bucketed in the old zone). It bumps the
 * epoch of each of the tenant's workspaces and of the tenant-wide overview through {@link createReportingEpochBumper} (the keys are built
 * there only). The Redis client is the one of the read cache (the same lazy connection, or the injected test seam); with no Redis the
 * entries expire by TTL (5 minutes at most) and nothing fails.
 * @param {{ config: any, log?: import("pino").Logger, tenantId: string, workspaceIds: readonly string[] }} input
 */
export async function bumpTenantReportingEpochs({ config, log, tenantId, workspaceIds }) {
  let redis = null;
  if (config?.reporting && Object.hasOwn(config.reporting, "cacheRedis"))
    redis = config.reporting.cacheRedis ?? null;
  else if (config?.reporting?.enabled === true && log) {
    getReportingReadCache({ config, log }); // creates the shared lazy connection when it does not exist yet
    redis = globalThis[KEY]?.redis ?? null;
  }
  const bump = createReportingEpochBumper({
    redis,
    enabled: config?.reporting?.enabled === true,
    log,
  });
  for (const workspaceId of workspaceIds.length > 0 ? workspaceIds : [TENANT_WIDE])
    await bump({ tenantId, workspaceId });
}
