import { buildCacheKey, buildCachePrefix } from "@qmentisai/shared";

/**
 * Tenant-scoped JSON cache. There is no way to address a raw key: every operation takes a scope
 * `{ tenantId, namespace, id }` and the key is built by the shared tenant key builder, which throws when `tenantId`
 * is missing. Every entry has a TTL. Cache only non-secret, re-derivable data; PostgreSQL stays the source of truth.
 * @param {{ redis: import("ioredis").Redis, defaultTtlSeconds?: number, maxTtlSeconds?: number }} options
 */
export function createCache({ redis, defaultTtlSeconds = 300, maxTtlSeconds = 86400 }) {
  const resolveTtl = (ttlSeconds) => {
    const ttl = ttlSeconds ?? defaultTtlSeconds;
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > maxTtlSeconds)
      throw new RangeError(`ttlSeconds must be an integer between 1 and ${maxTtlSeconds}`);
    return ttl;
  };

  const cache = {
    /**
     * @param {{ tenantId: string, namespace: string, id: string | number }} scope
     * @returns {Promise<unknown>} the cached value, or `undefined` on a miss.
     */
    async get(scope) {
      const key = buildCacheKey(scope);
      const raw = await redis.get(key);
      if (raw === null) return undefined;
      try {
        return JSON.parse(raw);
      } catch {
        await redis.del(key); // corrupt entry: treat as a miss
        return undefined;
      }
    },
    /**
     * @param {{ tenantId: string, namespace: string, id: string | number }} scope
     * @param {unknown} value JSON-serializable, not `undefined`.
     * @param {{ ttlSeconds?: number }} [options]
     */
    async set(scope, value, { ttlSeconds } = {}) {
      if (value === undefined) throw new TypeError("Cannot cache undefined");
      await redis.set(buildCacheKey(scope), JSON.stringify(value), "EX", resolveTtl(ttlSeconds));
    },
    /** @param {{ tenantId: string, namespace: string, id: string | number }} scope */
    async del(scope) {
      return redis.del(buildCacheKey(scope));
    },
    /**
     * Returns the cached value or computes, stores and returns it.
     * @template T
     * @param {{ tenantId: string, namespace: string, id: string | number }} scope
     * @param {() => Promise<T>} loader
     * @param {{ ttlSeconds?: number }} [options]
     * @returns {Promise<T>}
     */
    async getOrSet(scope, loader, options) {
      const cached = await cache.get(scope);
      if (cached !== undefined) return /** @type {T} */ (cached);
      const value = await loader();
      await cache.set(scope, value, options);
      return value;
    },
    /**
     * Deletes every entry of one tenant namespace (SCAN + UNLINK; never touches other tenants).
     * @param {{ tenantId: string, namespace: string }} scope
     * @returns {Promise<number>} number of keys removed
     */
    async invalidateNamespace(scope) {
      const prefix = buildCachePrefix(scope);
      let removed = 0;
      let cursor = "0";
      do {
        const [next, keys] = await redis.scan(cursor, "MATCH", `${prefix}*`, "COUNT", 200);
        cursor = next;
        if (keys.length > 0) removed += await redis.unlink(...keys);
      } while (cursor !== "0");
      return removed;
    },
  };
  return Object.freeze(cache);
}
