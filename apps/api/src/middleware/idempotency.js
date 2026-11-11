import { createHash } from "node:crypto";
import { ERROR_CODES } from "@qmentisai/contracts";
import { buildIdempotencyKey, buildPlatformKey } from "@qmentisai/shared";
import { AppError, ValidationError } from "../errors/app-error.js";

export const IDEMPOTENCY_HEADER = "Idempotency-Key";
const KEY_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;
const IN_PROGRESS_TTL_SECONDS = 120;

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
/** JSON with sorted keys, so the same request always has the same fingerprint. */
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`)
      .join(",")}}`;
  return JSON.stringify(value) ?? "null";
}

/** In-process store for development without Redis (not shared across instances). */
function createMemoryStore() {
  const entries = new Map();
  const alive = (key) => {
    const entry = entries.get(key);
    if (entry && entry.expiresAt <= Date.now()) entries.delete(key);
    return entries.get(key);
  };
  return {
    async setIfAbsent(key, value, ttl) {
      if (alive(key)) return false;
      entries.set(key, { value, expiresAt: Date.now() + ttl * 1000 });
      return true;
    },
    async get(key) {
      return alive(key)?.value ?? null;
    },
    async set(key, value, ttl) {
      entries.set(key, { value, expiresAt: Date.now() + ttl * 1000 });
    },
    async delete(key) {
      entries.delete(key);
    },
  };
}

function createRedisStore(redis) {
  return {
    async setIfAbsent(key, value, ttl) {
      return (await redis.set(key, JSON.stringify(value), "EX", ttl, "NX")) === "OK";
    },
    async get(key) {
      const raw = await redis.get(key);
      return raw ? JSON.parse(raw) : null;
    },
    async set(key, value, ttl) {
      await redis.set(key, JSON.stringify(value), "EX", ttl);
    },
    async delete(key) {
      await redis.del(key);
    },
  };
}

/**
 * `Idempotency-Key` for mutating endpoints that create resources or trigger side effects (a route opts in with
 * `idempotent: true`). The header is optional; when present:
 * - the key is scoped by TENANT + ACTOR + ROUTE (`tenantId`, user id, method and path pattern), so the same key used by
 *   another tenant, another user or on another route is a different key and can never replay someone else's response;
 * - the first request stores an "in progress" marker; a concurrent request with the same key is refused
 *   (`409 IDEMPOTENCY_CONFLICT`, `details.reason: "in_progress"`);
 * - a successful (2xx) response is stored for `IDEMPOTENCY_TTL_SECONDS` and replayed for later requests with the same key
 *   and the same request (status and body as stored, `Idempotent-Replayed: true`, current correlation id);
 * - the same key with a different request (params, query or body) is `409 IDEMPOTENCY_CONFLICT`
 *   (`details.reason: "different_request"`);
 * - failures (non-2xx) are not stored: the client may retry with the same key.
 * Redis-backed; in-process fallback without Redis (development only). Runs after authentication, validation and
 * authorization, so refused requests never consume or reveal a key.
 * @param {{ config: any, infra: { redis: any }, logger?: import("pino").Logger }} deps
 */
export function createIdempotency({ config, infra, logger }) {
  const store = infra.redis ? createRedisStore(infra.redis) : createMemoryStore();
  if (!infra.redis)
    logger?.warn("Redis is not configured: Idempotency-Key is per process (development only)");
  const ttl = config.http.idempotencyTtlSeconds;

  /** @param {string} routeId e.g. "POST /api/v1/workspaces" */
  function forRoute(routeId) {
    const routeHash = sha256(routeId).slice(0, 16);
    return async function idempotencyMiddleware(req, res, next) {
      const header = req.get(IDEMPOTENCY_HEADER);
      if (header === undefined) return next();
      if (!KEY_PATTERN.test(header))
        throw new ValidationError(
          [
            {
              path: IDEMPOTENCY_HEADER,
              code: "invalid_string",
              message: "Use 8-128 characters from A-Z a-z 0-9 . _ : -",
            },
          ],
          { source: "headers" },
        );
      const { principal } = req;
      const keyPart = sha256(header).slice(0, 32);
      const key = principal?.tenant
        ? buildIdempotencyKey({
            tenantId: principal.tenant.id,
            scope: `http.${principal.user.id}.${routeHash}`,
            key: keyPart,
          })
        : principal?.platform
          ? buildPlatformKey({
              namespace: "idem",
              parts: [principal.platform.platformUser.id, routeHash, keyPart],
            })
          : null;
      if (!key) return next(); // only authenticated, scoped callers can use keys
      const fingerprint = sha256(stableStringify([routeId, req.params, req.query, req.body]));

      const claimed = await store.setIfAbsent(
        key,
        { state: "in_progress", fingerprint },
        IN_PROGRESS_TTL_SECONDS,
      );
      if (!claimed) {
        const existing = await store.get(key);
        if (existing && existing.fingerprint !== fingerprint)
          throw new AppError(
            ERROR_CODES.IDEMPOTENCY_CONFLICT,
            "This Idempotency-Key was already used with a different request.",
            { details: { reason: "different_request" } },
          );
        if (!existing || existing.state === "in_progress")
          throw new AppError(
            ERROR_CODES.IDEMPOTENCY_CONFLICT,
            "A request with this Idempotency-Key is still being processed.",
            { details: { reason: "in_progress", retryAfterSeconds: 1 } },
          );
        res.set("Idempotent-Replayed", "true");
        res.status(existing.status);
        return res.json({
          ...existing.body,
          meta: { ...existing.body.meta, correlationId: req.id },
        });
      }

      // First request: capture a successful response so it can be replayed; release the key on any failure.
      const send = res.json.bind(res);
      res.json = (body) => {
        const status = res.statusCode;
        const save =
          status >= 200 && status < 300
            ? store.set(key, { state: "done", fingerprint, status, body }, ttl)
            : store.delete(key);
        save.catch((error) =>
          logger?.warn({ err: error }, "Could not update the idempotency record"),
        );
        return send(body);
      };
      res.on("close", () => {
        if (!res.writableFinished) store.delete(key).catch(() => {});
      });
      next();
    };
  }
  return Object.freeze({ forRoute });
}
