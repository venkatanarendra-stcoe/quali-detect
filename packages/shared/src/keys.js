/**
 * Tenant-scoped key and room builders (Redis keys, locks, rate limits, idempotency, Socket.IO rooms).
 * Rule (docs/architecture/TENANT_ISOLATION.md): tenant-owned data is always addressed through a key that starts with the
 * tenant. Every tenant-scoped builder REQUIRES a valid `tenantId` and throws when it is missing, so code cannot build an
 * unscoped key by accident. Platform-owned data uses the explicit `buildPlatformKey`.
 *
 * Segments are restricted to `A-Z a-z 0-9 . _ -` (no ":", whitespace or glob characters), so a value can never escape its
 * position in the key or inject a Redis glob pattern. Hash anything else (emails, IPs) before using it as a segment.
 */

export const KEY_ROOT = "qmentis";
const SEGMENT = /^[A-Za-z0-9._-]{1,128}$/;
/** Pattern that safe identifiers (tenant, workspace, ... ids) must match. */
export const SAFE_ID_PATTERN = SEGMENT;

/**
 * @param {string} name Segment label used in the error message.
 * @param {unknown} value
 * @returns {string}
 */
function segment(name, value) {
  if (typeof value !== "string" || !SEGMENT.test(value)) {
    throw new TypeError(
      `Invalid key segment "${name}": expected 1-128 characters from A-Z a-z 0-9 . _ -`,
    );
  }
  return value;
}

/**
 * Validates and returns a tenant id. Throws `TypeError` when missing or unsafe.
 * @param {unknown} tenantId
 * @returns {string}
 */
export function requireTenantId(tenantId) {
  return segment("tenantId", tenantId);
}

/**
 * Builds `qmentis:t:<tenantId>:<namespace>[:<part>...]`.
 * @param {{ tenantId: string, namespace: string, parts?: ReadonlyArray<string | number> }} input
 * @returns {string}
 */
export function buildTenantKey({ tenantId, namespace, parts = [] }) {
  return [
    KEY_ROOT,
    "t",
    requireTenantId(tenantId),
    segment("namespace", namespace),
    ...parts.map((part, index) => segment(`parts[${index}]`, String(part))),
  ].join(":");
}

/**
 * Key prefix (with trailing ":") for all keys of a tenant namespace, for SCAN-based invalidation.
 * @param {{ tenantId: string, namespace: string, parts?: ReadonlyArray<string | number> }} input
 */
export function buildTenantPrefix(input) {
  return `${buildTenantKey(input)}:`;
}

/**
 * Cache key: `qmentis:t:<tenantId>:cache:<namespace>:<id>`.
 * @param {{ tenantId: string, namespace: string, id: string | number }} input
 */
export const buildCacheKey = ({ tenantId, namespace, id }) =>
  buildTenantKey({ tenantId, namespace: "cache", parts: [namespace, id] });

/** Prefix of every cache key of one namespace for a tenant. @param {{ tenantId: string, namespace: string }} input */
export const buildCachePrefix = ({ tenantId, namespace }) =>
  buildTenantPrefix({ tenantId, namespace: "cache", parts: [namespace] });

/** Distributed lock key. @param {{ tenantId: string, resource: string }} input */
export const buildLockKey = ({ tenantId, resource }) =>
  buildTenantKey({ tenantId, namespace: "lock", parts: [resource] });

/** Rate-limit counter key. @param {{ tenantId: string, bucket: string, subject: string }} input */
export const buildRateLimitKey = ({ tenantId, bucket, subject }) =>
  buildTenantKey({ tenantId, namespace: "rl", parts: [bucket, subject] });

/** Message idempotency key. @param {{ tenantId: string, scope: string, key: string }} input */
export const buildIdempotencyKey = ({ tenantId, scope, key }) =>
  buildTenantKey({ tenantId, namespace: "idem", parts: [scope, key] });

/**
 * Key for PLATFORM-owned data only (not tenant data): `qmentis:p:<namespace>[:<part>...]`. Never use it to
 * store tenant-owned values.
 * @param {{ namespace: string, parts?: ReadonlyArray<string | number> }} input
 */
export function buildPlatformKey({ namespace, parts = [] }) {
  return [
    KEY_ROOT,
    "p",
    segment("namespace", namespace),
    ...parts.map((part, index) => segment(`parts[${index}]`, String(part))),
  ].join(":");
}

/**
 * Socket.IO room name scoped to a tenant (and optionally a workspace): `t:<tenantId>` or `t:<tenantId>:w:<workspaceId>`.
 * @param {{ tenantId: string, workspaceId?: string }} input
 */
export function buildTenantRoom({ tenantId, workspaceId }) {
  const base = `t:${requireTenantId(tenantId)}`;
  return workspaceId === undefined ? base : `${base}:w:${segment("workspaceId", workspaceId)}`;
}
