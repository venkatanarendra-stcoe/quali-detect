import { buildPlatformKey, buildRateLimitKey } from "@qmentisai/shared";
import { hashKeyPart } from "../hash.js";

// Atomic fixed-window counter: INCR, set the expiry on the first hit (and repair a missing expiry), return count and ttl.
const CONSUME_SCRIPT = `
local current = redis.call("INCR", KEYS[1])
local ttl = redis.call("TTL", KEYS[1])
if current == 1 or ttl < 0 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return { current, ttl }
`;

/**
 * Fixed-window rate limiter on Redis. `subject` (user id, IP, API key id...) is hashed, so any string is safe.
 * Tenant limits require `tenantId`; pre-authentication limits (login attempts) use the explicit `consumeGlobal`.
 * Fixed windows allow up to 2x `limit` across a window boundary; use a stricter limit where that matters.
 * @param {{ redis: import("ioredis").Redis }} options
 */
export function createRateLimiter({ redis }) {
  async function consumeKey(key, { limit, windowSeconds }) {
    if (!Number.isInteger(limit) || limit < 1)
      throw new RangeError("limit must be a positive integer");
    if (!Number.isInteger(windowSeconds) || windowSeconds < 1)
      throw new RangeError("windowSeconds must be a positive integer");
    const [count, ttl] = await redis.eval(CONSUME_SCRIPT, 1, key, windowSeconds);
    return {
      allowed: count <= limit,
      limit,
      remaining: Math.max(limit - count, 0),
      resetSeconds: ttl,
    };
  }
  return Object.freeze({
    /**
     * Counts one hit.
     * @param {{ tenantId: string, bucket: string, subject: string, limit: number, windowSeconds: number }} options
     * @returns {Promise<{ allowed: boolean, limit: number, remaining: number, resetSeconds: number }>}
     */
    consume: (options) =>
      consumeKey(
        buildRateLimitKey({
          tenantId: options.tenantId,
          bucket: options.bucket,
          subject: hashKeyPart(options.subject),
        }),
        options,
      ),
    /** Counts one hit without a tenant (for example login attempts before the tenant is known). @param {{ bucket: string, subject: string, limit: number, windowSeconds: number }} options */
    consumeGlobal: (options) =>
      consumeKey(
        buildPlatformKey({
          namespace: "rl",
          parts: [options.bucket, hashKeyPart(options.subject)],
        }),
        options,
      ),
  });
}
