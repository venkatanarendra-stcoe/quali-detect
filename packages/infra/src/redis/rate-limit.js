import { buildPlatformKey, buildRateLimitKey } from "@qmentisai/shared";
import { hashKeyPart } from "../hash.js";
import { assertDelayPolicy, capReachedAtFailure, progressiveDelaySeconds } from "./progressive.js";

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

// Counts a failure and (re)arms the decay expiry; the count survives as long as failures keep arriving within `decay`.
const FAILURE_SCRIPT = `
local current = redis.call("INCR", KEYS[1])
redis.call("EXPIRE", KEYS[1], ARGV[1])
return current
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
  const failureKeys = (bucket, subject) => ({
    failures: buildPlatformKey({ namespace: "rl", parts: [`pf-${bucket}`, hashKeyPart(subject)] }),
    block: buildPlatformKey({ namespace: "rl", parts: [`pb-${bucket}`, hashKeyPart(subject)] }),
  });
  return Object.freeze({
    /**
     * Seconds the subject must still wait before its next attempt is evaluated (0 when it may proceed). Read-only:
     * checking never extends a wait. `subject` is hashed, so it can be an e-mail address or an IP.
     * @param {{ bucket: string, subject: string }} options
     */
    async blockedFor({ bucket, subject }) {
      const ttl = await redis.ttl(failureKeys(bucket, subject).block);
      return ttl > 0 ? ttl : 0;
    },
    /**
     * Records one evaluated failure and arms the wait for the next attempt (progressive, capped, no hard lock).
     * @param {{ bucket: string, subject: string, freeAttempts: number, baseDelaySeconds: number, capSeconds: number, decaySeconds: number }} options
     * @returns {Promise<{ failures: number, delaySeconds: number, capReached: boolean }>}
     */
    async recordFailure(options) {
      assertDelayPolicy(options);
      const keys = failureKeys(options.bucket, options.subject);
      const failures = Number(
        await redis.eval(FAILURE_SCRIPT, 1, keys.failures, options.decaySeconds),
      );
      const delaySeconds = progressiveDelaySeconds(failures, options);
      if (delaySeconds > 0) await redis.set(keys.block, "1", "EX", delaySeconds);
      return { failures, delaySeconds, capReached: failures === capReachedAtFailure(options) };
    },
    /** Forgets the subject's failures (after a successful sign-in or verification). @param {{ bucket: string, subject: string }} options */
    async clearFailures({ bucket, subject }) {
      const keys = failureKeys(bucket, subject);
      await redis.del(keys.failures, keys.block);
    },
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
