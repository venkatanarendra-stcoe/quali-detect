import { assertDelayPolicy, capReachedAtFailure, progressiveDelaySeconds } from "@qmentisai/infra";

/**
 * Per-process limiter with the same `consumeGlobal`, `blockedFor`, `recordFailure` and `clearFailures` shape as the Redis limiter. Used for login throttling only
 * when Redis is not configured (development); production requires Redis, so limits are shared across API instances.
 * @param {{ now?: () => number }} [options]
 */
export function createMemoryRateLimiter({ now = Date.now } = {}) {
  const windows = new Map();
  const failures = new Map(); // key -> { count, expiresAt }
  const blocks = new Map(); // key -> until (ms)
  const key = (bucket, subject) => `${bucket}:${subject}`;
  return Object.freeze({
    /** @param {{ bucket: string, subject: string }} options */
    async blockedFor({ bucket, subject }) {
      const until = blocks.get(key(bucket, subject)) ?? 0;
      return Math.max(Math.ceil((until - now()) / 1000), 0);
    },
    /** @param {{ bucket: string, subject: string, freeAttempts: number, baseDelaySeconds: number, capSeconds: number, decaySeconds: number }} options */
    async recordFailure(options) {
      assertDelayPolicy(options);
      const k = key(options.bucket, options.subject);
      const at = now();
      const previous = failures.get(k);
      const count = previous && previous.expiresAt > at ? previous.count + 1 : 1;
      failures.set(k, { count, expiresAt: at + options.decaySeconds * 1000 });
      const delaySeconds = progressiveDelaySeconds(count, options);
      if (delaySeconds > 0) blocks.set(k, at + delaySeconds * 1000);
      return { failures: count, delaySeconds, capReached: count === capReachedAtFailure(options) };
    },
    /** @param {{ bucket: string, subject: string }} options */
    async clearFailures({ bucket, subject }) {
      failures.delete(key(bucket, subject));
      blocks.delete(key(bucket, subject));
    },
    /** @param {{ bucket: string, subject: string, limit: number, windowSeconds: number }} options */
    async consumeGlobal({ bucket, subject, limit, windowSeconds }) {
      const key = `${bucket}:${subject}`;
      const at = now();
      for (const [k, w] of windows) if (w.resetAt <= at) windows.delete(k);
      const current = windows.get(key) ?? { count: 0, resetAt: at + windowSeconds * 1000 };
      current.count += 1;
      windows.set(key, current);
      return {
        allowed: current.count <= limit,
        limit,
        remaining: Math.max(limit - current.count, 0),
        resetSeconds: Math.ceil((current.resetAt - at) / 1000),
      };
    },
  });
}
