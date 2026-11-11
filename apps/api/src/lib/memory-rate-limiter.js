/**
 * Per-process fixed-window limiter with the same `consumeGlobal` shape as the Redis limiter. Used for login throttling only
 * when Redis is not configured (development); production requires Redis, so limits are shared across API instances.
 * @param {{ now?: () => number }} [options]
 */
export function createMemoryRateLimiter({ now = Date.now } = {}) {
  const windows = new Map();
  return Object.freeze({
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
