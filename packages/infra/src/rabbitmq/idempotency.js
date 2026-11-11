import { buildIdempotencyKey } from "@qmentisai/shared";

/**
 * Redis-backed idempotency store for message handlers. `begin` claims a key: "new" (go ahead), "processing" (another
 * delivery is running it) or "done" (already completed: skip). `complete` marks it done for `doneTtlSeconds`; `release`
 * frees the claim after a failure so a retry can run. A crashed handler's claim expires after `processingTtlSeconds`.
 * Keys are tenant-scoped.
 * @param {{ redis: import("ioredis").Redis, processingTtlSeconds?: number, doneTtlSeconds?: number }} options
 */
export function createRedisIdempotencyStore({
  redis,
  processingTtlSeconds = 900,
  doneTtlSeconds = 86400,
}) {
  return Object.freeze({
    /** @param {{ tenantId: string, scope: string, key: string }} input @returns {Promise<"new" | "processing" | "done">} */
    async begin(input) {
      const key = buildIdempotencyKey(input);
      if ((await redis.set(key, "processing", "EX", processingTtlSeconds, "NX")) === "OK")
        return "new";
      return (await redis.get(key)) === "done" ? "done" : "processing";
    },
    /** @param {{ tenantId: string, scope: string, key: string }} input */
    async complete(input) {
      await redis.set(buildIdempotencyKey(input), "done", "EX", doneTtlSeconds);
    },
    /** @param {{ tenantId: string, scope: string, key: string }} input */
    async release(input) {
      await redis.del(buildIdempotencyKey(input));
    },
  });
}
