import { Redis } from "ioredis";
import { childLogger } from "../logging.js";

/**
 * Creates a Redis client (connects lazily on first command). Commands fail fast instead of queueing forever when Redis
 * is down. Connection errors are logged without the URL (it may contain credentials).
 * @param {{ url: string, name?: string, logger?: object }} options
 * @returns {import("ioredis").Redis}
 */
export function createRedisClient({ url, name = "qmentisai", logger }) {
  const log = childLogger(logger, { component: "redis" });
  const redis = new Redis(url, {
    lazyConnect: true,
    connectionName: name,
    maxRetriesPerRequest: 2,
    enableOfflineQueue: false,
    retryStrategy: (times) => Math.min(times * 200, 2000),
  });
  redis.on("error", (error) => log.warn({ err: error }, "Redis connection error"));
  return redis;
}

/**
 * Readiness probe: resolves when Redis answers PING (connects first if needed).
 * @param {import("ioredis").Redis} redis
 */
export async function pingRedis(redis) {
  if (redis.status === "wait" || redis.status === "end") await redis.connect();
  const reply = await redis.ping();
  if (reply !== "PONG") throw new Error("Unexpected Redis PING reply");
}

/** Closes the connection gracefully. @param {import("ioredis").Redis} redis */
export async function closeRedis(redis) {
  if (redis.status === "end") return;
  try {
    await redis.quit();
  } catch {
    redis.disconnect();
  }
}
