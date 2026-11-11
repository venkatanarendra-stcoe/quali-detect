import { disconnectDbClient, getDbClient, pingDatabase } from "@qmentisai/db";
import {
  closeRedis,
  createCache,
  createLockManager,
  createPublisher,
  createRabbitConnection,
  createRateLimiter,
  createRedisClient,
  pingRedis,
} from "@qmentisai/infra";

/**
 * Connects the infrastructure that is configured and returns `{ infra, close }`.
 * `infra` = `{ db, redis, cache, locks, rateLimiter, publisher }` (an entry is `null` when its URL is not configured).
 * Connections are lazy; each registers a readiness check (/ready). `close()` shuts them down in reverse dependency order
 * (RabbitMQ publisher and connection, Redis, Prisma) and never throws, so a failing close cannot hide the others.
 * Tenant rules: the cache, locks and rate limiter require `tenantId` on every call; the publisher validates the job envelope.
 * @param {{ config: any, logger: import("pino").Logger, readiness: ReturnType<typeof import("./readiness.js").createReadiness> }} deps
 */
export function createInfrastructure({ config, logger, readiness }) {
  const { databaseUrl, redisUrl, rabbitmqUrl } = config.infra;
  const infra = {
    db: null,
    redis: null,
    cache: null,
    locks: null,
    rateLimiter: null,
    publisher: null,
  };
  /** @type {Array<{ name: string, close: () => Promise<unknown> }>} */
  const closers = [];

  if (databaseUrl) {
    infra.db = getDbClient({ datasourceUrl: databaseUrl });
    readiness.register("database", () => pingDatabase(infra.db));
    closers.push({ name: "database", close: async () => disconnectDbClient() });
  }
  if (redisUrl) {
    const redis = createRedisClient({ url: redisUrl, name: "qmentisai-api", logger });
    Object.assign(infra, {
      redis,
      cache: createCache({ redis }),
      locks: createLockManager({ redis }),
      rateLimiter: createRateLimiter({ redis }),
    });
    readiness.register("redis", () => pingRedis(redis));
    closers.push({ name: "redis", close: async () => closeRedis(redis) });
  }
  if (rabbitmqUrl) {
    const connection = createRabbitConnection({ url: rabbitmqUrl, logger, connectAttempts: 1 });
    infra.publisher = createPublisher({ connection, logger });
    readiness.register("rabbitmq", () => connection.ping());
    closers.push({
      name: "rabbitmq",
      close: async () => {
        await infra.publisher.close();
        await connection.close();
      },
    });
  }

  return {
    infra: Object.freeze(infra),
    /** Closes RabbitMQ, then Redis, then Prisma (the reverse of the order they were opened in). */
    async close() {
      for (const { name, close } of closers.reverse()) {
        try {
          await close();
        } catch (error) {
          logger.error({ err: error, resource: name }, "Failed to close resource");
        }
      }
    },
  };
}
