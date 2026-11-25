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
 * `infra` = `{ db, redis, cache, locks, rateLimiter, publisher, rabbit }` (`rabbit` is the shared connection, for the realtime consumer) (an entry is `null` when its URL is not configured).
 * Connections are lazy; each registers a readiness check (/ready). `close()` shuts them down in reverse dependency order
 * (RabbitMQ publisher and connection, Redis, Prisma) and never throws, so a failing close cannot hide the others.
 * Tenant rules: the cache, locks and rate limiter require `tenantId` on every call; the publisher validates the job envelope.
 * B4 of the E2E run: the Redis client is lazy and has no offline queue, so until something connected it every command failed with "Stream isn't
 * writeable" (the first login or webhook after a boot answered 500 until `GET /ready` happened to ping it). The connection now STARTS at once and
 * `ready()` waits for it, at most `redisStartupMs`: the API does not listen before its Redis answered (or the wait ran out, which is logged and
 * leaves readiness to report it; the client keeps reconnecting by its own retry strategy).
 * @param {{ config: any, logger: import("pino").Logger, readiness: ReturnType<typeof import("./readiness.js").createReadiness>,
 *           redisFactory?: typeof createRedisClient, redisStartupMs?: number }} deps
 */
export function createInfrastructure({
  config,
  logger,
  readiness,
  redisFactory = createRedisClient,
  redisStartupMs = 5000,
}) {
  const { databaseUrl, redisUrl, rabbitmqUrl } = config.infra;
  const infra = {
    db: null,
    redis: null,
    cache: null,
    locks: null,
    rateLimiter: null,
    publisher: null,
    rabbit: null,
  };
  /** @type {Array<{ name: string, close: () => Promise<unknown> }>} */
  const closers = [];
  /** Resolves when the startup connections have been tried (never rejects). @type {Promise<boolean>} */
  let startup = Promise.resolve(true);

  if (databaseUrl) {
    infra.db = getDbClient({ datasourceUrl: databaseUrl });
    readiness.register("database", () => pingDatabase(infra.db));
    closers.push({ name: "database", close: async () => disconnectDbClient() });
  }
  if (redisUrl) {
    const redis = redisFactory({ url: redisUrl, name: "qmentisai-api", logger });
    Object.assign(infra, {
      redis,
      cache: createCache({ redis }),
      locks: createLockManager({ redis }),
      rateLimiter: createRateLimiter({ redis }),
    });
    readiness.register("redis", () => pingRedis(redis));
    let timer;
    startup = Promise.race([
      pingRedis(redis).then(
        () => true,
        (error) => {
          logger.warn({ err: error }, "Redis did not answer at startup; readiness will report it");
          return false;
        },
      ),
      new Promise((resolve) => {
        timer = setTimeout(() => {
          logger.warn({ waitedMs: redisStartupMs }, "Redis did not answer in time at startup");
          resolve(false);
        }, redisStartupMs);
      }),
    ]).finally(() => clearTimeout(timer));
    closers.push({ name: "redis", close: async () => closeRedis(redis) });
  }
  if (rabbitmqUrl) {
    const connection = createRabbitConnection({ url: rabbitmqUrl, logger, connectAttempts: 1 });
    infra.rabbit = connection;
    infra.publisher = createPublisher({ connection, logger });
    // Startup declaration of the shared broker topology (idempotent). The API must still start without a broker
    // (readiness reports it); the publisher declares the topology again on its first publish.
    infra.publisher
      .declareTopology()
      .catch((error) =>
        logger.warn({ err: error }, "Could not declare the broker topology at startup"),
      );
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
    /** Waits for the startup connections (Redis); resolves false when one did not answer in time. */
    ready: () => startup,
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
