import fp from "fastify-plugin";
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
 * Connects the infrastructure that is configured and exposes it as `app.infra`
 * (`{ db, redis, cache, locks, rateLimiter, publisher }`; an entry is `null` when its URL is not configured).
 * Connections are lazy; each registers a readiness check (/ready) and is closed on shutdown.
 * Tenant rules: the cache, locks and rate limiter require `tenantId` on every call; the publisher validates the job envelope.
 */
export default fp(
  async function infrastructurePlugin(app) {
    const { databaseUrl, redisUrl, rabbitmqUrl } = app.config.infra;
    const infra = {
      db: null,
      redis: null,
      cache: null,
      locks: null,
      rateLimiter: null,
      publisher: null,
    };

    if (databaseUrl) {
      infra.db = getDbClient({ datasourceUrl: databaseUrl });
      app.readiness.register("database", () => pingDatabase(infra.db));
      app.addHook("onClose", async () => disconnectDbClient());
    }
    if (redisUrl) {
      const redis = createRedisClient({ url: redisUrl, name: "qmentisai-api", logger: app.log });
      Object.assign(infra, {
        redis,
        cache: createCache({ redis }),
        locks: createLockManager({ redis }),
        rateLimiter: createRateLimiter({ redis }),
      });
      app.readiness.register("redis", () => pingRedis(redis));
      app.addHook("onClose", async () => closeRedis(redis));
    }
    if (rabbitmqUrl) {
      const connection = createRabbitConnection({
        url: rabbitmqUrl,
        logger: app.log,
        connectAttempts: 1,
      });
      infra.publisher = createPublisher({ connection, logger: app.log });
      app.readiness.register("rabbitmq", () => connection.ping());
      app.addHook("onClose", async () => {
        await infra.publisher.close();
        await connection.close();
      });
    }
    app.decorate("infra", Object.freeze(infra));
  },
  { name: "infrastructure", dependencies: ["readiness"] },
);
