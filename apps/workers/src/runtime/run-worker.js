import { ConfigError, loadWorkerConfig } from "../config.js";
import { createWorkerLogger } from "../logger.js";
import {
  closeRedis,
  createConsumer,
  createRabbitConnection,
  createRedisClient,
  createRedisIdempotencyStore,
  pingRedis,
} from "@qmentisai/infra";

/**
 * Runs one worker process: validated config, Redis (idempotency) and RabbitMQ connections, a consumer for the worker's
 * queue, and graceful shutdown on SIGINT/SIGTERM (stop consuming, wait for in-flight jobs up to the timeout, close
 * connections). A second signal exits immediately. Startup failures (bad config, unreachable broker) exit with code 1.
 * @param {{ name: string, queue: string, handler: Function }} options
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export async function runWorker({ name, queue, handler }) {
  let config;
  try {
    config = loadWorkerConfig();
  } catch (error) {
    if (!(error instanceof ConfigError)) throw error;
    console.error(error.message);
    process.exit(1);
  }

  const logger = createWorkerLogger(config, name);
  const redis = createRedisClient({
    url: config.redisUrl,
    name: `qmentisai-worker-${name}`,
    logger,
  });
  const connection = createRabbitConnection({ url: config.rabbitmqUrl, logger });
  const idempotency = createRedisIdempotencyStore({
    redis,
    doneTtlSeconds: config.idempotencyTtlSeconds,
  });
  const consumer = createConsumer({
    connection,
    queue,
    handler,
    logger,
    prefetch: config.prefetch,
    retryPolicy: config.retryPolicy,
    idempotency,
  });

  let stopping = null;
  const stop = () => {
    stopping ??= (async () => {
      logger.info("Shutting down");
      await consumer.stop({ timeoutMs: config.shutdownTimeoutMs });
      await connection.close();
      await closeRedis(redis);
      logger.info("Stopped");
    })();
    return stopping;
  };

  let signalled = false;
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      if (signalled) process.exit(1); // second signal: stop waiting
      signalled = true;
      logger.info({ signal }, "Signal received");
      stop().then(
        () => process.exit(0),
        (error) => {
          logger.error({ err: error }, "Shutdown failed");
          process.exit(1);
        },
      );
    });
  }
  // A dropped broker connection is fatal for a consumer: exit so the supervisor restarts the worker.
  connection.onClose(() => {
    logger.fatal("RabbitMQ connection lost, exiting");
    process.exit(1);
  });

  try {
    await pingRedis(redis);
    await consumer.start();
  } catch (error) {
    logger.fatal({ err: error }, "Worker failed to start");
    await stop().catch(() => {});
    process.exit(1);
  }
  logger.info({ queue }, "Worker running");
  return { stop };
}
