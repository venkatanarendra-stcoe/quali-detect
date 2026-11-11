import { ConfigError, loadWorkerConfig } from "../config.js";
import { createOwnershipVerifier } from "../ownership/index.js";
import { createWorkerLogger } from "../logger.js";
import { createProcessedMessageStore, getDbClient, disconnectDbClient } from "@qmentisai/db";
import {
  closeRedis,
  createConsumer,
  createRabbitConnection,
  createRedisClient,
  createRedisIdempotencyStore,
  pingRedis,
} from "@qmentisai/infra";

/**
 * Runs one worker process: validated config, the idempotency store (the durable `processed_messages` table when DATABASE_URL
 * is set, else Redis), RabbitMQ connection, a consumer for the worker's
 * queue, and graceful shutdown on SIGINT/SIGTERM (stop consuming, wait for in-flight jobs up to the timeout, close
 * connections). A second signal exits immediately. Startup failures (bad config, unreachable broker) exit with code 1.
 * @param {{ name: string, queue: string, handler: Function, verifyOwnership?: boolean, requireTenant?: boolean, onReady?: (context: { db: any, config: any, logger: any }) => (() => Promise<void>) | void }} options `onReady` runs after the consumer started (for example a ticker) and may return a stop function `verifyOwnership` re-validates tenant and resource ownership against the database before the handler (needs DATABASE_URL)
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export async function runWorker({
  name,
  queue,
  handler,
  verifyOwnership = false,
  requireTenant = true,
  onReady,
}) {
  let config;
  try {
    config = loadWorkerConfig();
  } catch (error) {
    if (!(error instanceof ConfigError)) throw error;
    console.error(error.message);
    process.exit(1);
  }

  const logger = createWorkerLogger(config, name);
  if (verifyOwnership && !config.databaseUrl) {
    console.error(
      "Invalid environment configuration:\n  - DATABASE_URL: required by this worker (ownership checks)",
    );
    process.exit(1);
  }
  const db = config.databaseUrl ? getDbClient({ datasourceUrl: config.databaseUrl }) : null;
  const redis =
    !db && config.redisUrl
      ? createRedisClient({ url: config.redisUrl, name: `qmentisai-worker-${name}`, logger })
      : null;
  const connection = createRabbitConnection({ url: config.rabbitmqUrl, logger });
  const idempotency = db
    ? createProcessedMessageStore({ db, processingTtlSeconds: config.claimTtlSeconds })
    : createRedisIdempotencyStore({ redis, doneTtlSeconds: config.idempotencyTtlSeconds });
  const consumer = createConsumer({
    connection,
    queue,
    handler,
    verify: verifyOwnership ? createOwnershipVerifier({ db }) : undefined,
    logger,
    prefetch: config.prefetch,
    retryPolicy: config.retryPolicy,
    idempotency,
    requireTenant,
  });

  let stopHook = null;
  let stopping = null;
  const stop = () => {
    stopping ??= (async () => {
      logger.info("Shutting down");
      await stopHook?.();
      await consumer.stop({ timeoutMs: config.shutdownTimeoutMs });
      await connection.close();
      if (redis) await closeRedis(redis);
      if (db) await disconnectDbClient();
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
    if (redis) await pingRedis(redis);
    if (db) await db.$queryRaw`SELECT 1`;
    await consumer.start();
  } catch (error) {
    logger.fatal({ err: error }, "Worker failed to start");
    await stop().catch(() => {});
    process.exit(1);
  }
  stopHook = (await onReady?.({ db, config, logger })) ?? null;
  logger.info({ queue }, "Worker running");
  return { stop };
}
