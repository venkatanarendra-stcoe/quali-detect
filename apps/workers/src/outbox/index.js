import { createOutboxRepository, disconnectDbClient, getDbClient } from "@qmentisai/db";
import { createOutboxRelay, createPublisher, createRabbitConnection } from "@qmentisai/infra";
import { ConfigError, loadWorkerConfig } from "../config.js";
import { createWorkerLogger } from "../logger.js";

/** Entry point of the outbox relay (docs/architecture/WORKER_ARCHITECTURE.md, "Transactional outbox"). */
export const WORKER_NAME = "outbox";

/**
 * Runs the outbox relay: publishes committed outbox rows to RabbitMQ with publisher confirms. Any number of instances can
 * run at once (row locking with SKIP LOCKED). Unlike queue consumers it SURVIVES a broker outage: publishing fails, rows
 * stay pending, and publishing resumes by itself when the broker returns. Graceful stop on SIGINT/SIGTERM (finish the batch).
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export async function start() {
  let config;
  try {
    config = loadWorkerConfig();
    if (!config.databaseUrl)
      throw new ConfigError([
        { variable: "DATABASE_URL", message: "required by the outbox relay" },
      ]);
  } catch (error) {
    if (!(error instanceof ConfigError)) throw error;
    console.error(error.message);
    process.exit(1);
  }
  const logger = createWorkerLogger(config, WORKER_NAME);
  const db = getDbClient({ datasourceUrl: config.databaseUrl });
  // One connection attempt per publish: a broker outage must fail the batch quickly, not hold row locks while retrying.
  const connection = createRabbitConnection({
    url: config.rabbitmqUrl,
    logger,
    connectAttempts: 1,
  });
  const publisher = createPublisher({ connection, logger, retryPolicy: config.retryPolicy });
  const relay = createOutboxRelay({
    repository: createOutboxRepository({ db }),
    publisher,
    logger,
    ...config.outbox,
  });

  let stopping = null;
  const stop = () => {
    stopping ??= (async () => {
      logger.info("Shutting down");
      await relay.stop();
      await publisher.close();
      await connection.close();
      await disconnectDbClient();
      logger.info("Stopped");
    })();
    return stopping;
  };
  let signalled = false;
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      if (signalled) process.exit(1);
      signalled = true;
      logger.info({ signal }, "Signal received");
      stop().then(
        () => process.exit(0),
        () => process.exit(1),
      );
    });
  }
  relay.start();
  logger.info("Worker running");
  return { stop };
}
