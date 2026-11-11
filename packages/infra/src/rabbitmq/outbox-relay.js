import { childLogger } from "../logging.js";
import { computeBackoffDelay } from "./retry.js";

const sleep = (ms, signal) =>
  new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(timer);
      resolve(undefined);
    });
  });

/**
 * The outbox relay: repeatedly claims due outbox rows (`FOR UPDATE SKIP LOCKED`, so any number of relay instances can run
 * side by side), publishes each to RabbitMQ and waits for the broker's publisher confirm, then marks it sent in the same
 * transaction. Failures are rescheduled with bounded exponential backoff and jitter; a message that can never be valid is
 * marked dead. A broker outage is survived: publishing fails, rows stay pending, and the relay resumes by itself when the
 * broker is back (the publisher reconnects on demand). Delivery is at-least-once.
 * @param {{
 *   repository: ReturnType<typeof import("@qmentisai/db").createOutboxRepository>,
 *   publisher: ReturnType<typeof import("./publisher.js").createPublisher>,
 *   logger?: object, batchSize?: number, pollIntervalMs?: number, maxAttempts?: number,
 *   baseDelayMs?: number, maxDelayMs?: number,
 * }} options
 */
export function createOutboxRelay({
  repository,
  publisher,
  logger,
  batchSize = 20,
  pollIntervalMs = 1000,
  maxAttempts = 100,
  baseDelayMs = 1000,
  maxDelayMs = 60000,
}) {
  const log = childLogger(logger, { component: "outbox-relay" });
  let running = false;
  let loop = null;
  let abort = null;

  const publishRow = async (row) => {
    try {
      await publisher.publish({
        queue: row.queue,
        exchange: row.exchange ?? undefined,
        routingKey: row.routingKey ?? undefined,
        envelope: row.payload,
      });
    } catch (error) {
      // An invalid stored envelope can never succeed: do not retry it forever.
      if (error?.name === "ZodError" || error?.name === "MessageContractError")
        error.permanent = true;
      throw error;
    }
  };

  /** Processes one batch. @returns {Promise<{ claimed: number, sent: number, failed: number, dead: number }>} */
  async function runOnce() {
    const result = await repository.processBatch({
      limit: batchSize,
      maxAttempts,
      nextDelayMs: (attempts) =>
        computeBackoffDelay({ attempt: attempts, baseDelayMs, maxDelayMs }),
      publish: publishRow,
    });
    if (result.sent > 0) log.info({ ...result }, "Outbox batch published");
    if (result.failed > 0 || result.dead > 0)
      log.warn({ ...result }, "Outbox batch had failures (rows rescheduled or marked dead)");
    return result;
  }

  return Object.freeze({
    runOnce,
    /** Starts the polling loop (returns immediately). */
    start() {
      if (running) throw new Error("Outbox relay already started");
      running = true;
      abort = new AbortController();
      loop = (async () => {
        log.info({ batchSize, pollIntervalMs }, "Outbox relay started");
        while (running) {
          let busy = false;
          try {
            const { claimed, sent } = await runOnce();
            busy = claimed > 0 && sent === claimed; // a full, successful batch: look again at once
          } catch (error) {
            log.error({ err: error }, "Outbox batch failed");
          }
          if (running && !busy) await sleep(pollIntervalMs, abort.signal);
        }
      })();
    },
    /** Stops after the current batch. */
    async stop() {
      running = false;
      abort?.abort();
      await loop;
      loop = null;
      log.info("Outbox relay stopped");
    },
  });
}
