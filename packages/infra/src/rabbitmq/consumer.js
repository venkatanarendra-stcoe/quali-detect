import { jobEnvelopeSchema } from "@qmentisai/contracts";
import { childLogger } from "../logging.js";
import { classifyError, computeBackoffDelay, resolveRetryPolicy } from "./retry.js";
import { EXCHANGES, assertTopology, mainQueueName, retryRoutingKey } from "./topology.js";

/**
 * @typedef {object} JobContext
 * @property {number} attempt 1-based delivery attempt of this message.
 * @property {object} log Logger bound to messageId, correlationId, tenantId and eventType.
 */

/**
 * Consumer for one worker queue.
 *
 * Per message: parse JSON -> validate with `jobEnvelopeSchema` -> require tenantId (default) -> idempotency claim -> run handler.
 * Success acks. Failure is classified: transient and attempts left -> republished to the retry tier (bounded exponential
 * backoff with jitter) ; otherwise -> the dead-letter queue with the failure reason. Malformed or tenant-less messages go
 * straight to the dead-letter queue. A message is acked only after its retry/dead-letter copy is confirmed by the broker,
 * so a failure while rescheduling leads to redelivery rather than loss (delivery is at-least-once; handlers must be idempotent).
 * The tenantId in a message is untrusted: handlers must still verify that the referenced resources belong to it.
 *
 * @param {{
 *   connection: ReturnType<typeof import("./connection.js").createRabbitConnection>,
 *   queue: string,
 *   handler: (envelope: import("zod").infer<typeof jobEnvelopeSchema>, context: JobContext) => Promise<void>,
 *   logger?: object,
 *   prefetch?: number,
 *   retryPolicy?: Parameters<typeof resolveRetryPolicy>[0],
 *   idempotency?: ReturnType<typeof import("./idempotency.js").createRedisIdempotencyStore>,
 *   requireTenant?: boolean,
 *   unknownErrorAs?: "transient" | "non-retryable",
 *   random?: () => number,
 * }} options
 */
export function createConsumer({
  connection,
  queue,
  handler,
  logger,
  prefetch = 5,
  retryPolicy,
  idempotency,
  requireTenant = true,
  unknownErrorAs = "non-retryable",
  random = Math.random,
}) {
  const policy = resolveRetryPolicy(retryPolicy);
  const log = childLogger(logger, { component: "consumer", queue });
  let channel = null;
  let consumerTag = null;
  let inFlight = 0;
  let idleWaiters = [];
  let stopping = false;

  const settleIdle = () => {
    if (inFlight === 0) {
      for (const resolve of idleWaiters) resolve();
      idleWaiters = [];
    }
  };

  /** Publishes a copy to an exchange and waits for the broker confirm. */
  function republish(exchange, routingKey, message, extra) {
    return new Promise((resolve, reject) => {
      const { properties } = message;
      channel.publish(
        exchange,
        routingKey,
        message.content,
        {
          persistent: true,
          contentType: properties.contentType,
          messageId: properties.messageId,
          correlationId: properties.correlationId,
          timestamp: properties.timestamp,
          type: properties.type,
          headers: { ...properties.headers, ...extra.headers },
          ...(extra.expiration === undefined ? {} : { expiration: String(extra.expiration) }),
        },
        (error) => (error ? reject(error) : resolve(undefined)),
      );
    });
  }

  const deadLetter = async (message, reason, attempt, extraLog = {}) => {
    await republish(EXCHANGES.DEAD_LETTER, queue, message, {
      headers: {
        "x-attempt": attempt,
        "x-failure-reason": reason,
        "x-failed-at": new Date().toISOString(),
      },
    });
    log.error(
      { reason, attempt, messageId: message.properties.messageId, ...extraLog },
      "Message moved to the dead-letter queue",
    );
  };

  const scheduleRetry = async (message, attempt) => {
    // `attempt` failed deliveries so far; this is retry number `attempt` -> tier `attempt`.
    const delayMs = computeBackoffDelay({
      attempt,
      baseDelayMs: policy.baseDelayMs,
      maxDelayMs: policy.maxDelayMs,
      jitter: policy.jitter,
      random,
    });
    await republish(EXCHANGES.RETRY, retryRoutingKey(queue, attempt), message, {
      expiration: delayMs,
      headers: { "x-attempt": attempt },
    });
    return delayMs;
  };

  async function process(message) {
    const attempt = Number(message.properties.headers?.["x-attempt"] ?? 0);
    let envelope;
    try {
      envelope = jobEnvelopeSchema.parse(JSON.parse(message.content.toString("utf8")));
    } catch {
      await deadLetter(message, "invalid-envelope", attempt);
      return;
    }
    if (requireTenant && !envelope.tenantId) {
      await deadLetter(message, "missing-tenant", attempt, { messageId: envelope.messageId });
      return;
    }

    const jobLog = childLogger(log, {
      messageId: envelope.messageId,
      correlationId: envelope.correlationId,
      tenantId: envelope.tenantId,
      eventType: envelope.eventType,
    });
    const claim =
      idempotency && envelope.tenantId
        ? {
            tenantId: envelope.tenantId,
            scope: queue,
            key: envelope.idempotencyKey ?? envelope.messageId,
          }
        : null;

    if (claim) {
      const state = await idempotency.begin(claim);
      if (state === "done") {
        jobLog.info("Duplicate delivery skipped (already processed)");
        return;
      }
      if (state === "processing") {
        // Another delivery is running this job right now: try again later instead of running it twice.
        await settleFailure(
          message,
          attempt,
          new Error("Job is already being processed"),
          jobLog,
          "transient",
        );
        return;
      }
    }

    try {
      await handler(envelope, { attempt: attempt + 1, log: jobLog });
      if (claim) await idempotency.complete(claim);
    } catch (error) {
      if (claim)
        await idempotency
          .release(claim)
          .catch((releaseError) =>
            jobLog.warn({ err: releaseError }, "Could not release idempotency claim"),
          );
      await settleFailure(
        message,
        attempt,
        error,
        jobLog,
        classifyError(error, { unknownAs: unknownErrorAs }),
      );
    }
  }

  async function settleFailure(message, attempt, error, jobLog, kind) {
    const failed = attempt + 1;
    if (kind === "transient" && failed < policy.maxAttempts) {
      const delayMs = await scheduleRetry(message, failed);
      jobLog.warn(
        { attempt: failed, maxAttempts: policy.maxAttempts, retryInMs: delayMs, err: error },
        "Transient failure, retry scheduled",
      );
      return;
    }
    const reason = kind === "transient" ? "max-attempts-exceeded" : "non-retryable";
    await deadLetter(message, reason, failed, { err: error });
  }

  async function onMessage(message) {
    if (message === null) {
      log.warn("Consumer cancelled by the broker");
      return;
    }
    inFlight += 1;
    try {
      await process(message);
      channel.ack(message);
    } catch (error) {
      // Rescheduling failed (broker/channel problem): do not lose the message; ask for redelivery.
      log.error(
        { err: error, messageId: message.properties.messageId },
        "Could not settle message, requesting redelivery",
      );
      try {
        channel.nack(message, false, true);
      } catch {
        // channel is gone; the broker redelivers unacked messages when it closes
      }
    } finally {
      inFlight -= 1;
      settleIdle();
    }
  }

  return Object.freeze({
    /** Declares the topology and starts consuming. */
    async start() {
      if (channel) throw new Error("Consumer already started");
      channel = await connection.createConfirmChannel();
      channel.on("error", (error) => log.warn({ err: error }, "Consumer channel error"));
      await assertTopology(channel, { queue, retryPolicy: policy });
      await channel.prefetch(prefetch);
      ({ consumerTag } = await channel.consume(
        mainQueueName(queue),
        (message) => void onMessage(message),
        { noAck: false },
      ));
      log.info({ prefetch, maxAttempts: policy.maxAttempts }, "Consumer started");
    },
    /**
     * Graceful stop: stop taking new messages, wait for in-flight handlers (up to `timeoutMs`), close the channel.
     * Unfinished messages stay unacked and are redelivered.
     * @param {{ timeoutMs?: number }} [options]
     * @returns {Promise<{ drained: boolean }>}
     */
    async stop({ timeoutMs = 30000 } = {}) {
      if (!channel || stopping) return { drained: true };
      stopping = true;
      if (consumerTag) await channel.cancel(consumerTag).catch(() => {});
      let timer;
      const drained = await Promise.race([
        inFlight === 0 ? true : new Promise((resolve) => idleWaiters.push(() => resolve(true))),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve(false), timeoutMs);
        }),
      ]);
      clearTimeout(timer);
      await channel.close().catch(() => {});
      channel = null;
      log.info({ drained }, "Consumer stopped");
      return { drained };
    },
    get inFlight() {
      return inFlight;
    },
  });
}
