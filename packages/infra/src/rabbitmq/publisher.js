import { createEventEnvelope, createJobEnvelope, parseMessage } from "@qmentisai/contracts";
import { childLogger } from "../logging.js";
import { EXCHANGES, assertTopology, mainQueueName } from "./topology.js";
import { resolveRetryPolicy } from "./retry.js";

/**
 * Publishes validated messages (jobs and events share one envelope family) to a worker queue with persistent delivery and
 * broker confirms. Every message is validated with `parseMessage` (envelope + catalogued payload) before it leaves the
 * process. Publishing is not atomic with a database write: when a state change must reliably produce a message, write it
 * to the transactional outbox in the same transaction (`createOutbox`) and let the relay call this publisher.
 * @param {{ connection: ReturnType<typeof import("./connection.js").createRabbitConnection>, logger?: object, retryPolicy?: object }} options
 */
export function createPublisher({ connection, logger, retryPolicy }) {
  const log = childLogger(logger, { component: "publisher" });
  const policy = resolveRetryPolicy(retryPolicy);
  const declared = new Set();
  let channelPromise = null;

  async function channel() {
    if (!channelPromise) {
      channelPromise = connection.createConfirmChannel().then(
        (ch) => {
          const reset = () => {
            channelPromise = null;
            declared.clear();
          };
          ch.on("close", reset);
          ch.on("error", (error) => log.warn({ err: error }, "Publisher channel error"));
          return ch;
        },
        (error) => {
          channelPromise = null;
          throw error;
        },
      );
    }
    return channelPromise;
  }

  const publisher = {
    /**
     * Validates and publishes a message to `queue`. Resolves after the broker confirms.
     * @param {{ queue: string, exchange?: string, routingKey?: string, envelope: unknown, allowUnknownTypes?: boolean }} input `exchange` + `routingKey` publish to a topic exchange (SCM events); otherwise to the direct jobs exchange
     * @returns {Promise<ReturnType<typeof parseMessage>>} the validated message that was sent
     */
    async publish({ queue, exchange, routingKey, envelope, allowUnknownTypes = true }) {
      const valid = parseMessage(envelope, { allowUnknownTypes });
      const ch = await channel();
      if (exchange) {
        if (!declared.has(`x:${exchange}`)) {
          await ch.assertExchange(exchange, "topic", { durable: true });
          declared.add(`x:${exchange}`);
        }
      } else if (!declared.has(queue)) {
        await assertTopology(ch, { queue, retryPolicy: policy });
        declared.add(queue);
      }
      await new Promise((resolve, reject) => {
        ch.publish(
          exchange ?? EXCHANGES.JOBS,
          exchange ? routingKey : queue,
          Buffer.from(JSON.stringify(valid)),
          {
            persistent: true,
            contentType: "application/json",
            messageId: valid.messageId,
            correlationId: valid.correlationId,
            timestamp: Math.floor(Date.parse(valid.occurredAt) / 1000),
            type: valid.type,
            headers: {
              "x-attempt": 0,
              "x-schema-version": valid.schemaVersion,
              "x-envelope-version": valid.envelopeVersion,
              "x-kind": valid.kind,
            },
          },
          (error) => (error ? reject(error) : resolve(undefined)),
        );
      });
      log.debug(
        {
          queue: mainQueueName(queue),
          messageId: valid.messageId,
          type: valid.type,
          correlationId: valid.correlationId,
        },
        "Job published",
      );
      return valid;
    },
    /**
     * Builds an envelope (filling messageId, correlationId, createdAt) and publishes it.
     * @param {{ queue: string, envelope: Parameters<typeof createJobEnvelope>[0] }} input
     */
    publishJob: ({ queue, envelope }) =>
      publisher.publish({ queue, envelope: createJobEnvelope(envelope) }),
    /** Builds an event (filling messageId, correlationId, occurredAt) and publishes it. @param {{ queue: string, envelope: Parameters<typeof createEventEnvelope>[0] }} input */
    publishEvent: ({ queue, envelope }) =>
      publisher.publish({ queue, envelope: createEventEnvelope(envelope) }),
    async close() {
      const current = channelPromise;
      channelPromise = null;
      if (current) await (await current).close().catch(() => {});
    },
  };
  return Object.freeze(publisher);
}
