import { jobEnvelopeSchema, createJobEnvelope } from "@qmentisai/contracts";
import { childLogger } from "../logging.js";
import { EXCHANGES, assertTopology, mainQueueName } from "./topology.js";
import { resolveRetryPolicy } from "./retry.js";

/**
 * Publishes validated job envelopes to a worker queue with persistent delivery and broker confirms.
 * Every message is validated with `jobEnvelopeSchema` before it leaves the process. Note: publishing is not atomic with a
 * database write; use the transactional outbox (docs/technical/EVENT_CONTRACTS.md) when state changes must reliably produce a message.
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
     * Validates and publishes an envelope to `queue`. Resolves after the broker confirms.
     * @param {{ queue: string, envelope: import("zod").input<typeof jobEnvelopeSchema> }} input
     * @returns {Promise<import("zod").infer<typeof jobEnvelopeSchema>>} the validated envelope that was sent
     */
    async publish({ queue, envelope }) {
      const valid = jobEnvelopeSchema.parse(envelope);
      const ch = await channel();
      if (!declared.has(queue)) {
        await assertTopology(ch, { queue, retryPolicy: policy });
        declared.add(queue);
      }
      await new Promise((resolve, reject) => {
        ch.publish(
          EXCHANGES.JOBS,
          queue,
          Buffer.from(JSON.stringify(valid)),
          {
            persistent: true,
            contentType: "application/json",
            messageId: valid.messageId,
            correlationId: valid.correlationId,
            timestamp: Math.floor(Date.parse(valid.createdAt) / 1000),
            type: valid.eventType,
            headers: { "x-attempt": 0, "x-schema-version": valid.schemaVersion },
          },
          (error) => (error ? reject(error) : resolve(undefined)),
        );
      });
      log.debug(
        {
          queue: mainQueueName(queue),
          messageId: valid.messageId,
          eventType: valid.eventType,
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
    async close() {
      const current = channelPromise;
      channelPromise = null;
      if (current) await (await current).close().catch(() => {});
    },
  };
  return Object.freeze(publisher);
}
