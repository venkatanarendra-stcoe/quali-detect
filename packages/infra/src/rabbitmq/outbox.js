import { parseMessage } from "@qmentisai/contracts";

/**
 * Producer side of the transactional outbox. `enqueue(tx, ...)` validates the message (envelope + catalogued payload) and
 * writes it to `outbox_messages` THROUGH THE TRANSACTION CLIENT of the state change, so the message exists if and only if
 * the change committed. Nothing is published here; the relay does that (see outbox-relay.js).
 * @param {{ repository: { enqueue: (client: any, input: { queue: string, message: any }) => Promise<unknown> } }} deps from `createOutboxRepository`
 */
export function createOutbox({ repository }) {
  return Object.freeze({
    /**
     * @param {any} tx the Prisma TRANSACTION client the caller is using (never the root client: that would not be atomic)
     * @param {{ queue: string, message: unknown }} input a job or event envelope (`createJobEnvelope` / `createEventEnvelope`)
     * @returns {Promise<{ messageId: string }>}
     */
    async enqueue(tx, { queue, message }) {
      if (!tx || typeof tx.$transaction === "function")
        throw new TypeError(
          "outbox.enqueue needs the transaction client of the state change, not the root client.",
        );
      if (typeof queue !== "string" || queue === "") throw new TypeError("queue is required.");
      const valid = parseMessage(message, { allowUnknownTypes: true });
      await repository.enqueue(tx, { queue, message: valid });
      return { messageId: valid.messageId };
    },
  });
}
