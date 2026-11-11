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
     * @param {{ queue: string, exchange?: string, routingKey?: string, message: unknown }} input a job or event envelope; `exchange` + `routingKey` target a topic exchange instead of the direct queue
     * @returns {Promise<{ messageId: string }>}
     */
    async enqueue(tx, { queue, exchange, routingKey, message }) {
      if (!tx || typeof tx.$transaction === "function")
        throw new TypeError(
          "outbox.enqueue needs the transaction client of the state change, not the root client.",
        );
      if (typeof queue !== "string" || queue === "") throw new TypeError("queue is required.");
      const valid = parseMessage(message, { allowUnknownTypes: true });
      if (Boolean(exchange) !== Boolean(routingKey))
        throw new TypeError("exchange and routingKey go together.");
      await repository.enqueue(tx, { queue, exchange, routingKey, message: valid });
      return { messageId: valid.messageId };
    },
  });
}
