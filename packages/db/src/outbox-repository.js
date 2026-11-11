import { withTransaction } from "./transaction.js";

const MAX_ERROR_LENGTH = 500;

/**
 * Persistence of the transactional outbox. Two audiences:
 * - PRODUCERS call `enqueue(tx, ...)` inside the transaction that changes state, so the message is committed (or rolled
 *   back) together with the change;
 * - the RELAY calls `processBatch`, which claims due rows with `FOR UPDATE SKIP LOCKED` (several relay instances can run
 *   at once: each takes different rows and none waits for another), publishes them while holding the row locks and marks the result in the same
 *   transaction. If a relay dies mid-batch the transaction rolls back, the rows stay pending and are published again by
 *   another relay: delivery is at-least-once, consumers deduplicate (`processed_messages`).
 * @param {{ db: any }} deps Prisma client
 */
export function createOutboxRepository({ db }) {
  return Object.freeze({
    /**
     * Writes one outbox row. Pass the TRANSACTION client of the state change. `message` must already be a validated envelope.
     * Idempotent per (messageId, queue): enqueueing the same message for the same queue twice is a no-op.
     * @param {any} client Prisma transaction client (or client)
     * @param {{ queue: string, exchange?: string, routingKey?: string, message: { messageId: string, type: string, tenantId?: string } & Record<string, unknown> }} input
     */
    async enqueue(client, { queue, exchange, routingKey, message }) {
      return client.outboxMessage.upsert({
        where: { messageId_queue: { messageId: message.messageId, queue } },
        create: {
          tenantId: message.tenantId ?? null,
          messageId: message.messageId,
          type: message.type,
          queue,
          exchange: exchange ?? null,
          routingKey: routingKey ?? null,
          payload: message,
        },
        update: {},
      });
    },

    /**
     * Claims up to `limit` due pending rows, hands each to `publish`, and records the outcome in the same transaction.
     * `publish(row)` resolves after the broker confirmed; it throws to fail. A thrown error with `permanent === true`
     * marks the row dead at once; any other error reschedules it with `nextDelayMs(attempts)` (dead after `maxAttempts`).
     * The batch stops at the first failure so an unavailable broker does not hold the transaction open row by row.
     * @param {{
     *   limit: number, maxAttempts: number, nextDelayMs: (attempts: number) => number, now?: () => Date,
     *   publish: (row: { id: string, tenantId: string | null, messageId: string, type: string, queue: string, exchange: string | null, routingKey: string | null, payload: any, attempts: number }) => Promise<void>,
     * }} options
     * @returns {Promise<{ claimed: number, sent: number, failed: number, dead: number }>}
     */
    async processBatch({ limit, maxAttempts, nextDelayMs, now = () => new Date(), publish }) {
      return withTransaction(
        db,
        async (tx) => {
          const rows = await tx.$queryRaw`
            SELECT id, tenant_id AS "tenantId", message_id AS "messageId", type, queue, exchange, routing_key AS "routingKey", payload, attempts
            FROM outbox_messages
            WHERE status = 'pending' AND available_at <= now()
            ORDER BY created_at, id
            LIMIT ${limit}
            FOR UPDATE SKIP LOCKED`;
          const result = { claimed: rows.length, sent: 0, failed: 0, dead: 0 };
          const sentIds = [];
          for (const row of rows) {
            try {
              await publish(row);
              sentIds.push(row.id);
            } catch (error) {
              const attempts = row.attempts + 1;
              const dead = error?.permanent === true || attempts >= maxAttempts;
              await tx.outboxMessage.update({
                where: { id: row.id },
                data: {
                  attempts,
                  status: dead ? "dead" : "pending",
                  availableAt: new Date(now().getTime() + nextDelayMs(attempts)),
                  lastError: String(error?.message ?? error).slice(0, MAX_ERROR_LENGTH),
                },
              });
              result[dead ? "dead" : "failed"] += 1;
              break;
            }
          }
          if (sentIds.length > 0) {
            await tx.outboxMessage.updateMany({
              where: { id: { in: sentIds } },
              data: { status: "sent", sentAt: now(), lastError: null },
            });
            result.sent = sentIds.length;
          }
          return result;
        },
        { timeout: 60000, maxWait: 10000 },
      );
    },

    /** Operational counts by status. */
    async counts() {
      const rows = await db.outboxMessage.groupBy({ by: ["status"], _count: { _all: true } });
      return Object.fromEntries(rows.map((r) => [r.status, r._count._all]));
    },

    /** Puts dead rows back in the queue (operator action). @param {{ tenantId?: string }} [filter] @returns {Promise<number>} rows requeued */
    async requeueDead({ tenantId } = {}) {
      const { count } = await db.outboxMessage.updateMany({
        where: { status: "dead", ...(tenantId ? { tenantId } : {}) },
        data: { status: "pending", attempts: 0, availableAt: new Date() },
      });
      return count;
    },

    /** Deletes sent rows older than `before`. Not scheduled anywhere yet (retention is an Open decision). @param {{ before: Date }} input */
    async purgeSent({ before }) {
      const { count } = await db.outboxMessage.deleteMany({
        where: { status: "sent", sentAt: { lt: before } },
      });
      return count;
    },
  });
}
