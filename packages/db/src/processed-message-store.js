/**
 * Database idempotency store for message consumers (table `processed_messages`), the durable replacement for the Redis
 * store. Same contract as the Redis store, so the consumer uses either:
 * - `begin` claims (tenant, consumer, key): "new" (go ahead), "processing" (another delivery runs it), "done" (skip);
 * - `complete` marks it done; `release` frees the claim after a failure so a retry can run;
 * - a claim whose worker crashed is reclaimed after `processingTtlSeconds`.
 * Rows are tenant-scoped: the unique key is (tenantId, consumer, idempotencyKey).
 * @param {{ db: any, processingTtlSeconds?: number }} options Prisma client
 */
export function createProcessedMessageStore({ db, processingTtlSeconds = 900 }) {
  const isUniqueViolation = (error) => error?.code === "P2002";
  const where = ({ tenantId, scope, key }) => ({
    tenantId_consumer_idempotencyKey: { tenantId, consumer: scope, idempotencyKey: key },
  });
  return Object.freeze({
    /** @param {{ tenantId: string, scope: string, key: string, messageId?: string }} input @returns {Promise<"new" | "processing" | "done">} */
    async begin(input) {
      try {
        await db.processedMessage.create({
          data: {
            tenantId: input.tenantId,
            consumer: input.scope,
            idempotencyKey: input.key,
            messageId: input.messageId ?? input.key,
          },
        });
        return "new";
      } catch (error) {
        if (!isUniqueViolation(error)) throw error;
      }
      const row = await db.processedMessage.findUnique({ where: where(input) });
      if (!row) return "processing"; // released between our two statements: let the redelivery decide
      if (row.status === "done") return "done";
      const cutoff = new Date(Date.now() - processingTtlSeconds * 1000);
      const { count } = await db.processedMessage.updateMany({
        where: { id: row.id, status: "processing", claimedAt: { lt: cutoff } },
        data: { claimedAt: new Date() },
      });
      return count === 1 ? "new" : "processing";
    },
    /** @param {{ tenantId: string, scope: string, key: string }} input */
    async complete(input) {
      await db.processedMessage.updateMany({
        where: { tenantId: input.tenantId, consumer: input.scope, idempotencyKey: input.key },
        data: { status: "done", completedAt: new Date() },
      });
    },
    /** @param {{ tenantId: string, scope: string, key: string }} input */
    async release(input) {
      await db.processedMessage.deleteMany({
        where: {
          tenantId: input.tenantId,
          consumer: input.scope,
          idempotencyKey: input.key,
          status: "processing",
        },
      });
    },
    /** Deletes completed rows older than `before` (retention is an Open decision; not scheduled). @param {{ before: Date }} input */
    async purgeDone({ before }) {
      const { count } = await db.processedMessage.deleteMany({
        where: { status: "done", completedAt: { lt: before } },
      });
      return count;
    },
  });
}
