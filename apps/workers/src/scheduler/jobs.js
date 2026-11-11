import { createJobEnvelope, QUEUE_NAMES } from "@qmentisai/contracts";
import { createOutboxRepository } from "@qmentisai/db";
import { createOutbox } from "@qmentisai/infra";

/**
 * Enqueues the periodic session purge job through the transactional outbox. The messageId is derived from the time bucket
 * (`sessions-purge-<n>`), and the outbox is unique per (messageId, queue), so several scheduler instances ticking in the
 * same interval produce ONE job.
 * @param {{ db: any, intervalSeconds: number, retentionSeconds: number, now?: Date }} input
 * @returns {Promise<{ messageId: string }>}
 */
export async function enqueueSessionPurge({
  db,
  intervalSeconds,
  retentionSeconds,
  now = new Date(),
}) {
  const outbox = createOutbox({ repository: createOutboxRepository({ db }) });
  const bucket = Math.floor(now.getTime() / (intervalSeconds * 1000));
  return db.$transaction((tx) =>
    outbox.enqueue(tx, {
      queue: QUEUE_NAMES.SCHEDULER,
      message: createJobEnvelope({
        messageId: `sessions-purge-${bucket}`,
        type: "maintenance.sessions.purge_requested",
        schemaVersion: 1,
        initiator: { type: "system", id: "scheduler" },
        payload: { retentionSeconds },
      }),
    }),
  );
}

/**
 * Deletes tenant and platform sessions that expired, or were revoked, more than `retentionSeconds` ago. Naturally
 * idempotent (a repeat deletes nothing more), which matters because platform-level jobs have no tenant to key an
 * idempotency claim on. Active sessions are never touched.
 * @param {{ db: any, retentionSeconds: number, now?: Date }} input
 * @returns {Promise<{ sessions: number, platformSessions: number }>}
 */
export async function purgeSessions({ db, retentionSeconds, now = new Date() }) {
  const cutoff = new Date(now.getTime() - retentionSeconds * 1000);
  const where = { OR: [{ expiresAt: { lt: cutoff } }, { revokedAt: { lt: cutoff } }] };
  const [sessions, platformSessions] = await Promise.all([
    db.session.deleteMany({ where }),
    db.platformSession.deleteMany({ where }),
  ]);
  return { sessions: sessions.count, platformSessions: platformSessions.count };
}

/**
 * Enqueues a platform-level job (no tenant) through the outbox. The messageId is derived from the time bucket, so several
 * scheduler instances ticking in the same interval produce ONE job.
 * @param {{ db: any, queue: string, type: string, intervalSeconds: number, payload: object, prefix: string, now?: Date }} input
 */
export async function enqueuePlatformJob({
  db,
  queue,
  type,
  intervalSeconds,
  payload,
  prefix,
  now = new Date(),
}) {
  const outbox = createOutbox({ repository: createOutboxRepository({ db }) });
  const bucket = Math.floor(now.getTime() / (intervalSeconds * 1000));
  return db.$transaction((tx) =>
    outbox.enqueue(tx, {
      queue,
      message: createJobEnvelope({
        messageId: `${prefix}-${bucket}`,
        type,
        schemaVersion: 1,
        initiator: { type: "system", id: "scheduler" },
        payload,
      }),
    }),
  );
}
