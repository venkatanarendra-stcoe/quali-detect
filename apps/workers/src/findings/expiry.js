import { createFindingExceptionsRepository } from "@qmentisai/db";

/** Exceptions expired per batch, and batches per tick (a backlog drains over a few ticks; each tick is bounded). */
export const EXPIRY_BATCH = 200;
export const EXPIRY_MAX_BATCHES = 5;

/**
 * The handler of the scheduled job `findings.exception.expire` (docs/modules/findings/SPEC.md 5.8 EX-3, 9.1): the scheduler worker
 * enqueues one platform job per five-minute bucket (the bucket is in the message id, so several scheduler instances produce ONE job),
 * the findings worker runs this. The job carries no tenant: it asks the database for approved exceptions whose `expires_at` has passed
 * and ends each in its OWN transaction, under the tenant, workspace and id of the row, with the finding locked: the exception becomes
 * `expired`, the finding `reopened` by the system actor `expiry` (history row, audit entry, `finding.exception_expired` and
 * `finding.reopened` events, SLA restarted). It is naturally idempotent: a replay, or a second instance, finds nothing due (a finding
 * that is no longer accepted or suppressed is skipped), and an exception another transaction already ended is a no-op. A failure of one
 * item is logged (ids only) and never stops the others; the rest is retried at the next tick. The read path never waits for this job:
 * an overdue acceptance is already shown as reopened and is expired lazily by the next write (EX-3).
 * @param {{ db: any, clock?: () => Date }} deps
 * @returns {(message: any, context: { log: any }) => Promise<void>}
 */
export function createExceptionExpiryHandler({ db, clock = () => new Date() }) {
  const exceptions = createFindingExceptionsRepository({ db });
  return async function handleExceptionExpiry(message, { log }) {
    if (message.type !== "findings.exception.expire")
      throw new TypeError(`The expiry handler does not handle "${message.type}".`);
    const total = { due: 0, expired: 0, skipped: 0, failed: 0 };
    for (let i = 0; i < EXPIRY_MAX_BATCHES; i += 1) {
      const done = await exceptions.expireDue(clock(), EXPIRY_BATCH, (error, ref) =>
        log.error(
          { err: error, tenantId: ref.tenantId, findingId: ref.findingId },
          "findings expiry: one exception could not be expired",
        ),
      );
      for (const key of Object.keys(total)) total[key] += done[key];
      // a short batch means nothing is left; a batch that expired nothing means the rest failed: do not spin on it
      if (done.due < EXPIRY_BATCH || done.expired === 0) break;
    }
    log.info(total, "findings expiry: tick finished");
  };
}
