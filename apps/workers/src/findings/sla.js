import { createFindingAssignmentsRepository, withTransaction } from "@qmentisai/db";

/** Findings marked per batch, and batches per tick (a backlog drains over a few ticks; each tick is bounded). */
export const SLA_SWEEP_BATCH = 200;
export const SLA_SWEEP_MAX_BATCHES = 5;

/**
 * The handler of the scheduled job `findings.sla.sweep` (docs/modules/findings/SPEC.md 5.9 SL-4, 9.1): the scheduler worker enqueues one
 * platform job per five-minute bucket (the bucket is in the message id, so several scheduler instances produce ONE job), the findings
 * worker runs this. The job carries no tenant: it asks the database for open findings whose clock crossed `due_soon` or `breached` and
 * were not yet notified in this cycle, and handles each in its OWN transaction under the tenant, workspace and id of the row, with the
 * finding locked and the condition re-checked: the marker column is set and the event `finding.sla_due_soon` or `finding.sla_breached`
 * is written to the outbox (ids, the severity and the due date only), by the system actor `sla`. Naturally idempotent: a replay or a
 * second instance finds nothing due, and a finding another transaction already marked is skipped. A failure of one item is logged (ids
 * only) and never stops the others; the rest is retried at the next tick. Nothing here changes a status: the SLA is a clock, not a
 * workflow state.
 * @param {{ db: any, clock?: () => Date }} deps
 * @returns {(message: any, context: { log: any }) => Promise<void>}
 */
export function createSlaSweepHandler({ db, clock = () => new Date() }) {
  const assignments = createFindingAssignmentsRepository({ db });
  return async function handleSlaSweep(message, { log }) {
    if (message.type !== "findings.sla.sweep")
      throw new TypeError(`The SLA sweep handler does not handle "${message.type}".`);
    const total = { due: 0, notified: 0, skipped: 0, failed: 0 };
    for (let i = 0; i < SLA_SWEEP_MAX_BATCHES; i += 1) {
      const now = clock();
      const rows = await assignments.dueForSweep(now, SLA_SWEEP_BATCH);
      let notified = 0;
      for (const row of rows) {
        total.due += 1;
        try {
          const done = await withTransaction(
            db,
            (tx) =>
              assignments.notifySla(
                tx,
                {
                  tenantId: row.tenantId,
                  workspaceId: row.workspaceId,
                  id: row.id,
                  phase: row.phase,
                  dueAt: row.slaDueAt,
                },
                now,
              ),
            { timeout: 30_000, maxWait: 10_000 },
          );
          if (done.notified) {
            notified += 1;
            total.notified += 1;
          } else total.skipped += 1;
        } catch (error) {
          total.failed += 1;
          log.error(
            { err: error, tenantId: row.tenantId, findingId: row.id },
            "findings SLA sweep: one finding could not be marked",
          );
        }
      }
      // a short batch means nothing is left; a batch that marked nothing means the rest is stuck: do not spin on it
      if (rows.length < SLA_SWEEP_BATCH || notified === 0) break;
    }
    log.info(total, "findings SLA sweep: tick finished");
  };
}
