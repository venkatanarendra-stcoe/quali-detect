import { EXECUTION_CANCEL_MODES } from "@qmentisai/shared";
import { withTransaction } from "../transaction.js";
import { createExecutionRepository } from "./repository.js";

const REASON = /^[a-z][a-z_:]{0,63}$/;

/**
 * The shared cancel functions (docs/modules/executions/SPEC.md part D, ER-18 to ER-20, §5.9). One place for every way an
 * execution is cancelled, so the quota unit is given back exactly once whoever cancels:
 * - `cancelQueued` is the `queued -> cancelled` compare-and-set with the unit released in the SAME transaction (the user's
 *   cancel, the claim-time gates, the stale sweeps, supersede, a closed pull request, a deleted pipeline);
 * - `requestCancel` only RECORDS a cancel request on a preparing/running execution (no terminal write by the requester); the
 *   lease holder honours it at its safe points.
 * Both are scoped by the trusted tenant, run in the caller's transaction (or open one) and leave the audit entry and the
 * outbox message to the caller, in that same transaction.
 * @param {{ db: any, entitlements?: any }} deps
 */
export function createExecutionCancellation({ db, entitlements }) {
  const executions = createExecutionRepository({ db, entitlements });
  return Object.freeze({
    /**
     * `queued -> cancelled` by compare-and-set; of any number of racing cancels and claims exactly one wins and only the
     * winner releases the unit (`quota_released_at` is set in the same statement, the trigger refuses a second write).
     * @param {{ tenantId: string, executionId: string, reason: string, actor?: { type: "system" | "user", userId?: string }, correlationId?: string, eventDetails?: Record<string, unknown> }} input
     * @param {any} [client] Prisma client or the caller's transaction client.
     * @returns {Promise<{ cancelled: boolean, quotaReleased: boolean, statusRev: number | null }>}
     */
    async cancelQueued(
      { tenantId, executionId, reason, actor, correlationId, eventDetails },
      client = db,
    ) {
      if (typeof reason !== "string" || !REASON.test(reason))
        throw new TypeError("a cancel needs a stable reason code");
      const done = await executions.transitionExecution(
        {
          tenantId,
          executionId,
          from: "queued",
          to: "cancelled",
          reason,
          releaseQuota: true,
          actor: actor ?? { type: "system" },
          correlationId,
          eventDetails: eventDetails ?? { reason },
        },
        client,
      );
      return {
        cancelled: done.transitioned,
        quotaReleased: done.quotaReleased,
        statusRev: done.execution?.statusRev ?? null,
      };
    },

    /**
     * Records a cancel request (ER-18) on a `preparing`/`running` execution: the four cancel columns are set ONCE (null to
     * value), a `cancel_requested` history row is appended, and nothing else changes: the status stays, no quota moves. A
     * second request (or a concurrent one) matches no row and changes nothing (`recorded: false`). `graceSeconds` bounds how
     * long running tasks may continue (`graceful`) or how long the holder waits for aborted ones (`immediate`).
     * @param {{ tenantId: string, executionId: string, userId: string, mode: "graceful" | "immediate", graceSeconds: number, correlationId?: string }} input
     * @param {any} [client]
     * @returns {Promise<{ recorded: boolean, status: string | null, cancelRequestedAt: Date | null, cancelMode: string | null, cancelGraceUntil: Date | null }>}
     */
    async requestCancel(
      { tenantId, executionId, userId, mode, graceSeconds, correlationId },
      client = db,
    ) {
      if (!EXECUTION_CANCEL_MODES.includes(mode)) throw new TypeError("unknown cancel mode");
      if (!Number.isFinite(graceSeconds) || graceSeconds < 0)
        throw new TypeError("graceSeconds must be a non-negative number");
      return withTransaction(client, async (tx) => {
        const rows = await tx.$queryRaw`
          UPDATE executions
          SET cancel_requested_at = now(), cancel_requested_by_user_id = ${userId}::uuid, cancel_mode = ${mode}::execution_cancel_mode,
              cancel_grace_until = now() + make_interval(secs => ${Number(graceSeconds)}::double precision), updated_at = now()
          WHERE id = ${executionId}::uuid AND tenant_id = ${tenantId}::uuid AND status IN ('preparing', 'running') AND cancel_requested_at IS NULL
          RETURNING status::text AS status, cancel_requested_at AS "cancelRequestedAt", cancel_mode::text AS "cancelMode",
                    cancel_grace_until AS "cancelGraceUntil"`;
        const row = rows[0];
        if (!row)
          return {
            recorded: false,
            status: null,
            cancelRequestedAt: null,
            cancelMode: null,
            cancelGraceUntil: null,
          };
        await executions.recordEvent(
          {
            tenantId,
            executionId,
            type: "cancel_requested",
            reason: "user_cancelled",
            actor: { type: "user", userId },
            correlationId,
            details: { mode, graceSeconds: Number(graceSeconds), status: row.status },
          },
          tx,
        );
        return { recorded: true, ...row };
      });
    },
  });
}
