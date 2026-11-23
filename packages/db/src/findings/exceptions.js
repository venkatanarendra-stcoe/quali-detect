import { FindingConflictError } from "./errors.js";
import { emitFindingEvent, writeFindingAudit } from "./lifecycle-support.js";
import { transitionFinding } from "./transitions.js";
import { withTransaction } from "../transaction.js";
import { EXCEPTION_SOURCE_STATUSES } from "@qmentisai/shared";

/**
 * @typedef {import("./transitions.js").FindingScope} FindingScope
 * @typedef {{ type: "user", userId: string } | { type: "system", code: "expiry" }} ExceptionActor
 */

/** The chain columns every child row of a finding carries. @param {any} finding */
const chainOf = (finding) => ({
  tenantId: finding.tenantId,
  workspaceId: finding.workspaceId,
  repositoryId: finding.repositoryId,
  pipelineId: finding.pipelineId,
  findingId: finding.id,
});

/**
 * Accept-risk and suppression exceptions (Part B, docs/modules/findings/SPEC.md 5.8, EX-1 to EX-7). Every write method runs in the
 * caller's transaction with the finding row locked and re-checked by the service. A request, a rejection and a withdrawal do NOT change
 * the finding's status (EX-1, EX-2): only the pending pointer and `rev` move (the trigger demands `rev + 1` on every update), so there is
 * no history row for them; the timeline reads the exception rows themselves. Approval, revocation and expiry change the status through
 * `transitionFinding`.
 * @param {{ db: any }} deps
 */
export function createFindingExceptionsRepository({ db }) {
  /**
   * Ends an approved exception: the exception row, then the finding to `reopened` (SM-21). The actor is the system (expiry) or a user
   * (revocation).
   */
  async function endApproved(
    tx,
    { scope, finding, exception, endState, reasonCode, actor, note, expectedRev, now },
  ) {
    const moved = await tx.findingException.updateMany({
      where: {
        tenantId: scope.tenantId,
        findingId: finding.id,
        id: exception.id,
        state: "approved",
      },
      data: { state: endState, stateReason: reasonCode, endedAt: now },
    });
    if (moved.count !== 1) throw new FindingConflictError("already_decided");
    const done = await transitionFinding(tx, {
      scope,
      findingId: finding.id,
      expectedRev,
      to: "reopened",
      actor,
      reasonCode,
      note,
      columns: {
        activeExceptionId: null,
        exceptionExpiresAt: null,
        acceptedSeverity: null,
        reopenCount: { increment: 1 },
        absentCount: 0,
        fixClaimedAt: null,
        closedAt: null,
      },
    });
    if (endState === "expired")
      await emitFindingEvent(
        tx,
        scope,
        finding,
        actor,
        "finding.exception_expired",
        `finding-exception-expired-${exception.id}`,
        {
          findingId: finding.id,
          workspaceId: scope.workspaceId,
          exceptionId: exception.id,
          kind: exception.kind,
          rev: done.rev,
        },
      );
    else
      await emitFindingEvent(
        tx,
        scope,
        finding,
        actor,
        "finding.exception_decided",
        `finding-exception-${endState}-${exception.id}`,
        {
          findingId: finding.id,
          workspaceId: scope.workspaceId,
          exceptionId: exception.id,
          kind: exception.kind,
          decision: "revoke",
          rev: done.rev,
        },
      );
    await emitFindingEvent(
      tx,
      scope,
      finding,
      actor,
      "finding.reopened",
      `finding-reopened-${finding.id}-${done.rev}`,
      { findingId: finding.id, workspaceId: scope.workspaceId, reason: reasonCode, rev: done.rev },
    );
    return { rev: done.rev };
  }

  const api = {
    /**
     * EX-1: inserts a `pending` exception and sets the finding's pending pointer; the status is unchanged. `accepted_severity` is
     * the finding's effective severity at the request (EX-5 compares against it). `now` is the service's clock: it is the exception's
     * `created_at`, so the expiry window the service validated is the one the database CHECK sees.
     * @type {(tx: any, input: { scope: FindingScope, finding: any, kind: "accept_risk" | "suppress", requestedByUserId: string, justification: string, compensatingControls?: string | null, expiresAt?: Date | null, requestedApproverUserId?: string | null, now: Date }) => Promise<{ exceptionId: string, rev: number }>}
     */
    async request(
      tx,
      {
        scope,
        finding,
        kind,
        requestedByUserId,
        justification,
        compensatingControls,
        expiresAt,
        requestedApproverUserId,
        now,
      },
    ) {
      if (!EXCEPTION_SOURCE_STATUSES.includes(finding.status))
        throw new FindingConflictError("transition_not_allowed");
      if (finding.pendingExceptionId) throw new FindingConflictError("exception_pending");
      const actor = { type: /** @type {const} */ ("user"), userId: requestedByUserId };
      const row = await tx.findingException.create({
        data: {
          ...chainOf(finding),
          kind,
          requestedByUserId,
          justification,
          compensatingControls: compensatingControls ?? null,
          requestedApproverUserId: requestedApproverUserId ?? null,
          expiresAt: expiresAt ?? null,
          acceptedSeverity: finding.severity,
          createdAt: now,
        },
        select: { id: true },
      });
      const rev = finding.rev + 1;
      await tx.finding.update({
        where: { tenantId_id: { tenantId: scope.tenantId, id: finding.id } },
        data: { pendingExceptionId: row.id, rev },
      });
      await writeFindingAudit(tx, scope, actor, "finding.exception_requested", finding.id, {
        exceptionId: row.id,
        kind,
        rev,
      });
      await emitFindingEvent(
        tx,
        scope,
        finding,
        actor,
        "finding.exception_requested",
        `finding-exception-requested-${row.id}`,
        { findingId: finding.id, workspaceId: scope.workspaceId, exceptionId: row.id, kind, rev },
      );
      return { exceptionId: row.id, rev };
    },

    /**
     * EX-2: the requester withdraws a pending request (no status change).
     * @type {(tx: any, input: { scope: FindingScope, finding: any, exception: { id: string, kind: string }, userId: string }) => Promise<{ rev: number }>}
     */
    async withdraw(tx, { scope, finding, exception, userId }) {
      const actor = { type: /** @type {const} */ ("user"), userId };
      const moved = await tx.findingException.updateMany({
        where: {
          tenantId: scope.tenantId,
          findingId: finding.id,
          id: exception.id,
          state: "pending",
          requestedByUserId: userId,
        },
        data: { state: "withdrawn", stateReason: "withdrawn", endedAt: new Date() },
      });
      if (moved.count !== 1) throw new FindingConflictError("already_decided");
      const rev = finding.rev + 1;
      await tx.finding.update({
        where: { tenantId_id: { tenantId: scope.tenantId, id: finding.id } },
        data: { pendingExceptionId: null, rev },
      });
      await writeFindingAudit(tx, scope, actor, "finding.exception_withdrawn", finding.id, {
        exceptionId: exception.id,
        kind: exception.kind,
        rev,
      });
      await emitFindingEvent(
        tx,
        scope,
        finding,
        actor,
        "finding.exception_decided",
        `finding-exception-withdrawn-${exception.id}`,
        {
          findingId: finding.id,
          workspaceId: scope.workspaceId,
          exceptionId: exception.id,
          kind: exception.kind,
          decision: "withdraw",
          rev,
        },
      );
      return { rev };
    },

    /**
     * SM-19, SM-20, EX-2: inserts the approval row (the SOD trigger may refuse it) and settles the exception. Approve moves the
     * finding to `accepted_risk` or `suppressed` (SLA stops); reject leaves the status alone and clears the pending pointer.
     * @type {(tx: any, input: { scope: FindingScope, finding: any, exception: { id: string, kind: "accept_risk" | "suppress", expiresAt: Date | null, acceptedSeverity: string }, approverUserId: string, decision: "approve" | "reject", comment?: string, expectedRev?: number }) => Promise<{ approvalId: string, rev: number }>}
     */
    async decide(
      tx,
      { scope, finding, exception, approverUserId, decision, comment, expectedRev },
    ) {
      const actor = { type: /** @type {const} */ ("user"), userId: approverUserId };
      const approval = await tx.findingApproval.create({
        data: {
          ...chainOf(finding),
          exceptionId: exception.id,
          approverUserId,
          decision,
          comment: comment ?? null,
        },
        select: { id: true },
      });
      const now = new Date();
      const moved = await tx.findingException.updateMany({
        where: {
          tenantId: scope.tenantId,
          findingId: finding.id,
          id: exception.id,
          state: "pending",
        },
        data:
          decision === "approve"
            ? { state: "approved", decidedAt: now }
            : { state: "rejected", stateReason: "rejected", decidedAt: now, endedAt: now },
      });
      if (moved.count !== 1) throw new FindingConflictError("already_decided");
      let rev;
      if (decision === "approve") {
        const done = await transitionFinding(tx, {
          scope,
          findingId: finding.id,
          expectedRev,
          to: exception.kind === "accept_risk" ? "accepted_risk" : "suppressed",
          actor,
          reasonCode: exception.kind === "accept_risk" ? "risk_accepted" : "suppressed",
          note: comment,
          columns: {
            pendingExceptionId: null,
            activeExceptionId: exception.id,
            exceptionExpiresAt: exception.expiresAt ?? null,
            acceptedSeverity: exception.acceptedSeverity,
          },
        });
        rev = done.rev;
      } else {
        rev = finding.rev + 1;
        await tx.finding.update({
          where: { tenantId_id: { tenantId: scope.tenantId, id: finding.id } },
          data: { pendingExceptionId: null, rev },
        });
        await writeFindingAudit(tx, scope, actor, "finding.exception_decided", finding.id, {
          exceptionId: exception.id,
          kind: exception.kind,
          decision: "reject",
          rev,
        });
      }
      await emitFindingEvent(
        tx,
        scope,
        finding,
        actor,
        "finding.exception_decided",
        `finding-exception-decided-${exception.id}`,
        {
          findingId: finding.id,
          workspaceId: scope.workspaceId,
          exceptionId: exception.id,
          kind: exception.kind,
          decision,
          rev,
        },
      );
      return { approvalId: approval.id, rev };
    },

    /**
     * SM-21: ends an approved exception and reopens the finding (expired, revoked or invalidated). The generic form behind `revoke` and
     * `expireIfDue`; `endState` and `reasonCode` must agree (`expired` with `risk_acceptance_expired` or `suppression_expired`,
     * `revoked` with `revoked`, `invalidated` with `severity_increased`).
     * @type {(tx: any, input: { scope: FindingScope, finding: any, exception: { id: string, kind: "accept_risk" | "suppress" }, endState: "expired" | "revoked" | "invalidated", reasonCode: string, actor: ExceptionActor, note?: string, expectedRev?: number, now: Date }) => Promise<{ rev: number }>}
     */
    end: endApproved,

    /**
     * EX-4, SM-21: a holder of `finding.accept_risk` / `finding.suppress` revokes an active exception (a reason is required); the
     * finding goes to `reopened` and its SLA restarts.
     * @type {(tx: any, input: { scope: FindingScope, finding: any, exception: { id: string, kind: "accept_risk" | "suppress" }, userId: string, reason: string, expectedRev?: number }) => Promise<{ rev: number }>}
     */
    async revoke(tx, { scope, finding, exception, userId, reason, expectedRev }) {
      return endApproved(tx, {
        scope,
        finding,
        exception,
        endState: "revoked",
        reasonCode: "revoked",
        actor: { type: "user", userId },
        note: reason,
        expectedRev,
        now: new Date(),
      });
    },

    /**
     * EX-3, SM-21: the system ends an exception whose `expires_at` has passed (`system:expiry`). Idempotent: when the finding is no
     * longer in the accepted state, or the exception is not due, nothing happens. The finding row must be locked by the caller.
     * @type {(tx: any, scope: FindingScope, finding: any, now: Date) => Promise<{ expired: boolean, rev?: number }>}
     */
    async expireIfDue(tx, scope, finding, now) {
      if (
        !["accepted_risk", "suppressed"].includes(finding.status) ||
        !finding.activeExceptionId ||
        !finding.exceptionExpiresAt ||
        finding.exceptionExpiresAt.getTime() > now.getTime()
      )
        return { expired: false };
      const exception = await tx.findingException.findFirst({
        where: {
          tenantId: scope.tenantId,
          findingId: finding.id,
          id: finding.activeExceptionId,
          state: "approved",
        },
        select: { id: true, kind: true },
      });
      if (!exception) return { expired: false };
      const done = await endApproved(tx, {
        scope,
        finding,
        exception,
        endState: "expired",
        reasonCode:
          exception.kind === "accept_risk" ? "risk_acceptance_expired" : "suppression_expired",
        actor: { type: "system", code: "expiry" },
        expectedRev: undefined,
        now,
      });
      return { expired: true, rev: done.rev };
    },

    /**
     * Approved exceptions whose `expires_at` has passed, oldest first, in bounded batches (the expiry job). Reads across tenants
     * ONLY because the caller is the system job; each item is then expired in its own transaction under the tenant's scope.
     * @type {(now: Date, limit: number) => Promise<Array<{ tenantId: string, workspaceId: string, findingId: string, exceptionId: string }>>}
     */
    async dueForExpiry(now, limit) {
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new TypeError("limit");
      return db.$queryRaw`
        SELECT f.tenant_id::text AS "tenantId", f.workspace_id::text AS "workspaceId", f.id::text AS "findingId", e.id::text AS "exceptionId"
          FROM finding_exceptions e
          JOIN findings f ON f.tenant_id = e.tenant_id AND f.id = e.finding_id AND f.active_exception_id = e.id
         WHERE e.state = 'approved' AND e.expires_at IS NOT NULL AND e.expires_at <= ${now}
           AND f.status IN ('accepted_risk', 'suppressed')
         ORDER BY e.expires_at ASC, e.id ASC
         LIMIT ${limit}`;
    },

    /**
     * The job: expires up to `limit` due exceptions, each in its own transaction (a failure of one never blocks the others) with the
     * row locked by tenant, workspace and id. Returns the counters.
     * @type {(now: Date, limit: number, onError?: (error: unknown, ref: object) => void) => Promise<{ due: number, expired: number, skipped: number, failed: number }>}
     */
    async expireDue(now, limit, onError) {
      const due = await api.dueForExpiry(now, limit);
      const out = { due: due.length, expired: 0, skipped: 0, failed: 0 };
      for (const ref of due) {
        try {
          const result = await withTransaction(db, async (tx) => {
            const scope = { tenantId: ref.tenantId, workspaceId: ref.workspaceId };
            const rows = await tx.$queryRaw`
              SELECT id FROM findings
               WHERE tenant_id = ${ref.tenantId}::uuid AND workspace_id = ${ref.workspaceId}::uuid AND id = ${ref.findingId}::uuid
               FOR UPDATE`;
            if (rows.length === 0) return { expired: false };
            const finding = await tx.finding.findUnique({
              where: { tenantId_id: { tenantId: ref.tenantId, id: ref.findingId } },
            });
            return api.expireIfDue(tx, scope, finding, now);
          });
          if (result.expired) out.expired += 1;
          else out.skipped += 1;
        } catch (error) {
          out.failed += 1;
          onError?.(error, ref);
        }
      }
      return out;
    },
  };
  return Object.freeze(api);
}
