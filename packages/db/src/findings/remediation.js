import { FindingConflictError } from "./errors.js";
import { emitFindingEvent } from "./lifecycle-support.js";
import { transitionFinding } from "./transitions.js";

/**
 * @typedef {import("./transitions.js").FindingScope} FindingScope
 */

/**
 * Remediation and verification rows (Part C, docs/modules/findings/SPEC.md 5.7 RM-1, RM-2; verification rows are WRITTEN by the
 * ingestion path of A1, never here). EVERY write method runs inside the caller's transaction `tx` with the finding row ALREADY locked and
 * re-checked by the service. A remediation record references the finding's open assignment (a finding in `assigned` or `in_remediation`
 * always has one); the status moves through `transitionFinding` with a USER as the actor. Nothing here ever sets `verified_fixed` or
 * `reopened`: a person cannot verify what a scan has not (RM-2). `submit` only claims a fix (`fixed_pending_verification`,
 * `fix_claimed_at` set, `absent_count` 0); the next eligible scan decides.
 * @param {{ db: any }} deps
 */
export function createFindingRemediationRepository({ db }) {
  /** The open assignment of the finding (by tenant and finding) or null. */
  const openAssignment = (tx, tenantId, findingId) =>
    tx.findingAssignment.findFirst({
      where: { tenantId, findingId, endedAt: null },
      orderBy: { createdAt: "desc" },
      select: { id: true },
    });

  return Object.freeze({
    /**
     * SM-12 (`kind: "work_started"`, `assigned` to `in_remediation`) and SM-13 (`kind: "fix_submitted"`, `assigned` or `in_remediation`
     * to `fixed_pending_verification`). Inserts the record (the assignment it belongs to, the actor, the PR link, ticket key and note of
     * a submitted fix), then moves the finding through the transition function (history `work_started` or `fix_submitted`, audit
     * `finding.remediation_started` / `finding.fix_submitted`, the status hint). Event `finding.fix_submitted` for a submission.
     * @type {(tx: any, input: { scope: FindingScope, finding: any, kind: "work_started" | "fix_submitted", userId: string, pullRequestUrl?: string | null, ticketKey?: string | null, note?: string | null, expectedRev?: number }) => Promise<{ remediationId: string, rev: number }>}
     */
    async record(
      tx,
      { scope, finding, kind, userId, pullRequestUrl, ticketKey, note, expectedRev },
    ) {
      const actor = { type: /** @type {const} */ ("user"), userId };
      if (kind !== "work_started" && kind !== "fix_submitted") throw new TypeError("kind");
      const from = kind === "work_started" ? ["assigned"] : ["assigned", "in_remediation"];
      if (!from.includes(finding.status)) throw new FindingConflictError("transition_not_allowed");
      const assignment = await openAssignment(tx, scope.tenantId, finding.id);
      if (!assignment) throw new FindingConflictError("transition_not_allowed");
      const record = await tx.remediationRecord.create({
        data: {
          tenantId: scope.tenantId,
          workspaceId: scope.workspaceId,
          repositoryId: finding.repositoryId,
          pipelineId: finding.pipelineId,
          findingId: finding.id,
          assignmentId: assignment.id,
          kind,
          actorUserId: userId,
          pullRequestUrl: kind === "fix_submitted" ? (pullRequestUrl ?? null) : null,
          ticketKey: kind === "fix_submitted" ? (ticketKey ?? null) : null,
          note: note ?? null,
        },
        select: { id: true },
      });
      const done = await transitionFinding(tx, {
        scope,
        findingId: finding.id,
        expectedRev,
        to: kind === "work_started" ? "in_remediation" : "fixed_pending_verification",
        actor,
        reasonCode: kind === "work_started" ? "work_started" : "fix_submitted",
        ...(note ? { note } : {}),
        columns: kind === "fix_submitted" ? { fixClaimedAt: new Date(), absentCount: 0 } : {},
      });
      if (kind === "fix_submitted")
        await emitFindingEvent(
          tx,
          scope,
          finding,
          actor,
          "finding.fix_submitted",
          `finding-fix-submitted-${finding.id}-${done.rev}`,
          {
            findingId: finding.id,
            workspaceId: scope.workspaceId,
            remediationId: record.id,
            rev: done.rev,
          },
        );
      return { remediationId: record.id, rev: done.rev };
    },

    /**
     * Verification records of one finding, newest first (written by the ingestion path only). By tenant AND workspace AND finding.
     * @type {(scope: FindingScope, findingId: string) => Promise<object[]>}
     */
    async verifications(scope, findingId) {
      return db.verificationRecord.findMany({
        where: { tenantId: scope.tenantId, workspaceId: scope.workspaceId, findingId },
        orderBy: { createdAt: "desc" },
        select: { id: true, outcome: true, executionId: true, commitSha: true, createdAt: true },
        take: 100,
      });
    },
  });
}
