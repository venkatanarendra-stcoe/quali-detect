import { Prisma } from "@prisma/client";
import { FindingConflictError } from "./errors.js";
import { createFindingsRepository } from "./findings.js";
import { emitFindingEvent, slaDueFor, writeFindingAudit } from "./lifecycle-support.js";
import { transitionFinding } from "./transitions.js";

/**
 * @typedef {import("./transitions.js").FindingScope} FindingScope
 * @typedef {{ type: "user", userId: string }} UserActor
 */

const MICROS_SQL = (col) =>
  Prisma.raw(`to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`);
const MICROS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The chain columns every child row of a finding carries (composite foreign key to the finding). @param {any} finding */
const chainOf = (finding) => ({
  tenantId: finding.tenantId,
  workspaceId: finding.workspaceId,
  repositoryId: finding.repositoryId,
  pipelineId: finding.pipelineId,
  findingId: finding.id,
});

/**
 * Review, approval, claim and comment rows (Part B, docs/modules/findings/SPEC.md 5.7, 6.1, 8.2). EVERY write method runs inside the
 * caller's transaction `tx` with the finding row ALREADY locked (`getForWrite(..., { forUpdate: true })`) and re-checked by the
 * service; the status always changes through `transitionFinding` (the one function, SPEC 6.2) with the actor set (a USER here, never
 * the system), and each write adds its history row (by the transition), its audit entry and its outbox event in the same transaction.
 * The database is the second lock: the SOD trigger refuses an approval by anyone who reviewed, or requested an exception on, the
 * finding (SPEC SOD-5).
 * @param {{ db: any }} deps
 */
export function createFindingReviewsRepository({ db }) {
  const reads = createFindingsRepository({ db });

  /** @param {any} tx @param {string} tenantId @param {string[]} ids @returns {Promise<Map<string, string>>} */
  async function names(tx, tenantId, ids) {
    const unique = [...new Set(ids.filter(Boolean))];
    if (unique.length === 0) return new Map();
    const rows = await tx.tenantMembership.findMany({
      where: { tenantId, userId: { in: unique } },
      select: { user: { select: { id: true, name: true } } },
    });
    return new Map(rows.map((r) => [r.user.id, r.user.name]));
  }

  return Object.freeze({
    /**
     * SM-2: `new` to `in_review` with the caller as claimant; or the audited take-over of another reviewer's claim on an `in_review`
     * finding (no status change: `rev` rises, the claimant changes).
     * @param {any} tx
     * @param {{ scope: FindingScope, finding: any, userId: string, expectedRev?: number }} input
     * @returns {Promise<{ rev: number, takeover: boolean }>}
     */
    async claim(tx, { scope, finding, userId, expectedRev }) {
      const actor = { type: /** @type {const} */ ("user"), userId };
      if (finding.status === "new") {
        const done = await transitionFinding(tx, {
          scope,
          findingId: finding.id,
          expectedRev,
          to: "in_review",
          actor,
          reasonCode: "review_started",
          columns: { claimedByUserId: userId },
        });
        return { rev: done.rev, takeover: false };
      }
      if (finding.status !== "in_review" || finding.claimedByUserId === userId)
        throw new FindingConflictError("transition_not_allowed");
      const rev = finding.rev + 1;
      await tx.finding.update({
        where: { tenantId_id: { tenantId: scope.tenantId, id: finding.id } },
        data: { claimedByUserId: userId, rev },
      });
      await writeFindingAudit(tx, scope, actor, "finding.review_started", finding.id, {
        takeover: true,
        previousClaimantUserId: finding.claimedByUserId ?? null,
        rev,
      });
      return { rev, takeover: true };
    },

    /**
     * RV-1, SM-3: inserts the (pending, immutable) review and moves the finding to `awaiting_approval` carrying the pending pointer;
     * from `new` the two history rows (SM-2, then SM-3) are written in this transaction. The latest advisory at this moment is
     * recorded as a reference only (RV-3). Inserts the review row for the transition: a conflict rolls both back.
     * @type {(tx: any, input: { scope: FindingScope, finding: any, reviewerUserId: string, decision: string, rationale: string, severityOverride?: string | null, expectedRev?: number }) => Promise<{ reviewId: string, rev: number }>}
     */
    async record(
      tx,
      { scope, finding, reviewerUserId, decision, rationale, severityOverride, expectedRev },
    ) {
      const actor = { type: /** @type {const} */ ("user"), userId: reviewerUserId };
      const advisory = await tx.findingAiAdvisory.findFirst({
        where: { tenantId: scope.tenantId, findingId: finding.id, status: "ok" },
        orderBy: { createdAt: "desc" },
        select: { id: true },
      });
      const review = await tx.findingReview.create({
        data: {
          ...chainOf(finding),
          reviewerUserId,
          decision,
          rationale,
          severityOverride: severityOverride ?? null,
          advisoryIdAtDecision: advisory?.id ?? null,
        },
        select: { id: true },
      });
      let rev = expectedRev;
      if (finding.status === "new") {
        const step = await transitionFinding(tx, {
          scope,
          findingId: finding.id,
          expectedRev: rev,
          to: "in_review",
          actor,
          reasonCode: "review_started",
          columns: { claimedByUserId: reviewerUserId },
        });
        rev = step.rev;
      }
      const done = await transitionFinding(tx, {
        scope,
        findingId: finding.id,
        expectedRev: rev,
        to: "awaiting_approval",
        actor,
        reasonCode: "review_recorded",
        note: rationale,
        columns: { pendingReviewId: review.id, claimedByUserId: reviewerUserId },
      });
      await emitFindingEvent(
        tx,
        scope,
        finding,
        actor,
        "finding.review_recorded",
        `finding-review-${review.id}`,
        {
          findingId: finding.id,
          workspaceId: scope.workspaceId,
          reviewId: review.id,
          decision,
          rev: done.rev,
        },
      );
      return { reviewId: review.id, rev: done.rev };
    },

    /**
     * SM-4 / SOD-3: the reviewer withdraws the pending review; the finding returns to `in_review`.
     * @type {(tx: any, input: { scope: FindingScope, finding: any, reviewId: string, userId: string, expectedRev?: number }) => Promise<{ rev: number }>}
     */
    async withdraw(tx, { scope, finding, reviewId, userId, expectedRev }) {
      const moved = await tx.findingReview.updateMany({
        where: {
          tenantId: scope.tenantId,
          findingId: finding.id,
          id: reviewId,
          state: "pending",
          reviewerUserId: userId,
        },
        data: { state: "withdrawn", decidedAt: new Date() },
      });
      if (moved.count !== 1) throw new FindingConflictError("already_decided");
      const done = await transitionFinding(tx, {
        scope,
        findingId: finding.id,
        expectedRev,
        to: "in_review",
        actor: { type: "user", userId },
        reasonCode: "review_withdrawn",
        columns: { pendingReviewId: null },
      });
      return { rev: done.rev };
    },

    /**
     * SM-5, SM-6, SM-7 (RV-2): inserts the approval row (the SOD trigger may refuse it), advances the review out of `pending` and
     * moves the finding: approve of a true positive applies the severity override and recomputes the SLA (audited as
     * `finding.severity_overridden`); approve of a false positive stops the SLA; a rejection returns the finding to `in_review`.
     * @type {(tx: any, input: { scope: FindingScope, finding: any, review: { id: string, decision: string, severityOverride?: string | null }, approverUserId: string, decision: "approve" | "reject", comment?: string, expectedRev?: number }) => Promise<{ approvalId: string, rev: number }>}
     */
    async decide(tx, { scope, finding, review, approverUserId, decision, comment, expectedRev }) {
      const actor = { type: /** @type {const} */ ("user"), userId: approverUserId };
      const approval = await tx.findingApproval.create({
        data: {
          ...chainOf(finding),
          reviewId: review.id,
          approverUserId,
          decision,
          comment: comment ?? null,
        },
        select: { id: true },
      });
      const moved = await tx.findingReview.updateMany({
        where: { tenantId: scope.tenantId, findingId: finding.id, id: review.id, state: "pending" },
        data: { state: decision === "approve" ? "approved" : "rejected", decidedAt: new Date() },
      });
      if (moved.count !== 1) throw new FindingConflictError("already_decided");

      /** @type {Record<string, unknown>} */
      const columns = { pendingReviewId: null };
      let to;
      let reasonCode;
      let override = null;
      if (decision === "reject") {
        to = "in_review";
        reasonCode = "rejected";
      } else if (review.decision === "false_positive") {
        to = "false_positive";
        reasonCode = "approved_fp";
      } else {
        to = "approved";
        reasonCode = "approved_tp";
        override = review.severityOverride ?? null;
        columns.severityOverride = override;
        const next = override ?? finding.toolSeverity;
        if (next !== finding.severity && finding.slaDueAt && finding.slaStartedAt)
          columns.slaDueAt = await slaDueFor(tx, scope.tenantId, next, finding.slaStartedAt);
      }
      const done = await transitionFinding(tx, {
        scope,
        findingId: finding.id,
        expectedRev,
        to,
        actor,
        reasonCode,
        note: comment,
        columns,
      });
      if (to === "approved" && (override ?? finding.toolSeverity) !== finding.severity)
        await writeFindingAudit(tx, scope, actor, "finding.severity_overridden", finding.id, {
          previous: finding.severity,
          next: override ?? finding.toolSeverity,
          reviewId: review.id,
          rev: done.rev,
        });
      await emitFindingEvent(
        tx,
        scope,
        finding,
        actor,
        "finding.approval_decided",
        `finding-approval-${approval.id}`,
        {
          findingId: finding.id,
          workspaceId: scope.workspaceId,
          approvalId: approval.id,
          kind: "review",
          decision,
          rev: done.rev,
        },
      );
      return { approvalId: approval.id, rev: done.rev };
    },

    /**
     * SM-8 / SM-18: a reviewer takes a `false_positive` or `reopened` finding back to review (a reason is required).
     * @type {(tx: any, input: { scope: FindingScope, finding: any, userId: string, reason: string, expectedRev?: number }) => Promise<{ rev: number }>}
     */
    async reopenForReview(tx, { scope, finding, userId, reason, expectedRev }) {
      const done = await transitionFinding(tx, {
        scope,
        findingId: finding.id,
        expectedRev,
        to: "in_review",
        actor: { type: "user", userId },
        reasonCode: finding.status === "reopened" ? "rereview" : "fp_reopened",
        note: reason,
        columns: { claimedByUserId: userId },
      });
      return { rev: done.rev };
    },

    /**
     * Distinct users who recorded a review on the finding (any round).
     * @type {(scope: FindingScope, findingId: string, tx?: any) => Promise<string[]>}
     */
    async reviewerIds(scope, findingId, tx = db) {
      const rows = await tx.findingReview.findMany({
        where: { tenantId: scope.tenantId, findingId },
        distinct: ["reviewerUserId"],
        select: { reviewerUserId: true },
      });
      return rows.map((r) => r.reviewerUserId);
    },

    /**
     * Every user who may NOT approve or reject on this finding (SOD-1): any reviewer of any round and any requester of an
     * exception. The same union the database trigger checks.
     * @type {(scope: FindingScope, findingId: string, tx?: any) => Promise<string[]>}
     */
    async sodBlockedIds(scope, findingId, tx = db) {
      const [reviewers, requesters] = await Promise.all([
        tx.findingReview.findMany({
          where: { tenantId: scope.tenantId, findingId },
          distinct: ["reviewerUserId"],
          select: { reviewerUserId: true },
        }),
        tx.findingException.findMany({
          where: { tenantId: scope.tenantId, findingId },
          distinct: ["requestedByUserId"],
          select: { requestedByUserId: true },
        }),
      ]);
      return [
        ...new Set([
          ...reviewers.map((r) => r.reviewerUserId),
          ...requesters.map((r) => r.requestedByUserId),
        ]),
      ];
    },

    /**
     * `GET /approvals`: the pending decision requests of the workspace (reviews awaiting approval and pending exceptions), oldest
     * first (`(created_at, id)`), numbered (`offset`) or keyset (`after`). Each item carries the hydrated finding entry (the list-item
     * source), the requester and a short preview; the caller's `canDecide` is computed by the API (it needs the caller).
     * @type {(scope: FindingScope, query: { kind?: "review" | "exception", severity?: string[], pipelineId?: string, limit: number, offset?: number, after?: Array<string | null> | null, withTotal?: boolean }) => Promise<{ items: object[], totalItems?: number, hasMore: boolean, nextKey: Array<string | null> | null }>}
     */
    async pendingApprovals(scope, query) {
      const { tenantId, workspaceId } = scope;
      const limit = query.limit;
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new TypeError("limit");
      const offset = query.offset ?? 0;
      if (!Number.isInteger(offset) || offset < 0 || offset > 10000) throw new TypeError("offset");
      if (query.after && offset > 0) throw new TypeError("offset with cursor");
      if (query.pipelineId && !UUID.test(query.pipelineId)) throw new TypeError("pipelineId");
      const conditions = [
        query.severity?.length
          ? Prisma.sql`AND f.severity::text = ANY(${query.severity}::text[])`
          : null,
        query.pipelineId ? Prisma.sql`AND f.pipeline_id = ${query.pipelineId}::uuid` : null,
      ].filter(Boolean);
      const filters = conditions.length > 0 ? Prisma.join(conditions, " ") : Prisma.empty;
      const parts = [];
      if (query.kind !== "exception")
        parts.push(Prisma.sql`
          SELECT 'review'::text AS kind, r.id::text AS id, r.finding_id::text AS finding_id, r.created_at AS at, r.reviewer_user_id::text AS by_user,
                 r.decision::text AS decision, r.rationale AS text, NULL::timestamptz AS expires_at, NULL::text AS exception_kind
            FROM finding_reviews r
            JOIN findings f ON f.tenant_id = r.tenant_id AND f.id = r.finding_id AND f.pending_review_id = r.id
           WHERE r.tenant_id = ${tenantId}::uuid AND r.workspace_id = ${workspaceId}::uuid AND r.state = 'pending' AND f.status = 'awaiting_approval' ${filters}`);
      if (query.kind !== "review")
        parts.push(Prisma.sql`
          SELECT 'exception'::text AS kind, e.id::text AS id, e.finding_id::text AS finding_id, e.created_at AS at, e.requested_by_user_id::text AS by_user,
                 NULL::text AS decision, e.justification AS text, e.expires_at AS expires_at, e.kind::text AS exception_kind
            FROM finding_exceptions e
            JOIN findings f ON f.tenant_id = e.tenant_id AND f.id = e.finding_id AND f.pending_exception_id = e.id
           WHERE e.tenant_id = ${tenantId}::uuid AND e.workspace_id = ${workspaceId}::uuid AND e.state = 'pending' ${filters}`);
      const union = Prisma.join(parts, " UNION ALL ");
      let cursor = Prisma.empty;
      if (query.after) {
        const [position, id] = query.after;
        // the decoded cursor carries the time as a `microDate` (a Date with its exact `micros` text) or as that text
        const at = typeof position === "string" ? position : position?.micros;
        if (!MICROS.test(String(at)) || !UUID.test(String(id)))
          throw new TypeError("cursor position");
        cursor = Prisma.sql`WHERE (t.at, t.id) > (${at}::timestamptz, ${id}::text)`;
      }
      const [rows, counted] = await Promise.all([
        db.$queryRaw`
          SELECT t.*, ${MICROS_SQL("t.at")} AS at_key FROM (${union}) t ${cursor}
          ORDER BY t.at ASC, t.id ASC LIMIT ${limit + 1} OFFSET ${offset}`,
        query.withTotal
          ? db.$queryRaw`SELECT count(*)::int AS n FROM (${union}) t`
          : Promise.resolve(null),
      ]);
      const hasMore = rows.length > limit;
      const page = rows.slice(0, limit);
      const entries = await reads.hydrate(scope, [...new Set(page.map((r) => r.finding_id))]);
      const byFinding = new Map(entries.map((e) => [e.finding.id, e]));
      const people = await names(
        db,
        tenantId,
        page.map((r) => r.by_user),
      );
      const last = page.at(-1);
      return {
        items: page
          .filter((r) => byFinding.has(r.finding_id))
          .map((r) => ({
            kind: r.kind,
            requestId: r.id,
            entry: byFinding.get(r.finding_id),
            requestedBy: { id: r.by_user, displayName: people.get(r.by_user) ?? "Former member" },
            submittedAt: r.at,
            decision: r.decision,
            text: r.text,
            expiresAt: r.expires_at,
            exceptionKind: r.exception_kind,
          })),
        ...(counted ? { totalItems: counted[0].n } : {}),
        hasMore,
        nextKey: hasMore && last ? [last.at_key, last.id] : null,
      };
    },

    /**
     * Inserts a comment (insert-only table): audit, event; no change to the finding row (no `rev` change).
     * @type {(tx: any, input: { scope: FindingScope, finding: any, authorUserId: string, body: string }) => Promise<{ id: string, authorUserId: string, body: string, createdAt: Date }>}
     */
    async addComment(tx, { scope, finding, authorUserId, body }) {
      const actor = { type: /** @type {const} */ ("user"), userId: authorUserId };
      const row = await tx.findingComment.create({
        data: { ...chainOf(finding), authorUserId, body },
        select: { id: true, authorUserId: true, body: true, createdAt: true },
      });
      await writeFindingAudit(tx, scope, actor, "finding.comment_added", finding.id, {
        commentId: row.id,
      });
      await emitFindingEvent(
        tx,
        scope,
        finding,
        actor,
        "finding.comment_added",
        `finding-comment-${row.id}`,
        { findingId: finding.id, workspaceId: scope.workspaceId, commentId: row.id },
      );
      return row;
    },
  });
}
