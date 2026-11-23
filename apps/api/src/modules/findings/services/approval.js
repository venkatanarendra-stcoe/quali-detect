import { FINDINGS_LIMITS, can } from "@qmentisai/shared";
import { NotFoundError, ValidationError } from "../../../errors/app-error.js";
import { cursorContext, microDate } from "../../../lib/keyset.js";
import { toApprovalItemDto } from "../mappers/lifecycle.js";
import { isSodBlocked } from "../policies/lifecycle.js";
import {
  auditApprovalRefusal,
  forbidden,
  refuseSecretText,
  runFindingWrite,
  stateConflict,
} from "./lifecycle-support.js";

const MAX_APPROVALS_OFFSET = 10000;
const CURSOR_KIND = "findings.approvals";

/**
 * Approve and reject of a REVIEW decision, and the Approvals queue (Part B, docs/modules/findings/SPEC.md 5.6, 5.7 RV-2, 8.1, 8.2).
 *
 * Segregation of duties is enforced here BEFORE anything is written (SOD-1: the approver may not be ANY user who recorded a review on
 * the finding, any round, nor the requester of an exception on it; user ids only, no role bypasses it), by the database trigger of
 * `finding_approvals` as the backstop, and shown to the caller as `canDecide` and as a disabled action. A refusal is `403 FORBIDDEN`
 * with `details.reason = "separation_of_duties"` and is audited (`finding.approval_denied`, both user ids and the decision id); a
 * lost race (the other approver won) is `409 FINDING_STATE_CONFLICT` and is audited the same way.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/lifecycle.js").createFindingsLifecycleRepository>,
 *   reads: ReturnType<typeof import("./read.js").createFindingsReadService>,
 *   clock?: () => Date,
 * }} deps
 */
export function createFindingsApprovalService({ repository, reads, clock = () => new Date() }) {
  const deps = { repository, clock };

  /** @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {string} reviewId @param {any} body @param {"approve" | "reject"} decision */
  async function decideReview(actor, ref, reviewId, body, decision) {
    refuseSecretText({ comment: body.comment });
    let review = null;
    try {
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        before: async (tx, finding, scope) => {
          review = await repository.findReview(tx, scope, finding.id, reviewId);
          if (!review) throw new NotFoundError();
          const blocked = await repository.reviews.sodBlockedIds(scope, finding.id, tx);
          if (isSodBlocked(blocked, actor.userId)) throw forbidden("separation_of_duties");
        },
        apply: (tx, finding, scope) => {
          const r = /** @type {any} */ (review);
          if (
            finding.status !== "awaiting_approval" ||
            finding.pendingReviewId !== reviewId ||
            r.state !== "pending"
          )
            throw stateConflict("already_decided");
          return repository.reviews.decide(tx, {
            scope,
            finding,
            review: r,
            approverUserId: actor.userId,
            decision,
            comment: body.comment,
            expectedRev: finding.rev,
          });
        },
      });
    } catch (error) {
      await auditApprovalRefusal(repository, actor, ref, error, {
        kind: "review",
        decisionId: reviewId,
        counterpartUserId: /** @type {any} */ (review)?.reviewerUserId ?? null,
      });
      throw error;
    }
    return reads.get(actor, ref);
  }

  return Object.freeze({
    /** `POST /findings/{id}/reviews/{reviewId}/approve` (SM-5, SM-6). */
    approveReview: (actor, ref, reviewId, body) =>
      decideReview(actor, ref, reviewId, body, "approve"),
    /** `POST /findings/{id}/reviews/{reviewId}/reject` (SM-7); a comment is required (the schema). */
    rejectReview: (actor, ref, reviewId, body) =>
      decideReview(actor, ref, reviewId, body, "reject"),

    /**
     * `GET /approvals`: pending reviews and pending exceptions of one workspace, oldest first, with `canDecide` and
     * `cannotDecideReason` computed for THIS caller (`separation_of_duties`, `missing_permission`). Numbered pages (`page`, `pageSize`)
     * or keyset (`cursor`, `limit`, signed and bound to the filters, the workspace and the tenant).
     * @param {{ tenantId: string, userId: string, permissions: any }} actor @param {any} query validated `approvalsQuerySchema` output
     */
    async approvals(actor, query) {
      const numbered = query.page !== undefined || query.pageSize !== undefined;
      const limit = numbered
        ? (query.pageSize ?? FINDINGS_LIMITS.defaultPageSize)
        : (query.limit ?? FINDINGS_LIMITS.defaultPageSize);
      const page = query.page ?? 1;
      if (numbered && (page - 1) * limit > MAX_APPROVALS_OFFSET)
        throw new ValidationError(
          [
            {
              path: "page",
              code: "custom",
              message: "The requested page is too deep. Use a cursor or a filter.",
            },
          ],
          { source: "querystring" },
        );
      const scope = { tenantId: actor.tenantId, workspaceId: query.workspaceId };
      const cursor = cursorContext({
        kind: CURSOR_KIND,
        scope: `tenant:${actor.tenantId}`,
        query: { ...query, sort: "submittedAt:asc" },
        specs: {},
        terms: [
          { field: "at", direction: "asc", type: "date", nullable: false, column: "created_at" },
          { field: "id", direction: "asc", type: "uuid", nullable: false },
        ],
        extra: { workspaceId: query.workspaceId },
      });
      const result = await repository.reviews.pendingApprovals(scope, {
        kind: query.kind,
        severity: query.severity,
        pipelineId: query.pipelineId,
        limit,
        offset: numbered ? (page - 1) * limit : 0,
        after: cursor.after,
        withTotal: numbered,
      });
      const here = { type: /** @type {const} */ ("workspace"), workspaceId: query.workspaceId };
      const canApprove = can(actor.permissions, "approval.approve", here);
      const canReject = can(actor.permissions, "approval.reject", here);
      const sod = await repository.sodUserIdsByFinding(
        scope,
        result.items.map((i) => i.entry.finding.id),
      );
      const now = clock();
      const next = cursor.next({
        hasMore: result.hasMore,
        nextKey: result.nextKey ? [microDate(result.nextKey[0]), result.nextKey[1]] : null,
      });
      return {
        items: result.items.map((row) =>
          toApprovalItemDto(row, {
            now,
            callerUserId: actor.userId,
            canApprove,
            canReject,
            sodUserIds: sod.get(row.entry.finding.id) ?? [],
          }),
        ),
        pagination: {
          limit,
          ...next,
          ...(numbered
            ? {
                page,
                pageSize: limit,
                totalItems: result.totalItems ?? 0,
                totalPages: Math.ceil((result.totalItems ?? 0) / limit),
              }
            : {}),
        },
      };
    },
  });
}
