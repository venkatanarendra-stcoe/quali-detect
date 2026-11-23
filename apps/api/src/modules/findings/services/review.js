import { AppError, NotFoundError } from "../../../errors/app-error.js";
import { toWrittenCommentDto } from "../mappers/lifecycle.js";
import {
  forbidden,
  mapFindingError,
  refuseSecretText,
  runFindingWrite,
  stateConflict,
} from "./lifecycle-support.js";

/**
 * The review side of the findings write API (Part B, docs/modules/findings/SPEC.md 5.7, 8.2): claim, record a decision, withdraw it,
 * take a false positive back to review, comment, and the bulk claim. Every method runs the one write transaction of
 * `runFindingWrite` (workspace not archived, the finding locked by tenant, workspace and id, `expectedRev` checked, an overdue
 * acceptance expired first) and returns the finding AS THE CALLER now sees it (the detail DTO with the per-caller
 * `lifecycle.allowedActions`), the shape of the E mock. Permissions of the route were checked by the central engine before this
 * code runs; the rules that need the data (status, ownership of a review) are checked here, inside the lock.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/lifecycle.js").createFindingsLifecycleRepository>,
 *   reads: ReturnType<typeof import("./read.js").createFindingsReadService>,
 *   clock?: () => Date,
 * }} deps
 */
export function createFindingsReviewService({ repository, reads, clock = () => new Date() }) {
  const deps = { repository, clock };
  const detail = (actor, ref) => reads.get(actor, ref);

  return Object.freeze({
    /**
     * `GET /review-queue` (the read service owns the paging; Part B routes it).
     * @param {any} actor @param {any} query validated `reviewQueueQuerySchema` output
     */
    reviewQueue: (actor, query) => reads.reviewQueue(actor, query),

    /** `POST /findings/{id}/claim` (SM-2, or an audited take-over). @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {{ expectedRev: number }} body */
    async claim(actor, ref, body) {
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        apply: (tx, finding, scope) =>
          repository.reviews.claim(tx, {
            scope,
            finding,
            userId: actor.userId,
            expectedRev: finding.rev,
          }),
      });
      return detail(actor, ref);
    },

    /** `POST /findings/{id}/reviews` (SM-3, RV-1). @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {any} body validated `createReviewBodySchema` output */
    async createReview(actor, ref, body) {
      refuseSecretText({ rationale: body.rationale });
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        apply: (tx, finding, scope) => {
          if (finding.status !== "new" && finding.status !== "in_review")
            throw stateConflict("transition_not_allowed");
          // a review on a finding with a pending exception is refused (SPEC 6.1)
          if (finding.pendingExceptionId) throw stateConflict("exception_pending");
          return repository.reviews.record(tx, {
            scope,
            finding,
            reviewerUserId: actor.userId,
            decision: body.decision,
            rationale: body.rationale,
            severityOverride: body.severityOverride ?? null,
            expectedRev: finding.rev,
          });
        },
      });
      return detail(actor, ref);
    },

    /** `POST /findings/{id}/reviews/{reviewId}/withdraw` (SM-4, SOD-3): only the reviewer. @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {string} reviewId @param {{ expectedRev: number }} body */
    async withdrawReview(actor, ref, reviewId, body) {
      let review = null;
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        before: async (tx, finding, scope) => {
          review = await repository.findReview(tx, scope, finding.id, reviewId);
          if (!review) throw new NotFoundError();
          if (review.reviewerUserId !== actor.userId) throw forbidden("not_reviewer");
        },
        apply: (tx, finding, scope) => {
          if (finding.status !== "awaiting_approval" || finding.pendingReviewId !== reviewId)
            throw stateConflict("already_decided");
          return repository.reviews.withdraw(tx, {
            scope,
            finding,
            reviewId,
            userId: actor.userId,
            expectedRev: finding.rev,
          });
        },
      });
      return detail(actor, ref);
    },

    /** `POST /findings/{id}/reopen-review` (SM-8, SM-18). @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {{ reason: string, expectedRev: number }} body */
    async reopenReview(actor, ref, body) {
      refuseSecretText({ reason: body.reason });
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        apply: (tx, finding, scope) => {
          if (finding.status !== "false_positive" && finding.status !== "reopened")
            throw stateConflict("transition_not_allowed");
          return repository.reviews.reopenForReview(tx, {
            scope,
            finding,
            userId: actor.userId,
            reason: body.reason,
            expectedRev: finding.rev,
          });
        },
      });
      return detail(actor, ref);
    },

    /**
     * `POST /findings/{id}/comments` (insert-only): any visible finding, `finding.comment` checked by the route. No `expectedRev`: a
     * comment is not a state change and does not move the revision.
     * @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {{ body: string }} body
     */
    async addComment(actor, ref, body) {
      refuseSecretText({ body: body.body });
      const row = await runFindingWrite(deps, actor, ref, {
        apply: (tx, finding, scope) =>
          repository.reviews.addComment(tx, {
            scope,
            finding,
            authorUserId: actor.userId,
            body: body.body,
          }),
      });
      return toWrittenCommentDto(row, await repository.displayNameOf(actor.tenantId, actor.userId));
    },

    /**
     * `POST /findings/bulk/claim` (D-29): at most 50 findings of ONE workspace, each authorized (the route authorized the caller in that
     * workspace), claimed and audited on its own; a finding the caller cannot see is reported as not found, never as forbidden.
     * @param {any} actor @param {{ workspaceId: string, findingIds: string[] }} body
     */
    async bulkClaim(actor, body) {
      const results = [];
      for (const findingId of body.findingIds) {
        try {
          await runFindingWrite(
            deps,
            actor,
            { id: findingId, workspaceId: body.workspaceId },
            {
              apply: (tx, finding, scope) => {
                if (finding.status !== "new") throw stateConflict("transition_not_allowed");
                return repository.reviews.claim(tx, {
                  scope,
                  finding,
                  userId: actor.userId,
                  expectedRev: finding.rev,
                });
              },
            },
          );
          results.push({ findingId, ok: true });
        } catch (error) {
          const e = mapFindingError(error);
          if (!(e instanceof AppError)) throw e;
          results.push({
            findingId,
            ok: false,
            errorCode: e.code,
            ...(typeof e.details?.reason === "string" ? { reason: e.details.reason } : {}),
          });
        }
      }
      return { results };
    },
  });
}
