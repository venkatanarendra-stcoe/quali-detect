import { OPENAPI_TAGS } from "../constants/index.js";
import { createFindingsReviewController } from "../controllers/review.js";
import { createFindingsLifecycleRepository } from "../repositories/lifecycle.js";
import { findingScope, workspaceQueryScope } from "../repositories/read-scopes.js";
import { workspaceBodyScope } from "../repositories/write-scopes.js";
import {
  bulkClaimBodySchema,
  claimBodySchema,
  createCommentBodySchema,
  createReviewBodySchema,
  findingParamsSchema,
  reopenReviewBodySchema,
  reviewParamsSchema,
  reviewQueueQuerySchema,
  withdrawReviewBodySchema,
} from "../schemas/index.js";
import { lifecycleResponses } from "../schemas/lifecycle.js";
import { readResponses } from "../schemas/read.js";
import { createFindingsReadService } from "../services/read.js";
import { createFindingsReviewService } from "../services/review.js";

/**
 * Findings routes, part B: the Reviews queue, claim, record a decision, withdraw it, take a finding back to review, comment and the
 * bulk claim (docs/modules/findings/SPEC.md 8.1, 8.2). Every route authorizes in the finding's OWN workspace (the finding is loaded by
 * tenant and id; a hidden, foreign or missing finding is the identical 404, a visible one without the key is 403), takes an
 * `Idempotency-Key` and the `write` rate limit, and answers with the finding as the caller now sees it. `expectedRev` of the body is
 * the optimistic-concurrency token (`409 FINDING_STATE_CONFLICT` when stale). `/findings/bulk/claim` is registered BEFORE the item
 * routes. The route keys and their permissions are frozen in `PERMISSION_BY_ROUTE` of `@qmentisai/shared`.
 * @param {import("./index.js").FindingsRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const findingsReviewRoutes = (deps) =>
  async function register(app) {
    const { authz } = deps;
    const repository = createFindingsLifecycleRepository({ db: deps.db });
    const reads = createFindingsReadService({ repository: repository.reads });
    const service = createFindingsReviewService({ repository, reads });
    const controller = createFindingsReviewController({ service });
    const tags = [OPENAPI_TAGS.reviews];
    const config = { audience: "tenant" };
    const inWorkspace = (key, scope = findingScope()) => authz.authorize(key, scope);
    const reviewGate = inWorkspace("finding.review");
    const commentGate = inWorkspace("finding.comment");

    app.get(
      "/review-queue",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("security_review.view", workspaceQueryScope()),
        schema: {
          tags,
          summary: "The Reviews queue: findings awaiting a decision, oldest first",
          querystring: reviewQueueQuerySchema,
          response: { 200: readResponses.list },
        },
      },
      controller.reviewQueue,
    );

    app.post(
      "/findings/bulk/claim",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: inWorkspace("finding.review", workspaceBodyScope()),
        schema: {
          tags,
          summary: "Start review on up to 50 findings of one workspace (per-item result)",
          body: bulkClaimBodySchema,
          response: { 200: lifecycleResponses.bulk },
        },
      },
      controller.bulkClaim,
    );

    app.post(
      "/findings/:id/claim",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: reviewGate,
        schema: {
          tags,
          summary: "Start review (claim) of a new finding, or take over a claim",
          params: findingParamsSchema,
          body: claimBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.claim,
    );
    app.post(
      "/findings/:id/reviews",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: reviewGate,
        schema: {
          tags,
          summary: "Record a true or false positive decision (it then awaits approval)",
          params: findingParamsSchema,
          body: createReviewBodySchema,
          response: { 201: lifecycleResponses.finding },
        },
      },
      controller.createReview,
    );
    app.post(
      "/findings/:id/reviews/:reviewId/withdraw",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: reviewGate,
        schema: {
          tags,
          summary: "Withdraw your own pending decision (back to in review)",
          params: reviewParamsSchema,
          body: withdrawReviewBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.withdrawReview,
    );
    app.post(
      "/findings/:id/reopen-review",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: reviewGate,
        schema: {
          tags,
          summary:
            "Take a false positive or reopened finding back to review (a reason is required)",
          params: findingParamsSchema,
          body: reopenReviewBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.reopenReview,
    );
    app.post(
      "/findings/:id/comments",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: commentGate,
        schema: {
          tags,
          summary: "Add a comment (insert-only; plain text, credential-shaped text is refused)",
          params: findingParamsSchema,
          body: createCommentBodySchema,
          response: { 201: lifecycleResponses.comment },
        },
      },
      controller.addComment,
    );
  };
