import { OPENAPI_TAGS } from "../constants/index.js";
import { createFindingsApprovalController } from "../controllers/approval.js";
import { createFindingsLifecycleRepository } from "../repositories/lifecycle.js";
import { findingScope, workspaceQueryScope } from "../repositories/read-scopes.js";
import {
  approvalsQuerySchema,
  approveBodySchema,
  rejectBodySchema,
  reviewParamsSchema,
} from "../schemas/index.js";
import { lifecycleResponses } from "../schemas/lifecycle.js";
import { createFindingsApprovalService } from "../services/approval.js";
import { createFindingsReadService } from "../services/read.js";

/**
 * Findings routes, part B: the Approvals queue and approve and reject of a review decision (docs/modules/findings/SPEC.md 8.1, 8.2).
 * Segregation of duties is enforced by the service (the approver is never a user who recorded a review on the finding) and by the
 * database trigger; the queue carries `canDecide` and `cannotDecideReason` for THE CALLER. Lead-only keys (`approval.approve`,
 * `approval.reject`): Admin does not hold them by default (AUTHORIZATION decision 5).
 * @param {import("./index.js").FindingsRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const findingsApprovalRoutes = (deps) =>
  async function register(app) {
    const { authz } = deps;
    const repository = createFindingsLifecycleRepository({ db: deps.db });
    const reads = createFindingsReadService({ repository: repository.reads });
    const service = createFindingsApprovalService({ repository, reads });
    const controller = createFindingsApprovalController({ service });
    const tags = [OPENAPI_TAGS.approvals];
    const config = { audience: "tenant" };
    const inWorkspace = (key, scope = findingScope()) => authz.authorize(key, scope);
    const approveGate = inWorkspace("approval.approve");
    const rejectGate = inWorkspace("approval.reject");

    app.get(
      "/approvals",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("approval.view", workspaceQueryScope()),
        schema: {
          tags,
          summary:
            "The Approvals queue: pending decisions and exception requests, with canDecide for the caller",
          querystring: approvalsQuerySchema,
          response: { 200: lifecycleResponses.approvals },
        },
      },
      controller.approvals,
    );
    app.post(
      "/findings/:id/reviews/:reviewId/approve",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: approveGate,
        schema: {
          tags,
          summary: "Approve a review decision (never your own: separation of duties)",
          params: reviewParamsSchema,
          body: approveBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.approveReview,
    );
    app.post(
      "/findings/:id/reviews/:reviewId/reject",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: rejectGate,
        schema: {
          tags,
          summary: "Reject a review decision (a comment is required; never your own)",
          params: reviewParamsSchema,
          body: rejectBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.rejectReview,
    );
  };
