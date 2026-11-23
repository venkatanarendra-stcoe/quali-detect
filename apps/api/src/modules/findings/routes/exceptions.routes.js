import { OPENAPI_TAGS } from "../constants/index.js";
import { createFindingsExceptionsController } from "../controllers/exceptions.js";
import { createFindingsLifecycleRepository } from "../repositories/lifecycle.js";
import { findingScope } from "../repositories/read-scopes.js";
import {
  createExceptionBodySchema,
  exceptionApproveBodySchema,
  exceptionParamsSchema,
  exceptionRejectBodySchema,
  findingParamsSchema,
  revokeExceptionBodySchema,
  withdrawExceptionBodySchema,
} from "../schemas/index.js";
import { lifecycleResponses } from "../schemas/lifecycle.js";
import { createFindingsExceptionsService } from "../services/exceptions.js";
import { createFindingsReadService } from "../services/read.js";

/**
 * Findings routes, part B: accept risk and suppression (docs/modules/findings/SPEC.md 5.8, 8.2): request, withdraw, approve, reject,
 * revoke. A request needs `finding.accept_risk` for `kind: accept_risk` and `finding.suppress` for `kind: suppress` (the body's kind,
 * validated before authorization, picks the key); withdraw and revoke need only that the finding is visible here, and the service then
 * checks the requester (withdraw) or the key of the exception's kind (revoke). Approve and reject are `approval.approve` and
 * `approval.reject` with segregation of duties.
 * @param {import("./index.js").FindingsRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const findingsExceptionRoutes = (deps) =>
  async function register(app) {
    const { authz } = deps;
    const repository = createFindingsLifecycleRepository({ db: deps.db });
    const reads = createFindingsReadService({ repository: repository.reads });
    const resolvePermissions = (subject, workspaceId) =>
      authz.service.resolveFor(subject, workspaceId);
    const service = createFindingsExceptionsService({ repository, reads, resolvePermissions });
    const controller = createFindingsExceptionsController({ service });
    const tags = [OPENAPI_TAGS.findings];
    const config = { audience: "tenant" };
    const inWorkspace = (key, scope = findingScope()) => authz.authorize(key, scope);
    const acceptRiskGate = inWorkspace("finding.accept_risk");
    const suppressionGate = inWorkspace("finding.suppress");
    const exceptionViewGate = inWorkspace("finding.view");
    const exceptionApproveGate = inWorkspace("approval.approve");
    const exceptionRejectGate = inWorkspace("approval.reject");
    /** The key of the REQUEST depends on the body's kind (validated before this runs). */
    const requestGate = Object.assign(
      (request, response, next) =>
        (request.body.kind === "suppress" ? suppressionGate : acceptRiskGate)(
          request,
          response,
          next,
        ),
      { permission: acceptRiskGate.permission },
    );

    app.post(
      "/findings/:id/exceptions",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: requestGate,
        schema: {
          tags,
          summary:
            "Request an accepted risk (finding.accept_risk) or a suppression (finding.suppress); the status is unchanged until it is approved",
          params: findingParamsSchema,
          body: createExceptionBodySchema,
          response: { 201: lifecycleResponses.finding },
        },
      },
      controller.request,
    );
    app.post(
      "/findings/:id/exceptions/:exceptionId/withdraw",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: exceptionViewGate,
        schema: {
          tags,
          summary: "Withdraw your own pending exception request",
          params: exceptionParamsSchema,
          body: withdrawExceptionBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.withdraw,
    );
    app.post(
      "/findings/:id/exceptions/:exceptionId/approve",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: exceptionApproveGate,
        schema: {
          tags,
          summary:
            "Approve an exception request (never your own, nor as a reviewer of the finding)",
          params: exceptionParamsSchema,
          body: exceptionApproveBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.approve,
    );
    app.post(
      "/findings/:id/exceptions/:exceptionId/reject",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: exceptionRejectGate,
        schema: {
          tags,
          summary: "Reject an exception request (a comment is required; never your own)",
          params: exceptionParamsSchema,
          body: exceptionRejectBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.reject,
    );
    app.post(
      "/findings/:id/exceptions/:exceptionId/revoke",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: exceptionViewGate,
        schema: {
          tags,
          summary:
            "Revoke an active accepted risk (finding.accept_risk) or suppression (finding.suppress); the finding is reopened",
          params: exceptionParamsSchema,
          body: revokeExceptionBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.revoke,
    );
  };
