import { OPENAPI_TAGS } from "../constants/index.js";
import { createFindingsRemediationController } from "../controllers/remediation.js";
import { createFindingsRemediationRepository } from "../repositories/remediation.js";
import { findingScope, workspaceQueryScope } from "../repositories/read-scopes.js";
import { workspaceBodyScope } from "../repositories/write-scopes.js";
import {
  assignBodySchema,
  boardColumnParamsSchema,
  boardColumnQuerySchema,
  boardQuerySchema,
  bulkAssignBodySchema,
  clearAssignmentBodySchema,
  findingParamsSchema,
  remediationStartBodySchema,
  remediationSubmitBodySchema,
} from "../schemas/index.js";
import { lifecycleResponses } from "../schemas/lifecycle.js";
import { remediationResponses } from "../schemas/remediation.js";
import { createFindingsBoardService } from "../services/board.js";
import { createFindingsReadService } from "../services/read.js";
import { createFindingsRemediationService } from "../services/remediation.js";

/**
 * Findings routes, part C: assign, unassign, start work, submit a fix, the bulk assign and the remediation board (docs/modules/findings/
 * SPEC.md 8.1, 8.2). Every item route authorizes in the finding's OWN workspace (the finding is loaded by tenant and id; a hidden,
 * foreign or missing finding is the identical 404, a visible one without the key is 403); the collection reads authorize in the
 * workspace named by `workspaceId` (404 when it is not the caller's). Writes take an `Idempotency-Key` and the `write` rate limit and
 * answer with the finding as the caller now sees it. `expectedRev` of the body is the optimistic-concurrency token (`409
 * FINDING_STATE_CONFLICT` when stale). `/findings/bulk/assign` is registered BEFORE the item routes. The route keys and their
 * permissions are frozen in `PERMISSION_BY_ROUTE` of `@qmentisai/shared`.
 * @param {import("./index.js").FindingsRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const findingsRemediationRoutes = (deps) =>
  async function register(app) {
    const { authz } = deps;
    const repository = createFindingsRemediationRepository({ db: deps.db });
    const reads = createFindingsReadService({ repository: repository.reads });
    const resolvePermissions = (subject, workspaceId) =>
      authz.service.resolveFor(subject, workspaceId);
    const remediation = createFindingsRemediationService({
      repository,
      reads,
      resolvePermissions,
    });
    const board = createFindingsBoardService({ repository });
    const controller = createFindingsRemediationController({ remediation, board });
    const tags = [OPENAPI_TAGS.remediation];
    const config = { audience: "tenant" };
    const inWorkspace = (key, scope = findingScope()) => authz.authorize(key, scope);
    const assignGate = inWorkspace("finding.assign");
    const remediateGate = inWorkspace("finding.remediate");

    app.get(
      "/remediation/board",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("remediation.view", workspaceQueryScope()),
        schema: {
          tags,
          summary:
            "The remediation board: five columns with counts, the first 25 cards and a cursor each",
          querystring: boardQuerySchema,
          response: { 200: remediationResponses.board },
        },
      },
      controller.board,
    );
    app.get(
      "/remediation/board/:column",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("remediation.view", workspaceQueryScope()),
        schema: {
          tags,
          summary: "One board column, keyset paged (most severe first)",
          params: boardColumnParamsSchema,
          querystring: boardColumnQuerySchema,
          response: { 200: remediationResponses.column },
        },
      },
      controller.boardColumn,
    );

    app.post(
      "/findings/bulk/assign",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: inWorkspace("finding.assign", workspaceBodyScope()),
        schema: {
          tags,
          summary: "Assign up to 50 findings of one workspace to one assignee (per-item result)",
          body: bulkAssignBodySchema,
          response: { 200: lifecycleResponses.bulk },
        },
      },
      controller.bulkAssign,
    );

    app.post(
      "/findings/:id/assignments",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: assignGate,
        schema: {
          tags,
          summary:
            "Assign an approved or reopened finding, or reassign one in progress, to a member who can remediate",
          params: findingParamsSchema,
          body: assignBodySchema,
          response: { 201: lifecycleResponses.finding },
        },
      },
      controller.assign,
    );
    app.post(
      "/findings/:id/assignments/clear",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: assignGate,
        schema: {
          tags,
          summary: "Unassign a finding (back to approved)",
          params: findingParamsSchema,
          body: clearAssignmentBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.clear,
    );
    app.post(
      "/findings/:id/remediation/start",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: remediateGate,
        schema: {
          tags,
          summary:
            "Start work on an assigned finding (its assignee, or a holder of the assign permission)",
          params: findingParamsSchema,
          body: remediationStartBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.start,
    );
    app.post(
      "/findings/:id/remediation/submit",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: remediateGate,
        schema: {
          tags,
          summary:
            "Submit a fix with an optional pull request link, ticket key and note; a later complete scan verifies it",
          params: findingParamsSchema,
          body: remediationSubmitBodySchema,
          response: { 200: lifecycleResponses.finding },
        },
      },
      controller.submit,
    );
  };
