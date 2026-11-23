import { OPENAPI_TAGS } from "../constants/index.js";
import { createFindingsReadController } from "../controllers/read.js";
import { createFindingsReadRepository } from "../repositories/read.js";
import { findingScope, workspaceQueryScope } from "../repositories/read-scopes.js";
import {
  findingParamsSchema,
  keysetQuerySchema,
  listFindingsQuerySchema,
  summaryQuerySchema,
} from "../schemas/index.js";
import { readResponses } from "../schemas/read.js";
import { createFindingsReadService } from "../services/read.js";

/**
 * Findings routes, part A1: the read routes (docs/modules/findings/SPEC.md 8.1): list, summary, detail, history, comments, similar. The
 * collection routes take `workspaceId` as a REQUIRED query parameter: the workspace is loaded by tenant and id, and a workspace of
 * another tenant, a hidden one or an unknown id is the same 404; a visible workspace without `finding.view` is 403. The item routes load
 * the finding by TENANT and id and authorize in ITS workspace (identical 404 for a foreign, hidden or missing finding). The route keys
 * and their permissions are frozen in `PERMISSION_BY_ROUTE` of `@qmentisai/shared`. `/findings/summary` is registered BEFORE
 * `/findings/:id`.
 * @param {import("./index.js").FindingsRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const findingsReadRoutes = (deps) =>
  async function register(app) {
    const { authz } = deps;
    const reads = createFindingsReadService({
      repository: createFindingsReadRepository({ db: deps.db }),
    });
    const controller = createFindingsReadController({ reads });
    const tags = [OPENAPI_TAGS.findings];
    const config = { audience: "tenant" };
    const inWorkspace = (key, scope) => authz.authorize(key, scope);

    app.get(
      "/findings",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", workspaceQueryScope()),
        schema: {
          tags,
          summary:
            "List findings of one workspace (filters, saved views, numbered or cursor pages)",
          querystring: listFindingsQuerySchema,
          response: { 200: readResponses.list },
        },
      },
      controller.list,
    );
    app.get(
      "/findings/summary",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", workspaceQueryScope()),
        schema: {
          tags,
          summary: "Counts for the saved views, severities and statuses of one workspace",
          querystring: summaryQuerySchema,
          response: { 200: readResponses.summary },
        },
      },
      controller.summary,
    );
    app.get(
      "/findings/:id",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", findingScope()),
        schema: {
          tags,
          summary:
            "Get a finding with its evidence, commit-pinned link, advisory and allowed actions",
          params: findingParamsSchema,
          response: { 200: readResponses.detail },
        },
      },
      controller.get,
    );
    app.get(
      "/findings/:id/history",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", findingScope()),
        schema: {
          tags,
          summary: "The immutable timeline of a finding, newest first (cursor pages)",
          params: findingParamsSchema,
          querystring: keysetQuerySchema,
          response: { 200: readResponses.history },
        },
      },
      controller.history,
    );
    app.get(
      "/findings/:id/comments",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", findingScope()),
        schema: {
          tags,
          summary: "Comments of a finding, oldest first (cursor pages)",
          params: findingParamsSchema,
          querystring: keysetQuerySchema,
          response: { 200: readResponses.comments },
        },
      },
      controller.comments,
    );
    app.get(
      "/findings/:id/similar",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", findingScope()),
        schema: {
          tags,
          summary:
            "The same vulnerability in OTHER pipelines of the workspace (links only, never merged)",
          params: findingParamsSchema,
          response: { 200: readResponses.similar },
        },
      },
      controller.similar,
    );
  };
