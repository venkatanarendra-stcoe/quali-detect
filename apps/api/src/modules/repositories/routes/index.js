import { OPENAPI_TAG } from "../constants/index.js";
import {
  availableListResponseSchema,
  availableQuerySchema,
  branchesResponseSchema,
  connectBodySchema,
  disconnectBodySchema,
  disconnectedResponseSchema,
  listRepositoriesQuerySchema,
  pullRequestsResponseSchema,
  repositoryListResponseSchema,
  repositoryParamsSchema,
  repositoryResponseSchema,
  sbomQuerySchema,
  syncResponseSchema,
  updateBodySchema,
  workspaceParamsSchema,
} from "../schemas/index.js";

/**
 * Repository routes. Collection: only repositories in workspaces where the caller holds repository.view (never 403). Item
 * routes use the repository scope resolver: a repository of another tenant, or in a workspace the caller cannot see, is the
 * same 404; visible but not permitted is 403. Mutations are rate limited and accept Idempotency-Key.
 * @param {ReturnType<typeof import("../controllers/index.js").createRepositoryController>} controller
 * @param {{ authorize: Function, context: Function, scopes: any }} authz
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const repositoryRoutes = (controller, authz) =>
  async function repositories(app) {
    const tags = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const inWorkspace = (key) => authz.authorize(key, authz.scopes.workspace());
    const onRepository = (key) => authz.authorize(key, authz.scopes.repository());
    const write = { rateLimit: "write", idempotent: true };
    app.get(
      "/repositories",
      {
        config,
        preHandler: authz.context,
        schema: {
          tags,
          summary: "List repositories in the workspaces the caller can see",
          querystring: listRepositoriesQuerySchema,
          response: { 200: repositoryListResponseSchema },
        },
      },
      controller.list,
    );
    app.get(
      "/workspaces/:workspaceId/repositories/available",
      {
        config,
        preHandler: inWorkspace("repository.connect"),
        schema: {
          tags,
          summary:
            "Allow-listed repositories of a workspace GitHub connection (marks the ones already connected)",
          params: workspaceParamsSchema,
          querystring: availableQuerySchema,
          response: { 200: availableListResponseSchema },
        },
      },
      controller.available,
    );
    app.post(
      "/workspaces/:workspaceId/repositories",
      {
        config,
        ...write,
        preHandler: inWorkspace("repository.connect"),
        schema: {
          tags,
          summary: "Connect (or reconnect) a repository into the workspace",
          params: workspaceParamsSchema,
          body: connectBodySchema,
          response: { 201: repositoryResponseSchema },
        },
      },
      controller.connect,
    );
    app.get(
      "/repositories/:repositoryId",
      {
        config,
        preHandler: onRepository("repository.view"),
        schema: {
          tags,
          summary: "Get a repository",
          params: repositoryParamsSchema,
          response: { 200: repositoryResponseSchema },
        },
      },
      controller.get,
    );
    app.get(
      "/repositories/:repositoryId/sbom",
      {
        config,
        rateLimit: "read",
        preHandler: onRepository("repository.view"),
        schema: {
          tags,
          summary:
            "Download the latest stored SBOM (CycloneDX JSON, redacted copy) of the repository as an attachment",
          params: repositoryParamsSchema,
          querystring: sbomQuerySchema,
          response: { 200: {} },
        },
      },
      controller.sbom,
    );
    app.patch(
      "/repositories/:repositoryId",
      {
        config,
        preHandler: onRepository("repository.update"),
        schema: {
          tags,
          summary: "Edit display name, description or owner",
          params: repositoryParamsSchema,
          body: updateBodySchema,
          response: { 200: repositoryResponseSchema },
        },
      },
      controller.update,
    );
    app.post(
      "/repositories/:repositoryId/sync",
      {
        config,
        ...write,
        preHandler: onRepository("repository.sync"),
        schema: {
          tags,
          summary: "Queue a sync with GitHub",
          params: repositoryParamsSchema,
          response: { 202: syncResponseSchema },
        },
      },
      controller.sync,
    );
    app.post(
      "/repositories/:repositoryId/enable",
      {
        config,
        ...write,
        preHandler: onRepository("repository.toggle"),
        schema: {
          tags,
          summary: "Enable a repository",
          params: repositoryParamsSchema,
          response: { 200: repositoryResponseSchema },
        },
      },
      controller.enable,
    );
    app.post(
      "/repositories/:repositoryId/disable",
      {
        config,
        ...write,
        preHandler: onRepository("repository.toggle"),
        schema: {
          tags,
          summary: "Disable a repository (events are ignored)",
          params: repositoryParamsSchema,
          response: { 200: repositoryResponseSchema },
        },
      },
      controller.disable,
    );
    app.delete(
      "/repositories/:repositoryId",
      {
        config,
        preHandler: onRepository("repository.disconnect"),
        schema: {
          tags,
          summary: "Disconnect a repository (history is kept; reconnecting reactivates it)",
          params: repositoryParamsSchema,
          body: disconnectBodySchema,
          response: { 200: disconnectedResponseSchema },
        },
      },
      controller.disconnect,
    );
    app.get(
      "/repositories/:repositoryId/branches",
      {
        config,
        preHandler: onRepository("repository.view"),
        schema: {
          tags,
          summary: "Branches, read live from GitHub (60 s cache)",
          params: repositoryParamsSchema,
          response: { 200: branchesResponseSchema },
        },
      },
      controller.branches,
    );
    app.get(
      "/repositories/:repositoryId/pull-requests",
      {
        config,
        preHandler: onRepository("repository.view"),
        schema: {
          tags,
          summary: "Open pull requests, read live from GitHub (60 s cache)",
          params: repositoryParamsSchema,
          response: { 200: pullRequestsResponseSchema },
        },
      },
      controller.pullRequests,
    );
  };
