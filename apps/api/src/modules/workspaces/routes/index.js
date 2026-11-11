import { OPENAPI_TAG } from "../constants/index.js";
import {
  createWorkspaceBodySchema,
  listWorkspacesQuerySchema,
  updateWorkspaceBodySchema,
  workspaceListResponseSchema,
  workspaceParamsSchema,
  workspaceResponseSchema,
} from "../schemas/index.js";

/**
 * Workspace routes. Collection: visible workspaces only (never 403). Item routes: `authorize` answers 404 for workspaces
 * the caller cannot see and 403 when visible but not permitted.
 * @param {ReturnType<typeof import("../controllers/index.js").createWorkspaceController>} controller
 * @param {{ authorize: Function, context: Function, scopes: any }} authz
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const workspaceRoutes = (controller, authz) =>
  async function workspaces(app) {
    const tag = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const inWorkspace = (key) => authz.authorize(key, authz.scopes.workspace());
    app.get(
      "/workspaces",
      {
        config,
        preHandler: authz.context,
        schema: {
          tags: tag,
          summary: "List the workspaces the caller can see",
          querystring: listWorkspacesQuerySchema,
          response: { 200: workspaceListResponseSchema },
        },
      },
      controller.list,
    );
    app.post(
      "/workspaces",
      {
        config,
        preHandler: authz.authorize("workspace.create"),
        schema: {
          tags: tag,
          summary:
            "Create a workspace (counts against the plan limit; the owner becomes its administrator)",
          body: createWorkspaceBodySchema,
          response: { 201: workspaceResponseSchema },
        },
      },
      controller.create,
    );
    app.get(
      "/workspaces/:workspaceId",
      {
        config,
        preHandler: inWorkspace("workspace.view"),
        schema: {
          tags: tag,
          summary: "Get a workspace",
          params: workspaceParamsSchema,
          response: { 200: workspaceResponseSchema },
        },
      },
      controller.get,
    );
    app.patch(
      "/workspaces/:workspaceId",
      {
        config,
        preHandler: inWorkspace("workspace.update"),
        schema: {
          tags: tag,
          summary: "Update a workspace (not while archived)",
          params: workspaceParamsSchema,
          body: updateWorkspaceBodySchema,
          response: { 200: workspaceResponseSchema },
        },
      },
      controller.update,
    );
    app.post(
      "/workspaces/:workspaceId/archive",
      {
        config,
        preHandler: inWorkspace("workspace.archive"),
        schema: {
          tags: tag,
          summary: "Archive a workspace (read-only until restored)",
          params: workspaceParamsSchema,
          response: { 200: workspaceResponseSchema },
        },
      },
      controller.archive,
    );
    app.post(
      "/workspaces/:workspaceId/restore",
      {
        config,
        preHandler: inWorkspace("workspace.archive"),
        schema: {
          tags: tag,
          summary: "Restore an archived workspace",
          params: workspaceParamsSchema,
          response: { 200: workspaceResponseSchema },
        },
      },
      controller.restore,
    );
  };
