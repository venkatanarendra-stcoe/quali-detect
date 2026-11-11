import { OPENAPI_TAG } from "../constants/index.js";
import {
  listMembersQuerySchema,
  memberListResponseSchema,
  memberParamsSchema,
  memberResponseSchema,
  removedResponseSchema,
  workspaceParamsSchema,
} from "../schemas/index.js";

/**
 * @param {ReturnType<typeof import("../controllers/index.js").createWorkspaceMemberController>} controller
 * @param {{ authorize: Function, scopes: any }} authz
 * @returns {import("fastify").FastifyPluginAsync}
 */
export const workspaceMemberRoutes = (controller, authz) =>
  async function workspaceMembers(app) {
    const tag = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const inWorkspace = (key) => authz.authorize(key, authz.scopes.workspace());
    app.get(
      "/workspaces/:workspaceId/members",
      {
        config,
        preHandler: inWorkspace("workspace.view"),
        schema: {
          tags: tag,
          summary: "List workspace members",
          params: workspaceParamsSchema,
          querystring: listMembersQuerySchema,
          response: { 200: memberListResponseSchema },
        },
      },
      controller.list,
    );
    app.put(
      "/workspaces/:workspaceId/members/:userId",
      {
        config,
        preHandler: inWorkspace("workspace.manage_members"),
        schema: {
          tags: tag,
          summary: "Add a tenant member to the workspace (idempotent)",
          params: memberParamsSchema,
          response: { 200: memberResponseSchema },
        },
      },
      controller.add,
    );
    app.delete(
      "/workspaces/:workspaceId/members/:userId",
      {
        config,
        preHandler: inWorkspace("workspace.manage_members"),
        schema: {
          tags: tag,
          summary: "Remove a member and their workspace-scope role assignments",
          params: memberParamsSchema,
          response: { 200: removedResponseSchema },
        },
      },
      controller.remove,
    );
  };
