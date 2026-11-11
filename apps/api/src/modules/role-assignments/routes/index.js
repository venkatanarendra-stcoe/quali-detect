import { OPENAPI_TAG } from "../constants/index.js";
import {
  assignmentListResponseSchema,
  assignmentParamsSchema,
  assignmentResponseSchema,
  createAssignmentBodySchema,
  listAssignmentsQuerySchema,
  revokedResponseSchema,
  updateAssignmentBodySchema,
  workspaceAssignmentParamsSchema,
  workspaceParamsSchema,
} from "../schemas/index.js";

/**
 * Tenant-scope assignments need tenant permissions (403 without them). Workspace-scope assignments are resolved inside
 * the workspace: not visible -> 404, visible but not permitted -> 403.
 * @param {ReturnType<typeof import("../controllers/index.js").createRoleAssignmentController>} controller
 * @param {{ authorize: Function, scopes: any }} authz
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const roleAssignmentRoutes = (controller, authz) =>
  async function roleAssignments(app) {
    const tag = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const view = authz.authorize("role.view");
    const manage = authz.authorize("role_assignment.manage_tenant");
    app.get(
      "/role-assignments",
      {
        config,
        preHandler: view,
        schema: {
          tags: tag,
          summary: "List tenant-scope role assignments",
          querystring: listAssignmentsQuerySchema,
          response: { 200: assignmentListResponseSchema },
        },
      },
      controller.list,
    );
    app.post(
      "/role-assignments",
      {
        rateLimit: "write",
        idempotent: true,
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Assign a role to a user or group at tenant scope (escalation-checked)",
          body: createAssignmentBodySchema,
          response: { 201: assignmentResponseSchema },
        },
      },
      controller.create,
    );
    app.patch(
      "/role-assignments/:assignmentId",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Suspend, reactivate or change the expiry of a tenant-scope assignment",
          params: assignmentParamsSchema,
          body: updateAssignmentBodySchema,
          response: { 200: assignmentResponseSchema },
        },
      },
      controller.update,
    );
    app.delete(
      "/role-assignments/:assignmentId",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary:
            "Revoke a tenant-scope assignment (409 LAST_TENANT_ADMIN if it would leave no administrator)",
          params: assignmentParamsSchema,
          response: { 200: revokedResponseSchema },
        },
      },
      controller.revoke,
    );

    const inWorkspace = (key) => authz.authorize(key, authz.scopes.workspace());
    const viewWs = inWorkspace("workspace.view_roles");
    const manageWs = inWorkspace("workspace.manage_members");
    app.get(
      "/workspaces/:workspaceId/role-assignments",
      {
        config,
        preHandler: viewWs,
        schema: {
          tags: tag,
          summary: "List workspace-scope role assignments",
          params: workspaceParamsSchema,
          querystring: listAssignmentsQuerySchema,
          response: { 200: assignmentListResponseSchema },
        },
      },
      controller.list,
    );
    app.post(
      "/workspaces/:workspaceId/role-assignments",
      {
        rateLimit: "write",
        idempotent: true,
        config,
        preHandler: manageWs,
        schema: {
          tags: tag,
          summary:
            "Assign a role at workspace scope (escalation-checked; adds the user to the roster)",
          params: workspaceParamsSchema,
          body: createAssignmentBodySchema,
          response: { 201: assignmentResponseSchema },
        },
      },
      controller.create,
    );
    app.patch(
      "/workspaces/:workspaceId/role-assignments/:assignmentId",
      {
        config,
        preHandler: manageWs,
        schema: {
          tags: tag,
          summary: "Suspend, reactivate or change the expiry of a workspace-scope assignment",
          params: workspaceAssignmentParamsSchema,
          body: updateAssignmentBodySchema,
          response: { 200: assignmentResponseSchema },
        },
      },
      controller.update,
    );
    app.delete(
      "/workspaces/:workspaceId/role-assignments/:assignmentId",
      {
        config,
        preHandler: manageWs,
        schema: {
          tags: tag,
          summary: "Revoke a workspace-scope assignment (the workspace keeps an administrator)",
          params: workspaceAssignmentParamsSchema,
          response: { 200: revokedResponseSchema },
        },
      },
      controller.revoke,
    );
  };
