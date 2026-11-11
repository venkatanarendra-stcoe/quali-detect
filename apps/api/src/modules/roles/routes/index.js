import { OPENAPI_TAG } from "../constants/index.js";
import {
  createRoleBodySchema,
  deletedResponseSchema,
  listRolesQuerySchema,
  permissionCatalogResponseSchema,
  roleListResponseSchema,
  roleParamsSchema,
  roleResponseSchema,
  updateRoleBodySchema,
} from "../schemas/index.js";

/**
 * `role.view` / `role.manage` are tenant permissions: callers without them get 403.
 * @param {ReturnType<typeof import("../controllers/index.js").createRoleController>} controller
 * @param {{ authorize: Function }} authz
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const roleRoutes = (controller, authz) =>
  async function roles(app) {
    const tag = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const view = authz.authorize("role.view");
    const manage = authz.authorize("role.manage");
    app.get(
      "/permissions",
      {
        config,
        preHandler: view,
        schema: {
          tags: tag,
          summary: "Permission catalog (tenant and workspace scope)",
          response: { 200: permissionCatalogResponseSchema },
        },
      },
      controller.permissions,
    );
    app.get(
      "/roles",
      {
        config,
        preHandler: view,
        schema: {
          tags: tag,
          summary: "List built-in and custom roles",
          querystring: listRolesQuerySchema,
          response: { 200: roleListResponseSchema },
        },
      },
      controller.list,
    );
    app.post(
      "/roles",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Create a custom role (from scratch or by cloning; escalation-checked)",
          body: createRoleBodySchema,
          response: { 201: roleResponseSchema },
        },
      },
      controller.create,
    );
    app.get(
      "/roles/:roleId",
      {
        config,
        preHandler: view,
        schema: {
          tags: tag,
          summary: "Get a role",
          params: roleParamsSchema,
          response: { 200: roleResponseSchema },
        },
      },
      controller.get,
    );
    app.patch(
      "/roles/:roleId",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Update a custom role (applies to all holders immediately)",
          params: roleParamsSchema,
          body: updateRoleBodySchema,
          response: { 200: roleResponseSchema },
        },
      },
      controller.update,
    );
    app.delete(
      "/roles/:roleId",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Delete an unassigned custom role",
          params: roleParamsSchema,
          response: { 200: deletedResponseSchema },
        },
      },
      controller.delete,
    );
  };
