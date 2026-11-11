import { OPENAPI_TAG } from "../constants/index.js";
import {
  effectivePermissionsQuerySchema,
  effectivePermissionsResponseSchema,
  inviteUserBodySchema,
  listUsersQuerySchema,
  removedResponseSchema,
  updateUserBodySchema,
  userListResponseSchema,
  userParamsSchema,
  userResponseSchema,
} from "../schemas/index.js";

/**
 * `user.view` / `user.manage` are tenant permissions: callers without them get 403.
 * @param {ReturnType<typeof import("../controllers/index.js").createUserController>} controller
 * @param {{ authorize: Function }} authz
 * @returns {import("fastify").FastifyPluginAsync}
 */
export const userRoutes = (controller, authz) =>
  async function users(app) {
    const tag = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const view = authz.authorize("user.view");
    const manage = authz.authorize("user.manage");
    app.get(
      "/users",
      {
        config,
        preHandler: view,
        schema: {
          tags: tag,
          summary: "List the tenant's members",
          querystring: listUsersQuerySchema,
          response: { 200: userListResponseSchema },
        },
      },
      controller.list,
    );
    app.post(
      "/users",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary:
            "Invite a person to the tenant (counts against the seat limit; needs their acceptance)",
          body: inviteUserBodySchema,
          response: { 201: userResponseSchema },
        },
      },
      controller.invite,
    );
    app.get(
      "/users/:userId",
      {
        config,
        preHandler: view,
        schema: {
          tags: tag,
          summary: "Get a member",
          params: userParamsSchema,
          response: { 200: userResponseSchema },
        },
      },
      controller.get,
    );
    app.patch(
      "/users/:userId",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Suspend or reactivate a member",
          params: userParamsSchema,
          body: updateUserBodySchema,
          response: { 200: userResponseSchema },
        },
      },
      controller.update,
    );
    app.delete(
      "/users/:userId",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Remove a member (or cancel an invitation) and everything it granted",
          params: userParamsSchema,
          response: { 200: removedResponseSchema },
        },
      },
      controller.remove,
    );
    app.get(
      "/users/:userId/effective-permissions",
      {
        config,
        preHandler: view,
        schema: {
          tags: tag,
          summary: "Explain a member's effective permissions and the assignments behind them",
          params: userParamsSchema,
          querystring: effectivePermissionsQuerySchema,
          response: { 200: effectivePermissionsResponseSchema },
        },
      },
      controller.effectivePermissions,
    );
  };
