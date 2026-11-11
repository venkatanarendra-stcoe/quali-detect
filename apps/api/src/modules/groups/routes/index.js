import { OPENAPI_TAG } from "../constants/index.js";
import {
  createGroupBodySchema,
  deletedResponseSchema,
  groupListResponseSchema,
  groupParamsSchema,
  groupResponseSchema,
  listGroupsQuerySchema,
  listMembersQuerySchema,
  memberListResponseSchema,
  memberParamsSchema,
  memberResponseSchema,
  removedResponseSchema,
  updateGroupBodySchema,
} from "../schemas/index.js";

/**
 * Tenant-level routes: `group.view` / `group.manage` are tenant permissions, so callers without them get 403.
 * @param {ReturnType<typeof import("../controllers/index.js").createGroupController>} controller
 * @param {{ authorize: Function }} authz
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const groupRoutes = (controller, authz) =>
  async function groups(app) {
    const tag = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const view = authz.authorize("group.view");
    const manage = authz.authorize("group.manage");
    app.get(
      "/groups",
      {
        config,
        preHandler: view,
        schema: {
          tags: tag,
          summary: "List groups",
          querystring: listGroupsQuerySchema,
          response: { 200: groupListResponseSchema },
        },
      },
      controller.list,
    );
    app.post(
      "/groups",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Create a group (flat; grants nothing by itself)",
          body: createGroupBodySchema,
          response: { 201: groupResponseSchema },
        },
      },
      controller.create,
    );
    app.get(
      "/groups/:groupId",
      {
        config,
        preHandler: view,
        schema: {
          tags: tag,
          summary: "Get a group",
          params: groupParamsSchema,
          response: { 200: groupResponseSchema },
        },
      },
      controller.get,
    );
    app.patch(
      "/groups/:groupId",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Update a group",
          params: groupParamsSchema,
          body: updateGroupBodySchema,
          response: { 200: groupResponseSchema },
        },
      },
      controller.update,
    );
    app.delete(
      "/groups/:groupId",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Delete a group and its role assignments",
          params: groupParamsSchema,
          response: { 200: deletedResponseSchema },
        },
      },
      controller.delete,
    );
    app.get(
      "/groups/:groupId/members",
      {
        config,
        preHandler: view,
        schema: {
          tags: tag,
          summary: "List group members",
          params: groupParamsSchema,
          querystring: listMembersQuerySchema,
          response: { 200: memberListResponseSchema },
        },
      },
      controller.listMembers,
    );
    app.put(
      "/groups/:groupId/members/:userId",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Add a tenant member to a group (idempotent; escalation-checked)",
          params: memberParamsSchema,
          response: { 200: memberResponseSchema },
        },
      },
      controller.addMember,
    );
    app.delete(
      "/groups/:groupId/members/:userId",
      {
        config,
        preHandler: manage,
        schema: {
          tags: tag,
          summary: "Remove a member from a group",
          params: memberParamsSchema,
          response: { 200: removedResponseSchema },
        },
      },
      controller.removeMember,
    );
  };
