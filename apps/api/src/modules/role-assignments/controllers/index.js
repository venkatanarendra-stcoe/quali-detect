import { actorFrom } from "../../../lib/http.js";

const TENANT = Object.freeze({ scopeType: "tenant" });
/** Workspace scope comes from the workspace loaded (with the tenant filter) by `authorize`. */
const scopeOf = (request) =>
  request.authz.scope.type === "workspace"
    ? { scopeType: "workspace", workspace: request.authz.resource }
    : TENANT;

/** @param {{ service: ReturnType<typeof import("../services/index.js").createRoleAssignmentService> }} deps */
export function createRoleAssignmentController({ service }) {
  return {
    list: async (request, reply) => {
      const { items, pagination } = await service.list(
        actorFrom(request),
        scopeOf(request),
        request.query,
      );
      return reply.paginated(items, pagination);
    },
    create: async (request, reply) =>
      reply
        .code(201)
        .success(await service.create(actorFrom(request), scopeOf(request), request.body)),
    update: async (request, reply) =>
      reply.success(
        await service.update(
          actorFrom(request),
          scopeOf(request),
          request.params.assignmentId,
          request.body,
        ),
      ),
    revoke: async (request, reply) =>
      reply.success(
        await service.revoke(actorFrom(request), scopeOf(request), request.params.assignmentId),
      ),
  };
}
