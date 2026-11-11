import { actorFrom } from "../../../lib/http.js";

/** @param {{ service: ReturnType<typeof import("../services/index.js").createWorkspaceMemberService> }} deps */
export function createWorkspaceMemberController({ service }) {
  return {
    list: async (request, reply) => {
      const { items, pagination } = await service.list(
        actorFrom(request),
        request.authz.resource,
        request.query,
      );
      return reply.paginated(items, pagination);
    },
    add: async (request, reply) =>
      reply.success(
        await service.add(actorFrom(request), request.authz.resource, request.params.userId),
      ),
    remove: async (request, reply) =>
      reply.success(
        await service.remove(actorFrom(request), request.authz.resource, request.params.userId),
      ),
  };
}
