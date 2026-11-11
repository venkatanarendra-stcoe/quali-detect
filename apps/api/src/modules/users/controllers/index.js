import { actorFrom } from "../../../lib/http.js";

/** @param {{ service: ReturnType<typeof import("../services/index.js").createUserService> }} deps */
export function createUserController({ service }) {
  return {
    list: async (request, reply) => {
      const { items, pagination } = await service.list(actorFrom(request), request.query);
      return reply.paginated(items, pagination);
    },
    get: async (request, reply) =>
      reply.success(await service.get(actorFrom(request), request.params.userId)),
    invite: async (request, reply) =>
      reply.code(201).success(await service.invite(actorFrom(request), request.body)),
    update: async (request, reply) =>
      reply.success(
        await service.setStatus(actorFrom(request), request.params.userId, request.body.status),
      ),
    remove: async (request, reply) =>
      reply.success(await service.remove(actorFrom(request), request.params.userId)),
    effectivePermissions: async (request, reply) =>
      reply.success(
        await service.explainPermissions(
          actorFrom(request),
          request.principal.tenant,
          request.params.userId,
          request.query.workspaceId,
        ),
      ),
  };
}
