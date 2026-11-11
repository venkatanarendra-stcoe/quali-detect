import { actorFrom } from "../../../lib/http.js";

/** @param {{ service: ReturnType<typeof import("../services/index.js").createGroupService> }} deps */
export function createGroupController({ service }) {
  return {
    list: async (request, reply) => {
      const { items, pagination } = await service.list(actorFrom(request), request.query);
      return reply.paginated(items, pagination);
    },
    get: async (request, reply) =>
      reply.success(await service.get(actorFrom(request), request.params.groupId)),
    create: async (request, reply) =>
      reply.code(201).success(await service.create(actorFrom(request), request.body)),
    update: async (request, reply) =>
      reply.success(await service.update(actorFrom(request), request.params.groupId, request.body)),
    delete: async (request, reply) =>
      reply.success(await service.delete(actorFrom(request), request.params.groupId)),
    listMembers: async (request, reply) => {
      const { items, pagination } = await service.listMembers(
        actorFrom(request),
        request.params.groupId,
        request.query,
      );
      return reply.paginated(items, pagination);
    },
    addMember: async (request, reply) =>
      reply.success(
        await service.addMember(actorFrom(request), request.params.groupId, request.params.userId),
      ),
    removeMember: async (request, reply) =>
      reply.success(
        await service.removeMember(
          actorFrom(request),
          request.params.groupId,
          request.params.userId,
        ),
      ),
  };
}
