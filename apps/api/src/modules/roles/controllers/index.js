import { actorFrom } from "../../../lib/http.js";

/** @param {{ service: ReturnType<typeof import("../services/index.js").createRoleService> }} deps */
export function createRoleController({ service }) {
  return {
    permissions: async (_request, reply) => reply.success(service.listPermissions()),
    list: async (request, reply) => {
      const { items, pagination } = await service.list(actorFrom(request), request.query);
      return reply.paginated(items, pagination);
    },
    get: async (request, reply) =>
      reply.success(await service.get(actorFrom(request), request.params.roleId)),
    create: async (request, reply) =>
      reply.code(201).success(await service.create(actorFrom(request), request.body)),
    update: async (request, reply) =>
      reply.success(await service.update(actorFrom(request), request.params.roleId, request.body)),
    delete: async (request, reply) =>
      reply.success(await service.delete(actorFrom(request), request.params.roleId)),
  };
}
