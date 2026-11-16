import { actorFrom } from "../../../lib/http.js";
import { toWorkspaceDto } from "../mappers/index.js";

/** @param {{ service: ReturnType<typeof import("../services/index.js").createWorkspaceService> }} deps */
export function createWorkspaceController({ service }) {
  return {
    list: async (request, reply) => {
      const { items, pagination } = await service.list(actorFrom(request), request.query);
      return reply.paginated(items, pagination);
    },
    overview: async (request, reply) => reply.success(await service.overview(actorFrom(request))),
    create: async (request, reply) =>
      reply.code(201).success(await service.create(actorFrom(request), request.body)),
    get: async (request, reply) => reply.success(toWorkspaceDto(request.authz.resource)),
    update: async (request, reply) =>
      reply.success(await service.update(actorFrom(request), request.authz.resource, request.body)),
    archive: async (request, reply) =>
      reply.success(await service.setArchived(actorFrom(request), request.authz.resource, true)),
    restore: async (request, reply) =>
      reply.success(await service.setArchived(actorFrom(request), request.authz.resource, false)),
  };
}
