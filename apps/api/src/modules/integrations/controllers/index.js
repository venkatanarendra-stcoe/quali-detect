import { actorFrom } from "../../../lib/http.js";

/** Trusted caller context plus the session id (bound into the linking state). @param {import("express").Request} request */
const actor = (request) => ({ ...actorFrom(request), sessionId: request.principal.session.id });

/** @param {{ service: ReturnType<typeof import("../services/index.js").createIntegrationService> }} deps */
export function createIntegrationController({ service }) {
  return {
    catalog: async (request, reply) => reply.success(await service.catalog(actor(request))),
    overview: async (request, reply) => reply.success(await service.overview(actor(request))),
    list: async (request, reply) => reply.success(await service.list(actor(request))),
    start: async (_request, reply) => reply.success(service.start()),
    authorize: async (request, reply) =>
      reply.success(await service.authorize(actor(request), request.body)),
    link: async (request, reply) =>
      reply.code(201).success(await service.link(actor(request), request.body)),
    refresh: async (request, reply) =>
      reply.success(await service.refresh(actor(request), request.params.linkId)),
    setScope: async (request, reply) =>
      reply.success(await service.setScope(actor(request), request.params.linkId, request.body)),
    workspaceLinks: async (request, reply) =>
      reply.success(await service.workspaceLinks(actor(request), request.params.workspaceId)),
    setWorkspaceRouting: async (request, reply) =>
      reply.success(
        await service.setWorkspaceRouting(
          actor(request),
          request.params.workspaceId,
          request.params.linkId,
          request.body,
        ),
      ),
    deliveries: async (request, reply) => {
      const { items, pagination } = await service.listDeliveries(
        actor(request),
        request.params.linkId,
        request.query,
      );
      return reply.paginated(items, pagination);
    },
    unlink: async (request, reply) =>
      reply.success(await service.unlink(actor(request), request.params.linkId, request.body)),
  };
}
