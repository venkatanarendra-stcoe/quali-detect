import { actorFrom } from "../../../lib/http.js";

/** Trusted caller context plus the session id (bound into the linking state). @param {import("express").Request} request */
const actor = (request) => ({ ...actorFrom(request), sessionId: request.principal.session.id });

/** @param {{ service: ReturnType<typeof import("../services/index.js").createIntegrationService> }} deps */
export function createIntegrationController({ service }) {
  return {
    catalog: async (request, reply) => reply.success(await service.catalog(actor(request))),
    overview: async (request, reply) => reply.success(await service.overview(actor(request))),
    listInstallations: async (request, reply) =>
      reply.success(await service.listInstallations(actor(request))),
    getSettings: async (request, reply) => reply.success(await service.getSettings(actor(request))),
    updateSettings: async (request, reply) =>
      reply.success(await service.updateSettings(actor(request), request.body)),
    workspaceOverview: async (request, reply) =>
      reply.success(await service.workspaceOverview(actor(request), request.params.workspaceId)),
    start: async (request, reply) => reply.success(await service.start(actor(request))),
    authorize: async (request, reply) =>
      reply.success(
        await service.authorize(actor(request), request.params.workspaceId, request.body),
      ),
    discover: async (request, reply) =>
      reply.success(await service.discover(actor(request), request.params.workspaceId)),
    link: async (request, reply) => {
      const result = await service.link(actor(request), request.body);
      // A discovery state lists candidates (200) and links nothing; a linking state creates the link (201).
      return (result.mode === "discover" ? reply : reply.code(201)).success(result);
    },
    refresh: async (request, reply) =>
      reply.success(
        await service.refresh(actor(request), request.params.workspaceId, request.params.linkId),
      ),
    listAllowList: async (request, reply) => {
      const { items, pagination } = await service.listAllowList(
        actor(request),
        request.params.workspaceId,
        request.params.linkId,
        request.query,
      );
      return reply.paginated(items, pagination);
    },
    setAllowList: async (request, reply) =>
      reply.success(
        await service.setAllowList(
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
      reply.success(
        await service.unlink(
          actor(request),
          request.params.workspaceId,
          request.params.linkId,
          request.body,
        ),
      ),
  };
}
