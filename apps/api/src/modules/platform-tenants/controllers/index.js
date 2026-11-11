/** Trusted context of the platform caller (session, never request input). @param {import("fastify").FastifyRequest} request */
const actorFrom = (request) => ({
  platformUserId: request.principal.platform.platformUser.id,
  permissions: request.principal.platform.permissions,
  requestId: request.id,
  ip: request.ip,
});

/** @param {{ service: ReturnType<typeof import("../services/index.js").createPlatformTenantService> }} deps */
export function createPlatformTenantController({ service }) {
  return {
    list: async (request, reply) => {
      const { items, pagination } = await service.list(actorFrom(request), request.query);
      return reply.paginated(items, pagination);
    },
    detail: async (request, reply) =>
      reply.success(await service.detail(actorFrom(request), request.params.tenantId)),
    provision: async (request, reply) =>
      reply.code(201).success(await service.provision(actorFrom(request), request.body)),
    /** One handler per lifecycle action (the action comes from the route, not from input). */
    lifecycle: (action) => async (request, reply) =>
      reply.success(
        await service.changeLifecycle(
          actorFrom(request),
          request.params.tenantId,
          action,
          request.body,
        ),
      ),
    plans: async (_request, reply) => reply.success(await service.listPlanVersions()),
  };
}
