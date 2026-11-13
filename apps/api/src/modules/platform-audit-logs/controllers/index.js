/** @param {{ service: ReturnType<typeof import("../services/index.js").createPlatformAuditLogService> }} deps */
export function createPlatformAuditLogController({ service }) {
  return {
    list: async (request, reply) => {
      const { items, pagination } = await service.list(
        { platformUserId: request.principal.platform.platformUser.id },
        request.query,
      );
      return reply.paginated(items, pagination);
    },
  };
}
