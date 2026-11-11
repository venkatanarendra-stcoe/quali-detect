import { actorFrom } from "../../../lib/http.js";

/** @param {{ service: ReturnType<typeof import("../services/index.js").createAuditLogService> }} deps */
export function createAuditLogController({ service }) {
  return {
    list: async (request, reply) => {
      const { items, pagination } = await service.list(actorFrom(request), request.query);
      return reply.paginated(items, pagination);
    },
  };
}
