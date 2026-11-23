import { actorFrom } from "../../../lib/http.js";

/**
 * Thin controller of the SLA settings routes (Part C, docs/modules/findings/SPEC.md 8.1, 8.2). The tenant is the session's; nothing in
 * the request names one.
 * @param {{ sla: ReturnType<typeof import("../services/sla.js").createFindingsSlaService> }} deps
 */
export function createFindingsSlaController({ sla }) {
  return {
    get: async (request, reply) => reply.success(await sla.get(actorFrom(request))),
    put: async (request, reply) => reply.success(await sla.put(actorFrom(request), request.body)),
  };
}
