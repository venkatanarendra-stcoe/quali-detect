import { actorFrom } from "../../../lib/http.js";

/**
 * Thin controller of the advisory request route. `request.authz.resource` is the minimal finding reference the scope resolver loaded
 * (by tenant and id); the service re-reads the finding by tenant, workspace and id.
 * @param {{ advisories: ReturnType<typeof import("../services/advisory.js").createAdvisoryService> }} deps
 */
export function createAdvisoryController({ advisories }) {
  return {
    request: async (request, reply) => {
      const resource = request.authz.resource;
      const dto = await advisories.request(actorFrom(request), {
        id: resource.id,
        workspaceId: resource.workspaceId ?? request.authz.scope.workspaceId,
      });
      return reply.code(202).success(dto);
    },
  };
}
