import { actorFrom } from "../../../lib/http.js";

/** @param {{ service: ReturnType<typeof import("../services/index.js").createTenantAiSettingsService> }} deps */
export function createTenantAiSettingsController({ service }) {
  return {
    get: async (request, reply) => reply.success(await service.get(actorFrom(request))),
    update: async (request, reply) =>
      reply.success(await service.update(actorFrom(request), request.body)),
  };
}
