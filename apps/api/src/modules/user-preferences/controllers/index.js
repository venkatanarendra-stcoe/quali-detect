import { actorFrom } from "../../../lib/http.js";

/** @param {{ service: ReturnType<typeof import("../services/index.js").createUserPreferenceService> }} deps */
export function createUserPreferenceController({ service }) {
  return {
    get: async (request, reply) => reply.success(await service.get(actorFrom(request))),
    landing: async (request, reply) => reply.success(await service.landing(actorFrom(request))),
    update: async (request, reply) =>
      reply.success(await service.update(actorFrom(request), request.body)),
  };
}
