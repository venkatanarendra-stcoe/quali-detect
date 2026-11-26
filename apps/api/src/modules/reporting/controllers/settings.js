import { actorFrom } from "../../../lib/http.js";

const KEY = /^[A-Za-z0-9._:-]{8,128}$/;

/** @param {{ service: ReturnType<typeof import("../services/settings.js").createReportingSettingsService> }} deps */
export function createReportingSettingsController({ service }) {
  return {
    get: async (request, reply) => reply.success(await service.get(actorFrom(request))),
    update: async (request, reply) => {
      const header = request.get("Idempotency-Key");
      return reply.success(
        await service.update(actorFrom(request), request.body, {
          idempotencyKey: typeof header === "string" && KEY.test(header) ? header : null,
        }),
      );
    },
  };
}
