import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError, ForbiddenError } from "../../../errors/app-error.js";

/**
 * HTTP adapters: read validated input, check the policy, call the service, send the envelope. No business logic.
 * @param {{
 *   service: ReturnType<typeof import("../services/index.js").createSystemService>,
 *   policy: typeof import("../policies/index.js").systemPolicy,
 * }} deps
 */
export function createSystemController({ service, policy }) {
  return {
    /** Liveness: the process is up. */
    health: async (_request, reply) => reply.success({ status: "ok" }),
    /** Readiness: registered dependency checks pass. */
    ready: async (_request, reply) => {
      const { ready, checks } = await service.getReadiness();
      if (!ready) {
        throw new AppError(ERROR_CODES.SERVICE_UNAVAILABLE, "The service is not ready.", {
          details: { failedChecks: checks.filter((c) => c.status === "down").map((c) => c.name) },
        });
      }
      return reply.success({ status: "ready", checks });
    },
    info: async (_request, reply) => {
      if (!policy.canReadInfo()) throw new ForbiddenError();
      return reply.success(service.getInfo());
    },
    listModules: async (request, reply) => {
      if (!policy.canListModules()) throw new ForbiddenError();
      const { items, pagination } = service.listModules(request.query);
      return reply.paginated(items, pagination);
    },
    getModule: async (request, reply) => reply.success(service.getModule(request.params.name)),
  };
}
