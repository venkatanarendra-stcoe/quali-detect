import { actorFrom } from "../../../lib/http.js";

/**
 * Thin controllers (SPEC executions §8.1). `request.authz.resource` is the minimal reference the scope resolver loaded
 * (`id`, `workspaceId`): the services re-read the execution by tenant, workspace and id.
 * @param {{
 *   service: ReturnType<typeof import("../services/index.js").createExecutionService>,
 *   reads: ReturnType<typeof import("../services/read.js").createExecutionReadService>,
 * }} deps
 */
export function createExecutionController({ service, reads }) {
  const actor = (request) => ({
    ...actorFrom(request),
    tenantStatus: request.principal.tenant.status,
  });
  const ref = (request) => ({
    id: request.authz.resource.id,
    workspaceId: request.authz.resource.workspaceId,
  });
  return {
    list: async (request, reply) => {
      const { items, pagination } = await reads.list(actor(request), request.query);
      return reply.success(items, { pagination });
    },
    get: async (request, reply) => reply.success(await reads.get(actor(request), ref(request))),
    events: async (request, reply) => {
      const { items, pagination } = await reads.events(actor(request), ref(request), request.query);
      return reply.success(items, { pagination });
    },
    logs: async (request, reply) =>
      reply.success(await reads.logs(actor(request), ref(request), request.query)),
    cancel: async (request, reply) => {
      const result = await service.cancel(actor(request), ref(request));
      return result.outcome === "cancelled"
        ? reply.code(200).success({ execution: result.execution })
        : reply.code(202).success({ execution: result.execution, cancelRequested: true });
    },
    retry: async (request, reply) => {
      const { execution } = await service.retry(
        actor(request),
        ref(request),
        request.get("Idempotency-Key"),
      );
      return reply.code(202).success({ execution });
    },
  };
}
