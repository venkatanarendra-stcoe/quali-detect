import { actorFrom } from "../../../lib/http.js";

/**
 * The trusted caller for services: tenant and user from the session, permissions from the authorization engine, and the
 * tenant status the session was resolved with (it feeds the derived effective state).
 * @param {import("express").Request} request
 */
const actor = (request) => ({
  ...actorFrom(request),
  tenantStatus: request.principal.tenant.status,
});

/** @param {{ service: ReturnType<typeof import("../services/index.js").createPipelineService> }} deps */
export function createPipelineController({ service }) {
  const resource = (request) => request.authz.resource;
  return {
    list: async (request, reply) => {
      const { items, pagination } = await service.list(actor(request), request.query);
      return reply.paginated(items, pagination);
    },
    listForRepository: async (request, reply) => {
      const { items, pagination } = await service.listForRepository(
        actor(request),
        resource(request),
        request.query,
      );
      return reply.paginated(items, pagination);
    },
    create: async (request, reply) =>
      reply
        .code(201)
        .success(await service.create(actor(request), resource(request), request.body)),
    get: async (request, reply) =>
      reply.success(await service.get(actor(request), resource(request))),
    update: async (request, reply) =>
      reply.success(await service.update(actor(request), resource(request), request.body)),
    listVersions: async (request, reply) => {
      const { items, pagination } = await service.listVersions(
        actor(request),
        resource(request),
        request.query,
      );
      return reply.paginated(items, pagination);
    },
    getVersion: async (request, reply) =>
      reply.success(
        await service.getVersion(actor(request), resource(request), request.params.version),
      ),
    publishConfig: async (request, reply) =>
      reply.success(await service.publishConfig(actor(request), resource(request), request.body)),
    enable: async (request, reply) =>
      reply.success(await service.setEnabled(actor(request), resource(request), true)),
    disable: async (request, reply) =>
      reply.success(await service.setEnabled(actor(request), resource(request), false)),
    remove: async (request, reply) =>
      reply.success(await service.remove(actor(request), resource(request), request.body)),
    run: async (request, reply) =>
      reply
        .code(202)
        .success(
          await service.run(
            actor(request),
            resource(request),
            request.body,
            request.get("Idempotency-Key"),
          ),
        ),
    listExecutions: async (request, reply) => {
      const { items, pagination } = await service.listExecutions(
        actor(request),
        resource(request),
        request.query,
      );
      return reply.paginated(items, pagination);
    },
    listDecisions: async (request, reply) => {
      const { items, pagination } = await service.listDecisions(
        actor(request),
        resource(request),
        request.query,
      );
      return reply.paginated(items, pagination);
    },
    dryRun: async (request, reply) =>
      reply.success(await service.dryRun(actor(request), resource(request), request.body)),
    options: async (request, reply) => reply.success(await service.options(actor(request))),
  };
}
