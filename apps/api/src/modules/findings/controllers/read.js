import { actorFrom } from "../../../lib/http.js";

/**
 * Thin controllers of the findings read routes (docs/modules/findings/SPEC.md 8.1). `request.authz.resource` is the minimal reference the
 * scope resolver loaded (`id`, `workspaceId`): the service re-reads the finding by tenant, workspace and id.
 * @param {{ reads: ReturnType<typeof import("../services/read.js").createFindingsReadService> }} deps
 */
export function createFindingsReadController({ reads }) {
  const actor = (request) => actorFrom(request);
  const ref = (request) => ({
    id: request.authz.resource.id,
    workspaceId: request.authz.resource.workspaceId ?? request.authz.scope.workspaceId,
  });
  /** A finding's ETag is its revision: it changes with every change of the row the detail shows. */
  const etag = (rev) => `W/"finding-${rev}"`;
  return {
    list: async (request, reply) => {
      const { items, pagination } = await reads.list(actor(request), request.query);
      return reply.success(items, { pagination });
    },
    summary: async (request, reply) =>
      reply.success(await reads.summary(actor(request), request.query)),
    get: async (request, reply) => {
      const dto = await reads.get(actor(request), ref(request));
      reply.set("ETag", etag(dto.rev));
      return reply.success(dto);
    },
    history: async (request, reply) => {
      const { items, pagination } = await reads.history(
        actor(request),
        ref(request),
        request.query,
      );
      return reply.success(items, { pagination });
    },
    comments: async (request, reply) => {
      const { items, pagination } = await reads.comments(
        actor(request),
        ref(request),
        request.query,
      );
      return reply.success(items, { pagination });
    },
    similar: async (request, reply) =>
      reply.success(await reads.similar(actor(request), ref(request))),
  };
}
