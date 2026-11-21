import { actorFrom } from "../../../lib/http.js";

/** @param {{ service: ReturnType<typeof import("../services/index.js").createRepositoryService> }} deps */
export function createRepositoryController({ service }) {
  const repo = (request) => request.authz.resource;
  return {
    list: async (request, reply) => {
      const { items, pagination } = await service.list(actorFrom(request), request.query);
      return reply.paginated(items, pagination);
    },
    available: async (request, reply) => {
      const { items, pagination } = await service.available(
        actorFrom(request),
        request.params.workspaceId,
        request.query,
      );
      return reply.paginated(items, pagination);
    },
    connect: async (request, reply) =>
      reply
        .code(201)
        .success(
          await service.connect(actorFrom(request), request.params.workspaceId, request.body),
        ),
    get: async (request, reply) =>
      reply.success(await service.get(actorFrom(request), repo(request))),
    /** The one raw (non-envelope) response of this module: the stored SBOM document as an attachment. Errors keep the envelope. */
    sbom: async (request, reply) => {
      const file = await service.sbom(actorFrom(request), repo(request), request.query);
      return reply
        .status(200)
        .set({
          "Content-Type": file.mediaType,
          "Content-Disposition": `attachment; filename="${file.fileName}"`,
          "X-Content-Type-Options": "nosniff",
          "Cache-Control": "private, no-store",
          ETag: file.etag,
        })
        .send(file.content);
    },
    update: async (request, reply) =>
      reply.success(await service.update(actorFrom(request), repo(request), request.body)),
    sync: async (request, reply) =>
      reply.code(202).success(await service.sync(actorFrom(request), repo(request))),
    enable: async (request, reply) =>
      reply.success(await service.setEnabled(actorFrom(request), repo(request), true)),
    disable: async (request, reply) =>
      reply.success(await service.setEnabled(actorFrom(request), repo(request), false)),
    disconnect: async (request, reply) =>
      reply.success(await service.disconnect(actorFrom(request), repo(request), request.body)),
    branches: async (request, reply) =>
      reply.success(await service.branches(actorFrom(request), repo(request))),
    pullRequests: async (request, reply) =>
      reply.success(await service.pullRequests(actorFrom(request), repo(request))),
  };
}
