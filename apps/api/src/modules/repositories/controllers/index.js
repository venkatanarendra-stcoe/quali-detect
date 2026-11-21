import { actorFrom } from "../../../lib/http.js";
import { isNotModified } from "../../../lib/conditional.js";

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
    /**
     * The one raw (non-envelope) response of this module: the stored SBOM document as an attachment. Errors keep the envelope.
     * The audit entry `repository.sbom_downloaded` is written ONLY when a 200 body is actually sent (owner decision 2026-11-21): a
     * conditional request whose `If-None-Match` still matches the ETag is answered 304 with no body and no audit entry (and no
     * document header beyond the validators), a HEAD request sends no body and writes none, and for a 200 the entry is written BEFORE
     * the send, so a failing audit write refuses the download and no body leaves. The freshness test is
     * evaluated (`isNotModified`, RFC 9110 weak comparison) after the permission and the scope of the route and the lookup, so a 304 is never an oracle for another tenant's
     * document (the same plain 404/403 answers come first).
     */
    sbom: async (request, reply) => {
      const actor = actorFrom(request);
      const file = await service.sbom(actor, repo(request), request.query);
      reply.set({ ETag: file.etag, "Cache-Control": "private, no-store" });
      if (isNotModified(request, file.etag)) return reply.status(304).end();
      const headers = {
        "Content-Type": file.mediaType,
        "Content-Disposition": `attachment; filename="${file.fileName}"`,
        "X-Content-Type-Options": "nosniff",
      };
      if (request.method === "HEAD") return reply.status(200).set(headers).end();
      try {
        await service.recordSbomDownload(actor, repo(request), file);
      } catch (error) {
        reply.removeHeader("ETag");
        throw error;
      }
      return reply.status(200).set(headers).send(file.content);
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
