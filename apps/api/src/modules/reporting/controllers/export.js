import { pipeline } from "node:stream/promises";
import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError } from "../../../errors/app-error.js";
import { actorFrom } from "../../../lib/http.js";
import { cursorBinding, decodeCursor, encodeCursor } from "../../../lib/keyset.js";

const CURSOR_TERMS = Object.freeze([
  { field: "createdAt", direction: "desc", type: "date", nullable: false },
  { field: "id", direction: "desc", type: "uuid", nullable: false },
]);

/**
 * Thin controllers of the export routes (Part C). The download streams the file through `pipeline` (back pressure, closed on a client
 * abort) with `Content-Disposition: attachment` and a SERVER-built filename, `Content-Type` from the format, `Cache-Control: no-store` and
 * `X-Content-Type-Options: nosniff`; it is an authenticated stream, never a link.
 * @param {{ service: ReturnType<typeof import("../services/export.js").createReportExportService> }} deps
 */
export function createReportExportController({ service }) {
  const binding = (actor, query) =>
    cursorBinding({
      kind: "reporting.reports",
      scope: actor.tenantId,
      query: { workspaceId: query.workspaceId, status: query.status },
      sort: "created_desc",
      terms: /** @type {any} */ (CURSOR_TERMS),
    });
  return {
    create: async (request, reply) =>
      reply.code(202).success(await service.create(actorFrom(request), request.body)),

    list: async (request, reply) => {
      const actor = actorFrom(request);
      const query = request.query;
      const bound = binding(actor, query);
      const after = query.cursor
        ? (() => {
            const [createdAt, id] = decodeCursor(query.cursor, {
              binding: bound,
              terms: /** @type {any} */ (CURSOR_TERMS),
            });
            return {
              createdAt: new Date(/** @type {any} */ (createdAt).toISOString()),
              id: /** @type {string} */ (id),
            };
          })()
        : null;
      const { items, next } = await service.list(actor, query, after);
      const nextCursor = next
        ? encodeCursor({ binding: bound, values: [next.createdAt, next.id] })
        : null;
      return reply.success({ items, nextCursor });
    },

    get: async (request, reply) =>
      reply.success(await service.get(actorFrom(request), request.authz.resource.id)),

    download: async (request, reply) => {
      const file = await service.download(actorFrom(request), request.authz.resource.id);
      reply.status(200);
      reply.set({
        "Content-Type": file.contentType,
        "Content-Length": String(file.bytes),
        "Content-Disposition": `attachment; filename="${file.filename}"`,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      try {
        await pipeline(file.stream, reply);
      } catch (error) {
        // headers are already out: end the connection, never write an error body into the file
        if (!reply.headersSent)
          throw new AppError(ERROR_CODES.SERVICE_UNAVAILABLE, "The report file is not available.", {
            cause: error,
          });
        reply.destroy();
      }
    },

    remove: async (request, reply) => {
      await service.remove(actorFrom(request), request.authz.resource.id);
      return reply.success({ deleted: true });
    },
  };
}
