import { actorFrom } from "../../../lib/http.js";
import { findingEtag } from "../mappers/etag.js";

/**
 * Thin controllers of the assignment, remediation and board routes (Part C, docs/modules/findings/SPEC.md 8.1, 8.2): parse nothing (the
 * route kit validated params, query and body), call the service with the trusted actor and the authorized resource reference, send the
 * standard envelope. A write answers with the finding AS THE CALLER now sees it and its new `ETag`, like Part B.
 * @param {{
 *   remediation: ReturnType<typeof import("../services/remediation.js").createFindingsRemediationService>,
 *   board: ReturnType<typeof import("../services/board.js").createFindingsBoardService>,
 * }} deps
 */
export function createFindingsRemediationController({ remediation, board }) {
  const actor = (request) => actorFrom(request);
  const ref = (request) => ({
    id: request.authz.resource.id,
    workspaceId: request.authz.resource.workspaceId ?? request.authz.scope.workspaceId,
  });
  const send = (reply, dto, status = 200) => {
    reply.set("ETag", findingEtag(dto));
    return reply.code(status).success(dto);
  };
  return {
    assign: async (request, reply) =>
      send(reply, await remediation.assign(actor(request), ref(request), request.body), 201),
    clear: async (request, reply) =>
      send(reply, await remediation.clear(actor(request), ref(request), request.body)),
    start: async (request, reply) =>
      send(reply, await remediation.start(actor(request), ref(request), request.body)),
    submit: async (request, reply) =>
      send(reply, await remediation.submit(actor(request), ref(request), request.body)),
    bulkAssign: async (request, reply) =>
      reply.success(await remediation.bulkAssign(actor(request), request.body)),
    board: async (request, reply) =>
      reply.success(await board.board(actor(request), request.query)),
    boardColumn: async (request, reply) => {
      const { items, pagination } = await board.column(
        actor(request),
        request.params.column,
        request.query,
      );
      return reply.success(items, { pagination });
    },
  };
}
