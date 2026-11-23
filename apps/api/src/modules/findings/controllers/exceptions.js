import { actorFrom } from "../../../lib/http.js";
import { findingEtag } from "./review.js";

/**
 * Thin controllers of the exception routes (Part B, docs/modules/findings/SPEC.md 5.8, 8.2): request, withdraw, approve, reject and
 * revoke an accept-risk or suppression exception. See `review.js` for the conventions.
 * @param {{ service: ReturnType<typeof import("../services/exceptions.js").createFindingsExceptionsService> }} deps
 */
export function createFindingsExceptionsController({ service }) {
  const actor = (request) => actorFrom(request);
  const ref = (request) => ({
    id: request.authz.resource.id,
    workspaceId: request.authz.resource.workspaceId ?? request.authz.scope.workspaceId,
  });
  const send = (reply, dto, status = 200) => {
    reply.set("ETag", findingEtag(dto.rev));
    return reply.code(status).success(dto);
  };
  const exceptionId = (request) => request.params.exceptionId;
  return {
    request: async (request, reply) =>
      send(reply, await service.request(actor(request), ref(request), request.body), 201),
    withdraw: async (request, reply) =>
      send(reply, await service.withdraw(actor(request), ref(request), exceptionId(request))),
    approve: async (request, reply) =>
      send(
        reply,
        await service.approve(actor(request), ref(request), exceptionId(request), request.body),
      ),
    reject: async (request, reply) =>
      send(
        reply,
        await service.reject(actor(request), ref(request), exceptionId(request), request.body),
      ),
    revoke: async (request, reply) =>
      send(
        reply,
        await service.revoke(actor(request), ref(request), exceptionId(request), request.body),
      ),
  };
}
