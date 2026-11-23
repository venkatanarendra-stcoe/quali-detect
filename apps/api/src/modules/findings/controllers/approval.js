import { actorFrom } from "../../../lib/http.js";
import { findingEtag } from "./review.js";

/**
 * Thin controllers of the approval routes (Part B, docs/modules/findings/SPEC.md 8.1, 8.2): the Approvals queue, and approve and
 * reject of a review decision. See `review.js` for the conventions.
 * @param {{ service: ReturnType<typeof import("../services/approval.js").createFindingsApprovalService> }} deps
 */
export function createFindingsApprovalController({ service }) {
  const actor = (request) => actorFrom(request);
  const ref = (request) => ({
    id: request.authz.resource.id,
    workspaceId: request.authz.resource.workspaceId ?? request.authz.scope.workspaceId,
  });
  const send = (reply, dto) => {
    reply.set("ETag", findingEtag(dto.rev));
    return reply.success(dto);
  };
  return {
    approvals: async (request, reply) => {
      const { items, pagination } = await service.approvals(actor(request), request.query);
      return reply.success(items, { pagination });
    },
    approveReview: async (request, reply) =>
      send(
        reply,
        await service.approveReview(
          actor(request),
          ref(request),
          request.params.reviewId,
          request.body,
        ),
      ),
    rejectReview: async (request, reply) =>
      send(
        reply,
        await service.rejectReview(
          actor(request),
          ref(request),
          request.params.reviewId,
          request.body,
        ),
      ),
  };
}
