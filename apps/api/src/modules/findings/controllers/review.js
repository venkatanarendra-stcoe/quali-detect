import { actorFrom } from "../../../lib/http.js";

/** A finding's ETag is its revision (the same value `GET /findings/{id}` sends). @param {number} rev */
export const findingEtag = (rev) => `W/"finding-${rev}"`;

/**
 * Thin controllers of the findings write routes (Part B, docs/modules/findings/SPEC.md 8.2): parse nothing (the route kit validated
 * params, query and body), call the service with the trusted actor and the authorized resource reference, send the standard envelope.
 * `request.authz.resource` is the minimal reference the scope resolver loaded (`id`, `workspaceId`): the service re-reads the finding by
 * tenant, workspace and id. A write answers with the finding AS THE CALLER now sees it (and its new `ETag`).
 * @param {{ service: ReturnType<typeof import("../services/review.js").createFindingsReviewService> }} deps
 */
export function createFindingsReviewController({ service }) {
  const actor = (request) => actorFrom(request);
  const ref = (request) => ({
    id: request.authz.resource.id,
    workspaceId: request.authz.resource.workspaceId ?? request.authz.scope.workspaceId,
  });
  /** @param {import("express").Response & { success: Function, code: Function }} reply @param {any} dto @param {number} [status] */
  const sendFinding = (reply, dto, status = 200) => {
    reply.set("ETag", findingEtag(dto.rev));
    return reply.code(status).success(dto);
  };
  return {
    reviewQueue: async (request, reply) => {
      const { items, pagination } = await service.reviewQueue(actor(request), request.query);
      return reply.success(items, { pagination });
    },
    claim: async (request, reply) =>
      sendFinding(reply, await service.claim(actor(request), ref(request), request.body)),
    createReview: async (request, reply) =>
      sendFinding(
        reply,
        await service.createReview(actor(request), ref(request), request.body),
        201,
      ),
    withdrawReview: async (request, reply) =>
      sendFinding(
        reply,
        await service.withdrawReview(
          actor(request),
          ref(request),
          request.params.reviewId,
          request.body,
        ),
      ),
    reopenReview: async (request, reply) =>
      sendFinding(reply, await service.reopenReview(actor(request), ref(request), request.body)),
    addComment: async (request, reply) =>
      reply.code(201).success(await service.addComment(actor(request), ref(request), request.body)),
    bulkClaim: async (request, reply) =>
      reply.success(await service.bulkClaim(actor(request), request.body)),
  };
}
