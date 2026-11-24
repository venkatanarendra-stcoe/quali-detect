import { FindingNotFoundError } from "@qmentisai/db";
import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError, ConflictError, NotFoundError } from "../../../errors/app-error.js";
import { toAdvisoryDto } from "../mappers/advisory.js";
import { advisoryRequestPolicy } from "../policies/advisory.js";

/**
 * The manual advisory request (docs/modules/findings/SPEC.md 8.2, 9.3.5). It writes ONE `finding.advisory.requested` job to the outbox and
 * ONE audit entry in the same transaction and nothing else: no advisory row (only the agent writes those), no finding change. The tenant
 * and user come from the session; the finding is loaded by tenant, workspace and id.
 * @param {{
 *   repository: ReturnType<typeof import("@qmentisai/db").createFindingAdvisoriesRepository>,
 *   audit: any,
 *   enabled: () => boolean,
 *   now?: () => Date,
 * }} deps `enabled`: whether the advisory agent is switched on (FINDINGS_AGENT_ENABLED); off means no job is queued
 */
export function createAdvisoryService({ repository, audit, enabled, now = () => new Date() }) {
  return Object.freeze({
    /**
     * @param {{ tenantId: string, userId: string, requestId?: string, ip?: string }} actor
     * @param {{ id: string, workspaceId: string }} ref the authorized finding reference (the workspace of the engine's decision)
     * @returns {Promise<ReturnType<typeof toAdvisoryDto>>} `pending` when queued, `not_configured` when the agent is off
     */
    async request(actor, ref) {
      const at = now();
      const scope = { tenantId: actor.tenantId, workspaceId: ref.workspaceId };
      try {
        return await repository.transaction(async (tx) => {
          // an archived workspace refuses every mutation, like every other findings write (D-F1): before the finding is even locked
          if ((await repository.workspaceStatus(tx, scope)) === "archived")
            throw new ConflictError("The workspace is archived.", {
              details: { reason: "workspace_archived" },
            });
          const { finding } = await repository.lockForRequest(tx, scope, ref.id);
          const policy = advisoryRequestPolicy(finding);
          if (!policy.allowed)
            throw new AppError(
              ERROR_CODES.FINDING_STATE_CONFLICT,
              "An advisory is not available for this finding.",
              { details: { reason: "transition_not_allowed" } },
            );
          if (!enabled()) return toAdvisoryDto({ status: "not_configured", egressLevel: "none" });
          if (!(await repository.requestAllowed(scope, finding.id, actor.userId, at, tx)))
            throw new AppError(
              ERROR_CODES.RATE_LIMITED,
              "Too many advisory requests. Try again later.",
              { details: { reason: "advisory_request_limit" } },
            );
          await repository.enqueueManual(tx, {
            tenantId: actor.tenantId,
            finding,
            userId: actor.userId,
            correlationId: actor.requestId,
            now: at,
          });
          await audit.tenant.record(
            {
              tenantId: actor.tenantId,
              actorUserId: actor.userId,
              action: "finding.advisory_requested",
              targetType: "finding",
              targetId: finding.id,
              workspaceId: finding.workspaceId,
              correlationId: actor.requestId,
              ipAddress: actor.ip,
              metadata: { reason: "manual" },
            },
            { tx },
          );
          return toAdvisoryDto(null, { pending: true });
        });
      } catch (error) {
        if (error instanceof FindingNotFoundError) throw new NotFoundError();
        throw error;
      }
    },
  });
}
