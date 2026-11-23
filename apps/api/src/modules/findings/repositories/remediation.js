import {
  createFindingAssignmentsRepository,
  createFindingRemediationRepository,
} from "@qmentisai/db";
import { createFindingsLifecycleRepository } from "./lifecycle.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Data access of the remediation, board and SLA-settings routes (Part C, docs/modules/findings/SPEC.md 8.1, 8.2): the write
 * transaction helpers of Part B (`createFindingsLifecycleRepository`: transaction, workspace status, the locked finding, member lookup)
 * plus the `@qmentisai/db` assignment and remediation repositories bound to this module's Prisma client. Prisma stays in the repository
 * layer; every method takes the trusted `{ tenantId, workspaceId }` scope of the request (FS-1).
 * @param {{ db: any }} deps
 */
export function createFindingsRemediationRepository({ db }) {
  const base = createFindingsLifecycleRepository({ db });
  const assignments = createFindingAssignmentsRepository({ db });
  const remediation = createFindingRemediationRepository({ db });
  return Object.freeze({
    ...base,
    assignments,
    remediation,

    /**
     * Whether the finding's pipeline is soft-deleted (no scan can verify a fix there, SPEC 5.13), by tenant AND workspace AND id.
     * @param {any} tx @param {{ tenantId: string, workspaceId: string }} scope @param {string} pipelineId
     */
    async pipelineDeleted(tx, scope, pipelineId) {
      const row = await tx.pipeline.findFirst({
        where: { tenantId: scope.tenantId, workspaceId: scope.workspaceId, id: pipelineId },
        select: { deletedAt: true },
      });
      return row === null || row.deletedAt !== null;
    },

    /**
     * The audit entry of a change of the tenant's SLA targets (`tenant.findings_sla_changed`, SPEC 11.4), written in the caller's
     * transaction. Metadata: the changed severities with their previous and new hours (numbers and enums only).
     * @param {any} tx
     * @param {{ tenantId: string, userId: string, requestId?: string, ip?: string }} actor
     * @param {Array<{ severity: string, previous: number | null, next: number | null }>} changes
     */
    async auditSlaChange(tx, actor, changes) {
      await tx.auditLog.create({
        data: {
          tenantId: actor.tenantId,
          actorType: "user",
          actorUserId: actor.userId,
          action: "tenant.findings_sla_changed",
          targetType: "tenant",
          targetId: actor.tenantId,
          metadata: {
            changes: changes.map((c) => ({
              severity: c.severity,
              previousHours: c.previous,
              newHours: c.next,
            })),
          },
          ...(actor.requestId && UUID.test(actor.requestId)
            ? { correlationId: actor.requestId }
            : {}),
          ...(actor.ip ? { ipAddress: actor.ip } : {}),
        },
      });
    },
  });
}
