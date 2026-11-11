import { resultOf } from "../../../lib/audit-view.js";

/** @param {any} row platform_audit_logs row with its actor */
export const toPlatformAuditEntryDto = (row) => ({
  id: row.id,
  createdAt: row.createdAt,
  action: row.action,
  result: resultOf(row.action),
  actor: row.actorPlatformUserId
    ? {
        type: "platform_user",
        id: row.actorPlatformUserId,
        name: row.actor?.name ?? null,
        email: row.actor?.email ?? null,
      }
    : { type: row.actorType, id: null, name: null, email: null },
  target: { type: row.targetType, id: row.targetId },
  workspaceId: null,
  tenantId: row.tenantId,
  correlationId: row.correlationId,
  ipAddress: row.ipAddress,
  changes: null,
  metadata: row.metadata,
});
