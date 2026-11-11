import { resultOf } from "../../../lib/audit-view.js";

/** @param {any} row audit_logs row with its actor */
export const toAuditEntryDto = (row) => ({
  id: row.id,
  createdAt: row.createdAt,
  action: row.action,
  result: resultOf(row.action),
  actor: row.actorUserId
    ? {
        type: "user",
        id: row.actorUserId,
        name: row.actor?.name ?? null,
        email: row.actor?.email ?? null,
      }
    : { type: row.actorType, id: null, name: null, email: null },
  target: { type: row.targetType, id: row.targetId },
  workspaceId: row.workspaceId,
  tenantId: row.tenantId,
  correlationId: row.correlationId,
  ipAddress: row.ipAddress,
  changes: row.changes,
  metadata: row.metadata,
});
