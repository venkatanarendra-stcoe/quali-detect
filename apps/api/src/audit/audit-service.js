import { assertAuditAction, isUuid } from "./actions.js";

/**
 * Append-only audit writer. Rows are never updated or deleted: this service has no such operation and PostgreSQL triggers
 * reject UPDATE/DELETE/TRUNCATE on `audit_logs` and `platform_audit_logs`.
 *
 * `record` is STRICT: pass the transaction client as `tx` so the audit row commits atomically with the change it describes
 * (if the audit write fails, the change rolls back). `recordSafe` is best effort, for events where failing the request
 * would be worse than losing the row (sign-in). `changes` holds before/after or added/removed diffs, never secrets.
 * Correlation ids that are not UUIDs (callers may send any safe token) are kept in `metadata.requestId`.
 * @param {{ db: any, logger: { error: Function } }} deps
 */
export function createAuditService({ db, logger }) {
  const normalize = (entry) => {
    assertAuditAction(entry.action);
    const { correlationId, targetId, metadata, ...rest } = entry;
    const extra = {};
    if (correlationId && !isUuid(correlationId)) extra.requestId = correlationId;
    if (targetId && !isUuid(targetId)) extra.targetRef = targetId;
    const merged = { ...(metadata ?? {}), ...extra };
    return {
      ...rest,
      targetId: isUuid(targetId) ? targetId : undefined,
      correlationId: isUuid(correlationId) ? correlationId : undefined,
      metadata: Object.keys(merged).length > 0 ? merged : undefined,
    };
  };
  const safely = (write) => async (entry) => {
    try {
      await write(entry);
    } catch (error) {
      logger.error({ err: error, action: entry.action }, "Could not write audit log");
    }
  };
  const writeTenant = (entry, { tx } = {}) =>
    (tx ?? db).auditLog.create({
      data: { actorType: entry.actorUserId ? "user" : "system", ...normalize(entry) },
    });
  const writePlatform = (entry, { tx } = {}) =>
    (tx ?? db).platformAuditLog.create({
      data: {
        actorType: entry.actorPlatformUserId ? "platform_user" : "system",
        ...normalize(entry),
      },
    });
  return Object.freeze({
    tenant: Object.freeze({
      /** @param {{ tenantId: string, actorUserId?: string, action: string, targetType?: string, targetId?: string, workspaceId?: string, changes?: object, metadata?: object, correlationId?: string, ipAddress?: string }} entry @param {{ tx?: any }} [options] */
      record: async (entry, options) => {
        if (!entry.tenantId) throw new TypeError("Tenant audit entries require tenantId.");
        await writeTenant(entry, options);
      },
      recordSafe: safely((entry) => writeTenant(entry)),
    }),
    platform: Object.freeze({
      /** @param {{ actorPlatformUserId?: string, action: string, targetType?: string, targetId?: string, tenantId?: string, metadata?: object, correlationId?: string, ipAddress?: string }} entry @param {{ tx?: any }} [options] */
      record: async (entry, options) => {
        await writePlatform(entry, options);
      },
      recordSafe: safely((entry) => writePlatform(entry)),
    }),
  });
}
