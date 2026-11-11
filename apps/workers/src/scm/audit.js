/**
 * System audit entries written by workers (the API's audit service lives in the API process). Same table, same
 * immutability; `actorType: "system"`. Call inside the transaction of the change it describes.
 * @param {any} tx Prisma transaction client
 * @param {{ tenantId: string, action: string, targetType: string, targetId: string, workspaceId?: string | null, metadata?: object }} entry
 */
export function auditSystem(
  tx,
  { tenantId, action, targetType, targetId, workspaceId = null, metadata = {} },
) {
  return tx.auditLog.create({
    data: { tenantId, actorType: "system", action, targetType, targetId, workspaceId, metadata },
  });
}
