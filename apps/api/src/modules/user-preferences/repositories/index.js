/**
 * Data access for user preferences. Every query carries the tenant AND the user (the unique key is `tenantId_userId`), so a
 * row is never reached by the user id alone.
 * @param {{ db: any }} deps
 */
export function createUserPreferenceRepository({ db }) {
  return Object.freeze({
    /** @param {{ tenantId: string, userId: string }} scope */
    find: ({ tenantId, userId }, client = db) =>
      client.userPreference.findUnique({ where: { tenantId_userId: { tenantId, userId } } }),
    /**
     * Creates or updates the user's row with the supplied fields only (atomic, idempotent).
     * @param {{ tenantId: string, userId: string, data: { accent?: string, defaultWorkspaceId?: string | null } }} input
     */
    upsert: ({ tenantId, userId, data }, client = db) =>
      client.userPreference.upsert({
        where: { tenantId_userId: { tenantId, userId } },
        create: { ...data, tenantId, userId },
        update: data,
      }),
    /**
     * A workspace of THIS tenant by id (never by id alone); null when it does not exist in the tenant.
     * @param {{ tenantId: string, workspaceId: string }} scope
     */
    findWorkspaceInTenant: ({ tenantId, workspaceId }, client = db) =>
      client.workspace.findFirst({
        where: { tenantId, id: workspaceId },
        select: { id: true, status: true },
      }),
  });
}
