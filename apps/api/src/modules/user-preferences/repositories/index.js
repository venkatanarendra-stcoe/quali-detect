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
     * @param {{ tenantId: string, userId: string, data: { accent?: string } }} input
     */
    upsert: ({ tenantId, userId, data }, client = db) =>
      client.userPreference.upsert({
        where: { tenantId_userId: { tenantId, userId } },
        create: { ...data, tenantId, userId },
        update: data,
      }),
  });
}
