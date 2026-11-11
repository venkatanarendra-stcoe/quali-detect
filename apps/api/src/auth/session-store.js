const TABLES = Object.freeze({
  tenant: { delegate: "session", subject: "userId" },
  platform: { delegate: "platformSession", subject: "platformUserId" },
});

/**
 * Data access for server-side sessions. One store per audience: tenant sessions live in `sessions`, platform sessions in
 * `platform_sessions`, so a token of one audience can never be found by the other. Only token HASHES are stored.
 * @param {{ db: any, kind: "tenant" | "platform" }} options
 */
export function createSessionStore({ db, kind }) {
  const { delegate, subject } = TABLES[kind];
  const table = () => db[delegate];
  return Object.freeze({
    /** @param {{ subjectId: string, tokenHash: string, userAgent?: string, authMethod: string, expiresAt: Date, mfaVerifiedAt?: Date | null, activeTenantId?: string | null }} input */
    create: ({
      subjectId,
      tokenHash,
      userAgent,
      authMethod,
      expiresAt,
      mfaVerifiedAt = null,
      activeTenantId = null,
    }) =>
      table().create({
        data: {
          [subject]: subjectId,
          tokenHash,
          userAgent,
          authMethod,
          expiresAt,
          mfaVerifiedAt,
          ...(kind === "tenant" ? { activeTenantId } : {}),
        },
      }),
    /** @param {string} tokenHash */
    findByTokenHash: (tokenHash) => table().findUnique({ where: { tokenHash } }),
    /** @param {string} id @param {Date} at */
    touch: (id, at) => table().update({ where: { id }, data: { lastSeenAt: at } }),
    /** @param {string} id @param {Date} at */
    revoke: (id, at) =>
      table().updateMany({ where: { id, revokedAt: null }, data: { revokedAt: at } }),
    /** Revoke every live session of a subject (deactivation, security events). @param {string} subjectId @param {Date} at */
    revokeAllForSubject: (subjectId, at) =>
      table().updateMany({
        where: { [subject]: subjectId, revokedAt: null },
        data: { revokedAt: at },
      }),
    /** Tenant sessions only. @param {string} id @param {string | null} tenantId */
    setActiveTenant: (id, tenantId) =>
      table().update({ where: { id }, data: { activeTenantId: tenantId } }),
  });
}
