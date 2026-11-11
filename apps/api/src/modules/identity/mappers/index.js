/** @param {{ id: string, email: string, name: string, status: string }} user */
export const toUserDto = ({ id, email, name, status }) => ({ id, email, name, status });

/** @param {{ id: string, slug: string, name: string, status: string }} tenant */
export const toTenantDto = ({ id, slug, name, status }) => ({ id, slug, name, status });

/** @param {{ status: string, joinedAt: Date | null }} membership */
export const toMembershipDto = ({ status, joinedAt }) => ({ status, joinedAt });

/** @param {{ expiresAt: Date, authMethod: string, mfaVerifiedAt: Date | null }} session */
export const toSessionDto = ({ expiresAt, authMethod, mfaVerifiedAt }) => ({
  expiresAt,
  authMethod,
  mfaVerified: Boolean(mfaVerifiedAt),
});
