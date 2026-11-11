/** @param {{ id: string, email: string, name: string, status: string }} user */
export const toPlatformUserDto = ({ id, email, name, status }) => ({ id, email, name, status });

/** @param {{ expiresAt: Date, authMethod: string, mfaVerifiedAt: Date | null }} session */
export const toPlatformSessionDto = ({ expiresAt, authMethod, mfaVerifiedAt }) => ({
  expiresAt,
  authMethod,
  mfaVerified: Boolean(mfaVerifiedAt),
});
