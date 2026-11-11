/**
 * Multi-factor policy. A session records `authMethod` and `mfaVerifiedAt`; when this returns true for a subject, requests
 * whose session has no `mfaVerifiedAt` are refused with 401 (`details.reason: "mfa_required"`) until a challenge completes.
 *
 * - platform (Root Console): MFA is MANDATORY for every session, always. The mock provider completes it with a shared
 *   6-digit code (MOCK_PLATFORM_MFA_CODE); a real provider (TOTP, WebAuthn, or an IdP that asserts MFA) sets `mfaVerifiedAt`.
 * - tenant: not required yet (Open decision: per-tenant MFA policy).
 * @param {{ audience: "tenant" | "platform", subjectId: string }} subject
 * @returns {boolean}
 */
export function requiresMfa({ audience }) {
  return audience === "platform";
}
