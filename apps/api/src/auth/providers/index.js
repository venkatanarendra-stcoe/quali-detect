import { createMockProvider } from "./mock.js";

/**
 * @typedef {object} AuthResult
 * @property {string} subjectId User id (tenant audience) or platform user id (platform audience).
 * @property {string} authMethod Recorded on the session: "mock" now; "oidc", "saml", "password+totp"... later.
 * @property {Date | null} [mfaVerifiedAt] Set when the provider already completed a second factor.
 *
 * @typedef {object} AuthProvider
 * @property {string} id
 * @property {(input: { audience: "tenant" | "platform", identifier: string, secret: string }) => Promise<AuthResult | null>} authenticate
 *   Verifies credentials; returns null for ANY failure (unknown user, wrong secret, inactive account) so callers cannot tell why.
 * @property {(input: { audience: "tenant" | "platform", subjectId: string, code: string }) => Promise<boolean>} [verifyMfa]
 *   Completes the second factor (optional; providers whose IdP already asserts MFA return `mfaVerifiedAt` from `authenticate`).
 *
 * Adding SSO later: implement a provider for the redirect/callback flow (OIDC or SAML), register it here, and let its callback
 * route call the same session service with `authMethod: "oidc"`. Adding MFA: set `mfaVerifiedAt` after a challenge and turn on
 * `requiresMfa` (mfa-policy.js). Nothing else (cookies, sessions, tenant context, guards) changes.
 */

/**
 * Registered providers by id. The mock provider exists only while MOCK_AUTH_ENABLED.
 * @param {{ db: any, config: any }} deps
 * @returns {ReadonlyMap<string, AuthProvider>}
 */
export function createAuthProviders({ db, config }) {
  const providers = new Map();
  if (config.auth.mock.enabled) providers.set("mock", createMockProvider({ db, config }));
  return providers;
}
