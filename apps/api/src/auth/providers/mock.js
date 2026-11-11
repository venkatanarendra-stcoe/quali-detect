import { secretsMatch } from "../tokens.js";

/**
 * MOCK authentication provider (development only; refused by configuration in production). Seeded users sign in with the
 * shared password from MOCK_AUTH_PASSWORD (platform users: MOCK_PLATFORM_AUTH_PASSWORD). No password hashes are involved.
 * The password comparison always runs, even for unknown users, and failures are indistinguishable to the caller.
 * @param {{ db: any, config: { auth: { mock: { tenantPassword?: string, platformPassword?: string, platformMfaCode?: string } } } }} deps
 * @returns {import("./index.js").AuthProvider}
 */
export function createMockProvider({ db, config }) {
  return {
    id: "mock",
    async authenticate({ audience, identifier, secret }) {
      const expected =
        audience === "platform"
          ? config.auth.mock.platformPassword
          : config.auth.mock.tenantPassword;
      const subject =
        audience === "platform"
          ? await db.platformUser.findUnique({
              where: { email: identifier },
              select: { id: true, status: true },
            })
          : await db.user.findUnique({
              where: { email: identifier },
              select: { id: true, status: true },
            });
      const passwordOk = secretsMatch(secret, expected);
      if (!subject || subject.status !== "active" || !passwordOk) return null;
      return { subjectId: subject.id, authMethod: "mock" };
    },
    /** Second factor: platform users only. Constant-time comparison with the configured code. */
    async verifyMfa({ audience, code }) {
      if (audience !== "platform") return false;
      const expected = config.auth.mock.platformMfaCode;
      return typeof expected === "string" && secretsMatch(code, expected);
    },
  };
}
