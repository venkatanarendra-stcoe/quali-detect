import { generateSessionToken, hashSessionToken, isWellFormedToken } from "./tokens.js";

const TOUCH_INTERVAL_MS = 60_000;

/**
 * Issues, resolves and revokes sessions for one audience. Sessions expire absolutely (`expiresAt`) and when idle
 * (`lastSeenAt`); `lastSeenAt` is refreshed at most once a minute to avoid a write per request.
 * @param {{ store: ReturnType<typeof import("./session-store.js").createSessionStore>, config: { auth: { sessionTtlSeconds: number, idleTimeoutSeconds: number } }, clock?: () => Date }} options
 */
export function createSessionService({ store, config, clock = () => new Date() }) {
  return Object.freeze({
    /**
     * Creates a session with a fresh random token (never reuse a token across logins: no session fixation).
     * @param {{ subjectId: string, activeTenantId?: string | null, userAgent?: string, authMethod: string, mfaVerifiedAt?: Date | null }} input
     * @returns {Promise<{ token: string, session: any }>} the raw token is returned once, for the cookie
     */
    async issue({ subjectId, activeTenantId, userAgent, authMethod, mfaVerifiedAt }) {
      const token = generateSessionToken();
      const expiresAt = new Date(clock().getTime() + config.auth.sessionTtlSeconds * 1000);
      const session = await store.create({
        subjectId,
        activeTenantId,
        authMethod,
        mfaVerifiedAt,
        expiresAt,
        tokenHash: hashSessionToken(token),
        userAgent: userAgent?.slice(0, 255),
      });
      return { token, session };
    },
    /**
     * Looks a raw token up. Returns null for malformed, unknown, revoked, expired or idle-timed-out sessions.
     * @param {string | undefined} token
     */
    async resolve(token) {
      if (!isWellFormedToken(token)) return null;
      const session = await store.findByTokenHash(hashSessionToken(token));
      if (!session || session.revokedAt) return null;
      const now = clock();
      if (
        session.expiresAt <= now ||
        now.getTime() - session.lastSeenAt.getTime() > config.auth.idleTimeoutSeconds * 1000
      )
        return null;
      if (now.getTime() - session.lastSeenAt.getTime() > TOUCH_INTERVAL_MS) {
        await store.touch(session.id, now);
        return { ...session, lastSeenAt: now };
      }
      return session;
    },
    /** @param {string} sessionId */
    revoke: (sessionId) => store.revoke(sessionId, clock()),
    /** @param {string} subjectId */
    revokeAll: (subjectId) => store.revokeAllForSubject(subjectId, clock()),
    /** @param {string} sessionId @param {string | null} tenantId */
    setActiveTenant: (sessionId, tenantId) => store.setActiveTenant(sessionId, tenantId),
  });
}
