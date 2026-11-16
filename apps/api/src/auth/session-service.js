import { generateSessionToken, hashSessionToken, isWellFormedToken } from "./tokens.js";

const TOUCH_INTERVAL_MS = 60_000;

/**
 * Issues, resolves and revokes sessions for one audience. Sessions expire absolutely (`expiresAt`) and when idle
 * (`lastSeenAt`); `lastSeenAt` is refreshed at most once a minute to avoid a write per request.
 * `onRevoked` is told about every revocation made through this service (`{ sessionId }` or `{ subjectId }`), AFTER it is stored, so
 * the realtime layer can disconnect the sockets of that session at once. It must not throw (a failure is swallowed).
 * @param {{ store: ReturnType<typeof import("./session-store.js").createSessionStore>, config: { auth: { sessionTtlSeconds: number, idleTimeoutSeconds: number } }, clock?: () => Date, onRevoked?: (event: { sessionId?: string, subjectId?: string }) => void }} options
 */
export function createSessionService({ store, config, clock = () => new Date(), onRevoked }) {
  const notify = (event) => {
    try {
      onRevoked?.(event);
    } catch {
      /* the periodic re-validation of the realtime layer is the guarantee */
    }
  };
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
    revoke: async (sessionId) => {
      const result = await store.revoke(sessionId, clock());
      notify({ sessionId });
      return result;
    },
    /** @param {string} subjectId */
    revokeAll: async (subjectId) => {
      const result = await store.revokeAllForSubject(subjectId, clock());
      notify({ subjectId });
      return result;
    },
    /** @param {string} sessionId @param {string | null} tenantId */
    setActiveTenant: (sessionId, tenantId) => store.setActiveTenant(sessionId, tenantId),
  });
}
