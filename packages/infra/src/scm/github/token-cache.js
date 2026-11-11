/**
 * In-process cache of GitHub installation access tokens. Tokens live ONLY in this Map: never persisted, never logged,
 * never returned by an API, never placed in a message. Concurrent requests for the same installation share one mint call
 * (single flight). A token is reused until `refreshMarginMs` before its expiry. No assumption is made about the token's
 * length or format (GitHub is changing it, see the spike D9).
 * @param {{ mint: (installationId: string) => Promise<{ token: string, expiresAt: Date }>, now?: () => number, refreshMarginMs?: number }} options
 */
export function createInstallationTokenCache({
  mint,
  now = Date.now,
  refreshMarginMs = 5 * 60 * 1000,
}) {
  /** @type {Map<string, { token: string, expiresAt: number }>} */
  const cache = new Map();
  /** @type {Map<string, Promise<string>>} */
  const inFlight = new Map();
  return Object.freeze({
    /** @param {string} installationId @returns {Promise<string>} */
    async get(installationId) {
      const hit = cache.get(installationId);
      if (hit && hit.expiresAt - refreshMarginMs > now()) return hit.token;
      let pending = inFlight.get(installationId);
      if (!pending) {
        pending = mint(installationId)
          .then(({ token, expiresAt }) => {
            cache.set(installationId, { token, expiresAt: expiresAt.getTime() });
            return token;
          })
          .finally(() => inFlight.delete(installationId));
        inFlight.set(installationId, pending);
      }
      return pending;
    },
    /** Forget the token (after a 401: it was revoked or expired early). */
    invalidate(installationId) {
      cache.delete(installationId);
    },
    clear() {
      cache.clear();
    },
    get size() {
      return cache.size;
    },
  });
}
