import { api, isApiError } from "@/lib/api/index.js";

/** Query key of the signed-in platform user (`GET /platform/me`). */
export const PLATFORM_ME_KEY = Object.freeze(["platform", "me"]);

/** Marker returned by `me` when the password step is done but the mandatory second factor is pending. */
export const MFA_PENDING = Object.freeze({ mfaPending: true });

export const platformAuthService = {
  /**
   * @returns {Promise<object | typeof MFA_PENDING | null>} the /platform/me payload, `MFA_PENDING`, or null (signed out).
   * 404 is also "signed out": a TENANT session cookie from the Tenant Application (same host, other port) reaches platform
   * routes and is answered with 404, which must not be mistaken for a platform session.
   */
  async me({ signal } = {}) {
    try {
      return await api.get("/platform/me", { signal, skipUnauthenticatedHandler: true });
    } catch (error) {
      if (isApiError(error) && error.status === 401) {
        return error.details?.reason === "mfa_required" ? MFA_PENDING : null;
      }
      if (isApiError(error) && error.status === 404) return null;
      throw error;
    }
  },
  login: (credentials) =>
    api.post("/platform/auth/login", credentials, { skipUnauthenticatedHandler: true }),
  verifyMfa: (code) =>
    api.post("/platform/auth/mfa/verify", { code }, { skipUnauthenticatedHandler: true }),
  logout: () => api.post("/platform/auth/logout", undefined, { skipUnauthenticatedHandler: true }),
};
