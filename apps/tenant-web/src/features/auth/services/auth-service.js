import { api, isApiError } from "@/lib/api/index.js";

/** Query key of the signed-in user (`GET /me`). `null` data means "not signed in". */
export const ME_KEY = Object.freeze(["me"]);

export const authService = {
  /** @returns {Promise<object | null>} the /me payload, or null when there is no valid session */
  async me({ signal } = {}) {
    try {
      return await api.get("/me", { signal, skipUnauthenticatedHandler: true });
    } catch (error) {
      if (isApiError(error) && error.status === 401) return null;
      throw error;
    }
  },
  login: (credentials) =>
    api.post("/auth/login", credentials, { skipUnauthenticatedHandler: true }),
  logout: () => api.post("/auth/logout", undefined, { skipUnauthenticatedHandler: true }),
  listTenants: ({ signal } = {}) => api.get("/me/tenants", { signal }),
  listInvitations: ({ signal } = {}) => api.get("/me/invitations", { signal }),
  acceptInvitation: (tenantId) => api.post(`/me/invitations/${tenantId}/accept`),
  switchTenant: (tenantId) => api.put("/me/active-tenant", { tenantId }),
};
