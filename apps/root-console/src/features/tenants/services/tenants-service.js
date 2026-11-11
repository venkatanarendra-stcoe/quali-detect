import { api } from "@/lib/api/index.js";

export const tenantsService = {
  /** @returns {Promise<{ items: any[], pagination: object | null }>} */
  list: (params, { signal } = {}) => api.getPage("/platform/tenants", { query: params, signal }),
  get: (tenantId, { signal } = {}) => api.get(`/platform/tenants/${tenantId}`, { signal }),
  provision: (body) => api.post("/platform/tenants", body),
  /** @param {"suspend" | "reactivate" | "deactivate"} action */
  changeLifecycle: (tenantId, action, body) =>
    api.post(`/platform/tenants/${tenantId}/${action}`, body),
  plans: ({ signal } = {}) => api.get("/platform/plans", { signal }),
};
