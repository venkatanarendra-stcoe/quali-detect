import { api } from "@/lib/api/index.js";

export const auditService = {
  /** @returns {Promise<{ items: any[], pagination: object | null }>} the tenant's audit entries (the tenant is the session's) */
  list: (params, { signal } = {}) => api.getPage("/audit-logs", { query: params, signal }),
};
