import { api } from "@/lib/api/index.js";

export const auditService = {
  /** @returns {Promise<{ items: any[], pagination: object | null }>} platform audit entries */
  list: (params, { signal } = {}) => api.getPage("/platform/audit-logs", { query: params, signal }),
};
