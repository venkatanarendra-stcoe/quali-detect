import { api } from "@/lib/api/index.js";

/**
 * Tenant AI settings (`GET/PUT /settings/ai`). The tenant is the session's: no tenant id is ever sent. The body is exactly
 * `{ externalConsent }`.
 */
export const aiSettingsService = {
  get: ({ signal } = {}) => api.get("/settings/ai", { signal }),
  update: (externalConsent) => api.put("/settings/ai", { externalConsent }),
};
