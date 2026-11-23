import { api } from "@/lib/api/index.js";

/**
 * Tenant AI settings (`GET/PUT /settings/ai`). The tenant is the session's: no tenant id is ever sent. The body is strict:
 * `{ externalConsent?, codeSnippetConsent? }` with at least one key (ADR-013 addendum; code excerpts need the first consent on,
 * and withdrawing the first clears the second on the server).
 */
export const aiSettingsService = {
  get: ({ signal } = {}) => api.get("/settings/ai", { signal }),
  /** @param {{ externalConsent?: boolean, codeSnippetConsent?: boolean }} body */
  update: (body) => api.put("/settings/ai", body),
};
