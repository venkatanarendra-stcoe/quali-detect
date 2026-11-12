import { api } from "@/lib/api/index.js";

const ws = (workspaceId) => `/workspaces/${workspaceId}/integrations/github`;

/** Integration API calls. Tenant level is read-only for GitHub; linking and the allow-list are workspace scoped. */
export const integrationsService = {
  catalog: ({ signal } = {}) => api.get("/integrations", { signal }),
  settings: ({ signal } = {}) => api.get("/integrations/settings", { signal }),
  updateSettings: (allowWorkspaceLinking) =>
    api.put("/integrations/settings", { allowWorkspaceLinking }),
  installations: ({ signal } = {}) => api.get("/integrations/github/installations", { signal }),
  deliveries: (installationId, params, { signal } = {}) =>
    api.getPage(`/integrations/github/installations/${installationId}/deliveries`, {
      query: params,
      signal,
    }),
  workspaceOverview: (workspaceId, { signal } = {}) => api.get(ws(workspaceId), { signal }),
  start: (workspaceId) => api.post(`${ws(workspaceId)}/start`),
  authorize: (workspaceId, installationId) =>
    api.post(`${ws(workspaceId)}/authorize`, { installationId }),
  link: (body) => api.post("/integrations/github/links", body),
  refresh: (workspaceId, linkId) => api.post(`${ws(workspaceId)}/links/${linkId}/refresh`),
  unlink: (workspaceId, linkId, confirm) =>
    api.delete(`${ws(workspaceId)}/links/${linkId}`, { body: { confirm } }),
  allowList: (workspaceId, linkId, params, { signal } = {}) =>
    api.getPage(`${ws(workspaceId)}/links/${linkId}/repositories`, { query: params, signal }),
  saveAllowList: (workspaceId, linkId, body) =>
    api.put(`${ws(workspaceId)}/links/${linkId}/repositories`, body),
};
