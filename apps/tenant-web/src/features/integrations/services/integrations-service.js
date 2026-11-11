import { api } from "@/lib/api/index.js";

export const integrationsService = {
  catalog: ({ signal } = {}) => api.get("/integrations", { signal }),
  github: ({ signal } = {}) => api.get("/integrations/github", { signal }),
  installations: ({ signal } = {}) => api.get("/integrations/github/installations", { signal }),
  start: () => api.post("/integrations/github/installations/start"),
  authorize: (installationId) =>
    api.post("/integrations/github/installations/authorize", { installationId }),
  link: (body) => api.post("/integrations/github/installations", body),
  refresh: (linkId) => api.post(`/integrations/github/installations/${linkId}/refresh`),
  setScope: (linkId, workspaceIds) =>
    api.put(`/integrations/github/installations/${linkId}/workspaces`, { workspaceIds }),
  deliveries: (linkId, params, { signal } = {}) =>
    api.getPage(`/integrations/github/installations/${linkId}/deliveries`, {
      query: params,
      signal,
    }),
  workspaceLinks: (workspaceId, { signal } = {}) =>
    api.get(`/workspaces/${workspaceId}/integrations`, { signal }),
  setRouting: (workspaceId, linkId, enabled) =>
    api.put(`/workspaces/${workspaceId}/integrations/${linkId}`, { enabled }),
  unlink: (linkId, confirm) =>
    api.delete(`/integrations/github/installations/${linkId}`, { body: { confirm } }),
};
