import { api } from "@/lib/api/index.js";

export const workspacesService = {
  /** @returns {Promise<{ items: any[], pagination: object | null }>} workspaces the caller can see */
  list: (params, { signal } = {}) => api.getPage("/workspaces", { query: params, signal }),
  get: (workspaceId, { signal } = {}) => api.get(`/workspaces/${workspaceId}`, { signal }),
  create: (body) => api.post("/workspaces", body),
  update: (workspaceId, body) => api.patch(`/workspaces/${workspaceId}`, body),
  archive: (workspaceId) => api.post(`/workspaces/${workspaceId}/archive`),
  restore: (workspaceId) => api.post(`/workspaces/${workspaceId}/restore`),
  listMembers: (workspaceId, params, { signal } = {}) =>
    api.getPage(`/workspaces/${workspaceId}/members`, { query: params, signal }),
  removeMember: (workspaceId, userId) => api.delete(`/workspaces/${workspaceId}/members/${userId}`),
  listAssignments: (workspaceId, params, { signal } = {}) =>
    api.getPage(`/workspaces/${workspaceId}/role-assignments`, { query: params, signal }),
  createAssignment: (workspaceId, body) =>
    api.post(`/workspaces/${workspaceId}/role-assignments`, body),
  revokeAssignment: (workspaceId, assignmentId) =>
    api.delete(`/workspaces/${workspaceId}/role-assignments/${assignmentId}`),
};
