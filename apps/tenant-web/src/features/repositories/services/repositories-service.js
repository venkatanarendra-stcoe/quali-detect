import { api } from "@/lib/api/index.js";

/** A fresh key per user action; retries of the SAME action reuse it (the wizard keeps one per repository). */
export const newIdempotencyKey = () => crypto.randomUUID();

export const repositoriesService = {
  list: (params, { signal } = {}) => api.getPage("/repositories", { query: params, signal }),
  get: (repositoryId, { signal } = {}) => api.get(`/repositories/${repositoryId}`, { signal }),
  available: (workspaceId, params, { signal } = {}) =>
    api.getPage(`/workspaces/${workspaceId}/repositories/available`, { query: params, signal }),
  connect: (workspaceId, body, idempotencyKey) =>
    api.post(`/workspaces/${workspaceId}/repositories`, body, {
      headers: { "Idempotency-Key": idempotencyKey },
    }),
  update: (repositoryId, body) => api.patch(`/repositories/${repositoryId}`, body),
  sync: (repositoryId) => api.post(`/repositories/${repositoryId}/sync`),
  enable: (repositoryId) => api.post(`/repositories/${repositoryId}/enable`),
  disable: (repositoryId) => api.post(`/repositories/${repositoryId}/disable`),
  disconnect: (repositoryId, confirm) =>
    api.delete(`/repositories/${repositoryId}`, { body: { confirm } }),
  branches: (repositoryId, { signal } = {}) =>
    api.get(`/repositories/${repositoryId}/branches`, { signal }),
  /** The latest stored SBOM (CycloneDX JSON) of the repository: `{ blob, fileName }`. */
  downloadSbom: (repositoryId, { signal } = {}) =>
    api.download(`/repositories/${repositoryId}/sbom`, { signal }),
  pullRequests: (repositoryId, { signal } = {}) =>
    api.get(`/repositories/${repositoryId}/pull-requests`, { signal }),
};
