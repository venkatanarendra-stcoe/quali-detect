import { api } from "@/lib/api/index.js";

/** A fresh key per user action; retries of the SAME action reuse it. */
export const newIdempotencyKey = () => crypto.randomUUID();

const idem = (key) => (key ? { headers: { "Idempotency-Key": key } } : {});

/** Pipelines API (SPEC §8). The tenant is the session's; no tenant id is ever sent. */
export const pipelinesService = {
  list: (params, { signal } = {}) => api.getPage("/pipelines", { query: params, signal }),
  listForRepository: (repositoryId, params, { signal } = {}) =>
    api.getPage(`/repositories/${repositoryId}/pipelines`, { query: params, signal }),
  options: (workspaceId, { signal } = {}) =>
    api.get(`/workspaces/${workspaceId}/pipelines/options`, { signal }),
  get: (pipelineId, { signal } = {}) => api.get(`/pipelines/${pipelineId}`, { signal }),
  create: (repositoryId, body, key) =>
    api.post(`/repositories/${repositoryId}/pipelines`, body, idem(key)),
  update: (pipelineId, body) => api.patch(`/pipelines/${pipelineId}`, body),
  publishConfig: (pipelineId, body, key) =>
    api.put(`/pipelines/${pipelineId}/config`, body, idem(key)),
  enable: (pipelineId, key) => api.post(`/pipelines/${pipelineId}/enable`, undefined, idem(key)),
  disable: (pipelineId, key) => api.post(`/pipelines/${pipelineId}/disable`, undefined, idem(key)),
  remove: (pipelineId, confirm) => api.delete(`/pipelines/${pipelineId}`, { body: { confirm } }),
  versions: (pipelineId, params, { signal } = {}) =>
    api.getPage(`/pipelines/${pipelineId}/versions`, { query: params, signal }),
  version: (pipelineId, version, { signal } = {}) =>
    api.get(`/pipelines/${pipelineId}/versions/${version}`, { signal }),
  run: (pipelineId, body, key) => api.post(`/pipelines/${pipelineId}/runs`, body, idem(key)),
  executions: (pipelineId, params, { signal } = {}) =>
    api.getPage(`/pipelines/${pipelineId}/executions`, { query: params, signal }),
  decisions: (pipelineId, params, { signal } = {}) =>
    api.getPage(`/pipelines/${pipelineId}/trigger-decisions`, { query: params, signal }),
  dryRun: (repositoryId, body) =>
    api.post(`/repositories/${repositoryId}/pipelines/test-triggers`, body),
};
