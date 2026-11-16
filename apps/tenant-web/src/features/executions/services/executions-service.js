import { api } from "@/lib/api/index.js";

/** A fresh key per user action; a retry of the SAME action reuses it (the retry endpoint REQUIRES one). */
export const newIdempotencyKey = () => crypto.randomUUID();

const idem = (key) => (key ? { headers: { "Idempotency-Key": key } } : {});

/** Executions API (SPEC §8.1). The tenant is the session's; no tenant id is ever sent. */
export const executionsService = {
  /** @returns {Promise<{ items: any[], pagination: object | null }>} no totals: cursor only */
  list: (params, { signal } = {}) => api.getPage("/executions", { query: params, signal }),
  get: (executionId, { signal } = {}) => api.get(`/executions/${executionId}`, { signal }),
  events: (executionId, params, { signal } = {}) =>
    api.getPage(`/executions/${executionId}/events`, { query: params, signal }),
  /** @returns {Promise<{ lines: any[], nextCursor: string | null, hasMore: boolean, truncated: boolean }>} */
  logs: (executionId, params, { signal } = {}) =>
    api.get(`/executions/${executionId}/logs`, { query: params, signal }),
  /** `{ execution }` (cancelled now, 200) or `{ execution, cancelRequested: true }` (request recorded, 202). */
  cancel: (executionId, key) => api.post(`/executions/${executionId}/cancel`, undefined, idem(key)),
  /** `{ execution }`: the NEW execution (202). The key is required by the API. */
  retry: (executionId, key) => api.post(`/executions/${executionId}/retry`, undefined, idem(key)),
};
