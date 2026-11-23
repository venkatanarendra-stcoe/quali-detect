import {
  advisoryRequestBodySchema,
  approveBodySchema,
  assignBodySchema,
  bulkAssignBodySchema,
  bulkClaimBodySchema,
  claimBodySchema,
  clearAssignmentBodySchema,
  createCommentBodySchema,
  createExceptionBodySchema,
  createReviewBodySchema,
  exceptionApproveBodySchema,
  exceptionRejectBodySchema,
  putSlaBodySchema,
  reopenReviewBodySchema,
  rejectBodySchema,
  remediationStartBodySchema,
  remediationSubmitBodySchema,
  revokeExceptionBodySchema,
  withdrawExceptionBodySchema,
  withdrawReviewBodySchema,
} from "@qmentisai/shared";
import { api } from "@/lib/api/index.js";
import { parseOrApiError } from "../schemas/validate.js";
import { pipelinesService } from "@/features/pipelines/services/pipelines-service.js";
import { workspacesService } from "@/features/workspaces/services/workspaces-service.js";
import { createMockFindingsService } from "./findings-api.mock.js";

/** A fresh key per user action; a retry of the SAME action reuses it (SPEC 8, Idempotency). */
export const newIdempotencyKey = () => crypto.randomUUID();
const idem = (key) => ({ headers: { "Idempotency-Key": key ?? newIdempotencyKey() } });

/**
 * Parses a request body with the FROZEN shared schema before it is sent, so the UI cannot send a shape the API refuses (the
 * same schema runs again on the server). A ZodError carries `issues[].params.reason` (`credential_shape`, ...); callers map it.
 * @template T
 * @param {{ parse: (value: unknown) => T }} schema
 * @param {unknown} body
 * @returns {T}
 */
const checked = (schema, body) => parseOrApiError(schema, body);

const rev = (id) => `/findings/${id}`;

/**
 * Findings API (SPEC section 8; `docs/modules/findings/SPEC.md`). The tenant is the session's: no tenant id is ever sent.
 * Every write takes `expectedRev` (from the last read) and an Idempotency-Key. Collection reads give `{ items, pagination }`.
 * `findingsApi` is this real implementation; `findingsService` (below) is the mock instead when `VITE_FINDINGS_MOCK=true`.
 */
export const findingsApi = {
  list: (params, { signal } = {}) => api.getPage("/findings", { query: params, signal }),
  summary: (workspaceId, { signal } = {}) =>
    api.get("/findings/summary", { query: { workspaceId }, signal }),
  /**
   * `Cache-Control: no-cache` is a workaround for server defect S-1 (AS_BUILT_E2): the detail ETag covers `rev` only, while the DTO
   * also holds the advisory, its pending and stale state, the per-caller actions and the SLA state, which change without a rev
   * change. Without the header the browser revalidates and Express answers 304, so the screen keeps a stale body.
   */
  get: (id, { signal } = {}) =>
    api.get(rev(id), { signal, headers: { "Cache-Control": "no-cache" } }),
  history: (id, params, { signal } = {}) =>
    api.getPage(`${rev(id)}/history`, { query: params, signal }),
  comments: (id, params, { signal } = {}) =>
    api.getPage(`${rev(id)}/comments`, { query: params, signal }),
  similar: (id, { signal } = {}) => api.get(`${rev(id)}/similar`, { signal }),
  reviewQueue: (params, { signal } = {}) => api.getPage("/review-queue", { query: params, signal }),
  approvals: (params, { signal } = {}) => api.getPage("/approvals", { query: params, signal }),
  board: (params, { signal } = {}) => api.get("/remediation/board", { query: params, signal }),
  boardColumn: (column, params, { signal } = {}) =>
    api.getPage(`/remediation/board/${column}`, { query: params, signal }),
  slaSettings: ({ signal } = {}) => api.get("/settings/findings-sla", { signal }),
  putSlaSettings: (body) => api.put("/settings/findings-sla", checked(putSlaBodySchema, body)),

  claim: (id, body, key) => api.post(`${rev(id)}/claim`, checked(claimBodySchema, body), idem(key)),
  createReview: (id, body, key) =>
    api.post(`${rev(id)}/reviews`, checked(createReviewBodySchema, body), idem(key)),
  withdrawReview: (id, reviewId, body, key) =>
    api.post(
      `${rev(id)}/reviews/${reviewId}/withdraw`,
      checked(withdrawReviewBodySchema, body),
      idem(key),
    ),
  approveReview: (id, reviewId, body, key) =>
    api.post(`${rev(id)}/reviews/${reviewId}/approve`, checked(approveBodySchema, body), idem(key)),
  rejectReview: (id, reviewId, body, key) =>
    api.post(`${rev(id)}/reviews/${reviewId}/reject`, checked(rejectBodySchema, body), idem(key)),
  reopenReview: (id, body, key) =>
    api.post(`${rev(id)}/reopen-review`, checked(reopenReviewBodySchema, body), idem(key)),
  assign: (id, body, key) =>
    api.post(`${rev(id)}/assignments`, checked(assignBodySchema, body), idem(key)),
  clearAssignment: (id, body, key) =>
    api.post(`${rev(id)}/assignments/clear`, checked(clearAssignmentBodySchema, body), idem(key)),
  startRemediation: (id, body, key) =>
    api.post(`${rev(id)}/remediation/start`, checked(remediationStartBodySchema, body), idem(key)),
  submitRemediation: (id, body, key) =>
    api.post(
      `${rev(id)}/remediation/submit`,
      checked(remediationSubmitBodySchema, body),
      idem(key),
    ),
  createException: (id, body, key) =>
    api.post(`${rev(id)}/exceptions`, checked(createExceptionBodySchema, body), idem(key)),
  withdrawException: (id, exceptionId, key) =>
    api.post(
      `${rev(id)}/exceptions/${exceptionId}/withdraw`,
      checked(withdrawExceptionBodySchema, {}),
      idem(key),
    ),
  approveException: (id, exceptionId, body, key) =>
    api.post(
      `${rev(id)}/exceptions/${exceptionId}/approve`,
      checked(exceptionApproveBodySchema, body),
      idem(key),
    ),
  rejectException: (id, exceptionId, body, key) =>
    api.post(
      `${rev(id)}/exceptions/${exceptionId}/reject`,
      checked(exceptionRejectBodySchema, body),
      idem(key),
    ),
  revokeException: (id, exceptionId, body, key) =>
    api.post(
      `${rev(id)}/exceptions/${exceptionId}/revoke`,
      checked(revokeExceptionBodySchema, body),
      idem(key),
    ),
  addComment: (id, body, key) =>
    api.post(`${rev(id)}/comments`, checked(createCommentBodySchema, body), idem(key)),
  requestAdvisory: (id, key) =>
    api.post(`${rev(id)}/advisory/request`, checked(advisoryRequestBodySchema, {}), idem(key)),
  bulkClaim: (body, key) =>
    api.post("/findings/bulk/claim", checked(bulkClaimBodySchema, body), idem(key)),
  bulkAssign: (body, key) =>
    api.post("/findings/bulk/assign", checked(bulkAssignBodySchema, body), idem(key)),

  /** Filter options and the assignee picker reuse the existing workspace endpoints (no findings route exists for them). */
  pipelines: async (workspaceId, { signal } = {}) => {
    const page = await pipelinesService.list({ workspaceId, limit: 100 }, { signal });
    return page.items.map((p) => ({
      id: p.id,
      name: p.name,
      repository: p.repository ? { id: p.repository.id, name: p.repository.name } : null,
    }));
  },
  assignees: async (workspaceId, q, { signal } = {}) => {
    const page = await workspacesService.listMembers(
      workspaceId,
      { pageSize: 20, sort: "name:asc", q: q || undefined },
      { signal },
    );
    return page.items.map((m) => ({ id: m.userId, displayName: m.name }));
  },
};

/** True when the screens run on the in-repo mock instead of the API (`VITE_FINDINGS_MOCK=true`; development only). */
export const FINDINGS_MOCK_ENABLED =
  import.meta.env.VITE_FINDINGS_MOCK === "true" && !import.meta.env.PROD;

/**
 * The service the hooks use. Same function names and shapes on both sides; Wave 3 integration is turning the flag off.
 * The mock is imported statically (small) but is only instantiated when the flag is on.
 */
export const findingsService = FINDINGS_MOCK_ENABLED ? createMockFindingsService() : findingsApi;
