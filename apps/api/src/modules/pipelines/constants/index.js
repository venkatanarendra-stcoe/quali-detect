export const MODULE_NAME = "pipelines";
export const API_PREFIX = "/api/v1";
export const OPENAPI_TAG = "Pipelines";

export const SORTABLE_FIELDS = Object.freeze(["name", "createdAt", "lastRequestedAt"]);

/** Keyset terms of the list sort fields stored on the row (`lastRequestedAt` is an aggregate: see `pipelineKeyTerms`). */
export const PIPELINE_KEY_SPECS = Object.freeze({
  name: { type: "string" },
  createdAt: { type: "date", column: "created_at" },
});
export const PIPELINE_TIE = "asc";

/**
 * Keyset terms of a pipeline list sort. Sorting by `lastRequestedAt` (an aggregate over executions, ordered in memory) uses
 * the fixed order latest request (never requested = -1), then name, then id, in the requested direction of the first.
 * @param {Array<{ field: string, direction: "asc" | "desc" }>} sort
 */
export function pipelineKeyTerms(sort) {
  const byRequest = sort.find((s) => s.field === "lastRequestedAt");
  if (!byRequest) return null;
  return [
    { field: "latest", direction: byRequest.direction, type: "number", nullable: false },
    { field: "name", direction: "asc", type: "string", nullable: false },
    { field: "id", direction: "asc", type: "uuid", nullable: false },
  ];
}

/** Statuses of an execution that are neither queued nor terminal: they block a soft delete (R-5). */
export const ACTIVE_EXECUTION_STATUSES = Object.freeze(["preparing", "running", "cancelling"]);

/** Statuses that count as "in flight" for the `skip` concurrency policy. */
export const IN_FLIGHT_EXECUTION_STATUSES = Object.freeze(["queued", ...ACTIVE_EXECUTION_STATUSES]);

/** Reason codes of `409 CONFLICT` (`details.reason`) and of the manual-run denial audit entry. */
export const REASONS = Object.freeze({
  NAME_TAKEN: "name_taken",
  REPOSITORY_NOT_ACTIVE: "repository_not_active",
  WORKSPACE_ARCHIVED: "workspace_archived",
  VERSION_CONFLICT: "version_conflict",
  PIPELINE_INCOMPLETE: "pipeline_incomplete",
  HAS_ACTIVE_EXECUTIONS: "has_active_executions",
  PIPELINE_DISABLED: "pipeline_disabled",
  MANUAL_DISABLED: "manual_disabled",
  FORK_POLICY: "fork_policy_requires_permission",
  REPOSITORY_PIPELINE_LIMIT: "repository_pipeline_limit",
  PERMISSION_DENIED: "permission_denied",
  QUOTA_EXCEEDED: "quota_exceeded",
  ENTITLEMENT_REQUIRED: "entitlement_required",
});

/** Gate reasons of a manual run that are audited as `execution.manual_denied`. */
export const MANUAL_GATE_REASONS = Object.freeze([
  REASONS.PIPELINE_DISABLED,
  REASONS.REPOSITORY_NOT_ACTIVE,
  REASONS.WORKSPACE_ARCHIVED,
  REASONS.MANUAL_DISABLED,
]);

export const QUOTA_PERIOD = (date = new Date()) => date.toISOString().slice(0, 7);
