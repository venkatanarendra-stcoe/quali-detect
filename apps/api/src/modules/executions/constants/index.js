export const MODULE_NAME = "executions";

/** Reason codes of `409 CONFLICT` (`details.reason`, SPEC executions §8.1) and of the retry denial audit entry. */
export const REASONS = Object.freeze({
  ALREADY_FINISHED: "already_finished",
  NOT_CANCELLABLE: "not_cancellable",
  NOT_RETRYABLE_STATUS: "not_retryable_status",
  PIPELINE_DELETED: "pipeline_deleted",
  PIPELINE_DISABLED: "pipeline_disabled",
  REPOSITORY_NOT_ACTIVE: "repository_not_active",
  WORKSPACE_ARCHIVED: "workspace_archived",
  RETRY_CHAIN_LIMIT: "retry_chain_limit",
  PERMISSION_DENIED: "permission_denied",
  QUOTA_EXCEEDED: "quota_exceeded",
  ENTITLEMENT_REQUIRED: "entitlement_required",
});

/** Gate reasons of a retry that are audited as `execution.retry_denied` (the retry never bypasses a gate, ER-21). */
export const RETRY_GATE_REASONS = Object.freeze([
  REASONS.PIPELINE_DELETED,
  REASONS.PIPELINE_DISABLED,
  REASONS.REPOSITORY_NOT_ACTIVE,
  REASONS.WORKSPACE_ARCHIVED,
  REASONS.RETRY_CHAIN_LIMIT,
]);

/** Statuses that count as "in flight" for the `skip` concurrency policy. */
export const IN_FLIGHT_STATUSES = Object.freeze(["queued", "preparing", "running"]);

export const QUOTA_PERIOD = (date = new Date()) => date.toISOString().slice(0, 7);

export const API_PREFIX = "/api/v1";
export const OPENAPI_TAG = "Executions";

/** Page sizes of the execution list (SPEC §8.1: 25, 50 or 100; default 25). */
export const LIST_LIMITS = Object.freeze([25, 50, 100]);
export const DEFAULT_LIST_LIMIT = 25;
/** Maximum `limit` of the events (history) and of the log lines. */
export const MAX_EVENTS_LIMIT = 100;
export const MAX_LOG_LIMIT = 500;
export const DEFAULT_LOG_LIMIT = 200;
/** Longest `from`..`to` window of the list (SPEC §8.1). */
export const MAX_RANGE_DAYS = 400;

export const LOG_LEVELS = Object.freeze(["debug", "info", "warn", "error"]);
export const LOG_ORDERS = Object.freeze(["asc", "desc"]);
/** The only sortable field of the list (`requestedAt`, ties by `id` in the same direction). */
export const SORTABLE_FIELDS = Object.freeze(["requestedAt"]);

/** Task statuses that count as "failed" in the list row's task summary. */
export const FAILED_TASK_STATUSES = Object.freeze(["failed", "timed_out"]);

/** Cursor kinds (part of every cursor's binding hash, so a cursor of one endpoint never works on another). */
export const CURSOR_KINDS = Object.freeze({
  LIST: "executions",
  EVENTS: "execution-events",
  LOGS: "execution-logs",
});
