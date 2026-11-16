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
