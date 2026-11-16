/**
 * The execution state machine (docs/modules/executions/SPEC.md §6.1, EXEC-001). One pure table used by the API, the workers
 * and the UI; the database enforces the SAME table in the trigger `executions_guard` through the SQL function
 * `execution_transition_allowed` (the security suite compares both for every pair of statuses, EXECDB-012).
 */

/** Every value of the `execution_status` enum, in database order. `cancelling` is legacy: it is never written (CF-1). */
export const EXECUTION_STATUS_VALUES = Object.freeze([
  "queued",
  "blocked",
  "skipped",
  "cancelled",
  "preparing",
  "running",
  "cancelling",
  "succeeded",
  "failed",
  "timed_out",
  "partial",
]);

/** Statuses a worker is working on (the execution holds a lease). */
export const EXECUTION_ACTIVE_STATUSES = Object.freeze(["preparing", "running"]);

/** Terminal after having run or been requested: a finish time exists. */
export const EXECUTION_OUTCOME_STATUSES = Object.freeze([
  "succeeded",
  "failed",
  "partial",
  "cancelled",
  "timed_out",
]);

/** Terminal statuses: no column ever changes again. `blocked` and `skipped` are terminal at creation (pipelines module). */
export const EXECUTION_TERMINAL_STATUSES = Object.freeze([
  ...EXECUTION_OUTCOME_STATUSES,
  "blocked",
  "skipped",
]);

/** The only allowed status changes: `from` -> allowed `to` values. Anything else is rejected, also by the database. */
export const EXECUTION_TRANSITIONS = Object.freeze({
  queued: Object.freeze(["preparing", "cancelled"]),
  preparing: Object.freeze(["running", "failed", "cancelled", "timed_out"]),
  running: Object.freeze(["succeeded", "partial", "failed", "cancelled", "timed_out"]),
});

/**
 * Whether an execution may move from `from` to `to`.
 * @param {string} from
 * @param {string} to
 * @returns {boolean}
 */
export function canTransitionExecution(from, to) {
  return Object.hasOwn(EXECUTION_TRANSITIONS, from) && EXECUTION_TRANSITIONS[from].includes(to);
}

/** @param {string} status @returns {boolean} */
export const isTerminalExecutionStatus = (status) => EXECUTION_TERMINAL_STATUSES.includes(status);

/** @param {string} status @returns {boolean} */
export const isActiveExecutionStatus = (status) => EXECUTION_ACTIVE_STATUSES.includes(status);

/**
 * Transitions in which the quota unit may be given back, in the statement that makes the execution terminal (SPEC §5.9):
 * the execution ended before any scan task started. `running -> *` and `preparing -> timed_out` never refund.
 */
export const EXECUTION_QUOTA_RELEASE_TRANSITIONS = Object.freeze([
  Object.freeze(["queued", "cancelled"]),
  Object.freeze(["preparing", "cancelled"]),
  Object.freeze(["preparing", "failed"]),
]);

/** @param {string} from @param {string} to @returns {boolean} */
export const canReleaseQuotaOnTransition = (from, to) =>
  EXECUTION_QUOTA_RELEASE_TRANSITIONS.some(([f, t]) => f === from && t === to);

/** Scan task statuses (SPEC §6.1, last paragraph). */
export const SCAN_TASK_STATUS_VALUES = Object.freeze([
  "pending",
  "queued",
  "running",
  "succeeded",
  "failed",
  "timed_out",
  "cancelled",
  "skipped",
  "unsupported",
]);

/**
 * Allowed scan task status changes; `running -> queued` is a retry attempt only (the attempt grows by one). `unsupported`
 * (SPEC §17.ab: the scan type is enabled but no engine is registered; reason `engine_not_registered`) is reachable only from
 * `pending` and `queued`, never from `running`.
 */
export const SCAN_TASK_TRANSITIONS = Object.freeze({
  pending: Object.freeze(["queued", "cancelled", "skipped", "unsupported"]),
  queued: Object.freeze(["running", "cancelled", "skipped", "unsupported"]),
  running: Object.freeze(["queued", "succeeded", "failed", "timed_out", "cancelled"]),
});

/** @param {string} from @param {string} to @returns {boolean} */
export function canTransitionScanTask(from, to) {
  return Object.hasOwn(SCAN_TASK_TRANSITIONS, from) && SCAN_TASK_TRANSITIONS[from].includes(to);
}

/** Terminal scan task statuses: the task row is immutable. */
export const SCAN_TASK_TERMINAL_STATUSES = Object.freeze([
  "succeeded",
  "failed",
  "timed_out",
  "cancelled",
  "skipped",
  "unsupported",
]);

/** The one reason a task is `unsupported` (SPEC §17.ab). */
export const SCAN_TASK_UNSUPPORTED_REASON = "engine_not_registered";

/** Types of `execution_events` rows. */
export const EXECUTION_EVENT_TYPES = Object.freeze([
  "transition",
  "recovered",
  "cancel_requested",
  "limit_deferred",
  "retry_requested",
  "task_unsupported",
]);
