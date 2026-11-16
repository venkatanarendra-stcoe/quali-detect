/**
 * Cancellation and retry rules of an execution (docs/modules/executions/SPEC.md part D: ER-14, ER-18 to ER-23). Pure: used by
 * the API service, the orchestrator and the scan handler, so the three agree on the same table.
 */

/** Cancel modes of a pipeline configuration (`execution.cancellation`). */
export const EXECUTION_CANCEL_MODES = Object.freeze(["graceful", "immediate"]);
/** The mode used when a snapshot cannot be read (the pipeline default, PT §5.8). */
export const DEFAULT_CANCEL_MODE = "graceful";

/**
 * The cancel mode of a configuration snapshot. The client never chooses it (ER-19).
 * @param {{ execution?: { cancellation?: string } } | null | undefined} config
 * @returns {"graceful" | "immediate"}
 */
export const cancelModeOf = (config) =>
  EXECUTION_CANCEL_MODES.includes(config?.execution?.cancellation)
    ? config.execution.cancellation
    : DEFAULT_CANCEL_MODE;

/**
 * How a cancel request on a preparing/running execution is answered (ER-18): `queued` is cancelled directly, an active
 * execution records the request, a finished one is a conflict, `blocked`/`skipped` can never be cancelled.
 * @param {string} status
 * @returns {"cancel_now" | "record_request" | "already_finished" | "not_cancellable"}
 */
export function cancelRouteOf(status) {
  if (status === "queued") return "cancel_now";
  if (status === "preparing" || status === "running") return "record_request";
  if (status === "blocked" || status === "skipped") return "not_cancellable";
  return "already_finished";
}

/**
 * Whether the lease holder keeps waiting for running tasks of a cancelled execution (ER-14). `immediate` aborts the running
 * attempts at once (the abort grace only bounds how long the holder waits for them to wind down); `graceful` lets them
 * finish until `cancel_grace_until`. Either way no task starts after the request.
 * @param {{ mode: "graceful" | "immediate", graceSecondsLeft: number | null, running: number }} input
 * @returns {"terminalize" | "wait"}
 */
export function cancelWaitDecision({ graceSecondsLeft, running }) {
  if (running === 0) return "terminalize";
  return graceSecondsLeft !== null && graceSecondsLeft <= 0 ? "terminalize" : "wait";
}

/**
 * Whether a scan task holder aborts its attempt now (ER-14): `immediate` as soon as the request exists, `graceful` once
 * the grace period is over.
 * @param {{ mode: string | null, requested: boolean, graceSecondsLeft: number | null }} input
 * @returns {boolean}
 */
export function shouldAbortAttempt({ mode, requested, graceSecondsLeft }) {
  if (!requested) return false;
  if (mode === "immediate") return true;
  return graceSecondsLeft !== null && graceSecondsLeft <= 0;
}

/** Statuses a retry may start from (ER-21): not `succeeded` (that is the pipeline's manual run), not `skipped`, not active. */
export const EXECUTION_RETRYABLE_STATUSES = Object.freeze([
  "failed",
  "timed_out",
  "partial",
  "cancelled",
  "blocked",
]);
/** `EXECUTION_RETRY_CHAIN_MAX` default (EQ-2d): how many retries may follow one original. */
export const DEFAULT_RETRY_CHAIN_MAX = 5;

/** @param {string} status @returns {boolean} */
export const isRetryableExecutionStatus = (status) => EXECUTION_RETRYABLE_STATUSES.includes(status);

/** Prefix of the stored idempotency key of a retry (ER-23): `retry:<userId>:<header>`. */
export const retryIdempotencyKey = (userId, header) => `retry:${userId}:${header}`;
