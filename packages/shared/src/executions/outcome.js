/**
 * Pure rules of the execution orchestrator that other modules (Findings, API, tests) must agree on
 * (docs/modules/executions/SPEC.md §5.4, ER-11, ER-24). No I/O.
 */

/** Scan types in the fixed catalog order the tasks are created and dispatched in (ER-11). */
export const SCAN_TASK_ORDER = Object.freeze(["sbom", "sca", "sast", "secrets"]);

/** Task statuses that still need work. */
export const SCAN_TASK_ACTIVE_STATUSES = Object.freeze(["pending", "queued", "running"]);

/**
 * Table 5.4 for a run that ended normally (no task is pending, queued or running), as amended by SPEC §17.ab (owner decision
 * 2026-11-16: an enabled scan type without a registered engine is `unsupported`, never `failed`, and never blocks the run).
 * Let `unsupported` tasks be those that never ran for lack of an engine:
 * - every task `succeeded` (and at least one task exists): `succeeded` (so SBOM alone enabled and run is `succeeded`);
 * - at least one `succeeded` and at least one `failed`/`timed_out`/other non-success: `partial` / `tasks_incomplete` (EQ-3);
 * - at least one `succeeded`, the rest only `unsupported`: `partial` / `tasks_unsupported`;
 * - no task `succeeded`, every task `unsupported` (nothing could run; Recommended, flagged in SPEC §17.ab): `failed` /
 *   `tasks_unsupported`;
 * - no task `succeeded` otherwise: `failed` / `tasks_failed`.
 * Deadline and cancel endings are decided by the caller, not here.
 * @param {Array<{ status: string }>} tasks
 * @returns {{ status: "succeeded" | "partial" | "failed", reason: string | null }}
 */
export function aggregateTaskOutcome(tasks) {
  if (!Array.isArray(tasks) || tasks.length === 0)
    return { status: "failed", reason: "tasks_failed" };
  if (tasks.some((t) => SCAN_TASK_ACTIVE_STATUSES.includes(t.status)))
    throw new TypeError("aggregateTaskOutcome needs every task to be finished");
  const succeeded = tasks.filter((t) => t.status === "succeeded").length;
  const unsupported = tasks.filter((t) => t.status === "unsupported").length;
  const otherNonSuccess = tasks.length - succeeded - unsupported;
  if (succeeded === tasks.length) return { status: "succeeded", reason: null };
  if (succeeded > 0)
    return otherNonSuccess > 0
      ? { status: "partial", reason: "tasks_incomplete" }
      : { status: "partial", reason: "tasks_unsupported" };
  if (otherNonSuccess === 0) return { status: "failed", reason: "tasks_unsupported" };
  return { status: "failed", reason: "tasks_failed" };
}

/**
 * `resolutionEligible` of `pipeline.execution.completed` (ER-24): necessary, not sufficient, for the Findings module to resolve
 * findings. True ONLY for a succeeded, full, trusted (non-fork) execution in which every enabled scan type has a task with a
 * complete, non-truncated result. An `unsupported` task never has a result, so an execution with one is never eligible (and its
 * status is `partial` or `failed` anyway).
 * @param {{ status: string, scanKind: string, trust: string, enabledScanTypes: string[], tasks: Array<{ scanType: string, status: string, completeness?: string | null, truncated?: boolean }> }} input
 * @returns {boolean}
 */
export function isResolutionEligible({ status, scanKind, trust, enabledScanTypes, tasks }) {
  if (status !== "succeeded" || scanKind !== "full" || trust !== "trusted") return false;
  if (enabledScanTypes.length === 0) return false;
  return enabledScanTypes.every((type) => {
    const task = tasks.find((t) => t.scanType === type);
    return task?.status === "succeeded" && task.completeness === "complete" && !task.truncated;
  });
}
