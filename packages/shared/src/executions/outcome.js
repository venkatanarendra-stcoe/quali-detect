/**
 * Pure rules of the execution orchestrator that other modules (Findings, API, tests) must agree on
 * (docs/modules/executions/SPEC.md §5.4, ER-11, ER-24). No I/O.
 */

/** Scan types in the fixed catalog order the tasks are created and dispatched in (ER-11). */
export const SCAN_TASK_ORDER = Object.freeze(["sbom", "sca", "sast", "secrets"]);

/** Task statuses that still need work. */
export const SCAN_TASK_ACTIVE_STATUSES = Object.freeze(["pending", "queued", "running"]);

/**
 * Table 5.4 for a run that ended normally (no task is pending, queued or running).
 * - every task `succeeded` (and at least one task exists): `succeeded`;
 * - at least one `succeeded` and at least one `failed`/`timed_out` (EQ-3, option A): `partial` / `tasks_incomplete`;
 * - no task `succeeded`: `failed` / `tasks_failed`.
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
  if (succeeded === tasks.length) return { status: "succeeded", reason: null };
  if (succeeded > 0) return { status: "partial", reason: "tasks_incomplete" };
  return { status: "failed", reason: "tasks_failed" };
}

/**
 * `resolutionEligible` of `pipeline.execution.completed` (ER-24): necessary, not sufficient, for the Findings module to resolve
 * findings. True ONLY for a succeeded, full, trusted (non-fork) execution in which every enabled scan type has a task with a
 * complete, non-truncated result.
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
