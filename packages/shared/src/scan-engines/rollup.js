import { TOOL_STATUSES, TOOLS_FAILED_REASON, toolReasonClass } from "./constants.js";

/**
 * Roll-up of per-tool run statuses into the task outcome (docs/modules/scan-engines/SPEC.md 5.4, owner decision D-6). Pure and
 * shared by the scan worker, the API mapper and the security suite. Evaluated top to bottom, first match wins:
 * 1 cancel or lease loss; 2 deadline; 3 nothing relevant to scan; 4 relevant files but no applicable tool; 5 at least one tool
 * `succeeded` or `partial` and no failure; 6 as 5 with at least one failed, timed out, cancelled or unavailable tool
 * (`succeeded`, DEGRADED, `incomplete`, never resolution eligible); 7 no tool succeeded and at least one failed (`failed`,
 * `tools_failed`, transient only when every failure is transient). No new task status; `unsupported` is never produced here.
 * A stale vulnerability database is never a failure (owner decision 2026-11-19): the reason `db_stale` is valid only on a
 * `partial` run and any other combination is refused with a TypeError, so a caller cannot fail a scan for staleness. A tool that
 * stays `unavailable` with `db_unavailable` after the retries is a broken tool of row 6 (degraded, `incomplete`) when another tool
 * produced output; when none did, the task is the ordinary `failed` task of row 7 with the transient class (the retry budget of
 * ER-13 decides how often).
 */

/** @typedef {{ toolId: string, status: typeof TOOL_STATUSES[number], reason?: string | null }} ToolOutcome */
/**
 * @typedef {object} TaskRollup
 * @property {"succeeded" | "failed" | "cancelled" | "timed_out"} taskStatus
 * @property {string | null} reason `tools_failed` for row 7, `cancelled` / `deadline` for rows 1 and 2
 * @property {"complete" | "incomplete" | null} completeness `null`: no result is written (row 7)
 * @property {number} toolsDegraded the incomplete-result flag of row 6
 * @property {"complete" | "partial" | "degraded" | "nothing_to_scan" | "language_gap"} coverageState
 * @property {string[]} coverageGaps
 * @property {boolean} resolutionEligible true only for a `succeeded` task with a `complete` result (ER-24)
 * @property {"transient" | "permanent" | null} errorClass only for a failed task
 * @property {number} matchedRow the row of table 5.4 that decided (1 to 7)
 */

const OK = new Set(["succeeded", "partial"]);
const BROKEN = new Set(["failed", "timed_out", "cancelled", "unavailable"]);

/**
 * @param {{ tools: ToolOutcome[], cancelled?: boolean, deadlineReached?: boolean, relevantFilesExist?: boolean, coverageGaps?: string[] }} input
 * `tools`: every tool of the scan type with its status (`skipped` = not applicable). `relevantFilesExist`: whether the tree has
 * any file relevant to the scan type (default true). `coverageGaps`: languages or kinds with no catalog tool (row 4).
 * @returns {TaskRollup}
 */
export function rollUpTask({
  tools,
  cancelled = false,
  deadlineReached = false,
  relevantFilesExist = true,
  coverageGaps = [],
}) {
  if (!Array.isArray(tools)) throw new TypeError("tools must be an array");
  for (const t of tools)
    if (!TOOL_STATUSES.includes(t?.status)) throw new TypeError("unknown tool status");
  for (const t of tools)
    if (toolReasonClass(t.reason) === "warning" && t.status !== "partial")
      throw new TypeError("a stale database is a warning on a partial run, never a failure");
  const base = {
    toolsDegraded: 0,
    coverageGaps: [],
    resolutionEligible: false,
    errorClass: /** @type {null} */ (null),
  };
  if (cancelled)
    return {
      ...base,
      taskStatus: "cancelled",
      reason: "cancelled",
      completeness: "incomplete",
      coverageState: "partial",
      matchedRow: 1,
    };
  if (deadlineReached)
    return {
      ...base,
      taskStatus: "timed_out",
      reason: "deadline",
      completeness: "incomplete",
      coverageState: "partial",
      matchedRow: 2,
    };
  const applicable = tools.filter((t) => t.status !== "skipped");
  const ok = applicable.filter((t) => OK.has(t.status));
  const broken = applicable.filter((t) => BROKEN.has(t.status));
  if (applicable.length === 0) {
    if (!relevantFilesExist)
      return {
        ...base,
        taskStatus: "succeeded",
        reason: null,
        completeness: "complete",
        coverageState: "nothing_to_scan",
        resolutionEligible: true,
        matchedRow: 3,
      };
    return {
      ...base,
      taskStatus: "succeeded",
      reason: null,
      completeness: "incomplete",
      coverageState: "language_gap",
      coverageGaps: [...coverageGaps],
      matchedRow: 4,
    };
  }
  if (ok.length === 0) {
    const transient = broken.every((t) => toolReasonClass(t.reason) === "transient");
    return {
      ...base,
      taskStatus: "failed",
      reason: TOOLS_FAILED_REASON,
      completeness: null,
      coverageState: "degraded",
      toolsDegraded: broken.length,
      errorClass: broken.length > 0 && transient ? "transient" : "permanent",
      matchedRow: 7,
    };
  }
  if (broken.length > 0)
    return {
      ...base,
      taskStatus: "succeeded",
      reason: null,
      completeness: "incomplete",
      coverageState: "degraded",
      toolsDegraded: broken.length,
      matchedRow: 6,
    };
  const partial = ok.some((t) => t.status === "partial");
  return {
    ...base,
    taskStatus: "succeeded",
    reason: null,
    completeness: partial ? "incomplete" : "complete",
    coverageState: partial ? "partial" : "complete",
    resolutionEligible: !partial,
    matchedRow: 5,
  };
}
