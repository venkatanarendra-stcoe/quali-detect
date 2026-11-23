/**
 * Resolution coverage (docs/modules/findings/SPEC.md 5.4, D-2, D-25): may execution E treat open finding F as ABSENT? Pure. The
 * answer is "yes" only when EVERY condition holds; any doubt leaves the finding untouched and says why (counted as
 * `resolution_skipped` by reason).
 *
 * @typedef {object} CoverageFinding the stored finding (read side)
 * @property {string} scanType
 * @property {string | null} [ecosystem]
 * @property {string | null} [path]
 * @property {string[]} [lastSeenTools] tool ids that reported it last (SPEC 7.2 `last_seen_tools`)
 *
 * @typedef {object} CoverageExecution facts of the execution, recomputed by the handler from database rows
 * @property {boolean} resolutionEligible event flag AND recomputed value combined with `min` (false when either is false)
 * @property {boolean} [eligibilityDisagrees] the event and the database disagreed (logged; fails closed)
 * @property {boolean} isBaseline trusted, branch, equals the tracked ref (IN-3)
 * @property {Date} startedAt
 * @property {Date | null} [resolutionWatermarkStartedAt] IN-6
 * @property {boolean} typeEnabled the pipeline still enables the finding's scan type
 *
 * @typedef {object} CoverageResult the `scan_results` row of the finding's scan type in this execution (or null)
 * @property {"complete" | "incomplete"} completeness
 * @property {boolean} truncated
 * @property {{ state?: string, coverageGaps?: string[], toolsDegraded?: number } | null} [coverage]
 * @property {boolean} [fullTree] the scope of the result is the full tree (no `full_filtered` or `targets` kind)
 *
 * @typedef {{ toolId: string, status: string }} CoverageToolRun
 */

/**
 * @param {CoverageFinding} finding
 * @param {CoverageExecution} execution
 * @param {CoverageResult | null} result
 * @param {CoverageToolRun[]} toolRuns tool runs of this task attempt
 * @returns {{ absent: true } | { absent: false, reason: string }}
 */
export function evaluateCoverage(finding, execution, result, toolRuns) {
  const no = (reason) => ({ absent: /** @type {const} */ (false), reason });
  // 1. the execution is resolution eligible (event AND database)
  if (execution.eligibilityDisagrees) return no("eligibility_disagrees");
  if (!execution.resolutionEligible) return no("not_eligible");
  // 2. the tracked baseline, and newer than the watermark
  if (!execution.isBaseline) return no("not_baseline");
  const wm = execution.resolutionWatermarkStartedAt;
  if (wm && execution.startedAt.getTime() <= wm.getTime()) return no("stale_watermark");
  // 5. the type is still enabled (checked early: no result exists otherwise)
  if (!execution.typeEnabled) return no("type_disabled");
  // 3. the result of the type exists, is complete, not truncated, covering and undegraded, full tree
  if (!result) return no("no_result");
  if (result.completeness !== "complete") return no("incomplete");
  if (result.truncated) return no("truncated");
  const cov = result.coverage ?? null;
  if (!cov || cov.state !== "complete") return no("coverage_not_complete");
  if (typeof cov.toolsDegraded !== "number" || cov.toolsDegraded !== 0) return no("tools_degraded");
  if (result.fullTree !== true) return no("partial_scope");
  // 4. no coverage gap matches the finding and every tool that last reported it ran to completion
  const gaps = Array.isArray(cov.coverageGaps) ? cov.coverageGaps : [];
  const eco = String(finding.ecosystem ?? "").toLowerCase();
  const path = String(finding.path ?? "");
  for (const raw of gaps) {
    const gap = String(raw).toLowerCase();
    if (gap === eco || (gap.length > 0 && (path === raw || path.startsWith(`${raw}/`))))
      return no("coverage_gap");
  }
  const tools = finding.lastSeenTools ?? [];
  for (const toolId of tools) {
    const run = toolRuns.find((r) => r.toolId === toolId);
    if (!run || run.status !== "succeeded") return no("tool_not_run");
  }
  return { absent: true };
}
