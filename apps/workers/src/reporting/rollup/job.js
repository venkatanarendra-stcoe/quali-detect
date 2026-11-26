import { NonRetryableError, TransientError, classifyError } from "@qmentisai/infra";
import {
  REPORTING_LIMITS,
  ROLLUP_ERROR_CODES,
  USABLE_TENANT_STATUSES,
  addDays,
  dayCloseInstant,
  diffDays,
  isDayString,
  isValidTimeZone,
  localDayOf,
} from "@qmentisai/shared";

/**
 * The rollup jobs (docs/modules/reporting-dashboards/SPEC.md 7.2, 10; ADR-015): the hourly INCREMENTAL run, the day CLOSE, the throttled
 * resumable BACKFILL and the REBUILD after a time-zone change. Pure orchestration over the frozen repository: every number comes from
 * `rollupRepository` (reads only the `report_*_v` views), every write is an idempotent upsert keyed by the natural key, and every run
 * leaves a `report_rollup_runs` row with the newest history row it read (`as_of_history_id`, so "data as of" is exact).
 *
 * SEVERITY SERIES: FORWARD-ONLY (proved by RPT-S10, stated in AS_BUILT_A.md). The state counters (per severity) are written ONLY by a
 * live run, whose `T` is "now" (or a close within `closeStateMaxLagMs` of the day end with no severity-changing decision since): the views
 * carry the CURRENT severity only, and a tool re-rate leaves no trace, so a past day's severity split cannot be reconstructed exactly. A
 * backfill therefore writes the flow, execution, decision and SBOM series and NEVER a state counter, and it never zeroes one.
 */

/** Tunables (a test overrides them through `options`). */
export const ROLLUP_DEFAULTS = Object.freeze({
  /** Days per backfill batch (one run row, one set of queries). */
  backfillBatchDays: 45,
  /** Pause between backfill batches, milliseconds (the throttle). */
  throttleMs: 250,
  /** A close writes the day's state only within this lag of the day end (a tool re-rate in the gap would be invisible). */
  closeStateMaxLagMs: 6 * 60 * 60 * 1000,
});

/** Months before `day` (calendar arithmetic on a day string). @param {string} day @param {number} months @returns {string} */
export function subtractMonths(day, months) {
  const [y, m, d] = day.split("-").map(Number);
  const t = new Date(Date.UTC(y, m - 1 - months, 1));
  const last = new Date(Date.UTC(t.getUTCFullYear(), t.getUTCMonth() + 1, 0)).getUTCDate();
  return `${String(t.getUTCFullYear()).padStart(4, "0")}-${String(t.getUTCMonth() + 1).padStart(2, "0")}-${String(Math.min(d, last)).padStart(2, "0")}`;
}

/**
 * Maps a thrown value to a stable `ROLLUP_ERROR_CODES` word and the retry class: input and ownership problems are NON-retryable, a
 * transient database or network error and a statement timeout are retryable, anything unknown is `internal` and not repeated blindly.
 * @param {any} error @returns {{ code: string, retryable: boolean }}
 */
export function classifyRollupError(error) {
  const known = (c) => (ROLLUP_ERROR_CODES.includes(c) ? c : "internal");
  if (error?.rollupCode) return { code: known(error.rollupCode), retryable: false };
  if (error instanceof NonRetryableError) return { code: known(error.reason), retryable: false };
  const pg = String(error?.meta?.code ?? error?.code ?? "");
  const text = String(error?.message ?? "");
  if (pg === "57014" || /statement timeout|canceling statement/i.test(text))
    return { code: "timeout", retryable: true };
  if (["40001", "40P01", "57P01", "08006", "08003", "08001", "53300"].includes(pg))
    return { code: "source_unavailable", retryable: true };
  if (error instanceof TransientError || classifyError(error) === "transient")
    return { code: "source_unavailable", retryable: true };
  return { code: "internal", retryable: false };
}

const sleep = (ms, signal) =>
  ms > 0
    ? new Promise((resolve) => {
        const timer = setTimeout(resolve, ms);
        signal?.addEventListener("abort", () => (clearTimeout(timer), resolve()), { once: true });
      })
    : Promise.resolve();

/**
 * @typedef {object} JobDeps
 * @property {import("@qmentisai/db").ReportingRollupRepository} repo
 * @property {any} log a Pino logger (ids, counts, codes)
 * @property {() => Date} now
 * @property {{ rollupRetentionMonths?: number }} [reporting]
 * @property {Partial<typeof ROLLUP_DEFAULTS>} [options]
 */

/**
 * The tenant and its reporting time zone, re-validated from the database (the message is never authority). Throws a non-retryable
 * `ownership_mismatch` for an unknown or unusable tenant and `invalid_range` for a time zone this runtime does not know.
 * @param {import("@qmentisai/db").ReportingRollupRepository} repo @param {string} tenantId
 */
export async function loadTenant(repo, tenantId) {
  const tenant = await repo.getTenantSettings({ tenantId });
  if (!tenant || !USABLE_TENANT_STATUSES.includes(tenant.status))
    throw new NonRetryableError("tenant is unknown or not usable", {
      reason: "ownership_mismatch",
    });
  if (!isValidTimeZone(tenant.timeZone))
    throw new NonRetryableError("tenant time zone is not valid", { reason: "invalid_range" });
  return tenant;
}

/** Runs `body` inside a run row: succeeded with the counts, or failed with the stable code (then rethrown, classified). */
async function inRun(deps, { tenantId, mode, day, rangeTo = null, timeZone }, body) {
  const { repo, now } = deps;
  const run = await repo.startRun({ tenantId, mode, day, rangeTo, timeZone, now: now() });
  try {
    const { rowsWritten, asOfHistoryId = null, ...rest } = await body();
    await repo.finishRun({
      tenantId,
      runId: run.id,
      status: "succeeded",
      rowsWritten,
      asOfHistoryId,
      now: now(),
    });
    return { runId: run.id, rowsWritten, ...rest };
  } catch (error) {
    const { code, retryable } = classifyRollupError(error);
    await repo
      .finishRun({
        tenantId,
        runId: run.id,
        status: "failed",
        rowsWritten: 0,
        errorCode: code,
        now: now(),
      })
      .catch(() => {});
    deps.log?.warn?.({ tenantId, mode, day, code, retryable }, "reporting rollup run failed");
    const wrap = retryable ? TransientError : NonRetryableError;
    throw wrap === NonRetryableError
      ? new NonRetryableError(`rollup ${mode} failed: ${code}`, { reason: code, cause: error })
      : new TransientError(`rollup ${mode} failed: ${code}`, { cause: error });
  }
}

/** The four non-state series of `[from, to]` and their writes. SBOM and executions are upsert-only unless `zeroExecutions`. */
async function writeSeries(deps, { tenantId, from, to, timeZone, zeroDays, zeroExecutions }) {
  const { repo } = deps;
  const range = { tenantId, from, to, timeZone };
  const [flow, executions, decisions, sbom] = await Promise.all([
    repo.computeFindingsFlow(range),
    repo.computeExecutionsDays(range),
    repo.computeDecisionsDays(range),
    repo.computeSbomDays(range),
  ]);
  let rows = 0;
  rows += await repo.upsertFindingsDays({
    tenantId,
    rows: flow,
    replace: { days: zeroDays, groups: ["flow"] },
  });
  rows += await repo.upsertExecutionsDays({
    tenantId,
    rows: executions,
    replaceDays: zeroExecutions ? zeroDays : [],
  });
  rows += await repo.upsertDecisionsDays({ tenantId, rows: decisions, replaceDays: zeroDays });
  // an SBOM day is a snapshot of the pipeline's latest result and the views keep only the latest: never zero a stored day
  rows += await repo.upsertSbomDays({ tenantId, rows: sbom, replaceDays: [] });
  return { rows, asOfHistoryId: flow.asOfHistoryId ?? null };
}

/**
 * Hourly run: TODAY's state at `T = now` (replaces today's state rows) and the flow, execution, decision and SBOM series of yesterday and
 * today (yesterday is recomputed so a late row heals without waiting for the close).
 * @param {JobDeps} deps @param {{ tenantId: string, timeZone: string }} tenant
 */
export async function runIncremental(deps, { tenantId, timeZone }) {
  const instant = deps.now();
  const today = localDayOf(instant, timeZone);
  const yesterday = addDays(today, -1);
  return inRun(deps, { tenantId, mode: "incremental", day: today, timeZone }, async () => {
    const state = await deps.repo.computeFindingsStateAsOf({ tenantId, instant });
    let rowsWritten = await deps.repo.upsertFindingsDays({
      tenantId,
      rows: state.map((r) => ({ ...r, day: today })),
      replace: { days: [today], groups: ["state"] },
    });
    const series = await writeSeries(deps, {
      tenantId,
      from: yesterday,
      to: today,
      timeZone,
      zeroDays: [yesterday, today],
      zeroExecutions: true,
    });
    rowsWritten += series.rows;
    return {
      rowsWritten,
      asOfHistoryId: state.asOfHistoryId ?? series.asOfHistoryId,
      stateWritten: true,
    };
  });
}

/**
 * Day close: finalises a finished tenant-local day. The series of the day are recomputed; the state at `T = end of the day` is written
 * ONLY while it is still exact (within the lag, and no approved severity override decided after T); otherwise the last hourly snapshot of
 * that day stays as it is.
 * @param {JobDeps} deps @param {{ tenantId: string, timeZone: string }} tenant @param {string} day
 */
export async function runClose(deps, { tenantId, timeZone }, day) {
  const now = deps.now();
  const today = localDayOf(now, timeZone);
  if (!isDayString(day) || !(day < today))
    throw new NonRetryableError("a day closes only after it ended", { reason: "invalid_range" });
  const options = { ...ROLLUP_DEFAULTS, ...deps.options };
  const closeAt = dayCloseInstant(day, timeZone);
  return inRun(deps, { tenantId, mode: "close", day, timeZone }, async () => {
    let rowsWritten = 0;
    let stateWritten = false;
    let asOfHistoryId = null;
    if (now.getTime() - closeAt.getTime() <= options.closeStateMaxLagMs) {
      const state = await deps.repo.computeFindingsStateAsOf({ tenantId, instant: closeAt });
      asOfHistoryId = state.asOfHistoryId ?? null;
      if (state.every((r) => r.severityExact)) {
        rowsWritten += await deps.repo.upsertFindingsDays({
          tenantId,
          rows: state.map((r) => ({ ...r, day })),
          replace: { days: [day], groups: ["state"] },
        });
        stateWritten = true;
      }
    }
    const series = await writeSeries(deps, {
      tenantId,
      from: day,
      to: day,
      timeZone,
      zeroDays: [day],
      zeroExecutions: true,
    });
    return {
      rowsWritten: rowsWritten + series.rows,
      asOfHistoryId: asOfHistoryId ?? series.asOfHistoryId,
      stateWritten,
    };
  });
}

/**
 * Backfill (and, with `reason: "timezone_changed"`, the REBUILD): the flow, execution, decision and SBOM series for `[from, to]`, in
 * throttled batches, one run row per batch, one tenant per call. Resumable: a batch already covered by a succeeded backfill run of the
 * same time zone is skipped (not for a rebuild or a repair, which recompute everything). A rebuild first clears the range through the
 * SECURITY DEFINER function, so a combination that no longer has data disappears (exact); that also drops the stored state snapshots of
 * the range (they were keyed by the old zone's days and cannot be reconstructed, see the module header).
 * @param {JobDeps} deps @param {{ tenantId: string, timeZone: string }} tenant
 * @param {{ from: string, to: string, reason?: string }} range @param {AbortSignal} [signal]
 */
export async function runBackfill(deps, { tenantId, timeZone }, { from, to, reason }, signal) {
  const options = { ...ROLLUP_DEFAULTS, ...deps.options };
  const now = deps.now();
  const today = localDayOf(now, timeZone);
  const months = deps.reporting?.rollupRetentionMonths ?? REPORTING_LIMITS.rollupRetentionMonths;
  const floor = subtractMonths(today, months);
  const start = from < floor ? floor : from;
  const end = to > today ? today : to;
  if (start > end) return { batches: 0, skipped: 0, rowsWritten: 0 };
  const recompute = reason === "timezone_changed" || reason === "repair";
  // the rebuild also voids the run coverage of the range, so a day only the old zone's runs covered reads as unknown again, not as zeros
  if (reason === "timezone_changed")
    await deps.repo.clearRange({ tenantId, from: start, to: end, voidCoverage: true });
  const covered = recompute
    ? []
    : (await deps.repo.listRuns({ tenantId, from: start, to: end, mode: "backfill" })).filter(
        (r) => r.status === "succeeded" && r.timeZone === timeZone && r.rangeTo,
      );
  let batches = 0;
  let skipped = 0;
  let total = 0;
  for (let bFrom = start; bFrom <= end; bFrom = addDays(bFrom, options.backfillBatchDays)) {
    if (signal?.aborted) throw new TransientError("rollup backfill aborted by shutdown");
    const bTo =
      diffDays(bFrom, end) < options.backfillBatchDays
        ? end
        : addDays(bFrom, options.backfillBatchDays - 1);
    if (covered.some((r) => r.day <= bFrom && r.rangeTo >= bTo)) {
      skipped += 1;
      continue;
    }
    const done = await inRun(
      deps,
      { tenantId, mode: "backfill", day: bFrom, rangeTo: bTo, timeZone },
      async () => {
        const series = await writeSeries(deps, {
          tenantId,
          from: bFrom,
          to: bTo,
          timeZone,
          zeroDays: listDaysBetween(bFrom, bTo),
          zeroExecutions: false,
        });
        return { rowsWritten: series.rows, asOfHistoryId: series.asOfHistoryId };
      },
    );
    batches += 1;
    total += done.rowsWritten;
    if (addDays(bTo, 1) <= end) await sleep(options.throttleMs, signal);
  }
  return { batches, skipped, rowsWritten: total };
}

const listDaysBetween = (from, to) =>
  Array.from({ length: diffDays(from, to) + 1 }, (_, i) => addDays(from, i));
