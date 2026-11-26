import {
  BACKLOG_STATUSES,
  FINDING_SCAN_TYPES,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  LIFECYCLE_GROUP_IDS,
  LIFECYCLE_GROUP_OF_STATUS,
  OPEN_FINDING_STATUSES,
  REPORT_EXECUTION_STATUSES,
  REPORTING_LIMITS,
  WORK_IN_PROGRESS_STATUSES,
  addDays,
  diffDays,
  listDays,
} from "@qmentisai/shared";

/**
 * DTO mappers of the reporting READ routes (docs/modules/reporting-dashboards/SPEC.md 9). The repository returns plain rows; these shape the
 * strict DTOs of `@qmentisai/shared` (`REPORTING_ROUTE_SCHEMAS`): counts, ids, enums and the explicitly listed drill-down strings only (aging
 * oldest ten, top-risk repository names, noisy rules). They never copy a row wholesale, so a column added to a view cannot leak into a DTO.
 */

const zeroed = (keys) => Object.fromEntries(keys.map((k) => [k, 0]));
const sumBy = (list, f) => list.reduce((a, r) => a + f(r), 0);
const OPEN = new Set(OPEN_FINDING_STATUSES);
const SEVERITIES_NO_INFO = FINDING_SEVERITIES.filter((s) => s !== "info");

/** A rate that is not shown below the minimum sample (SPEC 5 rule 9). @param {number} numerator @param {number} denominator */
export function toRate(numerator, denominator) {
  const tooFew = denominator < REPORTING_LIMITS.minDecisionsForRate;
  return {
    numerator,
    denominator,
    rate: tooFew || denominator === 0 ? null : numerator / denominator,
    tooFew,
  };
}

/** @param {import("@qmentisai/shared").ResolvedPeriod} p */
export const toPeriod = (p) => ({
  from: p.from,
  to: p.to,
  dayCount: p.dayCount,
  preset: p.preset,
});

/**
 * P-1 to P-9 (and P-10 when `pipelines` is given) from the grouped rows of the live query.
 * @param {{ groups: any[], pipelines: { healthy: number, total: number } | null }} raw
 */
export function toPostureDto(raw) {
  const byStatus = zeroed(FINDING_STATUSES);
  const bySeverity = zeroed(FINDING_SEVERITIES);
  const byType = zeroed(FINDING_SCAN_TYPES);
  for (const g of raw.groups) {
    byStatus[g.status] += g.n;
    if (OPEN.has(g.status)) {
      bySeverity[g.severity] += g.n;
      byType[g.scanType] += g.n;
    }
  }
  const byGroup = zeroed(LIFECYCLE_GROUP_IDS);
  for (const [status, n] of Object.entries(byStatus))
    byGroup[LIFECYCLE_GROUP_OF_STATUS[status]] += n;
  return {
    asOfDay: null,
    open: sumBy(OPEN_FINDING_STATUSES, (s) => byStatus[s]),
    bySeverity,
    byType,
    byGroup,
    byStatus,
    backlog: sumBy(BACKLOG_STATUSES, (s) => byStatus[s]),
    workInProgress: sumBy(WORK_IN_PROGRESS_STATUSES, (s) => byStatus[s]),
    criticalHighOpen: bySeverity.critical + bySeverity.high,
    exceptions: {
      inForce: byStatus.accepted_risk + byStatus.suppressed,
      expiringWithin30Days: sumBy(raw.groups, (g) => g.expiring),
    },
    awaitingDecision: {
      awaitingApproval: byStatus.awaiting_approval,
      pendingExceptions: sumBy(raw.groups, (g) => g.pendingExceptions),
    },
    newLast24Hours: sumBy(raw.groups, (g) => g.newLast24Hours),
    pipelinesHealthy: raw.pipelines ?? null,
  };
}

/**
 * The point-in-time posture from the daily rollup. The rollup keeps the open, backlog, work-in-progress, awaiting-verification and
 * exception COUNTS per type and severity, not one count per status: the statuses and groups it cannot tell apart are 0 (see AS_BUILT_B.md).
 * @param {{ day: string, rows: any[] }} raw
 */
export function toPostureAsOfDto(raw) {
  const bySeverity = zeroed(FINDING_SEVERITIES);
  const byType = zeroed(FINDING_SCAN_TYPES);
  for (const r of raw.rows) {
    bySeverity[r.severity] += r.open;
    byType[r.scanType] += r.open;
  }
  const awaitingVerification = sumBy(raw.rows, (r) => r.awaitingVerification);
  const exceptionsInForce = sumBy(raw.rows, (r) => r.exceptionsInForce);
  const byStatus = zeroed(FINDING_STATUSES);
  byStatus.fixed_pending_verification = awaitingVerification;
  const byGroup = zeroed(LIFECYCLE_GROUP_IDS);
  byGroup.awaiting_verification = awaitingVerification;
  byGroup.accepted_or_suppressed = exceptionsInForce;
  return {
    asOfDay: raw.day,
    open: sumBy(raw.rows, (r) => r.open),
    bySeverity,
    byType,
    byGroup,
    byStatus,
    backlog: sumBy(raw.rows, (r) => r.backlog),
    workInProgress: sumBy(raw.rows, (r) => r.wip),
    criticalHighOpen: bySeverity.critical + bySeverity.high,
    exceptions: { inForce: exceptionsInForce, expiringWithin30Days: 0 },
    awaitingDecision: { awaitingApproval: 0, pendingExceptions: 0 },
    newLast24Hours: null,
    pipelinesHealthy: null,
  };
}

/**
 * T-1 to T-5 on a continuous day axis. A day that NO rollup run touched is a gap: the point carries the day only (the strict point schema
 * has no null; an absent series key is the gap marker, never a 0). A covered day without rows is a real zero (the rollup is sparse).
 * @param {{ rows: any[], runs: any[], dataFrom: string | null }} raw
 * @param {{ from: string, to: string, series: string[], severityBackfilled?: boolean }} options
 */
export function toTrendPoints(raw, { from, to, series }) {
  const covered = new Set();
  for (const r of raw.rows) covered.add(r.day);
  for (const run of raw.runs) {
    const last = run.rangeTo ?? run.day;
    for (const d of listDays(run.day < from ? from : run.day, last > to ? to : last))
      covered.add(d);
  }
  const byDay = new Map();
  for (const r of raw.rows) {
    const d = byDay.get(r.day) ?? {
      new: 0,
      fixed: 0,
      closedOther: 0,
      reopened: 0,
      open: 0,
      awaitingVerification: 0,
      severity: zeroed(FINDING_SEVERITIES),
    };
    d.new += r.new;
    d.fixed += r.fixed;
    d.closedOther += r.closedOther;
    d.reopened += r.reopened;
    d.open += r.open;
    d.awaitingVerification += r.awaitingVerification;
    d.severity[r.severity] += r.open;
    byDay.set(r.day, d);
  }
  const want = new Set(series);
  return listDays(from, to).map((day) => {
    if (!covered.has(day)) return { day };
    const d = byDay.get(day) ?? {
      new: 0,
      fixed: 0,
      closedOther: 0,
      reopened: 0,
      open: 0,
      awaitingVerification: 0,
      severity: zeroed(FINDING_SEVERITIES),
    };
    return {
      day,
      ...(want.has("flow")
        ? { new: d.new, fixed: d.fixed, closedWithoutFix: d.closedOther, reopened: d.reopened }
        : {}),
      ...(want.has("severity") ? { openBySeverity: d.severity } : {}),
      ...(want.has("backlog") ? { open: d.open } : {}),
      ...(want.has("net_change")
        ? { netChange: d.new + d.reopened - d.fixed - d.closedOther }
        : {}),
      ...(want.has("awaiting_verification")
        ? { awaitingVerification: d.awaitingVerification }
        : {}),
    };
  });
}

/**
 * The labelled linear burn-down estimate (T-3): only when the open count fell over the trailing 14 covered days and at least 14 days
 * exist; it extends the last day by the average daily drop until the count reaches zero (at most 120 days).
 * @param {Array<{ day: string, open?: number }>} points
 */
export function toProjection(points) {
  const withOpen = points.filter((p) => typeof p.open === "number");
  const min = REPORTING_LIMITS.projectionMinDays;
  if (withOpen.length < min) return null;
  const tail = withOpen.slice(-min);
  const drop = tail[0].open - tail.at(-1).open;
  if (drop <= 0) return null;
  const perDay = drop / (min - 1);
  const days = [];
  let open = tail.at(-1).open;
  let day = tail.at(-1).day;
  while (open > 0 && days.length < 120) {
    day = addDays(day, 1);
    open = Math.max(0, open - perDay);
    days.push({ day, open: Math.round(open * 100) / 100 });
  }
  return days.length > 0 ? { days, label: /** @type {const} */ ("estimate") } : null;
}

/** @param {{ from: string, to: string }} p the Monday of each week of the period, continuous */
function weeksOf(p) {
  const monday = (d) => {
    const dow = (new Date(`${d}T00:00:00Z`).getUTCDay() + 6) % 7; // Monday = 0
    return addDays(d, -dow);
  };
  const first = monday(p.from);
  const count = Math.floor(diffDays(first, monday(p.to)) / 7) + 1;
  return Array.from({ length: count }, (_, i) => addDays(first, i * 7));
}

/** R-1 to R-3, R-7, R-8. @param {any} raw @param {import("@qmentisai/shared").ResolvedPeriod} p */
export function toRemediationDto(raw, p) {
  const fixedByWeek = new Map(raw.velocity.map((v) => [v.weekStart, v.fixed]));
  return {
    period: toPeriod(p),
    timeToRemediate: raw.timeToRemediate,
    velocity: weeksOf(p).map((weekStart) => ({
      weekStart,
      fixed: fixedByWeek.get(weekStart) ?? 0,
    })),
    timeToFirstDecision: raw.timeToFirstDecision,
    verificationLag: raw.verificationLag,
    reopenRate: toRate(raw.reopen.reopened, raw.reopen.fixed),
  };
}

/** R-4 and R-5. @param {{ open: any[], closed: any[] }} raw */
export function toSlaDto(raw) {
  const closed = Object.fromEntries(
    SEVERITIES_NO_INFO.map((s) => {
      const r = raw.closed.find((x) => x.severity === s);
      const withTarget = r?.withTarget ?? 0;
      const withinSla = r?.withinSla ?? 0;
      return [
        s,
        { withTarget, withinSla, compliance: withTarget > 0 ? withinSla / withTarget : null },
      ];
    }),
  );
  const bySeverity = Object.fromEntries(
    SEVERITIES_NO_INFO.map((s) => {
      const r = raw.open.find((x) => x.severity === s);
      return [
        s,
        { onTrack: r?.onTrack ?? 0, dueSoon: r?.dueSoon ?? 0, breached: r?.breached ?? 0 },
      ];
    }),
  );
  const total = {
    onTrack: sumBy(Object.values(bySeverity), (x) => x.onTrack),
    dueSoon: sumBy(Object.values(bySeverity), (x) => x.dueSoon),
    breached: sumBy(Object.values(bySeverity), (x) => x.breached),
  };
  return { closed, open: { bySeverity, total } };
}

/** R-6 including the oldest ten (titles are the redacted strings the Findings list shows). @param {any} raw @param {Date} now */
export function toAgingDto(raw, now) {
  return {
    buckets: ["0-7", "8-30", "31-90", "90+"].map((bucket) => {
      const by = zeroed(FINDING_SEVERITIES);
      for (const r of raw.buckets) if (r.bucket === bucket) by[r.severity] += r.n;
      return { bucket, bySeverity: by };
    }),
    oldest: raw.oldest.slice(0, REPORTING_LIMITS.agingOldestLimit).map((r) => ({
      id: r.id,
      title: r.title,
      severity: r.severity,
      ageDays: Math.max(0, Math.floor((now.getTime() - r.firstDetectedAt.getTime()) / 86_400_000)),
      repositoryName: r.repositoryName,
    })),
  };
}

/** S-1 to S-3, S-6, S-7. @param {any} raw @param {import("@qmentisai/shared").ResolvedPeriod} p */
export function toScanActivityDto(raw, p) {
  const byDay = new Map(raw.perDay.map((d) => [d.day, d]));
  const perDay = listDays(p.from, p.to).map((day) => {
    const d = byDay.get(day);
    return {
      day,
      total: d?.total ?? 0,
      byStatus: d ? d.byStatus : zeroed(REPORT_EXECUTION_STATUSES),
    };
  });
  const status = (s) => sumBy(raw.perDay, (d) => d.byStatus[s]);
  const denominator =
    status("succeeded") + status("failed") + status("partial") + status("timed_out");
  return {
    period: toPeriod(p),
    perDay,
    successRate: {
      numerator: status("succeeded"),
      denominator,
      rate: denominator > 0 ? status("succeeded") / denominator : null,
    },
    duration: raw.duration,
    queueWait: raw.queueWait,
    completeness: {
      complete: sumBy(raw.perDay, (d) => d.resultComplete),
      incomplete: sumBy(raw.perDay, (d) => d.resultPartial),
    },
    ingestionEligibleShare: {
      eligible: sumBy(raw.perDay, (d) => d.eligible),
      total: sumBy(raw.perDay, (d) => d.total),
    },
  };
}

/**
 * S-4 and S-5 with reasons, as OBSERVED in the executions and SBOM views (no configuration view exists).
 * @param {{ repositories: any[], pipelines: any[] }} raw
 */
export function toCoverageDto(raw) {
  const reasonOf = (r) =>
    r.livePipelines === 0
      ? "no_pipeline"
      : !r.recentSuccess
        ? "no_recent_scan"
        : r.lastIncomplete
          ? "last_scan_partial"
          : null;
  const uncovered = raw.repositories
    .map((r) => ({
      repositoryId: r.repositoryId,
      repositoryName: r.repositoryName,
      reason: reasonOf(r),
    }))
    .filter((r) => r.reason !== null);
  return {
    repositories: {
      covered: raw.repositories.length - uncovered.length,
      total: raw.repositories.length,
    },
    uncovered: uncovered.slice(0, 500),
    pipelines: raw.pipelines.slice(0, 500).map((p) => ({
      pipelineId: p.pipelineId,
      pipelineName: p.pipelineName,
      repositoryId: p.repositoryId,
      scanTypes: [
        {
          type: "sbom",
          enabled: p.sbomCompleteness !== null,
          lastComplete: p.sbomCompleteness === null ? null : p.sbomCompleteness === "complete",
        },
        ...["sca", "sast", "secrets"].map((type) => ({
          type,
          enabled: p.findingTypes.includes(type),
          lastComplete: null,
        })),
      ],
    })),
  };
}

/** S-8. @param {any} raw */
export const toSbomDto = (raw) => ({
  components: raw.components,
  vulnerable: raw.vulnerable,
  byEcosystem: raw.byEcosystem,
  trend: raw.trend,
});

/** Q-1 to Q-6 with the minimum sample rule. @param {any} raw @param {import("@qmentisai/shared").ResolvedPeriod} p */
export function toQualityDto(raw, p) {
  const types = raw.byType;
  const total = (f) => sumBy(types, f);
  const byTypeRate = Object.fromEntries(
    FINDING_SCAN_TYPES.map((t) => {
      const r = types.find((x) => x.scanType === t);
      return [t, toRate(r?.fp ?? 0, (r?.fp ?? 0) + (r?.tp ?? 0))];
    }),
  );
  const m = {
    advisoryFpHumanFp: total((r) => r.advisoryFpHumanFp),
    advisoryTpHumanTp: total((r) => r.advisoryTpHumanTp),
    advisoryFpHumanTp: total((r) => r.advisoryFpHumanTp),
    advisoryTpHumanFp: total((r) => r.advisoryTpHumanFp),
    advisoryUncertain: total((r) => r.advisoryUncertain),
  };
  const agreed = m.advisoryFpHumanFp + m.advisoryTpHumanTp;
  const decided = agreed + m.advisoryFpHumanTp + m.advisoryTpHumanFp;
  const tooFew = decided < REPORTING_LIMITS.minDecisionsForRate;
  return {
    period: toPeriod(p),
    falsePositiveRate: {
      overall: toRate(
        total((r) => r.fp),
        total((r) => r.fp) + total((r) => r.tp),
      ),
      byType: byTypeRate,
    },
    noisyRules: raw.noisyRules,
    advisoryCoverage: toRate(
      total((r) => r.withAdvisory),
      total((r) => r.eligible),
    ),
    advisoryAgreement: {
      agreed,
      decided,
      rate: tooFew || decided === 0 ? null : agreed / decided,
      tooFew,
      matrix: m,
    },
    humanOverrideRate: toRate(
      total((r) => r.overridden),
      total((r) => r.confident),
    ),
    advisoryOutcomes: raw.advisoryOutcomes,
  };
}

/** B-2, B-3, B-5 (the signed cursor is added by the service). @param {{ items: any[] }} raw @param {string} by */
export function toBreakdownItems(raw, by) {
  return raw.items.map((r) => ({
    key: r.key,
    label: r.label,
    ...(by === "pipeline" ? { deleted: r.deleted } : {}),
    open: r.open,
    bySeverity: r.bySeverity,
    slaBreached: r.slaBreached,
    share: r.share,
    ...(by === "repository" || by === "pipeline" ? { lastScan: r.lastScan ?? null } : {}),
  }));
}

/** B-4. @param {any[]} rows */
export const toTopRiskItems = (rows) =>
  rows.map((r) => ({
    repositoryId: r.repositoryId,
    repositoryName: r.repositoryName,
    score: r.score,
    critical: r.critical,
    high: r.high,
    medium: r.medium,
    low: r.low,
    breachedCriticalHigh: r.breachedCriticalHigh,
  }));

/** B-6 (no e-mail; display names only). @param {{ assignees: any[], unassigned: number }} raw */
export const toWorkloadDto = (raw) => ({
  assignees: raw.assignees.map((a) => ({
    user: { id: a.userId, displayName: a.displayName ?? "Unknown user" },
    open: a.open,
    dueSoon: a.dueSoon,
    breached: a.breached,
  })),
  unassigned: raw.unassigned,
});
