import {
  LIFECYCLE_GROUPS,
  REPORTING_LIMITS,
  RISK_FORMULA_TEXT,
  compareTopRisk,
  computeRiskScore,
  deriveSlaState,
  listDays,
} from "@qmentisai/shared";
import {
  PDF_COLORS,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  SEVERITY_PATTERN,
  formatDays,
  formatInt,
} from "./pdf-kit.js";

/**
 * The template builders (docs/modules/reporting-dashboards/SPEC.md 7.3): for each v1 template the CSV records and the PDF sections. The data
 * comes ONLY from the datasets of the export repository (`readExportPage`), which read the `report_*_v` views; nothing here touches a
 * source table, a rollup table or Part B's code. The definitions are those of SPEC 5 and 6 (they live in the datasets' SQL).
 */

const PAGE_SIZE_FINDINGS = 10000;
const PAGE_SIZE_GROUPS = 10000;
/** The longest list a PDF prints; the rest is counted ("N more not shown"). */
const PDF_LIST_LIMIT = 500;

/**
 * The reads a builder may make. `base` carries the tenant, workspace, period and options of the report row.
 * @typedef {object} ExportSource
 * @property {(dataset: string, pageSize?: number) => AsyncGenerator<Record<string, any>>} stream every row of a dataset, page by page
 * @property {(dataset: string) => Promise<Array<Record<string, any>>>} all every row of a single (small) dataset
 * @property {{ from: string | null, to: string | null, asOfDay: string | null, timeZone: string, now: Date, distinct: boolean }} view
 */

/** @param {unknown} v */
const n = (v) => (typeof v === "number" ? v : v === null || v === undefined ? 0 : Number(v));
/** @param {number | null | undefined} v @param {number} [d] */
const round = (v, d = 2) =>
  v === null || v === undefined || !Number.isFinite(v) ? null : Math.round(v * 10 ** d) / 10 ** d;
/** @param {Record<string, any>} r */
const pipelineName = (r) => (r.pipeline_deleted ? `${r.pipeline_name} (deleted)` : r.pipeline_name);
const severityBars = (rows) =>
  [...SEVERITY_ORDER, "unknown"]
    .filter((s) => s !== "unknown" || rows.some((r) => r.severity === "unknown" && n(r.n) > 0))
    .map((s) => ({
      label: SEVERITY_LABEL[s],
      value: n(rows.find((r) => r.severity === s)?.n),
      color: PDF_COLORS[s],
      pattern: SEVERITY_PATTERN[s],
    }));

// ------------------------------------------------------------------------------------------------------------------------------------
// CSV records (one object per row, keyed by the template's column keys)
// ------------------------------------------------------------------------------------------------------------------------------------

/** @type {Record<string, (source: ExportSource) => AsyncGenerator<Record<string, unknown>>>} */
export const CSV_RECORDS = {
  async *findings_by_pipeline(source) {
    const { now } = source.view;
    for await (const r of source.stream("csv", PAGE_SIZE_FINDINGS)) {
      const first = r.first_detected_at ? new Date(r.first_detected_at) : null;
      yield {
        id: r.id,
        title: r.title,
        scan_type: r.scan_type,
        severity: r.severity,
        status: r.status,
        repository: r.repository_name,
        pipeline: pipelineName(r),
        path: r.path,
        start_line: r.start_line,
        rule_id: r.rule_id,
        first_detected_at: first,
        age_days: first
          ? Math.max(0, Math.floor((now.getTime() - first.getTime()) / 86400000))
          : null,
        sla_state: deriveSlaState({ startedAt: r.sla_started_at, dueAt: r.sla_due_at, now }),
        sla_due_at: r.sla_due_at ? new Date(r.sla_due_at) : null,
        assignee: r.assignee_display_name,
      };
    }
  },
  async *sla_compliance(source) {
    for await (const r of source.stream("csv", PAGE_SIZE_GROUPS))
      yield {
        repository: r.repository_name,
        severity: r.severity,
        sla_state: r.sla_state,
        open_count: r.open_count,
        fixed_in_period: r.fixed_in_period,
        fixed_within_sla: r.fixed_within_sla,
      };
  },
  async *remediation_performance(source) {
    for await (const r of source.stream("csv", PAGE_SIZE_GROUPS))
      yield {
        severity: r.severity,
        scan_type: r.scan_type,
        fixed_count: r.count,
        median_days: round(r.median_days),
        p90_days: round(r.p90_days),
        mean_days: round(r.mean_days),
      };
  },
  async *sbom_inventory(source) {
    for await (const r of source.stream("csv", PAGE_SIZE_GROUPS))
      yield {
        component: r.component_purl,
        version: r.component_version,
        ecosystem: r.ecosystem,
        repository: r.repository_name,
        pipeline: r.pipeline_name,
        vulnerable: r.vulnerable === true,
      };
  },
  async *point_in_time_snapshot(source) {
    for await (const r of source.stream("csv", PAGE_SIZE_GROUPS))
      yield {
        day: source.view.asOfDay,
        repository: r.repository_name,
        scan_type: r.scan_type,
        severity: r.severity,
        open_count: r.open_count,
      };
  },
};

// ------------------------------------------------------------------------------------------------------------------------------------
// PDF sections
// ------------------------------------------------------------------------------------------------------------------------------------

const SLA_STATE_LABEL = { on_track: "On track", due_soon: "Due soon", breached: "Breached" };
const SLA_SERIES = [
  { label: "On track", color: PDF_COLORS.series3, pattern: "dots" },
  { label: "Due soon", color: PDF_COLORS.series2, pattern: "diagonal" },
  { label: "Breached", color: PDF_COLORS.series1, pattern: "solid" },
];

/** SLA state counts per severity as a stacked bar block. @param {any} kit @param {Array<Record<string, any>>} rows */
function slaOpenChart(kit, rows) {
  const categories = SEVERITY_ORDER.filter((s) => s !== "info").map((s) => ({
    label: SEVERITY_LABEL[s],
    values: ["on_track", "due_soon", "breached"].map((state) =>
      n(rows.find((r) => r.severity === s && r.sla_state === state)?.n),
    ),
  }));
  kit.stackedBars({ title: "Open findings by SLA state", categories, series: SLA_SERIES });
}

/** @param {any} kit @param {Array<Record<string, any>>} rows the `closed` dataset */
function slaClosedTable(kit, rows) {
  kit.table({
    columns: [
      { key: "severity", header: "Severity", width: 3 },
      { key: "fixed", header: "Fixed in period", width: 3, align: "right" },
      { key: "within", header: "Fixed within SLA", width: 3, align: "right" },
      { key: "share", header: "Share within SLA", width: 3, align: "right" },
    ],
    rows: SEVERITY_ORDER.filter((s) => s !== "info").map((s) => {
      const r = rows.find((x) => x.severity === s);
      const fixed = n(r?.fixed);
      return {
        severity: SEVERITY_LABEL[s],
        fixed: formatInt(fixed),
        within: formatInt(n(r?.within_sla)),
        share: fixed === 0 ? "no fixes" : `${Math.round((n(r?.within_sla) / fixed) * 100)}%`,
      };
    }),
  });
}

/** Burn-down: the open findings per day, stacked by the open lifecycle groups. @param {any} kit @param {string[]} days @param {Array<Record<string, any>>} rows */
function burnDown(kit, days, rows) {
  const groups = LIFECYCLE_GROUPS.filter((g) => g.open);
  const palette = [PDF_COLORS.series1, PDF_COLORS.series2, PDF_COLORS.series3, PDF_COLORS.series4];
  const patterns = ["solid", "diagonal", "dots", "horizontal"];
  const series = groups.map((g, i) => ({
    label: g.label,
    color: palette[i],
    pattern: patterns[i],
    values: days.map((d) =>
      rows
        .filter((r) => r.day === d && g.statuses.includes(r.status))
        .reduce((s, r) => s + n(r.n), 0),
    ),
  }));
  kit.stackedArea({ title: "Open findings per day, by lifecycle group", days, series });
}

/** @type {Record<string, (kit: any, source: ExportSource) => Promise<void>>} */
export const PDF_SECTIONS = {
  // ---------------------------------------------------------------- Executive security summary
  async executive_summary(kit, source) {
    const [bySeverity, ttr, slaOpen, slaClosed, risk, coverage] = await Promise.all([
      source.all("open_by_severity"),
      source.all("ttr_overall"),
      source.all("sla_open"),
      source.all("sla_closed"),
      source.all("risk_inputs"),
      source.all("coverage"),
    ]);
    const open = bySeverity.reduce((s, r) => s + n(r.n), 0);
    const criticalHigh =
      n(bySeverity.find((r) => r.severity === "critical")?.n) +
      n(bySeverity.find((r) => r.severity === "high")?.n);
    const breached = slaOpen
      .filter((r) => r.sla_state === "breached")
      .reduce((s, r) => s + n(r.n), 0);
    const t = ttr[0] ?? {};
    kit.heading("Key figures");
    kit.kpis([
      {
        label: "Open findings",
        value: formatInt(open),
        note: source.view.distinct ? "distinct issues" : "findings, per pipeline",
      },
      { label: "Critical and high open", value: formatInt(criticalHigh) },
      {
        label: "Median days to remediate",
        value: formatDays(t.median_days),
        note: `n = ${formatInt(n(t.count))} fixed in period`,
      },
      { label: "SLA breached (open)", value: formatInt(breached) },
    ]);
    kit.barChart({ title: "Open findings by severity", bars: severityBars(bySeverity) });

    kit.heading("Backlog burn-down");
    const days = listDays(
      /** @type {string} */ (source.view.from),
      /** @type {string} */ (source.view.to),
    );
    burnDown(kit, days, await source.all("burn_down"));
    kit.paragraph(
      "Open findings at the end of each day (tenant time zone), rebuilt from the status history.",
      { muted: true, size: 8 },
    );

    kit.heading("Top risky repositories");
    const ranked = risk
      .map((r) => ({
        name: r.repository_name,
        score: computeRiskScore({
          critical: n(r.critical),
          high: n(r.high),
          medium: n(r.medium),
          low: n(r.low),
          breachedCriticalHigh: n(r.breached_critical_high),
        }),
        oldestOpenCriticalAt: r.oldest_open_critical_at,
        r,
      }))
      .sort(compareTopRisk)
      .slice(0, 5);
    kit.table({
      columns: [
        { key: "name", header: "Repository", width: 6 },
        { key: "score", header: "Risk points", width: 2, align: "right" },
        { key: "critical", header: "Critical", width: 2, align: "right" },
        { key: "high", header: "High", width: 2, align: "right" },
        { key: "breached", header: "Breached C/H", width: 2, align: "right" },
      ],
      rows: ranked.map((x) => ({
        name: x.name,
        score: formatInt(x.score),
        critical: formatInt(n(x.r.critical)),
        high: formatInt(n(x.r.high)),
        breached: formatInt(n(x.r.breached_critical_high)),
      })),
      emptyText: "No open findings.",
    });
    kit.paragraph(`Risk points are not a probability. ${RISK_FORMULA_TEXT}.`, {
      muted: true,
      size: 8,
    });

    kit.heading("SLA compliance");
    slaClosedTable(kit, slaClosed);
    slaOpenChart(kit, slaOpen);

    kit.heading("Scan coverage statement");
    const recent = coverage.filter((c) => c.scanned_recently === true);
    const rest = coverage.filter((c) => c.scanned_recently !== true);
    kit.paragraph(
      `${formatInt(recent.length)} of ${formatInt(coverage.length)} repositories with at least one scan run had a succeeded scan in the last 30 days.`,
    );
    if (rest.length > 0)
      kit.table({
        columns: [
          { key: "name", header: "Repository without a recent succeeded scan", width: 6 },
          { key: "reason", header: "Reason", width: 3 },
        ],
        rows: rest.slice(0, 10).map((c) => ({
          name: c.repository_name,
          reason: c.last_status === "partial" ? "last scan partial" : "no recent succeeded scan",
        })),
      });
    if (rest.length > 10)
      kit.paragraph(`${formatInt(rest.length - 10)} more repositories are not listed.`, {
        muted: true,
        size: 8,
      });
    kit.paragraph(
      "Repositories that have never run a scan, and repositories without an enabled pipeline, are not part of this statement: reports read the scan history only.",
      { muted: true, size: 8 },
    );
  },

  // ---------------------------------------------------------------- Findings by pipeline
  async findings_by_pipeline(kit, source) {
    const [bySeverity, pipelines] = await Promise.all([
      source.all("by_severity"),
      source.all("by_pipeline"),
    ]);
    kit.heading("Open findings by severity");
    kit.barChart({ bars: severityBars(bySeverity) });
    kit.paragraph(
      `${formatInt(bySeverity.reduce((s, r) => s + n(r.n), 0))} open ${source.view.distinct ? "distinct issues" : "findings (a finding is counted once per pipeline)"}.`,
      { muted: true, size: 8 },
    );
    kit.heading("By pipeline");
    kit.table({
      columns: [
        { key: "repository", header: "Repository", width: 5 },
        { key: "pipeline", header: "Pipeline", width: 4 },
        { key: "critical", header: "Crit.", width: 1.4, align: "right" },
        { key: "high", header: "High", width: 1.4, align: "right" },
        { key: "medium", header: "Med.", width: 1.4, align: "right" },
        { key: "low", header: "Low", width: 1.4, align: "right" },
        { key: "open", header: "Open", width: 1.6, align: "right" },
        { key: "breached", header: "Breached", width: 1.8, align: "right" },
      ],
      rows: pipelines.slice(0, PDF_LIST_LIMIT).map((r) => ({
        repository: r.repository_name,
        pipeline: pipelineName(r),
        critical: n(r.critical),
        high: n(r.high),
        medium: n(r.medium),
        low: n(r.low),
        open: n(r.open),
        breached: n(r.breached),
      })),
      emptyText: "No open findings.",
    });
    if (pipelines.length > PDF_LIST_LIMIT)
      kit.paragraph(
        `${formatInt(pipelines.length - PDF_LIST_LIMIT)} more pipelines are not shown; export the CSV for every finding.`,
        { muted: true, size: 8 },
      );
  },

  // ---------------------------------------------------------------- SLA compliance
  async sla_compliance(kit, source) {
    const [closed, open, breached] = await Promise.all([
      source.all("closed"),
      source.all("open"),
      source.all("breached"),
    ]);
    kit.heading("Closed in the period");
    slaClosedTable(kit, closed);
    kit.heading("Open, by SLA state");
    slaOpenChart(kit, open);
    kit.table({
      columns: [
        { key: "severity", header: "Severity", width: 3 },
        { key: "on_track", header: SLA_STATE_LABEL.on_track, width: 2, align: "right" },
        { key: "due_soon", header: SLA_STATE_LABEL.due_soon, width: 2, align: "right" },
        { key: "breached", header: SLA_STATE_LABEL.breached, width: 2, align: "right" },
      ],
      rows: SEVERITY_ORDER.filter((s) => s !== "info").map((s) => ({
        severity: SEVERITY_LABEL[s],
        on_track: formatInt(n(open.find((r) => r.severity === s && r.sla_state === "on_track")?.n)),
        due_soon: formatInt(n(open.find((r) => r.severity === s && r.sla_state === "due_soon")?.n)),
        breached: formatInt(n(open.find((r) => r.severity === s && r.sla_state === "breached")?.n)),
      })),
    });
    kit.heading("Breached findings (oldest deadline first)");
    kit.table({
      columns: [
        { key: "severity", header: "Severity", width: 2 },
        { key: "title", header: "Title", width: 6 },
        { key: "repository", header: "Repository", width: 4 },
        { key: "pipeline", header: "Pipeline", width: 3 },
        { key: "due", header: "Was due", width: 3 },
      ],
      rows: breached.slice(0, 100).map((r) => ({
        severity: SEVERITY_LABEL[r.severity] ?? r.severity,
        title: r.title,
        repository: r.repository_name,
        pipeline: r.pipeline_name,
        due: r.sla_due_at ? new Date(r.sla_due_at).toISOString().slice(0, 10) : "",
      })),
      emptyText: "No breached findings.",
    });
    if (breached.length > 100)
      kit.paragraph(
        "More breached findings exist than the 100 listed; export the CSV for the counts per repository.",
        { muted: true, size: 8 },
      );
  },

  // ---------------------------------------------------------------- Remediation performance
  async remediation_performance(kit, source) {
    const [ttr, first, verification, velocity] = await Promise.all([
      source.all("ttr"),
      source.all("first_decision"),
      source.all("verification"),
      source.all("velocity"),
    ]);
    kit.heading("Time to remediate");
    const row = (label, r) => ({
      label,
      count: formatInt(n(r?.count)),
      median: formatDays(r?.median_days),
      p90: formatDays(r?.p90_days),
      mean: formatDays(r?.mean_days),
      reopened: formatInt(n(r?.reopened_then_fixed)),
    });
    kit.table({
      columns: [
        { key: "label", header: "Severity", width: 3 },
        { key: "count", header: "Fixed", width: 2, align: "right" },
        { key: "median", header: "Median days", width: 2.5, align: "right" },
        { key: "p90", header: "p90 days", width: 2.5, align: "right" },
        { key: "mean", header: "Mean days", width: 2.5, align: "right" },
        { key: "reopened", header: "Reopened, then fixed", width: 3.5, align: "right" },
      ],
      rows: [
        row(
          "All",
          ttr.find((r) => r.severity === null || r.severity === undefined),
        ),
        ...SEVERITY_ORDER.map((s) =>
          row(
            SEVERITY_LABEL[s],
            ttr.find((r) => r.severity === s),
          ),
        ),
      ],
    });
    kit.paragraph(
      "Days from first detection to the confirming scan, for findings fixed in the period. Median is the primary figure.",
      { muted: true, size: 8 },
    );

    kit.heading("Time to first decision");
    kit.table({
      columns: [
        { key: "type", header: "Scan type", width: 3 },
        { key: "count", header: "Decided", width: 2, align: "right" },
        { key: "median", header: "Median days", width: 2.5, align: "right" },
        { key: "p90", header: "p90 days", width: 2.5, align: "right" },
      ],
      rows: first.map((r) => ({
        type: r.scan_type,
        count: formatInt(n(r.count)),
        median: formatDays(r.median_days),
        p90: formatDays(r.p90_days),
      })),
      emptyText: "No first decisions in the period.",
    });

    kit.heading("Verification lag");
    const v = verification[0] ?? {};
    kit.paragraph(
      n(v.count) === 0
        ? "No verified fixes with a claimed fix in the period."
        : `Median ${formatDays(v.median_days)} days between a claimed fix and the confirming scan (n = ${formatInt(n(v.count))}).`,
    );

    kit.heading("Velocity and reopen rate");
    kit.barChart({
      title: "Fixed per week",
      bars: velocity.map((w) => ({
        label: w.week,
        value: n(w.fixed_count),
        color: PDF_COLORS.series1,
        pattern: "solid",
      })),
    });
    const fixed = velocity.reduce((s, w) => s + n(w.fixed_count), 0);
    const reopened = velocity.reduce((s, w) => s + n(w.reopened_count), 0);
    kit.table({
      columns: [
        { key: "week", header: "Week starting", width: 3 },
        { key: "new", header: "New", width: 2, align: "right" },
        { key: "fixed", header: "Fixed", width: 2, align: "right" },
        { key: "closed", header: "Closed without fix", width: 3, align: "right" },
        { key: "reopened", header: "Reopened", width: 2, align: "right" },
      ],
      rows: velocity.map((w) => ({
        week: w.week,
        new: n(w.new_count),
        fixed: n(w.fixed_count),
        closed: n(w.closed_other_count),
        reopened: n(w.reopened_count),
      })),
    });
    kit.paragraph(
      fixed === 0
        ? "Reopen rate: no fixes in the period."
        : `Reopen rate: ${reopened} reopened for ${fixed} fixed (${Math.round((reopened / fixed) * 100)}%).`,
    );
  },

  // ---------------------------------------------------------------- Detection quality
  async detection_quality(kit, source) {
    const min = REPORTING_LIMITS.minDecisionsForRate;
    const [fp, noisy, advisory, coverage] = await Promise.all([
      source.all("fp_rate"),
      source.all("noisy_rules"),
      source.all("advisory"),
      source.all("advisory_coverage"),
    ]);
    kit.heading("False-positive rate");
    kit.table({
      columns: [
        { key: "type", header: "Scan type", width: 3 },
        { key: "tp", header: "True positive", width: 2.5, align: "right" },
        { key: "fp", header: "False positive", width: 2.5, align: "right" },
        { key: "rate", header: "False-positive rate", width: 5, align: "right" },
      ],
      rows: fp.map((r) => {
        const total = n(r.tp) + n(r.fp);
        return {
          type: r.scan_type,
          tp: n(r.tp),
          fp: n(r.fp),
          rate:
            total < min
              ? `n = ${total}, too few to rate`
              : `${Math.round((n(r.fp) / total) * 100)}% (n = ${total})`,
        };
      }),
      emptyText: "No approved decisions in the period.",
    });
    kit.paragraph(`A rate over fewer than ${min} decisions is not shown as a percentage.`, {
      muted: true,
      size: 8,
    });

    kit.heading("Noisiest rules");
    kit.table({
      columns: [
        { key: "rule", header: "Rule", width: 6, mono: true },
        { key: "type", header: "Type", width: 2 },
        { key: "n", header: "Decisions", width: 2, align: "right" },
        { key: "share", header: "False-positive share", width: 3.5, align: "right" },
      ],
      rows: noisy.map((r) => ({
        rule: r.rule_id,
        type: r.scan_type,
        n: n(r.n),
        share: `${Math.round((n(r.fp) / n(r.n)) * 100)}%`,
      })),
      emptyText: `No rule has ${min} or more decisions in the period.`,
    });

    kit.heading("Advice versus human decision");
    const total = advisory.reduce((s, r) => s + n(r.n), 0);
    const matches = advisory
      .filter(
        (r) =>
          (r.suggestion === "likely_false_positive" && r.decision === "false_positive") ||
          (r.suggestion === "likely_true_positive" && r.decision === "true_positive"),
      )
      .reduce((s, r) => s + n(r.n), 0);
    const confident = advisory.filter(
      (r) => r.high_confidence === true && r.suggestion !== "uncertain",
    );
    const overridden = confident
      .filter(
        (r) =>
          (r.suggestion === "likely_false_positive" && r.decision === "true_positive") ||
          (r.suggestion === "likely_true_positive" && r.decision === "false_positive"),
      )
      .reduce((s, r) => s + n(r.n), 0);
    const cell = (suggestion, decision) =>
      formatInt(
        advisory
          .filter((r) => r.suggestion === suggestion && r.decision === decision)
          .reduce((s, r) => s + n(r.n), 0),
      );
    kit.table({
      columns: [
        { key: "advice", header: "Advice", width: 4 },
        { key: "tp", header: "Human: true positive", width: 3, align: "right" },
        { key: "fp", header: "Human: false positive", width: 3, align: "right" },
      ],
      rows: ["likely_true_positive", "likely_false_positive", "uncertain"].map((s) => ({
        advice: s.replaceAll("_", " "),
        tp: cell(s, "true_positive"),
        fp: cell(s, "false_positive"),
      })),
      emptyText: "No decision had an advisory.",
    });
    kit.paragraph(
      total < min
        ? `Agreement: n = ${total}, too few to rate.`
        : `Agreement between advice and the human decision: ${Math.round((matches / total) * 100)}% (n = ${total}). This compares advice with a human decision; it is not an accuracy figure.`,
    );
    kit.paragraph(
      confident.reduce((s, r) => s + n(r.n), 0) < min
        ? `Human override of a confident advisory: n = ${confident.reduce((s, r) => s + n(r.n), 0)}, too few to rate.`
        : `Human override of a confident advisory (confidence 80 or more): ${Math.round((overridden / confident.reduce((s, r) => s + n(r.n), 0)) * 100)}%.`,
    );
    const c = coverage[0] ?? {};
    kit.paragraph(
      n(c.eligible) < min
        ? `Advisory coverage: n = ${n(c.eligible)}, too few to rate.`
        : `Advisory coverage: ${Math.round((n(c.with_advisory) / n(c.eligible)) * 100)}% of ${formatInt(n(c.eligible))} decisions on code and component findings had an advisory at decision time.`,
    );
  },

  // ---------------------------------------------------------------- Point-in-time snapshot
  async point_in_time_snapshot(kit, source) {
    const [bySeverity, byType, byStatus, byRepository] = await Promise.all([
      source.all("by_severity"),
      source.all("by_type"),
      source.all("by_status"),
      source.all("by_repository"),
    ]);
    kit.heading(`Posture at the end of ${source.view.asOfDay}`);
    kit.kpis([
      {
        label: "Open findings",
        value: formatInt(bySeverity.reduce((s, r) => s + n(r.n), 0)),
        note: `as of ${source.view.asOfDay}, ${source.view.timeZone}`,
      },
    ]);
    kit.barChart({ title: "Open findings by severity", bars: severityBars(bySeverity) });
    if (bySeverity.some((r) => r.severity === "unknown" && n(r.n) > 0))
      kit.paragraph(
        "Unknown: the severity of these findings was changed after this day and the original is not recorded in the reporting views.",
        { muted: true, size: 8 },
      );
    kit.table({
      columns: [
        { key: "key", header: "Scan type", width: 4 },
        { key: "n", header: "Open", width: 2, align: "right" },
      ],
      rows: byType.map((r) => ({ key: r.scan_type, n: n(r.n) })),
      emptyText: "No open findings on this day.",
    });
    kit.table({
      columns: [
        { key: "key", header: "Status", width: 4 },
        { key: "n", header: "Open", width: 2, align: "right" },
      ],
      rows: byStatus.map((r) => ({ key: r.status.replaceAll("_", " "), n: n(r.n) })),
      emptyText: "No open findings on this day.",
    });
    kit.heading("By repository");
    kit.table({
      columns: [
        { key: "repository", header: "Repository", width: 6 },
        { key: "critical", header: "Crit.", width: 1.4, align: "right" },
        { key: "high", header: "High", width: 1.4, align: "right" },
        { key: "medium", header: "Med.", width: 1.4, align: "right" },
        { key: "low", header: "Low", width: 1.4, align: "right" },
        { key: "open", header: "Open", width: 1.6, align: "right" },
      ],
      rows: byRepository.slice(0, PDF_LIST_LIMIT).map((r) => ({
        repository: r.repository_name,
        critical: n(r.critical),
        high: n(r.high),
        medium: n(r.medium),
        low: n(r.low),
        open: n(r.open),
      })),
      emptyText: "No open findings on this day.",
    });
    if (byRepository.length > PDF_LIST_LIMIT)
      kit.paragraph(
        `${formatInt(byRepository.length - PDF_LIST_LIMIT)} more repositories are not shown; export the CSV for every row.`,
        { muted: true, size: 8 },
      );
  },
};
