import { Prisma } from "@prisma/client";
import {
  FLOW_CLOSED_OTHER_TO_STATUSES,
  FLOW_FIXED_TO_STATUSES,
  FLOW_REOPENED_TO_STATUSES,
  OPEN_FINDING_STATUSES,
  REPORTING_LIMITS,
  SLA_DUE_SOON_FRACTION,
  addDays,
  dayCloseInstant,
  dayStartInstant,
  listDays,
} from "@qmentisai/shared";

/**
 * The datasets of the report templates (docs/modules/reporting-dashboards/SPEC.md 7.3, 5, 6): every one is a read of the `report_*_v` VIEWS
 * through the worker role, which cannot read anything else (evidence, rationales, comments, advisory reasoning, justifications, secret
 * previews and e-mail addresses are not columns of any view). The definitions follow SPEC 5 and 6: open = the eight open statuses
 * (imported, never redefined), fixed = `verified_fixed`, the SLA state is derived from `sla_due_at` and now (SL-3), median and p90 are
 * `percentile_cont`. NOTHING here depends on the rollup tables (Part A): the point-in-time snapshot and the burn-down are rebuilt from the
 * immutable status history (`report_status_events_v`) and the decision timeline (`report_decisions_v`) with the same "latest history row
 * at or before T" rule the rollup uses.
 *
 * A dataset is either KEYED (a large, paged result: findings rows, SBOM components, grouped CSV rows; every row carries a unique `k` and
 * the page is "the rows after `k`") or a SINGLE read (a small aggregate, capped). Memory of the export is bounded by the page size.
 */

const S = Prisma.sql;
const raw = Prisma.raw;
const NONE = Prisma.empty;

/** The largest result of a single (unkeyed) dataset. */
const SINGLE_LIMIT = 20000;

/**
 * @typedef {object} DatasetContext
 * @property {string} tenantId
 * @property {string | null} workspaceId
 * @property {Record<string, any>} params validated options (`distinctIssues`, `includeAssignee`) plus the worker's `dataset` and `now`
 * @property {string} timeZone
 * @property {string | null} from first tenant-local day of the period
 * @property {string | null} to last tenant-local day of the period
 * @property {string | null} asOfDay
 * @property {Date | null} start instant of `from` 00:00 local
 * @property {Date | null} endExclusive instant of the day after `to` 00:00 local
 * @property {Date | null} asOfAt the last millisecond of `asOfDay` (the `T` of the day close)
 * @property {Date} now
 * @property {boolean} distinct
 * @property {boolean} assignee
 */

/** @param {Record<string, any>} a the arguments of `countExportRows` or `readExportPage` @returns {DatasetContext} */
export function datasetContext(a) {
  const params = a.params ?? {};
  const from = a.periodFrom ?? null;
  const to = a.periodTo ?? null;
  const asOfDay = a.asOfDay ?? null;
  const timeZone = a.timeZone ?? "UTC";
  return {
    tenantId: a.tenantId,
    workspaceId: a.workspaceId ?? null,
    params,
    timeZone,
    from,
    to,
    asOfDay,
    start: from ? dayStartInstant(from, timeZone) : null,
    endExclusive: to ? dayStartInstant(addDays(to, 1), timeZone) : null,
    asOfAt: asOfDay ? dayCloseInstant(asOfDay, timeZone) : null,
    now: params.now ? new Date(params.now) : new Date(),
    distinct: params.distinctIssues === true,
    assignee: params.includeAssignee === true,
  };
}

/** The tenant and (optional) workspace scope of one view alias. @param {DatasetContext} c @param {string} a */
const scope = (c, a) =>
  S`${raw(a)}.tenant_id = ${c.tenantId}::uuid AND (${c.workspaceId}::uuid IS NULL OR ${raw(a)}.workspace_id = ${c.workspaceId}::uuid)`;

/** @param {string} a */
const isOpen = (a) => S`${raw(a)}.status::text = ANY(${[...OPEN_FINDING_STATUSES]}::text[])`;

/** The SLA state of a finding row now (the SQL twin of `deriveSlaState`, SL-3). @param {DatasetContext} c @param {string} a */
const slaState = (c, a) => S`(CASE
  WHEN ${raw(a)}.sla_due_at IS NULL OR ${raw(a)}.sla_started_at IS NULL THEN 'not_applicable'
  WHEN ${c.now}::timestamptz > ${raw(a)}.sla_due_at THEN 'breached'
  WHEN ${raw(a)}.sla_due_at > ${raw(a)}.sla_started_at
    AND (${raw(a)}.sla_due_at - ${c.now}::timestamptz) <= (${raw(a)}.sla_due_at - ${raw(a)}.sla_started_at) * ${SLA_DUE_SOON_FRACTION}::float8 THEN 'due_soon'
  ELSE 'on_track' END)`;

/** The open count expression (findings, or distinct issues when asked). @param {DatasetContext} c @param {string} a */
const countOpen = (c, a) =>
  c.distinct
    ? S`count(DISTINCT COALESCE(${raw(a)}.correlation_key, ${raw(a)}.id::text))`
    : S`count(*)`;

/** @param {DatasetContext} c */
const inPeriod = (c, column) =>
  S`${raw(column)} >= ${c.start}::timestamptz AND ${raw(column)} < ${c.endExclusive}::timestamptz`;

const sevCounts = (a = "f") => S`
  count(*) FILTER (WHERE ${raw(a)}.severity::text = 'critical')::int AS critical,
  count(*) FILTER (WHERE ${raw(a)}.severity::text = 'high')::int AS high,
  count(*) FILTER (WHERE ${raw(a)}.severity::text = 'medium')::int AS medium,
  count(*) FILTER (WHERE ${raw(a)}.severity::text = 'low')::int AS low,
  count(*) FILTER (WHERE ${raw(a)}.severity::text = 'info')::int AS info`;

/** The fixed-in-period findings (R-1): days from first detection to verification. @param {DatasetContext} c */
const fixedInPeriod = (c) => S`
  SELECT f.severity::text AS severity, f.severity_rank, f.scan_type::text AS scan_type, f.reopen_count,
         extract(epoch FROM (f.verified_at - f.first_detected_at)) / 86400.0 AS days
  FROM report_findings_v f
  WHERE ${scope(c, "f")} AND f.status::text = 'verified_fixed' AND f.verified_at IS NOT NULL AND ${inPeriod(c, "f.verified_at")}`;

const stats = S`count(*)::int AS count,
  percentile_cont(0.5) WITHIN GROUP (ORDER BY days)::float8 AS median_days,
  percentile_cont(0.9) WITHIN GROUP (ORDER BY days)::float8 AS p90_days,
  avg(days)::float8 AS mean_days`;

/**
 * The open findings as of `T` (the status history: the latest row at or before T) with the severity in force at T. The severity of
 * a finding changes only through an approved review (`severity_override`) or an approved or expired exception (`accepted_severity`); a
 * finding whose severity was changed ONLY AFTER T has no reconstructable original in the views, so it is counted as `unknown`.
 * @param {DatasetContext} c @param {Date} at
 */
const openAsOf = (c, at) => S`
  ev AS (
    SELECT h.tenant_id, h.finding_id, h.to_status::text AS status, h.created_at,
           lead(h.created_at) OVER (PARTITION BY h.finding_id ORDER BY h.created_at, h.rev) AS next_at
    FROM report_status_events_v h WHERE ${scope(c, "h")}
  ),
  st AS (
    SELECT ev.finding_id, ev.status FROM ev
    WHERE ev.created_at <= ${at}::timestamptz AND (ev.next_at IS NULL OR ev.next_at > ${at}::timestamptz)
  ),
  chg AS (
    SELECT d.finding_id, d.decided_at AS at, d.severity_override::text AS sev
    FROM report_decisions_v d
    WHERE ${scope(c, "d")} AND d.source = 'review' AND d.state = 'approved' AND d.severity_override IS NOT NULL AND d.decided_at IS NOT NULL
    UNION ALL
    SELECT d.finding_id, d.decided_at, d.accepted_severity::text
    FROM report_decisions_v d
    WHERE ${scope(c, "d")} AND d.source = 'exception' AND d.state IN ('approved', 'expired') AND d.accepted_severity IS NOT NULL AND d.decided_at IS NOT NULL
  ),
  sev_at AS (
    SELECT DISTINCT ON (chg.finding_id) chg.finding_id, chg.sev FROM chg
    WHERE chg.at <= ${at}::timestamptz ORDER BY chg.finding_id, chg.at DESC
  ),
  has_chg AS (SELECT DISTINCT chg.finding_id FROM chg),
  snap AS (
    SELECT f.id, f.correlation_key, f.repository_id, f.repository_name, f.scan_type::text AS scan_type, st.status,
           COALESCE(sa.sev, CASE WHEN hc.finding_id IS NOT NULL THEN 'unknown' ELSE f.severity::text END) AS severity
    FROM st
    JOIN report_findings_v f ON f.tenant_id = ${c.tenantId}::uuid AND f.id = st.finding_id AND ${scope(c, "f")}
    LEFT JOIN sev_at sa ON sa.finding_id = st.finding_id
    LEFT JOIN has_chg hc ON hc.finding_id = st.finding_id
    WHERE st.status = ANY(${[...OPEN_FINDING_STATUSES]}::text[])
  )`;

/**
 * Dataset name to its definition. `sql(c)` is the whole query; a KEYED dataset's query selects a unique `k` (type `keyType`) and is paged
 * by `k > after`; `limit` caps a single read.
 * @type {Record<string, Record<string, { keyType?: "uuid" | "text", sql: (c: DatasetContext) => Prisma.Sql }>>}
 */
export const DATASETS = {
  // ---------------------------------------------------------------- findings by pipeline (CSV, PDF)
  findings_by_pipeline: {
    csv: {
      keyType: "uuid",
      sql: (c) => S`
        SELECT f.id AS k, f.id, f.title, f.scan_type::text AS scan_type, f.severity::text AS severity, f.status::text AS status,
               f.repository_name, f.pipeline_name, f.pipeline_deleted, f.path, f.start_line, f.rule_id,
               f.first_detected_at, f.sla_started_at, f.sla_due_at,
               ${c.assignee ? S`f.assignee_display_name` : S`NULL::text`} AS assignee_display_name
        FROM report_findings_v f WHERE ${scope(c, "f")}`,
    },
    by_severity: {
      sql: (c) => S`
        SELECT f.severity::text AS severity, ${countOpen(c, "f")}::int AS n
        FROM report_findings_v f WHERE ${scope(c, "f")} AND ${isOpen("f")} GROUP BY 1`,
    },
    by_pipeline: {
      sql: (c) => S`
        SELECT f.repository_name, f.pipeline_name, f.pipeline_deleted, ${sevCounts("f")}, count(*)::int AS open,
               count(*) FILTER (WHERE ${slaState(c, "f")} = 'breached')::int AS breached
        FROM report_findings_v f WHERE ${scope(c, "f")} AND ${isOpen("f")}
        GROUP BY 1, 2, 3 ORDER BY open DESC, 1, 2 LIMIT ${SINGLE_LIMIT}`,
    },
  },

  // ---------------------------------------------------------------- SLA compliance (CSV, PDF)
  sla_compliance: {
    csv: {
      keyType: "text",
      sql: (c) => S`
        WITH base AS (
          SELECT f.*, ${slaState(c, "f")} AS sla_now FROM report_findings_v f
          WHERE ${scope(c, "f")} AND f.severity::text <> 'info'
        ), o AS (
          SELECT repository_name, severity::text AS severity, severity_rank, sla_now AS sla_state, count(*)::int AS open_count, 0 AS fixed_in_period, 0 AS fixed_within_sla
          FROM base b WHERE ${isOpen("b")} AND sla_now <> 'not_applicable' GROUP BY 1, 2, 3, 4
        ), cl AS (
          SELECT repository_name, severity::text AS severity, severity_rank, 'closed'::text AS sla_state, 0 AS open_count,
                 count(*)::int AS fixed_in_period, (count(*) FILTER (WHERE verified_at <= sla_due_at))::int AS fixed_within_sla
          FROM base b WHERE b.status::text = 'verified_fixed' AND b.verified_at IS NOT NULL AND b.sla_due_at IS NOT NULL AND ${inPeriod(c, "b.verified_at")}
          GROUP BY 1, 2, 3
        )
        SELECT (u.repository_name || chr(31) || (9 - u.severity_rank)::text || chr(31) || u.sla_state) AS k, u.*
        FROM (SELECT * FROM o UNION ALL SELECT * FROM cl) u`,
    },
    closed: {
      sql: (c) => S`
        SELECT f.severity::text AS severity, count(*)::int AS fixed, (count(*) FILTER (WHERE f.verified_at <= f.sla_due_at))::int AS within_sla
        FROM report_findings_v f
        WHERE ${scope(c, "f")} AND f.severity::text <> 'info' AND f.status::text = 'verified_fixed' AND f.verified_at IS NOT NULL
          AND f.sla_due_at IS NOT NULL AND ${inPeriod(c, "f.verified_at")}
        GROUP BY 1`,
    },
    open: {
      sql: (c) => S`
        SELECT x.severity, x.sla_state, count(*)::int AS n FROM (
          SELECT f.severity::text AS severity, ${slaState(c, "f")} AS sla_state
          FROM report_findings_v f WHERE ${scope(c, "f")} AND f.severity::text <> 'info' AND ${isOpen("f")}
        ) x WHERE x.sla_state <> 'not_applicable' GROUP BY 1, 2`,
    },
    breached: {
      sql: (c) => S`
        SELECT f.id, f.severity::text AS severity, f.repository_name, f.pipeline_name, f.title, f.first_detected_at, f.sla_due_at
        FROM report_findings_v f
        WHERE ${scope(c, "f")} AND f.severity::text <> 'info' AND ${isOpen("f")} AND ${slaState(c, "f")} = 'breached'
        ORDER BY f.sla_due_at ASC, f.id LIMIT 101`,
    },
  },

  // ---------------------------------------------------------------- remediation performance (CSV, PDF)
  remediation_performance: {
    csv: {
      keyType: "text",
      sql: (c) => S`
        SELECT ((9 - x.severity_rank)::text || chr(31) || x.scan_type) AS k, x.severity, x.scan_type, ${stats}
        FROM (${fixedInPeriod(c)}) x GROUP BY x.severity, x.severity_rank, x.scan_type`,
    },
    ttr: {
      sql: (c) => S`
        SELECT x.severity, x.severity_rank, ${stats}, (count(*) FILTER (WHERE x.reopen_count > 0))::int AS reopened_then_fixed
        FROM (${fixedInPeriod(c)}) x GROUP BY GROUPING SETS ((x.severity, x.severity_rank), ())`,
    },
    first_decision: {
      sql: (c) => S`
        SELECT f.scan_type::text AS scan_type, count(*)::int AS count,
               percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM (r.first_review - f.first_detected_at)) / 86400.0)::float8 AS median_days,
               percentile_cont(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM (r.first_review - f.first_detected_at)) / 86400.0)::float8 AS p90_days
        FROM (
          SELECT d.tenant_id, d.finding_id, min(d.created_at) AS first_review
          FROM report_decisions_v d WHERE ${scope(c, "d")} AND d.source = 'review' GROUP BY 1, 2
        ) r
        JOIN report_findings_v f ON f.tenant_id = r.tenant_id AND f.id = r.finding_id
        WHERE ${inPeriod(c, "r.first_review")} GROUP BY 1 ORDER BY 1`,
    },
    verification: {
      sql: (c) => S`
        SELECT count(*)::int AS count,
               percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM (f.verified_at - f.fix_claimed_at)) / 86400.0)::float8 AS median_days
        FROM report_findings_v f
        WHERE ${scope(c, "f")} AND f.status::text = 'verified_fixed' AND f.verified_at IS NOT NULL AND f.fix_claimed_at IS NOT NULL
          AND ${inPeriod(c, "f.verified_at")}`,
    },
    velocity: {
      sql: (c) => S`
        SELECT (date_trunc('week', h.created_at AT TIME ZONE ${c.timeZone}))::date::text AS week,
               (count(*) FILTER (WHERE h.from_status IS NULL))::int AS new_count,
               (count(*) FILTER (WHERE h.to_status::text = ANY(${[...FLOW_FIXED_TO_STATUSES]}::text[])))::int AS fixed_count,
               (count(*) FILTER (WHERE h.to_status::text = ANY(${[...FLOW_CLOSED_OTHER_TO_STATUSES]}::text[])))::int AS closed_other_count,
               (count(*) FILTER (WHERE h.to_status::text = ANY(${[...FLOW_REOPENED_TO_STATUSES]}::text[])))::int AS reopened_count
        FROM report_status_events_v h WHERE ${scope(c, "h")} AND ${inPeriod(c, "h.created_at")} GROUP BY 1 ORDER BY 1`,
    },
  },

  // ---------------------------------------------------------------- SBOM inventory (CSV)
  sbom_inventory: {
    csv: {
      keyType: "text",
      sql: (c) => S`
        SELECT (s.pipeline_id::text || chr(31) || s.component_purl || chr(31) || COALESCE(s.component_version, '')) AS k,
               s.component_purl, s.component_version, s.ecosystem, s.repository_name, s.pipeline_name,
               EXISTS (
                 SELECT 1 FROM report_findings_v f
                 WHERE f.tenant_id = s.tenant_id AND f.pipeline_id = s.pipeline_id AND f.scan_type::text = 'sca'
                   AND f.component_purl = s.component_purl AND ${isOpen("f")}
               ) AS vulnerable
        FROM (
          SELECT DISTINCT v.tenant_id, v.pipeline_id, v.component_purl, v.component_version, v.ecosystem, v.repository_name, v.pipeline_name
          FROM report_sbom_latest_v v WHERE ${scope(c, "v")}
        ) s`,
    },
  },

  // ---------------------------------------------------------------- detection quality (PDF)
  detection_quality: {
    fp_rate: {
      sql: (c) => S`
        SELECT d.scan_type::text AS scan_type,
               (count(*) FILTER (WHERE d.decision = 'true_positive'))::int AS tp,
               (count(*) FILTER (WHERE d.decision = 'false_positive'))::int AS fp
        FROM report_decisions_v d
        WHERE ${scope(c, "d")} AND d.source = 'review' AND d.state = 'approved' AND d.decided_at IS NOT NULL AND ${inPeriod(c, "d.decided_at")}
        GROUP BY 1 ORDER BY 1`,
    },
    noisy_rules: {
      sql: (c) => S`
        SELECT d.rule_id, d.scan_type::text AS scan_type, count(*)::int AS n,
               (count(*) FILTER (WHERE d.decision = 'false_positive'))::int AS fp
        FROM report_decisions_v d
        WHERE ${scope(c, "d")} AND d.source = 'review' AND d.state = 'approved' AND d.decided_at IS NOT NULL AND ${inPeriod(c, "d.decided_at")}
        GROUP BY 1, 2 HAVING count(*) >= ${REPORTING_LIMITS.minDecisionsForRate}::int
        ORDER BY (count(*) FILTER (WHERE d.decision = 'false_positive'))::float8 / count(*) DESC, n DESC, 1 LIMIT 10`,
    },
    advisory: {
      sql: (c) => S`
        SELECT a.suggestion, d.decision, (COALESCE(a.confidence, 0) >= 80) AS high_confidence, count(*)::int AS n
        FROM report_decisions_v d
        JOIN report_advisories_v a ON a.tenant_id = d.tenant_id AND a.id = d.advisory_id_at_decision
        WHERE ${scope(c, "d")} AND d.source = 'review' AND d.state = 'approved' AND d.decided_at IS NOT NULL AND ${inPeriod(c, "d.decided_at")}
        GROUP BY 1, 2, 3`,
    },
    advisory_coverage: {
      sql: (c) => S`
        SELECT (count(*) FILTER (WHERE d.scan_type::text <> 'secrets'))::int AS eligible,
               (count(*) FILTER (WHERE d.scan_type::text <> 'secrets' AND d.advisory_id_at_decision IS NOT NULL))::int AS with_advisory
        FROM report_decisions_v d
        WHERE ${scope(c, "d")} AND d.source = 'review' AND d.state = 'approved' AND d.decided_at IS NOT NULL AND ${inPeriod(c, "d.decided_at")}`,
    },
  },

  // ---------------------------------------------------------------- point-in-time snapshot (CSV, PDF)
  point_in_time_snapshot: {
    csv: {
      keyType: "text",
      sql: (c) => S`
        WITH ${openAsOf(c, /** @type {Date} */ (c.asOfAt))}
        SELECT (s.repository_name || chr(31) || s.scan_type || chr(31) || s.severity) AS k,
               s.repository_name, s.scan_type, s.severity, count(*)::int AS open_count
        FROM snap s GROUP BY s.repository_name, s.scan_type, s.severity`,
    },
    by_severity: {
      sql: (c) => S`WITH ${openAsOf(c, /** @type {Date} */ (c.asOfAt))}
        SELECT s.severity, ${c.distinct ? S`count(DISTINCT COALESCE(s.correlation_key, s.id::text))` : S`count(*)`}::int AS n FROM snap s GROUP BY 1`,
    },
    by_type: {
      sql: (c) => S`WITH ${openAsOf(c, /** @type {Date} */ (c.asOfAt))}
        SELECT s.scan_type, count(*)::int AS n FROM snap s GROUP BY 1`,
    },
    by_status: {
      sql: (c) => S`WITH ${openAsOf(c, /** @type {Date} */ (c.asOfAt))}
        SELECT s.status, count(*)::int AS n FROM snap s GROUP BY 1`,
    },
    by_repository: {
      sql: (c) => S`WITH ${openAsOf(c, /** @type {Date} */ (c.asOfAt))}
        SELECT s.repository_name, count(*)::int AS open,
               (count(*) FILTER (WHERE s.severity = 'critical'))::int AS critical, (count(*) FILTER (WHERE s.severity = 'high'))::int AS high,
               (count(*) FILTER (WHERE s.severity = 'medium'))::int AS medium, (count(*) FILTER (WHERE s.severity = 'low'))::int AS low,
               (count(*) FILTER (WHERE s.severity = 'info'))::int AS info, (count(*) FILTER (WHERE s.severity = 'unknown'))::int AS unknown
        FROM snap s GROUP BY 1 ORDER BY open DESC, 1 LIMIT ${SINGLE_LIMIT}`,
    },
  },

  // ---------------------------------------------------------------- executive summary (PDF)
  executive_summary: {
    open_by_severity: {
      sql: (c) => S`
        SELECT f.severity::text AS severity, ${countOpen(c, "f")}::int AS n
        FROM report_findings_v f WHERE ${scope(c, "f")} AND ${isOpen("f")} GROUP BY 1`,
    },
    ttr_overall: {
      sql: (c) => S`SELECT ${stats} FROM (${fixedInPeriod(c)}) x`,
    },
    sla_open: {
      sql: (c) => S`
        SELECT x.severity, x.sla_state, count(*)::int AS n FROM (
          SELECT f.severity::text AS severity, ${slaState(c, "f")} AS sla_state
          FROM report_findings_v f WHERE ${scope(c, "f")} AND f.severity::text <> 'info' AND ${isOpen("f")}
        ) x WHERE x.sla_state <> 'not_applicable' GROUP BY 1, 2`,
    },
    sla_closed: {
      sql: (c) => S`
        SELECT f.severity::text AS severity, count(*)::int AS fixed, (count(*) FILTER (WHERE f.verified_at <= f.sla_due_at))::int AS within_sla
        FROM report_findings_v f
        WHERE ${scope(c, "f")} AND f.severity::text <> 'info' AND f.status::text = 'verified_fixed' AND f.verified_at IS NOT NULL
          AND f.sla_due_at IS NOT NULL AND ${inPeriod(c, "f.verified_at")}
        GROUP BY 1`,
    },
    risk_inputs: {
      sql: (c) => S`
        SELECT f.repository_id, f.repository_name, ${sevCounts("f")},
               (count(*) FILTER (WHERE f.severity::text IN ('critical', 'high') AND ${slaState(c, "f")} = 'breached'))::int AS breached_critical_high,
               min(f.first_detected_at) FILTER (WHERE f.severity::text = 'critical') AS oldest_open_critical_at
        FROM report_findings_v f WHERE ${scope(c, "f")} AND ${isOpen("f")}
        GROUP BY 1, 2 LIMIT ${SINGLE_LIMIT}`,
    },
    coverage: {
      sql: (c) => S`
        SELECT e.repository_id, e.repository_name,
               bool_or(e.status = 'succeeded' AND e.requested_at >= ${c.now}::timestamptz - interval '30 days') AS scanned_recently,
               (array_agg(e.status ORDER BY e.requested_at DESC))[1] AS last_status,
               max(e.requested_at) AS last_at
        FROM report_executions_v e WHERE ${scope(c, "e")} AND NOT e.pipeline_deleted
        GROUP BY 1, 2 ORDER BY 2 LIMIT ${SINGLE_LIMIT}`,
    },
    burn_down: {
      sql: (c) => {
        const days = listDays(/** @type {string} */ (c.from), /** @type {string} */ (c.to));
        const closes = days.map((d) => dayCloseInstant(d, c.timeZone).toISOString());
        return S`
          WITH t AS (SELECT * FROM unnest(${days}::date[], ${closes}::timestamptz[]) AS t(day, at)),
          ev AS (
            SELECT h.finding_id, h.to_status::text AS status, h.created_at,
                   lead(h.created_at) OVER (PARTITION BY h.finding_id ORDER BY h.created_at, h.rev) AS next_at
            FROM report_status_events_v h WHERE ${scope(c, "h")}
          )
          SELECT t.day::text AS day, ev.status, count(*)::int AS n
          FROM t JOIN ev ON ev.created_at <= t.at AND (ev.next_at IS NULL OR ev.next_at > t.at)
          WHERE ev.status = ANY(${[...OPEN_FINDING_STATUSES]}::text[])
          GROUP BY 1, 2 ORDER BY 1, 2`;
      },
    },
  },
};

/** The dataset every template reads for its CSV (`csv`) and the one used to count rows. */
export const CSV_DATASET = "csv";

/** The dataset whose rows `countExportRows` counts for a template that has no CSV (the source of its PDF). */
const COUNT_DATASET = {
  executive_summary: "open_by_severity",
  detection_quality: "fp_rate",
};

/**
 * @param {string} template @param {string} dataset @returns {{ keyType?: "uuid" | "text", sql: (c: DatasetContext) => Prisma.Sql }}
 * @throws {Error} an unknown template or dataset (a programming or tampering error, never a user input)
 */
export function resolveDataset(template, dataset) {
  const def = Object.hasOwn(DATASETS, template) ? DATASETS[template][dataset] : undefined;
  if (!def || !Object.hasOwn(DATASETS[template], dataset))
    throw new Error("unknown report dataset");
  return def;
}

/** The dataset `countExportRows` counts. @param {string} template */
export const countDatasetOf = (template) =>
  COUNT_DATASET[template] ?? (Object.hasOwn(DATASETS, template) ? CSV_DATASET : "unknown");

/**
 * Counts the rows of a dataset (exact; the cap check).
 * @param {any} db the worker client @param {DatasetContext} c @param {string} template @param {string} dataset
 * @returns {Promise<number>}
 */
export async function countDataset(db, c, template, dataset) {
  const def = resolveDataset(template, dataset);
  const [row] = await db.$queryRaw(S`SELECT count(*)::int AS n FROM (${def.sql(c)}) q`);
  return row?.n ?? 0;
}

/**
 * One page of a dataset. A keyed dataset returns `limit` rows after `after.k` and a `next` cursor when more may follow; a single dataset
 * returns everything (at most {@link SINGLE_LIMIT} rows) and `next: null`.
 * @param {any} db the worker client @param {DatasetContext} c @param {string} template @param {string} dataset
 * @param {{ k?: string } | null} after @param {number} limit
 * @returns {Promise<{ rows: Array<Record<string, any>>, next: { k: string } | null }>}
 */
export async function readDatasetPage(db, c, template, dataset, after, limit) {
  const def = resolveDataset(template, dataset);
  if (!def.keyType) {
    const rows = await db.$queryRaw(def.sql(c));
    return { rows, next: null };
  }
  const type = raw(def.keyType);
  const collate = def.keyType === "text" ? raw(' COLLATE "C"') : NONE;
  const afterK = after?.k ?? null;
  const rows = await db.$queryRaw(
    S`SELECT * FROM (${def.sql(c)}) s
      WHERE (${afterK}::${type} IS NULL OR s.k${collate} > ${afterK}::${type}${collate})
      ORDER BY s.k${collate} LIMIT ${limit}::int`,
  );
  const last = rows[rows.length - 1];
  return { rows, next: rows.length === limit && last ? { k: String(last.k) } : null };
}
