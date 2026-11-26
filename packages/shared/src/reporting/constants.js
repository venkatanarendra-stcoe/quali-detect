import { FINDING_STATUSES, OPEN_FINDING_STATUSES } from "../findings/constants.js";

/**
 * Constants of the Reporting and Dashboards module (docs/modules/reporting-dashboards/SPEC.md, contract freeze Part A0, ADR-015). One
 * definition of each word for the rollup worker, the read API, the exports and the UI. Nothing here is secret and nothing here is a
 * permission decision (the central authorization engine decides). The finding statuses are IMPORTED from the Findings constants and
 * never redefined (SPEC 5 rule 2); the lifecycle groups below only GROUP them and the module load fails if the grouping stops being
 * an exact partition of the 12 statuses.
 */

/** The master flag name of the module (API and workers); everything is OFF until it is the string "true" (SPEC 0.1). */
export const REPORTING_FLAG_NAME = "REPORTING_ENABLED";

/**
 * The lifecycle groups of SPEC 5 rule 3, in display order. `open: true` for the first four ("open" = the eight open statuses of the
 * Findings module). `label` is the UI word. `statuses` is declared here, once, for every chart and export.
 * @type {ReadonlyArray<Readonly<{ id: string, label: string, open: boolean, statuses: ReadonlyArray<string> }>>}
 */
export const LIFECYCLE_GROUPS = Object.freeze(
  [
    { id: "needs_triage", label: "Needs triage", open: true, statuses: ["new", "reopened"] },
    {
      id: "in_review",
      label: "In review",
      open: true,
      statuses: ["in_review", "awaiting_approval"],
    },
    {
      id: "confirmed_in_remediation",
      label: "Confirmed, in remediation",
      open: true,
      statuses: ["approved", "assigned", "in_remediation"],
    },
    {
      id: "awaiting_verification",
      label: "Awaiting verification",
      open: true,
      statuses: ["fixed_pending_verification"],
    },
    {
      id: "accepted_or_suppressed",
      label: "Accepted or suppressed",
      open: false,
      statuses: ["accepted_risk", "suppressed"],
    },
    { id: "false_positive", label: "False positive", open: false, statuses: ["false_positive"] },
    { id: "fixed", label: "Fixed", open: false, statuses: ["verified_fixed"] },
  ].map((g) => Object.freeze({ ...g, statuses: Object.freeze([...g.statuses]) })),
);

/** The group ids in display order. */
export const LIFECYCLE_GROUP_IDS = Object.freeze(LIFECYCLE_GROUPS.map((g) => g.id));

/** Status to the id of its group (total over the 12 finding statuses). @type {Readonly<Record<string, string>>} */
export const LIFECYCLE_GROUP_OF_STATUS = Object.freeze(
  Object.fromEntries(LIFECYCLE_GROUPS.flatMap((g) => g.statuses.map((s) => [s, g.id]))),
);

/** The open groups (the first four). */
export const OPEN_LIFECYCLE_GROUP_IDS = Object.freeze(
  LIFECYCLE_GROUPS.filter((g) => g.open).map((g) => g.id),
);

/** "Backlog" (SPEC 5 rule 3): open and not yet in anyone's hands. */
export const BACKLOG_STATUSES = Object.freeze([
  "new",
  "reopened",
  "in_review",
  "awaiting_approval",
  "approved",
]);
/** "Work in progress" (SPEC 5 rule 3). */
export const WORK_IN_PROGRESS_STATUSES = Object.freeze([
  "assigned",
  "in_remediation",
  "fixed_pending_verification",
]);
/** Statuses that are an exception in force (P-7, `exceptions_in_force`). */
export const EXCEPTION_IN_FORCE_STATUSES = Object.freeze(["accepted_risk", "suppressed"]);

/** Flow classification of a status-history row by its `to_status` (SPEC 5 rule 4; T-1). `new` is a row with no `from_status`. */
export const FLOW_FIXED_TO_STATUSES = Object.freeze(["verified_fixed"]);
export const FLOW_CLOSED_OTHER_TO_STATUSES = Object.freeze([
  "false_positive",
  "suppressed",
  "accepted_risk",
]);
export const FLOW_REOPENED_TO_STATUSES = Object.freeze(["reopened"]);

// The grouping is an exact partition of the 12 statuses and its open groups are exactly the Findings open set: fail at load otherwise.
{
  const all = LIFECYCLE_GROUPS.flatMap((g) => [...g.statuses]);
  const ok =
    all.length === FINDING_STATUSES.length &&
    new Set(all).size === all.length &&
    FINDING_STATUSES.every((s) => all.includes(s));
  if (!ok)
    throw new Error("reporting LIFECYCLE_GROUPS must partition the finding statuses exactly once");
  const open = LIFECYCLE_GROUPS.filter((g) => g.open).flatMap((g) => [...g.statuses]);
  if (
    open.length !== OPEN_FINDING_STATUSES.length ||
    !OPEN_FINDING_STATUSES.every((s) => open.includes(s))
  )
    throw new Error("reporting open lifecycle groups must equal OPEN_FINDING_STATUSES");
  const ws = [...BACKLOG_STATUSES, ...WORK_IN_PROGRESS_STATUSES];
  if (ws.length !== open.length || !open.every((s) => ws.includes(s)))
    throw new Error("backlog plus work in progress must equal the open statuses");
}

/** Period presets in days and the longest custom period (SPEC 17 D-5). */
export const REPORT_PERIOD_PRESETS = Object.freeze([7, 30, 90]);
export const REPORT_MAX_PERIOD_DAYS = 400;
/** The default tenant reporting time zone (SPEC 8.4). */
export const REPORT_DEFAULT_TIME_ZONE = "UTC";

/** Execution statuses that count in the executions rollup columns (SPEC 8.2 `report_daily_executions`, 6.4 S-1). */
export const REPORT_EXECUTION_STATUSES = Object.freeze([
  "succeeded",
  "failed",
  "partial",
  "timed_out",
  "cancelled",
  "skipped",
  "blocked",
]);
/** S-2: the statuses in the denominator of the success rate (cancelled, skipped and blocked are shown apart). */
export const SUCCESS_RATE_STATUSES = Object.freeze(["succeeded", "failed", "partial", "timed_out"]);

/** Limits and tunables of the module; ruled values of 2026-11-26 (SPEC 0.1). */
export const REPORTING_LIMITS = Object.freeze({
  /** CSV rows per file; a larger request is refused (`REPORT_TOO_LARGE`), never truncated. */
  csvMaxRows: 250000,
  /** Running (queued or running) export jobs per tenant. */
  maxConcurrentExportsPerTenant: 3,
  /** Export requests per user per hour (`REPORT_LIMIT_REACHED`, 429). */
  exportRequestsPerUserPerHour: 20,
  pdfMaxPages: 40,
  /** Generated file retention, days; the `report_exports` row stays `runRetentionMonths`. */
  fileRetentionDays: 30,
  /** A download is valid this long from the request that authorised it. */
  downloadValiditySeconds: 24 * 60 * 60,
  rollupRetentionMonths: 25,
  runRetentionMonths: 13,
  /** A rollup older than this is flagged `stale` (RPT-009). */
  staleAfterSeconds: 2 * 60 * 60,
  /** SPEC 5 rule 9: a rate over fewer decisions than this is not shown as a percentage. */
  minDecisionsForRate: 20,
  /** Server cache TTLs (D-4). */
  cacheTtlLiveSeconds: 30,
  cacheTtlRollupSeconds: 300,
  /** Client polling for the live tiles. */
  pollSeconds: 60,
  topRiskDefaultLimit: 10,
  topRiskMaxLimit: 50,
  /** Reads: `statement_timeout` of the read role, seconds (SPEC 12 item 7). */
  readStatementTimeoutSeconds: 5,
  /** `report_exports.params` byte ceiling (validated, no free text). */
  paramsMaxBytes: 2048,
  /** A projection needs this many days of history (T-3). */
  projectionMinDays: 14,
  /** The aging buckets of R-6, upper bounds in days (the last is open ended). */
  agingBucketDays: Object.freeze([7, 30, 90]),
  /** The 10 oldest critical and high findings of R-6. */
  agingOldestLimit: 10,
});

export const REPORT_FORMATS = Object.freeze(["csv", "pdf"]);
/** Report run states (SPEC 7.4). `deleted_at` marks a user deletion; `expired` is a purged file. */
export const REPORT_STATUSES = Object.freeze(["queued", "running", "ready", "failed", "expired"]);
/** `report_exports.error_code` of a failed run (SPEC 7.4). */
export const REPORT_FAILURE_CODES = Object.freeze([
  "too_large",
  "timeout",
  "source_unavailable",
  "internal",
]);
/** Rollup run modes and states (`report_rollup_runs`, SPEC 8.3). */
export const ROLLUP_MODES = Object.freeze(["incremental", "close", "backfill"]);
export const ROLLUP_RUN_STATUSES = Object.freeze(["running", "succeeded", "failed"]);
/** `report_rollup_runs.error_code` vocabulary (stable words, never a message). */
export const ROLLUP_ERROR_CODES = Object.freeze([
  "ownership_mismatch",
  "source_unavailable",
  "timeout",
  "invalid_range",
  "internal",
]);

/** Where `meta.source` came from. */
export const REPORT_SOURCES = Object.freeze(["live", "rollup"]);
/** Metric modes (SPEC 6 legend). */
export const METRIC_MODES = Object.freeze(["live", "rollup", "hybrid"]);

/** Breakdown dimensions of `GET /reporting/breakdown?by=` (SPEC 9). */
export const BREAKDOWN_DIMENSIONS = Object.freeze(["repository", "pipeline", "scan_type", "rule"]);
/** `GET /reporting/trends?series=` values (T-1 to T-5). */
export const TREND_SERIES = Object.freeze([
  "flow",
  "severity",
  "backlog",
  "net_change",
  "awaiting_verification",
]);
/** Tile coverage reasons of S-4. */
export const COVERAGE_REASONS = Object.freeze([
  "no_pipeline",
  "pipeline_disabled",
  "no_recent_scan",
  "last_scan_partial",
  "connection_unavailable",
]);

/** Audit actions of the module (SPEC 12 item 6). */
export const REPORTING_AUDIT_ACTIONS = Object.freeze([
  "report.generated",
  "report.downloaded",
  "report.deleted",
  "tenant.reporting_timezone_changed",
]);

/** Message type names (ADR-011 envelope; the payload schemas are in `./schemas.js` and registered in `@qmentisai/contracts`). */
export const REPORTING_MESSAGE_TYPES = Object.freeze({
  ROLLUP_REQUESTED: "reporting.rollup.requested",
  EXPORT_REQUESTED: "reporting.export.requested",
});

/** Redis cache key prefix (D-4): `rpt:{tenantId}:{workspaceId}:{metric}:{epoch}:{paramsHash}`. */
export const REPORTING_CACHE_PREFIX = "rpt";
