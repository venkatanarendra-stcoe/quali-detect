import {
  FINDING_SEVERITIES,
  LIFECYCLE_GROUPS,
  REPORT_MAX_PERIOD_DAYS,
  REPORTING_LIMITS,
} from "@qmentisai/shared";
import { SEVERITY_LABELS } from "@/features/findings/constants/index.js";

export { SEVERITY_LABELS };

/** Severity series always run Critical to Info (SCREENS 1). */
export const SEVERITY_ORDER = FINDING_SEVERITIES;

/** Severity CSS tokens (DESIGN_SYSTEM 2.2): read at paint time, so the dark and light values switch with the theme. */
export const SEVERITY_FILL = Object.freeze(
  Object.fromEntries(SEVERITY_ORDER.map((s) => [s, `var(--sev-${s})`])),
);

/** Pattern per severity so colour is never the only signal (solid, stripes, dots, cross-hatch, lines). */
export const SEVERITY_PATTERN = Object.freeze(
  Object.fromEntries(
    SEVERITY_ORDER.map((s, i) => [s, ["solid", "stripe", "dots", "cross", "lines"][i]]),
  ),
);

export const GROUP_LABELS = Object.freeze(
  Object.fromEntries(LIFECYCLE_GROUPS.map((g) => [g.id, g.label])),
);
export const GROUP_STATUSES = Object.freeze(
  Object.fromEntries(LIFECYCLE_GROUPS.map((g) => [g.id, g.statuses])),
);
/** Lifecycle groups use neutral chart tokens (never the accent: they are statuses) distinguished by a pattern. */
export const GROUP_STYLE = Object.freeze({
  needs_triage: { fill: "var(--chart-4)", pattern: "solid" },
  in_review: { fill: "var(--chart-2)", pattern: "solid" },
  confirmed_in_remediation: { fill: "var(--chart-3)", pattern: "solid" },
  awaiting_verification: { fill: "var(--chart-4)", pattern: "stripe" },
  accepted_or_suppressed: { fill: "var(--chart-2)", pattern: "stripe" },
  false_positive: { fill: "var(--chart-3)", pattern: "dots" },
  fixed: { fill: "var(--chart-4)", pattern: "dots" },
});

export const EXECUTION_STATUS_LABELS = Object.freeze({
  succeeded: "Succeeded",
  failed: "Failed",
  partial: "Partial",
  timed_out: "Timed out",
  cancelled: "Cancelled",
  skipped: "Skipped",
  blocked: "Blocked",
});
export const EXECUTION_STATUS_STYLE = Object.freeze({
  succeeded: { fill: "var(--status-success)", pattern: "solid" },
  failed: { fill: "var(--status-danger)", pattern: "solid" },
  partial: { fill: "var(--status-warning)", pattern: "solid" },
  timed_out: { fill: "var(--status-danger)", pattern: "stripe" },
  cancelled: { fill: "var(--status-neutral)", pattern: "solid" },
  skipped: { fill: "var(--status-neutral)", pattern: "stripe" },
  blocked: { fill: "var(--status-neutral)", pattern: "dots" },
});

export const COVERAGE_REASON_LABELS = Object.freeze({
  no_pipeline: "No pipeline",
  pipeline_disabled: "Pipeline disabled",
  no_recent_scan: "No recent scan",
  last_scan_partial: "Last scan partial",
  connection_unavailable: "Connection unavailable",
});
export const SCAN_TYPE_FULL = Object.freeze({
  sbom: "SBOM",
  sca: "SCA",
  sast: "SAST",
  secrets: "Secrets",
});

/** SLA states of open findings; `filter` is the value of the Findings list `sla` URL parameter. */
export const SLA_STATE_STYLE = Object.freeze({
  onTrack: {
    label: "On track",
    fill: "var(--status-success)",
    pattern: "solid",
    filter: "on_track",
  },
  dueSoon: {
    label: "Due soon",
    fill: "var(--status-warning)",
    pattern: "stripe",
    filter: "due_soon",
  },
  breached: {
    label: "Breached",
    fill: "var(--status-danger)",
    pattern: "solid",
    filter: "breached",
  },
});

export const REPORT_STATUS_LABELS = Object.freeze({
  queued: "Queued",
  running: "Running",
  ready: "Ready",
  failed: "Failed",
  expired: "Expired",
});
/** Stable failure codes of a run in plain words (SPEC 7.4). */
export const REPORT_FAILURE_TEXT = Object.freeze({
  too_large: "Too large: narrow the period or scope and generate again.",
  timeout: "Took too long to build. Try a shorter period.",
  source_unavailable: "The data source was unavailable. Try again in a few minutes.",
  internal: "Something went wrong on our side. Try again.",
});
/** Stable API codes shown inside the Generate dialog (SCREENS T-50). */
export const GENERATE_ERROR_TEXT = Object.freeze({
  REPORT_TOO_LARGE: "This report would be too large. Narrow the period or the scope.",
  REPORT_LIMIT_REACHED:
    "Too many reports are in progress or were requested this hour. Try again later.",
  REPORT_PERIOD_INVALID: "The period is not valid.",
  REPORT_PERIOD_TOO_LONG: `The period is longer than the maximum of ${REPORT_MAX_PERIOD_DAYS} days.`,
  REPORT_TEMPLATE_UNKNOWN: "This template or format is not available.",
  REPORT_AS_OF_UNAVAILABLE: "There is no data for that day yet. Choose a later day.",
});

/** One-line description and the words of "What's included" per v1 template (SPEC 7.3). */
export const TEMPLATE_COPY = Object.freeze({
  executive_summary: {
    description:
      "Key figures, burn-down, top risky repositories and the coverage statement for leaders.",
    includes: [
      "Key figures",
      "Backlog burn-down",
      "Top risky repositories",
      "SLA compliance",
      "Scan coverage statement",
    ],
  },
  findings_by_pipeline: {
    description:
      "One row per finding with its severity, status, repository, pipeline and SLA state.",
    includes: [
      "Finding id and title",
      "Scan type, severity and status",
      "Repository, pipeline and path",
      "Rule id",
      "First seen, age and SLA due date",
    ],
  },
  sla_compliance: {
    description: "SLA status of open findings and compliance of fixes, by severity and repository.",
    includes: [
      "Open findings by SLA state",
      "Fixed in the period",
      "Fixed within SLA",
      "Breached list",
    ],
  },
  remediation_performance: {
    description: "Median and p90 time to remediate, velocity and the reopen rate.",
    includes: [
      "Median, p90 and mean time to remediate",
      "By severity and scan type",
      "Velocity per week",
      "Reopen rate",
    ],
  },
  sbom_inventory: {
    description: "The latest component inventory with a vulnerable flag.",
    includes: [
      "Component, version and ecosystem",
      "Repository and pipeline",
      "Known vulnerability yes or no",
    ],
  },
  detection_quality: {
    description: "False-positive rate and advisory agreement with the sample sizes.",
    includes: [
      "False-positive rate with n",
      "Advisory coverage and agreement",
      "Human override of confident advice",
    ],
  },
  point_in_time_snapshot: {
    description: "Open findings as they were at the end of a chosen past day.",
    includes: ["Open findings by severity and scan type", "By repository", "As of the chosen day"],
  },
});
export const NOT_INCLUDED_TEXT = "Not included: code excerpts, comments, AI reasoning.";

export const POLL_MS = REPORTING_LIMITS.pollSeconds * 1000;
/** Realtime hints are coalesced into one refetch round (SCREENS 1: debounce 5 s). */
export const HINT_DEBOUNCE_MS = 5_000;
export const REPORT_POLL_MS = 5_000;
export const REPORTS_PAGE_SIZE = 25;
export const DEFAULT_PERIOD = 30;

/** Analysis screens (T-46 to T-49): path under the workspace, label, gate. Reached from the dashboard, never the sidebar (SPEC D-2). */
export const ANALYSIS_SCREENS = Object.freeze([
  { id: "dashboard", label: "Dashboard", path: "dashboard", permission: "workspace.view" },
  { id: "trends", label: "Trends", path: "dashboard/trends", permission: "finding.view" },
  {
    id: "remediation",
    label: "Remediation and SLA",
    path: "dashboard/remediation",
    permission: "finding.view",
  },
  {
    id: "scan-activity",
    label: "Scan activity",
    path: "dashboard/scan-activity",
    permission: "execution.view",
  },
  {
    id: "quality",
    label: "Detection quality",
    path: "dashboard/quality",
    permission: "security_review.view",
  },
]);
