/**
 * The metric catalogue (docs/modules/reporting-dashboards/SPEC.md section 6): one row per metric id, with its mode, the permission key that
 * gates it, its scope and the endpoint that serves it. The definitions themselves stay in the SPEC (one place); this is the DATA the API,
 * the UI and the suite share, so a metric cannot be served without a key or under a different mode than the SPEC says. No new permission
 * key: every `permission` is an existing catalogue key (`packages/shared/src/permissions.js`).
 *
 * `mode`: `live` (query on request), `rollup` (daily table), `hybrid` (both). `asOf`: `now` (a point in time, now or a chosen day) or
 * `period` (over the selected range). `scope`: `workspace` (a `workspaceId` is required) or `tenant` (the Organization Overview).
 * `route` is the frozen `METHOD /path` key of SPEC 9.
 */

/** @typedef {{ id: string, name: string, family: "P" | "T" | "R" | "S" | "Q" | "B", mode: "live" | "rollup" | "hybrid", asOf: "now" | "period", permission: string, scope: "workspace" | "tenant", route: string }} MetricDefinition */

/** @type {(id: string, name: string, mode: MetricDefinition["mode"], asOf: MetricDefinition["asOf"], permission: string, route: string, scope?: MetricDefinition["scope"]) => Readonly<MetricDefinition>} */
const m = (id, name, mode, asOf, permission, route, scope = "workspace") =>
  Object.freeze({
    id,
    name,
    family: /** @type {MetricDefinition["family"]} */ (id.charAt(0)),
    mode,
    asOf,
    permission,
    scope,
    route,
  });

const POSTURE = "GET /reporting/posture";
const TRENDS = "GET /reporting/trends";
const REMEDIATION = "GET /reporting/remediation";

/** @type {ReadonlyArray<Readonly<MetricDefinition>>} */
export const METRICS = Object.freeze([
  // 6.1 current posture (live)
  m("P-1", "Open findings", "live", "now", "finding.view", POSTURE),
  m("P-2", "Open by severity", "live", "now", "finding.view", POSTURE),
  m("P-3", "Open by type", "live", "now", "finding.view", POSTURE),
  m("P-4", "By lifecycle group and status", "live", "now", "finding.view", POSTURE),
  m("P-5", "Backlog and work in progress", "live", "now", "finding.view", POSTURE),
  m("P-6", "Critical and high open", "live", "now", "finding.view", POSTURE),
  m("P-7", "Exceptions in force and expiring", "live", "now", "finding.view", POSTURE),
  m("P-8", "Awaiting a decision", "live", "now", "finding.view", POSTURE),
  m("P-9", "New in the last 24 hours", "live", "now", "finding.view", POSTURE),
  m("P-10", "Pipelines healthy", "live", "now", "execution.view", POSTURE),
  // 6.2 trends (rollup)
  m("T-1", "New vs resolved per day", "rollup", "period", "finding.view", TRENDS),
  m("T-2", "Open findings per day by severity", "rollup", "period", "finding.view", TRENDS),
  m("T-3", "Backlog burn-down", "rollup", "period", "finding.view", TRENDS),
  m("T-4", "Net change", "rollup", "period", "finding.view", TRENDS),
  m("T-5", "Awaiting verification over time", "rollup", "period", "finding.view", TRENDS),
  // 6.3 remediation
  m("R-1", "Time to remediate", "live", "period", "finding.view", REMEDIATION),
  m("R-2", "Velocity", "rollup", "period", "finding.view", REMEDIATION),
  m("R-3", "Time to first decision", "live", "period", "finding.view", REMEDIATION),
  m("R-4", "SLA compliance (closed)", "live", "period", "finding.view", "GET /reporting/sla"),
  m("R-5", "SLA status (open)", "hybrid", "now", "finding.view", "GET /reporting/sla"),
  m("R-6", "Aging", "live", "now", "finding.view", "GET /reporting/aging"),
  m("R-7", "Verification lag", "live", "period", "finding.view", REMEDIATION),
  m("R-8", "Reopen rate", "rollup", "period", "finding.view", REMEDIATION),
  // 6.4 scan activity
  m(
    "S-1",
    "Executions per day by status",
    "rollup",
    "period",
    "execution.view",
    "GET /reporting/scan-activity",
  ),
  m("S-2", "Success rate", "rollup", "period", "execution.view", "GET /reporting/scan-activity"),
  m(
    "S-3",
    "Duration and queue wait",
    "live",
    "period",
    "execution.view",
    "GET /reporting/scan-activity",
  ),
  m("S-4", "Repository coverage", "live", "now", "execution.view", "GET /reporting/coverage"),
  m("S-5", "Scan-type coverage", "live", "now", "execution.view", "GET /reporting/coverage"),
  m(
    "S-6",
    "Result completeness",
    "rollup",
    "period",
    "execution.view",
    "GET /reporting/scan-activity",
  ),
  m(
    "S-7",
    "Ingestion-eligible share",
    "rollup",
    "period",
    "execution.view",
    "GET /reporting/scan-activity",
  ),
  m("S-8", "SBOM components", "hybrid", "now", "execution.view", "GET /reporting/sbom"),
  // 6.5 quality
  m(
    "Q-1",
    "False-positive rate",
    "hybrid",
    "period",
    "security_review.view",
    "GET /reporting/quality",
  ),
  m("Q-2", "Noisiest rules", "live", "period", "security_review.view", "GET /reporting/quality"),
  m(
    "Q-3",
    "Advisory coverage",
    "hybrid",
    "period",
    "security_review.view",
    "GET /reporting/quality",
  ),
  m(
    "Q-4",
    "Advisory agreement",
    "hybrid",
    "period",
    "security_review.view",
    "GET /reporting/quality",
  ),
  m(
    "Q-5",
    "Human override rate",
    "hybrid",
    "period",
    "security_review.view",
    "GET /reporting/quality",
  ),
  m("Q-6", "Advisory outcomes", "live", "period", "security_review.view", "GET /reporting/quality"),
  // 6.6 breakdowns and top risk
  m(
    "B-1",
    "By workspace (Organization Overview)",
    "hybrid",
    "period",
    "dashboard.view",
    "GET /reporting/overview",
    "tenant",
  ),
  m("B-2", "By repository", "live", "now", "finding.view", "GET /reporting/breakdown"),
  m("B-3", "By pipeline", "live", "now", "finding.view", "GET /reporting/breakdown"),
  m("B-4", "Top risky repositories", "live", "now", "finding.view", "GET /reporting/top-risk"),
  m("B-5", "By rule or CWE", "live", "now", "finding.view", "GET /reporting/breakdown"),
  m("B-6", "Per-assignee workload", "live", "now", "finding.assign", "GET /reporting/workload"),
]);

/** Metric id to its definition. @type {Readonly<Record<string, Readonly<MetricDefinition>>>} */
export const METRIC_BY_ID = Object.freeze(Object.fromEntries(METRICS.map((x) => [x.id, x])));

/** All metric ids in catalogue order. */
export const METRIC_IDS = Object.freeze(METRICS.map((x) => x.id));
