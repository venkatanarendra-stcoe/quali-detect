/**
 * The report template catalogue (docs/modules/reporting-dashboards/SPEC.md 7.3) as DATA: ids, formats, scope, period mode, CSV columns and PDF
 * sections. Part C (exports) renders from this table and the UI shows it; nothing about a template is decided anywhere else. Every column
 * names a column of a `report_*_v` view (`source`): the export worker reads the views only, so a column that is not in a view cannot be
 * listed here (the suite compares them with `information_schema`). No evidence, rationale, comment, advisory reasoning, exception
 * justification, secret preview or e-mail address can be a column.
 */

/** The fields a report never carries, in the words the Generate dialog shows (SPEC 11, 12 item 2). @type {ReadonlyArray<string>} */
export const REPORT_EXCLUDED_FIELDS = Object.freeze([
  "code excerpts (evidence snippets)",
  "reviewer rationales",
  "comments",
  "advisory reasoning",
  "exception justifications",
  "secret previews",
  "e-mail addresses",
]);

/** The notice the dialog and every PDF footer print. */
export const REPORT_EXCLUSION_NOTICE =
  "No code excerpts, comments, rationales or reasoning are included.";

/**
 * @typedef {object} ReportColumn
 * @property {string} key stable column key (the CSV header is `header`)
 * @property {string} header CSV header text
 * @property {string} source the `report_*_v` column the value comes from, or `derived:<name>`
 * @property {"text" | "number" | "timestamp" | "boolean"} type
 * @property {string} [requiresPermission] the column is written only when the requester holds this key (otherwise the column is omitted)
 */

/**
 * @typedef {object} ReportSection
 * @property {string} id
 * @property {string} title
 * @property {ReadonlyArray<string>} metrics metric ids of `./metrics.js`
 */

/**
 * @typedef {object} ReportTemplate
 * @property {string} id
 * @property {string} title
 * @property {ReadonlyArray<"csv" | "pdf">} formats
 * @property {ReadonlyArray<"workspace" | "tenant">} scopes `tenant` needs `dashboard.view` and `report.export` at tenant scope
 * @property {"period" | "asOfDay" | "none"} periodMode
 * @property {boolean} v1 false for a deferred template (refused with `REPORT_TEMPLATE_UNKNOWN`)
 * @property {ReadonlyArray<string>} metrics
 * @property {ReadonlyArray<ReportColumn>} csvColumns empty when the template has no CSV format
 * @property {ReadonlyArray<ReportSection>} pdfSections empty when the template has no PDF format
 * @property {ReadonlyArray<string>} sources the views the worker reads for this template
 * @property {string} [deferredReason]
 */

/** @type {(key: string, header: string, source: string, type?: ReportColumn["type"], requiresPermission?: string) => Readonly<ReportColumn>} */
const col = (key, header, source, type = "text", requiresPermission) =>
  Object.freeze({
    key,
    header,
    source,
    type,
    ...(requiresPermission ? { requiresPermission } : {}),
  });

/** @type {(id: string, title: string, metrics: string[]) => Readonly<ReportSection>} */
const sec = (id, title, metrics) => Object.freeze({ id, title, metrics: Object.freeze(metrics) });

/** @param {ReportTemplate} t @returns {Readonly<ReportTemplate>} */
const tpl = (t) =>
  Object.freeze({
    ...t,
    formats: Object.freeze([...t.formats]),
    scopes: Object.freeze([...t.scopes]),
    metrics: Object.freeze([...t.metrics]),
    csvColumns: Object.freeze([...t.csvColumns]),
    pdfSections: Object.freeze([...t.pdfSections]),
    sources: Object.freeze([...t.sources]),
  });

/** @type {ReadonlyArray<Readonly<ReportTemplate>>} */
export const REPORT_TEMPLATES = Object.freeze([
  tpl({
    id: "executive_summary",
    title: "Executive security summary",
    formats: ["pdf"],
    scopes: ["workspace", "tenant"],
    periodMode: "period",
    v1: true,
    metrics: ["P-1", "P-2", "P-6", "R-1", "R-4", "R-5", "T-3", "B-4", "S-4"],
    csvColumns: [],
    pdfSections: [
      sec("kpis", "Key figures", ["P-1", "P-2", "P-6", "R-1", "R-5"]),
      sec("burn_down", "Backlog burn-down", ["T-3"]),
      sec("top_risk", "Top risky repositories", ["B-4"]),
      sec("sla", "SLA compliance", ["R-4", "R-5"]),
      sec("coverage", "Scan coverage statement", ["S-4"]),
    ],
    sources: ["report_findings_v", "report_executions_v"],
  }),
  tpl({
    id: "findings_by_pipeline",
    title: "Findings by pipeline",
    formats: ["csv", "pdf"],
    scopes: ["workspace", "tenant"],
    periodMode: "none",
    v1: true,
    metrics: ["P-1", "P-2", "B-3"],
    csvColumns: [
      col("id", "Finding id", "id"),
      col("title", "Title", "title"),
      col("scan_type", "Scan type", "scan_type"),
      col("severity", "Severity", "severity"),
      col("status", "Status", "status"),
      col("repository", "Repository", "repository_name"),
      col("pipeline", "Pipeline", "pipeline_name"),
      col("path", "Path", "path"),
      col("start_line", "Line", "start_line", "number"),
      col("rule_id", "Rule id", "rule_id"),
      col("first_detected_at", "First seen", "first_detected_at", "timestamp"),
      col("age_days", "Age (days)", "derived:age_days", "number"),
      col("sla_state", "SLA state", "derived:sla_state"),
      col("sla_due_at", "SLA due", "sla_due_at", "timestamp"),
      // O-6: the assignee display name (never an e-mail) only for a requester who holds `finding.assign`
      col("assignee", "Assignee", "assignee_display_name", "text", "finding.assign"),
    ],
    pdfSections: [
      sec("summary", "Open findings by severity", ["P-1", "P-2"]),
      sec("by_pipeline", "By pipeline", ["B-3"]),
    ],
    sources: ["report_findings_v"],
  }),
  tpl({
    id: "sla_compliance",
    title: "SLA compliance",
    formats: ["csv", "pdf"],
    scopes: ["workspace", "tenant"],
    periodMode: "period",
    v1: true,
    metrics: ["R-4", "R-5"],
    csvColumns: [
      col("repository", "Repository", "repository_name"),
      col("severity", "Severity", "severity"),
      col("sla_state", "SLA state", "derived:sla_state"),
      col("open_count", "Open findings", "derived:count", "number"),
      col("fixed_in_period", "Fixed in period", "derived:count", "number"),
      col("fixed_within_sla", "Fixed within SLA", "derived:count", "number"),
    ],
    pdfSections: [
      sec("closed", "Closed in the period", ["R-4"]),
      sec("open", "Open, by SLA state", ["R-5"]),
    ],
    sources: ["report_findings_v"],
  }),
  tpl({
    id: "remediation_performance",
    title: "Remediation performance",
    formats: ["pdf", "csv"],
    scopes: ["workspace", "tenant"],
    periodMode: "period",
    v1: true,
    metrics: ["R-1", "R-2", "R-3", "R-7", "R-8", "T-1"],
    csvColumns: [
      col("severity", "Severity", "severity"),
      col("scan_type", "Scan type", "scan_type"),
      col("fixed_count", "Fixed", "derived:count", "number"),
      col("median_days", "Median days to remediate", "derived:median", "number"),
      col("p90_days", "p90 days to remediate", "derived:p90", "number"),
      col("mean_days", "Mean days to remediate", "derived:mean", "number"),
    ],
    pdfSections: [
      sec("ttr", "Time to remediate", ["R-1"]),
      sec("first_decision", "Time to first decision", ["R-3"]),
      sec("verification", "Verification lag", ["R-7"]),
      sec("velocity", "Velocity and reopen rate", ["R-2", "R-8", "T-1"]),
    ],
    sources: ["report_findings_v", "report_decisions_v", "report_status_events_v"],
  }),
  tpl({
    id: "sbom_inventory",
    title: "SBOM inventory",
    formats: ["csv"],
    scopes: ["workspace", "tenant"],
    periodMode: "none",
    v1: true,
    metrics: ["S-8"],
    csvColumns: [
      col("component", "Component (purl)", "component_purl"),
      col("version", "Version", "component_version"),
      col("ecosystem", "Ecosystem", "ecosystem"),
      col("repository", "Repository", "repository_name"),
      col("pipeline", "Pipeline", "pipeline_name"),
      col("vulnerable", "Has a known vulnerability", "derived:vulnerable", "boolean"),
    ],
    pdfSections: [],
    sources: ["report_sbom_latest_v", "report_findings_v"],
  }),
  tpl({
    id: "detection_quality",
    title: "Detection quality",
    formats: ["pdf"],
    scopes: ["workspace", "tenant"],
    periodMode: "period",
    v1: true,
    metrics: ["Q-1", "Q-2", "Q-3", "Q-4", "Q-5"],
    csvColumns: [],
    pdfSections: [
      sec("fp_rate", "False-positive rate", ["Q-1"]),
      sec("noisy_rules", "Noisiest rules", ["Q-2"]),
      sec("advisory", "Advice versus human decision", ["Q-3", "Q-4", "Q-5"]),
    ],
    sources: ["report_decisions_v", "report_advisories_v", "report_findings_v"],
  }),
  tpl({
    id: "point_in_time_snapshot",
    title: "Point-in-time snapshot",
    formats: ["csv", "pdf"],
    scopes: ["workspace", "tenant"],
    periodMode: "asOfDay",
    v1: true,
    metrics: ["P-1", "P-2", "P-3", "P-4", "B-2"],
    csvColumns: [
      col("day", "As of day", "derived:day"),
      col("repository", "Repository", "repository_name"),
      col("scan_type", "Scan type", "scan_type"),
      col("severity", "Severity", "severity"),
      col("open_count", "Open findings", "derived:count", "number"),
    ],
    pdfSections: [
      sec("posture", "Posture", ["P-1", "P-2", "P-3", "P-4"]),
      sec("by_repository", "By repository", ["B-2"]),
    ],
    sources: ["report_findings_v"],
  }),
  tpl({
    id: "audit_evidence_pack",
    title: "Audit evidence pack",
    formats: ["pdf"],
    scopes: ["tenant"],
    periodMode: "period",
    v1: false,
    metrics: [],
    csvColumns: [],
    pdfSections: [],
    sources: [],
    deferredReason: "needs the audit-log module's export",
  }),
]);

/** Template id to template. @type {Readonly<Record<string, Readonly<ReportTemplate>>>} */
export const REPORT_TEMPLATE_BY_ID = Object.freeze(
  Object.fromEntries(REPORT_TEMPLATES.map((t) => [t.id, t])),
);
/** The ids a request may name (deferred templates are known but refused). */
export const REPORT_TEMPLATE_IDS = Object.freeze(
  REPORT_TEMPLATES.filter((t) => t.v1).map((t) => t.id),
);
