/**
 * Which permission each Reporting route and dashboard section needs (docs/modules/reporting-dashboards/SPEC.md 3, 9). The keys are the
 * EXISTING catalogue keys: the module adds NO permission key and changes no built-in role. The central authorization engine decides;
 * this map only names what to ask. 404 for another tenant's or a hidden workspace, 403 for a visible workspace without the key.
 */

/** Route key (`METHOD /path`, the frozen contract) to the permission checked before the handler. `a|b` means both are needed. @type {Readonly<Record<string, string>>} */
export const REPORTING_PERMISSION_BY_ROUTE = Object.freeze({
  "GET /reporting/posture": "finding.view",
  "GET /reporting/trends": "finding.view",
  "GET /reporting/remediation": "finding.view",
  "GET /reporting/sla": "finding.view",
  "GET /reporting/aging": "finding.view",
  "GET /reporting/scan-activity": "execution.view",
  "GET /reporting/coverage": "execution.view",
  "GET /reporting/sbom": "execution.view",
  "GET /reporting/quality": "security_review.view",
  "GET /reporting/breakdown": "finding.view",
  "GET /reporting/top-risk": "finding.view",
  "GET /reporting/workload": "finding.assign",
  // tenant scope; per workspace the section's own key also applies (only accessible workspaces are counted)
  "GET /reporting/overview": "dashboard.view",
  // a workspace report needs `report.export`; a tenant-wide one also needs `dashboard.view` at tenant scope
  "POST /reporting/reports": "report.export",
  "GET /reporting/reports": "report.view",
  "GET /reporting/reports/{id}": "report.view",
  // `report.view` AND (the requester OR a `report.export` holder of the workspace): the service checks the second part
  "GET /reporting/reports/{id}/download": "report.view",
  // the requester or a `report.export` holder of the workspace: the service checks it; the route needs the page's key
  "DELETE /reporting/reports/{id}": "report.view",
  // tenant scope, the Organization Settings keys (not a new key): the zone decides every report day of the tenant
  "GET /reporting/settings": "tenant_settings.view",
  "PUT /reporting/settings": "tenant_settings.manage",
});

/** Dashboard section to the key that gates its data (SPEC 3, D-2): a tile without its key is hidden and the API answers 403. @type {Readonly<Record<string, string>>} */
export const REPORTING_PERMISSION_BY_SECTION = Object.freeze({
  page: "workspace.view",
  posture: "finding.view",
  trends: "finding.view",
  remediation: "finding.view",
  sla: "finding.view",
  aging: "finding.view",
  breakdown: "finding.view",
  topRisk: "finding.view",
  scanActivity: "execution.view",
  coverage: "execution.view",
  sbom: "execution.view",
  quality: "security_review.view",
  workload: "finding.assign",
  overview: "dashboard.view",
  reports: "report.view",
  export: "report.export",
});

/** Every permission key the module uses, for the suite's "all keys exist in the catalogue" check. */
export const REPORTING_PERMISSION_KEYS = Object.freeze([
  ...new Set(
    [
      ...Object.values(REPORTING_PERMISSION_BY_ROUTE),
      ...Object.values(REPORTING_PERMISSION_BY_SECTION),
    ].flatMap((p) => p.split("|")),
  ),
]);
