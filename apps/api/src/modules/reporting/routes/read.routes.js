/**
 * Reporting routes, Part B (read API): the thirteen `GET /reporting/*` read routes of docs/modules/reporting-dashboards/SPEC.md 9 (posture, trends,
 * remediation, sla, aging, scan-activity, coverage, sbom, quality, breakdown, top-risk, workload, overview). Part B owns this file and the files
 * it adds next to it (controllers, services, mappers, schemas); Part A0 froze the signature below and the route keys and permissions in
 * `REPORTING_PERMISSION_BY_ROUTE` and the schemas in `REPORTING_ROUTE_SCHEMAS` of `@qmentisai/shared`. It registers nothing until Part B fills it.
 * @param {import("./index.js").ReportingRouteDeps} _deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const reportingReadRoutes = (_deps) => async function register(_app) {};
