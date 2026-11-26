/**
 * Reporting routes, Part C (exports): `POST /reporting/reports`, `GET /reporting/reports`, `GET /reporting/reports/{id}`,
 * `GET /reporting/reports/{id}/download` (an authenticated stream, `no-store`, audited) and `DELETE /reporting/reports/{id}`
 * (docs/modules/reporting-dashboards/SPEC.md 9). Part C owns this file and the files it adds next to it; Part A0 froze the signature below and the
 * route keys, permissions and schemas in `@qmentisai/shared`. It registers nothing until Part C fills it.
 * @param {import("./index.js").ReportingRouteDeps} _deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const reportingExportRoutes = (_deps) => async function register(_app) {};
