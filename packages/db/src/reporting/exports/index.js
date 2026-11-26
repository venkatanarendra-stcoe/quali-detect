/**
 * Part C (exports) owns this directory (docs/modules/reporting-dashboards/SPEC.md 7.3, 8.3, 12; ADR-015). The two builders return the methods
 * named in `REPORTING_EXPORT_METHODS` (API side) and `REPORTING_EXPORT_WORKER_METHODS` (worker side) of ../index.js, which Part A0 froze and
 * which is not edited here.
 *
 *  - `api-methods.js`    the run row and its limits (the API's normal client, tenant scoped, transaction aware);
 *  - `worker-methods.js` claim, page, complete, fail, expire (the `qm_reporting` client);
 *  - `datasets.js`       the SQL of every template over the `report_*_v` views (no source table, no rollup table);
 *  - `mappers.js`        row mapping.
 */
export { buildExportMethods } from "./api-methods.js";
export { buildExportWorkerMethods } from "./worker-methods.js";
