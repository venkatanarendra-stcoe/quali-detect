/**
 * Part C (exports) owns this directory (docs/modules/reporting-dashboards/SPEC.md 7.3, 12, 18). Part A0 froze the factory signature below;
 * `../handlers.js` calls it and `../index.js` starts the worker, and neither is edited by a part. Put the code (CSV writer, pdfkit renderer,
 * object storage) in files next to this one. `pdfkit` is a dependency of the workers package only.
 *
 * Until Part C fills it, `createExportHandler` returns null (the dispatcher dead-letters `reporting.export.requested`).
 */

/**
 * The handler of `reporting.export.requested`: loads the `report_exports` row BY TENANT AND ID (a tenant in the message body is ignored),
 * claims it (`queued` to `running`), checks the row cap BEFORE writing a file, builds the CSV or PDF from the `report_*_v` views only,
 * stores it under `reports/{tenantId}/{reportId}.{ext}` and completes or fails the run with a stable code.
 * @param {import("../rollup/index.js").ReportingWorkerDeps} _deps
 * @returns {((message: any, context: { log?: any, attempt?: number, signal?: AbortSignal }) => Promise<void>) | null}
 */
export function createExportHandler(_deps) {
  return null;
}
