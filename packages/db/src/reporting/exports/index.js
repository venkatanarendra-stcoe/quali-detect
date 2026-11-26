/**
 * Part C (exports) owns this directory: write the methods named in `REPORTING_EXPORT_METHODS` (API side) and
 * `REPORTING_EXPORT_WORKER_METHODS` (worker side) of ../index.js here and return them from the two builders. Do not edit ../index.js.
 * Until Part C fills it the frozen methods reject with `ReportingNotImplementedError`.
 */

/**
 * @param {{ db: any }} deps the API's normal client
 * @returns {Record<string, (...args: any[]) => any>}
 */
export function buildExportMethods({ db: _db }) {
  return {};
}

/**
 * @param {{ db: any }} deps the worker client (`qm_reporting`)
 * @returns {Record<string, (...args: any[]) => any>}
 */
export function buildExportWorkerMethods({ db: _db }) {
  return {};
}
