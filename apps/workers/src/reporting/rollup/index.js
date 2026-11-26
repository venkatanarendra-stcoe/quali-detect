/**
 * Part A (rollup core) owns this directory (docs/modules/reporting-dashboards/SPEC.md 7.2, 18). Part A0 froze the two factory signatures below;
 * `../handlers.js` calls them and `../index.js` starts the worker, and neither is edited by a part. Put the code in files next to this one.
 *
 * Until Part A fills them: `createRollupHandler` returns null (the dispatcher dead-letters `reporting.rollup.requested`) and `startRollupTick`
 * returns null (no tick).
 */

/**
 * @typedef {object} ReportingWorkerDeps
 * @property {import("@qmentisai/db").ReportingRollupRepository} rollupRepository built on the WORKER role client (`qm_reporting`)
 * @property {import("@qmentisai/db").ReportingExportWorkerRepository} exportRepository built on the same client
 * @property {any} config the worker configuration (`config.reporting`)
 * @property {any} logger a Pino logger (ids, counts and codes only, never a value)
 * @property {() => Date} [now] a clock (tests)
 */

/**
 * The handler of `reporting.rollup.requested` (idempotent, tenant re-validated by the dispatcher's caller and again from the database).
 * @param {ReportingWorkerDeps} _deps
 * @returns {((message: any, context: { log?: any, attempt?: number, signal?: AbortSignal }) => Promise<void>) | null}
 */
export function createRollupHandler(_deps) {
  return null;
}

/**
 * The hourly tick that enqueues one `reporting.rollup.requested` per active tenant (through the transactional outbox, ADR-011) and the
 * retention purge. Called once after the consumers started; `db` is the shared pool (the outbox write), NOT the restricted client.
 * @param {ReportingWorkerDeps & { db: any }} _deps
 * @returns {{ stop: () => Promise<void> } | null}
 */
export function startRollupTick(_deps) {
  return null;
}
