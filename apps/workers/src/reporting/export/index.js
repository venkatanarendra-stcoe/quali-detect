import { buildExportHandler } from "./handler.js";
import { createReportObjectStore } from "./object-store.js";
import { expireReportFiles } from "./retention.js";

export { buildExportHandler, failureCodeOf } from "./handler.js";
export { createCsvStream, csvColumnsFor } from "./csv-writer.js";
export { createReportObjectStore, reportObjectKey } from "./object-store.js";
export { expireReportFiles } from "./retention.js";
export { ReportTooLargeError, createPdfReport } from "./pdf-kit.js";

/**
 * Part C (exports) owns this directory (docs/modules/reporting-dashboards/SPEC.md 7.3, 12, 18). Part A0 froze the factory signature below;
 * `../handlers.js` calls it and `../index.js` starts the worker.
 *
 * The handler of `reporting.export.requested`: loads the `report_exports` row BY TENANT AND ID (a tenant in the message body is refused),
 * claims it (`queued` to `running`), checks the row cap BEFORE writing a file, builds the CSV or PDF from the `report_*_v` views only,
 * stores it under `reports/{tenantId}/{reportId}.{ext}` and completes or fails the run with a stable code. After each job it also runs the
 * bounded file-retention pass (`expireReportFiles`). Returns null (the dispatcher dead-letters the message) when the artifact store root is
 * not configured: a report cannot be stored anywhere, and acknowledging the message would lose it.
 * @param {import("../rollup/index.js").ReportingWorkerDeps} deps
 * @returns {((message: any, context: { log?: any, attempt?: number, signal?: AbortSignal }) => Promise<void>) | null}
 */
export function createExportHandler(deps) {
  const root = deps.config?.execution?.artifactStoreRoot ?? null;
  if (!root) {
    deps.logger?.warn(
      "reporting export: ARTIFACT_STORE_ROOT is not set, so exports cannot be stored; the export handler is not built (messages are dead-lettered)",
    );
    return null;
  }
  const store = createReportObjectStore({ root });
  const handle = buildExportHandler({ ...deps, store });
  return async (message, context) => {
    await handle(message, context);
    await expireReportFiles({
      exportRepository: deps.exportRepository,
      store,
      now: deps.now?.() ?? new Date(),
      limit: 50,
      logger: context?.log ?? deps.logger,
    }).catch((error) =>
      (context?.log ?? deps.logger)?.warn(
        { code: error?.code },
        "reporting export: the retention pass failed",
      ),
    );
  };
}
