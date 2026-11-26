import { REPORTING_MESSAGE_TYPES } from "@qmentisai/shared";
import { createReportingDispatcher } from "./dispatch.js";
import { createExportHandler } from "./export/index.js";
import { createRollupHandler } from "./rollup/index.js";

/**
 * The dispatch table of the `reporting` worker, built from the parts' factories. Part A0 owns this file; a part never edits it (it fills its
 * factory in its own directory). A factory that returns null means "not built yet": that type is dead-lettered by the dispatcher.
 * @param {import("./rollup/index.js").ReportingWorkerDeps} deps
 * @returns {ReturnType<typeof createReportingDispatcher>}
 */
export function createReportingHandler(deps) {
  return createReportingDispatcher({
    [REPORTING_MESSAGE_TYPES.ROLLUP_REQUESTED]: createRollupHandler(deps),
    [REPORTING_MESSAGE_TYPES.EXPORT_REQUESTED]: createExportHandler(deps),
  });
}
