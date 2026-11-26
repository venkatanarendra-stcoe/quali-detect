import {
  buildComputeDecisionsDays,
  buildComputeExecutionsDays,
  buildComputeFindingsFlow,
  buildComputeSbomDays,
} from "./flow.js";
import { buildRuns } from "./runs.js";
import { buildComputeFindingsStateAsOf } from "./state.js";
import { buildStore } from "./store.js";

export { RollupInputError, ROLLUP_STATEMENT_TIMEOUT_MS } from "./util.js";

/**
 * The 19 frozen methods of `createReportingRollupRepository` (docs/modules/reporting-dashboards/SPEC.md 7.2, 8; ADR-015). Part A owns this
 * directory. Every method scopes by `tenantId` (never read from a row), uses bind parameters only and reads ONLY the `report_*_v` views and
 * the `report_*` tables (the role cannot read anything else). Optional additions to the frozen signatures (documented in AS_BUILT_A.md):
 * `upsertFindingsDays({ replace })`, `upsert*Days({ replaceDays })`, a `severityExact` flag on state rows and `asOfHistoryId` on the state array.
 * @param {{ db: any }} deps the worker client (`qm_reporting`)
 * @returns {Record<string, (...args: any[]) => any>}
 */
export function buildRollupMethods({ db }) {
  return {
    ...buildRuns(db),
    computeFindingsStateAsOf: buildComputeFindingsStateAsOf(db),
    computeFindingsFlow: buildComputeFindingsFlow(db),
    computeExecutionsDays: buildComputeExecutionsDays(db),
    computeDecisionsDays: buildComputeDecisionsDays(db),
    computeSbomDays: buildComputeSbomDays(db),
    ...buildStore(db),
  };
}
