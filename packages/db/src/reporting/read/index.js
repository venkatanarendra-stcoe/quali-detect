import { buildBreakdownMethods } from "./breakdown-metrics.js";
import { buildFindingsMetricMethods } from "./findings-metrics.js";
import { buildPostureMethods } from "./posture.js";
import { buildQualityMethods } from "./quality-metrics.js";
import { buildScanMetricMethods } from "./scan-metrics.js";

/**
 * Part B (read API) owns this directory: the sixteen methods named in `REPORTING_READ_METHODS` (../index.js, frozen by Part A0). The client is
 * the API READ client (a login member of `qm_reporting_ro`: SELECT on the `report_*_v` views and the `report_*` tables only, read-only
 * transactions, a 5 second statement timeout). Every method takes the tenant from the caller's session and the workspace validated by the
 * authorization layer, scopes EVERY statement by both, and returns plain rows (camelCase); the API mappers shape the DTOs. Read-only:
 * no method writes.
 * @param {{ db: any }} deps the API read client
 * @returns {Record<string, (...args: any[]) => any>}
 */
export function buildReadMethods({ db }) {
  return {
    ...buildPostureMethods(db),
    ...buildFindingsMetricMethods(db),
    ...buildScanMetricMethods(db),
    ...buildQualityMethods(db),
    ...buildBreakdownMethods(db),
  };
}
