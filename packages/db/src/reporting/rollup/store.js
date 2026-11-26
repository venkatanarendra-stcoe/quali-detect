import { RollupInputError, UPSERT_BATCH, assertUuid, inTransaction, num } from "./util.js";

/**
 * Writes of the rollup: idempotent upserts keyed by the natural primary key, the range clear and the retention purge (both through the
 * `SECURITY DEFINER` functions of the migration, because the role has no DELETE). Parameters only. A row is re-validated against the
 * tenant of the call (`tenantId` is NEVER taken from a row; a row naming another tenant refuses the whole call) and the composite
 * foreign key (tenant, workspace, repository, pipeline) refuses a mismatched chain in the database.
 *
 * Idempotency: an upsert rewrites a row only when a counter differs (`IS DISTINCT FROM`), so repeating a call changes nothing, not even
 * `computed_at`. The findings table holds two COLUMN GROUPS: the STATE counters (written by a live run) and the FLOW counters; a row
 * carries one group or both, and the upsert touches only the groups the row carries (a backfill of the flow never zeroes a state snapshot).
 */

const FINDINGS_STATE = [
  ["open_count", "openCount"],
  ["backlog_count", "backlogCount"],
  ["wip_count", "wipCount"],
  ["awaiting_verification_count", "awaitingVerificationCount"],
  ["sla_on_track", "slaOnTrack"],
  ["sla_due_soon", "slaDueSoon"],
  ["sla_breached", "slaBreached"],
  ["exceptions_in_force", "exceptionsInForce"],
  ["open_age_seconds_sum", "openAgeSecondsSum"],
];
const FINDINGS_FLOW = [
  ["new_count", "newCount"],
  ["fixed_count", "fixedCount"],
  ["closed_other_count", "closedOtherCount"],
  ["reopened_count", "reopenedCount"],
];
const EXECUTIONS = [
  ["total", "total"],
  ["succeeded_count", "succeededCount"],
  ["failed_count", "failedCount"],
  ["partial_count", "partialCount"],
  ["timed_out_count", "timedOutCount"],
  ["cancelled_count", "cancelledCount"],
  ["skipped_count", "skippedCount"],
  ["blocked_count", "blockedCount"],
  ["duration_ms_sum", "durationMsSum"],
  ["queue_wait_ms_sum", "queueWaitMsSum"],
  ["eligible_count", "eligibleCount"],
  ["result_complete_count", "resultCompleteCount"],
  ["result_partial_count", "resultPartialCount"],
];
const DECISIONS = [
  ["tp_count", "tpCount"],
  ["fp_count", "fpCount"],
  ["with_advisory", "withAdvisory"],
  ["agree_fp", "agreeFp"],
  ["agree_tp", "agreeTp"],
  ["advisory_fp_human_tp", "advisoryFpHumanTp"],
  ["advisory_tp_human_fp", "advisoryTpHumanFp"],
  ["advisory_uncertain", "advisoryUncertain"],
  ["override_confident", "overrideConfident"],
];
const SBOM = [
  ["components", "components"],
  ["components_vulnerable", "componentsVulnerable"],
];

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const SCAN_TYPES = new Set(["sca", "sast", "secrets"]);
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

/**
 * Validates a row (tenant, ids, day, enums, counters as non-negative safe integers) and returns it as the JSON object the statement reads.
 * @param {string} tenantId @param {any} row @param {Array<[string, string]>} fields @param {{ scanType?: boolean, severity?: boolean }} keys
 */
function toJson(tenantId, row, fields, keys) {
  if (!row || typeof row !== "object")
    throw new RollupInputError("invalid_range", "row is not an object");
  if (row.tenantId !== undefined && row.tenantId !== tenantId)
    throw new RollupInputError("ownership_mismatch", "a row names another tenant");
  const out = {
    workspace_id: assertUuid(row.workspaceId, "workspaceId"),
    repository_id: assertUuid(row.repositoryId, "repositoryId"),
    pipeline_id: assertUuid(row.pipelineId, "pipelineId"),
    day: row.day,
  };
  if (typeof out.day !== "string" || !DAY.test(out.day))
    throw new RollupInputError("invalid_range", "row day is not a day");
  if (keys.scanType) {
    if (!SCAN_TYPES.has(row.scanType)) throw new RollupInputError("invalid_range", "bad scan type");
    out.scan_type = row.scanType;
  }
  if (keys.severity) {
    if (!SEVERITIES.has(row.severity)) throw new RollupInputError("invalid_range", "bad severity");
    out.severity = row.severity;
  }
  for (const [col, key] of fields) {
    const v = row[key];
    if (!Number.isSafeInteger(v) || v < 0)
      throw new RollupInputError("invalid_range", `counter ${key} is not a non-negative integer`);
    out[col] = v;
  }
  return out;
}

const COLUMN_TYPE = (col) => (col.endsWith("_sum") ? "bigint" : "integer");

/**
 * One generic idempotent upsert statement over a table. `table` and the column names are CONSTANTS of this file (never input).
 * @param {any} tx @param {string} tenantId @param {{ table: string, key: string[], keyTypes: Record<string, string>, cols: string[] }} spec @param {any[]} rows
 */
async function upsertRows(tx, tenantId, spec, rows) {
  if (rows.length === 0) return 0;
  const { table, key, keyTypes, cols } = spec;
  const allKeys = ["workspace_id", "repository_id", ...key.filter((k) => k !== "tenant_id")];
  const colDefs = [...new Set([...allKeys, ...cols])].map(
    (c) => `${c} ${keyTypes[c] ?? COLUMN_TYPE(c)}`,
  );
  const insertCols = ["tenant_id", ...new Set([...allKeys, ...cols])];
  const selectCols = insertCols.map((c) => (c === "tenant_id" ? "$2::uuid" : `x.${c}`));
  const setList = cols.map((c) => `${c} = EXCLUDED.${c}`).join(", ");
  const distinct = `(${cols.map((c) => `t.${c}`).join(", ")}) IS DISTINCT FROM (${cols.map((c) => `EXCLUDED.${c}`).join(", ")})`;
  const sql = `INSERT INTO ${table} AS t (${insertCols.join(", ")}, computed_at)
    SELECT ${selectCols.join(", ")}, now() FROM jsonb_to_recordset($1::jsonb) AS x(${colDefs.join(", ")})
    ON CONFLICT (${key.join(", ")}) DO UPDATE SET ${setList}, computed_at = now() WHERE ${distinct}`;
  let written = 0;
  for (let i = 0; i < rows.length; i += UPSERT_BATCH)
    written += await tx.$executeRawUnsafe(
      sql,
      JSON.stringify(rows.slice(i, i + UPSERT_BATCH)),
      tenantId,
    );
  return written;
}

const UUID_TYPES = {
  workspace_id: "uuid",
  repository_id: "uuid",
  pipeline_id: "uuid",
  day: "date",
  scan_type: "finding_scan_type",
  severity: "finding_severity",
};

/** Splits a findings row set into the rows carrying the state group and those carrying the flow group. */
const hasAll = (row, fields) => fields.every(([, key]) => row[key] !== undefined);

/**
 * Zeroes the counters of the rows of `days` that are NOT in `json` (a combination that has no data any more must read zero), only where
 * they are not zero already. Runs AFTER the upsert, so a repeated call writes nothing at all.
 */
async function zeroStale(tx, tenantId, table, key, fields, json, days) {
  for (const d of days)
    if (!DAY.test(d)) throw new RollupInputError("invalid_range", "bad replace day");
  const k = key.filter((c) => c !== "tenant_id");
  const keyDefs = k.map((c) => `${c} ${UUID_TYPES[c]}`).join(", ");
  const on = k.map((c) => `fresh.${c} = t.${c}`).join(" AND ");
  const set = fields.map(([c]) => `${c} = 0`).join(", ");
  const nonZero = fields.map(([c]) => `t.${c} <> 0`).join(" OR ");
  return tx.$executeRawUnsafe(
    `UPDATE ${table} t SET ${set}, computed_at = now()
     WHERE t.tenant_id = $1::uuid AND t.day = ANY($2::date[]) AND (${nonZero})
       AND NOT EXISTS (SELECT 1 FROM jsonb_to_recordset($3::jsonb) AS fresh(${keyDefs}) WHERE ${on})`,
    tenantId,
    days,
    JSON.stringify(json.map((r) => Object.fromEntries(k.map((c) => [c, r[c]])))),
  );
}

/**
 * @param {any} db the worker client
 */
export function buildStore(db) {
  /** @param {{ tenantId: string, rows: any[], replace?: { days: string[], groups: Array<"state" | "flow"> } }} args */
  async function upsertFindingsDays({ tenantId, rows, replace }) {
    assertUuid(tenantId, "tenantId");
    const state = [];
    const flow = [];
    for (const row of rows) {
      if (hasAll(row, FINDINGS_STATE))
        state.push(toJson(tenantId, row, FINDINGS_STATE, { scanType: true, severity: true }));
      if (hasAll(row, FINDINGS_FLOW))
        flow.push(toJson(tenantId, row, FINDINGS_FLOW, { scanType: true, severity: true }));
      if (!hasAll(row, FINDINGS_STATE) && !hasAll(row, FINDINGS_FLOW))
        throw new RollupInputError("invalid_range", "a findings row carries neither counter group");
    }
    const table = "report_daily_findings";
    const key = ["tenant_id", "pipeline_id", "day", "scan_type", "severity"];
    return inTransaction(db, async (tx) => {
      let written = 0;
      for (const [group, fields, json] of [
        ["state", FINDINGS_STATE, state],
        ["flow", FINDINGS_FLOW, flow],
      ]) {
        written += await upsertRows(
          tx,
          tenantId,
          { table, key, keyTypes: UUID_TYPES, cols: fields.map(([c]) => c) },
          json,
        );
        if (replace?.groups?.includes(group))
          written += await zeroStale(tx, tenantId, table, key, fields, json, replace.days ?? []);
      }
      return written;
    });
  }

  const simple =
    (table, key, fields, keys) =>
    async ({ tenantId, rows, replaceDays }) => {
      assertUuid(tenantId, "tenantId");
      const json = rows.map((r) => toJson(tenantId, r, fields, keys));
      return inTransaction(db, async (tx) => {
        let written = await upsertRows(
          tx,
          tenantId,
          { table, key, keyTypes: UUID_TYPES, cols: fields.map(([c]) => c) },
          json,
        );
        if (replaceDays?.length)
          written += await zeroStale(tx, tenantId, table, key, fields, json, replaceDays);
        return written;
      });
    };

  return {
    upsertFindingsDays,
    upsertExecutionsDays: simple(
      "report_daily_executions",
      ["tenant_id", "pipeline_id", "day"],
      EXECUTIONS,
      {},
    ),
    upsertDecisionsDays: simple(
      "report_daily_decisions",
      ["tenant_id", "pipeline_id", "day", "scan_type"],
      DECISIONS,
      { scanType: true },
    ),
    upsertSbomDays: simple("report_daily_sbom", ["tenant_id", "pipeline_id", "day"], SBOM, {}),

    /**
     * Removes the daily rows of the range (the SECURITY DEFINER function). With `voidCoverage` (the REBUILD after a tenant time-zone change)
     * it ALSO voids the run-ledger coverage of the range in the same transaction: every succeeded run that touches a cleared day is marked
     * `failed` / `invalid_range` (the role has UPDATE on the ledger, never DELETE), so the days it covered read as NULL again (not as
     * covered zeros) until a run that is written after the clear covers them. Voiding is whole-run: a backfill batch that sticks out of
     * the range loses its coverage outside it too (a gap is honest, a false zero is not). Without the flag nothing but the rows changes.
     * @param {{ tenantId: string, from: string, to: string, voidCoverage?: boolean }} args
     */
    async clearRange({ tenantId, from, to, voidCoverage = false }) {
      assertUuid(tenantId, "tenantId");
      if (!DAY.test(from) || !DAY.test(to) || from > to)
        throw new RollupInputError("invalid_range", "bad day range");
      const rows = await inTransaction(db, async (tx) => {
        const cleared =
          await tx.$queryRaw`SELECT qm_reporting_clear_range(${tenantId}::uuid, ${from}::date, ${to}::date) AS n`;
        if (voidCoverage === true)
          await tx.$executeRaw`
            UPDATE report_rollup_runs SET status = 'failed', error_code = 'invalid_range'
            WHERE tenant_id = ${tenantId}::uuid AND status = 'succeeded'
              AND day <= ${to}::date AND COALESCE(range_to, day) >= ${from}::date`;
        return cleared;
      });
      return num(rows[0]?.n);
    },

    /** @param {{ rollupBefore: string, runsBefore: Date, exportsBefore: Date, limit: number }} args */
    async purgeExpired({ rollupBefore, runsBefore, exportsBefore, limit }) {
      if (!DAY.test(rollupBefore)) throw new RollupInputError("invalid_range", "bad cutoff day");
      if (!(runsBefore instanceof Date) || !(exportsBefore instanceof Date))
        throw new RollupInputError("invalid_range", "bad cutoff instant");
      if (!Number.isInteger(limit) || limit < 1 || limit > 100000)
        throw new RollupInputError("invalid_range", "bad purge limit");
      const rows = await inTransaction(
        db,
        (tx) =>
          tx.$queryRaw`SELECT qm_reporting_purge(${rollupBefore}::date, ${runsBefore}::timestamptz, ${exportsBefore}::timestamptz, ${limit}::int) AS n`,
      );
      return num(rows[0]?.n);
    },
  };
}
