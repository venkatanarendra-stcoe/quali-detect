import { USABLE_TENANT_STATUSES } from "@qmentisai/shared";
import { RollupInputError, assertUuid, inTransaction } from "./util.js";

/**
 * Tenant settings, tenant enumeration, pipeline chains and the run ledger (`report_rollup_runs`) of the rollup repository. Reads only the
 * seven views and the report tables; every query carries the tenant.
 */

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const MODES = new Set(["incremental", "close", "backfill"]);

const runOf = (r) => ({
  id: r.id,
  tenantId: r.tenantId,
  day: r.day,
  rangeTo: r.rangeTo ?? null,
  mode: r.mode,
  status: r.status,
  startedAt: r.startedAt,
  finishedAt: r.finishedAt ?? null,
  rowsWritten: Number(r.rowsWritten),
  errorCode: r.errorCode ?? null,
  asOfHistoryId: r.asOfHistoryId ?? null,
  timeZone: r.timeZone,
});

const RUN_COLUMNS = `id::text AS id, tenant_id::text AS "tenantId", to_char(day, 'YYYY-MM-DD') AS day, to_char(range_to, 'YYYY-MM-DD') AS "rangeTo",
  mode, status, started_at AS "startedAt", finished_at AS "finishedAt", rows_written AS "rowsWritten", error_code AS "errorCode",
  as_of_history_id::text AS "asOfHistoryId", time_zone AS "timeZone"`;

/** @param {any} db */
export function buildRuns(db) {
  return {
    /** @param {{ tenantId: string }} args */
    async getTenantSettings({ tenantId }) {
      assertUuid(tenantId, "tenantId");
      const rows = await db.$queryRaw`
        SELECT tenant_id::text AS "tenantId", tenant_status AS status, reporting_timezone AS "timeZone"
        FROM report_tenant_settings_v WHERE tenant_id = ${tenantId}::uuid`;
      return rows[0] ?? null;
    },

    /** @param {{ limit: number, afterTenantId?: string }} args */
    async listActiveTenants({ limit, afterTenantId }) {
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000)
        throw new RollupInputError("invalid_range", "bad page size");
      const after = afterTenantId ? assertUuid(afterTenantId, "afterTenantId") : null;
      const usable = [...USABLE_TENANT_STATUSES];
      return db.$queryRaw`
        SELECT tenant_id::text AS "tenantId", reporting_timezone AS "timeZone"
        FROM report_tenant_settings_v
        WHERE tenant_status = ANY(${usable}::text[]) AND (${after}::uuid IS NULL OR tenant_id > ${after}::uuid)
        ORDER BY tenant_id LIMIT ${limit}::int`;
    },

    /** @param {{ tenantId: string }} args */
    async listPipelineChains({ tenantId }) {
      assertUuid(tenantId, "tenantId");
      const rows = await db.$queryRaw`
        SELECT DISTINCT workspace_id::text AS "workspaceId", repository_id::text AS "repositoryId", pipeline_id::text AS "pipelineId" FROM (
          SELECT workspace_id, repository_id, pipeline_id FROM report_findings_v WHERE tenant_id = ${tenantId}::uuid
          UNION
          SELECT workspace_id, repository_id, pipeline_id FROM report_executions_v WHERE tenant_id = ${tenantId}::uuid
        ) c ORDER BY 3`;
      return rows.map((r) => ({ tenantId, ...r }));
    },

    /** @param {{ tenantId: string }} args */
    async earliestHistoryAt({ tenantId }) {
      assertUuid(tenantId, "tenantId");
      const rows = await db.$queryRaw`
        SELECT min(created_at) AS at FROM report_status_events_v WHERE tenant_id = ${tenantId}::uuid`;
      return rows[0]?.at ?? null;
    },

    /** @param {{ tenantId: string, mode: string, day: string, rangeTo?: string | null, timeZone: string, now: Date }} args */
    async startRun({ tenantId, mode, day, rangeTo = null, timeZone, now }) {
      assertUuid(tenantId, "tenantId");
      if (
        !MODES.has(mode) ||
        !DAY.test(day) ||
        (rangeTo !== null && (!DAY.test(rangeTo) || rangeTo < day))
      )
        throw new RollupInputError("invalid_range", "bad run");
      // the unique slot is (tenant, day, mode, started_at): when a replay starts in the same millisecond, take the next one
      for (let i = 0; i < 20; i += 1) {
        const startedAt = new Date(now.getTime() + i);
        const rows = await db.$queryRawUnsafe(
          `INSERT INTO report_rollup_runs (id, tenant_id, day, range_to, mode, status, started_at, time_zone)
           VALUES (gen_random_uuid(), $1::uuid, $2::date, $3::date, $4, 'running', $5::timestamptz, $6)
           ON CONFLICT (tenant_id, day, mode, started_at) DO NOTHING
           RETURNING ${RUN_COLUMNS}`,
          tenantId,
          day,
          rangeTo,
          mode,
          startedAt,
          timeZone,
        );
        if (rows[0]) return runOf(rows[0]);
      }
      throw new Error("could not allocate a rollup run slot");
    },

    /** @param {{ tenantId: string, runId: string, status: "succeeded" | "failed", rowsWritten: number, errorCode?: string | null, asOfHistoryId?: string | null, now: Date }} args */
    async finishRun({
      tenantId,
      runId,
      status,
      rowsWritten,
      errorCode = null,
      asOfHistoryId = null,
      now,
    }) {
      assertUuid(tenantId, "tenantId");
      assertUuid(runId, "runId");
      if (asOfHistoryId !== null) assertUuid(asOfHistoryId, "asOfHistoryId");
      await inTransaction(
        db,
        (tx) => tx.$executeRaw`
        UPDATE report_rollup_runs SET status = ${status}, finished_at = ${now}::timestamptz, rows_written = ${Math.max(0, Math.trunc(rowsWritten))}::int,
          error_code = ${errorCode}, as_of_history_id = ${asOfHistoryId}::uuid
        WHERE tenant_id = ${tenantId}::uuid AND id = ${runId}::uuid AND status = 'running'`,
      );
    },

    /** @param {{ tenantId: string, mode?: string, status?: string }} args */
    async findLatestRun({ tenantId, mode, status }) {
      assertUuid(tenantId, "tenantId");
      const m = mode ?? null;
      const s = status ?? null;
      const rows = await db.$queryRawUnsafe(
        `SELECT ${RUN_COLUMNS} FROM report_rollup_runs
         WHERE tenant_id = $1::uuid AND ($2::text IS NULL OR mode = $2) AND ($3::text IS NULL OR status = $3)
         ORDER BY started_at DESC, id DESC LIMIT 1`,
        tenantId,
        m,
        s,
      );
      return rows[0] ? runOf(rows[0]) : null;
    },

    /** @param {{ tenantId: string, from: string, to: string, mode?: string }} args */
    async listRuns({ tenantId, from, to, mode }) {
      assertUuid(tenantId, "tenantId");
      if (!DAY.test(from) || !DAY.test(to))
        throw new RollupInputError("invalid_range", "bad day range");
      const rows = await db.$queryRawUnsafe(
        `SELECT ${RUN_COLUMNS} FROM report_rollup_runs
         WHERE tenant_id = $1::uuid AND day <= $3::date AND COALESCE(range_to, day) >= $2::date AND ($4::text IS NULL OR mode = $4)
         ORDER BY started_at DESC, id DESC LIMIT 1000`,
        tenantId,
        from,
        to,
        mode ?? null,
      );
      return rows.map(runOf);
    },
  };
}
