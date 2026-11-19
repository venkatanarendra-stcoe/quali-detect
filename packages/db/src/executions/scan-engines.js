import { Prisma } from "@prisma/client";
import { withTransaction } from "../transaction.js";

/**
 * Data access of the scan-engine ensemble tables (docs/modules/scan-engines/SPEC.md 7.3, part D): `scan_tool_runs` and
 * `scan_result_item_details`. Nothing calls it yet (the scan worker is wired in part K). Every statement is scoped by the TRUSTED
 * tenant: the chain columns of a tool run come from the task row, never from the caller, and a detail row is written only for an
 * item of the same tenant and execution. The database enforces the shapes (CHECK), the attempt fence for tool runs (a zombie
 * attempt is refused), the refusal for terminal executions and insert-only; reads are always by tenant AND parent.
 */

const json = (value) => JSON.stringify(value ?? {});

/**
 * @param {{ db: any }} deps Prisma client
 */
export function createScanToolRunRepository({ db }) {
  return Object.freeze({
    /**
     * Inserts the tool runs of one task attempt (one row per tool). The task must belong to the tenant and the execution; the
     * database refuses an attempt that is not the task's current running attempt (`restrict_violation`).
     * @param {{ tenantId: string, executionId: string, scanTaskId: string, attempt: number, runs: object[] }} input
     * @param {any} [client]
     * @returns {Promise<{ inserted: number }>}
     */
    async insertMany({ tenantId, executionId, scanTaskId, attempt, runs }, client = db) {
      return withTransaction(client, async (tx) => {
        let inserted = 0;
        for (const r of runs) {
          const count = await tx.$executeRaw`
            INSERT INTO scan_tool_runs (id, tenant_id, workspace_id, repository_id, pipeline_id, execution_id, scan_task_id, attempt,
              tool_id, tool_version, image_digest, config_digest, rulepack_digest, db_snapshot_sha256, db_built_at, status, reason,
              exit_code, started_at, finished_at, duration_ms, scope, records_seen, records_dropped, findings_mapped, severity_counts,
              truncated, limits, capacity_wait_ms)
            SELECT gen_random_uuid(), t.tenant_id, t.workspace_id, t.repository_id, t.pipeline_id, t.execution_id, t.id, ${attempt}::int,
              ${r.toolId}, ${r.toolVersion}, ${r.imageDigest ?? null}, ${r.configDigest}, ${r.rulepackDigest ?? null},
              ${r.dbSnapshotSha256 ?? null}, ${r.dbBuiltAt ?? null}::timestamptz, ${r.status}, ${r.reason ?? null}, ${r.exitCode ?? null}::int,
              ${r.startedAt}::timestamptz, ${r.finishedAt}::timestamptz, ${r.durationMs}::int, ${json(r.scope)}::jsonb,
              ${r.recordsSeen ?? 0}::int, ${r.recordsDropped ?? 0}::int, ${r.findingsMapped ?? 0}::int, ${json(r.severityCounts)}::jsonb,
              ${r.truncated ?? false}::boolean, ${json(r.limits)}::jsonb, ${r.capacityWaitMs ?? 0}::int
            FROM scan_tasks t
            WHERE t.tenant_id = ${tenantId}::uuid AND t.id = ${scanTaskId}::uuid AND t.execution_id = ${executionId}::uuid`;
          inserted += count;
        }
        return { inserted };
      });
    },

    /**
     * The tool runs of one task (tenant and execution scoped), ordered by tool.
     * @param {{ tenantId: string, executionId: string, scanTaskId: string, attempt?: number }} input
     * @param {any} [client]
     */
    async listForTask({ tenantId, executionId, scanTaskId, attempt }, client = db) {
      const attemptFilter =
        attempt === undefined ? Prisma.empty : Prisma.sql`AND attempt = ${attempt}::int`;
      return client.$queryRaw`
        SELECT id, scan_task_id AS "scanTaskId", attempt, tool_id AS "toolId", tool_version AS "toolVersion", image_digest AS "imageDigest",
          status, reason, exit_code AS "exitCode", started_at AS "startedAt", finished_at AS "finishedAt", duration_ms AS "durationMs",
          records_seen AS "recordsSeen", records_dropped AS "recordsDropped", findings_mapped AS "findingsMapped",
          severity_counts AS "severityCounts", truncated, capacity_wait_ms AS "capacityWaitMs"
        FROM scan_tool_runs
        WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND scan_task_id = ${scanTaskId}::uuid ${attemptFilter}
        ORDER BY attempt, tool_id`;
    },
  });
}

/**
 * @param {{ db: any }} deps Prisma client
 */
export function createScanResultDetailRepository({ db }) {
  return Object.freeze({
    /**
     * Inserts the detail rows of a result, one per item ordinal. A row is written only when the item exists in this tenant AND
     * execution AND result, so a foreign tenant's ids insert nothing. Returns how many rows were inserted.
     * @param {{ tenantId: string, executionId: string, scanResultId: string, details: (object & { itemOrdinal?: number })[] }} input
     * Item ordinals are the array indexes when `itemOrdinal` is not given.
     * @param {any} [client]
     * @returns {Promise<{ inserted: number }>}
     */
    async insertMany({ tenantId, executionId, scanResultId, details }, client = db) {
      return withTransaction(client, async (tx) => {
        let inserted = 0;
        for (const [index, d] of details.entries()) {
          const ordinal = d.itemOrdinal ?? index;
          inserted += await tx.$executeRaw`
            INSERT INTO scan_result_item_details (tenant_id, execution_id, scan_result_id, item_ordinal, schema_version, dedup_key,
              confidence, confidence_basis, severity_assumed, provenance, advisories, cwe, evidence, scm_ref, url, scope, extra)
            SELECT i.tenant_id, i.execution_id, i.scan_result_id, i.ordinal, ${d.schemaVersion}::int, ${d.dedupKey},
              ${d.confidence}, ${d.confidenceBasis}, ${d.severityAssumed ?? false}::boolean, ${json(d.provenance)}::jsonb,
              ${JSON.stringify(d.advisories ?? [])}::jsonb, ${d.cwe ?? []}::int[],
              ${d.evidence === null || d.evidence === undefined ? null : JSON.stringify(d.evidence)}::jsonb,
              ${d.scmRef === null || d.scmRef === undefined ? null : JSON.stringify(d.scmRef)}::jsonb, ${d.url ?? null},
              ${json(d.scope)}::jsonb, ${json(d.extra)}::jsonb
            FROM scan_result_items i
            WHERE i.tenant_id = ${tenantId}::uuid AND i.execution_id = ${executionId}::uuid AND i.scan_result_id = ${scanResultId}::uuid
              AND i.ordinal = ${ordinal}::int`;
        }
        return { inserted };
      });
    },

    /**
     * The detail rows of one result with the list columns of their items (tenant and execution scoped), by ordinal.
     * @param {{ tenantId: string, executionId: string, scanResultId: string }} input
     * @param {any} [client]
     */
    async listForResult({ tenantId, executionId, scanResultId }, client = db) {
      return client.$queryRaw`
        SELECT d.item_ordinal AS "ordinal", i.kind, i.severity, i.title, i.path, d.dedup_key AS "dedupKey", d.confidence,
          d.confidence_basis AS "confidenceBasis", d.severity_assumed AS "severityAssumed", d.provenance, d.advisories, d.cwe,
          d.evidence, d.scm_ref AS "scmRef", d.url, d.scope, d.extra
        FROM scan_result_item_details d
        JOIN scan_result_items i ON i.tenant_id = d.tenant_id AND i.scan_result_id = d.scan_result_id AND i.ordinal = d.item_ordinal
        WHERE d.tenant_id = ${tenantId}::uuid AND d.execution_id = ${executionId}::uuid AND d.scan_result_id = ${scanResultId}::uuid
        ORDER BY d.item_ordinal`;
    },
  });
}
