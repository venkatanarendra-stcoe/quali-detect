import { Prisma } from "@prisma/client";
import { detailExtraSchema } from "@qmentisai/shared";
import { withTransaction } from "../transaction.js";

/**
 * Data access of the scan-engine ensemble tables (docs/modules/scan-engines/SPEC.md 7.3, part D): `scan_tool_runs` and
 * `scan_result_item_details`. The ensemble engine's results reach it through `finishTask` / `requeueTask` (part K core); a run may carry its own `id` (a UUID, so a finding's `rawRef.toolRunId` points at the row). Every statement is scoped by the TRUSTED
 * tenant: the chain columns of a tool run come from the task row, never from the caller, and a detail row is written only for an
 * item of the same tenant and execution. The database enforces the shapes (CHECK), the attempt fence for tool runs (a zombie
 * attempt is refused), the refusal for terminal executions and insert-only; reads are always by tenant AND parent.
 */

const json = (value) => JSON.stringify(value ?? {});
const nullableJson = (value) =>
  value === null || value === undefined ? null : JSON.stringify(value);

/**
 * Rows per statement of the batched detail insert. A statement carries one array parameter per column (17 bind parameters, far
 * below the Postgres limit of 65535 whatever the batch size), so the size only bounds one statement's payload (typically a few
 * MiB; at most 16 MiB at the 16 KiB row ceiling) and its running time. The 15 s budget of the surrounding transaction is spent
 * mostly on the per-row constraint and trigger work of the database, which batching does not change (SPEC scan-engines 17.f).
 */
export const DETAIL_INSERT_BATCH = 1000;

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
            SELECT COALESCE(${r.id ?? null}::uuid, gen_random_uuid()), t.tenant_id, t.workspace_id, t.repository_id, t.pipeline_id, t.execution_id, t.id, ${attempt}::int,
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

/** Rows per statement of the batched item insert (an item row is at most about 6 KiB; one JSON parameter per statement). */
export const ITEM_INSERT_BATCH = 2000;

const ITEM_KEYS = Object.freeze([
  "kind",
  "ruleId",
  "severity",
  "title",
  "path",
  "startLine",
  "endLine",
  "componentPurl",
  "componentVersion",
  "data",
]);

/**
 * @param {{ db: any }} deps Prisma client
 */
export function createScanResultItemRepository({ db }) {
  return Object.freeze({
    /**
     * Inserts the items of ONE result, ordinals 0..n-1 in array order, in batches of `ITEM_INSERT_BATCH` rows (one statement per
     * batch, one JSON parameter each: this replaces a Prisma `createMany` whose per-row cost exceeded the transaction budget for
     * a full-cap result). The tenant, execution and result columns of every row are copied from the RESULT row selected under the
     * three trusted predicates, never from the caller, so a foreign tenant's ids insert nothing. An item with a key outside the
     * item shape is refused before anything is written. The caller's transaction holds all batches.
     * @param {{ tenantId: string, executionId: string, scanResultId: string, items: Record<string, any>[] }} input
     * @param {any} [client]
     * @returns {Promise<{ inserted: number }>}
     */
    async insertMany({ tenantId, executionId, scanResultId, items }, client = db) {
      for (const item of items)
        for (const key of Object.keys(item))
          if (!ITEM_KEYS.includes(key)) throw new TypeError(`an item has an unknown field: ${key}`);
      return withTransaction(client, async (tx) => {
        let inserted = 0;
        for (let from = 0; from < items.length; from += ITEM_INSERT_BATCH) {
          const payload = JSON.stringify(
            items.slice(from, from + ITEM_INSERT_BATCH).map((item, offset) => ({
              ordinal: from + offset,
              kind: item.kind,
              rule_id: item.ruleId ?? undefined,
              severity: item.severity,
              title: item.title,
              path: item.path ?? undefined,
              start_line: item.startLine ?? undefined,
              end_line: item.endLine ?? undefined,
              component_purl: item.componentPurl ?? undefined,
              component_version: item.componentVersion ?? undefined,
              data: item.data ?? {},
            })),
          );
          inserted += await tx.$executeRaw`
            INSERT INTO scan_result_items (id, tenant_id, execution_id, scan_result_id, ordinal, kind, rule_id, severity, title, path,
              start_line, end_line, component_purl, component_version, data)
            SELECT gen_random_uuid(), r.tenant_id, r.execution_id, r.id, u.ordinal, u.kind, u.rule_id, u.severity, u.title, u.path,
              u.start_line, u.end_line, u.component_purl, u.component_version, u.data
            FROM jsonb_to_recordset(${payload}::jsonb) AS u(ordinal int, kind text, rule_id text, severity text, title text, path text,
              start_line int, end_line int, component_purl text, component_version text, data jsonb)
            CROSS JOIN scan_results r
            WHERE r.tenant_id = ${tenantId}::uuid AND r.execution_id = ${executionId}::uuid AND r.id = ${scanResultId}::uuid
            ORDER BY u.ordinal`;
        }
        return { inserted };
      });
    },
  });
}

/**
 * @param {{ db: any }} deps Prisma client
 */
export function createScanResultDetailRepository({ db }) {
  return Object.freeze({
    /**
     * Inserts the detail rows of a result, one per item ordinal, in BATCHES of `DETAIL_INSERT_BATCH` rows (one statement per batch:
     * `unnest` of one parameter array per column, so a statement carries 16 bind parameters however many rows it writes and the
     * Postgres limit of 65535 is never near). A row is written only when the item exists in this tenant AND execution AND result
     * (the statement selects FROM the item table under the three trusted predicates), so a foreign tenant's ids insert nothing.
     * Every row is validated BEFORE the first statement, so an invalid row inserts nothing. Returns how many rows were inserted.
     * The caller's transaction (finishTask) holds all batches: a failing batch rolls everything back.
     * @param {{ tenantId: string, executionId: string, scanResultId: string, details: (object & { itemOrdinal?: number })[] }} input
     * Item ordinals are the array indexes when `itemOrdinal` is not given.
     * @param {any} [client]
     * @returns {Promise<{ inserted: number }>}
     */
    async insertMany({ tenantId, executionId, scanResultId, details }, client = db) {
      // `extra` is validated at write time (strict, bounded; the database CHECK refuses credential shapes)
      const rows = details.map((d, index) => ({
        d,
        ordinal: d.itemOrdinal ?? index,
        extra: d.extra === undefined ? {} : detailExtraSchema.parse(d.extra),
      }));
      return withTransaction(client, async (tx) => {
        let inserted = 0;
        for (let from = 0; from < rows.length; from += DETAIL_INSERT_BATCH) {
          const batch = rows.slice(from, from + DETAIL_INSERT_BATCH);
          // ONE bind parameter per statement: the rows as a JSON array (absent key = SQL NULL), read by `jsonb_to_recordset`
          const payload = JSON.stringify(
            batch.map((r) => ({
              ordinal: r.ordinal,
              schema_version: r.d.schemaVersion,
              dedup_key: r.d.dedupKey,
              confidence: r.d.confidence,
              confidence_basis: r.d.confidenceBasis,
              severity_assumed: r.d.severityAssumed ?? false,
              provenance: r.d.provenance ?? {},
              advisories: r.d.advisories ?? [],
              cwe: r.d.cwe ?? [],
              evidence: r.d.evidence ?? undefined,
              scm_ref: r.d.scmRef ?? undefined,
              url: r.d.url ?? undefined,
              scope: r.d.scope ?? {},
              extra: r.extra,
            })),
          );
          inserted += await tx.$executeRaw`
            INSERT INTO scan_result_item_details (tenant_id, execution_id, scan_result_id, item_ordinal, schema_version, dedup_key,
              confidence, confidence_basis, severity_assumed, provenance, advisories, cwe, evidence, scm_ref, url, scope, extra)
            SELECT i.tenant_id, i.execution_id, i.scan_result_id, i.ordinal, u.schema_version, u.dedup_key,
              u.confidence, u.confidence_basis, u.severity_assumed, u.provenance, u.advisories,
              ARRAY(SELECT jsonb_array_elements_text(u.cwe)::int), u.evidence, u.scm_ref, u.url, u.scope, u.extra
            FROM jsonb_to_recordset(${payload}::jsonb) AS u(ordinal int, schema_version int, dedup_key text, confidence text,
              confidence_basis text, severity_assumed boolean, provenance jsonb, advisories jsonb, cwe jsonb, evidence jsonb,
              scm_ref jsonb, url text, scope jsonb, extra jsonb)
            JOIN scan_result_items i ON i.ordinal = u.ordinal
            WHERE i.tenant_id = ${tenantId}::uuid AND i.execution_id = ${executionId}::uuid AND i.scan_result_id = ${scanResultId}::uuid
            ORDER BY u.ordinal`;
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
