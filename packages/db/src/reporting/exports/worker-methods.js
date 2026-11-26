import { Prisma } from "@prisma/client";
import { REPORT_FAILURE_CODES } from "@qmentisai/shared";
import {
  CSV_DATASET,
  countDataset,
  countDatasetOf,
  datasetContext,
  readDatasetPage,
} from "./datasets.js";
import { toExportRow } from "./mappers.js";

const S = Prisma.sql;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** The only object key a report may have: `reports/<tenant>/<id>.<csv|pdf>` (the database repeats it as a CHECK). */
const OBJECT_KEY = /^reports\/[0-9a-f-]{36}\/[0-9a-f-]{36}\.(?:csv|pdf)$/;

/** @param {string} tenantId @param {string} id */
function assertIds(tenantId, id) {
  if (!UUID.test(String(tenantId)) || (id !== undefined && !UUID.test(String(id))))
    throw new TypeError("Invalid report reference.");
}

/**
 * The worker side of an export (the client of `qm_reporting`): claim, read the views, complete or fail, expire. A report is always loaded by
 * TENANT AND ID, the tenant coming from the verified message envelope, never from a payload. The role can read the `report_*_v` views and
 * the `report_*` tables and nothing else, so a source table (evidence, rationale, comment, advisory reasoning) is unreachable from here.
 * @param {{ db: any }} deps the worker client
 * @returns {Record<string, (...args: any[]) => any>}
 */
export function buildExportWorkerMethods({ db }) {
  /** The tenant reporting time zone rides on the row the worker loads (the worker has no other way to learn it). */
  const withZone = async (row) => {
    if (!row) return null;
    const mapped = toExportRow(row);
    const [zone] = await db.$queryRaw(
      S`SELECT reporting_timezone FROM report_tenant_settings_v WHERE tenant_id = ${mapped.tenantId}::uuid`,
    );
    return { ...mapped, timeZone: zone?.reporting_timezone ?? "UTC" };
  };

  return {
    async claimExport({ tenantId, id, now }) {
      assertIds(tenantId, id);
      const rows = await db.$queryRaw(
        S`UPDATE report_exports SET status = 'running', started_at = ${now}::timestamptz
          WHERE tenant_id = ${tenantId}::uuid AND id = ${id}::uuid AND status = 'queued' AND deleted_at IS NULL
          RETURNING *`,
      );
      return withZone(rows[0]);
    },

    async getExportForWorker({ tenantId, id }) {
      assertIds(tenantId, id);
      const rows = await db.$queryRaw(
        S`SELECT * FROM report_exports WHERE tenant_id = ${tenantId}::uuid AND id = ${id}::uuid`,
      );
      return withZone(rows[0]);
    },

    async countExportRows(args) {
      assertIds(args.tenantId);
      const c = datasetContext(args);
      return countDataset(db, c, args.template, countDatasetOf(args.template));
    },

    async readExportPage(args) {
      assertIds(args.tenantId);
      const c = datasetContext(args);
      const dataset = typeof args.params?.dataset === "string" ? args.params.dataset : CSV_DATASET;
      return readDatasetPage(db, c, args.template, dataset, args.after ?? null, args.limit);
    },

    async completeExport({ tenantId, id, objectKey, bytes, sha256, rowCount, expiresAt, now }) {
      assertIds(tenantId, id);
      if (!OBJECT_KEY.test(objectKey) || !objectKey.includes(`/${tenantId}/${id}.`))
        throw new TypeError("Invalid object key.");
      const changed = await db.$executeRaw(
        S`UPDATE report_exports
          SET status = 'ready', object_key = ${objectKey}, bytes = ${BigInt(bytes)}, sha256 = ${sha256},
              row_count = ${rowCount}::int, expires_at = ${expiresAt}::timestamptz, finished_at = ${now}::timestamptz
          WHERE tenant_id = ${tenantId}::uuid AND id = ${id}::uuid AND status = 'running'`,
      );
      return changed > 0;
    },

    async failExport({ tenantId, id, errorCode, now }) {
      assertIds(tenantId, id);
      const code = REPORT_FAILURE_CODES.includes(errorCode) ? errorCode : "internal";
      const changed = await db.$executeRaw(
        S`UPDATE report_exports SET status = 'failed', error_code = ${code}, finished_at = ${now}::timestamptz
          WHERE tenant_id = ${tenantId}::uuid AND id = ${id}::uuid AND status IN ('queued', 'running')`,
      );
      return changed > 0;
    },

    async expireExports({ now, limit }) {
      const rows = await db.$queryRaw(
        S`UPDATE report_exports e SET status = 'expired'
          FROM (
            SELECT tenant_id, id FROM report_exports
            WHERE status = 'ready' AND object_key IS NOT NULL AND (expires_at <= ${now}::timestamptz OR deleted_at IS NOT NULL)
            ORDER BY expires_at LIMIT ${limit}::int FOR UPDATE SKIP LOCKED
          ) x
          WHERE e.tenant_id = x.tenant_id AND e.id = x.id
          RETURNING e.tenant_id, e.id, e.object_key`,
      );
      return rows.map((r) => ({ tenantId: r.tenant_id, id: r.id, objectKey: r.object_key }));
    },
  };
}
