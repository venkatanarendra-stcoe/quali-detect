/**
 * Row mappers of the report-export repositories: plain camelCase rows, `DATE` columns as `YYYY-MM-DD` strings, `bigint` as a number.
 * Nothing here is exposed to a client: the API mapper (`apps/api/.../mappers/export.js`) hides `objectKey` and `sha256`.
 */

/** @param {Date | string | null | undefined} value @returns {string | null} */
export const dayOf = (value) => {
  if (value === null || value === undefined) return null;
  return (value instanceof Date ? value.toISOString() : String(value)).slice(0, 10);
};

/** @param {Date | string | null | undefined} value @returns {Date | null} */
const instant = (value) => (value === null || value === undefined ? null : new Date(value));

/**
 * A `report_exports` row from Prisma (camelCase) or from raw SQL (snake_case) to the frozen `ReportExportRow` shape.
 * @param {Record<string, any>} r
 * @returns {import("../index.js").ReportExportRow}
 */
export function toExportRow(r) {
  const pick = (camel, snake) => (r[camel] !== undefined ? r[camel] : r[snake]);
  const bytes = pick("bytes", "bytes");
  return {
    id: r.id,
    tenantId: pick("tenantId", "tenant_id"),
    workspaceId: pick("workspaceId", "workspace_id") ?? null,
    template: r.template,
    format: r.format,
    params: r.params ?? {},
    periodFrom: dayOf(pick("periodFrom", "period_from")),
    periodTo: dayOf(pick("periodTo", "period_to")),
    asOfDay: dayOf(pick("asOfDay", "as_of_day")),
    status: r.status,
    errorCode: pick("errorCode", "error_code") ?? null,
    requestedByUserId: pick("requestedByUserId", "requested_by_user_id"),
    createdAt: instant(pick("createdAt", "created_at")),
    startedAt: instant(pick("startedAt", "started_at")),
    finishedAt: instant(pick("finishedAt", "finished_at")),
    expiresAt: instant(pick("expiresAt", "expires_at")),
    objectKey: pick("objectKey", "object_key") ?? null,
    bytes: bytes === null || bytes === undefined ? null : Number(bytes),
    sha256: r.sha256 ?? null,
    rowCount: pick("rowCount", "row_count") ?? null,
    deletedAt: instant(pick("deletedAt", "deleted_at")),
  };
}
