/**
 * The report-run DTO (docs/modules/reporting-dashboards/SPEC.md 9, `reportRunDtoSchema` of `@qmentisai/shared`). It NEVER carries the object
 * key, the SHA-256, the params or the requester's e-mail: a client learns the status, the dates, the size and whether it may download.
 * @param {import("@qmentisai/db").ReportExportRow} row
 * @param {{ names: Map<string, string>, at: Date, canDownload: boolean }} context
 */
export function toReportDto(row, { names, canDownload }) {
  return {
    id: row.id,
    template: row.template,
    format: row.format,
    workspaceId: row.workspaceId,
    status: row.status,
    errorCode: row.errorCode,
    period: row.periodFrom && row.periodTo ? { from: row.periodFrom, to: row.periodTo } : null,
    asOfDay: row.asOfDay,
    requestedBy: {
      id: row.requestedByUserId,
      displayName: (names.get(row.requestedByUserId) ?? "Former member").slice(0, 200),
    },
    createdAt: /** @type {Date} */ (row.createdAt).toISOString(),
    startedAt: row.startedAt ? row.startedAt.toISOString() : null,
    finishedAt: row.finishedAt ? row.finishedAt.toISOString() : null,
    expiresAt: row.expiresAt ? row.expiresAt.toISOString() : null,
    bytes: row.bytes,
    rowCount: row.rowCount,
    canDownload,
  };
}
