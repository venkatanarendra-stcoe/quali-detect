/**
 * The file retention of the exports (docs/modules/reporting-dashboards/SPEC.md 8.6, owner ruling: 30 days): marks the `ready` reports past
 * `expires_at` (and the deleted ones) `expired` and removes their files. The `report_exports` ROW stays until the 13-month purge.
 *
 * Part A0 gave the export part no tick (the hourly `startRollupTick` is Part A's), so this is a function: the export handler calls it after
 * every finished job (bounded, best effort), and the rollup tick may call it once an hour. A file that cannot be removed is logged (ids and
 * code only) and left for the next run of the same function by an operator; the download route already answers 410 for an expired report.
 * @param {{ exportRepository: any, store: { delete: Function }, now?: Date, limit?: number, logger?: any }} deps
 * @returns {Promise<{ expired: number, removed: number }>}
 */
export async function expireReportFiles({
  exportRepository,
  store,
  now = new Date(),
  limit = 100,
  logger,
}) {
  const keys = await exportRepository.expireExports({ now, limit });
  let removed = 0;
  for (const { tenantId, id, objectKey } of keys) {
    const format = objectKey.endsWith(".pdf") ? "pdf" : "csv";
    try {
      await store.delete({ tenantId, reportId: id, format });
      removed += 1;
    } catch {
      logger?.warn(
        { tenantId, reportId: id },
        "reporting export: an expired file could not be removed",
      );
    }
  }
  return { expired: keys.length, removed };
}
