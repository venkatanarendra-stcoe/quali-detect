/**
 * Data access of the export routes that the frozen `createReportingExportsRepository` does not carry (Part C; Prisma stays in repositories).
 * Reads of the reporting VIEWS go through the READ client (`readDb()`, the `qm_reporting_ro` login: select on the views only); everything
 * else is the API's normal client. Every query is scoped by the session's tenant.
 * @param {{ db: any, readDb: () => any }} deps
 */
export function createReportExportSupport({ db, readDb }) {
  return Object.freeze({
    /**
     * Serialises the limit checks of one tenant's export requests (the transaction-scoped advisory lock is released at commit), so two
     * requests cannot both pass "fewer than three running" and then both queue.
     * @param {any} tx @param {string} tenantId
     */
    async lockTenantExports(tx, tenantId) {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`reporting.export:${tenantId}`}, 0))`;
    },

    /** The tenant reporting time zone (UTC when none is set). @param {string} tenantId @returns {Promise<string>} */
    async tenantTimeZone(tenantId) {
      const [row] = await readDb()
        .$queryRaw`SELECT reporting_timezone FROM report_tenant_settings_v WHERE tenant_id = ${tenantId}::uuid`;
      return row?.reporting_timezone ?? "UTC";
    },

    /**
     * The oldest status-history row of the scope (the first instant a point-in-time report can describe), or null when there is none.
     * @param {{ tenantId: string, workspaceId: string | null }} scope @returns {Promise<Date | null>}
     */
    async earliestHistoryAt({ tenantId, workspaceId }) {
      const [row] = await readDb()
        .$queryRaw`SELECT min(created_at) AS at FROM report_status_events_v
          WHERE tenant_id = ${tenantId}::uuid AND (${workspaceId}::uuid IS NULL OR workspace_id = ${workspaceId}::uuid)`;
      return row?.at ?? null;
    },

    /** Workspaces of the tenant (the tenant-wide scope check). @param {string} tenantId */
    workspaceCount: (tenantId) => db.workspace.count({ where: { tenantId } }),

    /** Display names of members of this tenant (never an e-mail). @param {string} tenantId @param {string[]} userIds @returns {Promise<Map<string, string>>} */
    async memberNames(tenantId, userIds) {
      if (userIds.length === 0) return new Map();
      const rows = await db.tenantMembership.findMany({
        where: { tenantId, userId: { in: userIds } },
        select: { user: { select: { id: true, name: true } } },
      });
      return new Map(rows.map((r) => [r.user.id, r.user.name]));
    },
  });
}
