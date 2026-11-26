/**
 * Data access of the tenant reporting time zone (`tenant_reporting_settings`, AS_BUILT_TZ.md). The API writes this table with its normal
 * client (it is not a role-restricted rollup table). Every query carries the tenant id of the session.
 * @param {{ db: any }} deps
 */
export function createReportingSettingsRepository({ db }) {
  return Object.freeze({
    /** Serialises the changes of ONE tenant's zone (released at commit), so two requests cannot both read the old zone. @param {any} tx @param {string} tenantId */
    async lockTenant(tx, tenantId) {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`reporting.settings:${tenantId}`}, 0))`;
    },

    /** @param {string} tenantId @param {any} [client] */
    findSettings: (tenantId, client = db) =>
      client.tenantReportingSettings.findUnique({ where: { tenantId } }),

    /**
     * Stores the zone (insert or replace). Tenant and actor come from the session.
     * @param {{ tenantId: string, zone: string, userId: string, now: Date }} input @param {any} tx
     */
    upsertZone: ({ tenantId, zone, userId, now }, tx) =>
      tx.tenantReportingSettings.upsert({
        where: { tenantId },
        create: { tenantId, reportingTimezone: zone, updatedByUserId: userId, updatedAt: now },
        update: { reportingTimezone: zone, updatedByUserId: userId, updatedAt: now },
      }),

    /** The oldest status-history instant of the tenant, or null. @param {string} tenantId @param {any} tx @returns {Promise<Date | null>} */
    async earliestHistoryAt(tenantId, tx) {
      const [row] =
        await tx.$queryRaw`SELECT min(created_at) AS at FROM finding_status_history WHERE tenant_id = ${tenantId}::uuid`;
      return row?.at ?? null;
    },

    /** Display name of a member of THIS tenant (never an e-mail), or null. @param {string} tenantId @param {string | null} userId */
    async memberName(tenantId, userId) {
      if (!userId) return null;
      const row = await db.tenantMembership.findFirst({
        where: { tenantId, userId },
        select: { user: { select: { name: true } } },
      });
      return row?.user?.name ?? null;
    },

    /** Workspaces of the tenant (their cache epochs are bumped on a change). @param {string} tenantId @returns {Promise<string[]>} */
    async workspaceIds(tenantId) {
      const rows = await db.workspace.findMany({ where: { tenantId }, select: { id: true } });
      return rows.map((r) => r.id);
    },

    /**
     * Whether a rebuild after `since` has finished: a succeeded backfill run of the tenant in `zone`, started at or after `since`, whose
     * range reaches `reachesDay` (a YYYY-MM-DD day).
     * @param {{ tenantId: string, zone: string, since: Date, reachesDay: string }} input
     */
    async hasFinishedRebuild({ tenantId, zone, since, reachesDay }) {
      const row = await db.reportRollupRun.findFirst({
        where: {
          tenantId,
          mode: "backfill",
          status: "succeeded",
          timeZone: zone,
          startedAt: { gte: since },
          rangeTo: { gte: new Date(`${reachesDay}T00:00:00.000Z`) },
        },
        select: { id: true },
      });
      return row !== null;
    },
  });
}
