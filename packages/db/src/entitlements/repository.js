/**
 * Reads entitlement and quota configuration and updates usage. Tenant-scoped reads carry the tenantId; the catalog and
 * quota definitions are platform data. Usage is changed only by atomic conditional SQL.
 * @param {{ db: any }} deps `db` is the default client; every function takes an optional `client` (a Prisma client or an
 * interactive-transaction client) used for ALL its queries, including the raw SQL of consume/release.
 */
export function createEntitlementRepository({ db }) {
  return Object.freeze({
    findCatalogEntry: (key, client = db) =>
      client.entitlementCatalog.findUnique({ where: { key } }),
    findTenantEntitlement: ({ tenantId, entitlementId }, client = db) =>
      client.tenantEntitlement.findUnique({
        where: { tenantId_entitlementId: { tenantId, entitlementId } },
      }),
    /** The entitlement as granted by the tenant's current usable subscription (trial/active, within its dates). */
    async findPlanEntitlement({ tenantId, entitlementId, now }, client = db) {
      const subscription = await client.tenantSubscription.findFirst({
        where: {
          tenantId,
          status: { in: ["trial", "active"] },
          startsAt: { lte: now },
          OR: [{ endsAt: null }, { endsAt: { gt: now } }],
        },
        orderBy: { startsAt: "desc" },
        select: { planVersionId: true },
      });
      if (!subscription) return null;
      return client.planEntitlement.findUnique({
        where: {
          planVersionId_entitlementId: { planVersionId: subscription.planVersionId, entitlementId },
        },
      });
    },
    findQuotaDefinition: (key, client = db) =>
      client.quotaDefinition.findUnique({ where: { key } }),
    findTenantQuota: ({ tenantId, quotaDefinitionId }, client = db) =>
      client.tenantQuota.findUnique({
        where: { tenantId_quotaDefinitionId: { tenantId, quotaDefinitionId } },
      }),
    async findUsage({ tenantId, quotaDefinitionId, periodKey }, client = db) {
      const row = await client.tenantQuotaUsage.findUnique({
        where: { tenantId_quotaDefinitionId_periodKey: { tenantId, quotaDefinitionId, periodKey } },
      });
      return row ? Number(row.used) : 0;
    },
    /**
     * Adds `amount` to usage only if the result stays within `limit`. One statement, so concurrent consumers cannot
     * overshoot. Returns the new usage, or null when the quota would be exceeded.
     */
    async consume({ tenantId, quotaDefinitionId, periodKey, amount, limit }, client = db) {
      const rows = await client.$queryRaw`
        INSERT INTO tenant_quota_usage (id, tenant_id, quota_definition_id, period_key, used, updated_at)
        VALUES (gen_random_uuid(), ${tenantId}::uuid, ${quotaDefinitionId}::uuid, ${periodKey}, ${BigInt(amount)}, now())
        ON CONFLICT (tenant_id, quota_definition_id, period_key)
        DO UPDATE SET used = tenant_quota_usage.used + EXCLUDED.used, updated_at = now()
        WHERE tenant_quota_usage.used + EXCLUDED.used <= ${BigInt(limit)}
        RETURNING used`;
      return rows.length === 0 ? null : Number(rows[0].used);
    },
    /** Gives back consumed amount (never below zero). */
    async release({ tenantId, quotaDefinitionId, periodKey, amount }, client = db) {
      await client.$executeRaw`
        UPDATE tenant_quota_usage SET used = GREATEST(used - ${BigInt(amount)}, 0), updated_at = now()
        WHERE tenant_id = ${tenantId}::uuid AND quota_definition_id = ${quotaDefinitionId}::uuid AND period_key = ${periodKey}`;
    },
  });
}
