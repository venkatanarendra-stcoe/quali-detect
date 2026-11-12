import { ENTITLEMENT_ERROR_CODES as CODES, EntitlementError } from "./errors.js";

/**
 * Entitlements (what a tenant's plan includes) and quotas (how much it may consume). This is a SEPARATE gate after
 * authorization: it never grants permissions and is never a substitute for them (docs/AUTHORIZATION.md §5.11).
 *
 * Rules (Recommended defaults):
 * - A key that is not in the entitlement catalog / quota definitions is NOT governed: allowed, unlimited.
 * - A governed key resolves tenant override (tenant_entitlements) first, then the tenant's current usable subscription
 *   (plan_entitlements); with neither, it is disabled (fail closed).
 * - A governed quota's limit is the tenant's own `tenant_quotas` value, else the limit of its linked entitlement; with no
 *   limit configured the quota is unprovisioned and consumption is refused.
 * Every method takes an optional `client` (Prisma client or interactive-transaction client, default: the repository's `db`).
 * @param {{ repository: ReturnType<typeof import("./repository.js").createEntitlementRepository>, clock?: () => Date }} deps
 */
export function createEntitlementService({ repository, clock = () => new Date() }) {
  const toLimit = (value) => (value === null || value === undefined ? null : Number(value));

  async function resolveEntitlement(tenantId, entry, client) {
    const override = await repository.findTenantEntitlement(
      { tenantId, entitlementId: entry.id },
      client,
    );
    if (override)
      return { enabled: override.enabled, limit: toLimit(override.limitValue), source: "tenant" };
    const plan = await repository.findPlanEntitlement(
      { tenantId, entitlementId: entry.id, now: clock() },
      client,
    );
    if (plan) return { enabled: plan.enabled, limit: toLimit(plan.limitValue), source: "plan" };
    return { enabled: false, limit: null, source: "none" };
  }

  const service = {
    /**
     * @param {{ tenantId: string, key: string }} input
     * @param {any} [client] Prisma client or transaction client.
     * @returns {Promise<{ key: string, governed: boolean, enabled: boolean, limit: number | null, source: string }>}
     */
    async checkEntitlement({ tenantId, key }, client) {
      const entry = await repository.findCatalogEntry(key, client);
      if (!entry) return { key, governed: false, enabled: true, limit: null, source: "ungoverned" };
      return { key, governed: true, ...(await resolveEntitlement(tenantId, entry, client)) };
    },

    /** Throws 403 ENTITLEMENT_REQUIRED when a governed feature is not included. @param {{ tenantId: string, key: string }} input @param {any} [client] */
    async assertEntitlement({ tenantId, key }, client) {
      const result = await service.checkEntitlement({ tenantId, key }, client);
      if (!result.enabled)
        throw new EntitlementError(
          CODES.ENTITLEMENT_REQUIRED,
          "This feature is not included in your plan.",
          { details: { entitlement: key } },
        );
      return result;
    },

    /**
     * For count limits ("workspaces.max"): the feature must be enabled and `currentCount + adding` within the limit.
     * Call inside the transaction that creates the record, after taking a lock, so concurrent creators are serialized.
     * @param {{ tenantId: string, key: string, currentCount: number, adding?: number }} input
     * @param {any} [client]
     */
    async assertWithinLimit({ tenantId, key, currentCount, adding = 1 }, client) {
      const result = await service.assertEntitlement({ tenantId, key }, client);
      if (result.limit !== null && currentCount + adding > result.limit) {
        throw new EntitlementError(CODES.QUOTA_EXCEEDED, "Your plan limit has been reached.", {
          details: { entitlement: key, limit: result.limit },
        });
      }
      return result;
    },

    /**
     * For consumable quotas (scans per month...): atomically adds `amount` to the tenant's usage for `periodKey`, or throws
     * 403 QUOTA_EXCEEDED. Use `releaseQuota` to give amount back when the metered operation fails.
     * @param {{ tenantId: string, quotaKey: string, amount?: number, periodKey?: string }} input
     * @param {any} [client] Pass the caller's transaction client to consume atomically with its writes.
     * @returns {Promise<{ governed: boolean, used: number | null, limit: number | null, remaining: number | null }>}
     */
    async consumeQuota({ tenantId, quotaKey, amount = 1, periodKey = "all" }, client) {
      if (!Number.isInteger(amount) || amount < 1)
        throw new TypeError("amount must be a positive integer");
      const definition = await repository.findQuotaDefinition(quotaKey, client);
      if (!definition) return { governed: false, used: null, limit: null, remaining: null };
      let limit = null;
      const tenantQuota = await repository.findTenantQuota(
        { tenantId, quotaDefinitionId: definition.id },
        client,
      );
      if (tenantQuota) limit = toLimit(tenantQuota.limitValue);
      if (definition.entitlementId) {
        const entry = { id: definition.entitlementId };
        const entitlement = await resolveEntitlement(tenantId, entry, client);
        if (!entitlement.enabled)
          throw new EntitlementError(
            CODES.ENTITLEMENT_REQUIRED,
            "This feature is not included in your plan.",
            { details: { quota: quotaKey } },
          );
        if (limit === null) limit = entitlement.limit;
      }
      const exceeded = () =>
        new EntitlementError(CODES.QUOTA_EXCEEDED, "Your plan quota has been reached.", {
          details: { quota: quotaKey, limit },
        });
      if (limit === null || amount > limit) throw exceeded();
      const used = await repository.consume(
        { tenantId, quotaDefinitionId: definition.id, periodKey, amount, limit },
        client,
      );
      if (used === null) throw exceeded();
      return { governed: true, used, limit, remaining: limit - used };
    },

    /** @param {{ tenantId: string, quotaKey: string, amount?: number, periodKey?: string }} input @param {any} [client] */
    async releaseQuota({ tenantId, quotaKey, amount = 1, periodKey = "all" }, client) {
      const definition = await repository.findQuotaDefinition(quotaKey, client);
      if (definition)
        await repository.release(
          { tenantId, quotaDefinitionId: definition.id, periodKey, amount },
          client,
        );
    },
  };
  return Object.freeze(service);
}
