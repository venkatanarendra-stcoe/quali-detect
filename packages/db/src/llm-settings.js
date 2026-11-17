import { assertTenantId } from "./repository.js";

/**
 * Data access for `tenant_llm_settings` (SPEC scan-decisioning 7.2a, ADR-013): the tenant's data-egress consent for an external
 * LLM provider. One row per tenant, created on the first change; no row means no consent. EVERY function takes the tenant id
 * (from the trusted session or job context, never from a body or message) and the row is reached by that id only.
 * @param {{ db: any }} deps
 */
export function createTenantLlmSettingsRepository({ db }) {
  return Object.freeze({
    /**
     * Whether the tenant consented to an external provider. False when there is no row.
     * @param {{ tenantId: string }} scope
     * @returns {Promise<boolean>}
     */
    async getExternalConsent({ tenantId }, client = db) {
      const row = await client.tenantLlmSettings.findUnique({
        where: { tenantId: assertTenantId(tenantId) },
        select: { externalConsent: true },
      });
      return row?.externalConsent === true;
    },

    /**
     * The tenant's settings row or null.
     * @param {{ tenantId: string }} scope
     */
    findSettings: ({ tenantId }, client = db) =>
      client.tenantLlmSettings.findUnique({ where: { tenantId: assertTenantId(tenantId) } }),

    /**
     * Sets the consent. Must run inside a transaction (`tx` is required): a per-tenant advisory lock serializes concurrent
     * writers so `previous` is exact, and the caller writes the audit entry in the same transaction. A write that does not
     * change the value touches nothing (`changed: false`).
     * @param {{ tenantId: string, enabled: boolean, userId: string }} input
     * @param {any} tx transaction client
     * @returns {Promise<{ previous: boolean, current: boolean, changed: boolean, row: object | null }>}
     */
    async setExternalConsent({ tenantId, enabled, userId }, tx) {
      assertTenantId(tenantId);
      if (!tx) throw new TypeError("setExternalConsent must run inside a transaction (pass tx).");
      if (typeof enabled !== "boolean") throw new TypeError("enabled must be a boolean.");
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`llm-settings:${tenantId}`}))`;
      const existing = await tx.tenantLlmSettings.findUnique({ where: { tenantId } });
      const previous = existing?.externalConsent === true;
      if (previous === enabled)
        return { previous, current: enabled, changed: false, row: existing };
      const now = new Date();
      const row = await tx.tenantLlmSettings.upsert({
        where: { tenantId },
        create: {
          tenantId,
          externalConsent: enabled,
          updatedByUserId: userId,
          consentChangedAt: now,
        },
        update: { externalConsent: enabled, updatedByUserId: userId, consentChangedAt: now },
      });
      return { previous, current: enabled, changed: true, row };
    },
  });
}

/**
 * The consent port `resolveLLMProvider` needs, backed by the repository. The tenant id is the only input.
 * @param {ReturnType<typeof createTenantLlmSettingsRepository>} repository
 * @returns {{ isExternalAllowed: (tenantId: string) => Promise<boolean> }}
 */
export function createLlmConsentGate(repository) {
  return Object.freeze({
    isExternalAllowed: (tenantId) => repository.getExternalConsent({ tenantId }),
  });
}
