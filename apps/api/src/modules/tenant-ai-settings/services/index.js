import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import { toAiSettingsDto } from "../mappers/index.js";

/**
 * Tenant AI settings use cases. The tenant and the user come from the session only.
 * @param {{ repository: ReturnType<typeof import("../repositories/index.js").createTenantAiSettingsRepository>, audit: any, llm: { provider?: string } | null }} deps
 */
export function createTenantAiSettingsService({ repository, audit, llm }) {
  return Object.freeze({
    async get(actor) {
      const row = await repository.findSettings({ tenantId: actor.tenantId });
      const changedBy = row
        ? await repository.findConsentChangedBy({ tenantId: actor.tenantId })
        : null;
      return toAiSettingsDto(row, llm, changedBy);
    },
    /**
     * Turns the external-provider consent on or off. A real change is written and audited in ONE transaction (metadata: the
     * previous and new value only). Writing the value that is already set is an idempotent no-op: nothing is written and no
     * audit entry is made, because nothing changed.
     */
    async update(actor, { externalConsent }) {
      return repository.transaction(async (tx) => {
        const result = await repository.setExternalConsent(
          { tenantId: actor.tenantId, enabled: externalConsent, userId: actor.userId },
          tx,
        );
        if (result.changed)
          await audit.tenant.record(
            {
              tenantId: actor.tenantId,
              actorUserId: actor.userId,
              action: AUDIT_ACTIONS.TENANT_LLM_CONSENT_CHANGED,
              targetType: "tenant_llm_settings",
              targetId: actor.tenantId,
              correlationId: actor.requestId,
              ipAddress: actor.ip,
              metadata: { previous: result.previous, new: result.current },
            },
            { tx },
          );
        const changedBy = await repository.findConsentChangedBy({ tenantId: actor.tenantId }, tx);
        return toAiSettingsDto(result.row, llm, changedBy);
      });
    },
  });
}
