import { ValidationError } from "../../../errors/app-error.js";
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
     * Changes the consent tiers (ADR-013 addendum). Each real change is written and audited in ONE transaction (metadata: the
     * previous and new value only). Writing a value that is already set is an idempotent no-op: nothing is written and no audit
     * entry is made. Withdrawing the metadata consent withdraws the code-snippet consent in the same write (the database CHECK),
     * and that second change is audited too. Turning the code-snippet consent on while the metadata consent is off is a 400.
     */
    async update(actor, { externalConsent, codeSnippetConsent }) {
      return repository.transaction(async (tx) => {
        const record = (action, previous, current) =>
          audit.tenant.record(
            {
              tenantId: actor.tenantId,
              actorUserId: actor.userId,
              action,
              targetType: "tenant_llm_settings",
              targetId: actor.tenantId,
              correlationId: actor.requestId,
              ipAddress: actor.ip,
              metadata: { previous, new: current },
            },
            { tx },
          );
        let row = null;
        if (externalConsent !== undefined) {
          const before = await repository.getConsents({ tenantId: actor.tenantId }, tx);
          const result = await repository.setExternalConsent(
            { tenantId: actor.tenantId, enabled: externalConsent, userId: actor.userId },
            tx,
          );
          row = result.row;
          if (result.changed)
            await record(AUDIT_ACTIONS.TENANT_LLM_CONSENT_CHANGED, result.previous, result.current);
          if (result.changed && !externalConsent && before.codeSnippetConsent)
            await record(AUDIT_ACTIONS.TENANT_LLM_CODE_CONSENT_CHANGED, true, false);
        }
        if (codeSnippetConsent !== undefined) {
          const result = await repository.setCodeSnippetConsent(
            { tenantId: actor.tenantId, enabled: codeSnippetConsent, userId: actor.userId },
            tx,
          );
          if (result.requiresExternal)
            throw new ValidationError(
              [
                {
                  path: "codeSnippetConsent",
                  code: "requires_external_consent",
                  message: "Code excerpts need the metadata consent.",
                },
              ],
              { source: "body" },
            );
          row = result.row ?? row;
          if (result.changed)
            await record(
              AUDIT_ACTIONS.TENANT_LLM_CODE_CONSENT_CHANGED,
              result.previous,
              result.current,
            );
        }
        const changedBy = await repository.findConsentChangedBy({ tenantId: actor.tenantId }, tx);
        return toAiSettingsDto(row, llm, changedBy);
      });
    },
  });
}
