import { PROVIDER_KIND } from "@qmentisai/infra";

/**
 * AI settings DTO. Never exposes the row, the model name, a URL or a key. `providerKind` comes from the deployment
 * configuration of `LLM_PROVIDER` ("local" for Ollama, "external" for Anthropic/OpenAI, null when none).
 * @param {{ externalConsent: boolean, updatedAt: Date, consentChangedAt: Date | null } | null | undefined} row
 * @param {{ provider?: string } | null | undefined} llm the API-side LLM configuration
 * @param {{ displayName: string } | null | undefined} changedBy who last changed the consent (display name only, resolved by
 *   the tenant scope; null when unknown, deleted or from another tenant). Never an id or an email.
 */
export function toAiSettingsDto(row, llm, changedBy = null) {
  const kind = PROVIDER_KIND[llm?.provider] ?? null;
  return {
    externalConsent: row?.externalConsent === true,
    assistant: { configured: kind !== null, providerKind: kind },
    updatedAt: row?.updatedAt?.toISOString() ?? null,
    consentChangedAt: row?.consentChangedAt?.toISOString() ?? null,
    consentChangedBy:
      typeof changedBy?.displayName === "string" ? { displayName: changedBy.displayName } : null,
  };
}
