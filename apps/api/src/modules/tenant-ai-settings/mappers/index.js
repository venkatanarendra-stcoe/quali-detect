import { providerKindFor } from "@qmentisai/infra";

/**
 * AI settings DTO. Never exposes the row, the model name, a URL or a key. `providerKind` comes from the deployment
 * configuration of `LLM_PROVIDER` ("local" for an Ollama on a loopback host, "external" for Anthropic/OpenAI and for an Ollama on any other host, null when none).
 * @param {{ externalConsent: boolean, codeSnippetConsent?: boolean, updatedAt: Date, consentChangedAt: Date | null } | null | undefined} row
 * @param {{ provider?: string, ollamaBaseUrl?: string } | null | undefined} llm the API-side LLM configuration
 * @param {{ displayName: string } | null | undefined} changedBy who last changed the consent (display name only, resolved by
 *   the tenant scope; null when unknown, deleted or from another tenant). Never an id or an email.
 */
export function toAiSettingsDto(row, llm, changedBy = null) {
  const kind = providerKindFor(llm);
  return {
    externalConsent: row?.externalConsent === true,
    codeSnippetConsent: row?.externalConsent === true && row?.codeSnippetConsent === true,
    assistant: { configured: kind !== null, providerKind: kind },
    updatedAt: row?.updatedAt?.toISOString() ?? null,
    consentChangedAt: row?.consentChangedAt?.toISOString() ?? null,
    consentChangedBy:
      typeof changedBy?.displayName === "string" ? { displayName: changedBy.displayName } : null,
  };
}
