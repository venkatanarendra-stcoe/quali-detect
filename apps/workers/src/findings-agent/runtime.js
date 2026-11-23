import {
  PROVIDER_KIND,
  createEnvPlatformSecretProvider,
  missingLLMKeyProblems,
  resolveLLMProvider,
} from "@qmentisai/infra";

const NO_PROVIDER = Object.freeze({
  providerKind: /** @type {const} */ ("none"),
  resolveProvider: async () => ({ provider: null, status: "not_configured" }),
});

/**
 * Builds the provider side of the advisory agent: `resolveLLMProvider` (the consent gate of ADR-013 lives there) with a consent port
 * backed by the agent repository, and the provider KIND the egress level needs. The default provider stays the local Ollama of the
 * deployment configuration (`LLM_PROVIDER`); nothing here changes the choice. As in the decision agent runtime, a hosted provider is
 * refused in production until a real platform secret provider exists.
 *
 * It imports NOTHING from `@qmentisai/db` on purpose (the no-write import-graph check, SPEC 9.3.4 layer 2): the consent port reads
 * through the repository the integration passes in, by the tenant id of the finding row.
 * @param {{
 *   repository: { readConsent: (scope: { tenantId: string }) => Promise<{ externalConsent: boolean, codeSnippetConsent: boolean }> },
 *   config: { environment: string, llm: ReturnType<typeof import("@qmentisai/infra").readLLMConfig>["config"] },
 *   env?: Record<string, string | undefined>, logger?: any, fetchImpl?: typeof fetch,
 * }} deps
 * @returns {{ providerKind: "none" | "local" | "external", resolveProvider: (input: { purpose: string, tenantId: string }) => Promise<{ provider: any, status: string }> }}
 */
export function createFindingsAgentRuntime({
  repository,
  config,
  env = process.env,
  logger,
  fetchImpl,
}) {
  const llm = config.llm;
  if (!llm || llm.provider === "none") return NO_PROVIDER;
  const providerKind = PROVIDER_KIND[llm.provider] ?? "none";
  const secrets = createEnvPlatformSecretProvider({ env });
  if (providerKind === "external") {
    if (config.environment === "production")
      throw new Error(
        "A hosted LLM provider needs a platform secret provider other than the environment one in production (not available yet); use a local provider or LLM_PROVIDER=none.",
      );
    for (const problem of missingLLMKeyProblems(llm, secrets))
      logger?.warn?.({ variable: problem.variable }, problem.message);
  }
  const consent = Object.freeze({
    isExternalAllowed: async (tenantId) =>
      (await repository.readConsent({ tenantId })).externalConsent === true,
    isCodeSnippetAllowed: async (tenantId) => {
      const c = await repository.readConsent({ tenantId });
      return c.externalConsent === true && c.codeSnippetConsent === true;
    },
  });
  return Object.freeze({
    providerKind,
    resolveProvider: ({ purpose, tenantId }) =>
      resolveLLMProvider({ purpose, tenantId, config: llm, secrets, consent, logger, fetchImpl }),
  });
}
