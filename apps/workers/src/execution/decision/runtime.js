import { createLlmConsentGate, createTenantLlmSettingsRepository } from "@qmentisai/db";
import {
  PROVIDER_KIND,
  createEnvPlatformSecretProvider,
  missingLLMKeyProblems,
  resolveLLMProvider,
} from "@qmentisai/infra";

const NO_PROVIDER = Object.freeze({ provider: null, status: "not_configured" });

/**
 * Builds the `resolveProvider` the decision agent needs (docs/modules/scan-decisioning/SPEC.md 17.d): `resolveLLMProvider` of
 * `@qmentisai/infra` (which holds the consent gate, AG-9) with the tenant consent port backed by `tenant_llm_settings` and the
 * PLATFORM secret provider for hosted-provider keys (the same `createEnvPlatformSecretProvider` the pipeline worker's GitHub
 * adapter uses). Not called by the orchestrator yet (part E).
 *
 * Production refuses the environment secret provider (ADR-009: KMS/Vault adapters do not exist yet), so with `NODE_ENV=production`
 * a hosted provider (Anthropic, OpenAI) makes this factory throw; a local Ollama needs no key and is allowed. A hosted provider
 * whose key is missing is NOT a startup failure (the agent then reports `not_configured` and the decision continues with the
 * floor): it is logged once by variable name.
 * @param {{ db: any, config: { environment: string, llm: ReturnType<typeof import("@qmentisai/infra").readLLMConfig>["config"] },
 *           env?: Record<string, string | undefined>, logger?: any }} deps
 * @returns {{ resolveProvider: (input: { purpose: string, tenantId: string }) => Promise<{ provider: any, status: string }> }}
 */
export function createDecisionAgentRuntime({ db, config, env = process.env, logger }) {
  const llm = config.llm;
  if (!llm || llm.provider === "none")
    return Object.freeze({ resolveProvider: async () => NO_PROVIDER });
  const secrets = createEnvPlatformSecretProvider({ env });
  if (PROVIDER_KIND[llm.provider] === "external") {
    if (config.environment === "production")
      throw new Error(
        "A hosted LLM provider needs a platform secret provider other than the environment one in production (not available yet); use a local provider or LLM_PROVIDER=none.",
      );
    for (const problem of missingLLMKeyProblems(llm, secrets))
      logger?.warn?.({ variable: problem.variable }, problem.message);
  }
  const consent = createLlmConsentGate(createTenantLlmSettingsRepository({ db }));
  return Object.freeze({
    resolveProvider: ({ purpose, tenantId }) =>
      resolveLLMProvider({ purpose, tenantId, config: llm, secrets, consent, logger }),
  });
}
