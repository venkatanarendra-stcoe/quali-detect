/** Provider names accepted by `LLM_PROVIDER`. */
export const LLM_PROVIDERS = Object.freeze(["none", "ollama", "anthropic", "openai"]);

/** Platform secret names of the hosted providers (ADR-009 PlatformSecretProvider); values never reach the database. */
export const LLM_KEY_SECRETS = Object.freeze({
  anthropic: "llm.anthropic.api_key",
  openai: "llm.openai.api_key",
});

const DEFAULTS = Object.freeze({
  ollamaBaseUrl: "http://127.0.0.1:11434",
  anthropicBaseUrl: "https://api.anthropic.com",
  openaiBaseUrl: "https://api.openai.com",
});

/**
 * Reads the deployment LLM configuration (ADR-013 section 2) from an environment object, shared by the API and the workers.
 * Plain validation like `readGitHubAppConfig` (this package has no Zod dependency and none is added); callers turn the
 * returned problems into their own ConfigError. Problems name the variable and the rule, never the value. There is NO
 * default model name; base URLs are deployment-only (never tenant-supplied) and carry no credentials. API keys are not read
 * here: they come from the PlatformSecretProvider.
 * @param {Record<string, string | undefined>} env
 * @param {{ production: boolean }} options
 * @returns {{ problems: Array<{ variable: string, message: string }>, config: Readonly<{
 *   provider: "none" | "ollama" | "anthropic" | "openai", model: string | null, ollamaBaseUrl: string,
 *   anthropicBaseUrl: string, openaiBaseUrl: string, requestTimeoutMs: number, maxConcurrentCalls: number }> | null }}
 */
export function readLLMConfig(env, { production }) {
  const problems = [];
  const text = (variable) => env[variable]?.trim() || undefined;
  const provider = text("LLM_PROVIDER") ?? "none";
  if (!LLM_PROVIDERS.includes(provider))
    problems.push({
      variable: "LLM_PROVIDER",
      message: `must be one of: ${LLM_PROVIDERS.join(", ")}`,
    });
  const model = text("LLM_MODEL") ?? null;
  if (provider !== "none" && LLM_PROVIDERS.includes(provider) && !model)
    problems.push({
      variable: "LLM_MODEL",
      message: "required while LLM_PROVIDER is not none (no default model)",
    });
  if (model && !/^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,199}$/.test(model))
    problems.push({
      variable: "LLM_MODEL",
      message: "must be 1 to 200 characters of letters, digits and . _ : / @ -",
    });
  const url = (variable, fallback, httpsInProduction) => {
    const raw = text(variable);
    if (raw === undefined) return fallback;
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      problems.push({ variable, message: "must be an http(s) URL" });
      return fallback;
    }
    if (!["http:", "https:"].includes(parsed.protocol)) {
      problems.push({ variable, message: "must be an http(s) URL" });
      return fallback;
    }
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      problems.push({ variable, message: "must not contain credentials, a query or a fragment" });
      return fallback;
    }
    if (httpsInProduction && production && parsed.protocol !== "https:") {
      problems.push({ variable, message: "must be https in production" });
      return fallback;
    }
    return raw.replace(/\/+$/, "");
  };
  const int = (variable, fallback, min, max) => {
    const raw = text(variable);
    if (raw === undefined) return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < min || value > max) {
      problems.push({ variable, message: `must be an integer from ${min} to ${max}` });
      return fallback;
    }
    return value;
  };
  const config = {
    provider: /** @type {any} */ (provider),
    model,
    ollamaBaseUrl: url("LLM_OLLAMA_BASE_URL", DEFAULTS.ollamaBaseUrl, false),
    anthropicBaseUrl: url("LLM_ANTHROPIC_BASE_URL", DEFAULTS.anthropicBaseUrl, true),
    openaiBaseUrl: url("LLM_OPENAI_BASE_URL", DEFAULTS.openaiBaseUrl, true),
    requestTimeoutMs: int("LLM_REQUEST_TIMEOUT_SECONDS", 30, 1, 300) * 1000,
    maxConcurrentCalls: int("LLM_MAX_CONCURRENT_CALLS", 4, 1, 64),
  };
  return { problems, config: problems.length > 0 ? null : Object.freeze(config) };
}

/**
 * Startup check for a process that will call the provider (the workers): names the missing key, never reads its value into a
 * message. The API does not call the model and does not need the key.
 * @param {{ provider: string }} config
 * @param {{ has: (name: string) => boolean }} secrets
 * @returns {Array<{ variable: string, message: string }>}
 */
export function missingLLMKeyProblems(config, secrets) {
  const name = LLM_KEY_SECRETS[config.provider];
  if (!name || secrets.has(name)) return [];
  return [
    {
      variable: name,
      message: `the platform secret for LLM_PROVIDER=${config.provider} is not set`,
    },
  ];
}
