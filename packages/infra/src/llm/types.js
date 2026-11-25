/**
 * LLM provider contract (ADR-013 section 1). Server-only. Optional by design: callers must keep working with no model.
 *
 * @typedef {{ id: "ollama" | "anthropic" | "openai", model: string }} LLMProviderInfo
 * @typedef {{ name: string, description: string, inputSchema: object }} LLMTool JSON Schema for the tool input
 * @typedef {{ role: "user" | "assistant", content: string }} LLMMessage plain text only
 * @typedef {{ name: string, input: unknown }} LLMToolCall
 * @typedef {{ text: string, toolCalls: LLMToolCall[], stopReason: string,
 *             usage: { inputTokens: number, outputTokens: number } }} LLMResult
 * @typedef {{ system: string, messages: LLMMessage[], tools?: LLMTool[], maxOutputTokens: number,
 *             temperature?: number, signal: AbortSignal }} LLMRequest
 * @typedef {{ info: LLMProviderInfo, complete(request: LLMRequest): Promise<LLMResult> }} LLMProvider
 *
 * Tool results: the adapters take plain text messages only. A tool result goes back as ONE `user` message built by
 * `toolResultMessage(name, output)`, so the loop is provider-neutral and no vendor tool-call ids are needed.
 */

/** Machine codes of `LLMError`. */
export const LLM_ERROR_CODES = Object.freeze([
  "timeout",
  "aborted",
  "transport",
  "http_status",
  "invalid_response",
  "not_configured",
]);

/**
 * Failure of a provider call. Carries a code and, for `http_status`, the numeric status. NEVER carries request headers, API
 * keys, prompts or response bodies (not in the message, not in any field, not in `cause`).
 */
export class LLMError extends Error {
  /**
   * @param {"timeout" | "aborted" | "transport" | "http_status" | "invalid_response" | "not_configured"} code
   * @param {{ status?: number, provider?: string }} [details]
   */
  constructor(code, { status, provider } = {}) {
    super(
      `LLM call failed: ${code}${status ? ` (HTTP ${status})` : ""}${provider ? ` [${provider}]` : ""}`,
    );
    this.name = "LLMError";
    this.code = code;
    if (status !== undefined) this.status = status;
    if (provider !== undefined) this.provider = provider;
  }
}

/**
 * The documented shape of a tool result turn.
 * @param {string} name tool name
 * @param {unknown} output JSON-serialisable result
 * @returns {LLMMessage}
 */
export function toolResultMessage(name, output) {
  return { role: "user", content: `Tool result for "${name}": ${JSON.stringify(output)}` };
}

/**
 * @param {unknown} value
 * @returns {asserts value is LLMProvider}
 * @throws {TypeError} when `value` does not satisfy the LLMProvider contract.
 */
export function assertLLMProvider(value) {
  const v = /** @type {any} */ (value);
  if (
    !v ||
    typeof v.complete !== "function" ||
    typeof v.info?.id !== "string" ||
    typeof v.info?.model !== "string" ||
    !["ollama", "anthropic", "openai"].includes(v.info.id)
  )
    throw new TypeError("Not an LLMProvider: needs info.id, info.model and complete().");
}

/** Provider kinds of the PROVIDER, before the host is looked at (use `providerKindFor`, which does). */
export const PROVIDER_KIND = Object.freeze({
  ollama: "local",
  anthropic: "external",
  openai: "external",
});

/** The only hosts that count as "this machine" (a LAN address does not: the data leaves the machine). */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * The kind of provider a deployment configuration really is (ADR-013, AP-6; owner decision 2026-11-25): a local provider needs no
 * data-egress consent, an external one does. A hosted vendor is always external. Ollama is local ONLY when its base URL is a loopback
 * host (`localhost`, `127.0.0.1`, `::1`); an Ollama on any other host, a LAN address included, sends the data off this machine and is
 * external, so both consent tiers apply to it. An unparseable URL is external (fail closed). `null` for no provider.
 * @param {{ provider?: string, ollamaBaseUrl?: string } | null | undefined} config
 * @returns {"local" | "external" | null}
 */
export function providerKindFor(config) {
  const base = PROVIDER_KIND[config?.provider];
  if (!base) return null;
  if (config.provider !== "ollama") return base;
  try {
    return LOOPBACK_HOSTS.has(new URL(config.ollamaBaseUrl).hostname.toLowerCase())
      ? "local"
      : "external";
  } catch {
    return "external";
  }
}
