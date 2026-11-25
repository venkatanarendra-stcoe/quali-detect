import { createAnthropicProvider } from "./anthropic.js";
import { LLM_KEY_SECRETS } from "./config.js";
import { createOllamaProvider } from "./ollama.js";
import { createOpenAIProvider } from "./openai.js";
import { LLMError, providerKindFor } from "./types.js";

/** @typedef {"ok" | "not_configured" | "consent_required" | "key_missing"} LLMResolution */

const limiters = new Map();

/**
 * A per-process counting semaphore, shared by every provider resolved with the same limit (the cap is per process, not per
 * tenant). Waiting honours the caller's AbortSignal.
 * @param {number} max
 */
function limiterFor(max) {
  let limiter = limiters.get(max);
  if (limiter) return limiter;
  let active = 0;
  const queue = [];
  const release = () => {
    active -= 1;
    queue.shift()?.();
  };
  limiter = {
    /** @template T @param {AbortSignal | undefined} signal @param {() => Promise<T>} run @returns {Promise<T>} */
    async run(signal, run) {
      if (active >= max) {
        await new Promise((resolve, reject) => {
          const entry = () => {
            signal?.removeEventListener("abort", onAbort);
            resolve(undefined);
          };
          const onAbort = () => {
            const i = queue.indexOf(entry);
            if (i >= 0) queue.splice(i, 1);
            reject(new LLMError("aborted"));
          };
          if (signal?.aborted) return onAbort();
          signal?.addEventListener("abort", onAbort, { once: true });
          queue.push(entry);
        });
      }
      active += 1;
      try {
        return await run();
      } finally {
        release();
      }
    },
  };
  limiters.set(max, limiter);
  return limiter;
}

/**
 * Resolves the provider for a purpose and a tenant. THE CONSENT GATE LIVES HERE (SPEC scan-decisioning AG-9, ADR-013): an
 * external provider (anthropic, openai) is built only when `consent.isExternalAllowed(tenantId)` is true, and no adapter (and
 * therefore no request) exists before that; a local provider (Ollama on a loopback host) needs none; an Ollama on any other host counts as external. The tenant id is used only for the consent
 * lookup and is never passed to an adapter or a request. A provider may be absent: `provider: null` is a normal result and the
 * caller continues without a model.
 *
 * As built, the result is `{ provider, status }` (ADR-013 text said "null"): `ok`, `not_configured` (provider none), `consent_required`
 * (external provider, tenant has not consented) or `key_missing` (hosted provider without its platform secret).
 * @param {{ purpose: string, tenantId: string,
 *           config: ReturnType<typeof import("./config.js").readLLMConfig>["config"],
 *           secrets: { get: (name: string) => string | null },
 *           consent: { isExternalAllowed: (tenantId: string) => Promise<boolean> },
 *           fetchImpl?: typeof fetch, logger?: { warn?: Function } }} options
 * @returns {Promise<{ provider: import("./types.js").LLMProvider | null, status: LLMResolution }>}
 */
export async function resolveLLMProvider({
  purpose,
  tenantId,
  config,
  secrets,
  consent,
  fetchImpl,
  logger,
}) {
  if (
    typeof purpose !== "string" ||
    purpose === "" ||
    typeof tenantId !== "string" ||
    tenantId === ""
  )
    throw new TypeError("resolveLLMProvider needs a purpose and a trusted tenantId.");
  if (!config || config.provider === "none" || !config.model)
    return { provider: null, status: "not_configured" };
  const kind = providerKindFor(config);
  if (!kind) return { provider: null, status: "not_configured" };
  if (kind === "external" && (await consent.isExternalAllowed(tenantId)) !== true)
    return { provider: null, status: "consent_required" };
  const timeoutMs = config.requestTimeoutMs;
  let inner;
  if (config.provider === "ollama") {
    inner = createOllamaProvider({
      baseUrl: config.ollamaBaseUrl,
      model: config.model,
      timeoutMs,
      fetchImpl,
    });
  } else {
    let apiKey = null;
    try {
      apiKey = secrets.get(LLM_KEY_SECRETS[config.provider]);
    } catch {
      apiKey = null;
    }
    if (typeof apiKey !== "string" || apiKey === "") {
      logger?.warn?.(
        { provider: config.provider, purpose },
        "LLM platform secret is not available",
      );
      return { provider: null, status: "key_missing" };
    }
    const make = config.provider === "anthropic" ? createAnthropicProvider : createOpenAIProvider;
    inner = make({
      baseUrl: config.provider === "anthropic" ? config.anthropicBaseUrl : config.openaiBaseUrl,
      model: config.model,
      apiKey,
      timeoutMs,
      fetchImpl,
    });
  }
  const limiter = limiterFor(config.maxConcurrentCalls);
  const provider = Object.freeze({
    info: inner.info,
    // An external provider re-checks the consent immediately before every request (after any wait for a concurrency slot), so a
    // consent turned off while a provider object is held, or while a call waits, still stops the request.
    complete: (request) =>
      limiter.run(request.signal, async () => {
        if (kind === "external" && (await consent.isExternalAllowed(tenantId)) !== true)
          throw new LLMError("not_configured", { provider: config.provider });
        return inner.complete(request);
      }),
  });
  return { provider, status: "ok" };
}
