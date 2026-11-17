import { LLMError } from "./types.js";

const RESET_CODES = new Set(["ECONNRESET", "EPIPE", "UND_ERR_SOCKET"]);

/**
 * Joins the caller's signal with an adapter-level hard timeout.
 * @param {AbortSignal | undefined} signal
 * @param {number} timeoutMs
 */
function combine(signal, timeoutMs) {
  const timeout = AbortSignal.timeout(timeoutMs);
  return { timeout, signal: signal ? AbortSignal.any([signal, timeout]) : timeout };
}

/**
 * POSTs JSON and returns the parsed JSON body. Non-streaming. One bounded retry on a transport reset only (never on an HTTP
 * status). Errors are `LLMError`s without headers, keys, prompts or bodies. The key must be passed in `headers` only.
 * @param {{ fetchImpl: typeof fetch, url: string, headers: Record<string, string>, body: unknown,
 *           signal?: AbortSignal, timeoutMs: number, provider: string }} options
 * @returns {Promise<unknown>}
 */
export async function postJson({ fetchImpl, url, headers, body, signal, timeoutMs, provider }) {
  const payload = JSON.stringify(body);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const joined = combine(signal, timeoutMs);
    let response;
    try {
      response = await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", ...headers },
        body: payload,
        signal: joined.signal,
        redirect: "error",
      });
      if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        throw new LLMError("http_status", { status: response.status, provider });
      }
      try {
        return await response.json();
      } catch (error) {
        if (joined.signal.aborted) throw error;
        throw new LLMError("invalid_response", { provider });
      }
    } catch (error) {
      if (error instanceof LLMError) throw error;
      if (signal?.aborted) throw new LLMError("aborted", { provider });
      if (joined.timeout.aborted) throw new LLMError("timeout", { provider });
      const reset = RESET_CODES.has(error?.cause?.code) || RESET_CODES.has(error?.code);
      if (reset && attempt === 0) continue;
      throw new LLMError("transport", { provider });
    }
  }
  throw new LLMError("transport", { provider });
}

/** @param {unknown} v @returns {number} */
export const count = (v) =>
  Number.isFinite(v) && v >= 0 ? Math.floor(/** @type {number} */ (v)) : 0;

/** @param {unknown} v */
export const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Parses tool arguments that a vendor sends as a JSON string; the result must be a plain object.
 * @param {unknown} raw
 * @param {string} provider
 * @returns {Record<string, unknown>}
 */
export function parseToolArguments(raw, provider) {
  let value = raw;
  if (typeof raw === "string") {
    try {
      value = raw.trim() === "" ? {} : JSON.parse(raw);
    } catch {
      throw new LLMError("invalid_response", { provider });
    }
  }
  if (!isPlainObject(value)) throw new LLMError("invalid_response", { provider });
  return /** @type {Record<string, unknown>} */ (value);
}
