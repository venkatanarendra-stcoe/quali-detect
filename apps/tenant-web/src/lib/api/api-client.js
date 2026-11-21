import { ApiError } from "./api-error.js";

const DEFAULT_TIMEOUT_MS = 20_000;
const CORRELATION_HEADER = "x-correlation-id";

const newCorrelationId = () => globalThis.crypto.randomUUID();

function buildQuery(query) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

/**
 * Shared API client.
 * - Session: HttpOnly cookie, sent with `credentials: "include"`; the token is never visible to JavaScript.
 * - Envelope: `{ success, data, meta }` is unwrapped; failures become `ApiError` with the server's stable code.
 * - Correlation: every request carries a fresh `x-correlation-id`; errors expose the id the server echoed.
 * - Cancellation: pass `signal` (TanStack Query does); an internal timeout aborts slow requests.
 * - 401 on a protected call invokes `onUnauthenticated` once so the app can return to sign-in.
 * @param {{ baseUrl?: string, timeoutMs?: number, onUnauthenticated?: () => void, fetchImpl?: typeof fetch }} [options]
 */
export function createApiClient({
  baseUrl = "/api/v1",
  timeoutMs = DEFAULT_TIMEOUT_MS,
  onUnauthenticated,
  fetchImpl = (...args) => globalThis.fetch(...args),
} = {}) {
  /** @returns {Promise<{ envelope: any, status: number, response?: Response }>} */
  async function send(
    method,
    path,
    {
      query,
      body,
      signal,
      headers: extraHeaders = {},
      skipUnauthenticatedHandler = false,
      binary = false,
    } = {},
  ) {
    const correlationId = newCorrelationId();
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    const onCallerAbort = () => controller.abort(signal.reason);
    if (signal) {
      if (signal.aborted) controller.abort(signal.reason);
      else signal.addEventListener("abort", onCallerAbort, { once: true });
    }
    let response;
    try {
      response = await fetchImpl(`${baseUrl}${path}${buildQuery(query)}`, {
        method,
        credentials: "include",
        headers: {
          Accept: "application/json",
          [CORRELATION_HEADER]: correlationId,
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
          ...extraHeaders,
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } catch (error) {
      if (timedOut) {
        throw new ApiError({
          status: 0,
          code: "TIMEOUT",
          message: "The request timed out.",
          correlationId,
        });
      }
      if (signal?.aborted) throw error; // cancelled by the caller: not an application error
      throw new ApiError({
        status: 0,
        code: "NETWORK_ERROR",
        message: "Network error.",
        correlationId,
      });
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onCallerAbort);
    }

    const echoed = response.headers.get(CORRELATION_HEADER) ?? correlationId;
    // a file download answers the file itself on success (never the envelope); every failure keeps the envelope below
    if (binary && response.ok) return { envelope: null, status: response.status, response };
    let envelope = null;
    try {
      envelope = await response.json();
    } catch {
      envelope = null;
    }
    if (envelope && typeof envelope === "object" && "success" in envelope) {
      if (envelope.success === true && response.ok) return { envelope, status: response.status };
      if (envelope.success === false && envelope.error) {
        const { code, message, details } = envelope.error;
        if (response.status === 401 && !skipUnauthenticatedHandler) onUnauthenticated?.();
        throw new ApiError({
          status: response.status,
          code,
          message,
          details,
          correlationId: envelope.meta?.correlationId ?? echoed,
        });
      }
    }
    throw new ApiError({
      status: response.status,
      code: "UNEXPECTED_RESPONSE",
      message: "Unexpected response from the server.",
      correlationId: echoed,
    });
  }

  const data = async (method, path, options) => (await send(method, path, options)).envelope.data;

  return Object.freeze({
    get: (path, options) => data("GET", path, options),
    post: (path, body, options) => data("POST", path, { ...options, body }),
    put: (path, body, options) => data("PUT", path, { ...options, body }),
    patch: (path, body, options) => data("PATCH", path, { ...options, body }),
    delete: (path, options) => data("DELETE", path, options),
    /**
     * File download (GET): resolves to `{ blob, fileName }`; the name is the server's `Content-Disposition` filename reduced to
     * `[A-Za-z0-9._-]`. Failures are `ApiError`s with the server's code, as everywhere else.
     */
    async download(path, options) {
      const { response } = await send("GET", path, { ...options, binary: true });
      const header = response.headers.get("content-disposition") ?? "";
      const named = /filename="([^"]{1,200})"/.exec(header)?.[1] ?? "download";
      const fileName = named.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[.-]+/, "") || "download";
      return { blob: await response.blob(), fileName };
    },
    /** Collection endpoint: `{ items, pagination }` from `data` and `meta.pagination`. */
    async getPage(path, options) {
      const { envelope } = await send("GET", path, options);
      return { items: envelope.data, pagination: envelope.meta?.pagination ?? null };
    },
  });
}
