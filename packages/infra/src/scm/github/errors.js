import { NonRetryableError, TransientError } from "../../rabbitmq/retry.js";

/**
 * Error from the GitHub API or from reaching it. Carries only safe, structured facts (never headers, tokens or bodies).
 */
export class GitHubApiError extends Error {
  /**
   * @param {string} message
   * @param {{ status?: number, code?: string, retryAfterMs?: number, rateLimited?: boolean, notFound?: boolean }} [details]
   */
  constructor(message, { status, code, retryAfterMs, rateLimited = false } = {}) {
    super(message);
    this.name = "GitHubApiError";
    this.status = status;
    this.code = code;
    this.retryAfterMs = retryAfterMs;
    this.rateLimited = rateLimited;
  }
  get notFound() {
    return this.status === 404;
  }
  /** 401 or 403 that is NOT a rate limit: the credential or the access is gone. */
  get accessDenied() {
    return (this.status === 401 || this.status === 403) && !this.rateLimited;
  }
}

/**
 * Reads GitHub's rate-limit signals (verified in the spike): 403/429 with `x-ratelimit-remaining: 0`, a `retry-after`
 * header, or a message that names a secondary rate limit. Returns the delay to wait, or null when this is not a rate limit.
 * @param {number} status @param {Headers} headers @param {string} message
 * @param {() => number} [now]
 * @returns {number | null} milliseconds to wait
 */
export function rateLimitDelayMs(status, headers, message, now = Date.now) {
  if (status !== 403 && status !== 429) return null;
  const retryAfter = Number(headers.get("retry-after"));
  if (Number.isFinite(retryAfter) && retryAfter > 0) return retryAfter * 1000;
  if (headers.get("x-ratelimit-remaining") === "0") {
    const reset = Number(headers.get("x-ratelimit-reset"));
    return Number.isFinite(reset) ? Math.max(reset * 1000 - now(), 1000) : 60000;
  }
  if (status === 429 || /secondary rate limit|rate limit/i.test(message)) return 60000;
  return null;
}

/**
 * Maps a GitHub failure onto the messaging layer's retry classes (WORKER_ARCHITECTURE): rate limits, 5xx, 408, network
 * errors are transient; everything else (401, 403 without a rate limit, 404, 422...) is not retryable.
 * @param {unknown} error
 * @returns {Error}
 */
export function toRetryable(error) {
  if (error instanceof GitHubApiError) {
    const transient =
      error.rateLimited ||
      error.status === undefined ||
      error.status >= 500 ||
      error.status === 408;
    return transient
      ? new TransientError(error.message, { cause: error })
      : new NonRetryableError(error.message, {
          reason: `github-${error.status ?? "error"}`,
          cause: error,
        });
  }
  return error instanceof Error ? error : new Error(String(error));
}
