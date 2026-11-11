/**
 * Retry classification and backoff (docs/architecture/WORKER_ARCHITECTURE.md): retry transient network, service,
 * rate-limit and infrastructure failures with bounded exponential backoff and jitter; do not retry invalid credentials,
 * invalid configuration, unsupported targets, validation or permission failures.
 */

/** Throw from a handler to request an automatic retry. */
export class TransientError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "TransientError";
  }
}

/** Throw from a handler when retrying cannot help (the message goes to the dead-letter queue). */
export class NonRetryableError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "NonRetryableError";
  }
}

const TRANSIENT_NETWORK_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EAI_AGAIN",
  "EPIPE",
  "ENOTFOUND",
  "ECONNABORTED",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_SOCKET",
]);
const TRANSIENT_HTTP_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
// Prisma: connection/timeouts/pool exhaustion are transient; constraint and validation errors are not.
const TRANSIENT_PRISMA_CODES = new Set(["P1001", "P1002", "P1008", "P1017", "P2024", "P2034"]);

/**
 * Classifies a thrown value. Explicit `TransientError`/`NonRetryableError` win; then known transient signals
 * (network error codes, HTTP 408/425/429/5xx, transient Prisma codes). Anything else is `unknownAs`
 * (default "non-retryable": an unrecognized failure is not repeated blindly, because a handler may have side effects).
 * @param {unknown} error
 * @param {{ unknownAs?: "transient" | "non-retryable" }} [options]
 * @returns {"transient" | "non-retryable"}
 */
export function classifyError(error, { unknownAs = "non-retryable" } = {}) {
  if (error instanceof NonRetryableError) return "non-retryable";
  if (error instanceof TransientError) return "transient";
  const e = /** @type {any} */ (error);
  if (e && typeof e === "object") {
    if (
      typeof e.code === "string" &&
      (TRANSIENT_NETWORK_CODES.has(e.code) || TRANSIENT_PRISMA_CODES.has(e.code))
    )
      return "transient";
    const status = Number(e.statusCode ?? e.status);
    if (Number.isInteger(status) && status >= 400)
      return TRANSIENT_HTTP_STATUS.has(status) ? "transient" : "non-retryable";
  }
  return unknownAs;
}

/**
 * Delay ceiling for retry number `attempt` (1-based): min(maxDelayMs, baseDelayMs * 2^(attempt-1)).
 * @param {{ attempt: number, baseDelayMs: number, maxDelayMs: number }} input
 */
export function backoffCeilingMs({ attempt, baseDelayMs, maxDelayMs }) {
  return Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
}

/**
 * Bounded exponential backoff with jitter. `equal` (default) = half the ceiling plus a random half; `full` = random up to
 * the ceiling; `none` = the ceiling. Never exceeds `maxDelayMs`.
 * @param {{ attempt: number, baseDelayMs: number, maxDelayMs: number, jitter?: "equal" | "full" | "none", random?: () => number }} input
 * @returns {number} milliseconds
 */
export function computeBackoffDelay({
  attempt,
  baseDelayMs,
  maxDelayMs,
  jitter = "equal",
  random = Math.random,
}) {
  const ceiling = backoffCeilingMs({ attempt, baseDelayMs, maxDelayMs });
  if (jitter === "none") return ceiling;
  if (jitter === "full") return Math.floor(random() * ceiling);
  return Math.floor(ceiling / 2 + random() * (ceiling / 2));
}

/**
 * Normalizes a retry policy.
 * @param {{ maxAttempts?: number, baseDelayMs?: number, maxDelayMs?: number, jitter?: "equal" | "full" | "none" }} [policy]
 */
export function resolveRetryPolicy({
  maxAttempts = 5,
  baseDelayMs = 1000,
  maxDelayMs = 60000,
  jitter = "equal",
} = {}) {
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10)
    throw new RangeError("maxAttempts must be an integer from 1 to 10");
  if (!Number.isInteger(baseDelayMs) || baseDelayMs < 1)
    throw new RangeError("baseDelayMs must be a positive integer");
  if (!Number.isInteger(maxDelayMs) || maxDelayMs < baseDelayMs)
    throw new RangeError("maxDelayMs must be an integer >= baseDelayMs");
  return Object.freeze({ maxAttempts, baseDelayMs, maxDelayMs, jitter });
}
