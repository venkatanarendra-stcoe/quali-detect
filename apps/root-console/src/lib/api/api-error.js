/**
 * Normalized API failure. Every failure the UI sees is an `ApiError`: HTTP errors carry the server's stable `code`,
 * transport failures use `NETWORK_ERROR` / `TIMEOUT` / `UNEXPECTED_RESPONSE`. `correlationId` lets users quote the
 * request to support. Aborted requests are NOT wrapped (they rethrow the AbortError so query cancellation works).
 */
export class ApiError extends Error {
  /**
   * @param {{ status: number, code: string, message: string, details?: Record<string, unknown>, correlationId?: string | null }} input
   */
  constructor({ status, code, message, details, correlationId = null }) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.correlationId = correlationId;
  }

  get isUnauthenticated() {
    return this.status === 401;
  }
  get isForbidden() {
    return this.status === 403;
  }
  get isNotFound() {
    return this.status === 404;
  }
  /** Transport-level failure (no usable response). */
  get isTransient() {
    return this.status === 0 || this.status >= 500;
  }
}

/** @param {unknown} error */
export const isApiError = (error) => error instanceof ApiError;

/**
 * A short message that is safe to show. Server messages are already client-safe (no stacks or SQL); transport
 * failures get fixed text.
 * @param {unknown} error
 */
export function describeError(error) {
  if (!isApiError(error)) return "Something went wrong. Please try again.";
  if (error.code === "NETWORK_ERROR")
    return "Cannot reach the server. Check your connection and try again.";
  if (error.code === "TIMEOUT") return "The server took too long to respond. Please try again.";
  if (error.code === "UNEXPECTED_RESPONSE")
    return "The server sent an unexpected response. Please try again.";
  if (error.code === "INTERNAL_ERROR") return "Something went wrong on our side. Please try again.";
  return error.message;
}
