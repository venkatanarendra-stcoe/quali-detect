import { ERROR_CODES } from "@qmentisai/contracts";

/** HTTP status for each stable error code. */
export const ERROR_HTTP_STATUS = Object.freeze({
  [ERROR_CODES.BAD_REQUEST]: 400,
  [ERROR_CODES.VALIDATION_FAILED]: 400,
  [ERROR_CODES.UNAUTHENTICATED]: 401,
  [ERROR_CODES.FORBIDDEN]: 403,
  [ERROR_CODES.RESOURCE_NOT_FOUND]: 404,
  [ERROR_CODES.CONFLICT]: 409,
  [ERROR_CODES.PAYLOAD_TOO_LARGE]: 413,
  [ERROR_CODES.UNSUPPORTED_MEDIA_TYPE]: 415,
  [ERROR_CODES.INTERNAL_ERROR]: 500,
  [ERROR_CODES.SERVICE_UNAVAILABLE]: 503,
  [ERROR_CODES.RATE_LIMITED]: 429,
  [ERROR_CODES.TENANT_SUSPENDED]: 403,
  [ERROR_CODES.TENANT_CONTEXT_REQUIRED]: 403,
  [ERROR_CODES.LAST_TENANT_ADMIN]: 409,
  [ERROR_CODES.ROLE_IN_USE]: 409,
  [ERROR_CODES.ROLE_ESCALATION]: 403,
  [ERROR_CODES.ENTITLEMENT_REQUIRED]: 403,
  [ERROR_CODES.QUOTA_EXCEEDED]: 403,
});

/**
 * Expected, client-safe error. `message` and `details` are returned to the caller, so never put stack traces, SQL,
 * secrets or provider payloads in them. Use `cause` for the underlying error (logged, never returned).
 */
export class AppError extends Error {
  /**
   * @param {string} code One of ERROR_CODES.
   * @param {string} message Safe, human-readable message.
   * @param {{ details?: Record<string, unknown>, cause?: unknown }} [options]
   */
  constructor(code, message, { details, cause } = {}) {
    super(message, { cause });
    this.name = new.target.name;
    this.code = code;
    this.statusCode = ERROR_HTTP_STATUS[code] ?? 500;
    this.details = details;
  }
}

export class NotFoundError extends AppError {
  /** @param {string} [message] */
  constructor(message = "The requested resource was not found.", options) {
    super(ERROR_CODES.RESOURCE_NOT_FOUND, message, options);
  }
}

export class ForbiddenError extends AppError {
  constructor(message = "You do not have permission to perform this action.", options) {
    super(ERROR_CODES.FORBIDDEN, message, options);
  }
}

export class ConflictError extends AppError {
  constructor(message = "The request conflicts with the current state of the resource.", options) {
    super(ERROR_CODES.CONFLICT, message, options);
  }
}

export class ValidationError extends AppError {
  /**
   * @param {Array<{ path: string, code: string, message: string }>} issues
   * @param {{ source?: string }} [options] Request part: body, querystring, params or headers.
   */
  constructor(issues, { source } = {}) {
    super(ERROR_CODES.VALIDATION_FAILED, "The request is invalid.", {
      details: { source, issues },
    });
  }
}
