import { ERROR_CODES } from "@qmentisai/contracts";

/** HTTP status for each stable error code. */
export const ERROR_HTTP_STATUS = Object.freeze({
  [ERROR_CODES.BAD_REQUEST]: 400,
  [ERROR_CODES.VALIDATION_FAILED]: 400,
  [ERROR_CODES.INVALID_CURSOR]: 400,
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
  [ERROR_CODES.TENANT_DEACTIVATION_EXPIRED]: 409,
  [ERROR_CODES.IDEMPOTENCY_CONFLICT]: 409,
  [ERROR_CODES.PROVIDER_UNAVAILABLE]: 502,
  [ERROR_CODES.LAST_TENANT_ADMIN]: 409,
  [ERROR_CODES.ROLE_IN_USE]: 409,
  [ERROR_CODES.FINDING_STATE_CONFLICT]: 409,
  // Reporting (SPEC 9): a too-large report is refused with 422 (the request is well formed but cannot be served), an expired file is 410.
  [ERROR_CODES.REPORT_PERIOD_INVALID]: 400,
  [ERROR_CODES.REPORT_PERIOD_TOO_LONG]: 400,
  [ERROR_CODES.REPORT_AS_OF_UNAVAILABLE]: 409,
  [ERROR_CODES.REPORT_TOO_LARGE]: 422,
  [ERROR_CODES.REPORT_LIMIT_REACHED]: 429,
  [ERROR_CODES.REPORT_NOT_READY]: 409,
  [ERROR_CODES.REPORT_EXPIRED]: 410,
  [ERROR_CODES.REPORT_TEMPLATE_UNKNOWN]: 400,
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
   * @param {Array<{ path: string, code: string, message: string, reason?: string }>} issues
   * @param {{ source?: string }} [options] Request part: body, querystring, params or headers.
   */
  constructor(issues, { source } = {}) {
    // `details.reason` is the machine reason of the first issue that has one (for example `credential_shape`), else absent
    const reason = issues.find((issue) => typeof issue.reason === "string")?.reason;
    super(ERROR_CODES.VALIDATION_FAILED, "The request is invalid.", {
      details: { source, issues, ...(reason ? { reason } : {}) },
    });
  }
}
