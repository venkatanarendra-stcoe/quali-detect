/**
 * Stable machine codes of the entitlement gate. They equal `ERROR_CODES.ENTITLEMENT_REQUIRED` / `QUOTA_EXCEEDED` of
 * `@qmentisai/contracts` (not imported: this package has no dependency on it).
 */
export const ENTITLEMENT_ERROR_CODES = Object.freeze({
  ENTITLEMENT_REQUIRED: "ENTITLEMENT_REQUIRED",
  QUOTA_EXCEEDED: "QUOTA_EXCEEDED",
});

/**
 * Domain error thrown by the entitlement helpers (API and workers). `message` and `details` are client-safe. The API
 * error handler maps it to the HTTP 403 envelope; workers map `code` to their own outcome (for example a blocked row).
 */
export class EntitlementError extends Error {
  /**
   * @param {"ENTITLEMENT_REQUIRED" | "QUOTA_EXCEEDED"} code
   * @param {string} message
   * @param {{ details?: Record<string, unknown> }} [options]
   */
  constructor(code, message, { details } = {}) {
    super(message);
    this.name = "EntitlementError";
    this.code = code;
    this.details = details;
  }
}
