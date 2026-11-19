/**
 * Errors of the scan sandbox layer (docs/modules/scan-engines/SPEC.md 6.2 to 6.5, ADR-014).
 * Messages name fields and rules, never values: a spec can carry repository-derived text.
 */

/** Stable machine codes of {@link SandboxError}. */
export const SANDBOX_ERROR_CODES = Object.freeze({
  invalidConfig: "invalid_config",
  invalidSpec: "invalid_spec",
  policyViolation: "policy_violation",
  runtimeUnavailable: "runtime_unavailable",
  runtimeError: "runtime_error",
  capacity: "capacity",
  imageUnavailable: "image_unavailable",
});

export class SandboxError extends Error {
  /**
   * @param {string} code one of {@link SANDBOX_ERROR_CODES}
   * @param {string} message names the rule or field, never a value
   * @param {string[]} [problems] one entry per violated rule (rule names only)
   */
  constructor(code, message, problems = []) {
    super(message);
    this.name = "SandboxError";
    this.code = code;
    this.problems = Object.freeze([...problems]);
  }
}
