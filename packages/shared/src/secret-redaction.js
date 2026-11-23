/**
 * The ONE shared secret-text redaction (owner decision 2026-11-24, docs/modules/findings/SPEC.md 9.3.2). It is reused by the advisory
 * input builder (`redactCredentialShapes`) and by the platform log redaction (`redactLogText` in `@qmentisai/infra`), so the pattern
 * list lives here only. It covers the scan-engines secret type classes (`SECRET_TYPE_CLASSES`: AWS keys, GitHub / GitLab / Slack tokens,
 * Stripe keys, JWTs, private keys, credentials in URLs, bearer tokens, password and generic API key assignments) plus a few provider
 * token shapes. Every pattern is anchored on a distinctive prefix or on a secret-looking NAME with a QUOTED value, so ordinary prose
 * and code stay untouched. Pure; no dependency.
 */

/** Value shapes of secrets (each one self-identifying). Source of truth; the regexes carry no `g` flag. */
export const SECRET_VALUE_SHAPES = Object.freeze([
  // private key blocks (the body is removed up to the footer, or to the end of an unterminated block)
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/,
  // AWS access key ids (long-term and temporary)
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  // GitHub and GitLab tokens
  /\bgh[pousr]_[A-Za-z0-9_]{8,}/,
  /\bgithub_pat_[A-Za-z0-9_]{8,}/,
  /\bglpat-[A-Za-z0-9_-]{16,}/,
  // Slack tokens (bot, user, app, refresh) and webhook paths
  /\bxox[abeprs]-[A-Za-z0-9-]{10,}/,
  /\bxapp-[0-9]-[A-Za-z0-9-]{10,}/,
  // Stripe secret, restricted and webhook keys (live and test); publishable keys are public and not matched
  /\b[sr]k_(?:live|test)_[A-Za-z0-9]{8,}/,
  /\bwhsec_[A-Za-z0-9]{16,}/,
  // JSON Web Tokens (header.payload.signature, the first two parts are base64url JSON)
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  // bearer tokens
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/i,
  // other provider tokens
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}/,
  /\bnpm_[A-Za-z0-9]{36}\b/,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/,
  // Azure storage connection string key
  /\bAccountKey=[A-Za-z0-9+/]{30,}={0,2}/,
  // credentials inside a URL
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@/i,
]);

/** A QUOTED value (six or more characters, no space) assigned to a secret-looking name: the name stays, the value goes. */
const QUOTED_ASSIGNMENT =
  /(\b(?:pass(?:word|wd)?|secret|client[_-]?secret|token|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key)["']?\s*[:=]\s*["'])[^"'\s]{6,}(["'])/gi;

const GLOBAL = SECRET_VALUE_SHAPES.map(
  (re) => new RegExp(re.source, `${re.flags.replace("g", "")}g`),
);

/**
 * Whether the text holds a secret shape (a value shape or a quoted secret assignment).
 * @param {unknown} text
 * @returns {boolean}
 */
export function hasSecretShape(text) {
  if (typeof text !== "string") return false;
  return (
    SECRET_VALUE_SHAPES.some((re) => re.test(text)) ||
    new RegExp(QUOTED_ASSIGNMENT.source, "i").test(text)
  );
}

/**
 * Replaces every secret shape with `[REDACTED]` (a quoted assignment keeps its name and quotes). Other text is left byte for byte.
 * @param {unknown} text
 * @returns {string}
 */
export function redactSecretShapes(text) {
  let out = String(text ?? "");
  for (const re of GLOBAL) out = out.replace(re, "[REDACTED]");
  return out.replace(QUOTED_ASSIGNMENT, "$1[REDACTED]$2");
}
