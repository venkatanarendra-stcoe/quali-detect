/**
 * Credential guard for everything that leaves the fetch step (docs/modules/executions/SPEC.md EXEC-010, ER-5, ADR-009): queue
 * messages, scan contexts, event details, error text and log lines must never carry an installation token, an Authorization
 * header, a `secretRef`, key material or a URL with credentials. `untrusted_fork` executions rely on this at every boundary.
 */

/** Keys that can only hold a credential (case-insensitive, matched on the key name). */
const CREDENTIAL_KEYS =
  /^(authorization|proxy-authorization|cookie|set-cookie|secretRef|secret_ref|secretValue|token|accessToken|access_token|installationToken|installation_token|refreshToken|privateKey|private_key|clientSecret|password|passwd|apiKey|api_key|masterKey|dek)$/i;

/** Value shapes of credentials (GitHub tokens, bearer headers, PEM keys, AWS key ids, credentials inside URLs). */
const CREDENTIAL_VALUES = [
  /\bgh[pousr]_[A-Za-z0-9_]{8,}/,
  /\bgithub_pat_[A-Za-z0-9_]{8,}/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}/,
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@/i,
  /[?&](?:access_token|token|X-Amz-Signature|sig)=[^&\s]{6,}/i,
];

/**
 * Where `value` (any JSON-like structure or string) carries a credential. Returns the paths only, never the values.
 * @param {unknown} value
 * @param {string} [path]
 * @returns {string[]}
 */
export function findCredentials(value, path = "value") {
  if (typeof value === "string")
    return CREDENTIAL_VALUES.some((re) => re.test(value)) ? [path] : [];
  if (Array.isArray(value))
    return value.flatMap((item, i) => findCredentials(item, `${path}[${i}]`));
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, item]) =>
    CREDENTIAL_KEYS.test(key) && item !== null && item !== undefined
      ? [`${path}.${key}`]
      : findCredentials(item, `${path}.${key}`),
  );
}

/**
 * Throws when `value` carries a credential. The error names the path, never the value.
 * @param {unknown} value
 * @param {string} label what is being checked (for example "outbox message")
 * @throws {TypeError}
 */
export function assertNoCredentials(value, label) {
  const found = findCredentials(value, label);
  if (found.length > 0)
    throw new TypeError(`${label} must not carry credentials (found at ${found.join(", ")}).`);
}

/**
 * Replaces credential-shaped substrings with `[REDACTED]` (for error text and log lines that could echo one).
 * @param {string} text
 * @returns {string}
 */
export function redactCredentialText(text) {
  let out = String(text);
  for (const re of CREDENTIAL_VALUES)
    out = out.replace(new RegExp(re.source, `${re.flags.replace("g", "")}g`), "[REDACTED]");
  return out;
}
