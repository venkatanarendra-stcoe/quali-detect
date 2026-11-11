/** Paths whose values are replaced with [REDACTED] in every log line (shared by the API and the workers). */
export const REDACT_PATHS = Object.freeze([
  "req.headers.authorization",
  "req.headers.cookie",
  'req.headers["x-api-key"]',
  'res.headers["set-cookie"]',
  // Pino wildcards match one nesting level, so top-level keys are listed explicitly too.
  "authorization",
  "password",
  "token",
  "accessToken",
  "refreshToken",
  "secret",
  "clientSecret",
  "apiKey",
  "plaintext",
  "webhookSecret",
  "installationToken",
  "userToken",
  "masterKey",
  "secretValue",
  "dek",
  "wrappedKey",
  "ciphertext",
  "*.plaintext",
  "*.masterKey",
  "*.secretValue",
  "*.dek",
  "*.wrappedKey",
  "*.ciphertext",
  "privateKey",
  "*.authorization",
  "*.password",
  "*.token",
  "*.accessToken",
  "*.refreshToken",
  "*.secret",
  "*.clientSecret",
  "*.apiKey",
  "*.privateKey",
  "*.webhookSecret",
  "*.installationToken",
  "*.userToken",
]);

/** Minimal logger contract used by this package (a Pino logger satisfies it). */
export const NOOP_LOGGER = Object.freeze({
  trace() {},
  debug() {},
  info() {},
  warn() {},
  error() {},
  child() {
    return NOOP_LOGGER;
  },
});

/**
 * @param {{ child?: Function } | undefined} logger
 * @param {Record<string, unknown>} bindings
 */
export function childLogger(logger, bindings) {
  const base = logger ?? NOOP_LOGGER;
  return typeof base.child === "function" ? base.child(bindings) : base;
}
