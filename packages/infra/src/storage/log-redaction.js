import { redactSecretShapes } from "@qmentisai/shared";
import { findCredentials, redactCredentialText } from "../credential-guard.js";

/** Longest stored message in characters (SPEC §7.4); the database repeats it as a CHECK. */
export const LOG_LINE_MAX_CHARS = 2000;
/** Placeholder written where a credential was. */
export const REDACTED = "[REDACTED]";

const LEVELS = new Set(["debug", "info", "warn", "error"]);
// A whole PEM private key block (header, body, footer) across line breaks; an unterminated block is cut to the end of the text.
const PEM_BLOCK =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g;
// Authorization-style headers with any scheme (Basic, Token, Digest, ...): everything after the colon on that line.
const AUTH_HEADER = /\b(proxy-)?authorization\s*[:=]\s*[^\r\n]*/gi;
// key=value / key: value pairs whose key can only hold a secret. The replacement carries no `=` so it can never match the
// query-string shape the database refuses.
const SECRET_PAIR =
  /\b(password|passwd|secret|client[_-]?secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|installation[_-]?token|secret[_-]?ref)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;&]+)/gi;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

/**
 * Redacts credentials from a piece of text (possibly several lines): installation and personal tokens, `Authorization`
 * headers, Bearer tokens, private-key blocks (whole), AWS key ids, credentials inside URLs, token query parameters and
 * `password=...`-style pairs (the patterns of `credential-guard.js` plus the log-specific ones). If anything credential-shaped
 * survives the passes, the whole text is replaced: a log line never keeps a credential shape.
 * @param {string} text
 * @returns {string}
 */
export function redactLogText(text) {
  let out = String(text).replace(PEM_BLOCK, REDACTED);
  out = redactCredentialText(out);
  out = out.replace(
    AUTH_HEADER,
    (_m, proxy) => `${proxy ? "proxy-" : ""}authorization: ${REDACTED}`,
  );
  out = out.replace(SECRET_PAIR, (_m, key) => `${key}: ${REDACTED}`);
  out = redactSecretShapes(out); // the ONE shared list (Stripe, Slack, JWT, quoted assignments, scan-engine secret classes)
  return findCredentials(out).length > 0 ? REDACTED : out;
}

/**
 * Turns one adapter or platform message into stored log lines: redacted FIRST (so a secret split by a line break is still
 * caught as a block), then split at line breaks, control characters turned into spaces, lone surrogates repaired, empty lines
 * dropped and every line cut at `LOG_LINE_MAX_CHARS` (`lineTruncated`). An unknown level becomes `info`.
 * @param {{ level?: string, message: unknown }} input
 * @param {{ maxLines?: number }} [options] at most this many lines come out (default 50)
 * @returns {Array<{ level: "debug" | "info" | "warn" | "error", message: string, lineTruncated: boolean }>}
 */
export function sanitizeLogMessage({ level, message }, { maxLines = 50 } = {}) {
  const safeLevel = LEVELS.has(level) ? level : "info";
  const redacted = redactLogText(String(message ?? "").toWellFormed());
  const lines = [];
  for (const raw of redacted.split(/\r\n|\r|\n/)) {
    if (lines.length >= maxLines) break;
    const text = raw.replace(CONTROL, " ").trim();
    if (text.length === 0) continue;
    const chars = [...text];
    const cut = chars.length > LOG_LINE_MAX_CHARS;
    lines.push({
      level: safeLevel,
      message: cut ? chars.slice(0, LOG_LINE_MAX_CHARS).join("") : text,
      lineTruncated: cut,
    });
  }
  return lines;
}
