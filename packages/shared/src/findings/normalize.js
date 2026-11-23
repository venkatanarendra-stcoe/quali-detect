import { FINDINGS_LIMITS } from "./constants.js";

/**
 * Pure normalization shared by the fingerprint, the ingestion plan and the advisory input (docs/modules/findings/SPEC.md 5.2.1).
 * No I/O, no `node:*` import (this package is bundled into the browser).
 */

// eslint-disable-next-line no-control-regex -- refusing control characters in untrusted text is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
// eslint-disable-next-line no-control-regex
const CONTROL_G = /[\u0000-\u001f\u007f-\u009f]/g;
/** Bidirectional override and isolate characters plus the line and paragraph separators. */
const BIDI_G = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]/g;
const BIDI = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]/;

/**
 * Repository-relative POSIX path, normalized for identity (SPEC 5.2.1): NFC, a leading `./` stripped, `//` collapsed, case kept.
 * @param {unknown} value
 * @returns {string | null} `null` when the item must be dropped (`skipped_bad_path`): empty, absolute, a `..` segment, a
 *   backslash, a control or bidirectional character, or longer than 1024
 */
export function normalizePath(value) {
  if (typeof value !== "string") return null;
  let p = value.trim().normalize("NFC");
  if (p.length === 0 || CONTROL.test(p) || BIDI.test(p) || p.includes("\\")) return null;
  while (p.startsWith("./")) p = p.slice(2);
  p = p.replace(/\/{2,}/g, "/");
  if (p.length === 0 || p.startsWith("/") || p.length > FINDINGS_LIMITS.pathMax) return null;
  const segments = p.split("/");
  if (segments.some((s) => s === ".." || s === "." || s === "")) return null;
  return p;
}

/**
 * One line of content for the content key (SPEC 5.2.1): trimmed, runs of whitespace collapsed to one space. Comments are kept.
 * @param {string} line
 */
export const normalizeContentLine = (line) =>
  String(line).normalize("NFC").trim().replace(/\s+/g, " ");

/**
 * Normalized lines of a text: per line normalized, empty lines dropped.
 * @param {string} text
 * @returns {string[]}
 */
export function normalizeContentLines(text) {
  return String(text)
    .split(/\r\n|\r|\n/)
    .map(normalizeContentLine)
    .filter((l) => l.length > 0);
}

/**
 * The lines `focusStart..focusEnd` of an evidence excerpt that starts at `startLine` (1-based).
 * @param {{ snippet?: string | null, startLine?: number | null, focusStart?: number | null, focusEnd?: number | null, kind?: string | null }} evidence
 * @returns {string[] | null} `null` when the excerpt is missing or the focus lies outside it (truncated excerpt)
 */
export function focusLines(evidence) {
  if (!evidence || typeof evidence.snippet !== "string" || evidence.snippet.length === 0)
    return null;
  const lines = evidence.snippet.split(/\r\n|\r|\n/);
  const start = Number.isInteger(evidence.startLine)
    ? /** @type {number} */ (evidence.startLine)
    : 1;
  const fs = Number.isInteger(evidence.focusStart)
    ? /** @type {number} */ (evidence.focusStart)
    : null;
  if (fs === null) return evidence.kind === "line" ? [lines[0]] : null;
  const fe = Number.isInteger(evidence.focusEnd) ? /** @type {number} */ (evidence.focusEnd) : fs;
  const from = fs - start;
  const to = fe - start;
  if (from < 0 || to < from || to >= lines.length) return null;
  return lines.slice(from, to + 1);
}

// The credential shapes of `qm_has_credential_shape` (migration 20261119120000) and `packages/infra` credential-guard.js.
const SHAPES = [
  /\bgh[pousr]_[A-Za-z0-9_]{8,}/,
  /\bgithub_pat_[A-Za-z0-9_]{8,}/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@/i,
  /[?&](access_token|token|X-Amz-Signature|sig)=[^&\s]{6,}/i,
];

/**
 * Whether the text holds a credential-shaped string (the shapes the database CHECK refuses). Used to refuse rationales, comments
 * and justifications (`VALIDATION_FAILED`, `reason: credential_shape`) and to drop tool text before it is stored.
 * @param {unknown} text
 * @returns {boolean}
 */
export function hasCredentialShape(text) {
  return typeof text === "string" && SHAPES.some((re) => re.test(text));
}

/**
 * Replaces every credential-shaped string with `[REDACTED]`; control and bidirectional characters become spaces. The result
 * never holds a credential shape (the whole text is replaced when something survives the passes).
 * @param {unknown} text
 * @returns {string}
 */
export function redactCredentialShapes(text) {
  let out = String(text ?? "")
    .replace(CONTROL_G, " ")
    .replace(BIDI_G, " ");
  for (const re of SHAPES)
    out = out.replace(new RegExp(re.source, `${re.flags.replace("g", "")}g`), "[REDACTED]");
  out = out.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$/, "[REDACTED]");
  return hasCredentialShape(out) ? "[REDACTED]" : out;
}

/** Strips control and bidirectional characters from a path or label that goes to a provider (SPEC 9.3.2). @param {string} text */
export const stripUnsafeChars = (text) =>
  String(text ?? "")
    .replace(CONTROL_G, "")
    .replace(BIDI_G, "");

/**
 * Deterministic class of a path for the advisory input (SPEC 9.3.2).
 * @param {string} path
 * @returns {"test" | "vendor" | "docs" | "config" | "generated" | "source"}
 */
export function classifyAdvisoryPath(path) {
  const p = String(path ?? "").toLowerCase();
  const seg = p.split("/");
  const base = seg[seg.length - 1] ?? "";
  if (
    seg.some((s) =>
      ["node_modules", "vendor", "third_party", "third-party", "bower_components"].includes(s),
    )
  )
    return "vendor";
  if (
    seg.some((s) =>
      ["test", "tests", "__tests__", "spec", "specs", "e2e", "fixtures", "testdata"].includes(s),
    ) ||
    /(^|[._-])(test|spec)\.[a-z0-9]+$/.test(base) ||
    /^test_.*\.py$/.test(base)
  )
    return "test";
  if (
    seg.some((s) =>
      ["dist", "build", "generated", "gen", "__generated__", ".next", "out"].includes(s),
    ) ||
    /\.(min\.js|pb\.go|generated\.[a-z]+)$/.test(base)
  )
    return "generated";
  if (
    seg.some((s) => ["docs", "doc", "documentation"].includes(s)) ||
    /\.(md|rst|adoc|txt)$/.test(base)
  )
    return "docs";
  if (
    seg[0] === ".github" ||
    /\.(ya?ml|json|toml|ini|cfg|conf|properties|env|lock)$/.test(base) ||
    /^(dockerfile|makefile|pom\.xml)$/.test(base)
  )
    return "config";
  return "source";
}

/**
 * The canonical purl of a component WITHOUT version, qualifiers and subpath (`pkg:type/namespace/name`), SPEC 5.2.2.
 * @param {string} purl
 * @returns {string | null}
 */
export function purlWithoutVersion(purl) {
  if (typeof purl !== "string" || !purl.startsWith("pkg:")) return null;
  let rest = purl.slice(4);
  const cut = rest.search(/[?#]/);
  if (cut >= 0) rest = rest.slice(0, cut);
  const slash = rest.lastIndexOf("/");
  const at = rest.indexOf("@", slash + 1);
  if (at >= 0) rest = rest.slice(0, at);
  const firstSlash = rest.indexOf("/");
  if (firstSlash <= 0 || firstSlash === rest.length - 1) return null;
  const type = rest.slice(0, firstSlash).toLowerCase();
  return `pkg:${type}${rest.slice(firstSlash)}`;
}
