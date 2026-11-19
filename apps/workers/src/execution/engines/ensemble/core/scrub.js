import { redactCredentialText } from "@qmentisai/infra";

/**
 * Containment of untrusted text and of secret values (docs/modules/scan-engines/SPEC.md 5.6.4, 7.2, ENG-S05, D-5). A secret VALUE
 * is never stored, logged or transmitted: the adapter hands the framework the raw field names that hold it, the framework removes
 * them before the mapper runs, keeps their values only in memory to scrub every string of the candidate (also in base64, base64url,
 * hex, URL-encoded and reversed forms), and derives nothing from them but a length bucket and, in memory only, a task-keyed HMAC.
 */

/** Values shorter than this are not scrubbed from text (a one-letter "value" would erase the title); they are still never stored as a field. */
export const MIN_SCRUB_LENGTH = 4;
// eslint-disable-next-line no-control-regex -- stripping control characters of untrusted text is the point
const ANSI = /\u001b\[[0-9;?]*[ -/]*[@-~]|\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;
// zero-width, bidirectional override/isolate and BOM code points (built from numbers so the source holds no invisible character)
const INVISIBLE_RANGES = [
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x2069],
  [0xfeff, 0xfeff],
];
const INVISIBLE = new RegExp(
  `[${INVISIBLE_RANGES.map(([a, b]) => String.fromCodePoint(a) + "-" + String.fromCodePoint(b)).join("")}]`,
  "gu",
);
const escapeInvisible = (ch) => `\\u${ch.codePointAt(0).toString(16).padStart(4, "0")}`;

/** Text of a tool, safe to store and render: ANSI sequences and control characters removed, bidirectional and zero-width characters shown as visible `\uXXXX`. */
export function cleanText(value) {
  return String(value).replace(ANSI, "").replace(CONTROL, "").replace(INVISIBLE, escapeInvisible);
}

/** Every form of `value` that a leak could take. */
export function secretVariants(value) {
  const raw = String(value);
  if (raw.length < MIN_SCRUB_LENGTH) return [];
  const buf = Buffer.from(raw, "utf8");
  const forms = new Set([
    raw,
    buf.toString("base64"),
    buf.toString("base64").replace(/=+$/, ""),
    buf.toString("base64url"),
    buf.toString("hex"),
    buf.toString("hex").toUpperCase(),
    encodeURIComponent(raw),
    Array.from(raw).reverse().join(""),
  ]);
  return [...forms].filter((f) => f.length >= MIN_SCRUB_LENGTH);
}

/** @param {string} text @param {string[]} variants */
export function removeVariants(text, variants) {
  let out = text;
  for (const v of variants) if (out.includes(v)) out = out.split(v).join("[REDACTED]");
  return out;
}

const PATH_KEYS = new Set(["path"]);
const MAX_DEPTH = 8;

/**
 * Cleans every string of a candidate-like value: control characters and ANSI removed, invisible characters escaped, known secret
 * values and credential shapes redacted. Keys named `path` keep their exact bytes (a finding path is the exact entry name) but are
 * still scrubbed of known secret values.
 * @param {unknown} value @param {string[]} variants @param {number} [depth]
 */
export function scrubDeep(value, variants, depth = 0, key = "") {
  if (depth > MAX_DEPTH) throw new TypeError("candidate too deep");
  if (typeof value === "string") {
    if (PATH_KEYS.has(key)) return removeVariants(value, variants);
    return removeVariants(redactCredentialText(cleanText(value)), variants);
  }
  if (Array.isArray(value)) return value.map((v) => scrubDeep(v, variants, depth + 1, key));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
      out[k] = scrubDeep(v, variants, depth + 1, k);
    }
    return out;
  }
  return value;
}

/** Coarse length bucket of a secret value (SPEC 7.2 example). */
export function lengthBucket(length) {
  if (length <= 16) return "<=16";
  if (length <= 32) return "<=32";
  if (length <= 64) return "<=64";
  return ">64";
}
