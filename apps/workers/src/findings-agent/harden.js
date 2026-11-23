import { redactLogText } from "@qmentisai/infra";
import { advisoryInputSchema } from "@qmentisai/shared";

/**
 * Defence in depth for what leaves the agent and what the model writes back (docs/modules/findings/SPEC.md 9.3.2: "re-passed through the
 * platform redaction"). `buildAdvisoryInput` (frozen, mirrors the credential shapes of the database CHECK) covers GitHub tokens, AWS
 * access key ids, URLs with credentials, bearer tokens and private keys; this layer adds the other common provider token shapes and a
 * quoted `secret = "value"` assignment, plus the platform `redactLogText`. A source excerpt can still hold a secret NO pattern knows:
 * that residual risk is why the excerpt needs its own tenant consent for an external provider and why secret findings never run.
 */
const EXTRA_SHAPES = [
  /\b[sr]k_(?:live|test)_[A-Za-z0-9]{8,}/g,
  /\bpk_(?:live|test)_[A-Za-z0-9]{8,}/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*/g,
];
/** A quoted value assigned to a secret-looking name: the name stays, the value goes. */
const ASSIGNMENT =
  /(\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[:=]\s*["'])[^"'\s]{6,}(["'])/gi;

/**
 * @param {string} text
 * @returns {string}
 */
export function redactExtraShapes(text) {
  let out = redactLogText(String(text));
  for (const re of EXTRA_SHAPES) out = out.replace(re, "[REDACTED]");
  return out.replace(ASSIGNMENT, "$1[REDACTED]$2");
}

const deepMap = (value) => {
  if (typeof value === "string") return redactExtraShapes(value);
  if (Array.isArray(value)) return value.map(deepMap);
  if (value && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, deepMap(v)]));
  return value;
};

/**
 * Runs every string of the built advisory input through the extra redaction and re-validates it against the strict schema.
 * @param {Record<string, unknown>} input a value `buildAdvisoryInput` returned
 * @returns {Record<string, unknown>}
 */
export function hardenAdvisoryInput(input) {
  return advisoryInputSchema.parse(deepMap(input));
}
