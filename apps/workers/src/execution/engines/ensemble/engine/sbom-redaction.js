import { redactLogText } from "@qmentisai/infra";
import { parseBoundedJson, ToolOutputError } from "../core/parse-kit.js";
import { runSync, runYielding } from "../core/yield.js";
import { SBOM_DOCUMENT_MAX_BYTES } from "./constants.js";

/**
 * Per-string redaction of the stored CycloneDX document (docs/modules/scan-engines/SPEC.md 17.l, owner decision 2026-11-20 replacing the
 * whole-text redaction of 17.j / D-23 (2)). The document is parsed with the strict parse kit (size, depth and node caps, forbidden keys),
 * walked ITERATIVELY with a checkpoint per container and per 256 members, and only the string VALUES (and object KEYS) that the credential
 * detector of the artifact store flags are replaced by a fixed marker; everything else is kept, so one credential-shaped field never drops
 * the document and the result is valid JSON by construction (it is serialized from the parsed value, not patched as text).
 *
 * The detector is the artifact store's own text redaction (`redactLogText`): a string is offending when redacting it alone changes it.
 * The serialized document is then checked to be a FIXED POINT of that redaction (the store masks `application/json` artifacts again on
 * `put`; a fixed point makes that pass a no-op, so it cannot break the JSON): if it is not, the document is NOT stored (fail closed).
 * Fail closed also applies when the document cannot be parsed within the caps, is not a JSON object, or exceeds the document ceiling;
 * the caller records the note and the task is never failed.
 */

/** Replaces an offending value (and an offending key). */
export const SBOM_REDACTION_MARKER = "[REDACTED]";
/** A string longer than this is replaced as a whole (a detector pass over it cannot be sliced, and no package field is this long). */
export const SBOM_MAX_STRING_CHARS = 1024 * 1024;
/** Members visited between two checkpoints. */
const MEMBER_STEP = 256;

const isObject = (v) => v !== null && typeof v === "object";

/**
 * The redaction walk as a checkpointed generator (see core/yield.js): `runSync` is the synchronous reference, `runYielding` the driver.
 * @param {any} doc the parsed document (modified in place; the caller owns it)
 * @param {(text: string) => string} redact the credential redaction of the artifact store
 * @returns {Generator<void, { replacedValues: number, replacedKeys: number }, void>}
 */
function* redactSteps(doc, redact) {
  let replacedValues = 0;
  let replacedKeys = 0;
  const offending = (s) => s.length > SBOM_MAX_STRING_CHARS || redact(s) !== s;
  const stack = [doc];
  let steps = 0;
  while (stack.length > 0) {
    const node = stack.pop();
    yield;
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        const v = node[i];
        if (typeof v === "string") {
          if (offending(v)) {
            node[i] = SBOM_REDACTION_MARKER;
            replacedValues += 1;
          }
        } else if (isObject(v)) stack.push(v);
        steps += 1;
        if (steps % MEMBER_STEP === 0) yield;
      }
      continue;
    }
    const keys = Object.keys(node);
    const renamed = new Map();
    const used = new Set(keys);
    let suffix = 1;
    for (const key of keys) {
      const v = node[key];
      if (typeof v === "string") {
        if (offending(v)) {
          node[key] = SBOM_REDACTION_MARKER;
          replacedValues += 1;
        }
      } else if (isObject(v)) stack.push(v);
      if (offending(key)) {
        // keys stay unique, so no member is lost: [REDACTED], [REDACTED]#2, ...
        let name = SBOM_REDACTION_MARKER;
        // bounded: the counter only moves forward, so all offending keys of one object cost O(members) together
        while (used.has(name)) {
          suffix += 1;
          name = `${SBOM_REDACTION_MARKER}#${suffix}`;
        }
        used.add(name);
        renamed.set(key, name);
        replacedKeys += 1;
      }
      steps += 1;
      if (steps % MEMBER_STEP === 0) yield;
    }
    if (renamed.size > 0) {
      // rebuild in place with the original member order
      const entries = keys.map((k) => [renamed.get(k) ?? k, node[k]]);
      for (const k of keys) {
        delete node[k];
        steps += 1;
        if (steps % MEMBER_STEP === 0) yield;
      }
      for (const [k, v] of entries) {
        node[k] = v;
        steps += 1;
        if (steps % MEMBER_STEP === 0) yield;
      }
    }
  }
  return { replacedValues, replacedKeys };
}

/**
 * @param {Buffer | string} stdout the raw document of the tool
 * @param {{ redact?: (text: string) => string, sync?: boolean, yieldOptions?: object, maxBytes?: number }} [options]
 * `redact` is the artifact store's redaction (a parameter only so the suite can drive a hostile one); `sync` runs the reference driver.
 * @returns {Promise<{ ok: true, bytes: Buffer, redacted: boolean, replaced: number } | { ok: false, note: "document_not_json" | "document_too_large" | "redaction_not_stable" }>}
 */
export async function redactedSbomDocument(stdout, options = {}) {
  const {
    redact = redactLogText,
    sync = false,
    yieldOptions,
    maxBytes = SBOM_DOCUMENT_MAX_BYTES,
  } = options;
  const raw = Buffer.isBuffer(stdout) ? stdout : Buffer.from(String(stdout), "utf8");
  if (raw.length > maxBytes) return { ok: false, note: "document_too_large" };
  let doc;
  try {
    doc = parseBoundedJson(raw);
  } catch (error) {
    if (error instanceof ToolOutputError) return { ok: false, note: "document_not_json" };
    throw error;
  }
  if (!isObject(doc) || Array.isArray(doc)) return { ok: false, note: "document_not_json" };
  const steps = redactSteps(doc, redact);
  const counts = sync ? runSync(steps) : await runYielding(steps, yieldOptions);
  const replaced = counts.replacedValues + counts.replacedKeys;
  const original = raw.toString("utf8");
  // an untouched document keeps its exact bytes when the store's pass leaves them alone, otherwise its compact serialization
  const candidates = replaced === 0 ? [original, JSON.stringify(doc)] : [JSON.stringify(doc)];
  // bounded: at most two candidate texts
  for (const text of candidates) {
    if (Buffer.byteLength(text) > maxBytes) return { ok: false, note: "document_too_large" };
    if (redact(text) === text)
      return { ok: true, bytes: Buffer.from(text, "utf8"), redacted: replaced > 0, replaced };
  }
  return { ok: false, note: "redaction_not_stable" };
}
