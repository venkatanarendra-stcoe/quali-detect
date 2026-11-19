/**
 * Strict parse kit for the output of a scan tool (docs/modules/scan-engines/SPEC.md 7.2 "Mapper boundaries", SE-4, ENG-S09). The
 * output of a tool is UNTRUSTED: it is bounded in size, depth and node count, parsed once, and refused when it carries a key that
 * could pollute a prototype. Nothing here recurses on untrusted depth. Failures throw {@link ToolOutputError} with a FIXED word.
 */

/** Hard defaults; the caller may only lower them. */
export const PARSE_LIMITS = Object.freeze({
  maxBytes: 64 * 1024 * 1024,
  maxDepth: 64,
  maxNodes: 5_000_000,
  maxRecords: 100_000,
});
/** Keys that are refused anywhere in a parsed document (own keys of the parsed objects). */
export const FORBIDDEN_KEYS = Object.freeze(["__proto__", "constructor", "prototype"]);

export class ToolOutputError extends Error {
  /** @param {"output_invalid" | "output_too_large"} reason the fixed failure word of SPEC 5.3 @param {string} detail fixed text, never tool output */
  constructor(reason, detail) {
    super(detail);
    this.name = "ToolOutputError";
    this.reason = reason;
  }
}

const isObject = (v) => v !== null && typeof v === "object";

/**
 * Parses JSON output of a tool: size cap, linear depth pre-check (a deeply nested document is refused before JSON.parse), a
 * node cap and a forbidden-key walk with an explicit stack.
 * @param {Buffer | string} input
 * @param {Partial<typeof PARSE_LIMITS>} [limits]
 * @returns {unknown}
 */
export function parseBoundedJson(input, limits = {}) {
  const cap = { ...PARSE_LIMITS, ...limits };
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
  if (buffer.length > cap.maxBytes)
    throw new ToolOutputError("output_too_large", "output too large");
  if (buffer.length === 0) throw new ToolOutputError("output_invalid", "empty output");
  let depth = 0;
  let inString = false;
  for (let i = 0; i < buffer.length; i += 1) {
    const c = buffer[i];
    if (inString) {
      if (c === 0x5c) i += 1;
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) inString = true;
    else if (c === 0x5b || c === 0x7b) {
      depth += 1;
      if (depth > cap.maxDepth) throw new ToolOutputError("output_invalid", "nesting too deep");
    } else if (c === 0x5d || c === 0x7d) {
      depth -= 1;
      if (depth < 0) throw new ToolOutputError("output_invalid", "unbalanced document");
    }
  }
  let doc;
  try {
    const text = buffer.toString("utf8");
    doc = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch {
    throw new ToolOutputError("output_invalid", "not valid JSON");
  }
  // every container counts itself plus its direct members, so a flood of tiny values is bounded as well
  let nodes = 0;
  const stack = [doc];
  while (stack.length > 0) {
    const node = stack.pop();
    if (!isObject(node)) continue;
    const members = Array.isArray(node) ? node : Object.keys(node);
    nodes += 1 + members.length;
    if (nodes > cap.maxNodes) throw new ToolOutputError("output_too_large", "too many nodes");
    if (Array.isArray(node)) {
      for (const item of node) if (isObject(item)) stack.push(item);
      continue;
    }
    for (const key of members) {
      if (FORBIDDEN_KEYS.includes(key))
        throw new ToolOutputError("output_invalid", "forbidden key");
      const value = node[key];
      if (isObject(value)) stack.push(value);
    }
  }
  return doc;
}

/**
 * A plain array of records out of a parsed document, or a refusal. `pick` selects the array (for example `(d) => d.Results`).
 * @param {unknown} doc @param {(doc: any) => unknown} [pick]
 * @returns {unknown[]}
 */
export function recordsOf(doc, pick = (d) => d) {
  const picked = pick(doc);
  if (!Array.isArray(picked)) throw new ToolOutputError("output_invalid", "records are not a list");
  return picked;
}

/** The kit handed to an adapter's `parse(streams, kit)`. */
export const PARSE_KIT = Object.freeze({ parseBoundedJson, recordsOf, ToolOutputError });
