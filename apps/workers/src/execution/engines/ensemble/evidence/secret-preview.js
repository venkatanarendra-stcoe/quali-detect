import { SECRET_TYPE_CLASSES } from "@qmentisai/shared";
import { EVIDENCE_CAPS, WITHHELD_LINE } from "./constants.js";
import { maskContextLine, maskFocusLine } from "./mask.js";

/**
 * The MASKED LINE PREVIEW of a secret finding (docs/modules/scan-engines/SPEC.md SE-42 as changed by the owner decision of 2026-11-22, D-27, 17.y,
 * 17.z; part J). The tools give no snippet, so the platform reads the line from the extracted tree at the reported location and masks it
 * ({@link maskFocusLine}). The value is never stored: only the masked text of the focus line and, around it, a few neighbouring lines that
 * are themselves masked (token-looking runs, sensitive assignments, every other finding's span) or withheld. Pure.
 *
 * It FAILS CLOSED and returns `null` (the finding keeps location and link only) when the location is unreliable (a line outside the file, a
 * blank line), the focus line is too long or holds a control byte, or the masking cannot be confirmed.
 */

const CLASSES = new Set(SECRET_TYPE_CLASSES);
const MAX_RANGE_MARKED = 2000;

/**
 * The index of what the tools reported, per file and line, built from the CANDIDATES (before the merge, which keeps only one tool's columns).
 * @param {object[]} candidates secret candidates with `location` and `mergeHints.typeClass`
 */
export function createSecretLineIndex(candidates) {
  /** @type {Map<string, { spans: { startColumn?: number, endColumn?: number }[], unknown: boolean, carries: boolean, typeClass: string }>} */
  const index = new Map();
  const at = (path, line) => {
    const key = `${path}\u0000${line}`;
    let entry = index.get(key);
    if (!entry) {
      entry = { spans: [], unknown: false, carries: true, typeClass: "other" };
      index.set(key, entry);
    }
    return entry;
  };
  for (const c of candidates) {
    const loc = c?.location;
    if (!loc?.path || !Number.isInteger(loc.startLine)) continue;
    const typeClass = CLASSES.has(c.mergeHints?.typeClass) ? c.mergeHints.typeClass : "other";
    const end = Number.isInteger(loc.endLine) ? loc.endLine : loc.startLine;
    const mark = (line, span) => {
      const e = at(loc.path, line);
      e.typeClass = typeClass;
      if (span) e.spans.push(span);
      else e.unknown = true;
    };
    if (end === loc.startLine) {
      mark(
        loc.startLine,
        loc.startColumn !== undefined && loc.endColumn !== undefined
          ? { startColumn: loc.startColumn, endColumn: loc.endColumn }
          : null,
      );
      continue;
    }
    mark(loc.startLine, loc.startColumn !== undefined ? { startColumn: loc.startColumn } : null);
    if (end - loc.startLine <= MAX_RANGE_MARKED)
      for (let n = loc.startLine + 1; n < end; n += 1) mark(n, null);
    mark(end, loc.endColumn !== undefined ? { endColumn: loc.endColumn } : null);
  }
  return {
    /** @param {string} path @param {number} line */
    get: (path, line) => index.get(`${path}\u0000${line}`) ?? null,
    size: index.size,
  };
}

/** The type class of a merged secret finding (the last segment of its dedup key). @param {{ dedupKey?: string }} finding */
export function typeClassOf(finding) {
  const last = String(finding?.dedupKey ?? "")
    .split("|")
    .pop();
  return CLASSES.has(last) ? last : "other";
}

/**
 * @param {{ finding: { location?: { path?: string, startLine?: number, endLine?: number }, dedupKey?: string }, lines: string[], index: ReturnType<typeof createSecretLineIndex> }} input
 * @returns {object | null} an evidence object of the shared schema, or null (fail closed)
 */
export function buildSecretEvidence({ finding, lines, index }) {
  const loc = finding.location;
  if (!loc?.path || !Number.isInteger(loc.startLine)) return null;
  const start = loc.startLine;
  const end = Number.isInteger(loc.endLine) ? loc.endLine : start;
  if (start < 1 || start > lines.length) return null;
  const typeClass = typeClassOf(finding);
  // a multi-line secret (a private key block) shows its first line only: the lines below it ARE the value
  const radius = end > start ? 0 : EVIDENCE_CAPS.secretContextLines;
  const from = Math.max(1, start - radius);
  const to = Math.min(lines.length, start + radius);
  const out = [];
  for (let n = from; n <= to; n += 1) {
    const info = index.get(loc.path, n);
    if (n === start) {
      const masked = maskFocusLine(lines[n - 1], {
        typeClass,
        spans: info?.spans ?? [],
        unknownSpan: info ? info.unknown : true,
      });
      if (masked === null) return null;
      out.push(masked);
      continue;
    }
    const masked = maskContextLine(lines[n - 1], {
      spans: info?.spans ?? [],
      carriesFinding: info?.carries === true,
      unknownSpan: info ? info.unknown : false,
      typeClass: info?.typeClass ?? "other",
    });
    out.push(masked ?? WITHHELD_LINE);
  }
  const snippet = out.join("\n");
  if (!out[start - from].includes("[REDACTED")) return null;
  return {
    kind: to > from ? "window" : "line",
    startLine: from,
    endLine: to,
    focusStart: start,
    focusEnd: start,
    snippet,
  };
}
