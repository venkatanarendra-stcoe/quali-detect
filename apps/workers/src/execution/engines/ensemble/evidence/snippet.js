import { CUT_MARKER, EVIDENCE_CAPS } from "./constants.js";

/**
 * The evidence object of a CODE finding (docs/modules/scan-engines/SPEC.md 5.13.2, 7.4; part J): the enclosing block when the extractor found one
 * of at most 80 lines, else the line window (10 lines either side, clipped to the file), under the line and byte caps. Pure. The text is
 * NOT yet redacted: the caller passes the evidence through the platform scrubber (`scrubDeep`, SE-43) before it is stored.
 */

const NODE_KINDS = new Set(["function", "method", "class"]);

/**
 * Caps one line: control characters were removed by the scrubber later; here only the length is bounded.
 * @param {string} line
 * @returns {{ text: string, cut: boolean }}
 */
export function capLine(line) {
  return line.length > EVIDENCE_CAPS.lineChars
    ? { text: line.slice(0, EVIDENCE_CAPS.lineChars) + CUT_MARKER, cut: true }
    : { text: line, cut: false };
}

/**
 * Joins lines `from..to` (1-based, inclusive) under the line and byte caps. Stops at the byte cap on a line boundary.
 * @param {string[]} lines @param {number} from @param {number} to
 * @param {(text: string, line: number) => string} [transform] applied to each line BEFORE the length cap (masking of a hard-coded secret, SE-43)
 * @returns {{ snippet: string, last: number, truncated: boolean }}
 */
export function joinLines(lines, from, to, transform = (text) => text) {
  const out = [];
  let bytes = 0;
  let truncated = false;
  let last = from - 1;
  for (let n = from; n <= to; n += 1) {
    const { text, cut } = capLine(transform(lines[n - 1], n));
    const size = Buffer.byteLength(text) + 1;
    if (bytes + size > EVIDENCE_CAPS.snippetBytes) {
      truncated = true;
      break;
    }
    out.push(text);
    bytes += size;
    last = n;
    if (cut) truncated = true;
  }
  return { snippet: out.join("\n"), last, truncated };
}

/**
 * @param {{ lines: string[], startLine: number, endLine?: number, block?: { nodeKind: string, enclosingStart: number, enclosingEnd: number } | null, language?: string, transform?: (text: string, line: number) => string }} input
 * @returns {object | null} an evidence object of the shared schema, or null when the location is not in the file
 */
export function buildCodeEvidence({
  lines,
  startLine,
  endLine,
  block = null,
  language,
  transform,
}) {
  const focusEnd = Math.min(endLine ?? startLine, lines.length);
  if (!Number.isInteger(startLine) || startLine < 1 || startLine > lines.length) return null;
  const lang = language ? { language } : {};
  if (
    block &&
    NODE_KINDS.has(block.nodeKind) &&
    block.enclosingStart <= startLine &&
    block.enclosingEnd >= focusEnd &&
    block.enclosingEnd <= lines.length &&
    block.enclosingEnd - block.enclosingStart + 1 <= EVIDENCE_CAPS.blockLines
  ) {
    const joined = joinLines(lines, block.enclosingStart, block.enclosingEnd, transform);
    // a block whose focus line fell off the byte cap is replaced by the window (the focus must be visible)
    if (joined.last >= focusEnd)
      return {
        kind: "block",
        ...lang,
        nodeKind: block.nodeKind,
        startLine: block.enclosingStart,
        endLine: joined.last,
        focusStart: startLine,
        focusEnd,
        snippet: joined.snippet,
        ...(joined.truncated ? { truncated: true } : {}),
      };
  }
  const r = EVIDENCE_CAPS.windowRadius;
  let from = Math.max(1, startLine - r);
  let to = Math.min(lines.length, focusEnd + r);
  // a very long finding range: the window never exceeds the block cap
  if (to - from + 1 > EVIDENCE_CAPS.blockLines) to = from + EVIDENCE_CAPS.blockLines - 1;
  const joined = joinLines(lines, from, to, transform);
  // the focus line must be inside what is stored: move the window down to it when the byte cap cut it off
  if (joined.last < startLine) {
    from = startLine;
    to = Math.min(lines.length, startLine + 2 * r);
    const again = joinLines(lines, from, to, transform);
    if (again.last < startLine) return null;
    return {
      kind: "window",
      ...lang,
      startLine: from,
      endLine: again.last,
      focusStart: startLine,
      focusEnd: Math.min(focusEnd, again.last),
      snippet: again.snippet,
      truncated: true,
    };
  }
  return {
    kind: "window",
    ...lang,
    startLine: from,
    endLine: joined.last,
    focusStart: startLine,
    focusEnd: Math.min(focusEnd, joined.last),
    snippet: joined.snippet,
    ...(joined.truncated ? { truncated: true } : {}),
  };
}
