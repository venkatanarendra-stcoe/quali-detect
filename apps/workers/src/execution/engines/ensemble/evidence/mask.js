/**
 * Masking of a source line that holds (or may hold) a secret (docs/modules/scan-engines/SPEC.md SE-42, 5.13.4, 17.y, 17.z; part J). Pure; no I/O.
 *
 * The tools give the platform NO snippet (the real Gitleaks `Match` is only a redacted span, detect-secrets gives nothing), so the platform
 * reads the line from the extracted tree itself and masks it. The mask is built from three INDEPENDENT sources and the union is replaced:
 *
 * 1. the span the tools reported (1-based columns, widened by one character on each side because the real Gitleaks columns are shifted by
 *    one on every line after the first, read both as UTF-16 units and as UTF-8 bytes, and widened to the whole token around them);
 * 2. when ANY finding on the line has no span (detect-secrets never has one): the whole right-hand side of the first `key = value`,
 *    `key: value` or `key => value` assignment;
 * 3. every token-looking run of the line (known token prefixes, a long mix of letters and digits, a long high-entropy run).
 *
 * It FAILS CLOSED: a focus line whose masking cannot be confirmed (no span and no assignment, a span outside the line, a mask that leaves a
 * token-looking run, a line that is too long or holds a control byte) gives `null`, and the finding keeps its location and link only.
 */

/** One line of a stored excerpt is at most this many characters (SPEC 5.13.2); a longer FOCUS line is not shown at all. */
export const MAX_LINE_CHARS = 300;

/** The characters that end a token. */
const BOUNDARY = new Set([..." \t\"'`<>(){}[],;"]);
// eslint-disable-next-line no-control-regex -- refusing control characters in a source line is the point
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f]/;
const KNOWN_PREFIX =
  /(?:AKIA|ASIA|AGPA|AIDA|AROA|ghp_|gho_|ghs_|ghu_|ghr_|github_pat_|glpat-|glptt-|xox[abprs]-|[sprw]k_(?:live|test)_|sk-|eyJ|AIza|ya29\.|SG\.|npm_|pypi-|-----BEGIN)/;
const RUN = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
/** The first assignment of a line: an identifier-ish key, an operator, the right-hand side. */
const ASSIGNMENT = /^(.*?[A-Za-z0-9_\]"'`)-]\s*(?::=|=>|===?|:|=)\s*)(\S.*)$/;
/** Key names that mark a value as sensitive on a CONTEXT line. */
const SENSITIVE_KEY =
  /(pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|credential|auth|private|bearer|signature|cert|key)/i;

/** @param {string} s */
const entropy = (s) => {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
};

/**
 * Whether a run of token characters looks like a credential or a key.
 * @param {string} run
 */
export function looksLikeToken(run) {
  if (KNOWN_PREFIX.test(run) && run.length >= 8) return true;
  if (run.length < 16) return false;
  const hasDigit = /[0-9]/.test(run);
  const hasLetter = /[A-Za-z]/.test(run);
  if (hasDigit && hasLetter) return true;
  return run.length >= 20 && entropy(run) >= 4;
}

/** @typedef {[number, number]} Interval half-open `[start, end)` over UTF-16 units of the line */

/** The token-looking runs of a line as intervals. @param {string} line @returns {Interval[]} */
export function tokenRuns(line) {
  const out = [];
  for (const m of line.matchAll(RUN)) {
    const start = m.index ?? 0;
    // a prefix (`ghp_`, `AKIA`) may sit right before a short remainder: extend over the adjacent token characters
    if (
      looksLikeToken(m[0]) ||
      KNOWN_PREFIX.test(line.slice(Math.max(0, start - 12), start + m[0].length))
    )
      out.push(/** @type {Interval} */ ([start, start + m[0].length]));
  }
  for (const m of line.matchAll(
    /(?:AKIA|ASIA|ghp_|gho_|ghs_|ghu_|ghr_|github_pat_|glpat-|xox[abprs]-|[sprw]k_(?:live|test)_|eyJ|AIza)[A-Za-z0-9._+/=-]*/g,
  ))
    out.push(/** @type {Interval} */ ([m.index ?? 0, (m.index ?? 0) + m[0].length]));
  return out;
}

/**
 * Grows an interval left and right over the token around it. To the left an assignment operator (`=` or `:`) also ends the token, so the
 * key name of `KEY=value` stays readable when the reported span starts at the value; the token-run mask still catches whatever
 * token-looking text is left.
 * @param {string} line @param {Interval} iv @returns {Interval}
 */
function widenToToken(line, [a, b]) {
  let s = Math.max(0, a);
  let e = Math.min(line.length, b);
  // the one-character tolerance may sit on the operator itself: it is not part of the value
  if (s < e && (line[s] === "=" || line[s] === ":")) s += 1;
  while (s > 0 && !BOUNDARY.has(line[s - 1]) && line[s - 1] !== "=" && line[s - 1] !== ":") s -= 1;
  while (e < line.length && !BOUNDARY.has(line[e])) e += 1;
  return [s, e];
}

/**
 * The interval a tool-reported span covers, as UTF-16 units (the union of the two readings of a column: as a UTF-16 unit and as a UTF-8
 * byte), with a one-character tolerance on each side, widened to the tokens it touches.
 * @param {string} line
 * @param {{ startColumn?: number, endColumn?: number }} span 1-based columns; an absent start is column 1, an absent end is the end of the line
 * @returns {Interval[]}
 */
export function spanIntervals(line, span) {
  // a span that starts beyond the end of the line is not a location in this line: an empty interval (the caller fails closed)
  if (span.startColumn !== undefined && span.startColumn - 1 > line.length) return [[0, 0]];
  const readings = [];
  const start = span.startColumn === undefined ? 1 : span.startColumn;
  readings.push([start - 1, span.endColumn === undefined ? line.length : span.endColumn]);
  if (Buffer.byteLength(line) !== line.length) {
    // columns counted in UTF-8 bytes: map byte offsets back to UTF-16 units
    const bytes = Buffer.from(line, "utf8");
    const unitAt = (byteOffset) =>
      byteOffset >= bytes.length
        ? line.length
        : bytes.subarray(0, byteOffset).toString("utf8").length;
    readings.push([
      unitAt(start - 1),
      span.endColumn === undefined ? line.length : unitAt(span.endColumn),
    ]);
  }
  return readings.map(([a, b]) =>
    widenToToken(line, [Math.max(0, a - 1), Math.min(line.length, b + 1)]),
  );
}

/** The right-hand side of the first assignment of a line, as an interval, or null. @param {string} line @returns {Interval | null} */
export function assignmentRhs(line) {
  const m = ASSIGNMENT.exec(line);
  if (!m) return null;
  const start = m[1].length;
  // a trailing `;` or `,` stays visible, a trailing line comment is part of the right-hand side (it may quote the value)
  return start < line.length ? [start, line.length] : null;
}

/** The union of intervals, sorted and merged. @param {Interval[]} list @returns {Interval[]} */
export function unionOf(list) {
  const sorted = list.filter(([a, b]) => b > a).sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const out = [];
  for (const iv of sorted) {
    const last = out[out.length - 1];
    if (last && iv[0] <= last[1]) last[1] = Math.max(last[1], iv[1]);
    else out.push([iv[0], iv[1]]);
  }
  return out;
}

/** Replaces the intervals by `marker` (each merged run once). @param {string} line @param {Interval[]} ivs @param {string} marker */
export function applyMask(line, ivs, marker) {
  let out = "";
  let at = 0;
  for (const [a, b] of unionOf(ivs)) {
    out += line.slice(at, a) + marker;
    at = b;
  }
  return out + line.slice(at);
}

/**
 * Masks a FOCUS line (a line a secret finding points at). Returns `null` when the masking cannot be confirmed.
 * @param {string} line
 * @param {{ typeClass: string, spans: { startColumn?: number, endColumn?: number }[], unknownSpan: boolean }} input `spans`: the spans the tools reported for this line (all findings); `unknownSpan`: some finding on this line has no span
 * @returns {string | null}
 */
export function maskFocusLine(line, { typeClass, spans, unknownSpan }) {
  if (typeof line !== "string" || line.length === 0 || line.trim() === "") return null;
  if (line.length > MAX_LINE_CHARS || CONTROL.test(line)) return null;
  const marker = `[REDACTED:${typeClass}]`;
  /** @type {Interval[]} */
  const ivs = [];
  let anchored = false;
  for (const span of spans) {
    const own = spanIntervals(line, span);
    // a span that lies wholly outside the line is an unreliable location: fail closed
    if (own.every(([a, b]) => b <= a)) return null;
    ivs.push(...own);
    anchored = true;
  }
  if (spans.length === 0 || unknownSpan) {
    const rhs = assignmentRhs(line);
    if (rhs) {
      ivs.push(rhs);
      anchored = true;
    } else if (spans.length === 0) {
      // no span and no assignment: nothing says where the value is
      if (tokenRuns(line).length === 0) return null;
    }
  }
  ivs.push(...tokenRuns(line));
  if (!anchored && ivs.length === 0) return null;
  const masked = applyMask(line, ivs, marker);
  // confirmation: the marker is there and nothing token-looking is left
  if (!masked.includes(marker)) return null;
  if (tokenRuns(masked.split(marker).join(" ")).length > 0) return null;
  return masked;
}

/**
 * Masks a CONTEXT line (a neighbour of a finding): other findings' spans, every token-looking run and the right-hand side of an assignment
 * whose key name is sensitive. A context line that itself carries a finding with no known span is masked like a focus line or withheld.
 * @param {string} line
 * @param {{ spans: { startColumn?: number, endColumn?: number }[], carriesFinding: boolean, unknownSpan: boolean, typeClass?: string }} input
 * @returns {string | null} `null`: the line must be withheld
 */
export function maskContextLine(line, { spans, carriesFinding, unknownSpan, typeClass = "other" }) {
  if (typeof line !== "string") return null;
  if (line.trim() === "") return line;
  if (line.length > MAX_LINE_CHARS || CONTROL.test(line)) return null;
  if (carriesFinding) return maskFocusLine(line, { typeClass, spans, unknownSpan });
  const marker = "[REDACTED]";
  /** @type {Interval[]} */
  const ivs = tokenRuns(line);
  const rhs = assignmentRhs(line);
  if (rhs && SENSITIVE_KEY.test(line.slice(0, rhs[0]))) ivs.push(rhs);
  const masked = applyMask(line, ivs, marker);
  return tokenRuns(masked.split(marker).join(" ")).length > 0 ? null : masked;
}

/** Key names whose value is masked on a CODE line (narrow on purpose: a code excerpt must stay readable). */
const CODE_SENSITIVE_KEY =
  /(pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|bearer|authorization)/i;
/** A right-hand side that is a literal value: starts with a quote or backtick, or is one bare word (no call, no operator). */
const LITERAL_RHS = /^(?:["'`]|[A-Za-z0-9+/_.-]{6,}[;,)]?\s*$)/;

/**
 * Masks one line of a CODE excerpt (a SAST finding's window or block), because a code line can itself hold a hard-coded secret and the
 * platform text redaction (`redactLogText`, SE-43) does not recognise every spelling (`dbPassword = "..."`). Masked: token-looking runs and
 * the literal right-hand side of an assignment to a sensitive key name; `force` (a finding of a hard-coded-credential rule, on the lines it
 * points at) masks the right-hand side of the first assignment whatever the key is called. The line is never withheld: it stays readable.
 * @param {string} line @param {{ force?: boolean }} [options]
 */
export function maskCodeLine(line, { force = false } = {}) {
  if (typeof line !== "string" || line.trim() === "") return line;
  /** @type {Interval[]} */
  const ivs = tokenRuns(line);
  const rhs = assignmentRhs(line);
  if (rhs) {
    const key = line.slice(0, rhs[0]);
    if (force || (CODE_SENSITIVE_KEY.test(key) && LITERAL_RHS.test(line.slice(rhs[0]).trimStart())))
      ivs.push(rhs);
  }
  return ivs.length === 0 ? line : applyMask(line, ivs, "[REDACTED]");
}
