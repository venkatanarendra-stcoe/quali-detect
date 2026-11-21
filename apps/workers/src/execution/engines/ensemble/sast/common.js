import { redactLogText } from "@qmentisai/infra";
import { z } from "zod";
import { sastKey, sastRuleClass } from "../core/merge-keys.js";
import { cleanText } from "../core/scrub.js";
import { languageOfFile } from "./languages.js";

/**
 * Pieces shared by the two SAST adapters (docs/modules/scan-engines/SPEC.md 5.6.3, 5.7, 5.13.2, SE-40 to SE-43, 7.2). Pure.
 */

/** Findings a SAST tool may report in one run (the framework cuts a larger output to `partial` / `output_too_large`). */
export const SAST_MAX_RECORDS = 50_000;
/** The tree is mounted at this container path; every path a tool reports must be below it. */
export const SRC_PREFIX = "/src/";

// eslint-disable-next-line no-control-regex -- refusing control characters in untrusted text is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
/** A bounded string without control characters. */
export const text = (max, min = 1) =>
  z
    .string()
    .min(min)
    .max(max)
    .refine((s) => !CONTROL.test(s), "control characters");
/** A bounded string that is clipped (not refused) when too long: the text of a tool message is free text. */
export const clipped = (max) =>
  z
    .string()
    .max(200_000)
    .transform((s) => s.slice(0, max));

/** @param {unknown} value a CWE label such as `CWE-89` or `CWE-89: Improper Neutralization` @returns {number | null} */
export function cweFromLabel(value) {
  const m = typeof value === "string" ? /^\s*(?:CWE-)?(\d{1,6})(?!\d)/i.exec(value) : null;
  const n = m ? Number(m[1]) : Number.NaN;
  return Number.isInteger(n) && n >= 1 && n <= 100000 ? n : null;
}

/** @param {unknown[]} labels @returns {number[]} sorted, unique, at most 10 */
export const cweList = (labels) =>
  [...new Set((Array.isArray(labels) ? labels : []).map(cweFromLabel).filter((n) => n !== null))]
    .sort((a, b) => a - b)
    .slice(0, 10);

/**
 * The repository-relative path of a path a tool reported under the archive mount (`/src/web/app.js` to `web/app.js`), or null for a path
 * outside it (SPEC 11.2: a tool-reported path outside the source root is dropped). The framework checks the rest (a safe relative
 * path that exists in the tree).
 * @param {unknown} reported
 */
export function relativeUnderSrc(reported) {
  if (typeof reported !== "string" || !reported.startsWith(SRC_PREFIX)) return null;
  const rest = reported.slice(SRC_PREFIX.length);
  return rest.length > 0 ? rest : null;
}

/** Excerpt caps (SPEC 5.13.2): lines, characters of one line, characters of the whole snippet. */
export const EVIDENCE_LIMITS = Object.freeze({ lines: 10, lineChars: 300, snippetChars: 4096 });
const CUT = "…";

/**
 * The evidence object of a SAST finding: the reported source lines, bounded (SPEC 5.13.2: at most 10 lines, 300 characters a line, 4 KiB
 * in all, the cut marked `truncated`). The text is UNTRUSTED customer source: the framework scrubs it (`scrubDeep` keeps the line breaks of a
 * `snippet`, removes control characters, redacts credential shapes and the known secret values, SE-43). `null` when there is
 * nothing to show.
 * @param {{ lines: string | undefined, path: string, startLine: number, endLine: number }} input
 */
export function buildEvidence({ lines, path, startLine, endLine }) {
  if (typeof lines !== "string" || lines.trim() === "") return null;
  const all = lines.replaceAll("\r", "").split("\n");
  if (all.length > 1 && all[all.length - 1] === "") all.pop();
  let truncated = all.length > EVIDENCE_LIMITS.lines;
  const kept = all.slice(0, EVIDENCE_LIMITS.lines).map((line) => {
    if (line.length <= EVIDENCE_LIMITS.lineChars) return line;
    truncated = true;
    return `${line.slice(0, EVIDENCE_LIMITS.lineChars)}${CUT}`;
  });
  let snippet = kept.join("\n");
  if (snippet.length > EVIDENCE_LIMITS.snippetChars) {
    snippet = snippet.slice(0, EVIDENCE_LIMITS.snippetChars);
    truncated = true;
  }
  const language = languageOfFile(path);
  const shownEnd = Math.min(endLine, startLine + kept.length - 1);
  return {
    kind: "line",
    ...(language ? { language } : {}),
    startLine,
    ...(shownEnd > startLine ? { endLine: shownEnd } : {}),
    snippet,
    ...(truncated ? { truncated: true } : {}),
  };
}

/**
 * The common body of a SAST candidate (kind, keys, location, evidence); the adapters add severity, confidence and provenance.
 * @param {{ ruleId: string, ruleName?: string, title: string, path: string, startLine: number, endLine: number, startColumn?: number, endColumn?: number, cwe: number[], toolId: string, evidence: object | null }} input
 */
export function sastBody({
  ruleId,
  ruleName,
  title,
  path,
  startLine,
  endLine,
  startColumn,
  endColumn,
  cwe,
  toolId,
  evidence,
}) {
  const ruleClass = sastRuleClass(cwe, toolId, ruleId);
  return {
    kind: "code_issue",
    dedupKey: sastKey(path, ruleClass, startLine),
    // cleaned and redacted with the platform text redaction (SE-43) FIRST, then clipped: the framework scrubs the candidate again (idempotent), so the length that was clipped is the final one
    title: redactLogText(cleanText(title || ruleId)).slice(0, 200),
    rule: {
      id: ruleId,
      ...(ruleName ? { name: redactLogText(cleanText(ruleName)).slice(0, 200) } : {}),
    },
    ...(cwe.length > 0 ? { cwe } : {}),
    location: {
      path,
      startLine,
      ...(endLine > startLine ? { endLine } : {}),
      ...(startColumn !== undefined ? { startColumn } : {}),
      ...(endColumn !== undefined && endColumn >= 1 ? { endColumn } : {}),
    },
    ...(evidence ? { evidence } : {}),
    mergeHints: { ruleClass },
  };
}
