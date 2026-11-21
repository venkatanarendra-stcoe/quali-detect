import { normalizeConfidence, normalizeSeverity } from "@qmentisai/shared";
import { z } from "zod";
import { defineToolAdapter } from "../core/adapter.js";
import {
  SAST_MAX_RECORDS,
  buildEvidence,
  clipped,
  relativeUnderSrc,
  sastBody,
  text,
} from "./common.js";
import { VENDORED_DIRECTORIES } from "./languages.js";
import { SAST_TOOL_LIMITS, planSastTool } from "./plan.js";

/**
 * Bandit (Python) as a tool adapter (docs/modules/scan-engines/SPEC.md 5.2, 5.6.3, 5.7, 11.3; IMAGES.md section 8). Bandit's built-in
 * rules (Apache-2.0) run unchanged. Every flag was VERIFIED with a real run on 2026-11-21 (Bandit 1.9.4, Python 3.12, rootful Docker 29.1.3):
 *
 * - `--ini /rules/empty.ini`: without it a repository `.bandit` file IS read ("Found project level .bandit file") and its `skips` removed
 *   all 13 findings of the test tree; with it the same tree gives 13 with a `.bandit`, a `setup.cfg`, a `pyproject.toml`, a `tox.ini`
 *   and a `bandit.yaml` planted. The file must hold a `[bandit]` section or Bandit warns on stderr;
 * - `--ignore-nosec`: without it `# nosec` comments removed 10 of 13 findings (a comment cannot hide a finding, OQ-16);
 * - `-c /rules/bandit.yaml` (the platform configuration), `-f json`, `-q`; `-r /src` for the whole tree, or explicit file targets after `--`
 *   without `-r`.
 * Exit 1 when issues are found, 0 when none, 2 for a configuration or usage error. A file Bandit cannot parse (a syntax error, a null
 * byte, nesting too deep) is listed in `errors[]` and does NOT change the exit code (the run is `partial`). Output (real):
 * `{ errors[], generated_at, metrics, results[] }`; a result has `test_id` (`B608`), `test_name`, `issue_severity`, `issue_confidence`,
 * `issue_text`, `issue_cwe.id`, `filename`, `line_number`, `line_range`, `col_offset`, `end_col_offset`, `code` (numbered source lines,
 * with context) and `more_info` (a URL, never read). The `metrics` object and every field not read here are stripped. **The text of a
 * hard-coded password test (B105, B106, B107) quotes the secret value** (`Possible hardcoded password: 'x'`, verified): such a finding gets a fixed title,
 * no evidence, and the quoted value is removed from every string.
 */

export const BANDIT_ARGV = Object.freeze([
  "-f",
  "json",
  "-c",
  "/rules/bandit.yaml",
  "--ini",
  "/rules/empty.ini",
  "--ignore-nosec",
  "-q",
  // the platform-owned vendored directories at any depth (SPEC 17.w (5)). VERIFIED: bare names match as SUBSTRINGS (`build` also dropped `my_build`
  // and `buildings`), the slash-delimited globs do not
  "-x",
  VENDORED_DIRECTORIES.map((name) => `*/${name}/*`).join(","),
]);
/** The argument that names the whole tree; omitted when explicit targets are given (they follow `--`, without `-r`). */
export const BANDIT_FULL_TARGET = Object.freeze(["-r", "/src"]);
export const BANDIT_ENV = Object.freeze({});
/** 1 is the exit code of a run that found issues. */
export const BANDIT_ACCEPTED_EXIT_CODES = Object.freeze([0, 1]);
/** Hard-coded password tests: their code line IS the secret, so no snippet is kept (SPEC SE-42). */
export const BANDIT_CREDENTIAL_TESTS = Object.freeze(["B105", "B106", "B107"]);
/**
 * The message of those tests is `Possible hardcoded password: '<the value>'` (VERIFIED on a real run, 2026-11-21): the tool's own text
 * carries the secret. Their title is this fixed platform text, and the quoted value is handed to the framework as a SECRET FIELD so it is
 * removed from every string of the finding.
 */
export const BANDIT_CREDENTIAL_TITLE = "Possible hardcoded password";
const CREDENTIAL_MESSAGE = /^Possible hardcoded password: '([\s\S]{1,1000})'$/;

export const banditRecordSchema = z
  .object({
    testId: z.string().regex(/^B\d{3}$/),
    testName: text(80).optional(),
    filename: text(1200),
    lineNumber: z.number().int().min(1).max(10_000_000),
    lineRange: z.array(z.number().int().min(1).max(10_000_000)).min(1).max(5000),
    colOffset: z.number().int().min(0).max(1_000_000).optional(),
    endColOffset: z.number().int().min(0).max(1_000_000).optional(),
    severity: z.string().max(20),
    confidence: z.string().max(20),
    message: clipped(300),
    cwe: z.number().int().min(1).max(100000).optional(),
    code: clipped(20_000).optional(),
    /** The value quoted by a hard-coded password test: a SECRET FIELD (removed before the mapper, scrubbed everywhere). */
    valueHint: z.string().max(1000).optional(),
  })
  .strict();

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const str = (v) => (typeof v === "string" ? v : undefined);
const int = (v) => (Number.isInteger(v) ? v : undefined);

/**
 * Flattens a parsed Bandit report; counts the files Bandit listed in `errors`.
 * @param {unknown} doc @param {{ ToolOutputError: new (reason: string, detail: string) => Error }} kit
 * @returns {{ records: (object | null)[], fileErrors: number }}
 */
export function banditRecords(doc, kit) {
  if (!isObject(doc) || !Array.isArray(doc.results))
    throw new kit.ToolOutputError("output_invalid", "not a Bandit report");
  const records = doc.results.map((r) => {
    if (!isObject(r)) return null;
    return {
      testId: r.test_id,
      testName: str(r.test_name),
      filename: r.filename,
      lineNumber: r.line_number,
      lineRange: Array.isArray(r.line_range)
        ? r.line_range.filter(Number.isInteger).slice(0, 5000)
        : [],
      colOffset: int(r.col_offset),
      endColOffset: int(r.end_col_offset),
      severity: str(r.issue_severity) ?? "",
      confidence: str(r.issue_confidence) ?? "",
      message: str(r.issue_text) ?? "",
      cwe: isObject(r.issue_cwe) ? int(r.issue_cwe.id) : undefined,
      code: str(r.code),
      valueHint: BANDIT_CREDENTIAL_TESTS.includes(r.test_id)
        ? CREDENTIAL_MESSAGE.exec(str(r.issue_text) ?? "")?.[1]
        : undefined,
    };
  });
  const fileErrors = Array.isArray(doc.errors) ? Math.min(doc.errors.length, 1_000_000) : 0;
  return { records, fileErrors };
}

/**
 * The lines of Bandit's numbered `code` ("12 text") inside the reported range, without the numbers (Bandit adds context lines around
 * the match; only the lines of the finding are kept).
 * @param {string | undefined} code @param {number} from @param {number} to
 */
export function banditLines(code, from, to) {
  if (typeof code !== "string") return undefined;
  const out = [];
  for (const line of code.split("\n")) {
    const m = /^(\d{1,8}) ?(.*)$/s.exec(line);
    if (!m) continue;
    const n = Number(m[1]);
    if (n >= from && n <= to) out.push(m[2]);
  }
  return out.length > 0 ? out.join("\n") : undefined;
}

/**
 * The pure mapper of a Bandit record to a code issue candidate body (SPEC 7.2, 5.6.3, 5.7): severity and confidence HIGH, MEDIUM, LOW;
 * the CWE Bandit reports; the line range; the columns of the first and last line.
 * @param {z.infer<typeof banditRecordSchema>} record
 */
export function mapBanditRecord(record) {
  const path = relativeUnderSrc(record.filename);
  if (path === null) throw new TypeError("a path outside the source root");
  const startLine = Math.min(record.lineNumber, ...record.lineRange);
  const endLine = Math.max(record.lineNumber, ...record.lineRange);
  const sev = normalizeSeverity("bandit", record.severity);
  const evidence = BANDIT_CREDENTIAL_TESTS.includes(record.testId)
    ? null
    : buildEvidence({
        lines: banditLines(record.code, startLine, endLine),
        path,
        startLine,
        endLine,
      });
  return {
    ...sastBody({
      ruleId: record.testId,
      ruleName: record.testName,
      title: BANDIT_CREDENTIAL_TESTS.includes(record.testId)
        ? BANDIT_CREDENTIAL_TITLE
        : record.message,
      path,
      startLine,
      endLine,
      // the columns describe the node that starts on `line_number`: kept only where they provably sit on the reported lines
      startColumn:
        record.colOffset === undefined || record.lineNumber !== startLine
          ? undefined
          : record.colOffset + 1,
      endColumn:
        record.endColOffset === undefined || startLine !== endLine
          ? undefined
          : record.endColOffset + 1,
      cwe: record.cwe === undefined ? [] : [record.cwe],
      toolId: "bandit",
      evidence,
    }),
    severity: sev.severity,
    severityAssumed: sev.assumed,
    confidence: normalizeConfidence(record.confidence),
    confidenceBasis: "tool",
    provenance: [
      {
        ruleId: record.testId,
        severityRaw: record.severity.slice(0, 60),
        severityScale: "bandit",
        confidenceRaw: record.confidence.slice(0, 40),
      },
    ],
  };
}

/** @returns {Readonly<object>} */
export function createBanditAdapter() {
  return defineToolAdapter({
    toolId: "bandit",
    scanType: "sast",
    imageKey: "bandit",
    plan: (ctx) =>
      planSastTool(
        {
          toolId: "bandit",
          imageKey: "bandit",
          argv: BANDIT_ARGV,
          fullTarget: BANDIT_FULL_TARGET,
          env: BANDIT_ENV,
          limits: SAST_TOOL_LIMITS.bandit,
        },
        ctx,
      ),
    parse: (streams, kit) => banditRecords(kit.parseBoundedJson(streams.stdout, kit.limits), kit),
    recordSchema: banditRecordSchema,
    secretFields: ["valueHint"],
    map: (record) => mapBanditRecord(record),
    acceptedExitCodes: BANDIT_ACCEPTED_EXIT_CODES,
    maxRecords: SAST_MAX_RECORDS,
  });
}
