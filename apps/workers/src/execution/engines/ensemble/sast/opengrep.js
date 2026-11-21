import { normalizeConfidence, normalizeSeverity } from "@qmentisai/shared";
import { z } from "zod";
import { defineToolAdapter } from "../core/adapter.js";
import {
  SAST_MAX_RECORDS,
  buildEvidence,
  clipped,
  cweList,
  relativeUnderSrc,
  sastBody,
  text,
} from "./common.js";
import { VENDORED_DIRECTORIES } from "./languages.js";
import { SAST_TOOL_LIMITS, planSastTool } from "./plan.js";

/**
 * Opengrep as a tool adapter (docs/modules/scan-engines/SPEC.md 5.2, 5.6.3, 5.7, 11.3, D-14, D-16; IMAGES.md section 8). The own-built
 * image (LGPL-2.1 binary in its own container, never linked) runs the PLATFORM-OWNED rule pack only: `--config /rules/qm-sast` is
 * the only configuration, never `auto`, never a registry. Every flag of the sealed line was VERIFIED with a real run on 2026-11-21
 * (Opengrep 2.0.0, rootful Docker 29.1.3; IMAGES.md section 8):
 *
 * - `--disable-nosem`: without it a `nosemgrep` comment in the repository suppresses the finding (verified: 26 results became 0);
 *   with it the results are kept, and the JSON still marks them `is_ignored: true`, a field this adapter NEVER reads (a comment cannot
 *   hide a finding, OQ-16);
 * - `--no-git-ignore`: without it a repository `.gitignore` (and a `.git` directory: exit 2 "Could not get files from git ls-files")
 *   decides which files are scanned;
 * - `--x-ignore-semgrepignore-files` (an `--x-` option "not part of the opengrep API"; it works in 2.0.0, a later version that drops
 *   it exits 2 and the tool fails visibly): without it a repository `.semgrepignore` with `*` made the scan cover 0 files;
 * - `--no-rewrite-rule-ids`: the rule id stays `qm.<lang>.<name>` instead of a path-derived `rules.qm-sast.qm...`;
 * - `--no-autofix` (the tree is read-only anyway), `--timeout 30` (per rule and file), `--max-target-bytes 1000000`, `-j 2`, `--json`,
 *   `--quiet`.
 * - `--exclude <name>` once per platform-owned vendored directory (SPEC 17.w (5)); the repository cannot change the list.
 * There is NO `--metrics` and NO version-check option (`--metrics=off` is an unknown option, exit 2); the binary has no metrics or
 * update feature and the container has no network. `.semgrep.yml`, `.semgrep/`, `.opengrep/` and `semgrep.yml` in the repository are
 * never read (config planting test, same 26 results as the clean tree).
 *
 * Output (real): `{ version, results[], errors[], paths: { scanned[] }, skipped_rules, interfile_languages_used }`; a result has
 * `check_id`, `path`, `start` and `end` of `{ line, col, offset }`, and `extra` with `message`, `severity` (ERROR, WARNING, INFO),
 * `metadata` (the platform rule's own `cwe`, `confidence`, `category`), `lines` (the source line or lines), and `metavars`, whose
 * `abstract_content` is the SOURCE TEXT of each matched variable. `metavars` is read for ONE purpose only: the value of `$VALUE` in a
 * `hardcoded-credential` finding, handed to the framework as a SECRET FIELD, so that exact text is removed from every string of the
 * finding. Exit 0 with and without findings (no `--error`); 2 for a file or rule error, 7 for an invalid or missing configuration, 8 for
 * an unknown rule language; `errors[]` lists files that could not be processed (a syntax error is `PartialParsing` at level `warn`).
 */

export const OPENGREP_ARGV = Object.freeze([
  "scan",
  "--config",
  "/rules/qm-sast",
  "--disable-nosem",
  "--no-git-ignore",
  "--x-ignore-semgrepignore-files",
  "--no-rewrite-rule-ids",
  "--json",
  "--quiet",
  "--timeout",
  "30",
  "--max-target-bytes",
  "1000000",
  "-j",
  "2",
  "--no-autofix",
  // the platform-owned vendored directories, skipped at any depth (SPEC 17.w (5); verified: `--exclude node_modules` also skips `deep/node_modules`
  // and keeps `my_build` and `buildings`)
  ...VENDORED_DIRECTORIES.flatMap((name) => ["--exclude", name]),
]);
/** The Opengrep version whose flags were VERIFIED (SPEC 17.w (4)); the lock file must name exactly this version, so an upgrade is a deliberate, re-verified act. */
export const OPENGREP_VERIFIED_VERSION = "2.0.0";
/** The argument that names the whole tree; omitted when explicit targets are given (they follow `--`). */
export const OPENGREP_FULL_TARGET = Object.freeze(["/src"]);
/** No effect was proven (the tool has no such feature); they are in the sandbox allowlist and cost nothing. */
export const OPENGREP_ENV = Object.freeze({
  SEMGREP_SEND_METRICS: "off",
  SEMGREP_ENABLE_VERSION_CHECK: "0",
});
/** The only accepted exit code: findings do not change it (no `--error`). */
export const OPENGREP_ACCEPTED_EXIT_CODES = Object.freeze([0]);
/** A platform rule id: `qm.<language>.<name>`; anything else is not from the platform pack and is dropped. */
export const PLATFORM_RULE_ID = /^qm\.[a-z0-9]+\.[a-z0-9]+(?:-[a-z0-9]+)*$/;
/** Rule categories whose finding never carries a snippet (a hard-coded credential IS the secret). */
export const CREDENTIAL_CATEGORY = "hardcoded-credential";

const position = z.object({
  line: z.number().int().min(1).max(10_000_000),
  col: z.number().int().min(1).max(1_000_000),
});

/** One result (the record the framework validates). Unknown keys are STRIPPED by the flattening below, never copied. */
export const opengrepRecordSchema = z
  .object({
    ruleId: z.string().max(200).regex(PLATFORM_RULE_ID),
    path: text(1200),
    start: position,
    end: position,
    severity: z.string().max(20),
    message: clipped(300),
    cwe: z.array(z.string().max(120)).max(10),
    confidence: z.string().max(20).optional(),
    qmSeverity: z.string().max(20).optional(),
    category: z.string().max(60).optional(),
    lines: clipped(20_000).optional(),
    /** The source text of `$VALUE` of a hard-coded credential rule: a SECRET FIELD (removed before the mapper, scrubbed everywhere). */
    valueHint: z.string().max(1000).optional(),
  })
  .strict()
  .refine((r) => r.end.line >= r.start.line, "range");

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const str = (v) => (typeof v === "string" ? v : undefined);

/**
 * Flattens a parsed Opengrep report into records and counts the files the tool could not process.
 * @param {unknown} doc @param {{ ToolOutputError: new (reason: string, detail: string) => Error }} kit
 * @returns {{ records: (object | null)[], fileErrors: number }}
 */
export function opengrepRecords(doc, kit) {
  if (!isObject(doc) || !Array.isArray(doc.results))
    throw new kit.ToolOutputError("output_invalid", "not an Opengrep report");
  const records = doc.results.map((r) => {
    if (!isObject(r) || !isObject(r.extra) || !isObject(r.start) || !isObject(r.end)) return null;
    const meta = isObject(r.extra.metadata) ? r.extra.metadata : {};
    const category = str(meta.category);
    const value =
      category === CREDENTIAL_CATEGORY &&
      isObject(r.extra.metavars) &&
      isObject(r.extra.metavars.$VALUE)
        ? str(r.extra.metavars.$VALUE.abstract_content)
        : undefined;
    return {
      ruleId: r.check_id,
      path: r.path,
      start: { line: r.start.line, col: r.start.col },
      end: { line: r.end.line, col: r.end.col },
      severity: str(r.extra.severity) ?? "",
      message: str(r.extra.message) ?? "",
      cwe: (Array.isArray(meta.cwe) ? meta.cwe : [])
        .filter((x) => typeof x === "string")
        .slice(0, 10),
      confidence: str(meta.confidence),
      qmSeverity: str(meta.qm_severity),
      category,
      lines: str(r.extra.lines),
      valueHint: value,
    };
  });
  // every entry of `errors` is a file or rule the tool could not fully process (a syntax error, a timeout): the run is `partial`
  const fileErrors = Array.isArray(doc.errors) ? Math.min(doc.errors.length, 1_000_000) : 0;
  return { records, fileErrors };
}

/**
 * The pure mapper of an Opengrep record to a code issue candidate body (SPEC 7.2, 5.6.3, 5.7). Severity is the rule's ERROR, WARNING or
 * INFO (high, medium, low), or the platform rule's own `qm_severity`; the confidence is the rule's `confidence`. A hard-coded
 * credential finding has NO snippet (SPEC SE-42: omit rather than risk the value).
 * @param {z.infer<typeof opengrepRecordSchema>} record
 */
export function mapOpengrepRecord(record) {
  const path = relativeUnderSrc(record.path);
  if (path === null) throw new TypeError("a path outside the source root");
  const sev = normalizeSeverity("opengrep", record.severity, { qmSeverity: record.qmSeverity });
  const evidence =
    record.category === CREDENTIAL_CATEGORY
      ? null
      : buildEvidence({
          lines: record.lines,
          path,
          startLine: record.start.line,
          endLine: record.end.line,
        });
  return {
    ...sastBody({
      ruleId: record.ruleId,
      title: record.message,
      path,
      startLine: record.start.line,
      endLine: record.end.line,
      startColumn: record.start.col,
      endColumn: record.end.col,
      cwe: cweList(record.cwe),
      toolId: "opengrep",
      evidence,
    }),
    severity: sev.severity,
    severityAssumed: sev.assumed,
    confidence: normalizeConfidence(record.confidence),
    confidenceBasis: "tool",
    provenance: [
      {
        ruleId: record.ruleId,
        severityRaw: record.severity.slice(0, 60),
        severityScale: "opengrep",
        ...(record.confidence ? { confidenceRaw: record.confidence.slice(0, 40) } : {}),
      },
    ],
  };
}

/** @returns {Readonly<object>} */
export function createOpengrepAdapter() {
  return defineToolAdapter({
    toolId: "opengrep",
    scanType: "sast",
    imageKey: "opengrep",
    plan: (ctx) =>
      planSastTool(
        {
          toolId: "opengrep",
          imageKey: "opengrep",
          argv: OPENGREP_ARGV,
          fullTarget: OPENGREP_FULL_TARGET,
          env: OPENGREP_ENV,
          limits: SAST_TOOL_LIMITS.opengrep,
        },
        ctx,
      ),
    parse: (streams, kit) => opengrepRecords(kit.parseBoundedJson(streams.stdout, kit.limits), kit),
    recordSchema: opengrepRecordSchema,
    secretFields: ["valueHint"],
    map: (record) => mapOpengrepRecord(record),
    acceptedExitCodes: OPENGREP_ACCEPTED_EXIT_CODES,
    maxRecords: SAST_MAX_RECORDS,
  });
}
