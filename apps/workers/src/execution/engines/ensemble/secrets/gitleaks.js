import { z } from "zod";
import { defineToolAdapter } from "../core/adapter.js";
import {
  COLUMN,
  LINE,
  RULE_ID,
  SECRETS_MAX_RECORDS,
  relativeUnderSrc,
  secretBody,
  text,
} from "./common.js";
import { SECRETS_TOOL_LIMITS, planSecretsTool } from "./plan.js";
import { gitleaksTypeClass } from "./type-class.js";

/**
 * Gitleaks as a tool adapter (docs/modules/scan-engines/SPEC.md 5.2, 5.6.4, 5.7, 11.3, SE-40 to SE-45; IMAGES.md section 9). The upstream image
 * (MIT, digest pinned in the lock file, `ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0...`, 8.30.1) runs the sealed line below. Every flag was
 * VERIFIED with a real run on 2026-11-21 (rootful Docker 29.1.3) with negative controls on a planted tree:
 *
 * - `dir /src` is the directory mode: no `.git`, no history (the archive has none);
 * - `--redact` (100): the real JSON has `Secret` and `Match` equal to `REDACTED` (`Match` is ONLY the matched span, never the line), so the
 *   value never leaves the sandbox; the adapter still treats a `Secret` that is not `REDACTED` as a SECRET FIELD (a tool or version that
 *   fails to redact has its value removed from every string, and an in-task HMAC is the only thing derived from it, SPEC 5.6.4);
 * - `-c /rules/gitleaks.toml` (`[extend] useDefault = true`): without it a repository `.gitleaks.toml` is read (verified in part A);
 * - `--ignore-gitleaks-allow`: without it `gitleaks:allow` hides a finding (verified: 9 findings with, one fewer without);
 * - `--exit-code 7`: leaks give 7, none 0, an error 1 (an invalid configuration: `unable to load gitleaks config`);
 * - `--max-target-megabytes 5`: a file over 5 MB is skipped (a size cap, SPEC 11.3); decoding keeps its default depth;
 * - `--report-format json --report-path -`: the JSON array on stdout. `--no-banner --no-color --log-level warn` keep stderr small (the log
 *   level line still carries colour codes, which the exit classifier strips).
 * **A repository `.gitleaksignore` in the root of the scanned tree IS honoured whatever `-c` or `-i` say** (verified: all 9 findings
 * disappeared; one directory down it is not read), and no flag disables it. It is removed at EXTRACTION by the platform deny list
 * ({@link import("./scope.js").isSecretsToolControlPath}, SPEC 11.3 layer 2); `.gitignore`, `.gitattributes` and `.gitleaks.toml` in the
 * tree changed nothing (9 findings). The default configuration's own allowlist skips `node_modules`, lock files, `go.sum` and image files
 * (verified): that is a coverage difference to record, not something the platform can switch off.
 *
 * Output (real): a JSON array; an element has `RuleID`, `Description`, `StartLine`, `EndLine`, `StartColumn`, `EndColumn`, `Match`, `Secret`,
 * `File` (`/src/...`), `Entropy` (a number DERIVED FROM the value: never read), `Fingerprint` (`file:rule:line`, never read), commit fields
 * (empty) and `Tags`. ONLY the fields named in the flattening below are read; every other field is dropped before the schema.
 */

export const GITLEAKS_ARGV = Object.freeze([
  "dir",
  "--no-banner",
  "--no-color",
  "--redact",
  "--exit-code",
  "7",
  "-c",
  "/rules/gitleaks.toml",
  "--ignore-gitleaks-allow",
  "--max-target-megabytes",
  "5",
  "--report-format",
  "json",
  "--report-path",
  "-",
  "--log-level",
  "warn",
]);
/** Gitleaks always scans the whole tree (SPEC 5.9: full run, then filter). */
export const GITLEAKS_FULL_TARGET = Object.freeze(["/src"]);
export const GITLEAKS_ENV = Object.freeze({});
/** 7 is the exit code of a run that found leaks (`--exit-code 7`). */
export const GITLEAKS_ACCEPTED_EXIT_CODES = Object.freeze([0, 7]);
/** The value the tool prints in place of a redacted secret and match. */
export const GITLEAKS_REDACTED = "REDACTED";

/** A value-bearing field is clipped (never refused: a record whose unredacted text is huge must still have it scrubbed from every string). */
const clippedValue = z
  .string()
  .max(5_000_000)
  .transform((v) => v.slice(0, 10_000));

export const gitleaksRecordSchema = z
  .object({
    ruleId: z.string().regex(RULE_ID),
    filename: text(1200),
    startLine: LINE,
    endLine: LINE,
    startColumn: COLUMN.optional(),
    endColumn: COLUMN.optional(),
    /** `Secret` when the tool did NOT redact it: a SECRET FIELD (removed before the mapper, scrubbed everywhere, the only fingerprint source). */
    valueHint: clippedValue.optional(),
    /** `Match` when it is not the redaction marker: also a SECRET FIELD. */
    matchHint: clippedValue.optional(),
  })
  .strict()
  .refine((r) => r.endLine >= r.startLine, "range");

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const unredacted = (v) =>
  typeof v === "string" && v !== "" && v !== GITLEAKS_REDACTED ? v : undefined;

/**
 * Flattens a parsed Gitleaks report into value-free records (the only place that touches raw fields).
 * @param {unknown} doc @param {{ ToolOutputError: new (reason: string, detail: string) => Error }} kit
 * @returns {(object | null)[]}
 */
export function gitleaksRecords(doc, kit) {
  if (!Array.isArray(doc)) throw new kit.ToolOutputError("output_invalid", "not a Gitleaks report");
  return doc.map((r) => {
    if (!isObject(r)) return null;
    return {
      ruleId: r.RuleID,
      filename: r.File,
      startLine: r.StartLine,
      endLine: r.EndLine,
      startColumn:
        Number.isInteger(r.StartColumn) && r.StartColumn >= 1 ? r.StartColumn : undefined,
      endColumn: Number.isInteger(r.EndColumn) && r.EndColumn >= 1 ? r.EndColumn : undefined,
      valueHint: unredacted(r.Secret),
      matchHint: unredacted(r.Match),
    };
  });
}

/**
 * The pure mapper of a Gitleaks record to a secret candidate body (SPEC 7.2, 5.6.4, 5.7): type class from the rule table, fixed title,
 * severity from the platform table, location only.
 * @param {z.infer<typeof gitleaksRecordSchema>} record
 */
export function mapGitleaksRecord(record) {
  const path = relativeUnderSrc(record.filename);
  if (path === null) throw new TypeError("a path outside the source root");
  return secretBody({
    toolId: "gitleaks",
    ruleId: record.ruleId,
    typeClass: gitleaksTypeClass(record.ruleId),
    path,
    startLine: record.startLine,
    endLine: record.endLine,
    startColumn: record.startColumn,
    endColumn: record.endColumn,
  });
}

/** @returns {Readonly<object>} */
export function createGitleaksAdapter() {
  return defineToolAdapter({
    toolId: "gitleaks",
    scanType: "secrets",
    imageKey: "gitleaks",
    plan: (ctx) =>
      planSecretsTool(
        {
          toolId: "gitleaks",
          imageKey: "gitleaks",
          argv: GITLEAKS_ARGV,
          fullTarget: GITLEAKS_FULL_TARGET,
          env: GITLEAKS_ENV,
          limits: SECRETS_TOOL_LIMITS.gitleaks,
        },
        // Gitleaks never receives explicit targets (full run, then filter)
        { ...ctx, targets: undefined },
      ),
    parse: (streams, kit) => gitleaksRecords(kit.parseBoundedJson(streams.stdout, kit.limits), kit),
    recordSchema: gitleaksRecordSchema,
    secretFields: ["valueHint", "matchHint"],
    fingerprintField: "valueHint",
    map: (record) => mapGitleaksRecord(record),
    acceptedExitCodes: GITLEAKS_ACCEPTED_EXIT_CODES,
    maxRecords: SECRETS_MAX_RECORDS,
  });
}
