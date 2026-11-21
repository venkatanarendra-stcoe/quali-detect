import { z } from "zod";
import { defineToolAdapter } from "../core/adapter.js";
import { LINE, SECRETS_MAX_RECORDS, relativeUnderSrc, secretBody, slugOf, text } from "./common.js";
import { SECRETS_TOOL_LIMITS, planSecretsTool } from "./plan.js";
import { DETECT_SECRETS_KNOWN_TYPES, detectSecretsTypeClass } from "./type-class.js";

/**
 * detect-secrets as a tool adapter (docs/modules/scan-engines/SPEC.md 5.2, 5.6.4, 5.7, 11.3, SE-40 to SE-45; IMAGES.md section 9). The OWN-BUILT
 * image (Apache-2.0, `qm-spike-detect-secrets:1.5.0`, D-14; no registry digest yet, so the production lock still refuses it) runs the sealed
 * line below. VERIFIED with real runs on 2026-11-21 (detect-secrets 1.5.0, rootful Docker 29.1.3):
 *
 * - `-C /src scan --all-files .`: without `--all-files` the tool asks `git ls-files` and fails in a tree that is not a repository (part A); with
 *   it every file is read, including `node_modules` and `.git` (nothing is excluded: SPEC 17.w (5));
 * - `--disable-filter detect_secrets.filters.allowlist.is_line_allowlisted`: without it `# pragma: allowlist secret` hides a finding;
 * - no `--baseline` is ever given: a planted `.secrets.baseline` and `setup.cfg` changed nothing (the same 15 results as the clean tree);
 * - the DEFAULT plugin set only (27 plugins, no `--plugin`, no custom plugin path, nothing from the repository); the heuristic filters of the
 *   default set (indirect references, UUIDs, sequential strings, templated secrets, lock files) stay on;
 * - explicit targets after `--`: `... --disable-filter ... -- /src/web/app.js /src/svc/db.py` scans only those files (verified: three results in
 *   two files); the target `.` scans the tree. A directory that does not exist is NOT an error (exit 0, empty results): the platform mount
 *   always exists, and an empty result of an empty tree is still reported as the tool's output.
 * Exit 0 for a completed scan with or without results; an argument error exits 2 (`exit_code`).
 *
 * Output (real): `{ version, plugins_used[], filters_used[], results: { "<relative path>": [ { type, filename (`/src/...`), hashed_secret, is_verified,
 * line_number } ] }, generated_at }`. **`hashed_secret` is the SHA-1 of the secret value and is NEVER read** (SPEC D-5: nothing derived from a
 * value is stored); `is_verified` is never read either (no verification runs). The flattening reads `type`, `filename` and `line_number` only.
 * There is no match text and no column, so no evidence is kept.
 */

export const DETECT_SECRETS_ARGV = Object.freeze([
  "-C",
  "/src",
  "scan",
  "--all-files",
  "--disable-filter",
  "detect_secrets.filters.allowlist.is_line_allowlisted",
]);
/** The argument that names the whole tree (relative to `-C /src`); omitted when explicit targets are given (they follow `--`). */
export const DETECT_SECRETS_FULL_TARGET = Object.freeze(["."]);
export const DETECT_SECRETS_ENV = Object.freeze({});
export const DETECT_SECRETS_ACCEPTED_EXIT_CODES = Object.freeze([0]);

export const detectSecretsRecordSchema = z
  .object({
    type: text(80),
    filename: text(1200),
    lineNumber: LINE,
  })
  .strict();

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Flattens a parsed detect-secrets report into value-free records: `type`, `filename` and `line_number` of each result, nothing else.
 * @param {unknown} doc @param {{ ToolOutputError: new (reason: string, detail: string) => Error }} kit
 * @returns {(object | null)[]}
 */
export function detectSecretsRecords(doc, kit) {
  if (!isObject(doc) || !isObject(doc.results))
    throw new kit.ToolOutputError("output_invalid", "not a detect-secrets report");
  const records = [];
  for (const list of Object.values(doc.results)) {
    if (!Array.isArray(list)) {
      records.push(null);
      continue;
    }
    for (const r of list) {
      records.push(
        isObject(r) ? { type: r.type, filename: r.filename, lineNumber: r.line_number } : null,
      );
    }
  }
  return records;
}

/**
 * The pure mapper of a detect-secrets record to a secret candidate body (SPEC 7.2, 5.6.4, 5.7).
 * @param {z.infer<typeof detectSecretsRecordSchema>} record
 */
export function mapDetectSecretsRecord(record) {
  const path = relativeUnderSrc(record.filename);
  if (path === null) throw new TypeError("a path outside the source root");
  const known = DETECT_SECRETS_KNOWN_TYPES.includes(record.type);
  return secretBody({
    toolId: "detect-secrets",
    // only a label of the pinned plugin set becomes an id and a name (a value hidden in a label is never copied)
    ruleId: known ? slugOf(record.type) : "unknown",
    ...(known ? { ruleName: record.type } : {}),
    typeClass: detectSecretsTypeClass(record.type),
    path,
    startLine: record.lineNumber,
  });
}

/** @returns {Readonly<object>} */
export function createDetectSecretsAdapter() {
  return defineToolAdapter({
    toolId: "detect-secrets",
    scanType: "secrets",
    imageKey: "detect-secrets",
    plan: (ctx) =>
      planSecretsTool(
        {
          toolId: "detect-secrets",
          imageKey: "detect-secrets",
          argv: DETECT_SECRETS_ARGV,
          fullTarget: DETECT_SECRETS_FULL_TARGET,
          env: DETECT_SECRETS_ENV,
          limits: SECRETS_TOOL_LIMITS["detect-secrets"],
        },
        ctx,
      ),
    parse: (streams, kit) =>
      detectSecretsRecords(kit.parseBoundedJson(streams.stdout, kit.limits), kit),
    recordSchema: detectSecretsRecordSchema,
    map: (record) => mapDetectSecretsRecord(record),
    acceptedExitCodes: DETECT_SECRETS_ACCEPTED_EXIT_CODES,
    maxRecords: SECRETS_MAX_RECORDS,
  });
}
