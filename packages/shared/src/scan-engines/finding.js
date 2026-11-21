import { z } from "zod";
import {
  CONFIDENCES,
  CONFIDENCE_BASES,
  ENSEMBLE_FINDING_SCHEMA_VERSION,
  ENSEMBLE_SCAN_TYPES,
  ENSEMBLE_TOOL_IDS,
  FINDING_KINDS,
  FINDING_LIMITS as L,
  KIND_OF_SCAN_TYPE,
  SECRET_TYPE_CLASSES,
  SEVERITIES,
  SEVERITY_SCALES,
} from "./constants.js";
import { jsonbTextBytes } from "./json-size.js";

/**
 * The normalized ensemble finding (docs/modules/scan-engines/SPEC.md 7.2, owner decision D-11): the SHARED CONTRACT of the scan
 * worker, the API DTO mapper and the future Findings module (no `docs/modules/findings` exists yet, SPEC 0.1). Strict Zod schemas:
 * unknown keys are refused, every string and array is capped. A finding carries NO secret value and NO value-derived fingerprint
 * (D-5); a `dedupKey` is a MERGE key inside one task, never a finding identity (ADR-004, ER-26).
 *
 * `findingSchema` is the record the merger emits; `candidateSchema` is what a tool adapter's mapper emits (one provenance entry,
 * `taskRef`, optional in-memory `mergeHints`).
 */

// eslint-disable-next-line no-control-regex -- refusing control characters in untrusted text is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const bytes = jsonbTextBytes;
const noControl = (max, min = 1) =>
  z
    .string()
    .min(min)
    .max(max)
    .refine((s) => !CONTROL.test(s), "control characters");

/**
 * Whether `value` is a repository-relative POSIX path that stays inside the tree: not empty, not absolute, no `..` or `.` or empty
 * segment, no backslash, no control character, at most 1024 characters.
 * @param {unknown} value
 */
export function isSafeRelativePath(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > L.path) return false;
  if (value.startsWith("/") || value.includes("\\") || CONTROL.test(value)) return false;
  return value.split("/").every((s) => s !== "" && s !== "." && s !== "..");
}
const relPath = z.string().refine(isSafeRelativePath, "not a safe relative path");

const toolId = z.enum(/** @type {[string, ...string[]]} */ ([...ENSEMBLE_TOOL_IDS]));
const line = z.number().int().min(1).max(10_000_000);

export const provenanceEntrySchema = z
  .object({
    toolId,
    toolVersion: noControl(100),
    imageDigestShort: z.string().regex(/^(sha256:[0-9a-f]{8}|none)$/),
    ruleId: noControl(L.ruleId).optional(),
    severityRaw: noControl(60, 0),
    severityScale: z.enum(/** @type {[string, ...string[]]} */ ([...SEVERITY_SCALES])),
    confidenceRaw: noControl(40).optional(),
    /** SCA: the CVSS vectors (and the score where the tool gave one or the calculator computed it) this tool reported, at most two (SPEC 5.6.2). */
    cvss: z
      .array(
        z
          .object({
            version: z.enum(["3.0", "3.1", "4.0"]),
            vector: noControl(200),
            score: z.number().min(0).max(10).optional(),
          })
          .strict(),
      )
      .max(2)
      .optional(),
    rawRef: z.object({ toolRunId: z.string().uuid(), ordinal: z.number().int().min(0) }).strict(),
  })
  .strict()
  .refine((p) => bytes(p) <= L.provenanceEntryBytes, "provenance entry too large");

const evidenceSchema = z
  .object({
    kind: z.enum(["block", "window", "line"]),
    language: noControl(30).optional(),
    nodeKind: noControl(30).optional(),
    startLine: line.optional(),
    endLine: line.optional(),
    focusStart: line.optional(),
    focusEnd: line.optional(),
    snippet: z.string().max(4096).optional(),
    truncated: z.boolean().optional(),
  })
  .strict()
  .refine((e) => bytes(e) <= L.evidenceBytes, "evidence too large");

const locationSchema = z
  .object({
    path: relPath.optional(),
    startLine: line.optional(),
    endLine: line.optional(),
    startColumn: z.number().int().min(1).max(1_000_000).optional(),
    endColumn: z.number().int().min(1).max(1_000_000).optional(),
  })
  .strict()
  .refine(
    (l) => l.endLine === undefined || (l.startLine !== undefined && l.endLine >= l.startLine),
    "line range",
  );

const componentSchema = z
  .object({
    purl: noControl(L.purl),
    name: noControl(200),
    version: noControl(100).optional(),
    ecosystem: noControl(40),
    scope: z.enum(["prod", "dev", "optional", "peer", "unknown"]).optional(),
  })
  .strict();

const shape = {
  schemaVersion: z.literal(ENSEMBLE_FINDING_SCHEMA_VERSION),
  scanType: z.enum(/** @type {[string, ...string[]]} */ ([...ENSEMBLE_SCAN_TYPES])),
  kind: z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_KINDS])),
  dedupKey: noControl(L.dedupKey),
  title: noControl(L.title),
  severity: z.enum(/** @type {[string, ...string[]]} */ ([...SEVERITIES])),
  severityAssumed: z.boolean(),
  confidence: z.enum(/** @type {[string, ...string[]]} */ ([...CONFIDENCES])),
  confidenceBasis: z.enum(/** @type {[string, ...string[]]} */ ([...CONFIDENCE_BASES])),
  rule: z
    .object({ id: noControl(L.ruleId), name: noControl(200).optional(), tool: toolId })
    .strict(),
  cwe: z.array(z.number().int().min(1).max(100000)).max(L.cwe).optional(),
  advisories: z
    .array(z.object({ id: noControl(60), family: noControl(20) }).strict())
    .max(L.advisories)
    .optional(),
  location: locationSchema.optional(),
  component: componentSchema.optional(),
  locations: z
    .array(z.object({ path: relPath, startLine: line.optional() }).strict())
    .max(L.locations)
    .optional(),
  locationCount: z.number().int().min(0).optional(),
  fix: z
    .object({ fixedVersions: z.array(noControl(100)).max(L.fixedVersions) })
    .strict()
    .optional(),
  evidence: evidenceSchema.nullable().optional(),
  scmRef: z
    .object({
      provider: z.enum(["github"]),
      repoFullName: noControl(200),
      commitSha: z.string().regex(/^[0-9a-f]{40}$/),
      path: relPath.optional(),
      startLine: line.optional(),
      endLine: line.optional(),
    })
    .strict()
    .nullable()
    .optional(),
  url: z
    .string()
    .max(L.url)
    .regex(/^https:\/\/[^\s]+$/)
    .nullable()
    .optional(),
  scope: z
    .object({ kind: z.enum(["full", "targets", "full_filtered"]), inScope: z.boolean() })
    .strict()
    .optional(),
  rawRef: z.object({ toolRunId: z.string().uuid(), ordinal: z.number().int().min(0) }).strict(),
  /** Secrets only: at most the 4 leading characters, and only for a value longer than 12 (the `normalizeItems` rule). */
  preview: z.string().max(4).optional(),
};

/** Cross-field rules shared by findings and candidates. */
function refineCommon(f, ctx) {
  const bad = (message) => ctx.addIssue({ code: z.ZodIssueCode.custom, message });
  if (KIND_OF_SCAN_TYPE[f.scanType] !== f.kind) bad("kind does not belong to the scan type");
  if (!f.dedupKey.startsWith(`${f.scanType}|`)) bad("dedupKey must start with the scan type");
  if ((f.kind === "component" || f.kind === "vulnerability") && !f.component)
    bad("component required");
  if (f.kind === "component" && f.severity !== "info") bad("a component is info");
  if (f.kind === "secret" && f.severity === "critical") bad("a secret is never critical in v1");
  if (f.kind !== "secret" && f.preview !== undefined) bad("preview is for secrets only");
  if (f.kind === "secret" && !f.location?.path) bad("a secret needs a path");
  if ((f.kind === "code_issue" || f.kind === "secret") && f.location?.startLine === undefined)
    bad("a line is required");
  if (f.kind === "secret" && f.component) bad("a secret has no component");
  if (f.kind === "vulnerability" && (!f.advisories || f.advisories.length === 0))
    bad("advisory required");
}

export const findingSchema = z
  .object({
    ...shape,
    provenance: z.array(provenanceEntrySchema).min(1).max(L.provenanceEntries),
  })
  .strict()
  .superRefine((f, ctx) => {
    refineCommon(f, ctx);
    const tools = new Set(f.provenance.map((p) => p.toolId));
    if (f.confidenceBasis === "multi_tool" && tools.size < 2)
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "multi_tool needs two distinct tools" });
    if (f.confidenceBasis !== "multi_tool" && tools.size > 1)
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "several tools mean multi_tool" });
    if (!tools.has(f.rule.tool))
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "rule tool not in provenance" });
  });

/**
 * In-memory hints for the merger. They NEVER reach a finding: `fingerprint` is an HMAC under a key that exists only in memory for
 * this task attempt (SPEC 5.6.4); it is dropped when the finding is built.
 */
export const mergeHintsSchema = z
  .object({
    ruleClass: noControl(200).optional(),
    typeClass: z.enum(/** @type {[string, ...string[]]} */ ([...SECRET_TYPE_CLASSES])).optional(),
    fingerprint: z
      .string()
      .regex(/^[0-9a-f]{32}$/)
      .optional(),
    aliases: z.array(noControl(80)).max(40).optional(),
    primaryId: noControl(80).optional(),
    blockId: noControl(80).optional(),
  })
  .strict();

export const candidateSchema = z
  .object({
    ...shape,
    provenance: z.array(provenanceEntrySchema).length(1),
    taskRef: z.string().uuid(),
    mergeHints: mergeHintsSchema.optional(),
  })
  .strict()
  .superRefine((c, ctx) => {
    refineCommon(c, ctx);
    if (c.confidenceBasis === "multi_tool")
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "a candidate comes from one tool" });
    if (c.provenance[0].toolId !== c.rule.tool)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "rule tool differs from the provenance tool",
      });
  });

/**
 * The `extra` column of a detail row (docs/modules/scan-engines/SPEC.md 7.3): what the table has no column for. Validated at WRITE
 * time (owner decision 2026-11-19): strict (an unknown key is refused), every string and array capped, at most
 * {@link FINDING_LIMITS.extraBytes} as `jsonb::text`. It holds no secret value and nothing derived from one (D-5): the worker
 * builds it only from a validated finding and scrubs it with the secret-containment functions first; the database CHECK still
 * refuses a credential shape.
 */
export const detailExtraSchema = z
  .object({
    component: componentSchema.optional(),
    locations: z
      .array(z.object({ path: relPath, startLine: line.optional() }).strict())
      .max(L.locations)
      .optional(),
    locationCount: z.number().int().min(0).max(10_000_000).optional(),
    fix: z
      .object({ fixedVersions: z.array(noControl(100)).max(L.fixedVersions) })
      .strict()
      .optional(),
    ruleName: noControl(200).optional(),
    ruleTool: toolId,
    rawRef: z.object({ toolRunId: z.string().uuid(), ordinal: z.number().int().min(0) }).strict(),
  })
  .strict()
  .refine((e) => bytes(e) <= L.extraBytes, "extra too large");

/**
 * @typedef {z.infer<typeof findingSchema>} EnsembleFinding
 * @typedef {z.infer<typeof candidateSchema>} EnsembleCandidate
 * @typedef {z.infer<typeof provenanceEntrySchema>} ProvenanceEntry
 */
