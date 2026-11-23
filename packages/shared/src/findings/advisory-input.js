import { z } from "zod";
import {
  ADVISORY_PATH_CLASSES,
  ADVISORY_SUGGESTIONS,
  FINDINGS_LIMITS,
  FINDING_SCAN_TYPES,
} from "./constants.js";
import { classifyAdvisoryPath, redactCredentialShapes, stripUnsafeChars } from "./normalize.js";
import { sha256Hex } from "./sha256.js";

/**
 * The false-positive advisory agent's input, egress levels and output (docs/modules/findings/SPEC.md 9.3; owner decisions of
 * 2026-11-23). Pure, so the suite can call it with canaries. The evidence is UNTRUSTED DATA, never instructions.
 *
 * Owner rules built in here:
 *  - a SECRET finding never sends a snippet, a preview or any value-derived datum to ANY provider, local included (the agent does
 *    not run on secret findings in v1: {@link agentRunsOn});
 *  - a code snippet leaves the platform only to a LOCAL provider, or to an external provider with BOTH the metadata consent and
 *    the separate code-snippet consent (ADR-013 addendum, tier 2);
 *  - a finding of a non-trusted origin never reaches an external provider.
 */

/** Whether the agent runs on a finding at all (owner decision 2026-11-23: not on secrets in v1; not on `info`, SPEC 9.3.5). @param {{ scanType: string, severity?: string }} finding */
export function agentRunsOn(finding) {
  return finding.scanType !== "secrets" && finding.severity !== "info";
}

/**
 * The data-egress level for a provider kind, the tenant's consents and the finding (SPEC 9.3.3 and the owner decision).
 * @param {{
 *   providerKind: "none" | "local" | "external",
 *   externalConsent: boolean,
 *   codeSnippetConsent: boolean,
 *   scanType: string,
 *   originTrust: string,
 * }} input
 * @returns {"none" | "metadata" | "snippet"}
 */
export function egressLevelFor({
  providerKind,
  externalConsent,
  codeSnippetConsent,
  scanType,
  originTrust,
}) {
  if (providerKind === "none") return "none";
  const trusted = originTrust === "trusted";
  const secret = scanType === "secrets";
  if (providerKind === "local") {
    if (!trusted || secret) return "metadata";
    return "snippet";
  }
  // external
  if (!trusted) return "none";
  if (externalConsent !== true) return "none";
  if (codeSnippetConsent !== true || secret) return "metadata";
  return "snippet";
}

const safeText = (max) => z.string().min(1).max(max);

/** The strict input object the model sees (SPEC 9.3.2). No tenant, workspace, repository, pipeline, user, commit, URL, fingerprint. */
export const advisoryInputSchema = z
  .object({
    schemaVersion: z.literal(1),
    findingType: z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_SCAN_TYPES])),
    rule: z.object({ id: safeText(200), name: safeText(200).optional() }).strict(),
    toolSeverity: z.enum(["critical", "high", "medium", "low", "info"]),
    toolConfidence: z.enum(["low", "medium", "high"]),
    toolCount: z.number().int().min(1).max(6),
    cwe: z.array(z.number().int().min(1).max(100000)).max(10),
    advisories: z.array(z.object({ id: safeText(60), family: safeText(20) }).strict()).max(10),
    component: z
      .object({
        name: safeText(200),
        version: safeText(100).optional(),
        ecosystem: safeText(40),
        scope: safeText(20).optional(),
      })
      .strict()
      .optional(),
    fixedVersions: z.array(safeText(100)).max(10).optional(),
    location: z
      .object({
        path: safeText(FINDINGS_LIMITS.advisoryPathChars),
        startLine: z.number().int().min(1).optional(),
        endLine: z.number().int().min(1).optional(),
      })
      .strict(),
    pathClass: z.enum(/** @type {[string, ...string[]]} */ ([...ADVISORY_PATH_CLASSES])),
    history: z
      .object({
        occurrenceCount: z.number().int().min(0),
        daysSinceFirstSeen: z.number().int().min(0),
        reopenCount: z.number().int().min(0),
      })
      .strict(),
    evidence: z
      .object({
        language: safeText(30).optional(),
        nodeKind: safeText(30).optional(),
        snippet: z.string().min(1).max(FINDINGS_LIMITS.advisorySnippetChars),
      })
      .strict()
      .optional(),
  })
  .strict();

/** The whole-output-or-nothing result of the single tool `submit_advice` (SPEC 9.3.6). */
export const advisoryOutputSchema = z
  .object({
    suggestion: z.enum(/** @type {[string, ...string[]]} */ ([...ADVISORY_SUGGESTIONS])),
    confidence: z.number().int().min(0).max(100),
    reasoning: z.string().min(1).max(FINDINGS_LIMITS.reasoningMax),
  })
  .strict();

/**
 * Cleans the model's reasoning for storage: credential shapes redacted, control and bidirectional characters stripped, plain text.
 * @param {string} text
 */
export const cleanAdvisoryReasoning = (text) =>
  redactCredentialShapes(stripUnsafeChars(text)).slice(0, FINDINGS_LIMITS.reasoningMax);

/** The snippet window: at most 40 lines around the focus, 200 characters per line, 1500 characters, redacted. */
function boundedSnippet(evidence) {
  const all = String(evidence.snippet ?? "").split(/\r\n|\r|\n/);
  const start = Number.isInteger(evidence.startLine) ? evidence.startLine : 1;
  const focusIdx = Number.isInteger(evidence.focusStart)
    ? Math.max(0, evidence.focusStart - start)
    : 0;
  const maxLines = FINDINGS_LIMITS.advisorySnippetLines;
  const from = Math.max(0, Math.min(focusIdx - Math.floor(maxLines / 2), all.length - maxLines));
  const lines = all
    .slice(from, from + maxLines)
    .map((l) =>
      redactCredentialShapes(stripUnsafeChars(l)).slice(0, FINDINGS_LIMITS.advisoryLineChars),
    );
  let out = lines.join("\n");
  if (out.length > FINDINGS_LIMITS.advisorySnippetChars)
    out = out.slice(0, FINDINGS_LIMITS.advisorySnippetChars);
  return out;
}

/**
 * Builds the advisory input. At egress `metadata` or `none` the result CANNOT carry `evidence` (a function, not a flag). A secret
 * finding NEVER carries `evidence`, whatever the level, and no secret-derived field exists in the schema at all (no `preview`, no
 * `valueLength`). Returns `null` when the level is `none`.
 * @param {{
 *   scanType: string, ruleId: string, ruleName?: string | null, toolSeverity: string, confidence: string, toolCount?: number,
 *   cwe?: number[], advisoryIds?: Array<{ id: string, family?: string }>, componentName?: string | null,
 *   componentVersion?: string | null, ecosystem?: string | null, componentScope?: string | null, fixedVersions?: string[],
 *   path: string, startLine?: number | null, endLine?: number | null, occurrenceCount: number, firstDetectedAt: Date | string,
 *   reopenCount: number
 * }} finding the `fp_agent_findings` view row (no ids of any tenant object)
 * @param {{ language?: string | null, nodeKind?: string | null, kind?: string | null, startLine?: number | null, focusStart?: number | null, focusEnd?: number | null, snippet?: string | null } | null} evidence
 * @param {"none" | "local" | "metadata" | "snippet"} egressLevel
 * @param {Date} now
 */
export function buildAdvisoryInput(finding, evidence, egressLevel, now) {
  if (egressLevel === "none") return null;
  const path = redactCredentialShapes(stripUnsafeChars(finding.path)).slice(
    0,
    FINDINGS_LIMITS.advisoryPathChars,
  );
  const days = Math.max(
    0,
    Math.floor((now.getTime() - new Date(finding.firstDetectedAt).getTime()) / 86_400_000),
  );
  /** @type {Record<string, unknown>} */
  const input = {
    schemaVersion: 1,
    findingType: finding.scanType,
    rule: {
      id: redactCredentialShapes(finding.ruleId).slice(0, 200),
      ...(finding.ruleName ? { name: redactCredentialShapes(finding.ruleName).slice(0, 200) } : {}),
    },
    toolSeverity: finding.toolSeverity,
    toolConfidence: finding.confidence,
    toolCount: Math.min(6, Math.max(1, finding.toolCount ?? 1)),
    cwe: (finding.cwe ?? []).slice(0, 10),
    advisories: (finding.advisoryIds ?? [])
      .slice(0, 10)
      .map((a) => ({ id: a.id, family: a.family ?? "other" })),
    location: {
      path,
      ...(finding.startLine ? { startLine: finding.startLine } : {}),
      ...(finding.endLine ? { endLine: finding.endLine } : {}),
    },
    pathClass: classifyAdvisoryPath(finding.path),
    history: {
      occurrenceCount: finding.occurrenceCount,
      daysSinceFirstSeen: days,
      reopenCount: finding.reopenCount,
    },
  };
  if (finding.scanType === "sca" && finding.componentName) {
    input.component = {
      name: finding.componentName,
      ...(finding.componentVersion ? { version: finding.componentVersion } : {}),
      ecosystem: finding.ecosystem ?? "unknown",
      ...(finding.componentScope ? { scope: finding.componentScope } : {}),
    };
    if (finding.fixedVersions?.length) input.fixedVersions = finding.fixedVersions.slice(0, 10);
  }
  const mayCarryCode =
    (egressLevel === "snippet" || egressLevel === "local") && finding.scanType !== "secrets";
  if (
    mayCarryCode &&
    evidence &&
    typeof evidence.snippet === "string" &&
    evidence.snippet.length > 0
  ) {
    const snippet = boundedSnippet(evidence);
    if (snippet.length > 0)
      input.evidence = {
        ...(evidence.language ? { language: evidence.language } : {}),
        ...(evidence.nodeKind ? { nodeKind: evidence.nodeKind } : {}),
        snippet,
      };
  }
  return advisoryInputSchema.parse(input);
}

/**
 * The `input_hash` of an advisory (SPEC 9.3.1): SHA-256 over the canonical (key-sorted) JSON of the input.
 * @param {unknown} input
 * @returns {string} 64 hex
 */
export function advisoryInputHash(input) {
  const canon = (v) =>
    Array.isArray(v)
      ? v.map(canon)
      : v && typeof v === "object"
        ? Object.fromEntries(
            Object.keys(v)
              .sort()
              .map((k) => [k, canon(v[k])]),
          )
        : v;
  return sha256Hex(JSON.stringify(canon(input)));
}
