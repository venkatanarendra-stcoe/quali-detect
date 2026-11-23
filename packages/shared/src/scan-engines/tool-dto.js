import { z } from "zod";
import {
  EVIDENCE_FALLBACK_REASONS,
  EXTRACTOR_STATUSES,
  SEVERITIES,
  TOOL_REASONS,
  TOOL_STATUSES,
} from "./constants.js";

/**
 * The tool-run and coverage part of the task DTO of `GET /executions/{id}` (docs/modules/scan-engines/SPEC.md 8, 17.o; Part L).
 * ONE definition shared by the API response schema, the DTO mapper and the tenant web app, so the two sides cannot drift. Every
 * value is a number, a fixed word, a catalog name or a short hash: no tool output, command line, path, URL or free text.
 */

/** Platform display names of the tools (SPEC 5.2). A tool id outside the catalog has no entry and is never shown by the API. */
export const TOOL_DISPLAY_NAMES = Object.freeze({
  "sbom-lite": "SBOM inventory (built in)",
  syft: "Syft",
  trivy: "Trivy",
  "osv-scanner": "OSV-Scanner",
  opengrep: "Opengrep",
  bandit: "Bandit",
  gosec: "gosec",
  gitleaks: "Gitleaks",
  "detect-secrets": "detect-secrets",
});

/** The word used for a status or reason the API does not know (a newer database value); the web app renders it neutrally. */
export const UNKNOWN_WORD = "unknown";

/** `coverage.state` of the DTO (SCREENS 3.4). `partial` is the cut or stale-data case with no failed tool. */
export const COVERAGE_DTO_STATES = Object.freeze([
  "complete",
  "partial",
  "partial_tools",
  "gaps",
  "nothing_to_scan",
]);
/** The stored `scan_results.coverage.state` word to the DTO word (SPEC 7.3 to SCREENS 3.4). */
export const COVERAGE_STATE_DTO = Object.freeze({
  complete: "complete",
  partial: "partial",
  degraded: "partial_tools",
  language_gap: "gaps",
  nothing_to_scan: "nothing_to_scan",
});

/**
 * Languages or file kinds the platform names in a coverage gap. A gap word outside this list is shown as `other`, so a tool-
 * or repository-derived string can never reach the screen through this field.
 */
export const COVERAGE_GAP_NAMES = Object.freeze([
  "c",
  "cpp",
  "csharp",
  "dart",
  "elixir",
  "go",
  "haskell",
  "java",
  "javascript",
  "kotlin",
  "lua",
  "php",
  "python",
  "ruby",
  "rust",
  "scala",
  "shell",
  "swift",
  "typescript",
  "other",
]);

/** The scan types and tool scopes the DTO names. */
const SCOPE_WORDS = Object.freeze(["full", "changed_paths"]);
export const TOOL_SCOPE_WORDS = SCOPE_WORDS;

const count = z.number().int().min(0);

/** One tool run of the latest attempt of a scan task. */
export const toolRunDtoSchema = z.object({
  toolId: z.enum(Object.keys(TOOL_DISPLAY_NAMES)),
  displayName: z.string(),
  /** `null` while the version is unknown (a tool that never started). */
  version: z.string().nullable(),
  /** `sha256:` plus the first eight hex characters; `null` for the in-process adapter and for a tool that never started. */
  imageShort: z.string().nullable(),
  builtIn: z.boolean(),
  status: z.enum([...TOOL_STATUSES, UNKNOWN_WORD]),
  reason: z.enum([...TOOL_REASONS, UNKNOWN_WORD]).nullable(),
  durationMs: count,
  counts: z.object(Object.fromEntries(SEVERITIES.map((s) => [s, count]))),
  findingsMapped: count,
  /** The kind of record the scan type produces (`component` for SBOM): the screen shows a count, not severity pills. */
  resultKind: z.enum(["component", "vulnerability", "code_issue", "secret"]),
  db: z.object({ builtAt: z.string().nullable(), versionShort: z.string().nullable() }).nullable(),
  scope: z.enum(SCOPE_WORDS).nullable(),
});

/**
 * Vulnerability-data tiers (SPEC scan-engines 5.12, SE-38): a snapshot older than the warn tier is shown "older than 3 days"; older
 * than the hard tier the stronger "out of date" notice. Display only: the server decides the tool status (`partial` / `db_stale`).
 */
export const DB_WARN_DAYS = 3;
export const DB_HARD_DAYS = 14;

/**
 * Attribution for advisory data derived from the GitHub Advisory Database (CC-BY-4.0; SCREENS 12, SPEC D-15, SE-47). ONE constant:
 * screens import it and never retype it. The two URLs are fixed here and are the only links rendered from it. Legal sign-off of
 * the text and its placement is a REQUIRED gate before production (SPEC OQ-26).
 */
export const ADVISORY_ATTRIBUTION = Object.freeze({
  advisoryUrl: "https://github.com/github/advisory-database",
  licenceUrl: "https://creativecommons.org/licenses/by/4.0/",
  text: "This product includes vulnerability advisory data from the GitHub Advisory Database (https://github.com/github/advisory-database), licensed under CC-BY-4.0 (https://creativecommons.org/licenses/by/4.0/). The data has been used in a form that may include format conversion and filtering. National Vulnerability Database data is public domain (U.S. Government work).",
});

/** The coverage statement of a result (counts and fixed words only). */
export const coverageDtoSchema = z.object({
  state: z.enum(COVERAGE_DTO_STATES),
  toolsDegraded: count,
  toolsTotal: count,
  gaps: z.array(z.enum(COVERAGE_GAP_NAMES)),
});

/**
 * The evidence counts of a SAST result stored in `scan_results.coverage.evidence` (SPEC 5.13.2, 17.ac): how many code findings got the
 * enclosing block and how many fell back to the line window, and why. Counts and fixed words only (no path, value or label from a tool);
 * unknown keys are refused. The producer validates it before storing and omits it when it does not hold.
 */
export const evidenceCoverageSchema = z
  .object({
    extractor: z.enum(EXTRACTOR_STATUSES),
    requested: count,
    invalid: count,
    blocks: count,
    windows: count,
    fallbacks: z
      .object(Object.fromEntries(EVIDENCE_FALLBACK_REASONS.map((r) => [r, count.optional()])))
      .strict(),
  })
  .strict();
