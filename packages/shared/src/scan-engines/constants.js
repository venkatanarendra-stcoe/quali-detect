/**
 * Constants of the scan-engine ensemble (docs/modules/scan-engines/SPEC.md 5.2 to 5.7, 7.2; part D). Shared by the scan worker, the
 * future API mapper and the security suite, so there is one definition of each word.
 */

/** Schema version of one normalized (ensemble) finding record (SPEC 7.2). Consumers refuse any other value. */
export const ENSEMBLE_FINDING_SCHEMA_VERSION = 1;
/** `scan_results.schema_version` of a result produced by an ensemble engine (SPEC 7.3). */
export const ENSEMBLE_RESULT_SCHEMA_VERSION = 2;

/** Scan types an ensemble engine can serve. */
export const ENSEMBLE_SCAN_TYPES = Object.freeze(["sbom", "sca", "sast", "secrets"]);
/** Finding kinds (`license` is reserved and is not accepted yet). */
export const FINDING_KINDS = Object.freeze(["component", "vulnerability", "code_issue", "secret"]);
/** The only finding kind a scan type may produce. */
export const KIND_OF_SCAN_TYPE = Object.freeze({
  sbom: "component",
  sca: "vulnerability",
  sast: "code_issue",
  secrets: "secret",
});
export const SEVERITIES = Object.freeze(["critical", "high", "medium", "low", "info"]);
/** Rank of a severity (higher is worse). */
export const SEVERITY_RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, info: 0 });
export const CONFIDENCES = Object.freeze(["low", "medium", "high"]);
export const CONFIDENCE_RANK = Object.freeze({ low: 0, medium: 1, high: 2 });
export const CONFIDENCE_BASES = Object.freeze(["tool", "multi_tool", "heuristic"]);

/**
 * Tool ids of the v1 ensembles, in TOOL ORDER (ties between tools are broken by this order, SPEC 5.6.3). `sbom-lite` is the
 * in-process SBOM adapter.
 */
export const ENSEMBLE_TOOL_IDS = Object.freeze([
  "sbom-lite",
  "syft",
  "trivy",
  "osv-scanner",
  "opengrep",
  "bandit",
  "gosec",
  "gitleaks",
  "detect-secrets",
]);
/** The scan types each tool may serve (SPEC 5.2). */
export const TOOL_SCAN_TYPES = Object.freeze({
  "sbom-lite": ["sbom"],
  syft: ["sbom"],
  trivy: ["sbom", "sca"],
  "osv-scanner": ["sca"],
  opengrep: ["sast"],
  bandit: ["sast"],
  gosec: ["sast"],
  gitleaks: ["secrets"],
  "detect-secrets": ["secrets"],
});
/** DEFERRED to v2 (owner decision OQ-24, 2026-11-19): never selected, never an adapter, never a provenance entry. */
export const DEFERRED_TOOL_IDS = Object.freeze(["grype"]);
/** EXCLUDED by the licence or safety gate of the Part A spike (SPEC 5.2.1): never selected. `semgrep-oss` is the not-selected fallback. */
export const EXCLUDED_TOOL_IDS = Object.freeze([
  "cdxgen",
  "trufflehog",
  "brakeman",
  "codeql",
  "semgrep-oss",
]);

/** Severity scales a tool can report in (the `severityScale` of a provenance entry). */
export const SEVERITY_SCALES = Object.freeze([
  "cvss",
  "trivy",
  "osv",
  "opengrep",
  "bandit",
  "gosec",
  "platform_table",
  "none",
]);

/** Per-tool run statuses (SPEC 5.3). */
export const TOOL_STATUSES = Object.freeze([
  "succeeded",
  "partial",
  "failed",
  "timed_out",
  "cancelled",
  "skipped",
  "unavailable",
]);
/** Fixed failure-reason words (SPEC 5.3): stable codes, never tool text. */
export const TOOL_REASONS = Object.freeze([
  "image_unavailable",
  "db_unavailable",
  "db_stale",
  "timeout",
  "out_of_memory",
  "exit_code",
  "output_invalid",
  "output_too_large",
  "sandbox_error",
  "killed",
  "no_applicable_files",
  "config_invalid",
  "capacity",
  "cancelled",
  "deadline",
]);
/**
 * Reasons a retry of the whole ensemble may help (SPEC 5.3, ER-13): infrastructure that can recover (owner decision 2026-11-19:
 * `db_unavailable` is transient). Every other FAILURE reason is PERMANENT for that tool (`killed`, `timeout`, `out_of_memory`
 * stay permanent for the run and are surfaced as degraded, never auto-retried).
 */
export const TRANSIENT_TOOL_REASONS = Object.freeze([
  "sandbox_error",
  "image_unavailable",
  "capacity",
  "db_unavailable",
]);
/**
 * Reasons that are a WARNING on a run that still produced output, never a failure (owner decision 2026-11-19): `db_stale` marks
 * the tool run `partial` (result `incomplete`, so never resolution eligible) and the scan proceeds. A stale database never fails,
 * skips or makes unavailable a tool.
 */
export const WARNING_TOOL_REASONS = Object.freeze(["db_stale"]);

/**
 * The class of a tool reason for the retry decision and the roll-up.
 * @param {string | null | undefined} reason
 * @returns {"warning" | "transient" | "permanent"} `permanent` for a missing or unknown reason (no retry loop can start)
 */
export function toolReasonClass(reason) {
  if (typeof reason === "string" && WARNING_TOOL_REASONS.includes(reason)) return "warning";
  if (typeof reason === "string" && TRANSIENT_TOOL_REASONS.includes(reason)) return "transient";
  return "permanent";
}
/** The error code of a task whose every tool failed (SPEC 5.4 row 7). */
export const TOOLS_FAILED_REASON = "tools_failed";

/** Coverage states of `scan_results.coverage.state` (SPEC 7.3). */
export const COVERAGE_STATES = Object.freeze([
  "complete",
  "partial",
  "degraded",
  "nothing_to_scan",
  "language_gap",
]);

/** Secret type classes (SPEC 5.6.4). */
export const SECRET_TYPE_CLASSES = Object.freeze([
  "private_key",
  "aws_access_key",
  "gcp_service_account",
  "azure_storage_key",
  "github_token",
  "gitlab_token",
  "slack_token",
  "stripe_key",
  "jwt",
  "basic_auth_url",
  "generic_api_key",
  "high_entropy_string",
  "password_assignment",
  "other",
]);
/** The generic classes that merge into a specific type reported on the same line (SPEC 5.6.4). */
export const GENERIC_SECRET_TYPE_CLASSES = Object.freeze([
  "generic_api_key",
  "high_entropy_string",
  "other",
]);

/** Caps of the normalized finding (SPEC 7.2, 7.3). */
export const FINDING_LIMITS = Object.freeze({
  dedupKey: 600,
  title: 200,
  ruleId: 200,
  path: 1024,
  purl: 500,
  provenanceEntries: 6,
  provenanceEntryBytes: 600,
  advisories: 20,
  cwe: 10,
  locations: 20,
  fixedVersions: 10,
  evidenceBytes: 8192,
  url: 2000,
  detailRowBytes: 16384,
  extraBytes: 16384,
});
/** SAST: two candidates of different tools whose start lines differ by at most this merge (Recommended, SPEC 5.6.3). */
export const SAST_LINE_TOLERANCE = 3;
/** Share of dropped records above which a tool's output is `output_invalid` (Recommended, SPEC 7.2). */
export const OUTPUT_DROP_RATIO_LIMIT = 0.2;

/**
 * Fixed codes of the coverage statement's `notes` (docs/modules/scan-engines/SPEC.md 17.y, 5.13.2). A note describes a standing limit of a result; it
 * never changes the coverage state or the completeness. The stored coverage holds the code; the text below is the one place the wording lives.
 */
export const SECRETS_COVERAGE_NOTE_CODE = "gitleaks_default_allowlist";
export const EVIDENCE_CAPPED_NOTE_CODE = "evidence_capped";
export const COVERAGE_NOTE_CODES = Object.freeze([
  SECRETS_COVERAGE_NOTE_CODE,
  EVIDENCE_CAPPED_NOTE_CODE,
]);

/**
 * The coverage text of a Secrets task (owner decision of 2026-11-22, D-27 (2)): Gitleaks skips some paths by the allowlist of its default
 * configuration, detect-secrets scans them. Shown by the tenant UI under the Tools table of a Secrets task.
 */
export const SECRETS_COVERAGE_NOTE =
  "Gitleaks skips node_modules, lock files, go.sum and image files by its default allowlist. detect-secrets scans those paths, so they are still covered.";

/** The text of each note code. */
export const COVERAGE_NOTE_TEXT = Object.freeze({
  [SECRETS_COVERAGE_NOTE_CODE]: SECRETS_COVERAGE_NOTE,
  [EVIDENCE_CAPPED_NOTE_CODE]:
    "Code excerpts are stored for the 500 highest-severity findings of a task. The others keep their location and link.",
});
