/**
 * Constants of the scan-decisioning floor (docs/modules/scan-decisioning/SPEC.md 5.2, 5.3, 7.2). Every list that decides
 * which scans a change requires lives in this one file so it can be reviewed in one place.
 */

/** The scan types in catalog order (the order of task ordinals, SPEC 5.3). */
export const FLOOR_SCAN_TYPES = Object.freeze(["sbom", "sca", "sast", "secrets"]);

/** File classes decided by path alone (no content is read). */
export const FILE_CLASSES = Object.freeze(["manifest", "code", "config", "docs", "other"]);

/** Statuses a changed file can carry (GitHub compare and pull-request files). */
export const DIFF_FILE_STATUSES = Object.freeze([
  "added",
  "modified",
  "removed",
  "renamed",
  "copied",
  "changed",
  "unchanged",
]);

/** Statuses that count as "the file content was written" (FL-2, FL-3 any_change). `removed` and `unchanged` are not. */
export const WRITTEN_FILE_STATUSES = Object.freeze([
  "added",
  "modified",
  "renamed",
  "copied",
  "changed",
]);

/** Outcome of change detection. `not_needed` = a full run (no diff taken). */
export const DIFF_STATUSES = Object.freeze({
  NOT_NEEDED: "not_needed",
  COMPLETE: "complete",
  TRUNCATED: "truncated",
  UNAVAILABLE: "unavailable",
});

/** Where the changed-file list came from. */
export const DIFF_SOURCES = Object.freeze({
  NONE: "none",
  GITHUB_COMPARE: "github_compare",
  GITHUB_PULL_FILES: "github_pull_files",
  UNAVAILABLE: "unavailable",
});

/** Floor rule ids (SPEC 5.3). FL-6 (empty changed set) has no id on a scan type: it is the `zeroScan` flag. */
export const FLOOR_RULES = Object.freeze({
  MANIFEST: "FL-1",
  CODE: "FL-2",
  SECRETS: "FL-3",
  DIFF_UNAVAILABLE: "FL-4",
  FULL_RUN: "FL-5",
});

/** The Secrets rule (AP-2): `any_change` = a written file of any class; `strict` = any changed file, removals included. */
export const SECRETS_RULES = Object.freeze({ ANY_CHANGE: "any_change", STRICT: "strict" });
export const DEFAULT_SECRETS_RULE = SECRETS_RULES.ANY_CHANGE;

/** Stable reason codes of an enabled type that was not selected. */
export const NOT_SELECTED_REASONS = Object.freeze({ NO_MATCHING_CHANGES: "no_matching_changes" });

/** Limits of the change summary (SPEC 5.2 CD-7, 7.2). */
export const SAMPLE_PATHS_DEFAULT = 20;
export const SAMPLE_PATH_MAX_LENGTH = 300;

// ---------------------------------------------------------------------------------------------------------------------
// Path classification lists (SPEC 5.3). Names are compared in lower case.
// ---------------------------------------------------------------------------------------------------------------------

/** Exact manifest file names. */
export const MANIFEST_NAMES = Object.freeze([
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "pipfile",
  "pipfile.lock",
  "poetry.lock",
  "go.mod",
  "go.sum",
  "cargo.toml",
  "cargo.lock",
  "pom.xml",
  "gemfile",
  "gemfile.lock",
  "composer.json",
  "composer.lock",
  "packages.config",
]);

/** Manifest name patterns: `requirements*.txt`, `build.gradle*`, `*.csproj`. */
export const MANIFEST_PATTERNS = Object.freeze([
  /^requirements.*\.txt$/,
  /^build\.gradle/,
  /\.csproj$/,
]);

/** Source-code extensions (lower case, no dot). */
export const CODE_EXTENSIONS = Object.freeze([
  "js",
  "jsx",
  "ts",
  "tsx",
  "mjs",
  "cjs",
  "py",
  "java",
  "kt",
  "kts",
  "go",
  "rs",
  "rb",
  "php",
  "cs",
  "c",
  "h",
  "cc",
  "cxx",
  "cpp",
  "hh",
  "hxx",
  "hpp",
  "m",
  "mm",
  "swift",
  "scala",
  "groovy",
  "dart",
  "lua",
  "pl",
  "pm",
  "r",
  "ex",
  "exs",
  "erl",
  "hs",
  "clj",
  "fs",
  "vb",
  "vue",
  "svelte",
  "sol",
  "sh",
  "bash",
  "zsh",
  "ps1",
  "sql",
]);

/** Configuration extensions (dotfiles are configuration too). */
export const CONFIG_EXTENSIONS = Object.freeze([
  "json",
  "yaml",
  "yml",
  "toml",
  "ini",
  "env",
  "properties",
  "tf",
]);

/** Documentation extensions. */
export const DOCS_EXTENSIONS = Object.freeze(["md", "rst", "txt", "adoc"]);
