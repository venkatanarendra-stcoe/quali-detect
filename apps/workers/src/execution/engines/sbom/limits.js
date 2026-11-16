/**
 * Hardening limits of the built-in SBOM inventory engine (docs/modules/executions/SPEC.md §17.ab). Every number bounds work on
 * UNTRUSTED repository content: the archive is data, parsed by hand-written parsers, never executed.
 */
export const SBOM_LIMITS = Object.freeze({
  /** One manifest or lockfile larger than this is skipped with a warning (`file_too_large`). */
  maxFileBytes: 5 * 1024 * 1024,
  /** Bytes read over the whole run; once spent, remaining files are skipped (`total_bytes_exceeded`) and the result is incomplete. */
  maxTotalBytes: 40 * 1024 * 1024,
  /** Manifest files parsed per run (`too_many_files`). */
  maxFiles: 500,
  /** Directories visited per run and the deepest directory level (`walk_limit`). */
  maxDirectories: 20000,
  maxDepth: 32,
  /** Components reported per run; more are dropped and the result is `truncated`. */
  maxComponents: 50000,
  /** Nesting depth accepted in JSON (`too_deeply_nested`) and in the package-lock v1 dependency tree. */
  maxJsonDepth: 128,
  /** Longest accepted line of a line-based format, and field lengths of a component. */
  maxLineLength: 4096,
  maxNameLength: 200,
  maxVersionLength: 100,
});
