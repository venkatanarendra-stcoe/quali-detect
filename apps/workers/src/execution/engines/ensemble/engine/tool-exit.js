/**
 * Classification of a container tool that ended with an exit code its adapter does not accept (docs/modules/scan-engines/SPEC.md 5.3,
 * 5.4, 17.i (d); released by ENG-L20 on 2026-11-20). The result is ALWAYS one of the fixed failure words, never tool text: the stderr
 * is read only to choose a word and is not stored, logged or returned. Real evidence (Syft 1.57.2, Trivy 0.76.2, rootful Docker 29.1.3):
 * - exit 137 (SIGKILL as reported by the runtime) with an empty stdout and an empty stderr is what a memory-limit kill looks like, for both
 *   tools; the platform's own kills (wall clock, abort, output cap) never reach this function because the runtime reports no exit code
 *   for them, so a 137 here was not ours: `out_of_memory` (permanent, never retried);
 * - a missing or unreadable platform configuration file ends with exit 1 and `invalid application config: file does not exist` (Syft)
 *   or `FATAL Fatal error config file "..." loading error` (Trivy): the platform's own file is wrong, `config_invalid`;
 * - every other startup error (an unknown flag, a database error) is exit 1 with a text: `exit_code`. Trivy vulnerability mode without a
 *   database says `DB error: failed to download vulnerability DB`; the SBOM role never needs a database (verified), so it is NOT mapped
 *   to `db_unavailable` in the SBOM role.
 *
 * The SCA role (part G, real runs of 2026-11-21, Trivy 0.76.2 and OSV-Scanner 2.7.1) adds the database classification: a database that
 * is missing, empty, corrupt or of another schema is the PLATFORM's problem, not the tool's, and ends as `db_unavailable` (transient):
 * Trivy exit 1 with `DB error:` (`--skip-db-update cannot be specified on the first run`, `failed to open db: invalid database`);
 * OSV-Scanner exit 127 with `could not load db for <ecosystem> ecosystem` (a corrupt archive) or `Error during extraction ... osvlocal`
 * (a missing or unwritable directory). OSV-Scanner exit 127 with `Failed to read config file` is `config_invalid`; any other 127 (an
 * unknown flag) is `exit_code`.
 */

/** Stderr examined for a classification (a larger text is cut; the real messages are one line). */
export const TOOL_EXIT_STDERR_BYTES = 16 * 1024;

const CONFIG_INVALID = Object.freeze([
  /(?:^|\n)invalid application config: /, // Syft
  /(?:^|\n)\S+\s+FATAL\s+Fatal error\s+config file .* loading error/, // Trivy
  /(?:^|\n)Failed to read config file/, // OSV-Scanner (exit 127)
]);
/** SCA role only: the database mount is unusable (see the header). */
const DB_UNAVAILABLE = Object.freeze({
  trivy: /(?:^|\n)\S+\s+FATAL\s+Fatal error\s+.*\bDB error:/,
  "osv-scanner": /could not load db for \S+ ecosystem|Error during extraction: .*osvlocal/,
});

/**
 * @param {{ exitCode: number | null, stderr?: string, accepted?: readonly number[], role?: "sbom" | "sca", toolId?: string }} input `role: "sca"` with a `toolId` enables the database classification
 * @returns {"out_of_memory" | "config_invalid" | "db_unavailable" | "exit_code" | null} `null` when the exit code is accepted
 */
export function classifyToolExit({ exitCode, stderr = "", accepted = [0], role = "sbom", toolId }) {
  if (accepted.includes(/** @type {number} */ (exitCode))) return null;
  if (exitCode === 137) return "out_of_memory";
  const text = String(stderr).slice(0, TOOL_EXIT_STDERR_BYTES);
  if (role === "sca" && Object.hasOwn(DB_UNAVAILABLE, toolId ?? "")) {
    const pattern = DB_UNAVAILABLE[/** @type {keyof typeof DB_UNAVAILABLE} */ (toolId)];
    if ((exitCode === 1 || exitCode === 127) && pattern.test(text)) return "db_unavailable";
  }
  if ((exitCode === 1 || exitCode === 127) && CONFIG_INVALID.some((re) => re.test(text)))
    return "config_invalid";
  return "exit_code";
}
