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
 *   to `db_unavailable` here (that word belongs to the SCA role, Part G).
 */

/** Stderr examined for a classification (a larger text is cut; the real messages are one line). */
export const TOOL_EXIT_STDERR_BYTES = 16 * 1024;

const CONFIG_INVALID = Object.freeze([
  /(?:^|\n)invalid application config: /, // Syft
  /(?:^|\n)\S+\s+FATAL\s+Fatal error\s+config file .* loading error/, // Trivy
]);

/**
 * @param {{ exitCode: number | null, stderr?: string, accepted?: readonly number[] }} input
 * @returns {"out_of_memory" | "config_invalid" | "exit_code" | null} `null` when the exit code is accepted
 */
export function classifyToolExit({ exitCode, stderr = "", accepted = [0] }) {
  if (accepted.includes(/** @type {number} */ (exitCode))) return null;
  if (exitCode === 137) return "out_of_memory";
  const text = String(stderr).slice(0, TOOL_EXIT_STDERR_BYTES);
  if (exitCode === 1 && CONFIG_INVALID.some((re) => re.test(text))) return "config_invalid";
  return "exit_code";
}
