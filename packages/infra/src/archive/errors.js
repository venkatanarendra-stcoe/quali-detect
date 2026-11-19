/** Stable failure codes of the archive layer (the orchestrator turns them into `prepare_failed:<code>`, the scan handler into the task error code). */
export const ARCHIVE_ERROR_CODES = Object.freeze({
  tooLarge: "archive_too_large",
  invalid: "archive_invalid",
  mismatch: "archive_mismatch",
  /** The extracted tree failed the fail-closed validation walk (SPEC scan-engines 11.2, D-18). */
  treeInvalid: "tree_invalid",
  /** A path of the tree is longer than the PATH_MAX-safe limit (SPEC scan-engines 11.2, D-18). */
  treePathTooLong: "tree_path_too_long",
});

export class ArchiveError extends Error {
  /** @param {"archive_too_large" | "archive_invalid" | "archive_mismatch" | "tree_invalid" | "tree_path_too_long"} code @param {string} message fixed text, never a repository-derived value */
  constructor(code, message) {
    super(message);
    this.name = "ArchiveError";
    this.code = code;
  }
}
