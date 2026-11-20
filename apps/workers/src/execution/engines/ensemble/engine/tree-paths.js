import { lstatSync } from "node:fs";
import path from "node:path";
import { isSafeRelativePath } from "@qmentisai/shared";

/** Distinct paths whose answer is remembered (a tool reports a handful of manifest files; the cap bounds a hostile document). */
export const TREE_PATH_CACHE_MAX = 100_000;

/**
 * The `pathExists` filter of the tool-output parse for ONE extracted tree (docs/modules/scan-engines/SPEC.md 5.6.1, SE-27, 17.i (a);
 * released by ENG-L20 on 2026-11-20 after real Syft and Trivy output showed that every reported location, once a leading slash is
 * removed, is a repository-relative path that exists in the tree). A path exists when it is a safe relative path (no `..`, no control
 * character, no absolute form) and `lstat` finds a regular file or a directory under the root: a symbolic link never counts (the
 * extractor creates none) and a path outside the tree cannot be asked about. The answer is a boolean only; nothing about the file is
 * read, so a tool cannot use the filter to learn content, and a failing `lstat` is "does not exist". Answers are cached per path.
 * @param {string} root absolute directory of the extracted tree
 * @returns {(relativePath: string) => boolean}
 */
export function createTreePathExists(root) {
  if (typeof root !== "string" || !path.isAbsolute(root))
    throw new TypeError("the tree root must be an absolute path");
  /** @type {Map<string, boolean>} */
  const cache = new Map();
  return (relativePath) => {
    if (typeof relativePath !== "string" || !isSafeRelativePath(relativePath)) return false;
    const known = cache.get(relativePath);
    if (known !== undefined) return known;
    let exists = false;
    try {
      const stat = lstatSync(path.join(root, relativePath));
      exists = stat.isFile() || stat.isDirectory();
    } catch {
      exists = false;
    }
    if (cache.size < TREE_PATH_CACHE_MAX) cache.set(relativePath, exists);
    return exists;
  };
}
