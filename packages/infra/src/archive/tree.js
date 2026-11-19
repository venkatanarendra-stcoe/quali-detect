import { lstat, opendir, realpath } from "node:fs/promises";
import path from "node:path";
import { ARCHIVE_ERROR_CODES, ArchiveError } from "./errors.js";

/**
 * Fail-closed validation of an EXTRACTED tree (docs/modules/scan-engines/SPEC.md 11.2, D-18, part C). It runs after extraction and
 * before any tool sees the tree. The first violation throws an {@link ArchiveError} with a fixed message (never a file name:
 * names come from the repository); the caller discards the whole tree.
 *
 * Rejected: a symbolic link, a hard link (link count above 1), a device, FIFO or socket; any mode other than 0644 (files) and 0755
 * (directories), which covers setuid, setgid, sticky, executable and group/other-writable files; an entry named `.git` (any
 * case) at any depth; an invalid name (empty, `.`, `..`, control characters, backslash, U+FFFD, longer than 255 bytes); two
 * a directory whose real path is not the expected path under the real root (an escape); a path longer than
 * {@link TREE_MAX_PATH_BYTES}; more entries, more bytes, deeper nesting or a bigger file than the caps.
 *
 * NOT rejected, but FLAGGED (owner decision 2026-11-19, SPEC 11.2 "keep both and flag"): two names of one directory that collide
 * after NFC normalisation and/or case folding. The extraction target and the tools' container are case-sensitive Linux, so they
 * are two distinct files and both are scanned; the pair is reported in `suspiciousPaths` (a case-insensitive checkout would let
 * one overwrite the other). A real on-disk collision cannot occur in one directory listing.
 */

/** Longest relative path (UTF-8 bytes) accepted. Linux PATH_MAX is 4096 including the NUL; the tools see the tree under `/src/` and add their own prefixes and suffixes, so 512 bytes are kept free (Trivy fails fatally and Gitleaks and detect-secrets silently miss files at over-long paths, SPEC 17.a). */
export const TREE_MAX_PATH_BYTES = 3584;
/** Longest single name (bytes): NAME_MAX of common Linux file systems. */
export const TREE_MAX_NAME_BYTES = 255;
export const TREE_FILE_MODE = 0o644;
export const TREE_DIR_MODE = 0o755;
/** Most suspicious paths reported by one walk (the count is exact, the list is capped). */
export const TREE_MAX_SUSPICIOUS = 100;

// eslint-disable-next-line no-control-regex
const BAD_NAME = /[\u0000-\u001f\u007f-\u009f\\�]/;
const fail = (code, what) =>
  new ArchiveError(code, `The extracted tree is not acceptable: ${what}.`);
const invalid = (what) => fail(ARCHIVE_ERROR_CODES.treeInvalid, what);
const tooLarge = (what) => fail(ARCHIVE_ERROR_CODES.tooLarge, what);

/** @param {string} name a single path component @returns {string | null} the problem, or null */
export function nameProblem(name) {
  if (name === "" || name === "." || name === "..") return "invalid name";
  if (BAD_NAME.test(name)) return "invalid name";
  if (name.toLowerCase() === ".git") return "git metadata";
  return null;
}

/**
 * @param {string} root the extracted tree (a real directory, not a link)
 * @param {{ maxEntries: number, maxFileBytes: number, maxTotalBytes: number, maxDepth: number }} limits
 * @returns {Promise<{ entries: number, files: number, directories: number, bytes: number, suspiciousCount: number, suspiciousPaths: { path: string, reason: "case_collision" | "unicode_collision" }[] }>} `suspiciousPaths` holds RELATIVE, repository-derived paths: escape them when shown, never log them raw
 */
export async function validateExtractedTree(root, limits) {
  const top = path.resolve(root);
  const rootStat = await lstat(top).catch(() => null);
  if (!rootStat || !rootStat.isDirectory()) throw invalid("the root is not a directory");
  if ((rootStat.mode & 0o7777) !== TREE_DIR_MODE) throw invalid("unexpected mode");
  const realRoot = await realpath(top);
  const totals = { entries: 0, files: 0, directories: 0, bytes: 0 };
  const flagged = new Set();
  const suspiciousPaths = [];
  const flag = (relPath, reason) => {
    if (flagged.has(relPath)) return;
    flagged.add(relPath);
    if (suspiciousPaths.length < TREE_MAX_SUSPICIOUS)
      suspiciousPaths.push({ path: relPath, reason });
  };
  /** @type {{ dir: string, rel: string[] }[]} */
  const stack = [{ dir: top, rel: [] }];
  while (stack.length > 0) {
    const { dir, rel } = /** @type {{ dir: string, rel: string[] }} */ (stack.pop());
    if ((await realpath(dir)) !== path.join(realRoot, ...rel))
      throw invalid("an entry escapes the root");
    const seen = new Map();
    const handle = await opendir(dir);
    for await (const item of handle) {
      totals.entries += 1;
      if (totals.entries > limits.maxEntries) throw tooLarge("entry count");
      const name = item.name;
      const problem = nameProblem(name);
      if (problem) throw invalid(problem);
      if (Buffer.byteLength(name) > TREE_MAX_NAME_BYTES)
        throw fail(ARCHIVE_ERROR_CODES.treePathTooLong, "a name is too long");
      const parts = [...rel, name];
      if (Buffer.byteLength(parts.join("/")) > TREE_MAX_PATH_BYTES)
        throw fail(ARCHIVE_ERROR_CODES.treePathTooLong, "a path is too long");
      if (parts.length > limits.maxDepth) throw tooLarge("path depth");
      const key = name.normalize("NFC").toLowerCase();
      const first = seen.get(key);
      if (first === undefined) seen.set(key, name);
      else {
        const reason =
          first.toLowerCase() === name.toLowerCase() ? "case_collision" : "unicode_collision";
        flag([...rel, first].join("/"), reason);
        flag(parts.join("/"), reason);
      }
      const full = path.join(dir, name);
      const st = await lstat(full);
      const mode = st.mode & 0o7777;
      if (st.isDirectory()) {
        if (mode !== TREE_DIR_MODE) throw invalid("unexpected mode");
        totals.directories += 1;
        stack.push({ dir: full, rel: parts });
      } else if (st.isFile()) {
        if (mode !== TREE_FILE_MODE) throw invalid("unexpected mode");
        if (st.nlink !== 1) throw invalid("hard link");
        if (st.size > limits.maxFileBytes) throw tooLarge("file size");
        totals.bytes += st.size;
        if (totals.bytes > limits.maxTotalBytes) throw tooLarge("expanded size");
        totals.files += 1;
      } else throw invalid("not a regular file or directory");
    }
  }
  return { ...totals, suspiciousCount: flagged.size, suspiciousPaths };
}
