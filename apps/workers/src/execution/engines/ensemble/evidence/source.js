import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { isSafeRelativePath } from "@qmentisai/shared";
import { EVIDENCE_CAPS } from "./constants.js";

/**
 * Bounded, safe reads of the extracted tree for evidence (docs/modules/scan-engines/SPEC.md 5.13.1, 5.13.2, 11.2; part J). The scan worker (outside
 * every container) reads the lines itself with plain file reads; this is the ONLY place that does. A path that is not a safe relative path,
 * a file that is not a regular file, a link (the extractor creates none, a path component or the file itself that resolves outside the
 * tree is refused anyway), a file over the byte cap, a file with a NUL byte (binary) or text that is not valid UTF-8 gives `null`, never a
 * partial read and never an error.
 */

const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * The lines of one file of the tree, or `null`.
 * @param {string} root absolute directory of the extracted tree
 * @param {string} relativePath
 * @param {{ maxBytes?: number }} [options]
 * @returns {Promise<string[] | null>} the lines without line terminators (`\n` and `\r\n` end a line)
 */
export async function readTreeLines(
  root,
  relativePath,
  { maxBytes = EVIDENCE_CAPS.windowFileBytes } = {},
) {
  if (typeof root !== "string" || !path.isAbsolute(root) || !isSafeRelativePath(relativePath))
    return null;
  const full = path.join(root, relativePath);
  let handle;
  try {
    const stat = await lstat(full);
    if (!stat.isFile() || stat.size > maxBytes) return null;
    const [realRoot, realFile] = await Promise.all([realpath(root), realpath(full)]);
    if (!realFile.startsWith(realRoot + path.sep)) return null;
    handle = await open(full, constants.O_RDONLY | constants.O_NOFOLLOW);
    const buf = Buffer.alloc(stat.size);
    let off = 0;
    while (off < stat.size) {
      const { bytesRead } = await handle.read(buf, off, stat.size - off, off);
      if (bytesRead === 0) break;
      off += bytesRead;
    }
    const bytes = buf.subarray(0, off);
    if (bytes.includes(0)) return null;
    const text = decoder.decode(bytes);
    const lines = text.split("\n");
    // `\r\n` ends a line; a final newline does not start another
    if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
    return lines.map((l) => (l.endsWith("\r") ? l.slice(0, -1) : l));
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => {});
  }
}

/**
 * A small cache of the lines of recently read files (a task's findings cluster by file). Bounded by the number of files.
 * @param {string} root @param {number} [capacity]
 */
export function createLineReader(root, capacity = 8) {
  /** @type {Map<string, string[] | null>} */
  const cache = new Map();
  return async function lines(relativePath) {
    if (cache.has(relativePath)) {
      const hit = cache.get(relativePath) ?? null;
      cache.delete(relativePath);
      cache.set(relativePath, hit);
      return hit;
    }
    const read = await readTreeLines(root, relativePath);
    cache.set(relativePath, read);
    if (cache.size > capacity) cache.delete(cache.keys().next().value);
    return read;
  };
}
