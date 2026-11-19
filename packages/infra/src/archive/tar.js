import { chmod, lstat, mkdir, open, rm } from "node:fs/promises";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { ARCHIVE_ERROR_CODES, ArchiveError } from "./errors.js";
import {
  TREE_DIR_MODE,
  TREE_FILE_MODE,
  TREE_MAX_NAME_BYTES,
  TREE_MAX_PATH_BYTES,
  validateExtractedTree,
} from "./tree.js";

/**
 * A bounded, in-house tar.gz reader on Node built-ins (docs/modules/executions/SPEC.md §6.3, §13.1: the spec prefers it to a
 * new dependency). It is a PARSER of untrusted bytes: nothing in the archive is executed, imported, built or installed (R-8).
 * What it does with entries:
 * - regular files are extracted (mode 0644, never executable, never setuid) under the destination directory;
 * - directories are created (0755) and the destination must sit inside a private (0700) parent, so a non-root scan container can
 *   read the tree while nothing outside can traverse to it (SPEC scan-engines D-18);
 * - any path with a `.git` component is NOT extracted (repository git config and hooks never reach a tool);
 * - the extracted tree is validated before the call returns and the whole tree is removed on any violation ({@link validateExtractedTree});
 * - symbolic links, hard links, devices and FIFOs are SKIPPED, never followed and never created, so nothing inside the
 *   destination can point outside it;
 * - entries whose path is absolute, contains `..`, a NUL or a control character are SKIPPED and counted;
 * - the top-level directory GitHub puts around the tree is stripped;
 * - hard caps (entries, one file, expanded total, expansion ratio, path depth/length) abort with `archive_too_large`.
 */

/** Default caps; the orchestrator passes its configured values. */
export const DEFAULT_ARCHIVE_LIMITS = Object.freeze({
  maxEntries: 100000,
  maxFileBytes: 50 * 1024 * 1024,
  maxTotalBytes: 1024 * 1024 * 1024,
  maxRatio: 200,
  maxDepth: 64,
  maxPathLength: 1024,
});

const BLOCK = 512;
const MAX_META_BYTES = 65536;
const field = (buf, start, end) => {
  const slice = buf.subarray(start, end);
  const nul = slice.indexOf(0);
  return slice.subarray(0, nul === -1 ? slice.length : nul).toString("utf8");
};
const octal = (buf, start, end) => {
  if (buf[start] & 0x80) {
    // GNU base-256 size
    let value = 0;
    for (let i = start + 1; i < end; i += 1) value = value * 256 + buf[i];
    return value;
  }
  const text = field(buf, start, end).trim();
  return text === "" ? 0 : Number.parseInt(text, 8);
};

function parsePax(data) {
  const out = {};
  let pos = 0;
  while (pos < data.length) {
    const space = data.indexOf(0x20, pos);
    if (space === -1) break;
    const length = Number.parseInt(data.subarray(pos, space).toString("utf8"), 10);
    if (!Number.isFinite(length) || length <= space - pos + 1 || pos + length > data.length) break;
    const record = data.subarray(space + 1, pos + length - 1).toString("utf8");
    const eq = record.indexOf("=");
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    pos += length;
  }
  return out;
}

/**
 * Walks a tar.gz stream. `onFile({ path, size })` returns a sink `{ write(buffer), close() }` for the body of a regular file
 * or `null` to skip it; `onDirectory(path)` is called for directories.
 * @param {import("node:stream").Readable} source
 * @param {{ limits?: Partial<typeof DEFAULT_ARCHIVE_LIMITS>, onFile?: Function, onDirectory?: Function, exclude?: (relativePath: string) => boolean, expectTopDirIncludes?: string }} options
 * @returns {Promise<{ entries: number, files: number, bytes: number, skippedUnsafe: number, skippedLinks: number, excluded: number, topDir: string | null }>}
 */
export async function walkTarGz(source, options = {}) {
  const limits = { ...DEFAULT_ARCHIVE_LIMITS, ...options.limits };
  const stats = {
    entries: 0,
    files: 0,
    bytes: 0,
    skippedUnsafe: 0,
    skippedLinks: 0,
    excluded: 0,
    topDir: null,
  };
  let compressed = 0;
  const counter = new Transform({
    transform(chunk, _e, cb) {
      compressed += chunk.length;
      cb(null, chunk);
    },
  });
  let expanded = 0;
  let header = Buffer.alloc(0);
  let state = "header";
  let remaining = 0;
  let padding = 0;
  let sink = null;
  let meta = null; // { kind: "pax" | "longname" | "ignore", chunks: [], size }
  let pending = {}; // overrides for the NEXT entry (pax path, GNU long name)
  let zeroBlocks = 0;
  let ended = false;

  const tooLarge = (what) =>
    new ArchiveError("archive_too_large", `The archive exceeds the limit: ${what}.`);

  /** Maps an archive path to a safe relative path, or null when the entry must be skipped. */
  function relativePath(raw) {
    if (raw.length > limits.maxPathLength) throw tooLarge("path length");
    // eslint-disable-next-line no-control-regex
    if (raw === "" || /[\u0000-\u001f]/.test(raw) || raw.startsWith("/") || raw.includes("\\"))
      return null;
    const parts = raw.split("/").filter((p) => p !== "" && p !== ".");
    if (parts.some((p) => p === "..")) return null;
    if (parts.length === 0) return null;
    if (stats.topDir === null) {
      if (
        options.expectTopDirIncludes &&
        !parts[0].toLowerCase().includes(options.expectTopDirIncludes.toLowerCase())
      )
        throw new ArchiveError(
          "archive_mismatch",
          "The archive does not contain the requested commit.",
        );
      stats.topDir = parts[0];
    }
    if (parts[0] !== stats.topDir) return null;
    const rest = parts.slice(1);
    if (rest.length > limits.maxDepth) throw tooLarge("path depth");
    return rest.length === 0 ? "" : rest.join("/");
  }

  async function handleHeader(block) {
    if (block.every((b) => b === 0)) {
      zeroBlocks += 1;
      if (zeroBlocks >= 2) ended = true;
      return;
    }
    zeroBlocks = 0;
    // checksum: the sum of all header bytes with the checksum field read as spaces
    let sum = 0;
    for (let i = 0; i < BLOCK; i += 1) sum += i >= 148 && i < 156 ? 0x20 : block[i];
    if (sum !== octal(block, 148, 156))
      throw new ArchiveError("archive_invalid", "The archive header is corrupt.");
    const type = String.fromCharCode(block[156] || 0x30);
    const size = octal(block, 124, 136);
    if (!Number.isFinite(size) || size < 0)
      throw new ArchiveError("archive_invalid", "The archive header is corrupt.");

    if (type === "x" || type === "g" || type === "L" || type === "K") {
      if (size > MAX_META_BYTES) throw tooLarge("metadata size");
      meta = {
        kind: type === "x" ? "pax" : type === "L" ? "longname" : "ignore",
        chunks: [],
        size,
      };
      remaining = size;
      padding = (BLOCK - (size % BLOCK)) % BLOCK;
      state = size === 0 ? "pad" : "meta";
      if (size === 0) finishMeta();
      return;
    }

    stats.entries += 1;
    if (stats.entries > limits.maxEntries) throw tooLarge("entry count");
    const prefix = field(block, 345, 500);
    const baseName = field(block, 0, 100);
    const name =
      pending.path ??
      (prefix && field(block, 257, 262) === "ustar" ? `${prefix}/${baseName}` : baseName);
    pending = {};
    const isFile = type === "0" || type === "7";
    const isDir = type === "5";
    const bodySize = isFile ? size : size; // links normally carry 0; other bodies are skipped
    remaining = bodySize;
    padding = (BLOCK - (bodySize % BLOCK)) % BLOCK;
    sink = null;

    if (!isFile && !isDir) {
      stats.skippedLinks += 1; // symlink, hard link, device, fifo: never created, never followed
    } else {
      const rel = relativePath(name);
      if (rel === null) stats.skippedUnsafe += 1;
      else if (rel === "") {
        /* the top-level directory itself */
      } else if (options.exclude?.(rel)) stats.excluded += 1;
      else if (isDir) await options.onDirectory?.(rel);
      else {
        if (size > limits.maxFileBytes) throw tooLarge("file size");
        stats.bytes += size;
        if (stats.bytes > limits.maxTotalBytes) throw tooLarge("expanded size");
        stats.files += 1;
        sink = (await options.onFile?.({ path: rel, size })) ?? null;
      }
    }
    state = remaining > 0 ? "body" : padding > 0 ? "pad" : "header";
    if (state !== "body") await closeSink();
  }

  function finishMeta() {
    const data = Buffer.concat(meta.chunks);
    if (meta.kind === "pax") {
      const records = parsePax(data);
      if (typeof records.path === "string") pending.path = records.path;
    } else if (meta.kind === "longname") pending.path = field(data, 0, data.length);
    meta = null;
  }

  async function closeSink() {
    if (sink) {
      const done = sink;
      sink = null;
      await done.close();
    }
  }

  let failure = null; // the first error OUR code raised (the pipeline may report a premature close of a stream it destroyed instead)
  try {
    await pipeline(source, counter, createGunzip(), async (gz) => {
      try {
        await consume(gz);
      } catch (error) {
        failure = error;
        throw error;
      }
    });
    if (state === "body" || state === "meta")
      throw new ArchiveError("archive_invalid", "The archive ended inside an entry.");
  } catch (error) {
    await closeSink().catch(() => {});
    const cause = failure ?? error;
    if (cause instanceof ArchiveError) throw cause;
    if (
      cause?.code?.startsWith?.("Z_") ||
      /unexpected end of file|incorrect header check/i.test(cause?.message ?? "")
    )
      throw new ArchiveError("archive_invalid", "The archive is not a valid gzip stream.");
    throw cause;
  }
  return stats;

  async function consume(gz) {
    {
      for await (const chunk of gz) {
        expanded += chunk.length;
        if (expanded > limits.maxRatio * Math.max(compressed, 1) + 1024 * 1024)
          throw tooLarge("expansion ratio");
        let offset = 0;
        while (offset < chunk.length) {
          if (ended) break; // anything after the end-of-archive marker is ignored
          if (state === "header") {
            const take = Math.min(BLOCK - header.length, chunk.length - offset);
            header =
              header.length === 0 && take === BLOCK
                ? chunk.subarray(offset, offset + take)
                : Buffer.concat([header, chunk.subarray(offset, offset + take)]);
            offset += take;
            if (header.length === BLOCK) {
              const block = header;
              header = Buffer.alloc(0);
              await handleHeader(Buffer.from(block));
            }
          } else if (state === "body" || state === "meta") {
            const take = Math.min(remaining, chunk.length - offset);
            const piece = chunk.subarray(offset, offset + take);
            if (state === "meta") meta.chunks.push(Buffer.from(piece));
            else if (sink) await sink.write(piece);
            offset += take;
            remaining -= take;
            if (remaining === 0) {
              if (state === "meta") finishMeta();
              else await closeSink();
              state = padding > 0 ? "pad" : "header";
            }
          } else {
            const take = Math.min(padding, chunk.length - offset);
            offset += take;
            padding -= take;
            if (padding === 0) state = "header";
          }
        }
      }
    }
  }
}

/**
 * Checks an archive against the caps WITHOUT writing anything (the fetch step's safety check, SPEC §6.3).
 * @param {import("node:stream").Readable} source
 * @param {{ limits?: Partial<typeof DEFAULT_ARCHIVE_LIMITS>, exclude?: (p: string) => boolean, expectTopDirIncludes?: string }} [options]
 */
export const inspectTarGz = (source, options = {}) => walkTarGz(source, options);

/**
 * Extracts an archive into `destDir` (created, mode 0755, which must not exist yet and must sit inside a private parent: owned
 * by the process user with no group or other access). Every path is re-resolved and must stay inside `destDir`; existing files
 * are never overwritten (an exact duplicate path, or an on-disk collision, aborts with `archive_invalid`; names differing only by case or
 * Unicode normalisation are distinct files and are kept and flagged, see {@link validateExtractedTree}); modes are set explicitly, whatever the umask (files 0644, directories
 * 0755). Entries with a `.git` component are skipped and counted in `gitDenied`. A path over the PATH_MAX-safe limit fails with
 * `tree_path_too_long` before anything is written. After extraction the tree is validated ({@link validateExtractedTree}); on
 * ANY failure the destination is removed and the error is thrown, so no tool can ever receive a partial or doubtful tree.
 * @param {import("node:stream").Readable} source
 * @param {{ destDir: string, limits?: Partial<typeof DEFAULT_ARCHIVE_LIMITS>, exclude?: (p: string) => boolean, expectTopDirIncludes?: string }} options
 */
export async function extractTarGz(source, { destDir, ...options }) {
  const limits = { ...DEFAULT_ARCHIVE_LIMITS, ...options.limits };
  const root = path.resolve(destDir);
  const parent = await lstat(path.dirname(root)).catch(() => null);
  if (
    !parent ||
    !parent.isDirectory() ||
    (parent.mode & 0o077) !== 0 ||
    (typeof process.getuid === "function" && parent.uid !== process.getuid())
  )
    throw new ArchiveError(
      ARCHIVE_ERROR_CODES.treeInvalid,
      "The extraction parent directory is not private.",
    );
  try {
    await mkdir(root, { mode: TREE_DIR_MODE });
  } catch {
    throw new ArchiveError(ARCHIVE_ERROR_CODES.treeInvalid, "The extraction target exists.");
  }
  const inside = (target) => target === root || target.startsWith(`${root}${path.sep}`);
  const conflict = () =>
    new ArchiveError(ARCHIVE_ERROR_CODES.invalid, "The archive contains conflicting entries.");
  const guardPath = (rel) => {
    if (
      Buffer.byteLength(rel) > TREE_MAX_PATH_BYTES ||
      rel.split("/").some((part) => Buffer.byteLength(part) > TREE_MAX_NAME_BYTES)
    )
      throw new ArchiveError(
        ARCHIVE_ERROR_CODES.treePathTooLong,
        "A path of the archive is too long.",
      );
  };
  const known = new Set([""]);
  async function ensureDir(rel) {
    if (known.has(rel)) return;
    await ensureDir(rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "");
    const target = path.resolve(root, rel);
    if (!inside(target)) throw conflict();
    try {
      await mkdir(target, { mode: TREE_DIR_MODE });
    } catch (error) {
      if (error?.code !== "EEXIST" || !(await lstat(target)).isDirectory()) throw conflict();
    }
    await chmod(target, TREE_DIR_MODE);
    known.add(rel);
  }
  let gitDenied = 0;
  const denied = (rel) => rel.split("/").some((part) => part.toLowerCase() === ".git");
  try {
    await chmod(root, TREE_DIR_MODE);
    const stats = await walkTarGz(source, {
      ...options,
      limits,
      exclude: (rel) => {
        if (denied(rel)) {
          gitDenied += 1;
          return true;
        }
        return options.exclude?.(rel) ?? false;
      },
      async onDirectory(rel) {
        guardPath(rel);
        await ensureDir(rel);
      },
      async onFile({ path: rel }) {
        guardPath(rel);
        const target = path.resolve(root, rel);
        if (!inside(target)) return null;
        await ensureDir(rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "");
        let handle;
        try {
          handle = await open(target, "wx", TREE_FILE_MODE);
        } catch (error) {
          // EEXIST = an EXACT duplicate path, or a real on-disk collision (a case-insensitive host file system): abort rather than
          // let the first entry hide the second from the scan. Names that differ only by case or Unicode form are distinct
          // files on the case-sensitive Linux target: both are extracted and flagged by the tree walk.
          throw conflict();
        }
        await handle.chmod(TREE_FILE_MODE);
        return {
          write: (buffer) => handle.write(buffer),
          close: () => handle.close(),
        };
      },
    });
    const tree = await validateExtractedTree(root, limits);
    return { ...stats, gitDenied, tree };
  } catch (error) {
    await rm(root, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
}
