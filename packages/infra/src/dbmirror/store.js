import { createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { chmod, lstat, mkdir, readdir, rename, rm, stat } from "node:fs/promises";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { DB_TOOL_IDS } from "@qmentisai/shared";
import { extractTarGz } from "../archive/tar.js";
import { snapshotArchiveCapsFor } from "./inspect.js";

/** The stage or the stored object exceeded `maxBytes`. */
export class DbMirrorTooLargeError extends Error {
  /** @param {number} maxBytes */
  constructor(maxBytes) {
    super(`The snapshot exceeds ${maxBytes} bytes.`);
    this.name = "DbMirrorTooLargeError";
    this.maxBytes = maxBytes;
  }
}

/** A stored object does not hash to the digest it is addressed by (corrupted or tampered). */
export class DbMirrorIntegrityError extends Error {
  constructor() {
    super("The stored snapshot does not match its sha256 address.");
    this.name = "DbMirrorIntegrityError";
  }
}

const SHA256 = /^[0-9a-f]{64}$/;
const STAGE_ID = /^[0-9a-f]{24}$/;

/**
 * Validates a snapshot address. ONE place derives every path, so no caller can supply one (SE-32).
 * @param {{ tool: string, sha256: string }} ref
 */
function checkRef({ tool, sha256 }) {
  if (!DB_TOOL_IDS.includes(tool)) throw new TypeError("Unknown mirror tool.");
  if (typeof sha256 !== "string" || !SHA256.test(sha256)) throw new TypeError("Invalid sha256.");
}

/** Makes a materialized (0555/0444) tree removable. @param {string} dir */
async function makeWritable(dir) {
  const info = await lstat(dir).catch(() => null);
  if (!info) return;
  if (info.isSymbolicLink()) return;
  if (info.isDirectory()) {
    await chmod(dir, 0o755);
    for (const name of await readdir(dir)) await makeWritable(path.join(dir, name));
  } else await chmod(dir, 0o644);
}

/** @param {string} dir */
async function removeTree(dir) {
  await makeWritable(dir);
  await rm(dir, { recursive: true, force: true });
}

/** @param {string} dir mode 0555 for directories and 0444 for files, depth first; `top: false` leaves `dir` itself writable */
async function sealTree(dir, top = true) {
  for (const name of await readdir(dir)) {
    const target = path.join(dir, name);
    const info = await lstat(target);
    if (info.isDirectory()) await sealTree(target);
    else if (info.isFile()) await chmod(target, 0o444);
  }
  if (top) await chmod(dir, 0o555);
}

/**
 * Local-filesystem DbMirrorStore (docs/modules/scan-engines/SPEC.md 5.12, SE-32, SE-33, SE-36; the object-storage driver is Open).
 * Public vulnerability data, NOT tenant data: one shared set, no tenant in any path, read-only for the scan path. Layout:
 *   `<root>/stage/<id>`                 a download in progress (temporary name; never visible as a snapshot)
 *   `<root>/db/<tool>/<sha256>.tar.gz`  the object, content addressed (written once, by rename)
 *   `<cache>/<tool>/<sha256>/`          the materialized tree (0555 / 0444), created by an atomic rename after the archive was
 *                                       hashed again and extracted with the hardened extractor
 * @param {{ root: string, cacheRoot: string, archiveCaps?: Partial<import("./inspect.js").ArchiveCaps> }} options absolute directories
 */
export function createLocalDbMirrorStore({ root, cacheRoot, archiveCaps = {} }) {
  for (const dir of [root, cacheRoot])
    if (typeof dir !== "string" || !path.isAbsolute(dir))
      throw new TypeError("The mirror store directories must be absolute paths.");
  const base = path.resolve(root);
  const cache = path.resolve(cacheRoot);
  const objectFile = (ref) => {
    checkRef(ref);
    return path.join(base, "db", ref.tool, `${ref.sha256}.tar.gz`);
  };
  const cacheDir = (ref) => {
    checkRef(ref);
    return path.join(cache, ref.tool, ref.sha256);
  };
  const stageFile = (id) => {
    if (typeof id !== "string" || !STAGE_ID.test(id)) throw new TypeError("Invalid stage id.");
    return path.join(base, "stage", id);
  };

  /** @param {string} file @returns {Promise<string>} */
  async function hashFile(file) {
    const hash = createHash("sha256");
    await pipeline(createReadStream(file), async (source) => {
      for await (const chunk of source) hash.update(chunk);
    });
    return hash.digest("hex");
  }

  return Object.freeze({
    kind: "local-fs",

    /**
     * Streams a download into a temporary object: counted, hashed, size-capped. The caller learns the sha256 OF THE BYTES RECEIVED
     * and compares it with the upstream metadata; nothing is addressable until `commit`.
     * @param {import("node:stream").Readable} source
     * @param {{ maxBytes: number }} options
     * @returns {Promise<{ stageId: string, bytes: number, sha256: string }>}
     */
    async stage(source, { maxBytes }) {
      await mkdir(path.join(base, "stage"), { recursive: true, mode: 0o700 });
      const stageId = randomBytes(12).toString("hex");
      const file = stageFile(stageId);
      const hash = createHash("sha256");
      let bytes = 0;
      const counter = new Transform({
        transform(chunk, _e, cb) {
          bytes += chunk.length;
          if (bytes > maxBytes) return cb(new DbMirrorTooLargeError(maxBytes));
          hash.update(chunk);
          return cb(null, chunk);
        },
      });
      try {
        await pipeline(source, counter, createWriteStream(file, { mode: 0o600 }));
      } catch (error) {
        await rm(file, { force: true });
        throw error;
      }
      return { stageId, bytes, sha256: hash.digest("hex") };
    },

    /** @param {string} stageId @returns {import("node:stream").Readable} */
    openStaged: (stageId) => createReadStream(stageFile(stageId)),

    /** @param {string} stageId */
    discardStaged: (stageId) => rm(stageFile(stageId), { force: true }),

    /**
     * Moves a staged object to its content address (atomic rename). An object that already exists is kept. The digest is computed
     * again from the staged file, so a swapped file cannot be committed under another digest.
     * @param {{ tool: string, sha256: string, stageId: string }} input
     * @returns {Promise<{ created: boolean }>}
     */
    async commit({ tool, sha256, stageId }) {
      const target = objectFile({ tool, sha256 });
      const source = stageFile(stageId);
      if ((await hashFile(source)) !== sha256) {
        await rm(source, { force: true });
        throw new DbMirrorIntegrityError();
      }
      await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      if (await stat(target).catch(() => null)) {
        await rm(source, { force: true });
        return { created: false };
      }
      await rename(source, target);
      await chmod(target, 0o444);
      return { created: true };
    },

    /** @param {{ tool: string, sha256: string }} ref @returns {import("node:stream").Readable} */
    open: (ref) => createReadStream(objectFile(ref)),

    /** @param {{ tool: string, sha256: string }} ref @returns {Promise<{ bytes: number } | null>} */
    async stat(ref) {
      const info = await stat(objectFile(ref)).catch(() => null);
      return info?.isFile() ? { bytes: info.size } : null;
    },

    /** Re-hashes a stored object. @param {{ tool: string, sha256: string }} ref @returns {Promise<boolean>} */
    async verify(ref) {
      const file = objectFile(ref);
      if (!(await stat(file).catch(() => null))) return false;
      return (await hashFile(file)) === ref.sha256;
    },

    /** Removes an object and its materialized tree. @param {{ tool: string, sha256: string }} ref */
    async remove(ref) {
      await rm(objectFile(ref), { force: true });
      await removeTree(cacheDir(ref));
    },

    /** @param {string} tool @returns {Promise<Array<{ sha256: string, bytes: number, mtimeMs: number }>>} */
    async list(tool) {
      checkRef({ tool, sha256: "0".repeat(64) });
      const dir = path.join(base, "db", tool);
      const names = await readdir(dir).catch(() => []);
      const out = [];
      for (const name of names) {
        const m = /^([0-9a-f]{64})\.tar\.gz$/.exec(name);
        if (!m) continue;
        const info = await stat(path.join(dir, name));
        out.push({ sha256: m[1], bytes: info.size, mtimeMs: info.mtimeMs });
      }
      return out;
    },

    /** Staged objects older than `olderThanMs` (a crash between download and commit leaves them). */
    async sweepStage({ olderThanMs, now = Date.now() }) {
      const dir = path.join(base, "stage");
      let removed = 0;
      for (const name of await readdir(dir).catch(() => [])) {
        if (!STAGE_ID.test(name)) continue;
        const info = await stat(path.join(dir, name)).catch(() => null);
        if (info && now - info.mtimeMs > olderThanMs) {
          await rm(path.join(dir, name), { force: true });
          removed += 1;
        }
      }
      return removed;
    },

    /** @param {{ tool: string, sha256: string }} ref @returns {string} the directory a scan mounts read-only at `/db` */
    cacheDirFor: cacheDir,

    /**
     * Materializes a snapshot ONCE into the host cache (SE-36): the stored object is hashed again and must match its address, then
     * extracted with the hardened extractor into a temporary directory, sealed (0555/0444) and moved into place by an atomic rename.
     * Concurrent callers are safe: the loser removes its copy and uses the winner's. A directory that exists is complete by
     * construction (it only appears by rename).
     * @param {{ tool: string, sha256: string }} ref
     * @returns {Promise<{ dir: string, created: boolean }>}
     * @throws {DbMirrorIntegrityError} the object is missing or does not match its digest (nothing is extracted)
     */
    async materialize(ref) {
      const final = cacheDir(ref);
      if ((await stat(final).catch(() => null))?.isDirectory())
        return { dir: final, created: false };
      if (!(await this.verify(ref))) throw new DbMirrorIntegrityError();
      await mkdir(path.dirname(final), { recursive: true, mode: 0o700 });
      await chmod(cache, 0o700).catch(() => {});
      await mkdir(path.join(cache, ".tmp"), { recursive: true, mode: 0o700 });
      const temp = path.join(cache, ".tmp", randomBytes(8).toString("hex"));
      try {
        await extractTarGz(createReadStream(objectFile(ref)), {
          destDir: temp,
          limits: snapshotArchiveCapsFor(ref.tool, archiveCaps),
        });
        // Moving a directory needs write access to it, so the top directory is sealed after the rename.
        await sealTree(temp, false);
        try {
          await rename(temp, final);
          await chmod(final, 0o555);
        } catch (error) {
          if (!["ENOTEMPTY", "EEXIST"].includes(error?.code)) throw error;
          await removeTree(temp);
          return { dir: final, created: false };
        }
        return { dir: final, created: true };
      } catch (error) {
        await removeTree(temp).catch(() => {});
        throw error;
      }
    },

    /** @param {{ tool: string, sha256: string }} ref */
    removeMaterialized: (ref) => removeTree(cacheDir(ref)),
  });
}
