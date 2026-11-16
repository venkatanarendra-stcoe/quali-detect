import { createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rename, rm, stat } from "node:fs/promises";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const NAME = /^[a-z][a-z0-9._-]{0,63}$/;

/** The upload exceeded `maxBytes`. */
export class ArtifactTooLargeError extends Error {
  constructor(maxBytes) {
    super(`The artifact exceeds ${maxBytes} bytes.`);
    this.name = "ArtifactTooLargeError";
    this.maxBytes = maxBytes;
  }
}

/**
 * Minimal local-filesystem ArtifactStore (docs/modules/executions/SPEC.md §7.5; the production driver is Open, EQ-4). Part C
 * uses it only for the archive hand-off between the fetch step and the scan worker. The key of an object is derived by ONE
 * function, `t/<tenantId>/x/<executionId>/<name>`: the tenant is in every path, there is no public URL and the caller never
 * supplies a path. Objects are written under a temporary name and renamed, so a half-written object is never visible under
 * its key; the root is created with mode 0700.
 * @param {{ root: string }} options absolute directory
 */
export function createLocalArtifactStore({ root }) {
  if (typeof root !== "string" || !path.isAbsolute(root))
    throw new TypeError("The artifact store root must be an absolute path.");
  const base = path.resolve(root);

  /** @param {{ tenantId: string, executionId: string, name: string }} ref */
  function locate({ tenantId, executionId, name }) {
    if (!SEGMENT.test(tenantId ?? "") || !SEGMENT.test(executionId ?? "") || !NAME.test(name ?? ""))
      throw new TypeError("Invalid artifact reference.");
    const dir = path.join(base, "t", tenantId, "x", executionId);
    return { dir, file: path.join(dir, name), key: `t/${tenantId}/x/${executionId}/${name}` };
  }

  return Object.freeze({
    kind: "local-fs",
    /** @param {{ tenantId: string, executionId: string, name: string }} ref @returns {string} the tenant-scoped key */
    keyFor: (ref) => locate(ref).key,

    /**
     * Stores a stream: counted, hashed, size-capped, written to a temporary name and renamed. With `ifAbsent` an existing
     * object is kept and `created` is false (the stream is not read).
     * @param {{ tenantId: string, executionId: string, name: string }} ref
     * @param {import("node:stream").Readable} source
     * @param {{ maxBytes: number, ifAbsent?: boolean }} options
     * @returns {Promise<{ created: boolean, bytes: number, sha256: string | null }>}
     */
    async put(ref, source, { maxBytes, ifAbsent = false }) {
      const { dir, file } = locate(ref);
      await mkdir(base, { recursive: true, mode: 0o700 });
      await mkdir(dir, { recursive: true, mode: 0o700 });
      if (ifAbsent && (await stat(file).catch(() => null))) {
        source.destroy?.();
        return { created: false, bytes: 0, sha256: null };
      }
      const temp = `${file}.tmp-${randomBytes(6).toString("hex")}`;
      const hash = createHash("sha256");
      let bytes = 0;
      const meter = new Transform({
        transform(chunk, _encoding, callback) {
          bytes += chunk.length;
          if (bytes > maxBytes) return callback(new ArtifactTooLargeError(maxBytes));
          hash.update(chunk);
          callback(null, chunk);
        },
      });
      try {
        await pipeline(source, meter, createWriteStream(temp, { mode: 0o600, flags: "wx" }));
        await rename(temp, file);
      } catch (error) {
        await rm(temp, { force: true });
        throw error;
      }
      return { created: true, bytes, sha256: hash.digest("hex") };
    },

    /** @param {{ tenantId: string, executionId: string, name: string }} ref @returns {import("node:stream").Readable} */
    open: (ref) => createReadStream(locate(ref).file),

    /** Size of the object, or null when it does not exist. @param {{ tenantId: string, executionId: string, name: string }} ref */
    async size(ref) {
      const info = await stat(locate(ref).file).catch(() => null);
      return info?.isFile() ? info.size : null;
    },

    /** SHA-256 of the stored object, or null when it does not exist. @param {{ tenantId: string, executionId: string, name: string }} ref */
    async sha256(ref) {
      const { file } = locate(ref);
      if (!(await stat(file).catch(() => null))) return null;
      const hash = createHash("sha256");
      for await (const chunk of createReadStream(file)) hash.update(chunk);
      return hash.digest("hex");
    },

    /** Deletes one object (and leftover temporary objects of it). @param {{ tenantId: string, executionId: string, name: string }} ref */
    async delete(ref) {
      const { dir, file } = locate(ref);
      await rm(file, { force: true });
      const { readdir } = await import("node:fs/promises");
      for (const entry of await readdir(dir).catch(() => []))
        if (entry.startsWith(`${ref.name}.tmp-`)) await rm(path.join(dir, entry), { force: true });
    },

    /** Deletes everything stored for an execution. @param {{ tenantId: string, executionId: string }} ref */
    async deleteExecution({ tenantId, executionId }) {
      const { dir } = locate({ tenantId, executionId, name: "x" });
      await rm(dir, { recursive: true, force: true });
    },
  });
}
