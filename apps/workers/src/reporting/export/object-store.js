import { createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rename, rm, stat } from "node:fs/promises";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { ArtifactTooLargeError } from "@qmentisai/infra";

/**
 * The object store of generated reports (docs/modules/reporting-dashboards/SPEC.md 12 item 5). It REUSES the Executions artifact store's
 * design (the local-filesystem driver of `@qmentisai/infra`: one validated key, the tenant in every path, no public URL, written under a
 * temporary name and renamed so a half-written object is never visible, size-capped and hashed while it streams, root mode 0700, objects
 * mode 0600, `ArtifactTooLargeError`) and its traversal rules (no separator, `..`, leading dot, upper-case or over-long segment), but not
 * its key layout: a report key is `reports/<tenantId>/<reportId>.<csv|pdf>`, the shape the `report_exports.object_key` CHECK demands. The
 * key is ALWAYS built here from two canonical UUIDs and a format from a closed list; no name ever comes from a request, a message body or a
 * user. The API reads the same tree with `apps/api/src/modules/reporting/export-object-reader.js` (same validator, read only).
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const FORMATS = Object.freeze(["csv", "pdf"]);

/**
 * The tenant-scoped key of a report. Throws `TypeError` for anything that is not two lower-case canonical UUIDs and a known format
 * (separators, `..`, a leading dot, upper case, over-long values, non-strings).
 * @param {{ tenantId: string, reportId: string, format: string }} ref
 * @returns {string}
 */
export function reportObjectKey({ tenantId, reportId, format }) {
  if (
    typeof tenantId !== "string" ||
    typeof reportId !== "string" ||
    !UUID.test(tenantId) ||
    !UUID.test(reportId) ||
    !FORMATS.includes(format)
  )
    throw new TypeError("Invalid report reference.");
  return `reports/${tenantId}/${reportId}.${format}`;
}

/**
 * Local-filesystem driver for report objects.
 * @param {{ root: string }} options absolute directory (the same `ARTIFACT_STORE_ROOT` the Executions store uses; the trees do not meet: `t/` and `reports/`)
 */
export function createReportObjectStore({ root }) {
  if (typeof root !== "string" || !path.isAbsolute(root))
    throw new TypeError("The report store root must be an absolute path.");
  const base = path.resolve(root);

  /** @param {{ tenantId: string, reportId: string, format: string }} ref */
  const locate = (ref) => {
    const key = reportObjectKey(ref);
    const file = path.join(base, ...key.split("/"));
    // belt and braces: the resolved path stays under the root
    if (!file.startsWith(`${base}${path.sep}`)) throw new TypeError("Invalid report reference.");
    return { key, file, dir: path.dirname(file) };
  };

  return Object.freeze({
    kind: "local-fs-reports",
    /** @param {{ tenantId: string, reportId: string, format: string }} ref */
    keyFor: (ref) => locate(ref).key,

    /**
     * Stores a stream: counted, hashed, size-capped, written to a temporary name and renamed. An existing object is replaced atomically.
     * @param {{ tenantId: string, reportId: string, format: string }} ref
     * @param {import("node:stream").Readable} source
     * @param {{ maxBytes: number }} options
     * @returns {Promise<{ key: string, bytes: number, sha256: string }>}
     */
    async put(ref, source, { maxBytes }) {
      const { key, dir, file } = locate(ref);
      await mkdir(base, { recursive: true, mode: 0o700 });
      await mkdir(dir, { recursive: true, mode: 0o700 });
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
      return { key, bytes, sha256: hash.digest("hex") };
    },

    /** @param {{ tenantId: string, reportId: string, format: string }} ref @returns {import("node:stream").Readable} */
    open: (ref) => createReadStream(locate(ref).file),

    /** Size of the object, or null when it does not exist. @param {{ tenantId: string, reportId: string, format: string }} ref */
    async size(ref) {
      const info = await stat(locate(ref).file).catch(() => null);
      return info?.isFile() ? info.size : null;
    },

    /** Deletes one object (idempotent). @param {{ tenantId: string, reportId: string, format: string }} ref */
    async delete(ref) {
      await rm(locate(ref).file, { force: true });
    },
  });
}
