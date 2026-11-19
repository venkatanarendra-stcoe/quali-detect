import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { ArtifactTooLargeError } from "./artifact-store.js";
import { parseArtifactRef } from "./artifact-ref.js";
import { redactLogText } from "./log-redaction.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TEXT_TYPES = new Set(["application/json", "text/plain"]);
/** The most one artifact may hold (the database CHECK is the same number). */
export const ARTIFACT_MAX_BYTES = 1048576;
/** The most one `sbom_document` artifact (a raw CycloneDX or SPDX document) may hold: 16 MiB (scan-engines SPEC 7.3, D-8; the database CHECK is the same number). */
export const SBOM_DOCUMENT_MAX_BYTES = 16 * 1048576;
const ARTIFACT_CLASSES = new Set(["standard", "sbom_document"]);

async function readCapped(source, maxBytes) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of source) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.length;
    if (bytes > maxBytes) {
      source.destroy?.();
      throw new ArtifactTooLargeError(maxBytes);
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

/**
 * Postgres driver of the `ArtifactStore` interface (docs/modules/executions/SPEC.md §7.5, §17.ac): small capped objects (1 MiB
 * each, 20 and 8 MiB per execution, insert-only) kept in `execution_artifacts`. The production object-storage driver is still
 * Open and will implement the same methods. The key is the same tenant-scoped `t/<tenant>/x/<execution>/<name>` as the local
 * driver and comes from the same validator; ids must be UUIDs. Text and JSON content passes the credential redaction before it
 * is hashed and stored (the stored sha256 is of the stored bytes).
 * @param {{ repository: ReturnType<typeof import("@qmentisai/db").createExecutionArtifactRepository>, maxBytes?: number }} deps
 */
export function createPostgresArtifactStore({
  repository,
  maxBytes = ARTIFACT_MAX_BYTES,
  sbomMaxBytes = SBOM_DOCUMENT_MAX_BYTES,
}) {
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > ARTIFACT_MAX_BYTES)
    throw new TypeError(`maxBytes must be an integer between 1 and ${ARTIFACT_MAX_BYTES}.`);
  if (!Number.isInteger(sbomMaxBytes) || sbomMaxBytes < 1 || sbomMaxBytes > SBOM_DOCUMENT_MAX_BYTES)
    throw new TypeError(
      `sbomMaxBytes must be an integer between 1 and ${SBOM_DOCUMENT_MAX_BYTES}.`,
    );
  const locate = (ref) => {
    const parsed = parseArtifactRef(ref);
    if (!UUID.test(parsed.tenantId) || !UUID.test(parsed.executionId))
      throw new TypeError("Invalid artifact reference.");
    return parsed;
  };
  return Object.freeze({
    kind: "postgres",
    /** @param {{ tenantId: string, executionId: string, name: string }} ref @returns {string} the tenant-scoped key */
    keyFor: (ref) => locate(ref).key,

    /**
     * Stores a stream (buffered and capped at `maxBytes`). With `ifAbsent` an existing object is kept and `created` is false.
     * @param {{ tenantId: string, executionId: string, name: string }} ref
     * @param {import("node:stream").Readable | Buffer | string} source
     * @param {{ maxBytes?: number, ifAbsent?: boolean, mediaType?: "application/json" | "text/plain" | "application/octet-stream", artifactClass?: "standard" | "sbom_document" }} [options]
     * `artifactClass` `sbom_document` raises the ceiling of THIS object to 16 MiB (the other classes keep 1 MiB).
     * @returns {Promise<{ created: boolean, bytes: number, sha256: string | null }>}
     */
    async put(
      ref,
      source,
      {
        maxBytes: limit,
        ifAbsent = false,
        mediaType = "application/octet-stream",
        artifactClass = "standard",
      } = {},
    ) {
      if (!ARTIFACT_CLASSES.has(artifactClass)) throw new TypeError("Unsupported artifact class.");
      const { tenantId, executionId, name } = locate(ref);
      const classMax = artifactClass === "sbom_document" ? sbomMaxBytes : maxBytes;
      const cap = Math.min(limit ?? classMax, classMax);
      let content = await readCapped(
        Buffer.isBuffer(source) || typeof source === "string"
          ? Readable.from([Buffer.from(source)])
          : source,
        cap,
      );
      if (TEXT_TYPES.has(mediaType))
        content = Buffer.from(redactLogText(content.toString("utf8")), "utf8");
      if (content.length > cap) throw new ArtifactTooLargeError(cap);
      const sha256 = createHash("sha256").update(content).digest("hex");
      const result = await repository.put({
        tenantId,
        executionId,
        name,
        mediaType,
        content,
        sha256,
        ifAbsent,
        artifactClass,
      });
      return {
        created: result.created,
        bytes: result.created ? content.length : 0,
        sha256: result.created ? sha256 : null,
      };
    },

    /** @param {{ tenantId: string, executionId: string, name: string }} ref @returns {import("node:stream").Readable} */
    open(ref) {
      const { tenantId, executionId, name } = locate(ref);
      return Readable.from(
        (async function* () {
          const row = await repository.get({ tenantId, executionId, name });
          if (!row)
            throw Object.assign(new Error("The artifact does not exist."), { code: "ENOENT" });
          yield row.content;
        })(),
      );
    },

    /** Size of the object, or null when it does not exist. @param {{ tenantId: string, executionId: string, name: string }} ref */
    async size(ref) {
      const { tenantId, executionId, name } = locate(ref);
      return (await repository.head({ tenantId, executionId, name }))?.sizeBytes ?? null;
    },

    /** SHA-256 of the stored object, or null when it does not exist. @param {{ tenantId: string, executionId: string, name: string }} ref */
    async sha256(ref) {
      const { tenantId, executionId, name } = locate(ref);
      return (await repository.head({ tenantId, executionId, name }))?.sha256 ?? null;
    },

    /** Deletes one object. @param {{ tenantId: string, executionId: string, name: string }} ref */
    async delete(ref) {
      const { tenantId, executionId, name } = locate(ref);
      await repository.remove({ tenantId, executionId, name });
    },

    /** Deletes everything stored for an execution. @param {{ tenantId: string, executionId: string }} ref */
    async deleteExecution({ tenantId, executionId }) {
      const { tenantId: t, executionId: x } = locate({ tenantId, executionId, name: "x" });
      await repository.removeExecution({ tenantId: t, executionId: x });
    },
  });
}
