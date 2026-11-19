import { Prisma } from "@prisma/client";
import { withTransaction } from "../transaction.js";

/** An artifact with this name already exists for the execution (artifacts are insert-only). */
export class ArtifactExistsError extends Error {
  constructor() {
    super("The artifact already exists.");
    this.name = "ArtifactExistsError";
    this.code = "ARTIFACT_EXISTS";
  }
}

const MEDIA_TYPES = new Set(["application/json", "text/plain", "application/octet-stream"]);
/** Artifact classes with their own ceilings (migration 20261119120100): `standard` and `sbom_document`. */
const ARTIFACT_CLASSES = new Set(["standard", "sbom_document"]);
const MAX_PAGE = 200;

/**
 * Data access of execution artifacts (docs/modules/executions/SPEC.md §7.5, §17.ac), the Postgres driver's repository. Called
 * through `createPostgresArtifactStore` of `@qmentisai/infra`, which validates the reference (one path-segment name, no
 * traversal), caps the size and redacts text content. EVERYTHING is scoped by the trusted `tenantId` and the execution (and the
 * workspace when given): an artifact is never read, listed, written or deleted by name or id alone, and the chain columns of
 * a new row come from the execution row, never from the caller. The database enforces the name rule, the size ceiling, the
 * per-execution count and byte caps and the refusal for terminal executions; rows are insert-only.
 * @param {{ db: any }} deps Prisma client
 */
export function createExecutionArtifactRepository({ db }) {
  const workspaceFilter = (workspaceId) =>
    workspaceId ? Prisma.sql`AND workspace_id = ${workspaceId}::uuid` : Prisma.empty;
  return Object.freeze({
    /**
     * Inserts one artifact. With `ifAbsent` an existing name is kept (`created: false`); without it `ArtifactExistsError`.
     * Returns `{ created: false, found: false }` when the tenant has no such execution.
     * @param {{ tenantId: string, executionId: string, name: string, mediaType: string, content: Buffer, sha256: string, ifAbsent?: boolean, artifactClass?: "standard" | "sbom_document" }} input
     * @param {any} [client]
     * @returns {Promise<{ created: boolean, found: boolean }>}
     */
    async put(
      {
        tenantId,
        executionId,
        name,
        mediaType,
        content,
        sha256,
        ifAbsent = false,
        artifactClass = "standard",
      },
      client = db,
    ) {
      if (!MEDIA_TYPES.has(mediaType)) throw new TypeError("Unsupported artifact media type.");
      if (!Buffer.isBuffer(content)) throw new TypeError("content must be a Buffer");
      if (!ARTIFACT_CLASSES.has(artifactClass)) throw new TypeError("Unsupported artifact class.");
      return withTransaction(client, async (tx) => {
        const rows = await tx.$queryRaw`
          INSERT INTO execution_artifacts (id, tenant_id, workspace_id, repository_id, pipeline_id, execution_id, name, media_type, size_bytes, sha256, content, artifact_class)
          SELECT gen_random_uuid(), e.tenant_id, e.workspace_id, e.repository_id, e.pipeline_id, e.id, ${name}, ${mediaType}, ${content.length}::int, ${sha256}, ${content}, ${artifactClass}
          FROM executions e WHERE e.tenant_id = ${tenantId}::uuid AND e.id = ${executionId}::uuid
          ON CONFLICT (tenant_id, execution_id, name) DO NOTHING
          RETURNING id`;
        if (rows.length === 1) return { created: true, found: true };
        const exists = await tx.$queryRaw`
          SELECT 1 FROM executions WHERE tenant_id = ${tenantId}::uuid AND id = ${executionId}::uuid`;
        if (exists.length === 0) return { created: false, found: false };
        if (!ifAbsent) throw new ArtifactExistsError();
        return { created: false, found: true };
      });
    },

    /**
     * One artifact with its content, or null (tenant, execution and, when given, workspace scoped).
     * @param {{ tenantId: string, workspaceId?: string, executionId: string, name: string }} input
     * @param {any} [client]
     * @returns {Promise<null | { name: string, mediaType: string, sizeBytes: number, sha256: string, content: Buffer, createdAt: Date }>}
     */
    async get({ tenantId, workspaceId, executionId, name }, client = db) {
      const rows = await client.$queryRaw`
        SELECT name, media_type AS "mediaType", size_bytes AS "sizeBytes", sha256, content, created_at AS "createdAt"
        FROM execution_artifacts
        WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND name = ${name} ${workspaceFilter(workspaceId)}`;
      return rows[0] ?? null;
    },

    /**
     * Metadata of one artifact (no content), or null.
     * @param {{ tenantId: string, workspaceId?: string, executionId: string, name: string }} input
     * @param {any} [client]
     */
    async head({ tenantId, workspaceId, executionId, name }, client = db) {
      const rows = await client.$queryRaw`
        SELECT name, media_type AS "mediaType", size_bytes AS "sizeBytes", sha256, created_at AS "createdAt"
        FROM execution_artifacts
        WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND name = ${name} ${workspaceFilter(workspaceId)}`;
      return rows[0] ?? null;
    },

    /**
     * Artifacts of an execution by name (keyset on `name`, metadata only).
     * @param {{ tenantId: string, workspaceId?: string, executionId: string, afterName?: string, limit?: number }} input
     * @param {any} [client]
     */
    async list({ tenantId, workspaceId, executionId, afterName = "", limit = 50 }, client = db) {
      const size = Math.min(Math.max(1, Math.floor(limit)), MAX_PAGE);
      const rows = await client.$queryRaw`
        SELECT name, media_type AS "mediaType", size_bytes AS "sizeBytes", sha256, created_at AS "createdAt"
        FROM execution_artifacts
        WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND name > ${afterName} ${workspaceFilter(workspaceId)}
        ORDER BY name LIMIT ${size + 1}`;
      const items = rows.slice(0, size);
      return {
        items,
        nextAfterName: items.length > 0 ? items[items.length - 1].name : null,
        hasMore: rows.length > size,
      };
    },

    /**
     * Deletes one artifact (tenant and execution scoped); returns whether a row went.
     * @param {{ tenantId: string, executionId: string, name: string }} input
     * @param {any} [client]
     */
    async remove({ tenantId, executionId, name }, client = db) {
      const count = await client.$executeRaw`
        DELETE FROM execution_artifacts WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND name = ${name}`;
      return count === 1;
    },

    /**
     * Deletes every artifact of an execution (tenant scoped); returns the number deleted.
     * @param {{ tenantId: string, executionId: string }} input
     * @param {any} [client]
     */
    removeExecution: ({ tenantId, executionId }, client = db) =>
      client.$executeRaw`
        DELETE FROM execution_artifacts WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid`,
  });
}
