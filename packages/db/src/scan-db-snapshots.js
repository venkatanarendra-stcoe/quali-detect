import {
  DB_ALERT_ACTIONS,
  DB_ALERT_STAGES,
  DB_REJECT_REASONS,
  DB_TOOL_IDS,
} from "@qmentisai/shared";
import { withTransaction } from "./transaction.js";

/**
 * Repository of `scan_db_snapshots` (docs/modules/scan-engines/SPEC.md 5.12, SE-33, SE-35). PLATFORM-LEVEL public data: the table has
 * no tenant column and no tenant is ever an input here (a result's own provenance columns live in the tenant-owned
 * `scan_tool_runs`). The database enforces what matters (one `active` per tool, one-way status changes, immutable identity, no
 * DELETE); this repository composes it. Rows are mapped to plain objects with a `Number` size, and `toProvenanceRow` is the ONLY
 * shape handed to the scan path.
 * @param {{ db: any }} deps Prisma client
 */
export function createScanDbSnapshotRepository({ db }) {
  const mapRow = (row) =>
    row
      ? {
          id: row.id,
          toolId: row.toolId,
          sourceVersion: row.sourceVersion,
          upstreamBuiltAt: row.upstreamBuiltAt,
          fetchedAt: row.fetchedAt,
          sizeBytes: Number(row.sizeBytes),
          sha256: row.sha256,
          status: row.status,
          promotedAt: row.promotedAt,
          retiredAt: row.retiredAt,
          rejectedReason: row.rejectedReason,
          contentPrunedAt: row.contentPrunedAt,
          sources: row.sources,
          recordCounts: row.recordCounts,
        }
      : null;
  const tool = (toolId) => {
    if (!DB_TOOL_IDS.includes(toolId)) throw new TypeError("Unknown mirror tool.");
    return toolId;
  };
  const lock = (client, toolId) =>
    client.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`scan_db_snapshots:${toolId}`}, 0))`;

  const api = {
    /**
     * Inserts a candidate. A snapshot with the same (tool, sha256) is NOT inserted again: the existing row is returned with
     * `created: false` (an idempotent refresh).
     * @param {{ toolId: string, sourceVersion: string, upstreamBuiltAt: Date, sizeBytes: number, sha256: string, sources: object[], recordCounts: object, fetchedAt?: Date }} input
     * @param {any} [client]
     */
    async insertCandidate(input, client = db) {
      const toolId = tool(input.toolId);
      const rows = await client.$queryRaw`
        INSERT INTO scan_db_snapshots (id, tool_id, source_version, upstream_built_at, fetched_at, size_bytes, sha256, sources, record_counts)
        VALUES (gen_random_uuid(), ${toolId}, ${input.sourceVersion}, ${input.upstreamBuiltAt}, ${input.fetchedAt ?? new Date()}, ${input.sizeBytes}::bigint,
                ${input.sha256}, ${JSON.stringify(input.sources)}::jsonb, ${JSON.stringify(input.recordCounts)}::jsonb)
        ON CONFLICT (tool_id, sha256) DO NOTHING RETURNING id`;
      const row = await api.getBySha({ toolId, sha256: input.sha256 }, client);
      return { snapshot: row, created: rows.length === 1 };
    },

    /** @param {{ toolId: string, sha256: string }} ref @param {any} [client] */
    async getBySha({ toolId, sha256 }, client = db) {
      return mapRow(
        await client.scanDbSnapshot.findUnique({
          where: { toolId_sha256: { toolId: tool(toolId), sha256 } },
        }),
      );
    },

    /** The one active snapshot of a tool, or null (one statement, so it is never torn). @param {string} toolId @param {any} [client] */
    async getActive(toolId, client = db) {
      return mapRow(
        await client.scanDbSnapshot.findFirst({
          where: { toolId: tool(toolId), status: "active" },
        }),
      );
    },

    /** Newest first. @param {string} toolId @param {{ statuses?: string[], limit?: number }} [options] @param {any} [client] */
    async list(toolId, { statuses, limit = 50 } = {}, client = db) {
      const rows = await client.scanDbSnapshot.findMany({
        where: { toolId: tool(toolId), ...(statuses ? { status: { in: statuses } } : {}) },
        orderBy: [{ upstreamBuiltAt: "desc" }, { createdAt: "desc" }],
        take: Math.min(Math.max(limit, 1), 200),
      });
      return rows.map(mapRow);
    },

    /**
     * Step 1 of the atomic switch: retires the active snapshot of the tool (if any). Call it inside the SAME transaction as
     * {@link activate}; used alone it would leave a tool without an active snapshot, which is why {@link promote} composes both.
     * @param {string} toolId @param {any} client a transaction client
     */
    async retireActive(toolId, client) {
      await lock(client, tool(toolId));
      const rows = await client.$queryRaw`
        UPDATE scan_db_snapshots SET status = 'retired', retired_at = now() WHERE tool_id = ${toolId} AND status = 'active' RETURNING id`;
      return rows[0]?.id ?? null;
    },

    /** Step 2: activates a candidate. @param {string} id @param {any} client a transaction client @returns {Promise<boolean>} */
    async activate(id, client) {
      const rows = await client.$queryRaw`
        UPDATE scan_db_snapshots SET status = 'active', promoted_at = now() WHERE id = ${id}::uuid AND status = 'candidate' RETURNING id`;
      return rows.length === 1;
    },

    /**
     * The atomic switch (SE-35): ONE transaction retires the previous active snapshot and activates the candidate, under a
     * per-tool advisory lock. A reader sees the old snapshot or the new one, never none and never two; a failure anywhere rolls
     * both steps back, so the previous snapshot stays active. A candidate that is no longer a candidate promotes nothing.
     * @param {{ id: string, toolId: string }} input
     * @returns {Promise<{ promoted: boolean, retiredId: string | null }>}
     */
    async promote({ id, toolId }) {
      tool(toolId);
      return db.$transaction(async (tx) => {
        await lock(tx, toolId);
        const candidate = await tx.scanDbSnapshot.findFirst({
          where: { id, toolId, status: "candidate" },
          select: { id: true },
        });
        if (!candidate) return { promoted: false, retiredId: null };
        const retiredId = await api.retireActive(toolId, tx);
        const ok = await api.activate(id, tx);
        if (!ok) throw new Error("The candidate vanished inside the promotion transaction.");
        return { promoted: true, retiredId };
      });
    },

    /** Rejects a candidate with a fixed reason; a non-candidate is left alone. @param {{ id: string, reason: string }} input @param {any} [client] @returns {Promise<boolean>} */
    async reject({ id, reason }, client = db) {
      if (!DB_REJECT_REASONS.includes(reason)) throw new TypeError("Unknown reject reason.");
      const rows = await client.$queryRaw`
        UPDATE scan_db_snapshots SET status = 'rejected', rejected_reason = ${reason} WHERE id = ${id}::uuid AND status = 'candidate' RETURNING id`;
      return rows.length === 1;
    },

    /** Records a rejected download that never became a candidate (the digest is the bytes received). @param {{ toolId: string, sourceVersion: string, upstreamBuiltAt: Date, sizeBytes: number, sha256: string, reason: string, sources?: object[], recordCounts?: object }} input @param {any} [client] */
    async insertRejected(input, client = db) {
      if (!DB_REJECT_REASONS.includes(input.reason)) throw new TypeError("Unknown reject reason.");
      const toolId = tool(input.toolId);
      await client.$executeRaw`
        INSERT INTO scan_db_snapshots (id, tool_id, source_version, upstream_built_at, size_bytes, sha256, status, rejected_reason, sources, record_counts)
        VALUES (gen_random_uuid(), ${toolId}, ${input.sourceVersion}, ${input.upstreamBuiltAt}, ${input.sizeBytes}::bigint, ${input.sha256}, 'rejected', ${input.reason},
                ${JSON.stringify(input.sources ?? [])}::jsonb, ${JSON.stringify(input.recordCounts ?? {})}::jsonb)
        ON CONFLICT (tool_id, sha256) DO NOTHING`;
    },

    /**
     * The operator alert "a refresh was blocked by quarantine" (SPEC scan-engines SE-39, owner decision D-24 (f)): ONE platform audit
     * entry (`platform_audit_logs`, actor type `system`, no tenant, the Root Console audit log is where an operator reads it) per
     * (tool, digest). The advisory lock of the pair and the NOT EXISTS make it once even for two concurrent refreshes, and a repeated
     * refresh of the same digest writes nothing (no spam). The entry carries ONLY the tool id, the fixed reason word, the stage word,
     * the digest and integer counts: no URL, host, token, source name, record id or upstream text ever reaches it.
     * @param {{ toolId: string, sha256: string, stage: string, counts?: { records?: number, quarantined?: number, notAllowed?: number, invalid?: number } }} input
     * @param {any} [client]
     * @returns {Promise<{ recorded: boolean }>} `recorded` is false when this digest was already alerted
     */
    async recordQuarantineAlert({ toolId, sha256, stage, counts = {} }, client = db) {
      tool(toolId);
      if (!/^[0-9a-f]{64}$/.test(String(sha256))) throw new TypeError("Invalid snapshot digest.");
      if (!DB_ALERT_STAGES.includes(stage)) throw new TypeError("Unknown alert stage.");
      const count = (n) => (Number.isInteger(n) && n >= 0 && n <= 1_000_000_000 ? n : null);
      const metadata = {
        toolId,
        reason: "quarantined_source",
        stage,
        sha256,
        records: count(counts.records),
        quarantined: count(counts.quarantined),
        notAllowed: count(counts.notAllowed),
        invalid: count(counts.invalid),
      };
      return withTransaction(client, async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`scan_db_alert:${toolId}:${sha256}`}, 0))`;
        const rows = await tx.$queryRaw`
          INSERT INTO platform_audit_logs (id, actor_type, action, target_type, metadata, created_at)
          SELECT gen_random_uuid(), 'system'::platform_actor_type, ${DB_ALERT_ACTIONS.QUARANTINE_DENIED}, 'scan_db_snapshot', ${JSON.stringify(metadata)}::jsonb,
                 clock_timestamp()
          WHERE NOT EXISTS (
            SELECT 1 FROM platform_audit_logs
            WHERE action = ${DB_ALERT_ACTIONS.QUARANTINE_DENIED} AND metadata->>'toolId' = ${toolId} AND metadata->>'sha256' = ${sha256})
          RETURNING id`;
        return { recorded: rows.length === 1 };
      });
    },

    /** Rejects candidates older than `olderThanSeconds` (a crash between insert and promotion). @param {{ olderThanSeconds: number }} input @param {any} [client] @returns {Promise<Array<{ toolId: string, sha256: string }>>} */
    async abandonStaleCandidates({ olderThanSeconds }, client = db) {
      const rows = await client.$queryRaw`
        UPDATE scan_db_snapshots SET status = 'rejected', rejected_reason = 'abandoned'
        WHERE status = 'candidate' AND created_at < now() - make_interval(secs => ${olderThanSeconds}::double precision)
        RETURNING tool_id AS "toolId", sha256`;
      return rows;
    },

    /** Retired snapshots beyond the newest `keep` whose content is not yet pruned (SE-33: the previous N are kept). @param {{ toolId: string, keep: number }} input @param {any} [client] */
    async prunableRetired({ toolId, keep }, client = db) {
      const rows = await client.scanDbSnapshot.findMany({
        where: { toolId: tool(toolId), status: "retired" },
        orderBy: { promotedAt: "desc" },
        skip: keep,
      });
      return rows.filter((r) => r.contentPrunedAt === null).map(mapRow);
    },

    /** @param {string} id @param {any} [client] */
    async markPruned(id, client = db) {
      await client.$executeRaw`UPDATE scan_db_snapshots SET content_pruned_at = now() WHERE id = ${id}::uuid AND content_pruned_at IS NULL`;
    },
  };
  return Object.freeze(api);
}

/**
 * The READ-ONLY view of the snapshot table for the scan path (SPEC scan-engines SE-36, ENG-S12): the only function is `getActive`, so
 * code that can only start tools can neither promote, reject, retire nor insert a snapshot, whatever it imports.
 * @param {{ db: any }} deps Prisma client
 */
export function createScanDbSnapshotReader({ db }) {
  const repository = createScanDbSnapshotRepository({ db });
  return Object.freeze({
    /** @param {string} toolId @param {any} [client] */
    getActive: (toolId, client) => repository.getActive(toolId, client),
  });
}
