import { withTransaction } from "../transaction.js";

/** The one marker row of the orchestrator (ER-31). */
export const FIRST_ENABLED_MARKER = "orchestrator.first_enabled";

/**
 * Persisted first-enable marker and one-time stale-sweep state (docs/modules/executions/SPEC.md ER-31, `execution_orchestrator_markers`:
 * platform-level, no tenant column, never exposed by an API). The marker is the DATABASE ROW; the environment flag only makes a
 * worker look at it. `first_enabled_at` and `sweep_completed_at` are set once (database trigger); a completed sweep never runs
 * again, even if the flag is switched off and on.
 * @param {{ db: any }} deps Prisma client
 */
export function createOrchestratorMarkerRepository({ db }) {
  const read = (client) =>
    client.executionOrchestratorMarker.findUnique({ where: { markerKey: FIRST_ENABLED_MARKER } });
  return Object.freeze({
    /** Inserts the marker if it does not exist (ON CONFLICT DO NOTHING) and returns the row. @param {any} [client] */
    async ensureMarker(client = db) {
      await client.$executeRaw`
        INSERT INTO execution_orchestrator_markers (marker_key, first_enabled_at) VALUES (${FIRST_ENABLED_MARKER}, now()) ON CONFLICT (marker_key) DO NOTHING`;
      return read(client);
    },
    /** @param {any} [client] */
    getMarker: (client = db) => read(client),
    /**
     * Takes the sweep lease: only while the sweep is not completed and nobody else holds an unexpired lease. Exactly one
     * worker gets the row; a crashed sweeper's lease expires and the next start continues the sweep.
     * @param {{ workerId: string, leaseTtlSeconds: number }} input
     * @param {any} [client]
     */
    async takeSweepLease({ workerId, leaseTtlSeconds }, client = db) {
      const rows = await client.$queryRaw`
        UPDATE execution_orchestrator_markers
        SET sweep_started_at = COALESCE(sweep_started_at, now()), sweep_lease_owner = ${workerId},
            sweep_lease_expires_at = now() + make_interval(secs => ${leaseTtlSeconds}::double precision)
        WHERE marker_key = ${FIRST_ENABLED_MARKER} AND sweep_completed_at IS NULL
          AND (sweep_lease_owner IS NULL OR sweep_lease_expires_at < now() OR sweep_lease_owner = ${workerId})
        RETURNING marker_key`;
      return rows.length === 1;
    },
    /** Adds to `swept_count` and extends the lease (progress of a batch). @param {{ workerId: string, count: number, leaseTtlSeconds: number }} input @param {any} [client] */
    async recordSweepProgress({ workerId, count, leaseTtlSeconds }, client = db) {
      const rows = await client.$queryRaw`
        UPDATE execution_orchestrator_markers
        SET swept_count = swept_count + ${count}::int, sweep_lease_expires_at = now() + make_interval(secs => ${leaseTtlSeconds}::double precision)
        WHERE marker_key = ${FIRST_ENABLED_MARKER} AND sweep_completed_at IS NULL AND sweep_lease_owner = ${workerId}
        RETURNING marker_key`;
      return rows.length === 1;
    },
    /** Completes the sweep once (the lease holder only). @param {{ workerId: string }} input @param {any} [client] */
    async completeSweep({ workerId }, client = db) {
      return withTransaction(client, async (tx) => {
        const rows = await tx.$queryRaw`
          UPDATE execution_orchestrator_markers
          SET sweep_completed_at = now(), sweep_lease_owner = NULL, sweep_lease_expires_at = NULL
          WHERE marker_key = ${FIRST_ENABLED_MARKER} AND sweep_completed_at IS NULL AND sweep_lease_owner = ${workerId}
          RETURNING swept_count AS "sweptCount"`;
        return rows[0] ?? null;
      });
    },
  });
}
