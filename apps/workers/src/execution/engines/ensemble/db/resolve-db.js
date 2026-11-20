import { DbMirrorIntegrityError } from "@qmentisai/infra";
import { classifyDbStaleness, dbProvenance, dbStalenessEffect } from "@qmentisai/shared";

/**
 * The READ side of the vulnerability DB mirror, used by the scan path (docs/modules/scan-engines/SPEC.md SE-36, SE-37, SE-38, D-22;
 * part F). It resolves the ONE `active` snapshot of a tool, materializes it into the host cache (the stored object is hashed again
 * and must match its address first) and returns the read-only mount directory, the provenance a result records and the effect of
 * the staleness tier. It imports nothing from the refresh worker (`apps/workers/src/dbrefresh`): the scan path can neither download,
 * promote nor reject anything (ENG-S12 source guard). A candidate, retired or rejected snapshot is never returned.
 *
 * Outcomes:
 * - `{ state: "ok" }`: `dir` to mount at `/db`, `provenance` (sha256 and dates only), `effect` (`succeeded` for fresh, `partial` with
 *   reason `db_stale` otherwise: staleness NEVER fails a scan);
 * - `{ state: "missing" }`: no active snapshot, or its object is missing or does not match its digest: tool `unavailable`, reason
 *   `db_unavailable` (transient). An unverified object is never mounted.
 * @param {{ repo: { getActive: (toolId: string) => Promise<any> }, store: { materialize: Function }, now?: () => Date, days?: Partial<{ aging: number, stale: number, expired: number }> }} deps
 */
export function createDbSnapshotResolver({ repo, store, now = () => new Date(), days }) {
  return Object.freeze({
    /** @param {string} toolId */
    async resolve(toolId) {
      const missing = {
        state: /** @type {const} */ ("missing"),
        effect: { toolStatus: "unavailable", reason: "db_unavailable", failsScan: false },
      };
      const snapshot = await repo.getActive(toolId);
      if (!snapshot) return missing;
      let dir;
      try {
        ({ dir } = await store.materialize({ tool: toolId, sha256: snapshot.sha256 }));
      } catch (error) {
        if (error instanceof DbMirrorIntegrityError) return missing;
        throw error;
      }
      const at = now();
      const { tier } = classifyDbStaleness({ builtAt: snapshot.upstreamBuiltAt, now: at }, days);
      return {
        state: /** @type {const} */ ("ok"),
        dir,
        provenance: dbProvenance(snapshot, { now: at, days }),
        effect: dbStalenessEffect(tier),
      };
    },
  });
}
