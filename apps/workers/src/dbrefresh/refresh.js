import {
  DbMirrorIntegrityError,
  DbMirrorTooLargeError,
  checkDeclaredSources,
  inspectSnapshotArchive,
} from "@qmentisai/infra";
import { DB_TOOL_IDS } from "@qmentisai/shared";
import { z } from "zod";

/**
 * The vulnerability DB refresh of ONE tool (docs/modules/scan-engines/SPEC.md 5.12, SE-33..SE-35, SE-45, SE-46, T13; part F). The
 * downloader is an injected interface (the real one, the only component with network egress, is the owner's; tests use a fake):
 *   `latest({ toolId, signal })`                       -> the upstream's integrity metadata (see `upstreamMetadataSchema`)
 *   `download({ toolId, metadata, signal })`           -> a Readable of the tar.gz bundle
 * Order of one refresh (nothing is promoted until every step passed; ANY failure keeps the previous `active` snapshot):
 *   1. refuse a tool without a mirror (Grype, D-21); take the per-tool lock (Redis, when configured; the database enforces the rest)
 *   2. read the upstream metadata; refuse a declared quarantined or non-allowlisted source BEFORE downloading anything
 *   3. a digest the mirror already knows is not downloaded again (idempotent); a known `candidate` resumes at step 8
 *   4. download into a temporary name with a size cap, hash the bytes received
 *   5. verify the digest against the upstream metadata (a mismatch is rejected and recorded under the digest we computed)
 *   6. inspect the archive without extracting it (hostile archive containment, record-level source allowlist and quarantine)
 *   7. commit the object to its content address and write the `candidate` row
 *   8. promotion gate: size and age sanity, then materialize (re-hash) and the canary scan in the sandbox
 *   9. atomic switch (one transaction), then prune retired snapshots beyond the newest N
 * Rows are written only for bytes this process hashed itself, so an upstream cannot poison the table with a digest it merely claims.
 */

/** The integrity metadata the downloader must obtain from the upstream (no URL, host, token or path in it). */
export const upstreamMetadataSchema = z
  .object({
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    sizeBytes: z.number().int().positive(),
    builtAt: z.string().datetime(),
    sourceVersion: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$/),
    sources: z.array(z.string().max(64)).min(1).max(50),
  })
  .strict();

/** The reasons an INSPECTION verdict maps to. */
const VERDICT_REASON = Object.freeze({
  archive_hostile: "archive_hostile",
  record_invalid: "record_invalid",
  quarantined_source: "quarantined_source",
  source_not_allowed: "source_not_allowed",
  empty: "empty",
});

const SKEW_MS = 24 * 3600 * 1000;

/**
 * The size and age part of the promotion gate (SE-35 a). Pure.
 * @param {{ sizeBytes: number, upstreamBuiltAt: Date }} candidate
 * @param {{ sizeBytes: number } | null} active
 * @param {{ now: Date, minSizePercent: number, maxUpstreamAgeDays: number }} policy
 * @returns {null | "empty" | "too_small" | "too_old" | "future_built"}
 */
export function promotionSanity(candidate, active, { now, minSizePercent, maxUpstreamAgeDays }) {
  if (!(candidate.sizeBytes > 0)) return "empty";
  if (active && candidate.sizeBytes * 100 < active.sizeBytes * minSizePercent) return "too_small";
  const built = candidate.upstreamBuiltAt.getTime();
  if (built > now.getTime() + SKEW_MS) return "future_built";
  if (now.getTime() - built > maxUpstreamAgeDays * 86_400_000) return "too_old";
  return null;
}

/**
 * @typedef {{
 *   repo: ReturnType<typeof import("@qmentisai/db").createScanDbSnapshotRepository>,
 *   store: ReturnType<typeof import("@qmentisai/infra").createLocalDbMirrorStore>,
 *   downloader: { latest: Function, download: Function },
 *   canary: (input: { toolId: string, sha256: string, dir: string, signal?: AbortSignal }) => Promise<{ ok: boolean, reason?: string }>,
 *   lock?: { acquirePlatform: Function } | null,
 *   now?: () => Date,
 * }} RefreshDeps
 * @typedef {{ toolId: string, outcome: "promoted" | "unchanged" | "rejected" | "skipped_locked" | "canary_unavailable" | "not_candidate", reason?: string, sha256?: string }} RefreshOutcome
 */

/**
 * @param {{ toolId: string, deps: RefreshDeps, scanDb: any, signal?: AbortSignal, log?: any }} input `scanDb` is `config.scanDb`
 * @returns {Promise<RefreshOutcome>}
 */
export async function refreshTool({ toolId, deps, scanDb, signal, log }) {
  if (!DB_TOOL_IDS.includes(toolId)) throw new TypeError("This tool has no mirror in v1.");
  const { repo, store, downloader, canary, lock } = deps;
  const now = () => (deps.now ?? (() => new Date()))();
  const held = lock
    ? await lock.acquirePlatform({
        resource: `scan-db-refresh-${toolId}`,
        ttlMs: scanDb.lockTtlSeconds * 1000,
      })
    : undefined;
  if (held === null) return { toolId, outcome: "skipped_locked" };
  try {
    // 2. upstream metadata, checked before anything is downloaded
    const metadata = upstreamMetadataSchema.parse(await downloader.latest({ toolId, signal }));
    const declared = checkDeclaredSources(metadata.sources);
    if (!declared.ok) {
      const reason = declared.quarantined.length > 0 ? "quarantined_source" : "source_not_allowed";
      log?.warn?.(
        { toolId, reason },
        "The upstream declares a source that is not allowed; nothing was downloaded",
      );
      return { toolId, outcome: "rejected", reason };
    }
    const builtAt = new Date(metadata.builtAt);
    if (metadata.sizeBytes > scanDb.maxBytes)
      return { toolId, outcome: "rejected", reason: "too_large" };

    // 3. idempotency: the mirror knows this digest already
    const known = await repo.getBySha({ toolId, sha256: metadata.sha256 });
    let candidate = known?.status === "candidate" ? known : null;
    if (known && !candidate) {
      if (known.status === "rejected")
        return { toolId, outcome: "rejected", reason: known.rejectedReason, sha256: known.sha256 };
      return { toolId, outcome: "unchanged", sha256: known.sha256 };
    }

    if (!candidate) {
      // 4. download and hash the bytes received
      let staged;
      try {
        staged = await store.stage(await downloader.download({ toolId, metadata, signal }), {
          maxBytes: scanDb.maxBytes,
        });
      } catch (error) {
        if (error instanceof DbMirrorTooLargeError)
          return { toolId, outcome: "rejected", reason: "too_large" };
        throw error;
      }
      const fail = async (reason, counts = {}) => {
        await store.discardStaged(staged.stageId);
        await repo.insertRejected({
          toolId,
          sourceVersion: metadata.sourceVersion,
          upstreamBuiltAt: builtAt,
          sizeBytes: Math.max(staged.bytes, 1),
          sha256: staged.sha256,
          reason,
          sources: declared.sources,
          recordCounts: counts,
        });
        log?.warn?.(
          { toolId, reason, sha256: staged.sha256 },
          "A downloaded snapshot was rejected",
        );
        return {
          toolId,
          outcome: /** @type {const} */ ("rejected"),
          reason,
          sha256: staged.sha256,
        };
      };
      // 5. integrity against the upstream metadata
      if (staged.sha256 !== metadata.sha256 || staged.bytes !== metadata.sizeBytes)
        return fail("integrity_mismatch");
      // 6. inspection without extraction
      const inspected = await inspectSnapshotArchive(store.openStaged(staged.stageId));
      const counts = {
        records: inspected.records,
        bySource: inspected.bySource,
        quarantined: inspected.quarantined,
        notAllowed: inspected.notAllowed,
        invalid: inspected.invalid,
      };
      if (inspected.verdict !== "ok") return fail(VERDICT_REASON[inspected.verdict], counts);
      // 7. content address and candidate row
      await store.commit({ tool: toolId, sha256: staged.sha256, stageId: staged.stageId });
      const sources = [
        ...declared.sources,
        ...inspected.declaredSources.filter((s) => !declared.sources.some((d) => d.id === s.id)),
      ];
      ({ snapshot: candidate } = await repo.insertCandidate({
        toolId,
        sourceVersion: metadata.sourceVersion,
        upstreamBuiltAt: builtAt,
        sizeBytes: staged.bytes,
        sha256: staged.sha256,
        sources,
        recordCounts: counts,
      }));
    }

    // 8. promotion gate
    const reject = async (reason) => {
      await repo.reject({ id: candidate.id, reason });
      await store.remove({ tool: toolId, sha256: candidate.sha256 });
      log?.warn?.(
        { toolId, reason, sha256: candidate.sha256 },
        "A candidate snapshot was rejected",
      );
      return {
        toolId,
        outcome: /** @type {const} */ ("rejected"),
        reason,
        sha256: candidate.sha256,
      };
    };
    const active = await repo.getActive(toolId);
    const sanity = promotionSanity(candidate, active, {
      now: now(),
      minSizePercent: scanDb.minSizePercent,
      maxUpstreamAgeDays: scanDb.maxUpstreamAgeDays,
    });
    if (sanity) return reject(sanity);
    let dir;
    try {
      ({ dir } = await store.materialize({ tool: toolId, sha256: candidate.sha256 }));
    } catch (error) {
      if (error instanceof DbMirrorIntegrityError) return reject("integrity_mismatch");
      if (error?.name === "ArchiveError") return reject("archive_hostile");
      throw error;
    }
    let verdict;
    try {
      verdict = await canary({ toolId, sha256: candidate.sha256, dir, signal });
    } catch {
      verdict = { ok: false, reason: "unavailable" };
    }
    // the canary could not RUN (runtime down): the candidate stays and the next refresh resumes it; it is not the snapshot's fault
    if (!verdict.ok && verdict.reason === "unavailable")
      return { toolId, outcome: "canary_unavailable", sha256: candidate.sha256 };
    if (!verdict.ok) return reject("canary_failed");

    // 9. the atomic switch, then retention of the previous N
    const switched = await repo.promote({ id: candidate.id, toolId });
    if (!switched.promoted) return { toolId, outcome: "not_candidate", sha256: candidate.sha256 };
    for (const old of await repo.prunableRetired({ toolId, keep: scanDb.keepRetired })) {
      await store.remove({ tool: toolId, sha256: old.sha256 });
      await repo.markPruned(old.id);
    }
    log?.info?.(
      { toolId, sha256: candidate.sha256, retired: switched.retiredId !== null },
      "A snapshot was promoted",
    );
    return { toolId, outcome: "promoted", sha256: candidate.sha256 };
  } finally {
    await held?.release().catch(() => {});
  }
}
