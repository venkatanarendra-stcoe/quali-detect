import {
  createCapacityGate,
  createCliSandboxRuntime,
  createJanitor,
  createLocalDbMirrorStore,
  createSandboxRunner,
} from "@qmentisai/infra";
import { createScanDbSnapshotReader, createScanTaskRepository } from "@qmentisai/db";
import { loadImageLock } from "../catalog/index.js";
import { createDbSnapshotResolver } from "../db/resolve-db.js";
import { createEnsembleSbomEngine } from "./engine.js";
import { createEnsembleSastEngine } from "./sast-engine.js";
import { createEnsembleScaEngine } from "./sca-engine.js";
import { createTreePathExists } from "./tree-paths.js";

/**
 * Builds the ensemble engines (SBOM, SCA and SAST) and the pieces around it from the validated worker configuration (docs/modules/scan-engines/SPEC.md
 * 5.8, 6.4, part K core). Called ONLY by the scan worker and ONLY while the ensemble rollout flag is true; nothing else
 * imports it. It creates the CLI runtime (execFile, never a shell, never a socket mount), the per-attempt runner, the capacity gate
 * (per worker, tenant, task and fork share), the image resolver from the reviewed lock file and the janitor. `startJanitor` sweeps
 * once at start and then every `janitorSeconds`; the returned function stops it. A sweep error is logged by code only.
 * @param {{ config: any, db: any, logger?: any, runtime?: any }} deps `runtime` replaces the CLI runtime (tests)
 */
export function buildEnsembleEngine({ config, db, logger, runtime }) {
  const s = config.scanEngines;
  // the verified vulnerability-database snapshots are materialized by the Part F store into `scanDb.cacheRoot` and mounted read-only
  // at /db (SPEC SE-36); without both roots the SCA tools are `unavailable` / `db_unavailable` (fail visible, never a silent skip)
  const d = config.scanDb ?? {};
  const dbReady = typeof d.cacheRoot === "string" && typeof d.mirrorRoot === "string";
  if (!dbReady)
    logger?.warn?.(
      "SCAN_DB_MIRROR_ROOT and SCAN_DB_CACHE_ROOT are not both set: every SCA tool will be unavailable (db_unavailable)",
    );
  const sandboxConfig = {
    ...s.sandbox,
    mountRoots: {
      archive: [s.archiveRoot],
      db: dbReady ? [d.cacheRoot] : [],
      rules: [s.rulesDir],
    },
  };
  const rt = runtime ?? createCliSandboxRuntime({ config: sandboxConfig });
  const runner = createSandboxRunner({ runtime: rt });
  const forkShare = Math.max(1, Math.floor((s.maxContainers * s.untrustedCapacityShare) / 100));
  const gate = createCapacityGate({
    perWorker: s.maxContainers,
    perTenant: s.maxContainersPerTenant,
    perTask: s.toolParallelism,
    forkShare,
  });
  const { resolver, sha256 } = loadImageLock({ production: s.production === true });
  const engine = createEnsembleSbomEngine({
    runner,
    gate,
    resolver,
    rulesDir: s.rulesDir,
    toolWaitMs: s.waitSeconds * 1000,
    treePathExists: createTreePathExists,
  });
  const dbResolver = dbReady
    ? createDbSnapshotResolver({
        repo: createScanDbSnapshotReader({ db }),
        store: createLocalDbMirrorStore({ root: d.mirrorRoot, cacheRoot: d.cacheRoot }),
        days: d.stalenessDays,
      })
    : { resolve: async () => ({ state: "missing" }) };
  const scaEngine = createEnsembleScaEngine({
    runner,
    gate,
    resolver,
    dbResolver,
    rulesDir: s.rulesDir,
    toolWaitMs: s.waitSeconds * 1000,
    treePathExists: createTreePathExists,
  });
  // SAST: the platform rule pack under `<rulesDir>/qm-sast` is loaded and checked here (a broken pack stops the worker's first scan
  // task, never scans with a partly valid pack)
  const sastEngine = createEnsembleSastEngine({
    runner,
    gate,
    resolver,
    rulesDir: s.rulesDir,
    toolWaitMs: s.waitSeconds * 1000,
    treePathExists: createTreePathExists,
  });
  const tasks = createScanTaskRepository({ db });
  const janitor = createJanitor({
    runtime: rt,
    // the container label is the 1-based attempt number, the task column is 0-based
    isAttemptRunning: (ref) => tasks.isAttemptRunning({ ...ref, attempt: ref.attempt - 1 }),
    onError: (event) =>
      logger?.warn?.({ code: event.code }, "The scan janitor could not remove a container"),
  });
  const log = logger?.child ? logger.child({ component: "scan-janitor" }) : logger;
  return {
    engine,
    scaEngine,
    sastEngine,
    /** Every ensemble engine, for the registry (the SBOM, SCA and SAST engines). */
    engines: [engine, scaEngine, sastEngine],
    runner,
    gate,
    janitor,
    imageLockSha256: sha256,
    /** Sweeps now and every `janitorSeconds`; returns the stop function. Never throws. */
    startJanitor() {
      const sweep = () =>
        janitor.sweep().then(
          (r) => {
            if (r.removed.length > 0)
              log?.warn?.({ removed: r.removed.length }, "Orphan scan containers removed");
          },
          (e) => log?.warn?.({ errorName: e?.name }, "The scan janitor sweep failed"),
        );
      void sweep();
      const timer = setInterval(sweep, s.janitorSeconds * 1000);
      timer.unref?.();
      return () => clearInterval(timer);
    },
  };
}
