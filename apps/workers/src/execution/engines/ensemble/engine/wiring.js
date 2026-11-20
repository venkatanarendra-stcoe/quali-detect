import {
  createCapacityGate,
  createCliSandboxRuntime,
  createJanitor,
  createSandboxRunner,
} from "@qmentisai/infra";
import { createScanTaskRepository } from "@qmentisai/db";
import { loadImageLock } from "../catalog/index.js";
import { createEnsembleSbomEngine } from "./engine.js";
import { createTreePathExists } from "./tree-paths.js";

/**
 * Builds the ensemble engine and the pieces around it from the validated worker configuration (docs/modules/scan-engines/SPEC.md
 * 5.8, 6.4, part K core). Called ONLY by the scan worker and ONLY while the ensemble rollout flag is true; nothing else
 * imports it. It creates the CLI runtime (execFile, never a shell, never a socket mount), the per-attempt runner, the capacity gate
 * (per worker, tenant, task and fork share), the image resolver from the reviewed lock file and the janitor. `startJanitor` sweeps
 * once at start and then every `janitorSeconds`; the returned function stops it. A sweep error is logged by code only.
 * @param {{ config: any, db: any, logger?: any, runtime?: any }} deps `runtime` replaces the CLI runtime (tests)
 */
export function buildEnsembleEngine({ config, db, logger, runtime }) {
  const s = config.scanEngines;
  const sandboxConfig = {
    ...s.sandbox,
    mountRoots: { archive: [s.archiveRoot], db: [], rules: [s.rulesDir] },
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
