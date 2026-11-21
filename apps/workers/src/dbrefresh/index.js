import { QUEUE_NAMES } from "@qmentisai/contracts";
import { createScanDbSnapshotRepository } from "@qmentisai/db";
import {
  NonRetryableError,
  createCliSandboxRuntime,
  createLocalDbMirrorStore,
  createLockManager,
  createRedisClient,
  createSandboxRunner,
  closeRedis,
} from "@qmentisai/infra";
import { loadImageLock } from "../execution/engines/ensemble/catalog/index.js";
import { runWorker } from "../runtime/run-worker.js";
import { createSandboxCanary } from "./canary.js";
import { refreshTool } from "./refresh.js";

/** Entry point of the `dbrefresh` platform worker role (docs/modules/scan-engines/SPEC.md SE-34, part F). */
export const WORKER_NAME = "dbrefresh";

/**
 * A downloader that refuses to download: the real downloader (the only component with network egress, to an allowlist of the upstream
 * hosts) is not built yet and needs the owner (ENG-L09). With the refresh enabled and no downloader wired the job fails closed.
 * @returns {{ latest: Function, download: Function }}
 */
export function createUnconfiguredDownloader() {
  const refuse = async () => {
    throw new NonRetryableError("No snapshot downloader is configured in this process.", {
      reason: "downloader-unconfigured",
    });
  };
  return Object.freeze({ latest: refuse, download: refuse });
}

/**
 * The handler of `maintenance.scan_db.refresh_requested`. It runs ONLY in the `dbrefresh` worker. A message alone never enables it:
 * the process must have SCAN_DB_REFRESH_ENABLED=true (second gate, same pattern as the retention purge), and the message's tool list
 * is intersected with the process's own list. Tools are refreshed one after another; one tool failing does not stop the next, and an
 * unexpected error is re-thrown at the end so the queue retries (the refresh is idempotent). Logs: tool ids, outcomes, reason words
 * and digests only, never a URL, host, header or upstream text.
 * @param {{ db?: any, config: any, logger?: any, deps: import("./refresh.js").RefreshDeps }} input
 * @returns {(message: any, context: { log: any }) => Promise<void>}
 */
export function createDbRefreshHandler({ config, deps }) {
  return async (message, { log }) => {
    const scanDb = config?.scanDb;
    if (!scanDb?.refreshEnabled)
      throw new NonRetryableError("The vulnerability DB refresh is not enabled in this process.", {
        reason: "refresh-disabled",
      });
    if (message.type !== "maintenance.scan_db.refresh_requested")
      throw new NonRetryableError(`The dbrefresh worker does not handle "${message.type}".`, {
        reason: "unsupported-message-type",
      });
    const tools = message.payload.tools.filter((t) => scanDb.tools.includes(t));
    let failure = null;
    const outcomes = [];
    for (const toolId of tools) {
      try {
        outcomes.push(await refreshTool({ toolId, deps, scanDb, log }));
      } catch (error) {
        if (error instanceof NonRetryableError) throw error;
        failure ??= error;
        outcomes.push({ toolId, outcome: "error", reason: error?.name ?? "Error" });
      }
    }
    // housekeeping: crashed runs leave staged downloads and candidates that never reached the gate
    const abandoned = await deps.repo.abandonStaleCandidates({
      olderThanSeconds: scanDb.candidateAbandonSeconds,
    });
    for (const a of abandoned)
      await deps.store.remove({ tool: a.toolId, sha256: a.sha256 }).catch(() => {});
    const staged = await deps.store.sweepStage({
      olderThanMs: scanDb.candidateAbandonSeconds * 1000,
    });
    log.info(
      { outcomes, abandoned: abandoned.length, stagedRemoved: staged },
      "Vulnerability DB refresh finished (counts and digests only)",
    );
    if (failure) throw failure;
  };
}

/**
 * Wires the real dependencies from the configuration: the local-fs mirror store, the snapshot repository, the Redis lock (when
 * REDIS_URL is set), the sandbox runner and the image lock for the canary, and the downloader passed in (unconfigured by default).
 * @param {{ db: any, config: any, logger?: any, downloader?: { latest: Function, download: Function } }} input
 */
export function buildDbRefreshDeps({ db, config, logger, downloader }) {
  const s = config.scanDb;
  const sandboxConfig = {
    ...(config.scanEngines?.sandbox ?? {}),
    mountRoots: {
      archive: [],
      db: [s.cacheRoot],
      rules: config.scanEngines?.rulesDir ? [config.scanEngines.rulesDir] : [],
    },
  };
  const runner = createSandboxRunner({
    runtime: createCliSandboxRuntime({ config: sandboxConfig }),
  });
  const { resolver } = loadImageLock({ production: config.scanEngines?.production === true });
  const redis = config.redisUrl
    ? createRedisClient({ url: config.redisUrl, name: "qmentisai-worker-dbrefresh", logger })
    : null;
  return {
    deps: {
      repo: createScanDbSnapshotRepository({ db }),
      store: createLocalDbMirrorStore({ root: s.mirrorRoot, cacheRoot: s.cacheRoot }),
      downloader: downloader ?? createUnconfiguredDownloader(),
      canary: createSandboxCanary({
        runner,
        resolver,
        rulesDir: config.scanEngines?.rulesDir ?? null,
      }),
      lock: redis ? createLockManager({ redis }) : null,
    },
    close: async () => {
      if (redis) await closeRedis(redis);
    },
  };
}

/**
 * The consumer of the `dbrefresh` queue. `requireTenant: false` is essential: the refresh message is a platform job and carries no
 * tenant, which the consumer would otherwise refuse.
 */
export const DBREFRESH_CONSUMER = Object.freeze({
  name: WORKER_NAME,
  queue: QUEUE_NAMES.DBREFRESH,
  requireTenant: false,
});

/**
 * The handler of this process and what to close at shutdown. With the refresh disabled (the default) the handler refuses every job and
 * NOTHING is built (no runtime, no lock connection).
 * @param {{ db: any, config: any, logger?: any, downloader?: { latest: Function, download: Function } }} input
 * @returns {{ handler: ReturnType<typeof createDbRefreshHandler>, close: () => Promise<void> }}
 */
export function createDbRefreshHandlerFor({ db, config, logger, downloader }) {
  if (!config.scanDb.refreshEnabled)
    return {
      handler: createDbRefreshHandler({ config, deps: /** @type {any} */ (null) }),
      close: async () => {},
    };
  const built = buildDbRefreshDeps({ db, config, logger, downloader });
  return { handler: createDbRefreshHandler({ config, deps: built.deps }), close: built.close };
}

/**
 * Starts the dbrefresh worker. With SCAN_DB_REFRESH_ENABLED=false (the default) it consumes its queue and refuses every job.
 * @param {{ downloader?: { latest: Function, download: Function } }} [options]
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export function start({ downloader } = {}) {
  let closer = async () => {};
  return runWorker({
    ...DBREFRESH_CONSUMER,
    buildHandler: ({ db, config, logger }) => {
      const built = createDbRefreshHandlerFor({ db, config, logger, downloader });
      closer = built.close;
      return built.handler;
    },
    onReady: () => async () => closer(),
  });
}
