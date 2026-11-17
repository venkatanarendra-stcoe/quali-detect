import os from "node:os";
import { QUEUE_NAMES } from "@qmentisai/contracts";
import { createLocalArtifactStore } from "@qmentisai/infra";
import { engineRegistry } from "../execution/registry.js";
import { createScanTaskHandler } from "../execution/scan-handler.js";
import { createNoopHandler } from "../handlers/noop.js";
import { runWorker } from "../runtime/run-worker.js";

/** Entry point of the scan worker (see docs/architecture/WORKER_ARCHITECTURE.md). */
export const WORKER_NAME = "scan";

/**
 * Starts the scan worker. With `EXECUTION_ORCHESTRATOR_ENABLED=false` (the default) it consumes the `scan` queue with a no-op
 * handler. With the flag on it runs the scan task handler (docs/modules/executions/SPEC.md part C) on `scan` AND on
 * `scan-untrusted` (same handler, separate consumers, ER-7). This process loads NO GitHub App or SecretStore configuration
 * (ER-5): it receives the archive through the artifact store and the task from the database.
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export async function start() {
  // TEST-ONLY hook: loaded by a dynamic import only when EXECUTION_TEST_DELAY_MS is set (throws in production)
  const delayRequested =
    !!process.env.EXECUTION_TEST_DELAY_MS && process.env.EXECUTION_TEST_DELAY_MS !== "0";
  const testDelayModule = delayRequested ? await import("../execution/test-delay.js") : null;
  const build = ({ db, config, logger }) =>
    config.execution.enabled
      ? createScanTaskHandler({
          testDelay: testDelayModule ? testDelayModule.loadTestDelay(process.env, logger) : null,
          db,
          config,
          logger,
          store: createLocalArtifactStore({ root: config.execution.artifactStoreRoot }),
          engines: engineRegistry,
          tmpRoot: os.tmpdir(),
        })
      : createNoopHandler();
  const enabled = process.env.EXECUTION_ORCHESTRATOR_ENABLED === "true";
  return runWorker({
    name: WORKER_NAME,
    queue: QUEUE_NAMES.SCAN,
    buildHandler: build,
    verifyOwnership: (config) => config.execution.enabled,
    additional: enabled
      ? [{ queue: QUEUE_NAMES.SCAN_UNTRUSTED, buildHandler: build, verifyOwnership: true }]
      : [],
  });
}
