/**
 * SBOM ensemble (docs/modules/scan-engines/SPEC.md 16.1 part E): Syft and Trivy (SBOM mode) as tool adapters over CycloneDX JSON, the
 * `sbom-lite` adapter over the legacy in-process inventory, and the pure run of the three over scripted tool output. NOT wired
 * into the scan worker (part K); the legacy engine stays the registered default and the rollout flag stays off.
 */
import { rollUpTask } from "@qmentisai/shared";
import { createAdapterRegistry } from "../core/adapter.js";
import { mergeTaskCandidates } from "../core/merger.js";
import { runToolParse } from "../core/run-parse.js";
import { createSbomLiteAdapter } from "./sbom-lite.js";
import { createSyftAdapter } from "./syft.js";
import { createTrivySbomAdapter } from "./trivy-sbom.js";

export * from "./cyclonedx.js";
export * from "./plan.js";
export { SYFT_ARGV, SYFT_ENV, createSyftAdapter } from "./syft.js";
export { TRIVY_SBOM_ARGV, TRIVY_SBOM_ENV, createTrivySbomAdapter } from "./trivy-sbom.js";
export { collectSbomLiteStreams, createSbomLiteAdapter, sbomLiteRecords } from "./sbom-lite.js";

/**
 * The SBOM adapters in tool order. `sbom-lite` is always present (the legacy and default path); Syft and Trivy only when the
 * ensemble is enabled (the caller reads the rollout flag, this module reads nothing).
 * @param {{ ensembleEnabled?: boolean }} [options]
 */
export function createSbomAdapterRegistry({ ensembleEnabled = false } = {}) {
  const registry = createAdapterRegistry([createSbomLiteAdapter()]);
  if (ensembleEnabled === true) {
    registry.register(createSyftAdapter());
    registry.register(createTrivySbomAdapter());
  }
  return registry;
}

/**
 * Parses the output of each SBOM tool run, merges the candidates of the task by the exact merge key (SE-12 strict) and rolls the
 * tool statuses up (SPEC 5.4). Pure apart from reading the supplied streams.
 * @param {{
 *   taskRef: string,
 *   runs: ({ adapter: Readonly<any>, streams: { stdout: Buffer | string, exitCode: number | null, truncated?: boolean }, ctx: Omit<import("../core/run-parse.js").ParseContext, "taskRef"> }
 *     | { toolId: string, status: "skipped" | "unavailable", reason: string })[],
 *   relevantFilesExist?: boolean
 * }} input
 */
export function runSbomEnsemble({ taskRef, runs, relevantFilesExist = true }) {
  const outcomes = [];
  const candidates = [];
  const tools = [];
  for (const run of runs) {
    if ("adapter" in run) {
      const outcome = runToolParse(run.adapter, run.streams, { ...run.ctx, taskRef });
      outcomes.push({ toolId: run.adapter.toolId, ...outcome, candidates: undefined });
      candidates.push(...outcome.candidates);
      tools.push({ toolId: run.adapter.toolId, status: outcome.status, reason: outcome.reason });
    } else {
      outcomes.push({ toolId: run.toolId, status: run.status, reason: run.reason });
      tools.push({ toolId: run.toolId, status: run.status, reason: run.reason });
    }
  }
  const merged = mergeTaskCandidates({ taskRef, scanType: "sbom", candidates });
  const rollup = rollUpTask({ tools, relevantFilesExist });
  return { outcomes, rollup, findings: merged.findings, stats: merged.stats };
}
