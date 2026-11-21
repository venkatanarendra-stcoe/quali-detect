/**
 * SCA ensemble (docs/modules/scan-engines/SPEC.md 16.1 part G): Trivy (language ecosystems only) and OSV-Scanner (offline) as tool
 * adapters over their JSON output, and the pure run of the two over scripted tool output. Grype is DEFERRED to v2 (D-21): it has no
 * adapter and the adapter registry refuses it.
 */
import { rollUpTask } from "@qmentisai/shared";
import { createAdapterRegistry } from "../core/adapter.js";
import { mergeTaskCandidates } from "../core/merger.js";
import { runToolParse } from "../core/run-parse.js";
import { createOsvScannerAdapter } from "./osv-scanner.js";
import { createTrivyScaAdapter } from "./trivy-vuln.js";

export * from "./common.js";
export * from "./plan.js";
export {
  OSV_ACCEPTED_EXIT_CODES,
  OSV_SCA_ARGV,
  OSV_SCA_ENV,
  createOsvScannerAdapter,
  mapOsvRecord,
  osvRecordSchema,
  osvRecords,
} from "./osv-scanner.js";
export {
  TRIVY_SCA_ARGV,
  TRIVY_SCA_ENV,
  createTrivyScaAdapter,
  mapTrivyRecord,
  trivyRecordSchema,
  trivyRecords,
} from "./trivy-vuln.js";

/** The SCA adapters in tool order (Trivy, OSV-Scanner). Both only when the ensemble is enabled (the caller reads the flag). */
export function createScaAdapterRegistry({ ensembleEnabled = false } = {}) {
  const registry = createAdapterRegistry([]);
  if (ensembleEnabled === true) {
    registry.register(createTrivyScaAdapter());
    registry.register(createOsvScannerAdapter());
  }
  return registry;
}

/**
 * Parses the output of each SCA tool run, merges the candidates of the task (alias union-find, SE-12 strict) and rolls the tool
 * statuses up (SPEC 5.4). Pure apart from reading the supplied streams.
 * @param {{
 *   taskRef: string,
 *   runs: ({ adapter: Readonly<any>, streams: { stdout: Buffer | string, exitCode: number | null, truncated?: boolean }, ctx: Omit<import("../core/run-parse.js").ParseContext, "taskRef">, dbStale?: boolean }
 *     | { toolId: string, status: "skipped" | "unavailable", reason: string })[],
 *   relevantFilesExist?: boolean
 * }} input `dbStale` marks a run against a snapshot of a stale tier: a clean run becomes `partial` / `db_stale`
 */
export function runScaEnsemble({ taskRef, runs, relevantFilesExist = true }) {
  const outcomes = [];
  const candidates = [];
  const tools = [];
  for (const run of runs) {
    if ("adapter" in run) {
      const outcome = runToolParse(run.adapter, run.streams, { ...run.ctx, taskRef });
      const stale = run.dbStale === true && outcome.status === "succeeded";
      const status = stale ? "partial" : outcome.status;
      const reason = stale ? "db_stale" : outcome.reason;
      outcomes.push({
        toolId: run.adapter.toolId,
        ...outcome,
        status,
        reason,
        candidates: undefined,
      });
      candidates.push(...outcome.candidates);
      tools.push({ toolId: run.adapter.toolId, status, reason });
    } else {
      outcomes.push({ toolId: run.toolId, status: run.status, reason: run.reason });
      tools.push({ toolId: run.toolId, status: run.status, reason: run.reason });
    }
  }
  const merged = mergeTaskCandidates({ taskRef, scanType: "sca", candidates });
  const rollup = rollUpTask({ tools, relevantFilesExist });
  return { outcomes, rollup, findings: merged.findings, stats: merged.stats };
}
