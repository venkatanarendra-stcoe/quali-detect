/**
 * Secrets ensemble (docs/modules/scan-engines/SPEC.md 16.1 part I): Gitleaks and detect-secrets as tool adapters over their JSON output with
 * value-dropping parse schemas, the type-class table, the file inventory and applicability gate, the incremental scope, and the pure run of
 * the two over scripted tool output. No secret value, value-derived hash or snippet ever leaves an adapter.
 */
import { rollUpTask } from "@qmentisai/shared";
import { createAdapterRegistry } from "../core/adapter.js";
import { mergeTaskCandidates } from "../core/merger.js";
import { runToolParse } from "../core/run-parse.js";
import { createDetectSecretsAdapter } from "./detect-secrets.js";
import { createGitleaksAdapter } from "./gitleaks.js";

export * from "./common.js";
export * from "./plan.js";
export * from "./scope.js";
export * from "./type-class.js";
export {
  DETECT_SECRETS_ACCEPTED_EXIT_CODES,
  DETECT_SECRETS_ARGV,
  DETECT_SECRETS_ENV,
  DETECT_SECRETS_FULL_TARGET,
  createDetectSecretsAdapter,
  detectSecretsRecordSchema,
  detectSecretsRecords,
  mapDetectSecretsRecord,
} from "./detect-secrets.js";
export {
  GITLEAKS_ACCEPTED_EXIT_CODES,
  GITLEAKS_ARGV,
  GITLEAKS_ENV,
  GITLEAKS_FULL_TARGET,
  GITLEAKS_REDACTED,
  createGitleaksAdapter,
  gitleaksRecordSchema,
  gitleaksRecords,
  mapGitleaksRecord,
} from "./gitleaks.js";

/** The Secrets adapters in tool order (Gitleaks, detect-secrets). Both only when the ensemble is enabled (the caller reads the flag). */
export function createSecretsAdapterRegistry({ ensembleEnabled = false } = {}) {
  const registry = createAdapterRegistry([]);
  if (ensembleEnabled === true) {
    registry.register(createGitleaksAdapter());
    registry.register(createDetectSecretsAdapter());
  }
  return registry;
}

/**
 * Parses the output of each Secrets tool run, merges the candidates of the task (type class, file and line; SE-12 strict) and rolls the tool
 * statuses up (SPEC 5.4). Pure apart from reading the supplied streams.
 * @param {{
 *   taskRef: string,
 *   runs: ({ adapter: Readonly<any>, streams: { stdout: Buffer | string, exitCode: number | null, truncated?: boolean }, ctx: Omit<import("../core/run-parse.js").ParseContext, "taskRef"> }
 *     | { toolId: string, status: "skipped" | "unavailable", reason: string })[],
 *   relevantFilesExist?: boolean
 * }} input
 */
export function runSecretsEnsemble({ taskRef, runs, relevantFilesExist = true }) {
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
  const merged = mergeTaskCandidates({ taskRef, scanType: "secrets", candidates });
  const rollup = rollUpTask({ tools, relevantFilesExist, coverageGaps: [] });
  return { outcomes, rollup, findings: merged.findings, stats: merged.stats };
}
