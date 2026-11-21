/**
 * SAST ensemble (docs/modules/scan-engines/SPEC.md 16.1 part H): Opengrep with the platform-owned rule pack and Bandit as tool
 * adapters over their JSON output, language detection and the applicability gate, the incremental scope, and the pure run of the two over
 * scripted tool output. gosec is HELD (SPEC phase 4b): it has no adapter and the engine never selects it.
 */
import { rollUpTask } from "@qmentisai/shared";
import { createAdapterRegistry } from "../core/adapter.js";
import { mergeTaskCandidates } from "../core/merger.js";
import { runToolParse } from "../core/run-parse.js";
import { createBanditAdapter } from "./bandit.js";
import { createOpengrepAdapter } from "./opengrep.js";

export * from "./common.js";
export * from "./languages.js";
export * from "./plan.js";
export * from "./rule-pack.js";
export * from "./scope.js";
export {
  BANDIT_ACCEPTED_EXIT_CODES,
  BANDIT_ARGV,
  BANDIT_CREDENTIAL_TESTS,
  BANDIT_CREDENTIAL_TITLE,
  BANDIT_ENV,
  BANDIT_FULL_TARGET,
  banditLines,
  banditRecordSchema,
  banditRecords,
  createBanditAdapter,
  mapBanditRecord,
} from "./bandit.js";
export {
  CREDENTIAL_CATEGORY,
  OPENGREP_ACCEPTED_EXIT_CODES,
  OPENGREP_ARGV,
  OPENGREP_ENV,
  OPENGREP_FULL_TARGET,
  OPENGREP_VERIFIED_VERSION,
  PLATFORM_RULE_ID,
  createOpengrepAdapter,
  mapOpengrepRecord,
  opengrepRecordSchema,
  opengrepRecords,
} from "./opengrep.js";

/** The SAST adapters in tool order (Opengrep, Bandit). Both only when the ensemble is enabled (the caller reads the flag). */
export function createSastAdapterRegistry({ ensembleEnabled = false } = {}) {
  const registry = createAdapterRegistry([]);
  if (ensembleEnabled === true) {
    registry.register(createOpengrepAdapter());
    registry.register(createBanditAdapter());
  }
  return registry;
}

/**
 * Parses the output of each SAST tool run, merges the candidates of the task (rule class, file and line tolerance, SE-12 strict) and
 * rolls the tool statuses up (SPEC 5.4). Pure apart from reading the supplied streams.
 * @param {{
 *   taskRef: string,
 *   runs: ({ adapter: Readonly<any>, streams: { stdout: Buffer | string, exitCode: number | null, truncated?: boolean }, ctx: Omit<import("../core/run-parse.js").ParseContext, "taskRef"> }
 *     | { toolId: string, status: "skipped" | "unavailable", reason: string })[],
 *   relevantFilesExist?: boolean,
 *   coverageGaps?: string[]
 * }} input
 */
export function runSastEnsemble({ taskRef, runs, relevantFilesExist = true, coverageGaps = [] }) {
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
  const merged = mergeTaskCandidates({ taskRef, scanType: "sast", candidates });
  const rollup = rollUpTask({ tools, relevantFilesExist, coverageGaps });
  return { outcomes, rollup, findings: merged.findings, stats: merged.stats };
}
