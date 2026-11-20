import { redactLogText } from "@qmentisai/infra";
import { DEFAULT_SECRETS_RULE, DIFF_STATUSES, computeFloor } from "@qmentisai/shared";
import { detectChanges } from "./change-detection.js";

/**
 * The deterministic floor of one execution (docs/modules/scan-decisioning/SPEC.md 5.3): change detection plus the pure
 * `computeFloor` of `@qmentisai/shared`. Returns the shape part E persists in `scan_decisions`:
 * `{ diff: { source, status, changedTotal, summary }, secretsRule, floor, notSelected, zeroScan }`. The floor is ALWAYS inside
 * `enabledTypes`; a failed, truncated or unavailable diff yields every enabled type (fail closed). Not yet called by the
 * orchestrator (part E). No patch text, no file contents, no token: `summary.samples` are control-stripped, length-capped and
 * credential-redacted paths, up to `config.scanDecision.samplePaths` per class.
 * @param {{
 *   execution: Parameters<typeof detectChanges>[0]["execution"],
 *   repository: Parameters<typeof detectChanges>[0]["repository"],
 *   github: Parameters<typeof detectChanges>[0]["github"],
 *   config: { scanDecision: { secretsRule: string, maxChangedFiles: number, maxPages: number, samplePaths: number } },
 *   enabledTypes: string[],
 *   exclusions?: { paths?: string[] } | null,
 *   signal?: AbortSignal,
 *   logger?: any,
 *   collectChangedFiles?: boolean,
 * }} input `enabledTypes` and `exclusions` come from the execution's pipeline configuration snapshot
 */
export async function decideFloor({
  execution,
  repository,
  github,
  config,
  enabledTypes,
  exclusions,
  signal,
  logger,
  collectChangedFiles = false,
}) {
  const detected = await detectChanges({ execution, repository, github, config, signal, logger });
  const secretsRule = config.scanDecision.secretsRule ?? DEFAULT_SECRETS_RULE;
  const { floor, changed, notSelected, zeroScan } = computeFloor({
    scanKind: execution.scanKind,
    diff: { status: detected.status, files: detected.files },
    enabledTypes,
    secretsRule,
    exclusions,
    redact: redactLogText,
    samplePaths: config.scanDecision.samplePaths,
  });
  logger?.info?.(
    {
      executionId: execution.id,
      diffStatus: detected.status,
      floorTypes: floor.length,
      notSelected: notSelected.length,
      changedTotal: changed.total,
      zeroScan,
    },
    "Scan floor computed",
  );
  return {
    diff: {
      source: detected.source,
      status: detected.status,
      reason: detected.reason,
      changedTotal: detected.status === DIFF_STATUSES.COMPLETE ? changed.total : 0,
      summary: changed,
    },
    secretsRule,
    floor,
    notSelected,
    zeroScan,
    ...(collectChangedFiles ? { changedFiles: detected.files } : {}),
  };
}
