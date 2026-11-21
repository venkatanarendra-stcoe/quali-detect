import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { rollUpTask } from "@qmentisai/shared";
import { mergeTaskCandidatesAsync } from "../core/merger.js";
import { runToolParseAsync } from "../core/run-parse.js";
import { toStorageRowsAsync } from "../core/storage.js";
import { filterToChanged } from "../sast/scope.js";
import {
  DETECT_SECRETS_ARGV,
  DETECT_SECRETS_ENV,
  createDetectSecretsAdapter,
} from "../secrets/detect-secrets.js";
import { createGitleaksAdapter } from "../secrets/gitleaks.js";
import {
  isSecretsToolControlPath,
  planSecretsScope,
  scopedFileInventory,
  secretsApplicability,
  walkAllFiles,
} from "../secrets/scope.js";
import { createContainerToolRunner } from "./container-run.js";
import { DEFAULT_TOOL_WAIT_MS, ENGINE_ID, ENSEMBLE_VERSION } from "./constants.js";
import { runManifestSha256 } from "./run-manifest.js";

/**
 * The ensemble engine for the Secrets scan type (docs/modules/scan-engines/SPEC.md 5.2, 5.4 row 3, 5.5, 5.6.4, 5.7, 5.9, 6.1, part I): Gitleaks and
 * detect-secrets in their sandboxes, registered under the catalog id `default` only while the rollout flag is on. It owns everything between
 * "the tree is extracted" and "the result is ready to store".
 *
 * What it adds to the SAST engine's shape: EVERYTHING is scanned (no vendored-directory list, SPEC 17.w (5)); a tree with no file is "nothing to
 * scan" (row 3) and there is no language gap; Gitleaks always scans the whole tree and the changed-path filter is applied afterwards, while
 * detect-secrets receives the changed files as explicit targets (SPEC 5.9); the engine declares {@link isSecretsToolControlPath} as its
 * EXTRACTION DENY LIST (`extractionDeny`, SPEC 11.3 layer 2), which the scan handler applies when it extracts the archive: a repository
 * `.gitleaksignore` in the root of the tree hides every finding and no flag prevents it (verified on a real run), so it never reaches a tool.
 *
 * No secret value, hash of a value or snippet exists anywhere here: the adapters drop them at the schema, the findings hold locations and
 * classes only, and the log line of the engine carries counts only.
 *
 * @param {{
 *   runner: { runTool: Function, abortAttempt: Function },
 *   gate: { acquire: Function },
 *   resolver: { resolve: Function },
 *   rulesDir: string,
 *   toolWaitMs?: number,
 *   now?: () => number,
 *   newId?: () => string,
 *   treePathExists?: (sourceDir: string) => (relativePath: string) => boolean,
 *   walkTree?: typeof walkAllFiles
 * }} deps `rulesDir` holds the platform configuration (`gitleaks.toml`), mounted read-only at `/rules`; read ONCE here (fail fast)
 */
export function createEnsembleSecretsEngine({
  runner,
  gate,
  resolver,
  rulesDir,
  toolWaitMs = DEFAULT_TOOL_WAIT_MS,
  now = Date.now,
  newId = randomUUID,
  treePathExists,
  walkTree = walkAllFiles,
}) {
  if (typeof rulesDir !== "string" || !path.isAbsolute(rulesDir))
    throw new TypeError("rulesDir must be an absolute path");
  const adapters = [createGitleaksAdapter(), createDetectSecretsAdapter()];
  const sha = (...parts) => {
    const h = createHash("sha256");
    for (const part of parts) h.update(part).update("\0");
    return h.digest("hex");
  };
  const configDigests = {
    gitleaks: sha(readFileSync(path.join(rulesDir, "gitleaks.toml"))),
    // detect-secrets has no configuration file: its configuration IS the sealed command line and environment
    "detect-secrets": sha(JSON.stringify([DETECT_SECRETS_ARGV, DETECT_SECRETS_ENV])),
  };
  const runContainerTool = createContainerToolRunner({
    runner,
    gate,
    resolver,
    scanType: "secrets",
    rulesDir,
    configDigests,
    toolWaitMs,
    now,
    newId,
  });
  const version = `ensemble-secrets/${ENSEMBLE_VERSION}`;

  /** A tool the tree gives no file to: recorded, never started (SPEC 5.3, SE-9). */
  const skipped = (adapter) => {
    const at = new Date(now()).toISOString();
    return {
      record: {
        id: newId(),
        toolId: adapter.toolId,
        toolVersion: "unknown",
        imageDigest: null,
        configDigest: configDigests[adapter.toolId],
        status: "skipped",
        reason: "no_applicable_files",
        exitCode: null,
        scope: { kind: "full", paths: 0 },
        limits: {},
        capacityWaitMs: 0,
        startedAt: at,
        finishedAt: at,
        durationMs: 0,
      },
      streams: null,
    };
  };

  /** Parses one tool's output with the REAL adapter; a file the tool could not process makes a clean run `partial`. */
  async function parseTool(adapter, ran, taskRef, pathExists, kind) {
    const { record, streams } = ran;
    if (streams === null) return { record, candidates: [] };
    const outcome = await runToolParseAsync(adapter, streams, {
      taskRef,
      toolRunId: record.id,
      toolVersion: record.toolVersion,
      imageDigest: record.imageDigest,
      ...(pathExists ? { pathExists } : {}),
    });
    return {
      record: {
        ...record,
        status: outcome.status,
        reason: outcome.reason,
        recordsSeen: outcome.recordsSeen,
        recordsDropped: outcome.recordsDropped,
        findingsMapped: outcome.findingsMapped,
        severityCounts: outcome.severityCounts,
        truncated: outcome.truncated,
      },
      // every candidate states how its tool was scoped (SPEC 7.2 `scope`)
      candidates: outcome.candidates.map((c) => ({ ...c, scope: { kind, inScope: true } })),
    };
  }

  return Object.freeze({
    scanType: "secrets",
    engineId: ENGINE_ID,
    version,
    idempotent: true,
    /** Tells the scan handler to hand over the trusted platform facts (tenant, deadline, trust, changed paths). */
    needsPlatform: true,
    /** The extraction deny list of this scan type (SPEC 11.3 layer 2): tool-control files never reach a tool. */
    extractionDeny: isSecretsToolControlPath,
    /**
     * @param {Readonly<Record<string, any>>} context the frozen ScanContext
     * @param {{ signal: AbortSignal, log: (level: string, message: string) => void, emit: Function, platform: { tenantId: string, deadlineEpoch: number, secondsToDeadline: number, fork?: boolean, changedPaths?: { status: string, paths: string[] }, maxItems?: number } }} hooks
     */
    async runTask(context, { signal, log, platform }) {
      if (!platform?.tenantId) throw new TypeError("the ensemble engine needs the platform facts");
      const taskRef = context.taskId;
      const ctx = { platform, context, signal, log };
      const inventory = await walkTree(context.sourceDir);
      const scope = planSecretsScope(platform.changedPaths, inventory);
      const app = secretsApplicability(scopedFileInventory(inventory, scope.changed));
      const settled = await Promise.all(
        adapters.map(async (adapter) => {
          if (!app.applicable[adapter.toolId]) return { adapter, ran: skipped(adapter) };
          const targets = scope.targets[adapter.toolId] ?? null;
          if (targets !== null && targets.length === 0) return { adapter, ran: skipped(adapter) };
          const kind = scope.toolKinds[adapter.toolId];
          const ran = await runContainerTool(adapter, ctx, {
            ...(targets !== null ? { targets } : {}),
            scope: {
              kind,
              paths: targets !== null ? targets.length : (scope.changed?.size ?? 0),
            },
          });
          return { adapter, ran, kind };
        }),
      );
      // an abort leaves nothing behind: every container of this attempt is killed and removed (SPEC 6.4)
      if (signal.aborted)
        await runner
          .abortAttempt({ taskId: context.taskId, attempt: context.attempt + 1 })
          .catch(() => {});
      const pathExists = treePathExists ? treePathExists(context.sourceDir) : undefined;
      const parsed = [];
      // bounded: one entry per tool (two); each parse below checkpoints per record
      for (const s of settled)
        parsed.push(
          await parseTool(
            s.adapter,
            s.ran,
            taskRef,
            pathExists,
            s.kind ?? scope.toolKinds[s.adapter.toolId],
          ),
        );
      const toolRuns = parsed.map((p) => p.record);
      const reason = String(signal.reason?.message);
      const rollup = rollUpTask({
        tools: toolRuns.map((r) => ({ toolId: r.toolId, status: r.status, reason: r.reason })),
        cancelled: signal.aborted && reason !== "task_deadline",
        deadlineReached: signal.aborted && reason === "task_deadline",
        relevantFilesExist: app.relevantFilesExist,
        coverageGaps: [],
      });
      const merged = await mergeTaskCandidatesAsync({
        taskRef,
        scanType: "secrets",
        // bounded: concatenates the candidate lists of the two tools (one native pass)
        candidates: parsed.flatMap((p) => p.candidates),
      });
      // SE-24: merge first, filter after, once, identically for every kind of incremental scope
      const filtered = filterToChanged(merged.findings, scope.changed);
      const rows = await toStorageRowsAsync(filtered.kept, platform.maxItems ?? 50_000);
      const incomplete = rollup.completeness === "incomplete" || rows.truncated;
      if (scope.kind !== "full")
        log(
          "info",
          `Secrets scope ${scope.kind}: ${filtered.dropped} findings outside the changed paths were not kept`,
        );
      return {
        status: rollup.taskStatus === "failed" ? "failed" : "succeeded",
        items: rows.items,
        truncated: rows.truncated,
        incomplete,
        ensemble: {
          rollup,
          toolRuns,
          details: rows.details,
          severityCounts: rows.severityCounts,
          droppedFindings: rows.dropped,
          scope: {
            kind: scope.kind,
            targetsDropped: scope.targetsDropped,
            outOfScopeDropped: filtered.dropped,
          },
          coverage: {
            state: rollup.coverageState,
            coverageGaps: rollup.coverageGaps,
            toolsDegraded: rollup.toolsDegraded,
            tools: toolRuns.map((r) => ({ toolId: r.toolId, status: r.status })),
          },
          runManifestSha256: runManifestSha256({
            ensembleVersion: ENSEMBLE_VERSION,
            tools: toolRuns
              .filter((r) => r.toolVersion !== "unknown")
              .map((r) => ({
                toolId: r.toolId,
                toolVersion: r.toolVersion,
                imageDigest: r.imageDigest,
                configDigest: r.configDigest,
                rulepackDigest: null,
              })),
          }),
          document: null,
          changedPathsStatus: platform.changedPaths?.status ?? null,
        },
      };
    },
  });
}
