import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { EVIDENCE_CAPPED_NOTE_CODE, rollUpTask } from "@qmentisai/shared";
import { mergeTaskCandidatesAsync } from "../core/merger.js";
import { runToolParseAsync } from "../core/run-parse.js";
import { toStorageRowsAsync } from "../core/storage.js";
import { createBanditAdapter } from "../sast/bandit.js";
import { applicability, walkSourceTree } from "../sast/languages.js";
import { createOpengrepAdapter } from "../sast/opengrep.js";
import { loadRulePack } from "../sast/rule-pack.js";
import { dropVendored, filterToChanged, planScope, scopedInventory } from "../sast/scope.js";
import { createContainerToolRunner } from "./container-run.js";
import { DEFAULT_TOOL_WAIT_MS, ENGINE_ID, ENSEMBLE_VERSION } from "./constants.js";
import { enrichFindings, evidenceCoverageOf } from "../evidence/index.js";
import { runManifestSha256 } from "./run-manifest.js";

/**
 * The ensemble engine for the SAST scan type (docs/modules/scan-engines/SPEC.md 5.2, 5.4 rows 3 and 4, 5.5, 5.6.3, 5.7, 5.9, 6.1, part H):
 * Opengrep with the platform-owned rule pack and Bandit in their sandboxes, registered under the catalog id `default` only while the
 * rollout flag is on. gosec is HELD (SPEC phase 4b) and is never selected. It owns everything between "the tree is extracted" and "the
 * result is ready to store".
 *
 * Applicability (OQ-17 rows 3 and 4, owner decision D-24 (c)): the tree is walked once (bounded, by file NAME, SE-7); a tool whose
 * languages have no file is recorded `skipped` / `no_applicable_files` and never started; a tree with no source file of any known language
 * is "nothing to scan" (complete, zero findings, row 3); a tree with source files and no applicable tool is a language gap (row 4,
 * `incomplete`); a mixed tree names the languages no tool covers in the coverage statement and the result is `incomplete` (never resolution
 * eligible, because code that was not analysed cannot be called clean).
 *
 * Scope (SE-22 to SE-24, SE-27; scope.js): the changed-path list of an incremental scan narrows a tool to explicit file targets
 * (`targets`), or the tool runs over the whole tree and the findings are filtered (`full_filtered`); the same filter is applied once to the
 * MERGED findings in both kinds. Anything else is a full run.
 *
 * The rule pack is loaded and checked ONCE here (a pack with a problem stops the engine: it never scans with a partly valid pack) and its
 * digest enters the run manifest. It never throws for a tool-originated problem; only a programming error escapes. Pure of the
 * environment: every dependency is injected, so the Docker-free suite drives it with a `FakeSandboxRuntime`.
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
 *   walkTree?: typeof walkSourceTree
 * }} deps `rulesDir` holds the platform rule pack (`qm-sast/`) and tool configuration (`bandit.yaml`, `empty.ini`), mounted read-only at `/rules`; all are read ONCE here (fail fast)
 */
export function createEnsembleSastEngine({
  runner,
  gate,
  resolver,
  rulesDir,
  toolWaitMs = DEFAULT_TOOL_WAIT_MS,
  now = Date.now,
  newId = randomUUID,
  treePathExists,
  walkTree = walkSourceTree,
}) {
  if (typeof rulesDir !== "string" || !path.isAbsolute(rulesDir))
    throw new TypeError("rulesDir must be an absolute path");
  const rulePack = loadRulePack(rulesDir);
  const adapters = [createOpengrepAdapter(), createBanditAdapter()];
  const banditConfigDigest = createHash("sha256")
    .update(readFileSync(path.join(rulesDir, "bandit.yaml")))
    .update("\0")
    .update(readFileSync(path.join(rulesDir, "empty.ini")))
    .digest("hex");
  const configDigests = { opengrep: rulePack.digest, bandit: banditConfigDigest };
  const runContainerTool = createContainerToolRunner({
    runner,
    gate,
    resolver,
    scanType: "sast",
    rulesDir,
    configDigests,
    toolWaitMs,
    now,
    newId,
  });
  const version = `ensemble-sast/${ENSEMBLE_VERSION}`;

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
  async function parseTool(adapter, ran, taskRef, pathExists, scope) {
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
      // every candidate states how it was scoped (SPEC 7.2 `scope`)
      candidates: outcome.candidates.map((c) => ({
        ...c,
        scope: { kind: scope.kind, inScope: true },
      })),
    };
  }

  return Object.freeze({
    scanType: "sast",
    engineId: ENGINE_ID,
    version,
    idempotent: true,
    /** Tells the scan handler to hand over the trusted platform facts (tenant, deadline, trust, changed paths). */
    needsPlatform: true,
    /**
     * @param {Readonly<Record<string, any>>} context the frozen ScanContext
     * @param {{ signal: AbortSignal, log: (level: string, message: string) => void, emit: Function, platform: { tenantId: string, deadlineEpoch: number, secondsToDeadline: number, fork?: boolean, changedPaths?: { status: string, paths: string[] }, maxItems?: number } }} hooks
     */
    async runTask(context, { signal, log, platform }) {
      if (!platform?.tenantId) throw new TypeError("the ensemble engine needs the platform facts");
      const taskRef = context.taskId;
      const ctx = { platform, context, signal, log };
      const inventory = await walkTree(context.sourceDir);
      const scope = planScope(platform.changedPaths, inventory);
      const app = applicability(scopedInventory(inventory, scope.changed));
      const settled = await Promise.all(
        adapters.map(async (adapter) => {
          if (!app.applicable[adapter.toolId]) return { adapter, ran: skipped(adapter) };
          const targets = scope.kind === "targets" ? scope.targets[adapter.toolId] : null;
          if (targets !== null && targets.length === 0) return { adapter, ran: skipped(adapter) };
          const toolScope = {
            kind: scope.kind,
            paths: targets !== null ? targets.length : (scope.changed?.size ?? 0),
          };
          const ran = await runContainerTool(adapter, ctx, {
            ...(targets !== null ? { targets } : {}),
            scope: toolScope,
          });
          return { adapter, ran };
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
        parsed.push(await parseTool(s.adapter, s.ran, taskRef, pathExists, scope));
      const toolRuns = parsed.map((p) => p.record);
      const reason = String(signal.reason?.message);
      const rollup = rollUpTask({
        tools: toolRuns.map((r) => ({ toolId: r.toolId, status: r.status, reason: r.reason })),
        cancelled: signal.aborted && reason !== "task_deadline",
        deadlineReached: signal.aborted && reason === "task_deadline",
        relevantFilesExist: app.relevantFilesExist,
        coverageGaps: app.gaps,
      });
      const merged = await mergeTaskCandidatesAsync({
        taskRef,
        scanType: "sast",
        // bounded: concatenates the candidate lists of the two tools (one native pass)
        candidates: parsed.flatMap((p) => p.candidates),
      });
      // SE-24: merge first, filter after, once, identically for every kind of incremental scope
      const filtered = filterToChanged(dropVendored(merged.findings).kept, scope.changed);
      // evidence part J: the provider link and the enclosing block (extractor image) or the line window, for the highest-severity findings
      const enriched = await enrichFindings({
        findings: filtered.kept,
        sourceDir: context.sourceDir,
        repo: platform.scm ?? null,
        extractor: { deps: { runner, gate, resolver }, ctx: { platform, context, signal } },
        signal,
      });
      log(
        "info",
        `SAST evidence: ${enriched.summary.blocks} blocks, ${enriched.summary.windows} windows, ${enriched.summary.capped} beyond the cap, extractor ${enriched.summary.extractor}, window reasons ${JSON.stringify(enriched.summary.fallbacks)}`,
      );
      const evidenceCoverage = evidenceCoverageOf(enriched.summary);
      const rows = await toStorageRowsAsync(enriched.findings, platform.maxItems ?? 50_000);
      // a mixed tree: the languages no tool covers are named and the result is not complete
      const gapped = [5, 6].includes(rollup.matchedRow) && app.gaps.length > 0;
      const incomplete = rollup.completeness === "incomplete" || rows.truncated || gapped;
      if (scope.kind !== "full")
        log(
          "info",
          `SAST scope ${scope.kind}: ${filtered.dropped} findings outside the changed paths were not kept`,
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
            state: gapped ? "language_gap" : rollup.coverageState,
            coverageGaps: gapped ? app.gaps : rollup.coverageGaps,
            toolsDegraded: rollup.toolsDegraded,
            tools: toolRuns.map((r) => ({ toolId: r.toolId, status: r.status })),
            ...(enriched.summary.capped > 0 ? { notes: [EVIDENCE_CAPPED_NOTE_CODE] } : {}),
            // how often the block extractor fell back to the line window, and why (SPEC 17.ac): counts and fixed words only
            ...(evidenceCoverage ? { evidence: evidenceCoverage } : {}),
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
                rulepackDigest: r.toolId === "opengrep" ? rulePack.digest : null,
              })),
          }),
          document: null,
          changedPathsStatus: platform.changedPaths?.status ?? null,
        },
      };
    },
  });
}
