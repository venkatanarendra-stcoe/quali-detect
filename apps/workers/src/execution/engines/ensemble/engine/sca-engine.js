import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { rollUpTask } from "@qmentisai/shared";
import { mergeTaskCandidatesAsync } from "../core/merger.js";
import { runToolParseAsync } from "../core/run-parse.js";
import { enrichFindings } from "../evidence/index.js";
import { toStorageRowsAsync } from "../core/storage.js";
import { createOsvScannerAdapter } from "../sca/osv-scanner.js";
import { createTrivyScaAdapter } from "../sca/trivy-vuln.js";
import { createContainerToolRunner } from "./container-run.js";
import { DEFAULT_TOOL_WAIT_MS, ENGINE_ID, ENSEMBLE_VERSION } from "./constants.js";
import { runManifestSha256 } from "./run-manifest.js";

/**
 * The ensemble engine for the SCA scan type (docs/modules/scan-engines/SPEC.md 5.2, 5.3, 5.4, 5.6.2, 5.7, 5.12, 6.1, part G): Trivy
 * (language ecosystems only) and OSV-Scanner (offline) in their sandboxes, each against the read-only vulnerability database snapshot
 * of the Part F mirror, registered under the catalog id `default` only while the rollout flag is on. Grype is never selected (deferred
 * to v2, the adapter registry refuses it). It owns everything between "the tree is extracted" and "the result is ready to store".
 *
 * The database (SPEC SE-36 to SE-38, D-22): before a tool starts, `dbResolver.resolve(toolId)` gives the ONE verified `active` snapshot
 * or nothing. Nothing (no snapshot, an object that does not match its digest, a failing lookup) makes the tool `unavailable` with the
 * transient reason `db_unavailable` WITHOUT starting a container, never a failure of the scan; a snapshot in any stale tier runs the tool
 * and makes its run `partial` with the warning reason `db_stale` (the result is `incomplete`, so never resolution eligible), never
 * `failed`. Every tool run records the snapshot sha256 and build time (SE-37) and they enter the run manifest (SE-26). SCA is a
 * whole-tree scan by nature (SPEC 5.9): `scope.kind` is `full` and no changed-path filter is applied.
 *
 * It never throws for a tool-originated problem; only a programming error escapes. Pure of the environment: every dependency is
 * injected, so the Docker-free suite drives it with a `FakeSandboxRuntime`.
 *
 * @param {{
 *   runner: { runTool: Function, abortAttempt: Function },
 *   gate: { acquire: Function },
 *   resolver: { resolve: Function },
 *   dbResolver: { resolve: (toolId: string) => Promise<{ state: "ok", dir: string, provenance: { dbSnapshotSha256: string, dbBuiltAt: string }, effect: { toolStatus: string, reason: string | null } } | { state: "missing" }> },
 *   rulesDir: string,
 *   toolWaitMs?: number,
 *   now?: () => number,
 *   newId?: () => string,
 *   treePathExists?: (sourceDir: string) => (relativePath: string) => boolean
 * }} deps `rulesDir` holds the platform tool configuration (`trivy.yaml`, `osv-scanner.toml`), mounted read-only at `/rules`; both files are
 *   read ONCE here (fail fast) to compute the configuration digests of the run manifest.
 */
export function createEnsembleScaEngine({
  runner,
  gate,
  resolver,
  dbResolver,
  rulesDir,
  toolWaitMs = DEFAULT_TOOL_WAIT_MS,
  now = Date.now,
  newId = randomUUID,
  treePathExists,
}) {
  if (typeof rulesDir !== "string" || !path.isAbsolute(rulesDir))
    throw new TypeError("rulesDir must be an absolute path");
  if (!dbResolver || typeof dbResolver.resolve !== "function")
    throw new TypeError("the SCA engine needs a database resolver");
  const adapters = [createTrivyScaAdapter(), createOsvScannerAdapter()];
  const digestOf = (file) =>
    createHash("sha256")
      .update(readFileSync(path.join(rulesDir, file)))
      .digest("hex");
  const configDigests = {
    trivy: digestOf("trivy.yaml"),
    "osv-scanner": digestOf("osv-scanner.toml"),
  };
  const runContainerTool = createContainerToolRunner({
    runner,
    gate,
    resolver,
    scanType: "sca",
    rulesDir,
    configDigests,
    toolWaitMs,
    now,
    newId,
  });
  const version = `ensemble-sca/${ENSEMBLE_VERSION}`;

  /** A tool that could not start for want of a snapshot: recorded, never run (SPEC 5.3: `unavailable` / `db_unavailable`, transient). */
  const noSnapshot = (adapter) => {
    const at = new Date(now()).toISOString();
    return {
      record: {
        id: newId(),
        toolId: adapter.toolId,
        toolVersion: "unknown",
        imageDigest: null,
        configDigest: configDigests[adapter.toolId],
        status: "unavailable",
        reason: "db_unavailable",
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

  /** Resolves the snapshot, runs the tool against it and remembers the staleness effect for the record. */
  async function runTool(adapter, ctx) {
    let db;
    try {
      db = await dbResolver.resolve(adapter.toolId);
    } catch {
      ctx.log("warn", `The vulnerability database of ${adapter.toolId} could not be resolved`);
      return { ran: noSnapshot(adapter), effect: null };
    }
    if (db.state !== "ok") return { ran: noSnapshot(adapter), effect: null };
    const ran = await runContainerTool(adapter, ctx, {
      dbDir: db.dir,
      dbProvenance: {
        dbSnapshotSha256: db.provenance.dbSnapshotSha256,
        dbBuiltAt: db.provenance.dbBuiltAt,
      },
    });
    return { ran, effect: db.effect };
  }

  /** Parses one tool's output with the REAL adapter and folds the outcome and the staleness warning into the record. */
  async function parseTool(adapter, { ran, effect }, taskRef, pathExists) {
    const { record, streams } = ran;
    if (streams === null) return { record, candidates: [] };
    const outcome = await runToolParseAsync(adapter, streams, {
      taskRef,
      toolRunId: record.id,
      toolVersion: record.toolVersion,
      imageDigest: record.imageDigest,
      ...(pathExists ? { pathExists } : {}),
    });
    // a stale database (any tier above fresh) makes a clean run `partial` / `db_stale`; it never changes a failure or another reason
    const stale = effect?.toolStatus === "partial" && outcome.status === "succeeded";
    return {
      record: {
        ...record,
        status: stale ? "partial" : outcome.status,
        reason: stale ? "db_stale" : outcome.reason,
        recordsSeen: outcome.recordsSeen,
        recordsDropped: outcome.recordsDropped,
        findingsMapped: outcome.findingsMapped,
        severityCounts: outcome.severityCounts,
        truncated: outcome.truncated,
      },
      candidates: outcome.candidates,
    };
  }

  return Object.freeze({
    scanType: "sca",
    engineId: ENGINE_ID,
    version,
    idempotent: true,
    /** Tells the scan handler to hand over the trusted platform facts (tenant, deadline, trust, changed paths). */
    needsPlatform: true,
    /**
     * @param {Readonly<Record<string, any>>} context the frozen ScanContext
     * @param {{ signal: AbortSignal, log: (level: string, message: string) => void, emit: Function, platform: { tenantId: string, deadlineEpoch: number, secondsToDeadline: number, fork?: boolean, changedPaths?: object, maxItems?: number } }} hooks
     */
    async runTask(context, { signal, log, platform }) {
      if (!platform?.tenantId) throw new TypeError("the ensemble engine needs the platform facts");
      const taskRef = context.taskId;
      const ctx = { platform, context, signal, log };
      const settled = await Promise.all(
        adapters.map(async (adapter) => ({ adapter, ran: await runTool(adapter, ctx) })),
      );
      // an abort leaves nothing behind: every container of this attempt is killed and removed (SPEC 6.4)
      if (signal.aborted)
        await runner
          .abortAttempt({ taskId: context.taskId, attempt: context.attempt + 1 })
          .catch(() => {});
      const pathExists = treePathExists ? treePathExists(context.sourceDir) : undefined;
      const parsed = [];
      // bounded: one entry per tool (two); each parse below checkpoints per record
      for (const s of settled) parsed.push(await parseTool(s.adapter, s.ran, taskRef, pathExists));
      const toolRuns = parsed.map((p) => p.record);
      const reason = String(signal.reason?.message);
      const rollup = rollUpTask({
        tools: toolRuns.map((r) => ({ toolId: r.toolId, status: r.status, reason: r.reason })),
        cancelled: signal.aborted && reason !== "task_deadline",
        deadlineReached: signal.aborted && reason === "task_deadline",
      });
      const merged = await mergeTaskCandidatesAsync({
        taskRef,
        scanType: "sca",
        // bounded: concatenates the candidate lists of the two tools (one native pass)
        candidates: parsed.flatMap((p) => p.candidates),
      });
      // evidence part J: the provider link to the manifest file that declared the component (no line, SPEC 5.13.3)
      const enriched = await enrichFindings({
        findings: merged.findings,
        sourceDir: context.sourceDir,
        repo: platform.scm ?? null,
        signal,
      });
      const rows = await toStorageRowsAsync(enriched.findings, platform.maxItems ?? 50_000);
      const incomplete = rollup.completeness === "incomplete" || rows.truncated;
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
                dbSnapshotSha256: r.dbSnapshotSha256 ?? null,
                dbBuiltAt: r.dbBuiltAt ?? null,
              })),
          }),
          document: null,
          changedPathsStatus: platform.changedPaths?.status ?? null,
        },
      };
    },
  });
}
