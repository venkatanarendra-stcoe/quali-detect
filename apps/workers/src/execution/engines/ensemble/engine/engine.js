import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { SandboxError, resolveRunSpecImage } from "@qmentisai/infra";
import { rollUpTask } from "@qmentisai/shared";
import { createSyftAdapter } from "../sbom/syft.js";
import { createTrivySbomAdapter } from "../sbom/trivy-sbom.js";
import { collectSbomLiteStreams, createSbomLiteAdapter } from "../sbom/sbom-lite.js";
import { mergeTaskCandidates } from "../core/merger.js";
import { runToolParse } from "../core/run-parse.js";
import { toStorageRows } from "../core/storage.js";
import {
  DEFAULT_TOOL_WAIT_MS,
  ENGINE_ID,
  ENSEMBLE_VERSION,
  SBOM_DOCUMENT_MAX_BYTES,
  SBOM_DOCUMENT_TOOL_ID,
} from "./constants.js";
import { runManifestSha256 } from "./run-manifest.js";

/**
 * The ensemble engine for the SBOM scan type (docs/modules/scan-engines/SPEC.md 6.1, 5.3, 5.4, 6.4, part K core): Syft and Trivy in
 * their sandboxes plus the in-process `sbom-lite` inventory, registered under the catalog id `default` only when the rollout flag
 * is on. It owns everything between "the tree is extracted" and "the result is ready to store": capacity, the runs through the
 * `SandboxRunner`, the strict parse of each output, the classification of every outcome into the fixed statuses and reasons, the
 * merge, the roll-up of table 5.4, the run manifest, the storage rows and the one canonical CycloneDX document. It never throws
 * for a tool-originated problem; only a programming error escapes. Pure of the environment: every dependency is injected, so the
 * Docker-free suite drives it with a `FakeSandboxRuntime`.
 *
 * HELD (blocked on ENG-L20, SPEC 17.i): no `pathExists` filter is passed to the parse (so no record is dropped for a path form),
 * the changed-path list is not used to narrow anything (every tool scans the whole tree, `scope.kind = "full"`), and the adapters
 * are used exactly as Part E wrote them.
 *
 * @param {{
 *   runner: ReturnType<typeof import("@qmentisai/infra").createSandboxRunner>,
 *   gate: ReturnType<typeof import("@qmentisai/infra").createCapacityGate>,
 *   resolver: ReturnType<typeof import("@qmentisai/infra").createImageResolver>,
 *   rulesDir: string,
 *   toolWaitMs?: number,
 *   now?: () => number,
 *   newId?: () => string,
 *   inventory?: Function
 * }} deps `rulesDir` holds the platform tool configuration (`syft.yaml`, `trivy.yaml`), mounted read-only at `/rules`; its files
 *   are read ONCE here (fail fast) to compute the configuration digests of the run manifest.
 */
export function createEnsembleSbomEngine({
  runner,
  gate,
  resolver,
  rulesDir,
  toolWaitMs = DEFAULT_TOOL_WAIT_MS,
  now = Date.now,
  newId = randomUUID,
  inventory,
}) {
  if (typeof rulesDir !== "string" || !path.isAbsolute(rulesDir))
    throw new TypeError("rulesDir must be an absolute path");
  const containerAdapters = [createSyftAdapter(), createTrivySbomAdapter()];
  const lite = createSbomLiteAdapter();
  const configDigest = (file) =>
    createHash("sha256")
      .update(readFileSync(path.join(rulesDir, file)))
      .digest("hex");
  const configDigests = { syft: configDigest("syft.yaml"), trivy: configDigest("trivy.yaml") };
  const liteDigest = createHash("sha256").update("sbom-lite:in-process").digest("hex");
  const version = `ensemble-sbom/${ENSEMBLE_VERSION}`;

  /** The timing columns of a tool run: ISO instants and the duration (never negative). */
  const stamp = (startedMs) => {
    const end = Math.max(now(), startedMs);
    return {
      startedAt: new Date(startedMs).toISOString(),
      finishedAt: new Date(end).toISOString(),
      durationMs: end - startedMs,
    };
  };
  /** An exit code the database accepts (0 to 255), or null. */
  const exitOf = (code) => (Number.isInteger(code) && code >= 0 && code <= 255 ? code : null);

  /** One container tool: capacity, plan, run, classification. Returns the tool run record and, when there is output, its streams. */
  async function runContainerTool(adapter, ctx) {
    const { platform, context, signal } = ctx;
    const startedAt = now();
    const record = {
      id: newId(),
      toolId: adapter.toolId,
      toolVersion: "unknown",
      imageDigest: null,
      configDigest: configDigests[adapter.toolId],
      status: "failed",
      reason: "sandbox_error",
      exitCode: null,
      scope: { kind: "full", paths: 0 },
      limits: {},
      capacityWaitMs: 0,
    };
    const finish = (over, streams = null) => ({
      record: { ...record, ...over, ...stamp(startedAt) },
      streams,
    });
    const abortReason = () =>
      signal.aborted && String(signal.reason?.message) === "task_deadline"
        ? "deadline"
        : "cancelled";
    let spec;
    try {
      const plan = adapter.plan({
        tenantId: platform.tenantId,
        executionId: context.executionId,
        taskId: context.taskId,
        // the container's attempt number is 1-based (RunSpec labels.attempt >= 1); the task's attempt column is 0-based
        attempt: context.attempt + 1,
        deadlineEpoch: platform.deadlineEpoch,
        secondsToDeadline: platform.secondsToDeadline,
        archiveDir: context.sourceDir,
        rulesDir,
      });
      spec = resolveRunSpecImage(
        {
          toolId: plan.toolId,
          imageKey: plan.imageKey,
          argv: plan.argv,
          mounts: plan.mounts,
          env: plan.env,
          limits: plan.limits,
          labels: plan.labels,
        },
        resolver,
        { scanType: "sbom" },
      );
      const entry = resolver.resolve(plan.imageKey, { scanType: "sbom" });
      record.toolVersion = entry.version;
      record.imageDigest = spec.image.slice(spec.image.indexOf("@") + 1);
      record.limits = { ...plan.limits };
    } catch (error) {
      if (
        error instanceof SandboxError &&
        ["image_unavailable", "tool_deferred"].includes(error.code)
      )
        return finish({ status: "unavailable", reason: "image_unavailable" });
      return finish({ status: "failed", reason: "sandbox_error" });
    }
    const waitStarted = now();
    let release;
    try {
      release = await gate.acquire(
        { tenantId: platform.tenantId, taskId: context.taskId, fork: platform.fork === true },
        { timeoutMs: toolWaitMs, signal },
      );
    } catch {
      const capacityWaitMs = now() - waitStarted;
      return signal.aborted
        ? finish({ status: "cancelled", reason: abortReason(), capacityWaitMs })
        : finish({ status: "unavailable", reason: "capacity", capacityWaitMs });
    }
    record.capacityWaitMs = now() - waitStarted;
    let result;
    try {
      result = await runner.runTool(spec, { signal });
    } catch (error) {
      release();
      if (error instanceof SandboxError && error.code === "image_unavailable")
        return finish({ status: "unavailable", reason: "image_unavailable" });
      return signal.aborted
        ? finish({ status: "cancelled", reason: abortReason() })
        : finish({ status: "failed", reason: "sandbox_error" });
    }
    release();
    const common = { exitCode: exitOf(result.exitCode) };
    if (result.status === "timed_out" || result.timedOut)
      return finish({ ...common, status: "timed_out", reason: "timeout" });
    if (result.status === "aborted" || result.aborted)
      return finish({ ...common, status: "cancelled", reason: abortReason() });
    if (result.status === "output_limit")
      return finish({ ...common, status: "failed", reason: "output_too_large" });
    if (result.status === "runtime_error")
      return finish({ ...common, status: "failed", reason: "sandbox_error" });
    return finish(
      { ...common, status: "succeeded", reason: null },
      {
        stdout: result.stdout,
        exitCode: result.exitCode,
        truncated: result.stdoutTruncated === true,
      },
    );
  }

  /** Parses one tool's output with the REAL adapter and folds the outcome into the record. */
  function parseTool(adapter, { record, streams }, taskRef) {
    if (streams === null) return { record, candidates: [], stdout: null };
    const outcome = runToolParse(adapter, streams, {
      taskRef,
      toolRunId: record.id,
      toolVersion: record.toolVersion,
      imageDigest: record.imageDigest,
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
      candidates: outcome.candidates,
      stdout: outcome.status === "failed" ? null : streams.stdout,
    };
  }

  /** The in-process legacy inventory as one more tool (no image, no container, no capacity). */
  async function runLite(ctx, taskRef) {
    const { context, signal, log } = ctx;
    const startedAt = now();
    const base = {
      id: newId(),
      toolId: "sbom-lite",
      toolVersion: "inventory-1",
      imageDigest: null,
      configDigest: liteDigest,
      exitCode: null,
      scope: { kind: "full", paths: 0 },
      limits: {},
      capacityWaitMs: 0,
    };
    const finished = (over) => ({ ...base, ...over, ...stamp(startedAt) });
    try {
      const collected = await collectSbomLiteStreams(context.sourceDir, {
        signal,
        log,
        ...(inventory ? { inventory } : {}),
      });
      if (signal.aborted)
        return {
          record: finished({
            status: "cancelled",
            reason: String(signal.reason?.message) === "task_deadline" ? "deadline" : "cancelled",
          }),
          candidates: [],
          stdout: null,
        };
      const outcome = runToolParse(lite, collected.streams, {
        taskRef,
        toolRunId: base.id,
        toolVersion: base.toolVersion,
        imageDigest: null,
      });
      // a truncated or incomplete inventory is a usable, incomplete result (legacy semantics), never a failure
      const limited =
        outcome.status === "succeeded" && (collected.truncated || collected.incomplete);
      return {
        record: finished({
          status: limited ? "partial" : outcome.status,
          reason: limited
            ? collected.truncated
              ? "output_too_large"
              : "output_invalid"
            : outcome.reason,
          recordsSeen: outcome.recordsSeen,
          recordsDropped: outcome.recordsDropped,
          findingsMapped: outcome.findingsMapped,
          severityCounts: outcome.severityCounts,
          truncated: outcome.truncated || collected.truncated === true,
        }),
        candidates: outcome.candidates,
        stdout: null,
      };
    } catch {
      return {
        record: finished({ status: "failed", reason: "output_invalid" }),
        candidates: [],
        stdout: null,
      };
    }
  }

  return Object.freeze({
    scanType: "sbom",
    engineId: ENGINE_ID,
    version,
    idempotent: true,
    /** Tells the scan handler to hand over the trusted platform facts (tenant, deadline, trust, changed paths). */
    needsPlatform: true,
    /**
     * @param {Readonly<Record<string, any>>} context the frozen ScanContext
     * @param {{ signal: AbortSignal, log: (level: string, message: string) => void, emit: Function, platform: { tenantId: string, deadlineEpoch: number, secondsToDeadline: number, fork?: boolean, changedPaths?: object } }} hooks
     */
    async runTask(context, { signal, log, platform }) {
      if (!platform?.tenantId) throw new TypeError("the ensemble engine needs the platform facts");
      const taskRef = context.taskId;
      const ctx = { platform, context, signal, log };
      const settled = await Promise.all([
        ...containerAdapters.map(async (adapter) => ({
          adapter,
          ran: await runContainerTool(adapter, ctx),
        })),
        runLite(ctx, taskRef).then((r) => ({ adapter: lite, ran: null, lite: r })),
      ]);
      // an abort leaves nothing behind: every container of this attempt is killed and removed (SPEC 6.4)
      if (signal.aborted)
        await runner
          .abortAttempt({ taskId: context.taskId, attempt: context.attempt + 1 })
          .catch(() => {});
      const parsed = settled.map((s) => (s.lite ? s.lite : parseTool(s.adapter, s.ran, taskRef)));
      const toolRuns = parsed.map((p) => p.record);
      const reason = String(signal.reason?.message);
      const rollup = rollUpTask({
        tools: toolRuns.map((r) => ({ toolId: r.toolId, status: r.status, reason: r.reason })),
        cancelled: signal.aborted && reason !== "task_deadline",
        deadlineReached: signal.aborted && reason === "task_deadline",
      });
      const merged = mergeTaskCandidates({
        taskRef,
        scanType: "sbom",
        candidates: parsed.flatMap((p) => p.candidates),
      });
      const rows = toStorageRows(merged.findings, platform.maxItems ?? 50_000);
      const syft = parsed.find((p) => p.record.toolId === SBOM_DOCUMENT_TOOL_ID);
      const document =
        syft?.stdout &&
        Buffer.byteLength(syft.stdout) <= SBOM_DOCUMENT_MAX_BYTES &&
        ["succeeded", "partial"].includes(syft.record.status)
          ? { toolId: SBOM_DOCUMENT_TOOL_ID, bytes: Buffer.from(syft.stdout, "utf8") }
          : null;
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
              })),
          }),
          document,
          changedPathsStatus: platform.changedPaths?.status ?? null,
        },
      };
    },
  });
}
