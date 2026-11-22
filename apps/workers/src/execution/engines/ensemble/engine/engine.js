import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { rollUpTask } from "@qmentisai/shared";
import { createSyftAdapter } from "../sbom/syft.js";
import { createTrivySbomAdapter } from "../sbom/trivy-sbom.js";
import { collectSbomLiteStreams, createSbomLiteAdapter } from "../sbom/sbom-lite.js";
import { mergeTaskCandidatesAsync } from "../core/merger.js";
import { runToolParseAsync } from "../core/run-parse.js";
import { enrichFindings } from "../evidence/index.js";
import { toStorageRowsAsync } from "../core/storage.js";
import {
  DEFAULT_TOOL_WAIT_MS,
  ENGINE_ID,
  ENSEMBLE_VERSION,
  SBOM_DOCUMENT_MAX_BYTES,
  SBOM_DOCUMENT_TOOL_ID,
} from "./constants.js";
import { runManifestSha256 } from "./run-manifest.js";
import { redactedSbomDocument } from "./sbom-redaction.js";
import { createContainerToolRunner } from "./container-run.js";

/**
 * The tools left out of the retry-class decision of table 5.4 row 7 (owner decision 2026-11-20, option A): the in-process inventory's
 * failure word is permanent and says nothing about the infrastructure, so only the container tools decide whether a failed task retries.
 */
const RETRY_CLASS_EXCLUDES = Object.freeze(["sbom-lite"]);

// The stored copy of the canonical SBOM document is redacted STRING BY STRING (owner decision 2026-11-20, SPEC 17.l); see ./sbom-redaction.js.
export { redactedSbomDocument };

/**
 * The ensemble engine for the SBOM scan type (docs/modules/scan-engines/SPEC.md 6.1, 5.3, 5.4, 6.4, part K core): Syft and Trivy in
 * their sandboxes plus the in-process `sbom-lite` inventory, registered under the catalog id `default` only when the rollout flag
 * is on. It owns everything between "the tree is extracted" and "the result is ready to store": capacity, the runs through the
 * `SandboxRunner`, the strict parse of each output, the classification of every outcome into the fixed statuses and reasons, the
 * merge, the roll-up of table 5.4, the run manifest, the storage rows and the one canonical CycloneDX document. It never throws
 * for a tool-originated problem; only a programming error escapes. Pure of the environment: every dependency is injected, so the
 * Docker-free suite drives it with a `FakeSandboxRuntime`.
 *
 * Released by ENG-L20 (2026-11-20, SPEC 17.n): `treePathExists` (when given, a record whose reported path is not in the extracted tree is
 * dropped by the parse, SE-27; the worker wiring always gives it), the exit-code classification of `classifyToolExit` (137 is
 * `out_of_memory`, a bad platform configuration `config_invalid`, anything else `exit_code`; stderr is read for the word only). Settled for
 * the SBOM scan type: every tool scans the WHOLE tree and `scope.kind` stays `full` (SPEC 5.9: SBOM and SCA are whole-tree by nature;
 * the changed-path list is carried for later scan types, narrowing and explicit targets stay HELD with them), and Trivy's SBOM mode needs
 * no vulnerability database (no database classification here, Part G owns it).
 *
 * @param {{
 *   runner: ReturnType<typeof import("@qmentisai/infra").createSandboxRunner>,
 *   gate: ReturnType<typeof import("@qmentisai/infra").createCapacityGate>,
 *   resolver: ReturnType<typeof import("@qmentisai/infra").createImageResolver>,
 *   rulesDir: string,
 *   toolWaitMs?: number,
 *   now?: () => number,
 *   newId?: () => string,
 *   inventory?: Function,
 *   redactDocument?: typeof redactedSbomDocument,
 *   treePathExists?: (sourceDir: string) => (relativePath: string) => boolean
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
  redactDocument = redactedSbomDocument,
  treePathExists,
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

  /** One container tool: capacity, plan, run, classification (shared with the SCA engine, `container-run.js`). */
  const runContainerTool = createContainerToolRunner({
    runner,
    gate,
    resolver,
    scanType: "sbom",
    rulesDir,
    configDigests,
    toolWaitMs,
    now,
    newId,
  });

  /** Parses one tool's output with the REAL adapter and folds the outcome into the record. */
  async function parseTool(adapter, { record, streams }, taskRef, pathExists) {
    if (streams === null) return { record, candidates: [], stdout: null };
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
      const outcome = await runToolParseAsync(lite, collected.streams, {
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
      // every heavy step below awaits and gives the event loop a turn every few milliseconds, so the lease heartbeat of the handler
      // (a timer on this loop) is never starved by a large result (owner decision 2026-11-20)
      const parsed = [];
      // a record whose path is not in the extracted tree is dropped (SE-27); the in-process inventory walks the tree itself
      const pathExists = treePathExists ? treePathExists(context.sourceDir) : undefined;
      // bounded: one entry per tool (three); each parse below checkpoints per record
      for (const s of settled)
        parsed.push(s.lite ? s.lite : await parseTool(s.adapter, s.ran, taskRef, pathExists));
      // bounded: one record per tool (three)
      const toolRuns = parsed.map((p) => p.record);
      const reason = String(signal.reason?.message);
      const rollup = rollUpTask({
        tools: toolRuns.map((r) => ({ toolId: r.toolId, status: r.status, reason: r.reason })),
        retryClassExcludes: [...RETRY_CLASS_EXCLUDES],
        cancelled: signal.aborted && reason !== "task_deadline",
        deadlineReached: signal.aborted && reason === "task_deadline",
      });
      const merged = await mergeTaskCandidatesAsync({
        taskRef,
        scanType: "sbom",
        // bounded: concatenates the candidate lists of the three tools (one native pass)
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
      // bounded: one entry per tool (three)
      const syft = parsed.find((p) => p.record.toolId === SBOM_DOCUMENT_TOOL_ID);
      let document = null;
      if (
        syft?.stdout &&
        Buffer.byteLength(syft.stdout) <= SBOM_DOCUMENT_MAX_BYTES &&
        ["succeeded", "partial"].includes(syft.record.status)
      ) {
        const stored = await redactDocument(syft.stdout);
        if (stored.ok)
          document = {
            toolId: SBOM_DOCUMENT_TOOL_ID,
            bytes: stored.bytes,
            redacted: stored.redacted,
          };
        else
          log(
            "warn",
            `The SBOM document was not stored (${stored.note}); the scan result is not affected`,
          );
      }
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
