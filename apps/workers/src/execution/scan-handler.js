import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  createExecutionRepository,
  createScanTaskRepository,
  withTransaction,
} from "@qmentisai/db";
import {
  NonRetryableError,
  assertNoCredentials,
  extractTarGz,
  redactCredentialText,
} from "@qmentisai/infra";
import { matchGlob, shouldAbortAttempt } from "@qmentisai/shared";
import { z } from "zod";
import { CONFIG_SCHEMA } from "../pipeline/execution-request.js";
import { ARCHIVE_NAME, CONTROL_CHARS } from "./constants.js";
import { EngineError } from "./engines.js";
import { createTaskLogWriter, resolveLogStore } from "./task-log.js";
import { createMessageProducer } from "./messages.js";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const clean = (value, max) =>
  redactCredentialText(String(value).replace(CONTROL_CHARS, "")).slice(0, max);

/** One normalized item (SPEC §7.4): locator facts only, no finding identity, no secret value. */
const itemSchema = z.object({
  kind: z.enum(["vulnerability", "license", "secret", "code_issue", "component"]),
  ruleId: z.string().max(400).nullish(),
  severity: z.enum(SEVERITIES),
  title: z.string().min(1).max(2000),
  path: z.string().max(4000).nullish(),
  startLine: z.number().int().min(1).nullish(),
  endLine: z.number().int().min(1).nullish(),
  componentPurl: z.string().max(2000).nullish(),
  componentVersion: z.string().max(1000).nullish(),
  data: z.record(z.unknown()).nullish(),
});
const SECRET_KEYS = /^(value|secret|secretValue|token|password|raw|match|plaintext)$/i;

/**
 * Normalizes the items of an engine into rows (untrusted strings: control characters stripped, lengths capped, credential-
 * shaped text redacted). A `secret` item never carries the value: only `data.preview`, at most 4 leading characters.
 * @param {unknown[]} raw @param {number} cap @returns {{ items: object[], truncated: boolean, dropped: number, severityCounts: Record<string, number> }}
 */
export function normalizeItems(raw, cap) {
  const items = [];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let dropped = 0;
  for (const candidate of raw) {
    const parsed = itemSchema.safeParse(candidate);
    if (!parsed.success) {
      dropped += 1;
      continue;
    }
    if (items.length >= cap) return { items, truncated: true, dropped, severityCounts };
    const i = parsed.data;
    let data = {};
    if (i.data) {
      for (const [key, value] of Object.entries(i.data)) {
        if (i.kind === "secret" && SECRET_KEYS.test(key)) continue;
        data[key] = typeof value === "string" ? clean(value, 500) : value;
      }
      // at most the first 4 characters, cut BEFORE any redaction pass (a 4-character prefix cannot hold a credential)
      if (i.kind === "secret" && typeof i.data.preview === "string")
        data.preview = i.data.preview.replace(CONTROL_CHARS, "").slice(0, 4);
      if (Buffer.byteLength(JSON.stringify(data)) > 4000) data = {};
    }
    const startLine = i.startLine ?? null;
    items.push({
      kind: i.kind,
      ruleId: i.ruleId ? clean(i.ruleId, 200) : null,
      severity: i.severity,
      title: clean(i.title, 200),
      path: i.path ? clean(i.path, 1024) : null,
      startLine,
      endLine:
        startLine !== null &&
        i.endLine !== null &&
        i.endLine !== undefined &&
        i.endLine >= startLine
          ? i.endLine
          : null,
      componentPurl: i.componentPurl ? clean(i.componentPurl, 500) : null,
      componentVersion: i.componentVersion ? clean(i.componentVersion, 100) : null,
      data,
    });
    severityCounts[i.severity] += 1;
  }
  return { items, truncated: false, dropped, severityCounts };
}

/** Exclusion predicate of the snapshot (`exclusions.paths`): applied at extraction so excluded paths never reach a scan. */
const exclusionOf = (patterns) => (relativePath) =>
  patterns.some(
    (pattern) =>
      matchGlob(pattern, relativePath) ||
      matchGlob(`${pattern.replace(/\/+$/, "")}/**`, relativePath),
  );

/**
 * The handler of the `scan` and `scan-untrusted` queues (docs/modules/executions/SPEC.md §6.5 step 1, ER-5, ER-6, ER-12 to ER-15).
 * It runs in the SCAN worker, which has NO GitHub or SecretStore settings. It claims the task attempt by compare-and-set,
 * loads everything from the database (the message only names the task), extracts the archive from the store into a private
 * temporary directory (static parsing only, R-8), calls the registered engine adapter with an `AbortSignal` bound to the
 * attempt deadline and the lease, and finishes the attempt exactly once: result + items, attempt close and terminal task
 * status in one transaction, together with the `scan.task.completed` wake-up. A zombie (superseded attempt, lost lease) writes
 * nothing.
 * The engine's `log(level, message)` also goes to the task's execution log (SPEC §17.ac): buffered, redacted and capped by the
 * LogStore, written only while the attempt is held (fenced), and flushed before the attempt is finished.
 * @param {{ db: any, config: any, logger: any, store: any, engines: any, workerId?: string, tmpRoot?: string, logStore?: any }} deps
 */
export function createScanTaskHandler({
  db,
  config,
  logger,
  store,
  engines,
  workerId,
  tmpRoot = os.tmpdir(),
  logStore,
}) {
  const ex = config.execution;
  const id = workerId ?? `scan-${process.pid}-${randomBytes(3).toString("hex")}`;
  const log = logger?.child ? logger.child({ component: "scan-handler" }) : logger;
  const tasks = createScanTaskRepository({ db });
  const executions = createExecutionRepository({ db });
  const producer = createMessageProducer({ db });
  const logs = resolveLogStore({ db, config, logStore });

  async function finish(exec, task, input) {
    return withTransaction(db, async (tx) => {
      const done = await tasks.finishTask(
        { tenantId: exec.tenantId, taskId: task.id, attempt: task.attempt, ...input },
        tx,
      );
      if (!done.finished) return done;
      await producer.taskCompleted(
        tx,
        exec,
        {
          taskId: task.id,
          scanType: task.scanType,
          attempt: task.attempt,
          status: input.status,
          resultId: done.resultId,
        },
        exec.correlationId,
      );
      await producer.taskStatusChanged(
        tx,
        exec,
        {
          taskId: task.id,
          scanType: task.scanType,
          status: input.status,
          rev: done.task.statusRev,
        },
        exec.correlationId,
      );
      return done;
    });
  }

  return async function handle(envelope, context) {
    if (envelope.type !== "scan.task.requested") return;
    const tenantId = envelope.tenantId;
    const { executionId, taskId, attempt } = envelope.payload;
    // the ownership check proved the chain; every read below is again by (tenant, id)
    const task = await tasks.claimTask({
      tenantId,
      executionId,
      taskId,
      attempt,
      workerId: id,
      leaseTtlSeconds: ex.leaseTtlSeconds,
    });
    if (!task) {
      context?.log?.info?.(
        { taskId, attempt },
        "Task attempt not claimable (finished, claimed or superseded); acknowledged",
      );
      return;
    }
    const exec = await executions.findExecution({ tenantId, executionId });
    if (!exec)
      throw new NonRetryableError("The execution does not exist.", {
        reason: "execution-not-found",
      });
    const abort = new AbortController();
    let leaseLost = false;
    const beat = setInterval(() => {
      tasks
        .renewTaskLease({
          tenantId,
          taskId,
          attempt,
          workerId: id,
          leaseTtlSeconds: ex.leaseTtlSeconds,
        })
        .then(({ renewed }) => {
          if (renewed) return;
          leaseLost = true;
          abort.abort(new Error("lease_lost"));
        })
        .catch(() => {});
    }, ex.heartbeatSeconds * 1000);
    const deadline = setTimeout(
      () => abort.abort(new Error("task_deadline")),
      Math.max(1, task.secondsToDeadline * 1000),
    );
    // Safe point (ER-14): the cancel request is read from the database, never from a message. `immediate` aborts this attempt
    // at once, `graceful` when the grace period is over; the abort is cooperative (the adapter's AbortSignal) and the partial
    // result is kept. Polled faster than the heartbeat so a cancel is honoured promptly.
    const cancelPoll = setInterval(
      () => {
        executions
          .readLifecycle({ tenantId, executionId })
          .then((lifecycle) => {
            if (
              lifecycle?.cancelRequestedAt &&
              shouldAbortAttempt({
                mode: lifecycle.cancelMode,
                requested: true,
                graceSecondsLeft: lifecycle.cancelGraceSecondsLeft,
              })
            )
              abort.abort(new Error("user_cancelled"));
          })
          .catch(() => {});
      },
      Math.min(ex.heartbeatSeconds * 1000, 1000),
    );
    const taskLog = createTaskLogWriter({
      logStore: logs,
      ref: { tenantId, executionId, taskId, attempt, workerId: id },
      logger: log,
    });
    taskLog.log(
      "info",
      `scan task started: ${task.scanType} with engine ${task.engineId} (attempt ${attempt + 1} of ${task.maxAttempts})`,
    );
    const workDir = await mkdtemp(path.join(tmpRoot, "qm-scan-"));
    const collected = [];
    let outcome;
    try {
      const adapter = engines.get(task.scanType, task.engineId);
      if (!adapter) {
        outcome = {
          status: "failed",
          reason: "engine_unavailable",
          errorClass: "permanent",
          errorCode: "engine_unavailable",
        };
      } else {
        const version = await db.pipelineConfigVersion.findFirst({
          where: { id: exec.configVersionId, tenantId, pipelineId: exec.pipelineId },
          select: { config: true },
        });
        const parsed = CONFIG_SCHEMA.safeParse(version?.config);
        if (!parsed.success) throw new EngineError("config_invalid", "permanent");
        const ref = { tenantId, executionId, name: ARCHIVE_NAME };
        if (!exec.archiveSha256 || (await store.sha256(ref)) !== exec.archiveSha256)
          throw new EngineError("archive_integrity", "permanent");
        const sourceDir = path.join(workDir, "src");
        await extractTarGz(store.open(ref), {
          destDir: sourceDir,
          limits: ex.archiveLimits,
          exclude: exclusionOf(parsed.data.exclusions?.paths ?? []),
        });
        // The ScanContext (ER-5): ids, scan type, engine, thresholds, deadline and the extracted tree. No token, no SecretStore
        // handle, no URL with credentials: the same guard that protects messages protects the context.
        const context = Object.freeze({
          executionId,
          taskId,
          attempt,
          scanType: task.scanType,
          engine: Object.freeze({
            id: task.engineId,
            profile: task.engineProfile,
            version: adapter.version,
          }),
          severityThreshold: task.severityThreshold,
          trust: exec.trust,
          deadlineSeconds: task.secondsToDeadline,
          sourceDir,
        });
        assertNoCredentials(context, "scan context");
        const run = await adapter.runTask(context, {
          signal: abort.signal,
          log: (level, message) => {
            log?.[["debug", "info", "warn", "error"].includes(level) ? level : "info"]?.(
              { taskId, attempt },
              redactCredentialText(clean(message, 500)),
            );
            taskLog.log(level, message);
          },
          emit: (item) => {
            if (collected.length < ex.maxResultItemsPerTask + 1) collected.push(item);
          },
        });
        if (abort.signal.aborted) throw abort.signal.reason;
        const all = [...collected, ...(run?.items ?? [])];
        const normalized = normalizeItems(all, ex.maxResultItemsPerTask);
        const result = {
          engineId: task.engineId,
          engineVersion: adapter.version,
          // an adapter may report its own cap (`truncated`) or a partial inventory (`incomplete`, e.g. a malformed file): both make the
          // result incomplete, which keeps the execution from being resolution eligible (SPEC §17.ab)
          completeness:
            normalized.truncated || run?.truncated === true || run?.incomplete === true
              ? "incomplete"
              : "complete",
          truncated: normalized.truncated || run?.truncated === true,
          severityCounts: normalized.severityCounts,
          items: normalized.items,
        };
        outcome =
          run?.status === "failed"
            ? {
                status: "failed",
                reason: "engine_failed",
                errorClass: "permanent",
                errorCode: "engine_failed",
              }
            : { status: "succeeded", result };
      }
    } catch (error) {
      const reasonText = abort.signal.aborted
        ? String(abort.signal.reason?.message)
        : String(error?.message ?? error);
      if (leaseLost || reasonText === "lease_lost") {
        outcome = null; // zombie: not ours any more, write nothing
      } else if (reasonText === "user_cancelled") {
        const normalized = normalizeItems(collected, ex.maxResultItemsPerTask);
        outcome = {
          status: "cancelled",
          reason: "user_cancelled",
          errorClass: "cancelled",
          errorCode: "user_cancelled",
          result: {
            engineId: task.engineId,
            engineVersion: engines.get(task.scanType, task.engineId)?.version ?? "unknown",
            completeness: "incomplete",
            truncated: normalized.truncated,
            severityCounts: normalized.severityCounts,
            items: normalized.items,
          },
        };
      } else if (reasonText === "task_deadline") {
        const normalized = normalizeItems(collected, ex.maxResultItemsPerTask);
        outcome = {
          status: "timed_out",
          // the abort came from the EXECUTION's deadline when that was the nearer limit (the driver then ends the execution timed_out)
          reason: task.limitedByExecution ? "execution_deadline" : "task_deadline",
          errorClass: "timeout",
          errorCode: task.limitedByExecution ? "execution_deadline" : "task_deadline",
          result: {
            engineId: task.engineId,
            engineVersion: engines.get(task.scanType, task.engineId)?.version ?? "unknown",
            completeness: "incomplete",
            truncated: normalized.truncated,
            severityCounts: normalized.severityCounts,
            items: normalized.items,
          },
        };
      } else if (error?.name === "ArchiveError" || error instanceof EngineError) {
        const permanent = error.errorClass !== "transient";
        outcome = {
          status: "failed",
          reason: permanent ? (error.code ?? "engine_failed") : "engine_error",
          errorClass: permanent ? "permanent" : "transient",
          errorCode: error.code ?? "engine_failed",
          retryable: !permanent,
        };
      } else {
        // an unexpected failure of the adapter or the platform is transient: retried while attempts remain
        outcome = {
          status: "failed",
          reason: "engine_error",
          errorClass: "transient",
          errorCode: "engine_error",
          retryable: true,
        };
        log?.warn?.(
          { taskId, attempt, errorName: error?.name },
          "Unexpected failure while running a scan task",
        );
      }
    } finally {
      clearInterval(beat);
      clearInterval(cancelPoll);
      clearTimeout(deadline);
      await rm(workDir, { recursive: true, force: true }).catch(() => {});
    }
    if (outcome)
      taskLog.log(
        outcome.status === "succeeded" ? "info" : "warn",
        `scan task ${outcome.retryable ? "will be retried after a transient failure" : outcome.status}${outcome.reason ? `: ${outcome.reason}` : ""}`,
      );
    // flushed BEFORE the attempt is finished: a finished task is no longer running, so the write fence would refuse the lines
    await taskLog.close();
    if (!outcome) return;
    if (outcome.retryable) {
      const next = await withTransaction(db, async (tx) => {
        const requeued = await tasks.requeueTask(
          { tenantId, taskId, attempt, errorClass: "transient", errorCode: outcome.errorCode },
          tx,
        );
        if (!requeued) return null;
        await producer.taskRequested(
          tx,
          exec,
          { id: taskId, scanType: task.scanType, attempt: requeued.attempt },
          { trust: exec.trust, deadlineAt: exec.deadlineAt },
          exec.correlationId,
        );
        await producer.taskStatusChanged(
          tx,
          exec,
          { taskId, scanType: task.scanType, status: "queued", rev: requeued.task.statusRev },
          exec.correlationId,
        );
        return requeued;
      });
      if (next) return; // a new attempt is queued; the aggregator waits for it
    }
    const { retryable: _retryable, ...input } = outcome;
    const done = await finish(exec, task, input);
    if (!done.finished)
      context?.log?.info?.({ taskId, attempt }, "The attempt was superseded; nothing was written");
  };
}
