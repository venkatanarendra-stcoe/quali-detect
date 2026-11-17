import { randomBytes } from "node:crypto";
import {
  LeaseLostError,
  createEntitlementRepository,
  createExecutionCancellation,
  createEntitlementService,
  createExecutionRepository,
  createOrchestratorMarkerRepository,
  createScanDecisionRepository,
  createScanTaskRepository,
  withTransaction,
} from "@qmentisai/db";
import {
  ArchiveError,
  ArtifactTooLargeError,
  GitHubApiError,
  TransientError,
  inspectTarGz,
} from "@qmentisai/infra";
import {
  NO_APPLICABLE_SCANS_REASON,
  SCAN_TASK_ORDER,
  SCAN_TASK_UNSUPPORTED_REASON,
  aggregateTaskOutcome,
  cancelWaitDecision,
  isResolutionEligible,
} from "@qmentisai/shared";
import { CONFIG_SCHEMA, UUID } from "../pipeline/execution-request.js";
import { auditSystem } from "../scm/audit.js";
import {
  ARCHIVE_NAME,
  AUDIT,
  AUDIT_BY_STATUS,
  DEFAULT_DEADLINE_SECONDS,
  EXECUTION_TIMEOUT_CAP_SECONDS,
  PLATFORM_PREPARE_FAILURES,
} from "./constants.js";
import { decideScans } from "./decision/index.js";
import { enabledScanTypes, evaluateGates } from "./gates.js";
import { createMessageProducer } from "./messages.js";
import { resolveLogStore } from "./task-log.js";

/** A prepare step failed with a stable code (becomes `prepare_failed:<code>`). */
class PrepareFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
/** A cancel request was seen at a safe point of the preparation (SPEC ER-14, ER-18). */
class CancelRequested extends Error {}
/** Every enabled scan type has no registered engine: nothing can run (SPEC §17.ab); the execution fails before any fetch. */
class NoEngineRegistered extends Error {}
/** The archive recorded by a previous holder is missing or does not match: a half-done side effect (ER-29). */
class WorkerLost extends Error {}

const sleepFor = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** The longest summary kept in the `decision_completed` event (the full text lives in the decision record). */
const EVENT_SUMMARY_MAX = 500;

/**
 * The bounded details of the `decision_completed` event (SPEC scan-decisioning 7.3): type names, statuses, counts and the short
 * model summary. No prompt, no file contents, no path, no credential.
 */
const decisionEventDetails = (decision) => ({
  floor: decision.floor.map((f) => f.scanType),
  added: decision.agent.additions.map((a) => a.scanType),
  final: decision.finalTypes,
  agentStatus: decision.agent.status,
  provider: decision.agent.provider,
  model: decision.agent.model,
  summary: decision.agent.summary ? decision.agent.summary.slice(0, EVENT_SUMMARY_MAX) : null,
  diffStatus: decision.diff.status,
  changedTotal: decision.diff.changedTotal,
});

/** One execution-log line about the decision (types and status only). */
const decisionLine = (decision, enabled) =>
  `scan decision: ${decision.finalTypes.length > 0 ? decision.finalTypes.join(", ") : "no scan"} of ${enabled.length} enabled type(s)${
    decision.agent ? ` (assistant: ${decision.agent.status})` : " (decision reused)"
  }`;

/** The payload of `pipeline.execution.completed`, built from the final execution row. */
const completedPayload = (final, { status, reason, resolutionEligible, tasks }) => ({
  executionId: final.id,
  pipelineId: final.pipelineId,
  repositoryId: final.repositoryId,
  workspaceId: final.workspaceId,
  status,
  statusReason: reason ?? null,
  scanKind: final.scanKind,
  trust: final.trust,
  refType: final.refType,
  refName: final.refName,
  commitSha: final.commitSha,
  pullRequestNumber: final.pullRequestNumber,
  configVersion: final.configVersion,
  configHash: final.configHash,
  startedAt: final.startedAt ? final.startedAt.toISOString() : null,
  finishedAt: final.finishedAt.toISOString(),
  cancelRequested: Boolean(final.cancelRequestedAt),
  resolutionEligible,
  tasks,
});

/**
 * The execution orchestrator of the pipeline worker (docs/modules/executions/SPEC.md part C, §6): first-enable stale sweep,
 * claim with re-validation, lease and heartbeat, the fetch step, task creation and dispatch, aggregation, the single
 * `pipeline.execution.completed` event, lease reclaim with resume-or-`worker_lost`, and the wake-up handler. It is OFF unless
 * `config.execution.enabled`; nothing here runs otherwise.
 *
 * Invariants: the database is the only source of state (ER-1); every read and write is scoped by the trusted tenant; every
 * write of a lease holder is fenced by `(execution, lease_epoch)` (ER-30); the installation token exists only inside the
 * source session of the fetch step (never logged, stored or sent) and `untrusted_fork` executions are fetched by the platform
 * and then handled with no credential at all; repository content is only parsed, never executed (R-8).
 * Milestones are also written to the execution log (SPEC §17.ac) through the LogStore, best effort: a log failure never fails
 * a run, and every line passes the store's redaction and caps.
 *
 * Scan decisioning (docs/modules/scan-decisioning/SPEC.md part E): in `preparing`, after the fetch and before any task exists, the
 * orchestrator decides WHICH enabled scans this run needs (deterministic floor + optional agent that can only add), records the
 * decision, and creates the tasks of the DECIDED types only, in one transaction fenced by the lease epoch. There is no switch for
 * the step: it runs whenever the orchestrator runs; without a provider the decision is the floor.
 * @param {{ db: any, config: any, logger: any, github: { openSourceSession: Function, listChangedFiles?: Function }, store: any, engines: any, workerId?: string, sleep?: (ms: number) => Promise<void>, logStore?: any, decisionRuntime?: { resolveProvider: Function } | null }} deps
 */
export function createOrchestrator({
  db,
  config,
  logger,
  github,
  store,
  engines,
  workerId,
  sleep = sleepFor,
  logStore,
  decisionRuntime = null,
}) {
  const ex = config.execution;
  const id = workerId ?? `pipeline-${process.pid}-${randomBytes(3).toString("hex")}`;
  const log = logger?.child ? logger.child({ component: "execution-orchestrator" }) : logger;
  const repo = createExecutionRepository({ db });
  const cancellation = createExecutionCancellation({ db });
  const tasksRepo = createScanTaskRepository({ db });
  const decisions = createScanDecisionRepository({ db });
  const markers = createOrchestratorMarkerRepository({ db });
  const entitlements = createEntitlementService({
    repository: createEntitlementRepository({ db }),
  });
  const producer = createMessageProducer({ db });
  const logs = resolveLogStore({ db, config, logStore });
  /** Appends execution-level log lines as the lease holder; never throws. */
  async function execLog(row, epoch, source, messages, level = "info") {
    try {
      await logs.appendExecution(
        { tenantId: row.tenantId, executionId: row.id, leaseEpoch: epoch, source },
        messages.map((message) => ({ level, message })),
      );
    } catch (error) {
      log?.warn?.(
        { executionId: row.id, errorName: error?.name },
        "Execution log lines could not be stored",
      );
    }
  }
  const unsupportedLines = (specs) =>
    specs
      .filter((spec) => !engines.has(spec.scanType, spec.engineId))
      .map(
        (spec) =>
          `scan type ${spec.scanType}: no engine is registered, the task is recorded unsupported`,
      );
  /** Executions this process holds the lease of: executionId -> { tenantId, executionId, epoch, controller }. */
  const owned = new Map();
  let ticking = false;
  let sweepDone = false;

  const auditCorrelation = (exec) =>
    UUID.test(exec.correlationId ?? "") ? exec.correlationId : null;
  const audit = (tx, exec, action, metadata = {}) =>
    auditSystem(tx, {
      tenantId: exec.tenantId,
      action,
      targetType: "execution",
      targetId: exec.id,
      workspaceId: exec.workspaceId,
      correlationId: auditCorrelation(exec),
      metadata: { executionId: exec.id, pipelineId: exec.pipelineId, ...metadata },
    });
  const ownIt = (row, epoch) => {
    owned.get(row.id)?.controller.abort();
    owned.get(row.id)?.cancelController.abort();
    const entry = {
      tenantId: row.tenantId,
      executionId: row.id,
      epoch,
      controller: new AbortController(),
      // aborted when a cancel request is seen while preparing: stops the fetch at once (the lease is still ours)
      cancelController: new AbortController(),
    };
    owned.set(row.id, entry);
    return entry;
  };
  const forget = (executionId) => {
    owned.get(executionId)?.controller.abort();
    owned.get(executionId)?.cancelController.abort();
    owned.delete(executionId);
  };

  // ------------------------------------------------------------------------------------------------ queued -> cancelled

  /**
   * `queued -> cancelled` with the quota unit given back once (CAS plus `quota_released_at`), the audit entry and the status
   * hint in one transaction. `queue_expired` and `expired_stale` are `execution.expired` (system actor).
   */
  async function cancelQueued(client, row, reason) {
    return withTransaction(client, async (tx) => {
      const done = await cancellation.cancelQueued(
        {
          tenantId: row.tenantId,
          executionId: row.id,
          reason,
          actor: { type: "system" },
          correlationId: row.correlationId ?? undefined,
        },
        tx,
      );
      if (!done.cancelled) return { cancelled: false };
      const expired = reason === "queue_expired" || reason === "expired_stale";
      await audit(tx, row, expired ? AUDIT.EXPIRED : AUDIT.CANCELLED, {
        reason,
        from: "queued",
        to: "cancelled",
        quotaReleased: done.quotaReleased,
      });
      await producer.statusChanged(tx, row, "cancelled", done.statusRev, row.correlationId);
      return { cancelled: true, quotaReleased: done.quotaReleased };
    });
  }

  // ------------------------------------------------------------------------------------------------ first-enable sweep

  /**
   * ER-31: the persisted marker and the one-time sweep of stale queued rows. Returns true once the sweep is COMPLETED (by
   * this or another worker); claims wait until then. The marker is the database row, not the environment.
   */
  async function ensureFirstEnableSweep() {
    if (sweepDone) return true;
    const marker = await markers.ensureMarker();
    if (marker.sweepCompletedAt) return (sweepDone = true);
    if (!(await markers.takeSweepLease({ workerId: id, leaseTtlSeconds: ex.leaseTtlSeconds })))
      return false;
    for (;;) {
      const batch = await repo.peekStaleQueued({
        thresholdSeconds: ex.staleThresholdSeconds,
        limit: ex.sweepBatchSize,
      });
      if (batch.length === 0) break;
      let swept = 0;
      for (const candidate of batch) {
        const row = await repo.findExecution({
          tenantId: candidate.tenantId,
          executionId: candidate.id,
        });
        if (!row || row.status !== "queued") continue;
        if ((await cancelQueued(db, row, "expired_stale")).cancelled) swept += 1;
      }
      if (
        !(await markers.recordSweepProgress({
          workerId: id,
          count: swept,
          leaseTtlSeconds: ex.leaseTtlSeconds,
        }))
      )
        return false; // lease lost: another worker continues
      if (swept === 0) break; // only rows that are locked or already handled remain
    }
    const done = await markers.completeSweep({ workerId: id });
    if (done) log.info({ sweptCount: done.sweptCount }, "First-enable stale sweep completed");
    return (sweepDone = Boolean(done));
  }

  /** Steady state: queued rows older than the threshold are cancelled `queue_expired` (ER-9, ER-32). */
  async function expireStale() {
    const batch = await repo.peekStaleQueued({
      thresholdSeconds: ex.staleThresholdSeconds,
      limit: ex.sweepBatchSize,
    });
    for (const candidate of batch) {
      const row = await repo.findExecution({
        tenantId: candidate.tenantId,
        executionId: candidate.id,
      });
      if (row?.status === "queued") await cancelQueued(db, row, "queue_expired");
    }
  }

  // ------------------------------------------------------------------------------------------------ claim

  /**
   * ER-4 and §6.2: ONE transaction under the pipeline advisory lock: re-read by tenant and id, run the gates from the
   * database, then cancel / defer / claim. Exactly one claimer wins the compare-and-set; every other does nothing.
   * @returns {Promise<{ outcome: "skipped" | "deferred" | "cancelled" } | { outcome: "claimed", row: any } | { outcome: "invalid", row: any, reason: string }>}
   */
  async function claimOne({ tenantId, executionId }) {
    const first = await repo.findExecution({ tenantId, executionId });
    if (!first || first.status !== "queued") return { outcome: "skipped" };
    return withTransaction(db, async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`pipeline:${tenantId}:${first.pipelineId}`}))`;
      const row = await repo.findExecution({ tenantId, executionId }, tx);
      if (!row || row.status !== "queued") return { outcome: "skipped" };
      const gate = await evaluateGates(
        { entitlements, staleThresholdSeconds: ex.staleThresholdSeconds },
        tx,
        row,
      );
      if (gate.decision === "defer") return { outcome: "deferred", reason: gate.reason };
      if (gate.decision === "cancel") {
        const done = await cancelQueued(tx, row, gate.reason);
        return { outcome: done.cancelled ? "cancelled" : "skipped", reason: gate.reason };
      }
      const deadlineSeconds =
        gate.decision === "go"
          ? Math.min(
              gate.cfg.execution?.timeoutSeconds ?? DEFAULT_DEADLINE_SECONDS,
              EXECUTION_TIMEOUT_CAP_SECONDS,
            )
          : DEFAULT_DEADLINE_SECONDS;
      const claimed = await repo.claimQueued(
        {
          tenantId,
          executionId,
          workerId: id,
          leaseTtlSeconds: ex.leaseTtlSeconds,
          deadlineSeconds,
          staleThresholdSeconds: ex.staleThresholdSeconds,
          correlationId: row.correlationId ?? undefined,
        },
        tx,
      );
      if (!claimed) return { outcome: "skipped" }; // lost the race (or it aged out between the gate and the claim)
      await audit(tx, row, AUDIT.PREPARING, {
        from: "queued",
        to: "preparing",
        leaseEpoch: claimed.leaseEpoch,
      });
      await producer.statusChanged(tx, row, "preparing", claimed.statusRev, row.correlationId);
      const full = { ...row, ...claimed, status: "preparing" };
      return gate.decision === "invalid"
        ? { outcome: "invalid", row: full, reason: gate.reason }
        : { outcome: "claimed", row: full };
    });
  }

  // ------------------------------------------------------------------------------------------------ terminal transition

  const taskCountsOf = (tasks) => ({
    total: tasks.length,
    succeeded: tasks.filter((t) => t.status === "succeeded").length,
    failed: tasks.filter((t) => t.status === "failed").length,
    timed_out: tasks.filter((t) => t.status === "timed_out").length,
    cancelled: tasks.filter((t) => t.status === "cancelled").length,
    skipped: tasks.filter((t) => t.status === "skipped").length,
    unsupported: tasks.filter((t) => t.status === "unsupported").length,
  });

  /**
   * The single terminal transition of a claimed execution, fenced by the held epoch: closes out unfinished tasks (when told
   * to), the CAS with quota release, the audit entry and ONE `pipeline.execution.completed` plus the status hint, all in one
   * transaction. A lost fence rolls everything back and returns `{ lost: true }`.
   * @returns {Promise<{ lost: boolean, quotaReleased?: boolean }>}
   */
  async function terminalize({
    row,
    epoch,
    from,
    to,
    reason,
    release = false,
    closeOut,
    details = {},
  }) {
    const { tenantId } = row;
    const executionId = row.id;
    try {
      const result = await withTransaction(db, async (tx) => {
        if (closeOut)
          await tasksRepo.closeOutTasks(
            { tenantId, executionId, leaseEpoch: epoch, ...closeOut },
            tx,
          );
        else await repo.fenceExecution({ tenantId, executionId, leaseEpoch: epoch }, tx);
        const tasks = await tasksRepo.listTasks({ tenantId, executionId }, tx);
        const results = await tasksRepo.listResults({ tenantId, executionId }, tx);
        const done = await repo.transitionExecution(
          {
            tenantId,
            executionId,
            from,
            to,
            reason,
            leaseEpoch: epoch,
            releaseQuota: release,
            taskCounts: taskCountsOf(tasks),
            actor: { type: "system" },
            correlationId: row.correlationId ?? undefined,
            eventDetails: { epoch, ...details },
          },
          tx,
        );
        if (!done.transitioned) throw new LeaseLostError({ executionId, leaseEpoch: epoch });
        const final = await repo.findExecution({ tenantId, executionId }, tx);
        const meta = {
          from,
          to,
          reason,
          quotaReleased: done.quotaReleased,
          epoch,
          taskCounts: taskCountsOf(tasks),
          ...details,
        };
        await audit(tx, row, AUDIT_BY_STATUS[to], meta);
        if (reason === "worker_lost") await audit(tx, row, AUDIT.WORKER_LOST, meta);

        let enabled = [];
        if (to === "succeeded") {
          const version = await tx.pipelineConfigVersion.findFirst({
            where: { id: final.configVersionId, tenantId, pipelineId: final.pipelineId },
            select: { config: true },
          });
          const parsed = CONFIG_SCHEMA.safeParse(version?.config);
          enabled = parsed.success ? enabledScanTypes(parsed.data) : [];
        }
        const byTask = new Map(results.map((r) => [r.scanTaskId, r]));
        const summary = tasks.map((t) => {
          const r = byTask.get(t.id);
          return {
            taskId: t.id,
            scanType: t.scanType,
            status: t.status,
            resultId: r?.id ?? null,
            itemCount: r?.itemCount ?? 0,
            completeness: r?.completeness ?? null,
          };
        });
        const eligible = isResolutionEligible({
          status: to,
          scanKind: final.scanKind,
          trust: final.trust,
          enabledScanTypes: enabled,
          tasks: tasks.map((t) => ({
            scanType: t.scanType,
            status: t.status,
            completeness: byTask.get(t.id)?.completeness ?? null,
            truncated: byTask.get(t.id)?.truncated ?? false,
          })),
        });
        await producer.completed(
          tx,
          row,
          completedPayload(final, {
            status: to,
            reason,
            resolutionEligible: eligible,
            tasks: summary,
          }),
          row.correlationId,
        );
        await producer.statusChanged(tx, row, to, done.execution.statusRev, row.correlationId);
        return { lost: false, quotaReleased: done.quotaReleased };
      });
      forget(executionId);
      await store.deleteExecution({ tenantId, executionId }).catch(() => {});
      return result;
    } catch (error) {
      if (error instanceof LeaseLostError) {
        forget(executionId);
        log.warn(
          { executionId, leaseEpoch: epoch },
          "Lease lost before the terminal transition; nothing was written",
        );
        return { lost: true };
      }
      throw error;
    }
  }

  /**
   * SPEC §17.ab: an enabled scan type without a registered engine is `unsupported` at once (terminal; no attempt, no queue
   * message, no credential), recorded in the history and announced; it never blocks the execution. Inside the caller's
   * transaction, right after the tasks are created.
   */
  async function markUnsupportedInTransaction(tx, row, epoch, specs) {
    const unsupported = await tasksRepo.markUnsupported(
      {
        tenantId: row.tenantId,
        executionId: row.id,
        leaseEpoch: epoch,
        scanTypes: specs
          .filter((spec) => !engines.has(spec.scanType, spec.engineId))
          .map((spec) => spec.scanType),
      },
      tx,
    );
    for (const task of unsupported) {
      await repo.recordEvent(
        {
          tenantId: row.tenantId,
          executionId: row.id,
          type: "task_unsupported",
          reason: SCAN_TASK_UNSUPPORTED_REASON,
          leaseEpoch: epoch,
          correlationId: row.correlationId ?? undefined,
          details: { taskId: task.id, scanType: task.scanType },
        },
        tx,
      );
      await producer.taskStatusChanged(
        tx,
        row,
        { taskId: task.id, scanType: task.scanType, status: "unsupported", rev: task.statusRev },
        row.correlationId,
      );
    }
    return unsupported;
  }

  const failPrepare = (row, epoch, code, details = {}) => {
    log.warn({ executionId: row.id, code }, "Execution failed while preparing");
    return terminalize({
      row,
      epoch,
      from: "preparing",
      to: "failed",
      reason: code === "worker_lost" ? "worker_lost" : `prepare_failed:${code}`,
      release: code === "worker_lost" || PLATFORM_PREPARE_FAILURES.includes(code),
      details: { code, ...details },
    });
  };

  // ------------------------------------------------------------------------------------------------ preparation

  /** Maps an error of the fetch step onto a stable code, and whether a retry may help. */
  function classify(error) {
    if (error instanceof PrepareFailure) return { code: error.code, transient: false };
    if (error instanceof ArtifactTooLargeError)
      return { code: "archive_too_large", transient: false };
    if (error instanceof ArchiveError) return { code: error.code, transient: false };
    if (error instanceof GitHubApiError) {
      if (error.code === "redirect_refused")
        return { code: "archive_host_refused", transient: false };
      const transient =
        error.rateLimited ||
        error.status === undefined ||
        error.status >= 500 ||
        error.status === 408;
      if (transient) return { code: "github_unavailable", transient: true };
      if (error.status === 404 || error.status === 422)
        return { code: "ref_not_found", transient: false };
      return { code: "repository_inaccessible", transient: false };
    }
    if (error?.code && /^(E[A-Z]+)$/.test(error.code))
      return { code: "storage_error", transient: true };
    return { code: "internal_error", transient: false };
  }

  /** Loads the snapshot and the repository facts for the fetch step (by tenant and id, no gating: the claim ran the gates). */
  async function loadPrepareContext(row) {
    const version = await db.pipelineConfigVersion.findFirst({
      where: { id: row.configVersionId, tenantId: row.tenantId, pipelineId: row.pipelineId },
      select: { config: true },
    });
    const parsed = CONFIG_SCHEMA.safeParse(version?.config);
    if (!parsed.success) throw new PrepareFailure("config_invalid");
    const repository = await db.repository.findFirst({
      where: { id: row.repositoryId, tenantId: row.tenantId, workspaceId: row.workspaceId },
      select: {
        fullName: true,
        link: { select: { installation: { select: { externalInstallationId: true } } } },
      },
    });
    const installationId = repository?.link?.installation?.externalInstallationId;
    if (!repository || !installationId) throw new PrepareFailure("repository_inaccessible");
    return { cfg: parsed.data, fullName: repository.fullName, installationId };
  }

  async function prepareOnce(row, entry, signal) {
    const { tenantId } = row;
    const epoch = entry.epoch;
    // Safe points of the preparation (ER-14): a cancel request recorded for a preparing execution ends it `cancelled` with
    // the unit given back (no scan started), at the start, after each side effect and, last, inside the transaction that
    // would start the tasks.
    const assertNotCancelled = async (client = db) => {
      const lifecycle = await repo.readLifecycle({ tenantId, executionId: row.id }, client);
      if (lifecycle?.cancelRequestedAt) throw new CancelRequested();
    };
    await assertNotCancelled();
    const { cfg, fullName, installationId } = await loadPrepareContext(row);
    const types = enabledScanTypes(cfg);
    if (types.length === 0) throw new PrepareFailure("config_invalid");
    // `ordinal` is the catalog position (SPEC scan-decisioning FT-6): gaps are expected when a type is not selected
    const specs = types.map((type) => ({
      scanType: type,
      ordinal: SCAN_TASK_ORDER.indexOf(type),
      engineId: cfg.scans[type].engine.id,
      engineProfile: cfg.scans[type].engine.profile ?? "default",
      severityThreshold: cfg.scans[type].severityThreshold ?? "low",
      timeoutSeconds: cfg.execution.scanTaskTimeoutSeconds,
      maxAttempts: ex.taskMaxAttempts,
    }));
    // SPEC §17.ab: when NO enabled scan type has a registered engine, nothing can run: the tasks are recorded `unsupported` and the
    // execution fails before anything is fetched (no archive, no credential is ever used)
    if (specs.every((spec) => !engines.has(spec.scanType, spec.engineId))) {
      await withTransaction(db, async (tx) => {
        await tasksRepo.createTasks(
          { tenantId, executionId: row.id, leaseEpoch: epoch, tasks: specs },
          tx,
        );
        await markUnsupportedInTransaction(tx, row, epoch, specs);
      });
      await execLog(row, epoch, "platform", unsupportedLines(specs), "warn");
      throw new NoEngineRegistered();
    }
    const ref = { tenantId, executionId: row.id, name: ARCHIVE_NAME };
    let session = null;
    let sha = row.commitSha;
    const open = async () =>
      (session ??= await github.openSourceSession({
        externalInstallationId: installationId,
        fullName,
      }));
    try {
      // ER-10: pin the commit once (null to value). A pull request uses its stored head SHA; nothing is re-read.
      if (!sha) {
        if (row.refType === "pull_request") throw new PrepareFailure("ref_not_found");
        const resolved = await (
          await open()
        ).resolveRef({ refType: row.refType, refName: row.refName });
        if (!resolved) throw new PrepareFailure("ref_not_found");
        sha = await repo.pinCommit({
          tenantId,
          executionId: row.id,
          leaseEpoch: epoch,
          commitSha: resolved,
        });
      }
      signal.throwIfAborted();
      await assertNotCancelled();
      // archive (ER-29 step table): a recorded archive must still be on disk and match; otherwise fetch from the pinned SHA
      if (row.archiveSha256) {
        if ((await store.sha256(ref)) !== row.archiveSha256) throw new WorkerLost("archive");
      } else {
        await store.delete(ref);
        const body = await (await open()).downloadArchive({ sha, signal });
        const put = await store.put(ref, body, { maxBytes: ex.archiveLimits.maxBytes });
        try {
          await inspectTarGz(store.open(ref), {
            limits: ex.archiveLimits,
            expectTopDirIncludes: sha.slice(0, 7),
          });
        } catch (error) {
          await store.delete(ref).catch(() => {});
          throw error;
        }
        await repo.recordArchive({
          tenantId,
          executionId: row.id,
          leaseEpoch: epoch,
          sha256: put.sha256,
          bytes: put.bytes,
        });
        await execLog(row, epoch, "fetch", [`source archive stored (${put.bytes} bytes)`]);
      }
      signal.throwIfAborted();
      await assertNotCancelled();
    } finally {
      session?.close();
    }
    // ---- the scan decision (SPEC scan-decisioning 5.1, 5.7), after the fetch and BEFORE any task exists
    const scope = {
      tenantId,
      executionId: row.id,
      workspaceId: row.workspaceId,
      repositoryId: row.repositoryId,
      pipelineId: row.pipelineId,
    };
    const persisted = await decisions.findDecision(scope);
    let decision;
    if (persisted) {
      // (1) the record exists: reuse it, no diff, no model (D9)
      decision = {
        finalTypes: persisted.finalTypes,
        zeroScan: persisted.finalTypes.length === 0,
        reused: true,
      };
    } else if (entry.decision) {
      // the same holder retries the step after a transient failure: the decision it already made is kept (no second model call)
      decision = entry.decision;
    } else {
      // (2) a marker without a record: the previous holder died mid-decision, the agent is NOT called again; (3) neither: full flow
      const interrupted = await decisions.hasDecisionStarted({ tenantId, executionId: row.id });
      if (!interrupted)
        await decisions.markDecisionStarted({
          tenantId,
          executionId: row.id,
          leaseEpoch: epoch,
          correlationId: row.correlationId ?? undefined,
        });
      signal.throwIfAborted();
      await assertNotCancelled();
      decision = await decideScans({
        execution: { ...row, commitSha: sha },
        tenantId,
        repository: { fullName, externalInstallationId: installationId },
        enabledTypes: types,
        exclusions: cfg.exclusions ?? null,
        github,
        runtime: decisionRuntime,
        config,
        signal,
        logger: log,
        interrupted,
      });
      // a cancel (or a lost lease, or the deadline) that arrived during the diff or the model call ends the step with NO record
      signal.throwIfAborted();
      await assertNotCancelled();
      entry.decision = decision;
    }
    const decided = new Set(decision.finalTypes);
    const decidedSpecs = specs.filter((spec) => decided.has(spec.scanType));
    // log lines are written while the execution is still preparing (a terminal execution accepts none)
    await execLog(row, epoch, "platform", [decisionLine(decision, types)]);
    if (decision.zeroScan)
      await execLog(row, epoch, "platform", [
        "no scan is applicable to this change: the execution will succeed without running a scan",
      ]);
    const outcome = await withTransaction(db, async (tx) => {
      await repo.fenceExecution({ tenantId, executionId: row.id, leaseEpoch: epoch }, tx);
      // the fence holds the row lock (FOR SHARE): a cancel request cannot commit between this check and our commit
      await assertNotCancelled(tx);
      if (!decision.reused) {
        await decisions.insertDecision(
          { tenantId, executionId: row.id, leaseEpoch: epoch, decision },
          tx,
        );
        await decisions.recordDecisionCompleted(
          {
            tenantId,
            executionId: row.id,
            leaseEpoch: epoch,
            correlationId: row.correlationId ?? undefined,
            details: decisionEventDetails(decision),
          },
          tx,
        );
        await audit(tx, row, AUDIT.DECISION_COMPLETED, {
          floor: decision.floor.map((f) => f.scanType),
          added: decision.agent.additions.map((a) => a.scanType),
          final: decision.finalTypes,
          agentStatus: decision.agent.status,
          provider: decision.agent.provider,
          model: decision.agent.model,
          diffStatus: decision.diff.status,
          zeroScan: decision.zeroScan,
          epoch,
        });
      }
      if (decision.zeroScan) {
        // SPEC 5.6 (AP-3): nothing applicable. preparing -> running -> succeeded in this one transaction, the same lease epoch,
        // no task, the quota unit given back once, never resolution-eligible.
        const ended = await decisions.finishZeroScan(
          {
            tenantId,
            executionId: row.id,
            leaseEpoch: epoch,
            correlationId: row.correlationId ?? undefined,
            endedDetails: { decision: "zero_scan" },
          },
          tx,
        );
        const final = await repo.findExecution({ tenantId, executionId: row.id }, tx);
        await audit(tx, row, AUDIT.STARTED, {
          from: "preparing",
          to: "running",
          taskCount: 0,
          epoch,
        });
        await producer.started(
          tx,
          row,
          { startedAt: final.startedAt, taskCount: 0 },
          row.correlationId,
        );
        await producer.statusChanged(
          tx,
          row,
          "running",
          ended.started.statusRev,
          row.correlationId,
        );
        await audit(tx, row, AUDIT.SUCCEEDED, {
          from: "running",
          to: "succeeded",
          reason: NO_APPLICABLE_SCANS_REASON,
          quotaReleased: ended.quotaReleased,
          epoch,
          taskCounts: taskCountsOf([]),
        });
        await producer.completed(
          tx,
          row,
          completedPayload(final, {
            status: "succeeded",
            reason: NO_APPLICABLE_SCANS_REASON,
            resolutionEligible: false,
            tasks: [],
          }),
          row.correlationId,
        );
        await producer.statusChanged(
          tx,
          row,
          "succeeded",
          ended.ended.statusRev,
          row.correlationId,
        );
        if (!decision.reused)
          await producer.decisionCompleted(tx, row, ended.ended.statusRev, row.correlationId);
        return "succeeded";
      }
      await tasksRepo.createDecidedTasks(
        { tenantId, executionId: row.id, leaseEpoch: epoch, tasks: decidedSpecs },
        tx,
      );
      await markUnsupportedInTransaction(tx, row, epoch, decidedSpecs);
      const done = await repo.transitionExecution(
        {
          tenantId,
          executionId: row.id,
          from: "preparing",
          to: "running",
          leaseEpoch: epoch,
          actor: { type: "system" },
          correlationId: row.correlationId ?? undefined,
          eventDetails: { epoch, taskCount: decidedSpecs.length },
        },
        tx,
      );
      if (!done.transitioned) throw new LeaseLostError({ executionId: row.id, leaseEpoch: epoch });
      const fresh = await repo.findExecution({ tenantId, executionId: row.id }, tx);
      await audit(tx, row, AUDIT.STARTED, {
        from: "preparing",
        to: "running",
        taskCount: decidedSpecs.length,
        epoch,
      });
      await producer.started(
        tx,
        row,
        { startedAt: fresh.startedAt, taskCount: decidedSpecs.length },
        row.correlationId,
      );
      await producer.statusChanged(tx, row, "running", done.execution.statusRev, row.correlationId);
      if (!decision.reused)
        await producer.decisionCompleted(tx, row, done.execution.statusRev, row.correlationId);
      await dispatchInTransaction(tx, { ...row, ...fresh }, epoch, ex.taskParallelism);
      return "running";
    });
    if (outcome === "succeeded") {
      forget(row.id);
      await store.deleteExecution({ tenantId, executionId: row.id }).catch(() => {});
      return outcome;
    }
    await execLog(row, epoch, "platform", [
      `execution started with ${decidedSpecs.length} scan task(s)`,
    ]);
    const skipped = unsupportedLines(decidedSpecs);
    if (skipped.length > 0) await execLog(row, epoch, "platform", skipped, "warn");
    return outcome;
  }

  /**
   * Prepares a claimed (or reclaimed `preparing`) execution: bounded retries of transient fetch failures, the deadline and the
   * lease as abort signals, and a stable `prepare_failed:<code>` otherwise. Returns `{ outcome }`.
   */
  async function runPrepare(row, entry) {
    const lifecycle = await repo.readLifecycle({ tenantId: row.tenantId, executionId: row.id });
    const ms = Math.max(
      1,
      Math.floor((lifecycle?.secondsToDeadline ?? DEFAULT_DEADLINE_SECONDS) * 1000),
    );
    const deadline = AbortSignal.timeout(ms);
    const signal = AbortSignal.any([
      entry.controller.signal,
      entry.cancelController.signal,
      deadline,
    ]);
    for (let attempt = 1; ; attempt += 1) {
      try {
        return { outcome: await prepareOnce(row, entry, signal) };
      } catch (error) {
        if (error instanceof LeaseLostError || entry.controller.signal.aborted) {
          forget(row.id);
          return { outcome: "lost" };
        }
        if (deadline.aborted) {
          const done = await terminalize({
            row,
            epoch: entry.epoch,
            from: "preparing",
            to: "timed_out",
            reason: "execution_deadline",
          });
          return { outcome: done.lost ? "lost" : "timed_out" };
        }
        if (error instanceof CancelRequested || entry.cancelController.signal.aborted) {
          // cancel honoured during preparation: no scan started, so the unit goes back (SPEC 6.1, 5.9)
          const done = await terminalize({
            row,
            epoch: entry.epoch,
            from: "preparing",
            to: "cancelled",
            reason: "user_cancelled",
            release: true,
            details: { step: "preparing", decision: "cancel" },
          });
          return { outcome: done.lost ? "lost" : "cancelled" };
        }
        if (error instanceof NoEngineRegistered) {
          // nothing could run: a platform capability gap, so the unit goes back (preparing -> failed, SPEC §5.9, §17.ab)
          const done = await terminalize({
            row,
            epoch: entry.epoch,
            from: "preparing",
            to: "failed",
            reason: "tasks_unsupported",
            release: true,
            details: { step: "preparing", decision: "fail", code: "no_engine_registered" },
          });
          return { outcome: done.lost ? "lost" : "failed" };
        }
        if (error instanceof WorkerLost) {
          const done = await failPrepare(row, entry.epoch, "worker_lost", {
            step: "preparing",
            decision: "fail",
          });
          return { outcome: done.lost ? "lost" : "failed" };
        }
        const verdict = classify(error);
        if (verdict.transient && attempt < ex.prepareMaxAttempts) {
          log.warn(
            {
              executionId: row.id,
              attempt,
              code: verdict.code,
              reason: error instanceof GitHubApiError ? error.message : error?.name,
            },
            "Transient failure while preparing; retrying",
          );
          await sleep(ex.prepareRetryDelayMs * attempt);
          continue;
        }
        if (verdict.code === "internal_error")
          log.error(
            { executionId: row.id, errorName: error?.name },
            "Unexpected failure while preparing",
          );
        const done = await failPrepare(row, entry.epoch, verdict.code);
        return { outcome: done.lost ? "lost" : "failed" };
      }
    }
  }

  // ------------------------------------------------------------------------------------------------ running: dispatch, aggregate

  /** Moves up to `limit` pending tasks to queued and writes their `scan.task.requested` jobs, inside the caller's transaction. */
  async function dispatchInTransaction(tx, row, epoch, limit) {
    const moved = await tasksRepo.queuePending(
      { tenantId: row.tenantId, executionId: row.id, leaseEpoch: epoch, limit },
      tx,
    );
    for (const task of moved) {
      await producer.taskRequested(
        tx,
        row,
        { id: task.id, scanType: task.scanType, attempt: task.attempt },
        { trust: row.trust, deadlineAt: row.deadlineAt },
        row.correlationId,
      );
      await producer.taskStatusChanged(
        tx,
        row,
        { taskId: task.id, scanType: task.scanType, status: "queued", rev: task.statusRev },
        row.correlationId,
      );
    }
    return moved.length;
  }

  /** A task whose scan worker died: retry (new attempt) when the engine is idempotent and attempts remain, else fail `worker_lost`. */
  async function recoverTask(row, epoch, task) {
    const engine = engines.get(task.scanType, task.engineId);
    const requeued = engine?.idempotent
      ? await withTransaction(db, async (tx) => {
          await repo.fenceExecution(
            { tenantId: row.tenantId, executionId: row.id, leaseEpoch: epoch },
            tx,
          );
          const next = await tasksRepo.requeueTask(
            {
              tenantId: row.tenantId,
              taskId: task.id,
              attempt: task.attempt,
              errorClass: "lease_expired",
              errorCode: "lease_expired",
            },
            tx,
          );
          if (next) {
            await producer.taskRequested(
              tx,
              row,
              { id: task.id, scanType: task.scanType, attempt: next.attempt },
              { trust: row.trust, deadlineAt: row.deadlineAt },
              row.correlationId,
            );
            await producer.taskStatusChanged(
              tx,
              row,
              {
                taskId: task.id,
                scanType: task.scanType,
                status: "queued",
                rev: next.task.statusRev,
              },
              row.correlationId,
            );
          }
          return Boolean(next);
        })
      : false;
    if (requeued) return;
    await withTransaction(db, async (tx) => {
      await repo.fenceExecution(
        { tenantId: row.tenantId, executionId: row.id, leaseEpoch: epoch },
        tx,
      );
      const done = await tasksRepo.finishTask(
        {
          tenantId: row.tenantId,
          taskId: task.id,
          attempt: task.attempt,
          status: "failed",
          reason: "worker_lost",
          errorClass: "lease_expired",
          errorCode: "worker_lost",
        },
        tx,
      );
      if (done.finished)
        await producer.taskStatusChanged(
          tx,
          row,
          { taskId: task.id, scanType: task.scanType, status: "failed", rev: done.task.statusRev },
          row.correlationId,
        );
    });
  }

  /**
   * Ends a running execution whose tasks are all finished by table 5.4. A task that ended at the EXECUTION's deadline makes
   * the execution `timed_out`; its result and the results of the finished tasks stay (B5).
   */
  function finishNaturally(row, epoch, tasks) {
    const outcome = aggregateTaskOutcome(tasks);
    if (
      outcome.status !== "succeeded" &&
      tasks.some((t) => t.statusReason === "execution_deadline")
    )
      return terminalize({
        row,
        epoch,
        from: "running",
        to: "timed_out",
        reason: "execution_deadline",
      });
    return terminalize({ row, epoch, from: "running", to: outcome.status, reason: outcome.reason });
  }

  /**
   * Honours a cancel request of a RUNNING execution at a safe point (SPEC ER-14, ER-18; both modes): nothing starts any more
   * (pending and queued tasks become `cancelled`, a claim and a retry attempt are refused by the database), tasks that are
   * mid-run are aborted by their scan worker at once (`immediate`) or when the grace period ends (`graceful`), results already
   * ingested stay, and the execution becomes `cancelled` as soon as no attempt is running or the grace has passed (a hung
   * attempt is then closed out). If no task was cancelled by the request (everything had already finished) the natural
   * outcome of table 5.4 stands and the request stays recorded on the row.
   */
  async function honourCancel(entry, row, lifecycle) {
    const { tenantId, executionId, epoch } = entry;
    await withTransaction(db, async (tx) => {
      const moved = await tasksRepo.cancelUnstarted(
        { tenantId, executionId, leaseEpoch: epoch, reason: "user_cancelled" },
        tx,
      );
      for (const task of moved)
        await producer.taskStatusChanged(
          tx,
          row,
          { taskId: task.id, scanType: task.scanType, status: "cancelled", rev: task.statusRev },
          row.correlationId,
        );
    });
    for (const task of await tasksRepo.listExpiredTaskLeases({ tenantId, executionId }))
      await recoverTask(row, epoch, task);
    const tasks = await tasksRepo.listTasks({ tenantId, executionId });
    const running = tasks.filter((t) => t.status === "running" || t.status === "queued").length;
    if (
      cancelWaitDecision({ graceSecondsLeft: lifecycle.cancelGraceSecondsLeft, running }) === "wait"
    )
      return { waiting: true };
    const cancelledByRequest =
      running > 0 ||
      tasks.some((t) => t.status === "cancelled" && t.statusReason === "user_cancelled");
    if (!cancelledByRequest) return finishNaturally(row, epoch, tasks);
    return terminalize({
      row,
      epoch,
      from: "running",
      to: "cancelled",
      reason: "user_cancelled",
      closeOut: {
        runningTo: "cancelled",
        pendingTo: "cancelled",
        reason: "user_cancelled",
        errorClass: "cancelled",
        errorCode: "user_cancelled",
      },
      details: { mode: lifecycle.cancelMode, decision: "cancel", graceElapsed: running > 0 },
    });
  }

  /**
   * One pass over a running execution this process holds: cancel (ER-14), deadline, dead scan workers, dispatch, and the
   * aggregation when every task is finished. Idempotent: every write is a compare-and-set. The execution deadline is a hard
   * limit and wins over a cancel that is still waiting for its grace period; a cancel is honoured first when the lease is
   * reclaimed (ER-29 order).
   */
  async function drive(entry) {
    const { tenantId, executionId, epoch } = entry;
    const lifecycle = await repo.readLifecycle({ tenantId, executionId });
    if (!lifecycle || lifecycle.leaseEpoch !== epoch || lifecycle.status !== "running")
      return forget(executionId);
    const row = await repo.findExecution({ tenantId, executionId });
    const pastDeadline = lifecycle.secondsToDeadline !== null && lifecycle.secondsToDeadline <= 0;
    if (lifecycle.cancelRequestedAt && !pastDeadline) return honourCancel(entry, row, lifecycle);
    for (const task of await tasksRepo.listExpiredTaskLeases({ tenantId, executionId }))
      await recoverTask(row, epoch, task);
    const tasks = await tasksRepo.listTasks({ tenantId, executionId });
    const inFlight = tasks.filter((t) => t.status === "queued" || t.status === "running").length;
    const pending = tasks.filter((t) => t.status === "pending").length;
    if (inFlight === 0 && pending === 0) return finishNaturally(row, epoch, tasks);
    if (pastDeadline)
      return terminalize({
        row,
        epoch,
        from: "running",
        to: "timed_out",
        reason: "execution_deadline",
        closeOut: {
          runningTo: "timed_out",
          pendingTo: "skipped",
          reason: "execution_deadline",
          errorClass: "timeout",
          errorCode: "execution_deadline",
        },
      });
    if (pending > 0 && inFlight < ex.taskParallelism)
      await withTransaction(db, (tx) =>
        dispatchInTransaction(tx, row, epoch, ex.taskParallelism - inFlight),
      );
  }

  // ------------------------------------------------------------------------------------------------ lease reclaim

  /**
   * ER-28/ER-29: reclaim an expired lease by compare-and-set (exactly one winner), then decide in the order of the spec:
   * cancel, deadline, reclaim limit, then the step table (resume only idempotent work, else `worker_lost`).
   */
  async function reclaimOne(candidate) {
    const row = await repo.findExecution({
      tenantId: candidate.tenantId,
      executionId: candidate.id,
    });
    if (!row || !["preparing", "running"].includes(row.status)) return;
    const won = await withTransaction(db, async (tx) => {
      const claimed = await repo.reclaimLease(
        {
          tenantId: row.tenantId,
          executionId: row.id,
          workerId: id,
          observedEpoch: candidate.leaseEpoch,
          leaseTtlSeconds: ex.leaseTtlSeconds,
        },
        tx,
      );
      if (!claimed) return null;
      await audit(tx, row, AUDIT.LEASE_RECLAIMED, {
        status: claimed.status,
        oldEpoch: candidate.leaseEpoch,
        newEpoch: claimed.leaseEpoch,
      });
      return claimed;
    });
    if (!won) return; // somebody else reclaimed it, or the lease is live
    const epoch = won.leaseEpoch;
    const status = won.status;
    const entry = ownIt(row, epoch);
    const fresh = await repo.findExecution({ tenantId: row.tenantId, executionId: row.id });
    const decide = { epoch, step: status };
    // (1) cancel requested, (2) deadline passed
    if (fresh.cancelRequestedAt)
      return terminalize({
        row: fresh,
        epoch,
        from: status,
        to: "cancelled",
        reason: "user_cancelled",
        release: status === "preparing",
        closeOut:
          status === "running"
            ? {
                runningTo: "cancelled",
                pendingTo: "cancelled",
                reason: "user_cancelled",
                errorClass: "cancelled",
                errorCode: "user_cancelled",
              }
            : undefined,
        details: { ...decide, decision: "cancel" },
      });
    const lifecycle = await repo.readLifecycle({ tenantId: row.tenantId, executionId: row.id });
    if (lifecycle && lifecycle.secondsToDeadline !== null && lifecycle.secondsToDeadline <= 0)
      return terminalize({
        row: fresh,
        epoch,
        from: status,
        to: "timed_out",
        reason: "execution_deadline",
        closeOut:
          status === "running"
            ? {
                runningTo: "timed_out",
                pendingTo: "skipped",
                reason: "execution_deadline",
                errorClass: "timeout",
                errorCode: "execution_deadline",
              }
            : undefined,
        details: { ...decide, decision: "timeout" },
      });
    // (3) reclaim limit: the epoch counts the claim and every reclaim (a crash between reclaim and decision still counts)
    const priorReclaims = epoch - 2;
    if (priorReclaims >= ex.maxReclaims) {
      if (status === "preparing")
        return failPrepare(fresh, epoch, "worker_lost", {
          ...decide,
          decision: "fail",
          why: "reclaim_limit",
        });
      return terminalize({
        row: fresh,
        epoch,
        from: "running",
        to: "failed",
        reason: "worker_lost",
        closeOut: {
          runningTo: "failed",
          pendingTo: "skipped",
          reason: "worker_lost",
          errorClass: "lease_expired",
          errorCode: "worker_lost",
        },
        details: { ...decide, decision: "fail", why: "reclaim_limit" },
      });
    }
    // (4) resume where the step table says so
    if (status === "preparing") {
      // a recorded archive that is gone or does not match is a half-done side effect: fail, do not resume
      if (
        fresh.archiveSha256 &&
        (await store.sha256({
          tenantId: row.tenantId,
          executionId: row.id,
          name: ARCHIVE_NAME,
        })) !== fresh.archiveSha256
      )
        return failPrepare(fresh, epoch, "worker_lost", {
          ...decide,
          decision: "fail",
          why: "archive_missing",
        });
      await recordRecovered(fresh, epoch, { ...decide, decision: "resume" });
      return runPrepare(fresh, entry);
    }
    // running: a task that must be re-run needs the archive; if it is gone the state is indeterminate
    const expired = await tasksRepo.listExpiredTaskLeases({
      tenantId: row.tenantId,
      executionId: row.id,
    });
    if (
      expired.length > 0 &&
      (await store.sha256({ tenantId: row.tenantId, executionId: row.id, name: ARCHIVE_NAME })) !==
        fresh.archiveSha256
    )
      return terminalize({
        row: fresh,
        epoch,
        from: "running",
        to: "failed",
        reason: "worker_lost",
        closeOut: {
          runningTo: "failed",
          pendingTo: "skipped",
          reason: "worker_lost",
          errorClass: "lease_expired",
          errorCode: "worker_lost",
        },
        details: { ...decide, decision: "fail", why: "archive_missing" },
      });
    await recordRecovered(fresh, epoch, { ...decide, decision: "resume" });
    return drive(entry);
  }

  async function recordRecovered(row, epoch, details) {
    await withTransaction(db, async (tx) => {
      await repo.recordEvent(
        {
          tenantId: row.tenantId,
          executionId: row.id,
          type: "recovered",
          leaseEpoch: epoch,
          correlationId: row.correlationId ?? undefined,
          details,
        },
        tx,
      );
      await audit(tx, row, AUDIT.RECOVERED, details);
    });
  }

  // ------------------------------------------------------------------------------------------------ entry points

  /** Claims one candidate and, when it wins, prepares it. */
  async function claimAndStart(candidate) {
    const claim = await claimOne(candidate);
    if (claim.outcome === "claimed") {
      const entry = ownIt(claim.row, claim.row.leaseEpoch);
      return runPrepare(claim.row, entry);
    }
    if (claim.outcome === "invalid") {
      ownIt(claim.row, claim.row.leaseEpoch);
      return failPrepare(claim.row, claim.row.leaseEpoch, claim.reason);
    }
    return claim;
  }

  /**
   * One sweeper tick (§6.4), in the order of the spec: the first-enable sweep (claims wait for it), expiry, claim with
   * per-tenant fairness, reclaim of expired leases, then one drive pass over the executions this process holds.
   */
  async function tick() {
    if (ticking) return;
    ticking = true;
    try {
      const ready = await ensureFirstEnableSweep();
      if (ready) {
        await expireStale();
        const candidates = await repo.peekQueued({
          limit: ex.sweepBatchSize,
          maxPerTenant: ex.maxPerTenantPerTick,
        });
        for (const candidate of candidates)
          await claimAndStart({ tenantId: candidate.tenantId, executionId: candidate.id });
      }
      for (const expired of await repo.peekExpiredLeases({ limit: ex.sweepBatchSize }))
        await reclaimOne(expired);
      for (const entry of [...owned.values()]) {
        const row = await repo.findExecution({
          tenantId: entry.tenantId,
          executionId: entry.executionId,
        });
        if (row?.status === "running") await drive(entry);
      }
    } finally {
      ticking = false;
    }
  }

  /** Renews the lease of every execution this process holds; a failed renewal means the lease is lost: stop at once. */
  async function heartbeat() {
    for (const entry of [...owned.values()]) {
      const { renewed } = await repo.renewLease({
        tenantId: entry.tenantId,
        executionId: entry.executionId,
        workerId: id,
        leaseEpoch: entry.epoch,
        leaseTtlSeconds: ex.leaseTtlSeconds,
      });
      if (!renewed) {
        log.warn(
          { executionId: entry.executionId, leaseEpoch: entry.epoch },
          "Lease lost; stopping work on this execution",
        );
        forget(entry.executionId);
        continue;
      }
      // safe point: a cancel request recorded while this execution is still preparing stops the fetch (ER-14)
      const lifecycle = await repo.readLifecycle({
        tenantId: entry.tenantId,
        executionId: entry.executionId,
      });
      if (lifecycle?.status === "preparing" && lifecycle.cancelRequestedAt)
        entry.cancelController.abort();
    }
  }

  /**
   * A cancel request reached an execution this process holds: a preparing one stops its fetch at the next safe point (the
   * cancel signal), a running one gets a drive pass now. The database row is read again; the message is never the authority.
   */
  async function onCancelRequested(entry) {
    const lifecycle = await repo.readLifecycle({
      tenantId: entry.tenantId,
      executionId: entry.executionId,
    });
    if (!lifecycle || lifecycle.leaseEpoch !== entry.epoch) return forget(entry.executionId); // the lease is lost
    if (!lifecycle.cancelRequestedAt) return;
    if (lifecycle.status === "preparing") entry.cancelController.abort();
    else if (lifecycle.status === "running") await drive(entry);
  }

  /**
   * The consumer handler of queue `pipeline` (flag on). The messages are WAKE-UPS: the execution row is the truth and the
   * claim is a compare-and-set, so a duplicate or a stale message does nothing (`processed_messages` stops the same
   * message twice, the claim and the lease epoch stop two workers on one execution).
   */
  async function handler(envelope, context) {
    const tenantId = envelope.tenantId;
    const executionId = envelope.payload?.executionId;
    if (envelope.type === "pipeline.execution.requested") {
      if (!(await ensureFirstEnableSweep())) return; // the claim waits for the sweep; the sweeper picks the row up
      const outcome = await claimAndStart({ tenantId, executionId });
      context?.log?.info?.({ outcome: outcome.outcome }, "Execution request handled");
    } else if (envelope.type === "scan.task.completed") {
      const entry = owned.get(executionId);
      if (entry && entry.tenantId === tenantId) await drive(entry);
    } else if (envelope.type === "pipeline.execution.cancel_requested") {
      // A wake-up only: the cancel columns are the signal and the lease holder honours them (ER-14). A process that does not
      // hold the lease does nothing; the holder's heartbeat and tick find the request anyway.
      const entry = owned.get(executionId);
      if (entry && entry.tenantId === tenantId) await onCancelRequested(entry);
      context?.log?.info?.({ type: envelope.type }, "Cancel wake-up handled");
    } else {
      context?.log?.info?.({ type: envelope.type }, "Wake-up acknowledged");
    }
  }

  /** Starts the heartbeat and the sweeper tick. Returns the stop function for `runWorker`'s `onReady`. */
  function start() {
    const run = (name, fn) => () =>
      fn().catch((error) => {
        const transient = error instanceof TransientError;
        log[transient ? "warn" : "error"](
          { err: error?.message, task: name },
          "Orchestrator pass failed",
        );
      });
    const beat = setInterval(run("heartbeat", heartbeat), ex.heartbeatSeconds * 1000);
    const sweep = setInterval(run("tick", tick), ex.sweepIntervalSeconds * 1000);
    run("tick", tick)();
    return async () => {
      clearInterval(beat);
      clearInterval(sweep);
      for (const entry of owned.values()) entry.controller.abort();
    };
  }

  return Object.freeze({
    workerId: id,
    handler,
    tick,
    heartbeat,
    start,
    claimAndStart,
    drive,
    reclaimOne,
    ensureFirstEnableSweep,
    /** The executions this process holds the lease of (tests, diagnostics). */
    owned: () =>
      [...owned.values()].map(({ tenantId, executionId, epoch }) => ({
        tenantId,
        executionId,
        epoch,
      })),
    /** Simulates a process that stopped heartbeating (tests): forgets everything without touching the database. */
    abandonAll: () => [...owned.keys()].forEach(forget),
  });
}
