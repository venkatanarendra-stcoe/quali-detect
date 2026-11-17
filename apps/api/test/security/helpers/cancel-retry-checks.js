import { randomUUID } from "node:crypto";
import { parseMessage } from "@qmentisai/contracts";
import {
  createEntitlementRepository,
  createEntitlementService,
  createOutboxRepository,
} from "@qmentisai/db";
import { createOutbox } from "@qmentisai/infra";
import { createAuditService } from "../../../src/audit/audit-service.js";
import {
  createExecutionService,
  createExecutionsRepository,
} from "../../../src/modules/executions/index.js";
import { CONFIG_SCHEMA } from "../../../../workers/src/pipeline/execution-request.js";
import { driveExecution } from "./execution-db.js";
import { sleep } from "./orchestrator.js";

/**
 * Cancellation and retry checks (ADR-008, docs/modules/executions/SPEC.md §14.1 EXE-008..010, part D): the service layer of
 * `apps/api/src/modules/executions` (HTTP routes are part G) and the worker side that honours a cancel request, IN PROCESS
 * against the disposable database, the local GitHub stub and the deterministic test engine of `orchestrator.js`. The scope
 * stays the security properties: tenant isolation (another tenant's execution is a 404), quota released exactly once under
 * concurrent cancels and a cancel racing the claim and the lease reclaim, and retry never bypassing a gate, a quota or the
 * trust of a fork. Timing of the grace period is covered only as far as it separates graceful from immediate. Every denial is
 * paired with a control so no denial is vacuous.
 */

const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const TOKEN_SHAPES =
  /ghs_stub_|ghu_stub_|BEGIN (RSA )?PRIVATE KEY|authorization|secretRef|Bearer /i;
const BASE_ENTRIES = [
  { name: "README.md", content: "# repo\n" },
  { name: "src", dir: true },
  { name: "src/a.js", content: "console.log(1)\n" },
];
export const withScript = (obj) => [
  ...BASE_ENTRIES,
  { name: "qm-test.json", content: JSON.stringify(obj) },
];
export const currentPeriod = () => new Date().toISOString().slice(0, 7);
export const CTX = { log: { info() {}, warn() {}, error() {} }, attempt: 1 };

export const attemptOf = async (fn) => {
  try {
    return { value: await fn() };
  } catch (error) {
    return { error };
  }
};
/** Whether every promise settles within `ms` (a handler that never returns is a failure, not a hang of the suite). */
export const within = (promises, ms) =>
  Promise.race([Promise.all(promises).then(() => true), sleep(ms).then(() => false)]);
const reasonOf = (r) => r.error?.details?.reason ?? null;
const isNotFound = (r) => r.error?.statusCode === 404 && r.error?.code === "RESOURCE_NOT_FOUND";

/** The service under test, wired like the module will be (real audit, outbox and entitlements over the disposable database). */
export function serviceOf(w, over = {}) {
  return createExecutionService({
    repository: createExecutionsRepository({ db: w.db }),
    audit: createAuditService({ db: w.db, logger: w.logger }),
    outbox: createOutbox({ repository: createOutboxRepository({ db: w.db }) }),
    entitlements: createEntitlementService({
      repository: createEntitlementRepository({ db: w.db }),
    }),
    config: { cancelGraceSeconds: 30, abortGraceSeconds: 30, retryChainMax: 5, ...over },
  });
}
export const actorOf = (tree, user = tree.user) => ({
  tenantId: tree.tenant.id,
  userId: user.id,
  requestId: randomUUID(),
  ip: "127.0.0.1",
});
/** An orchestrator whose lease does not expire while a scenario waits for a slow task. */
export const orchestratorOf = (w, opts) =>
  w.orchestrator({ EXECUTION_LEASE_TTL_SECONDS: "60" }, opts);

export async function until(fn, ms = 20000) {
  const start = Date.now();
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() - start > ms) return null;
    await sleep(100);
  }
}
/** Hands the pending task jobs of a tenant to the scan handler WITHOUT waiting for them; returns the running promises. */
export async function startTasks(w, tree, scan) {
  const rows = await w.db.outboxMessage.findMany({
    where: {
      tenantId: tree.tenant.id,
      status: "pending",
      queue: { in: ["scan", "scan-untrusted"] },
      type: "scan.task.requested",
    },
    orderBy: { createdAt: "asc" },
  });
  const started = [];
  for (const row of rows) {
    await w.db.outboxMessage.update({
      where: { id: row.id },
      data: { status: "sent", sentAt: new Date() },
    });
    const message = parseMessage(row.payload);
    await w.verify(message);
    started.push(
      scan(message, CTX).then(
        () => null,
        (error) => error,
      ),
    );
  }
  return started;
}
/** Delivers the `pipeline.execution.cancel_requested` wake-up of an execution to the orchestrator (the broker's job). */
export async function deliverCancelWakeup(w, tree, e, orch) {
  const rows = (
    await w.db.outboxMessage.findMany({
      where: {
        tenantId: tree.tenant.id,
        status: "pending",
        type: "pipeline.execution.cancel_requested",
      },
    })
  ).filter((r) => r.payload.executionId === e.id);
  for (const row of rows) {
    await w.db.outboxMessage.update({
      where: { id: row.id },
      data: { status: "sent", sentAt: new Date() },
    });
    const message = parseMessage(row.payload);
    await w.verify(message);
    await orch.handler(message, CTX);
  }
  return rows.length;
}
export const tasksOf = (w, e) =>
  w.db.scanTask.findMany({ where: { executionId: e.id }, orderBy: { ordinal: "asc" } });
const attemptsOf = (w, e) =>
  w.db.scanTaskAttempt.findMany({
    where: { executionId: e.id },
    orderBy: [{ scanTaskId: "asc" }, { attempt: "asc" }],
  });
const auditOf = (w, tree, action, e) => w.audit(tree, { action, ...(e ? { targetId: e.id } : {}) });
const countRows = async (w, tree) => ({
  executions: await w.db.execution.count({ where: { tenantId: tree.tenant.id } }),
  outbox: await w.db.outboxMessage.count({ where: { tenantId: tree.tenant.id } }),
  audit: await w.db.auditLog.count({ where: { tenantId: tree.tenant.id } }),
});
const sameCounts = (a, b) => JSON.stringify(a) === JSON.stringify(b);
/** Finishes the executions of a scenario cleanly so none keeps a lease another check could reclaim. */
export async function settle(w, tree, orchs, scan) {
  for (let round = 0; round < 6; round += 1) {
    for (const orch of orchs) await w.pump(tree, { orch, scan });
    const open = await w.db.execution.count({
      where: { tenantId: tree.tenant.id, status: { in: ["preparing", "running"] } },
    });
    if (open === 0) return true;
    for (const orch of orchs)
      for (const entry of orch.owned().filter((o) => o.tenantId === tree.tenant.id))
        await orch.drive(entry);
    await sleep(200);
  }
  return false;
}
/** A published second configuration version, made the pipeline's current one. */
async function publishVersion(w, tree, config, n) {
  const stored = CONFIG_SCHEMA.parse(config);
  const version = await w.version(tree.pipeline, stored, n);
  await w.db.pipeline.update({
    where: { id: tree.pipeline.id },
    data: { currentVersion: n, currentVersionId: version.id },
  });
  return version;
}
/** A tenant whose `scans.monthly` limit is `limit` with `used` units already spent in the current month. */
async function limitedTree(w, label, limit, used, config) {
  const tree = await w.tree(label, { entitled: false, ...(config ? { config } : {}) });
  const entitlement = await w.db.entitlementCatalog.findUnique({ where: { key: "scans.monthly" } });
  await w.db.tenantEntitlement.create({
    data: {
      tenantId: tree.tenant.id,
      entitlementId: entitlement.id,
      enabled: true,
      limitValue: BigInt(limit),
    },
  });
  await w.setQuotaUsage(tree, used, currentPeriod());
  return tree;
}
/** A configuration whose concurrency policy keeps queued siblings (the default `supersede` would cancel an earlier retry). */
const queueing = (w) =>
  w.config1({
    execution: {
      timeoutSeconds: 120,
      scanTaskTimeoutSeconds: 60,
      concurrency: { policy: "queue", maxQueued: 50, maxActive: 1 },
    },
  });
const failed = async (w, tree, over = {}, status = "failed", reason = "tasks_failed") => {
  const e = await w.execution(tree, over);
  await driveExecution(w.db, e.id, status, reason);
  return w.row(e);
};

export const CANCEL_RETRY_CHECKS = [
  {
    id: "EXE-037",
    name: "quota released exactly once on cancel of a queued execution (SPEC EXE-009): N parallel cancels of one queued execution end with exactly one cancelled outcome, usage down by exactly the consumed unit, quota_released_at set once, one transition event, one cancel_requested and one cancelled audit entry and one status hint, the losers answer already_finished and release nothing; cancels racing the claim leave every execution with one terminal outcome and usage equal to the start minus the rows that released (a claimed execution never refunds, a cancelled-while-preparing one refunds once, never twice); an execution that consumed no unit releases none; another tenant's usage and queued row are untouched; a single cancel releases one unit",
    async run(w) {
      const p = [];
      const svc = serviceOf(w);
      const tree = await w.tree("cq1");
      const other = await w.tree("cq2");
      const otherExec = await w.execution(other);
      await w.setQuotaUsage(other, 7);
      await w.setQuotaUsage(tree, 10);
      const actor = actorOf(tree);
      // (a) eight parallel cancels of one queued execution
      const a = await w.execution(tree);
      const results = await Promise.all(
        Array.from({ length: 8 }, () => attemptOf(() => svc.cancel(actor, { id: a.id }))),
      );
      const wins = results.filter((r) => r.value?.outcome === "cancelled");
      ok(p, wins.length === 1, `${wins.length} cancels won, not exactly one`);
      ok(
        p,
        results.filter((r) => reasonOf(r) === "already_finished").length === 7,
        "the losing cancels did not all answer already_finished",
      );
      const rowA = await w.row(a);
      ok(
        p,
        rowA.status === "cancelled" && rowA.statusReason === "user_cancelled",
        `status ${rowA.status}`,
      );
      ok(p, rowA.quotaReleasedAt !== null, "quota_released_at was not set");
      ok(
        p,
        (await w.quotaUsage(tree)) === 9,
        `usage ${await w.quotaUsage(tree)}, expected 9 (one unit back)`,
      );
      const transitions = (await w.events(a)).filter((e) => e.type === "transition");
      ok(
        p,
        transitions.length === 1 && transitions[0].toStatus === "cancelled",
        "not exactly one transition event",
      );
      ok(
        p,
        transitions[0]?.actorType === "user" && transitions[0]?.actorUserId === tree.user.id,
        "the transition event lacks the user actor",
      );
      ok(
        p,
        (await auditOf(w, tree, "execution.cancelled", a)).length === 1,
        "not exactly one execution.cancelled entry",
      );
      ok(
        p,
        (await auditOf(w, tree, "execution.cancel_requested", a)).length === 1,
        "not exactly one execution.cancel_requested entry",
      );
      const hints = (await w.outbox(tree, { type: "pipeline.execution.status_changed" })).filter(
        (m) => m.payload.executionId === a.id && m.payload.payload.status === "cancelled",
      );
      ok(p, hints.length === 1, `${hints.length} status hints for the cancel`);
      // (b) a cancel of an execution that consumed no unit releases none
      const free = await w.execution(tree, { quotaConsumed: 0, quotaPeriod: null });
      const before = await w.quotaUsage(tree);
      const rFree = await attemptOf(() => svc.cancel(actor, { id: free.id }));
      const rowFree = await w.row(free);
      ok(
        p,
        rFree.value?.outcome === "cancelled" && rowFree.status === "cancelled",
        "the unmetered cancel did not cancel",
      );
      ok(
        p,
        rowFree.quotaReleasedAt === null && (await w.quotaUsage(tree)) === before,
        "a unit was released for an unmetered execution",
      );
      // (c) cancels racing the claim
      const start = await w.quotaUsage(tree);
      const orch = orchestratorOf(w);
      const raced = [];
      for (let i = 0; i < 6; i += 1) raced.push(await w.execution(tree));
      const startUsage = await w.quotaUsage(tree);
      ok(p, startUsage === start, "fixture rows changed the usage");
      await Promise.all(
        raced.map((e) =>
          Promise.all([
            orch.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id }),
            attemptOf(() => svc.cancel(actor, { id: e.id })),
            attemptOf(() => svc.cancel(actor, { id: e.id })),
          ]),
        ),
      );
      ok(p, await settle(w, tree, [orch]), "the raced executions did not all finish");
      let released = 0;
      for (const e of raced) {
        const row = await w.row(e);
        const terminal = ["cancelled", "succeeded", "failed", "partial", "timed_out"].includes(
          row.status,
        );
        ok(p, terminal, `a raced execution is ${row.status}`);
        const terminalEvents = (await w.events(e)).filter(
          (ev) =>
            ev.type === "transition" &&
            ["cancelled", "succeeded", "failed", "partial", "timed_out"].includes(ev.toStatus),
        );
        ok(
          p,
          terminalEvents.length === 1,
          `${terminalEvents.length} terminal transitions for one execution`,
        );
        if (row.quotaReleasedAt) {
          released += 1;
          ok(
            p,
            row.status === "cancelled",
            "a unit was refunded for an execution that was not cancelled",
          );
          ok(
            p,
            (await tasksOf(w, e)).length === 0,
            "a unit was refunded for an execution that had started tasks",
          );
        }
        if (row.status === "cancelled" && !row.quotaReleasedAt) {
          // cancelled while running: the unit is consumed, the request is recorded
          ok(
            p,
            row.cancelRequestedAt !== null,
            "cancelled while running without a recorded request",
          );
        }
        ok(p, (await w.completed(tree, e)).length <= 1, "more than one completed event");
      }
      const finalUsage = await w.quotaUsage(tree);
      ok(
        p,
        finalUsage === startUsage - released,
        `usage ${finalUsage}, expected ${startUsage - released}`,
      );
      ok(
        p,
        finalUsage >= startUsage - raced.length,
        "usage fell below the start by more than the executions",
      );
      // (d) the other tenant is untouched
      ok(p, (await w.quotaUsage(other)) === 7, "another tenant's usage changed");
      ok(p, (await w.statusOf(otherExec)) === "queued", "another tenant's execution changed");
      // control: a single cancel releases one unit
      const single = await w.execution(tree);
      const beforeSingle = await w.quotaUsage(tree);
      const rs = await attemptOf(() => svc.cancel(actor, { id: single.id }));
      ok(
        p,
        rs.value?.outcome === "cancelled" && (await w.quotaUsage(tree)) === beforeSingle - 1,
        "control: a single cancel did not release exactly one unit",
      );
      return p;
    },
  },
  {
    id: "EXE-038",
    name: "immediate cancel of a running execution (SPEC EXE-010): the request answers cancel_requested and only records the columns (the requester writes no terminal state), the mode comes from the SNAPSHOT (immediate) and no client input exists, a second request moves nothing and writes no second event, audit entry or message; tasks that have not started never start and become cancelled, tasks mid-run are aborted at once (their attempt closes cancelled with the partial result kept as incomplete) although the abort grace has not passed, the execution ends cancelled user_cancelled with no quota refund and one completed event, and a cancel of the finished execution is already_finished and changes nothing",
    async run(w) {
      const p = [];
      const svc = serviceOf(w, { abortGraceSeconds: 20 });
      const tree = await w.tree("cimm", {
        config: w.config1({
          execution: { timeoutSeconds: 120, scanTaskTimeoutSeconds: 60, cancellation: "immediate" },
        }),
      });
      await w.setQuotaUsage(tree, 5);
      const e = await w.execution(tree, { entries: withScript({ slow: ["sbom", "sca"] }) });
      const actor = actorOf(tree);
      const orch = orchestratorOf(w);
      const scan = w.scanHandler();
      await orch.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
      const running = await startTasks(w, tree, scan);
      ok(p, running.length === 2, `${running.length} tasks were dispatched`);
      ok(
        p,
        !!(await until(
          async () => (await tasksOf(w, e)).filter((t) => t.status === "running").length === 2,
        )),
        "the two tasks did not start",
      );
      const before = Date.now();
      const first = await attemptOf(() => svc.cancel(actor, { id: e.id }));
      ok(
        p,
        first.value?.outcome === "cancel_requested" && first.value.alreadyRequested === false,
        `first answer ${first.value?.outcome ?? first.error?.message}`,
      );
      const afterRequest = await w.row(e);
      ok(p, afterRequest.status === "running", "the requester wrote a terminal state");
      ok(
        p,
        afterRequest.cancelRequestedByUserId === tree.user.id &&
          afterRequest.cancelMode === "immediate" &&
          afterRequest.cancelRequestedAt !== null,
        "the request columns are wrong",
      );
      const immediateGrace =
        (afterRequest.cancelGraceUntil - afterRequest.cancelRequestedAt) / 1000;
      ok(
        p,
        immediateGrace >= 19 && immediateGrace <= 21,
        `the abort grace of an immediate cancel is ${immediateGrace}s, not the configured 20`,
      );
      ok(p, afterRequest.quotaReleasedAt === null, "a running cancel released quota");
      const second = await attemptOf(() => svc.cancel(actor, { id: e.id }));
      const again = await w.row(e);
      ok(
        p,
        second.value?.outcome === "cancel_requested" &&
          second.value.alreadyRequested === true &&
          again.cancelRequestedAt.getTime() === afterRequest.cancelRequestedAt.getTime() &&
          again.cancelGraceUntil.getTime() === afterRequest.cancelGraceUntil.getTime(),
        "a second request moved the request or was not idempotent",
      );
      ok(
        p,
        (await auditOf(w, tree, "execution.cancel_requested", e)).length === 1,
        "a second request wrote a second audit entry",
      );
      ok(
        p,
        (await w.events(e, { type: "cancel_requested" })).length === 1,
        "a second request wrote a second event",
      );
      ok(
        p,
        (await deliverCancelWakeup(w, tree, e, orch)) === 1,
        "not exactly one cancel_requested message",
      );
      // nothing starts after the request, the unstarted tasks are cancelled
      const mid = await tasksOf(w, e);
      ok(
        p,
        mid.filter((t) => t.status === "cancelled").length === 2,
        "the unstarted tasks were not cancelled",
      );
      ok(p, await within(running, 20000), "the aborted scan handlers did not return");
      const outcome = await Promise.all(running);
      ok(
        p,
        outcome.every((x) => x === null),
        "a scan task handler failed",
      );
      ok(p, Date.now() - before < 25000, "the abort waited for the abort grace");
      ok(p, await settle(w, tree, [orch], scan), "the execution did not finish");
      const row = await w.row(e);
      ok(
        p,
        row.status === "cancelled" && row.statusReason === "user_cancelled",
        `final ${row.status}/${row.statusReason}`,
      );
      ok(
        p,
        row.quotaReleasedAt === null && (await w.quotaUsage(tree)) === 5,
        "a running cancel refunded the unit",
      );
      const tasks = await tasksOf(w, e);
      ok(
        p,
        tasks.length === 4 &&
          tasks.every((t) => t.status === "cancelled" && t.statusReason === "user_cancelled"),
        "not every task is cancelled user_cancelled",
      );
      const attempts = await attemptsOf(w, e);
      ok(
        p,
        attempts.length === 2 &&
          attempts.every((a) => a.status === "cancelled" && a.errorCode === "user_cancelled"),
        "the aborted attempts are not closed cancelled",
      );
      const results = await w.db.scanResult.findMany({ where: { executionId: e.id } });
      ok(
        p,
        results.length === 2 &&
          results.every((r) => r.completeness === "incomplete" && r.itemCount === 1),
        "the partial results were not kept as incomplete",
      );
      const completed = await w.completed(tree, e);
      ok(
        p,
        completed.length === 1 &&
          completed[0].payload.payload.status === "cancelled" &&
          completed[0].payload.payload.cancelRequested === true &&
          completed[0].payload.payload.resolutionEligible === false,
        "the completed event is wrong",
      );
      ok(
        p,
        (await auditOf(w, tree, "execution.cancelled", e)).length === 1,
        "not exactly one execution.cancelled entry",
      );
      // a cancel of the finished execution changes nothing
      const fp = await w.fingerprint(tree);
      const late = await attemptOf(() => svc.cancel(actor, { id: e.id }));
      ok(
        p,
        reasonOf(late) === "already_finished" && (await w.fingerprint(tree)) === fp,
        "a cancel of a finished execution was not a no-op conflict",
      );
      // (b) a task job that reaches the scan worker AFTER the request never starts (the claim itself refuses it)
      {
        const t2 = await w.tree("cimm2", { config: w.config1() });
        const e2 = await w.execution(t2);
        const orch2 = orchestratorOf(w);
        const scan2 = w.scanHandler();
        await orch2.claimAndStart({ tenantId: t2.tenant.id, executionId: e2.id });
        const queued = await tasksOf(w, e2);
        ok(
          p,
          queued.filter((t) => t.status === "queued").length === 2,
          "fixture: two task jobs should be queued",
        );
        const r2 = await attemptOf(() => svc.cancel(actorOf(t2), { id: e2.id }));
        ok(p, r2.value?.outcome === "cancel_requested", "(b) the request was not recorded");
        const late = await startTasks(w, t2, scan2);
        ok(p, await within(late, 10000), "(b) the late jobs did not return");
        ok(
          p,
          (await attemptsOf(w, e2)).length === 0 &&
            (await tasksOf(w, e2)).every((t) => t.status !== "running"),
          "(b) a task started after the cancel request",
        );
        await deliverCancelWakeup(w, t2, e2, orch2);
        ok(
          p,
          (await tasksOf(w, e2)).every((t) => t.status === "cancelled"),
          "(b) the holder left queued tasks of a cancelled execution alone",
        );
        ok(p, await settle(w, t2, [orch2], scan2), "(b) the execution did not finish");
        const done2 = await tasksOf(w, e2);
        ok(
          p,
          (await w.statusOf(e2)) === "cancelled" &&
            done2.every((t) => t.status === "cancelled" && t.statusReason === "user_cancelled"),
          "(b) the execution or its tasks are not cancelled",
        );
      }
      // (c) a request that arrives after every task finished does not turn the outcome into cancelled (table 5.4)
      {
        const t3 = await w.tree("cimm3", {
          config: w.config1({ scans: { sca: { enabled: true } } }),
        });
        const e3 = await w.execution(t3);
        const orch3 = orchestratorOf(w);
        const scan3 = w.scanHandler();
        await orch3.claimAndStart({ tenantId: t3.tenant.id, executionId: e3.id });
        ok(p, await within(await startTasks(w, t3, scan3), 10000), "(c) the task did not finish");
        const r3 = await attemptOf(() => svc.cancel(actorOf(t3), { id: e3.id }));
        ok(
          p,
          r3.value?.outcome === "cancel_requested" && (await w.statusOf(e3)) === "running",
          "(c) the request on a running execution with finished tasks was not recorded",
        );
        ok(p, await settle(w, t3, [orch3], scan3), "(c) the execution did not finish");
        const row3 = await w.row(e3);
        const completed3 = await w.completed(t3, e3);
        ok(
          p,
          row3.status === "succeeded" &&
            row3.cancelRequestedAt !== null &&
            completed3.length === 1 &&
            completed3[0].payload.payload.cancelRequested === true,
          `(c) the finished execution ended ${row3.status}`,
        );
        const late3 = await attemptOf(() => svc.cancel(actorOf(t3), { id: e3.id }));
        ok(
          p,
          reasonOf(late3) === "already_finished",
          "(c) a cancel after the outcome was not already_finished",
        );
      }
      return p;
    },
  },
  {
    id: "EXE-039",
    name: "graceful cancel (SPEC ER-14): the mode is the snapshot's graceful and the request records a grace deadline; tasks that have not started never start (cancelled); tasks mid-run are NOT aborted inside the grace period and finish with their complete results ingested; a task that outlives the grace period is aborted and keeps its partial result; no retry attempt starts after the request (a transient failure ends the task failed with no second attempt, while the same task without a cancel is retried); the execution ends cancelled and the request never refunds a running execution",
    async run(w) {
      const p = [];
      const graceful = {
        execution: { timeoutSeconds: 120, scanTaskTimeoutSeconds: 60, cancellation: "graceful" },
      };
      // G1: both running tasks finish inside a long grace period
      {
        const svc = serviceOf(w, { cancelGraceSeconds: 40 });
        const tree = await w.tree("cgr1", { config: w.config1(graceful) });
        const e = await w.execution(tree, {
          entries: withScript({ delay: { sbom: 2500, sca: 2500 } }),
        });
        const actor = actorOf(tree);
        const orch = orchestratorOf(w);
        const scan = w.scanHandler();
        await orch.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
        const running = await startTasks(w, tree, scan);
        await until(
          async () => (await tasksOf(w, e)).filter((t) => t.status === "running").length === 2,
        );
        const r = await attemptOf(() => svc.cancel(actor, { id: e.id }));
        const row = await w.row(e);
        ok(
          p,
          r.value?.outcome === "cancel_requested" && row.cancelMode === "graceful",
          "G1: the request is not a graceful cancel_requested",
        );
        const grace = (row.cancelGraceUntil - row.cancelRequestedAt) / 1000;
        ok(
          p,
          grace >= 39 && grace <= 41,
          `G1: the grace period is ${grace}s, not the configured 40`,
        );
        await deliverCancelWakeup(w, tree, e, orch);
        await sleep(1800);
        const mid = await tasksOf(w, e);
        ok(
          p,
          mid.filter((t) => t.status === "running").length === 2,
          "G1: a running task was aborted inside the grace period",
        );
        ok(
          p,
          mid.filter((t) => t.status === "cancelled").length === 2,
          "G1: the unstarted tasks were not cancelled",
        );
        ok(p, await within(running, 20000), "a scan handler did not return after the cancel");
        ok(p, await settle(w, tree, [orch], scan), "G1: the execution did not finish");
        const done = await tasksOf(w, e);
        ok(
          p,
          done.filter((t) => t.status === "succeeded").length === 2,
          "G1: the running tasks did not finish",
        );
        const results = await w.db.scanResult.findMany({ where: { executionId: e.id } });
        ok(
          p,
          results.length === 2 && results.every((x) => x.completeness === "complete"),
          "G1: the finished tasks' results were not ingested complete",
        );
        const attempts = await attemptsOf(w, e);
        ok(p, attempts.length === 2, "G1: a task started after the request");
        const final = await w.row(e);
        ok(
          p,
          final.status === "cancelled" &&
            final.statusReason === "user_cancelled" &&
            final.quotaReleasedAt === null,
          `G1: final ${final.status}`,
        );
      }
      // G2: a hung task is aborted when the grace period ends; a task that finishes inside it is kept
      {
        const svc = serviceOf(w, { cancelGraceSeconds: 2 });
        const tree = await w.tree("cgr2", { config: w.config1(graceful) });
        const e = await w.execution(tree, {
          entries: withScript({ slow: ["sbom"], delay: { sca: 500 } }),
        });
        const actor = actorOf(tree);
        const orch = orchestratorOf(w);
        const scan = w.scanHandler();
        await orch.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
        const running = await startTasks(w, tree, scan);
        await until(
          async () => (await tasksOf(w, e)).filter((t) => t.status === "running").length === 2,
        );
        const at = Date.now();
        await svc.cancel(actor, { id: e.id });
        await deliverCancelWakeup(w, tree, e, orch);
        ok(p, await within(running, 20000), "a scan handler did not return after the cancel");
        const waited = Date.now() - at;
        ok(
          p,
          waited >= 1500,
          `G2: the hung task was aborted after ${waited} ms, inside the grace period`,
        );
        ok(p, await settle(w, tree, [orch], scan), "G2: the execution did not finish");
        const done = await tasksOf(w, e);
        const sbom = done.find((t) => t.scanType === "sbom");
        const sca = done.find((t) => t.scanType === "sca");
        ok(
          p,
          sbom.status === "cancelled" && sca.status === "succeeded",
          `G2: sbom ${sbom.status}, sca ${sca.status}`,
        );
        const kept = await w.db.scanResult.findMany({ where: { scanTaskId: sbom.id } });
        ok(
          p,
          kept.length === 1 && kept[0].completeness === "incomplete",
          "G2: the aborted task's partial result was not kept",
        );
        ok(p, (await w.statusOf(e)) === "cancelled", "G2: the execution is not cancelled");
      }
      // G3: no retry attempt after the request; the control without a cancel is retried
      {
        const svc = serviceOf(w, { cancelGraceSeconds: 40 });
        const script = { delayThenTransient: { sbom: 1200 }, delay: { sca: 1600 } };
        const treeC = await w.tree("cgr3", { config: w.config1(graceful) });
        const e = await w.execution(treeC, { entries: withScript(script) });
        const orch = orchestratorOf(w);
        const scan = w.scanHandler();
        await orch.claimAndStart({ tenantId: treeC.tenant.id, executionId: e.id });
        const running = await startTasks(w, treeC, scan);
        await until(
          async () => (await tasksOf(w, e)).filter((t) => t.status === "running").length === 2,
        );
        await svc.cancel(actorOf(treeC), { id: e.id });
        await deliverCancelWakeup(w, treeC, e, orch);
        ok(p, await within(running, 20000), "a scan handler did not return after the cancel");
        ok(p, await settle(w, treeC, [orch], scan), "G3: the execution did not finish");
        const done = await tasksOf(w, e);
        const sbom = done.find((t) => t.scanType === "sbom");
        const attempts = (await attemptsOf(w, e)).filter((a) => a.scanTaskId === sbom.id);
        ok(
          p,
          sbom.status === "failed" && attempts.length === 1,
          `G3: sbom ${sbom.status} with ${attempts.length} attempts, a retry started after the request`,
        );
        ok(p, (await w.statusOf(e)) === "cancelled", "G3: the execution is not cancelled");
        // control: the same scripts without a cancel retry the transient failure
        const ctl = await w.tree("cgr3c", { config: w.config1(graceful) });
        const e2 = await w.execution(ctl, { entries: withScript(script) });
        await w.run(ctl, e2, { orch: orchestratorOf(w) });
        const sbom2 = (await tasksOf(w, e2)).find((t) => t.scanType === "sbom");
        const a2 = (await attemptsOf(w, e2)).filter((a) => a.scanTaskId === sbom2.id);
        ok(
          p,
          a2.length === 2,
          `control: the transient failure was attempted ${a2.length} times without a cancel`,
        );
      }
      return p;
    },
  },
  {
    id: "EXE-040",
    name: "cancel of a preparing execution and cancel racing the lease reclaim: a request recorded while the holder is fetching the code (the cancel is a request, no terminal write by the requester) ends the execution cancelled with NO task and the unit given back exactly once, one completed event; cancel requests racing two reclaimers of expired preparing leases leave every execution with one terminal outcome, at most one refund per execution (only if no task started), usage equal to the start minus the refunds, and a lease reclaimed with a request pending is honoured as cancelled rather than resumed",
    async run(w) {
      const p = [];
      const svc = serviceOf(w);
      // (a) the request arrives while the holder fetches the archive
      {
        const tree = await w.tree("cprep");
        await w.setQuotaUsage(tree, 3);
        const e = await w.execution(tree);
        const actor = actorOf(tree);
        let answer = null;
        const store = {
          ...w.store,
          put: async (...args) => {
            answer = await attemptOf(() => svc.cancel(actor, { id: e.id }));
            return w.store.put(...args);
          },
        };
        const orch = orchestratorOf(w, { store });
        const claim = await orch.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
        ok(
          p,
          answer?.value?.outcome === "cancel_requested" &&
            answer.value.execution.status === "preparing",
          `the request answered ${answer?.value?.outcome ?? answer?.error?.message}`,
        );
        ok(p, claim.outcome === "cancelled", `the preparation ended ${claim.outcome}`);
        const row = await w.row(e);
        ok(
          p,
          row.status === "cancelled" && row.statusReason === "user_cancelled",
          `final ${row.status}/${row.statusReason}`,
        );
        ok(
          p,
          row.quotaReleasedAt !== null && (await w.quotaUsage(tree)) === 2,
          "the unit was not given back exactly once",
        );
        ok(p, (await tasksOf(w, e)).length === 0, "tasks were created for a cancelled preparation");
        const completed = await w.completed(tree, e);
        ok(
          p,
          completed.length === 1 && completed[0].payload.payload.cancelRequested === true,
          "the completed event is wrong",
        );
        ok(
          p,
          (await w.events(e, { type: "cancel_requested" })).length === 1,
          "not exactly one cancel_requested event",
        );
      }
      // (b) the request races two reclaimers
      {
        const tree = await w.tree("cprec");
        await w.setQuotaUsage(tree, 10);
        const actor = actorOf(tree);
        const execs = [];
        for (let i = 0; i < 4; i += 1) {
          const e = await w.execution(tree);
          await w.repo.claimQueued({
            tenantId: tree.tenant.id,
            executionId: e.id,
            workerId: "dead-claimer",
            leaseTtlSeconds: 1,
            deadlineSeconds: 600,
            staleThresholdSeconds: 36 * 3600,
          });
          execs.push(e);
        }
        await sleep(1500);
        const a = orchestratorOf(w);
        const b = orchestratorOf(w);
        const scan = w.scanHandler();
        await Promise.all(
          execs.map((e) =>
            Promise.all([
              attemptOf(() => svc.cancel(actor, { id: e.id })),
              a.reclaimOne({ tenantId: tree.tenant.id, id: e.id, leaseEpoch: 1 }),
              b.reclaimOne({ tenantId: tree.tenant.id, id: e.id, leaseEpoch: 1 }),
            ]),
          ),
        );
        ok(p, await settle(w, tree, [a, b], scan), "the reclaimed executions did not all finish");
        let released = 0;
        for (const e of execs) {
          const row = await w.row(e);
          const terminal = (await w.events(e)).filter(
            (ev) =>
              ev.type === "transition" &&
              ["cancelled", "succeeded", "failed", "partial", "timed_out"].includes(ev.toStatus),
          );
          ok(p, terminal.length === 1, `${terminal.length} terminal transitions for one execution`);
          if (row.quotaReleasedAt) {
            released += 1;
            ok(
              p,
              row.status === "cancelled" && (await tasksOf(w, e)).length === 0,
              "a refund for an execution that started tasks or was not cancelled",
            );
          }
          ok(p, (await w.completed(tree, e)).length <= 1, "more than one completed event");
        }
        ok(
          p,
          (await w.quotaUsage(tree)) === 10 - released,
          `usage ${await w.quotaUsage(tree)}, expected ${10 - released}`,
        );
      }
      // (d) the request arrives in the narrowest window: after the last safe point of the fetch, right before the transaction
      // that would create the tasks (the database proxy runs the cancel as the first transaction after the fetch session closed)
      {
        const tree = await w.tree("cprep3");
        await w.setQuotaUsage(tree, 6);
        const e = await w.execution(tree);
        const actor = actorOf(tree);
        let armed = false;
        let answer = null;
        const github = {
          ...w.github,
          openSourceSession: async (args) => {
            const session = await w.github.openSourceSession(args);
            return {
              ...session,
              close: () => {
                armed = true;
                return session.close();
              },
            };
          },
        };
        const proxy = new Proxy(w.db, {
          get(target, prop) {
            if (prop === "$transaction")
              return async (...args) => {
                if (armed) {
                  armed = false;
                  answer = await attemptOf(() => svc.cancel(actor, { id: e.id }));
                }
                return target.$transaction(...args);
              };
            const value = target[prop];
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
        const orch = orchestratorOf(w, { github, db: proxy });
        const claim = await orch.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
        ok(
          p,
          answer?.value?.outcome === "cancel_requested",
          `(d) the request answered ${answer?.value?.outcome ?? answer?.error?.message}`,
        );
        const row = await w.row(e);
        ok(
          p,
          claim.outcome === "cancelled" &&
            row.status === "cancelled" &&
            row.quotaReleasedAt !== null,
          `(d) the execution ended ${row.status} (${claim.outcome}), not cancelled while preparing with its unit back`,
        );
        ok(
          p,
          (await tasksOf(w, e)).length === 0 && (await w.quotaUsage(tree)) === 5,
          "(d) tasks were created or the unit was not given back once",
        );
      }
      // (e) a cancel wake-up that reaches a holder whose lease was reclaimed does nothing: the new holder honours the request once
      {
        const tree = await w.tree("cstale");
        const e = await w.execution(tree, { entries: withScript({ slow: ["sbom", "sca"] }) });
        const a = w.orchestrator();
        await a.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
        await sleep(4600);
        const b = orchestratorOf(w);
        await b.reclaimOne({ tenantId: tree.tenant.id, id: e.id, leaseEpoch: 1 });
        const r = await attemptOf(() => svc.cancel(actorOf(tree), { id: e.id }));
        ok(p, r.value?.outcome === "cancel_requested", "(e) the request was not recorded");
        const stale = await attemptOf(() => deliverCancelWakeup(w, tree, e, a));
        ok(p, !stale.error, `(e) the wake-up broke the stale holder: ${stale.error?.message}`);
        ok(p, a.owned().length === 0, "(e) the stale holder still believes it owns the execution");
        ok(
          p,
          await settle(w, tree, [b], w.scanHandler()),
          "(e) the new holder did not finish the execution",
        );
        const row = await w.row(e);
        ok(
          p,
          row.status === "cancelled" && row.statusReason === "user_cancelled",
          `(e) final ${row.status}`,
        );
        ok(p, (await w.completed(tree, e)).length === 1, "(e) not exactly one completed event");
        ok(
          p,
          (await auditOf(w, tree, "execution.cancelled", e)).length === 1,
          "(e) not exactly one execution.cancelled entry",
        );
      }
      // (f) a fetch that hangs is stopped by the holder's heartbeat as soon as it sees the request (the cancel signal)
      {
        const tree = await w.tree("cprep4");
        await w.setQuotaUsage(tree, 8);
        const e = await w.execution(tree);
        let downloading = false;
        const github = {
          ...w.github,
          openSourceSession: async (args) => ({
            ...(await w.github.openSourceSession(args)),
            downloadArchive: ({ signal }) =>
              new Promise((_resolve, reject) => {
                downloading = true;
                signal.addEventListener("abort", () => reject(signal.reason), { once: true });
              }),
          }),
        };
        const orch = orchestratorOf(w, { github });
        const start = orch.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
        ok(p, !!(await until(() => downloading)), "(f) the fetch never started");
        const r = await attemptOf(() => svc.cancel(actorOf(tree), { id: e.id }));
        ok(p, r.value?.outcome === "cancel_requested", "(f) the request was not recorded");
        await orch.heartbeat();
        const ended = await Promise.race([start, sleep(15000).then(() => null)]);
        ok(
          p,
          ended?.outcome === "cancelled",
          `(f) the hung fetch was not stopped (${ended?.outcome ?? "still running"})`,
        );
        const row = await w.row(e);
        ok(
          p,
          row.status === "cancelled" &&
            row.quotaReleasedAt !== null &&
            (await w.quotaUsage(tree)) === 7,
          `(f) final ${row.status}`,
        );
      }
      // (c) deterministic: a lease reclaimed with the request already recorded is honoured, not resumed
      {
        const tree = await w.tree("cprec2");
        await w.setQuotaUsage(tree, 4);
        const e = await w.execution(tree);
        await w.repo.claimQueued({
          tenantId: tree.tenant.id,
          executionId: e.id,
          workerId: "dead-claimer",
          leaseTtlSeconds: 1,
          deadlineSeconds: 600,
          staleThresholdSeconds: 36 * 3600,
        });
        const r = await attemptOf(() => svc.cancel(actorOf(tree), { id: e.id }));
        ok(
          p,
          r.value?.outcome === "cancel_requested" && (await w.statusOf(e)) === "preparing",
          "the request on a preparing execution was not only recorded",
        );
        await sleep(1500);
        const orch = orchestratorOf(w);
        await orch.reclaimOne({ tenantId: tree.tenant.id, id: e.id, leaseEpoch: 1 });
        const row = await w.row(e);
        ok(
          p,
          row.status === "cancelled" &&
            row.statusReason === "user_cancelled" &&
            row.quotaReleasedAt !== null,
          `the reclaim ended ${row.status}`,
        );
        ok(
          p,
          (await w.quotaUsage(tree)) === 3 && (await tasksOf(w, e)).length === 0,
          "the reclaimed cancel did not refund once or created tasks",
        );
      }
      return p;
    },
  },
  {
    id: "EXE-041",
    name: "retry creates a NEW execution that pins the original commit and snapshot (SPEC EXE-008, ER-22): after the pipeline published another version, the retry of a failed push, schedule, manual-by-someone-else and blocked execution is a queued row with the ORIGINAL config version id and hash, the original's pinned commit SHA, ref, trigger and concurrency group, retry_of_execution_id, scan_kind_reason retry and the retrying user, one fresh quota unit, one pipeline.execution.requested message carrying the pinned SHA and original hash, one execution.retry_requested audit entry and event; the original row is unchanged; the new execution runs the OLD snapshot's tasks; a retry of a fork pull request stays untrusted_fork and incremental, goes to the scan-untrusted queue and no credential appears anywhere",
    async run(w) {
      const p = [];
      const svc = serviceOf(w);
      const tree = await w.tree("rtp");
      const actor = actorOf(tree);
      const reviewer = await w.db.user.create({
        data: { email: `rtp-b-${randomUUID()}@orch.example`, name: "B" },
      });
      // the original: failed, commit pinned; then the pipeline publishes a DIFFERENT version
      const orig = await failed(w, tree, { entries: BASE_ENTRIES });
      await publishVersion(
        w,
        tree,
        w.config1({
          scans: { sca: { enabled: true } },
          execution: { timeoutSeconds: 900, scanTaskTimeoutSeconds: 300 },
        }),
        2,
      );
      const origFingerprint = JSON.stringify(orig, (_k, v) =>
        typeof v === "bigint" ? v.toString() : v,
      );
      const usageBefore = await w.quotaUsage(tree, currentPeriod());
      const r = await attemptOf(() => svc.retry(actor, { id: orig.id }, "retry-key-1"));
      ok(p, !!r.value, `the retry failed: ${r.error?.message}`);
      if (!r.value) return p;
      const fresh = await w.row(r.value.execution);
      ok(
        p,
        fresh.id !== orig.id && fresh.status === "queued" && fresh.retryOfExecutionId === orig.id,
        "the retry is not a new queued execution pointing at the original",
      );
      ok(
        p,
        fresh.configVersionId === orig.configVersionId &&
          fresh.configHash === orig.configHash &&
          fresh.configVersion === orig.configVersion,
        "the retry does not use the original snapshot",
      );
      const current = await w.db.pipeline.findUnique({ where: { id: tree.pipeline.id } });
      ok(
        p,
        current.currentVersionId !== orig.configVersionId,
        "fixture: the pipeline's current version is not another one",
      );
      ok(
        p,
        fresh.commitSha === orig.commitSha && orig.commitSha !== null,
        "the retry does not pin the original commit",
      );
      ok(
        p,
        fresh.refType === orig.refType &&
          fresh.refName === orig.refName &&
          fresh.triggerType === orig.triggerType &&
          fresh.triggerKey === orig.triggerKey &&
          fresh.concurrencyGroup === orig.concurrencyGroup &&
          fresh.scanKind === orig.scanKind &&
          fresh.trust === orig.trust,
        "the retry changed the ref, trigger, group, scan kind or trust",
      );
      ok(
        p,
        fresh.scanKindReason === "retry" && fresh.requestedByUserId === tree.user.id,
        "scan_kind_reason or the requesting user is wrong",
      );
      ok(
        p,
        fresh.quotaConsumed === 1 &&
          fresh.quotaPeriod === currentPeriod() &&
          (await w.quotaUsage(tree, currentPeriod())) === usageBefore + 1,
        "the retry did not consume exactly one fresh unit",
      );
      const requested = (await w.outbox(tree, { type: "pipeline.execution.requested" })).filter(
        (m) => m.payload.executionId === fresh.id,
      );
      ok(
        p,
        requested.length === 1 &&
          requested[0].queue === "pipeline" &&
          requested[0].payload.payload.commitSha === orig.commitSha &&
          requested[0].payload.payload.configHash === orig.configHash,
        "not exactly one requested message carrying the pinned SHA and hash",
      );
      ok(
        p,
        (await auditOf(w, tree, "execution.retry_requested", fresh)).length === 1,
        "not exactly one retry_requested audit entry",
      );
      const ev = await w.events(fresh, { type: "retry_requested" });
      ok(
        p,
        ev.length === 1 && ev[0].actorUserId === tree.user.id,
        "no retry_requested event with the actor",
      );
      const afterOrig = await w.row(orig);
      ok(
        p,
        JSON.stringify(afterOrig, (_k, v) => (typeof v === "bigint" ? v.toString() : v)) ===
          origFingerprint,
        "the original execution changed",
      );
      // the new execution runs the OLD snapshot (four tasks), not the current version (one)
      const ran = await w.run(tree, fresh, { orch: orchestratorOf(w) });
      const tasks = await tasksOf(w, fresh);
      ok(
        p,
        ran.row.status === "succeeded" && tasks.length === 4,
        `the retry ran ${tasks.length} tasks to ${ran.row.status}, not the original snapshot's four`,
      );
      const completed = await w.completed(tree, fresh);
      ok(
        p,
        completed.length === 1 &&
          completed[0].payload.payload.commitSha === orig.commitSha &&
          completed[0].payload.payload.configHash === orig.configHash,
        "the completed event does not carry the pinned commit and original hash",
      );
      // schedule, manual (retried by another user) and blocked originals
      const slot = new Date(Date.now() - 3600_000);
      const sched = await failed(w, tree, {
        triggerType: "schedule",
        triggerKey: "nightly",
        scmEventId: null,
        scmDeliveryId: null,
        scmEventKind: null,
        scheduleSlot: slot,
        idempotencyKey: `schedule:${randomUUID()}`,
        scanKindReason: "scheduled",
      });
      const rs = await attemptOf(() => svc.retry(actor, { id: sched.id }, "retry-sched"));
      const freshS = rs.value && (await w.row(rs.value.execution));
      ok(
        p,
        freshS?.status === "queued" &&
          freshS.scheduleSlot?.getTime() === slot.getTime() &&
          freshS.triggerType === "schedule",
        `schedule retry: ${rs.error?.message ?? freshS?.status}`,
      );
      const manual = await failed(w, tree, {
        triggerType: "manual",
        triggerKey: "manual",
        scmEventId: null,
        scmDeliveryId: null,
        scmEventKind: null,
        requestedByUserId: tree.user.id,
        idempotencyKey: `manual:${tree.user.id}:${randomUUID()}`,
      });
      const rm = await attemptOf(() =>
        svc.retry(actorOf(tree, reviewer), { id: manual.id }, "retry-manual"),
      );
      const freshM = rm.value && (await w.row(rm.value.execution));
      ok(
        p,
        freshM?.status === "queued" && freshM.requestedByUserId === reviewer.id,
        `manual retry: ${rm.error?.message ?? freshM?.requestedByUserId}`,
      );
      const blocked = await w.execution(tree, {
        status: "blocked",
        statusReason: "quota_exceeded",
        quotaConsumed: 0,
        quotaPeriod: null,
      });
      const rb = await attemptOf(() => svc.retry(actor, { id: blocked.id }, "retry-blocked"));
      ok(
        p,
        rb.value?.execution.status === "queued",
        `blocked retry: ${rb.error?.message ?? rb.value?.execution.status}`,
      );
      // a fork pull request stays untrusted_fork and incremental, and carries no credential
      const ftree = await w.tree("rtf");
      const fexec = await w.fork(ftree);
      await driveExecution(w.db, fexec.id, "failed", "tasks_failed");
      const fr = await attemptOf(() => svc.retry(actorOf(ftree), { id: fexec.id }, "retry-fork"));
      const ffresh = fr.value && (await w.row(fr.value.execution));
      ok(
        p,
        ffresh?.trust === "untrusted_fork" &&
          ffresh.scanKind === "incremental" &&
          ffresh.refType === "pull_request" &&
          ffresh.pullRequestNumber === 7 &&
          ffresh.commitSha === fexec.commitSha,
        `fork retry: ${fr.error?.message ?? ffresh?.trust}`,
      );
      if (ffresh) {
        const orch = orchestratorOf(w);
        const run = await w.run(ftree, ffresh, { orch });
        ok(p, run.row.status === "succeeded", `the fork retry ended ${run.row.status}`);
        const jobs = await w.outbox(ftree, { type: "scan.task.requested" });
        ok(
          p,
          jobs.length === 4 && jobs.every((j) => j.queue === "scan-untrusted"),
          "the fork retry's tasks did not all go to scan-untrusted",
        );
        ok(
          p,
          !TOKEN_SHAPES.test(await w.dump(ftree)),
          "a credential appears in the fork retry's rows or messages",
        );
        const completedF = await w.completed(ftree, ffresh);
        ok(
          p,
          completedF.length === 1 &&
            completedF[0].payload.payload.resolutionEligible === false &&
            completedF[0].payload.payload.trust === "untrusted_fork",
          "the fork retry's completed event is wrong",
        );
      }
      return p;
    },
  },
  {
    id: "EXE-042",
    name: "retry idempotency and quota (SPEC EXE-008, ER-23): a missing or malformed Idempotency-Key is a validation error; the same key twice or six times in parallel returns the SAME new execution with one unit, one requested message and one audit entry; another key creates another execution; the same key by another user of the tenant, or in another tenant, is independent; the same key for another original is an IDEMPOTENCY_CONFLICT; an exhausted quota refuses with QUOTA_EXCEEDED and writes no row, no message and no consumption, and eight parallel retries against two remaining units create exactly two; a removed entitlement is ENTITLEMENT_REQUIRED; another tenant's quota is untouched",
    async run(w) {
      const p = [];
      const svc = serviceOf(w);
      const tree = await w.tree("rti", { config: queueing(w) });
      const other = await w.tree("rti2");
      const actor = actorOf(tree);
      const user2 = await w.db.user.create({
        data: { email: `rti-b-${randomUUID()}@orch.example`, name: "B" },
      });
      const f1 = await failed(w, tree);
      const f2 = await failed(w, tree);
      const fo = await failed(w, other);
      await w.setQuotaUsage(tree, 0, currentPeriod());
      await w.setQuotaUsage(other, 0, currentPeriod());
      // missing / malformed keys
      for (const bad of [undefined, null, "", "x".repeat(201), "has space", "tab\t"]) {
        const bk = await attemptOf(() => svc.retry(actor, { id: f1.id }, bad));
        ok(p, bk.error?.code === "VALIDATION_FAILED", `key ${JSON.stringify(bad)} was accepted`);
      }
      ok(
        p,
        (await w.db.execution.count({ where: { retryOfExecutionId: f1.id } })) === 0,
        "a retry row exists after rejected keys",
      );
      // the same key twice, then six times in parallel
      const one = await attemptOf(() => svc.retry(actor, { id: f1.id }, "K"));
      const two = await attemptOf(() => svc.retry(actor, { id: f1.id }, "K"));
      ok(
        p,
        one.value &&
          two.value &&
          one.value.execution.id === two.value.execution.id &&
          one.value.replayed === false &&
          two.value.replayed === true,
        "the same key did not return the same execution",
      );
      const par = await Promise.all(
        Array.from({ length: 6 }, () => attemptOf(() => svc.retry(actor, { id: f1.id }, "KP"))),
      );
      ok(
        p,
        par.every((x) => x.value) && new Set(par.map((x) => x.value.execution.id)).size === 1,
        "parallel calls with one key created more than one execution",
      );
      ok(
        p,
        (await w.db.execution.count({ where: { retryOfExecutionId: f1.id } })) === 2,
        "the keys K and KP did not create exactly two executions",
      );
      ok(
        p,
        (await w.quotaUsage(tree, currentPeriod())) === 2,
        `usage ${await w.quotaUsage(tree, currentPeriod())}, expected 2 units for 2 executions`,
      );
      ok(
        p,
        (await w.outbox(tree, { type: "pipeline.execution.requested" })).filter(
          (m) => m.payload.executionId === one.value.execution.id,
        ).length === 1,
        "more than one requested message for one key",
      );
      ok(
        p,
        (await auditOf(w, tree, "execution.retry_requested", one.value.execution)).length === 1,
        "more than one audit entry for one key",
      );
      // another key, another user, another tenant
      const three = await attemptOf(() => svc.retry(actor, { id: f1.id }, "K2"));
      ok(
        p,
        three.value && three.value.execution.id !== one.value.execution.id,
        "another key returned the first execution",
      );
      const usr = await attemptOf(() => svc.retry(actorOf(tree, user2), { id: f1.id }, "K"));
      ok(
        p,
        usr.value &&
          usr.value.execution.id !== one.value.execution.id &&
          usr.value.replayed === false,
        "the same key by another user was not independent",
      );
      const oth = await attemptOf(() => svc.retry(actorOf(other), { id: fo.id }, "K"));
      ok(
        p,
        oth.value && oth.value.replayed === false,
        "the same key in another tenant was not independent",
      );
      ok(p, (await w.quotaUsage(other, currentPeriod())) === 1, "another tenant's usage is wrong");
      // the same key for ANOTHER original
      const cnt = await countRows(w, tree);
      const clash = await attemptOf(() => svc.retry(actor, { id: f2.id }, "K"));
      ok(
        p,
        clash.error?.code === "IDEMPOTENCY_CONFLICT",
        `the same key for another original answered ${clash.error?.code ?? "success"}`,
      );
      ok(p, sameCounts(await countRows(w, tree), cnt), "a rejected key wrote rows");
      const treeUsage = await w.quotaUsage(tree, currentPeriod());
      // quota: two units left, eight parallel retries
      const q = await limitedTree(w, "rtq", 3, 1, queueing(w));
      const qf = await failed(w, q);
      const eight = await Promise.all(
        Array.from({ length: 8 }, (_v, i) =>
          attemptOf(() => serviceOf(w).retry(actorOf(q), { id: qf.id }, `Q${i}`)),
        ),
      );
      const made = eight.filter((x) => x.value);
      const refused = eight.filter((x) => x.error?.code === "QUOTA_EXCEEDED");
      ok(
        p,
        made.length === 2 && refused.length === 6,
        `${made.length} retries succeeded and ${refused.length} were refused, expected 2 and 6`,
      );
      ok(
        p,
        (await w.quotaUsage(q, currentPeriod())) === 3,
        "the usage exceeds or misses the limit",
      );
      ok(
        p,
        (await w.db.execution.count({
          where: { tenantId: q.tenant.id, retryOfExecutionId: qf.id },
        })) === 2,
        "rows exist for the refused retries",
      );
      ok(
        p,
        (await auditOf(w, q, "execution.retry_denied", qf)).filter(
          (a) => a.metadata?.reason === "quota_exceeded",
        ).length === 6,
        "the quota refusals were not all audited",
      );
      const fp = await countRows(w, q);
      const again = await attemptOf(() => svc.retry(actorOf(q), { id: qf.id }, "Q-more"));
      const after = await countRows(w, q);
      ok(
        p,
        again.error?.code === "QUOTA_EXCEEDED" &&
          after.executions === fp.executions &&
          after.outbox === fp.outbox &&
          (await w.quotaUsage(q, currentPeriod())) === 3,
        "an exhausted quota wrote a row, a message or a consumption",
      );
      // entitlement removed
      await w.db.tenantEntitlement.updateMany({
        where: { tenantId: q.tenant.id },
        data: { enabled: false },
      });
      const noEnt = await attemptOf(() => svc.retry(actorOf(q), { id: qf.id }, "Q-ent"));
      ok(
        p,
        noEnt.error?.code === "ENTITLEMENT_REQUIRED",
        `a removed entitlement answered ${noEnt.error?.code ?? "success"}`,
      );
      ok(
        p,
        (await w.quotaUsage(tree, currentPeriod())) === treeUsage,
        "another tenant's usage moved",
      );
      return p;
    },
  },
  {
    id: "EXE-043",
    name: "retry never bypasses a gate (SPEC EXE-008, ER-21, ER-22): succeeded, skipped, queued, preparing and running executions are not_retryable_status; a deleted or disabled pipeline, a disabled or unavailable repository, an archived workspace and a suspended tenant refuse the retry NOW with the stable reason and write no row, message or consumption (gate refusals audited retry_denied); after restoring them the same retry works; failed, partial, timed_out and cancelled can be retried; the retry chain is capped (retry_chain_limit past the configured length, a retry of the original still allowed); the pipeline's concurrency policy applies (supersede cancels the queued sibling and gives its unit back once, skip creates a skipped row without consuming)",
    async run(w) {
      const p = [];
      const svc = serviceOf(w);
      const tree = await w.tree("rtg");
      const actor = actorOf(tree);
      await w.setQuotaUsage(tree, 0, currentPeriod());
      // statuses
      const mk = async (status, reason = "tasks_failed") => failed(w, tree, {}, status, reason);
      const succeeded = await mk("succeeded", null);
      const skipped = await w.execution(tree, {
        status: "skipped",
        statusReason: "concurrency_skip",
        quotaConsumed: 0,
        quotaPeriod: null,
      });
      const queued = await w.execution(tree);
      const preparing = await w.execution(tree);
      await driveExecution(w.db, preparing.id, "preparing");
      const running = await w.execution(tree);
      await driveExecution(w.db, running.id, "running");
      const base = await countRows(w, tree);
      for (const [name, e] of Object.entries({ succeeded, skipped, queued, preparing, running })) {
        const rr = await attemptOf(() => svc.retry(actor, { id: e.id }, `st-${name}`));
        ok(
          p,
          reasonOf(rr) === "not_retryable_status",
          `${name} answered ${rr.error?.message ?? "success"}`,
        );
      }
      ok(p, sameCounts(await countRows(w, tree), base), "a refused status wrote rows");
      for (const [status, reason] of [
        ["failed", "tasks_failed"],
        ["partial", "tasks_incomplete"],
        ["timed_out", "execution_deadline"],
        ["cancelled", "user_cancelled"],
      ]) {
        const e = await mk(status, reason);
        const rr = await attemptOf(() => svc.retry(actor, { id: e.id }, `ok-${status}`));
        ok(
          p,
          rr.value?.execution.status === "queued",
          `${status} was not retryable: ${rr.error?.message}`,
        );
      }
      // gates
      const src = await mk("failed");
      const snap = async () => ({
        ...(await countRows(w, tree)),
        usage: await w.quotaUsage(tree, currentPeriod()),
      });
      const gates = [
        [
          "pipeline_deleted",
          () =>
            w.db.pipeline.update({
              where: { id: tree.pipeline.id },
              data: { deletedAt: new Date() },
            }),
          () =>
            w.db.pipeline.update({ where: { id: tree.pipeline.id }, data: { deletedAt: null } }),
        ],
        [
          "pipeline_disabled",
          () => w.db.pipeline.update({ where: { id: tree.pipeline.id }, data: { enabled: false } }),
          () => w.db.pipeline.update({ where: { id: tree.pipeline.id }, data: { enabled: true } }),
        ],
        [
          "repository_not_active",
          () => w.db.repository.update({ where: { id: tree.repo.id }, data: { enabled: false } }),
          () => w.db.repository.update({ where: { id: tree.repo.id }, data: { enabled: true } }),
        ],
        [
          "repository_not_active",
          () =>
            w.db.repository.update({
              where: { id: tree.repo.id },
              data: { status: "unavailable" },
            }),
          () => w.db.repository.update({ where: { id: tree.repo.id }, data: { status: "active" } }),
        ],
        [
          "workspace_archived",
          () => w.db.workspace.update({ where: { id: tree.ws.id }, data: { status: "archived" } }),
          () => w.db.workspace.update({ where: { id: tree.ws.id }, data: { status: "active" } }),
        ],
      ];
      let denied = 0;
      for (const [reason, apply, restore] of gates) {
        await apply();
        const before = await snap();
        const rr = await attemptOf(() => svc.retry(actor, { id: src.id }, `gate-${denied}`));
        ok(
          p,
          reasonOf(rr) === reason,
          `gate ${reason} answered ${rr.error?.code ?? "success"}/${reasonOf(rr)}`,
        );
        const after = await snap();
        ok(
          p,
          after.executions === before.executions &&
            after.outbox === before.outbox &&
            after.usage === before.usage,
          `gate ${reason} wrote a row, a message or a consumption`,
        );
        denied += 1;
        await restore();
      }
      ok(
        p,
        (await auditOf(w, tree, "execution.retry_denied", src)).length === denied,
        "the gate refusals were not all audited retry_denied",
      );
      await w.db.tenant.update({ where: { id: tree.tenant.id }, data: { status: "suspended" } });
      const before = await snap();
      const sus = await attemptOf(() => svc.retry(actor, { id: src.id }, "gate-suspended"));
      ok(
        p,
        sus.error?.code === "TENANT_SUSPENDED",
        `a suspended tenant answered ${sus.error?.code ?? "success"}`,
      );
      const after = await snap();
      ok(
        p,
        after.executions === before.executions &&
          after.outbox === before.outbox &&
          after.usage === before.usage,
        "a suspended tenant's retry wrote rows",
      );
      await w.db.tenant.update({ where: { id: tree.tenant.id }, data: { status: "active" } });
      const control = await attemptOf(() => svc.retry(actor, { id: src.id }, "gate-restored"));
      ok(
        p,
        control.value?.execution.status === "queued",
        `control: after restoring every gate the retry answered ${control.error?.message}`,
      );
      // chain cap
      {
        const capped = serviceOf(w, { retryChainMax: 2 });
        const ctree = await w.tree("rtc");
        const ca = actorOf(ctree);
        const f0 = await failed(w, ctree);
        const r1 = (await capped.retry(ca, { id: f0.id }, "c1")).execution;
        await driveExecution(w.db, r1.id, "failed", "tasks_failed");
        const r2 = (await capped.retry(ca, { id: r1.id }, "c2")).execution;
        await driveExecution(w.db, r2.id, "failed", "tasks_failed");
        const n = await countRows(w, ctree);
        const r3 = await attemptOf(() => capped.retry(ca, { id: r2.id }, "c3"));
        ok(
          p,
          reasonOf(r3) === "retry_chain_limit",
          `the third retry in a chain answered ${r3.error?.message ?? "success"}`,
        );
        ok(
          p,
          (await countRows(w, ctree)).executions === n.executions,
          "the capped retry wrote a row",
        );
        const r4 = await attemptOf(() => capped.retry(ca, { id: f0.id }, "c4"));
        ok(
          p,
          r4.value?.execution.retryOfExecutionId === f0.id,
          "control: a retry of the original was refused",
        );
      }
      // concurrency policy
      {
        const stree = await w.tree("rts");
        const sa = actorOf(stree);
        await w.setQuotaUsage(stree, 5, currentPeriod());
        const group = `ref:${randomUUID()}`;
        const f = await failed(w, stree, { concurrencyGroup: group, quotaPeriod: currentPeriod() });
        const sibling = await w.execution(stree, {
          concurrencyGroup: group,
          quotaPeriod: currentPeriod(),
        });
        const rr = await attemptOf(() => svc.retry(sa, { id: f.id }, "sup"));
        const sib = await w.row(sibling);
        ok(
          p,
          rr.value?.execution.status === "queued" &&
            sib.status === "cancelled" &&
            sib.statusReason === "superseded" &&
            sib.quotaReleasedAt !== null,
          `supersede: ${sib.status}/${sib.statusReason}`,
        );
        ok(
          p,
          (await w.quotaUsage(stree, currentPeriod())) === 5,
          "supersede + retry did not net to one unit back and one consumed",
        );
        const ktree = await w.tree("rtk", {
          config: w.config1({
            execution: {
              timeoutSeconds: 120,
              scanTaskTimeoutSeconds: 60,
              concurrency: { policy: "skip", maxQueued: 5, maxActive: 1 },
            },
          }),
        });
        await w.setQuotaUsage(ktree, 5, currentPeriod());
        const kgroup = `ref:${randomUUID()}`;
        const kf = await failed(w, ktree, { concurrencyGroup: kgroup });
        const busy = await w.execution(ktree, { concurrencyGroup: kgroup });
        await driveExecution(w.db, busy.id, "running");
        const ks = await attemptOf(() => svc.retry(actorOf(ktree), { id: kf.id }, "skip"));
        ok(
          p,
          ks.value?.execution.status === "skipped" &&
            ks.value.execution.statusReason === "concurrency_skip",
          `skip policy answered ${ks.value?.execution.status ?? ks.error?.message}`,
        );
        ok(
          p,
          (await w.quotaUsage(ktree, currentPeriod())) === 5 &&
            (await w.outbox(ktree, { type: "pipeline.execution.requested" })).length === 0,
          "a skipped retry consumed a unit or sent a request",
        );
      }
      return p;
    },
  },
  {
    id: "EXE-044",
    name: "cancel and retry are tenant scoped (SPEC EXE-001, EXE-002, EXE-007): tenant A calling cancel or retry (and the permission-denial recorders) with tenant B's execution id, or with its own execution under a workspace id it cannot match, gets the same 404 as for a random UUID, writes no audit entry in either tenant and changes neither tenant's rows or quota; a visible execution's permission denial is audited execution.cancel_denied / execution.retry_denied once with the reason and the actor and changes nothing; cancel of a finished execution is already_finished, of a skipped or blocked one not_cancellable, with nothing changed; the same calls on the tenant's own executions work",
    async run(w) {
      const p = [];
      const svc = serviceOf(w);
      const a = await w.tree("xta");
      const b = await w.tree("xtb");
      const actorA = actorOf(a);
      const bQueued = await w.execution(b);
      const bFailed = await failed(w, b);
      await w.setQuotaUsage(a, 3, currentPeriod());
      await w.setQuotaUsage(b, 3, currentPeriod());
      const ghost = randomUUID();
      const fpB = await w.fingerprint(b);
      const fpA = await w.fingerprint(a);
      const calls = {
        cancel: (id, extra) => svc.cancel(actorA, { id, ...extra }),
        retry: (id, extra) => svc.retry(actorA, { id, ...extra }, "x-key"),
      };
      const reference = {};
      for (const [name, fn] of Object.entries(calls))
        reference[name] = await attemptOf(() => fn(ghost));
      for (const [name, fn] of Object.entries(calls)) {
        const foreign = await attemptOf(() => fn(name === "cancel" ? bQueued.id : bFailed.id));
        ok(
          p,
          isNotFound(foreign) && foreign.error.message === reference[name].error?.message,
          `${name} on another tenant's execution answered ${foreign.error?.code ?? "success"}`,
        );
      }
      await svc.recordCancelPermissionDenied(actorA, { id: bQueued.id });
      await svc.recordRetryPermissionDenied(actorA, { id: bFailed.id });
      ok(
        p,
        (await w.fingerprint(b)) === fpB && (await w.fingerprint(a)) === fpA,
        "a foreign call wrote rows or audit entries in either tenant",
      );
      ok(
        p,
        (await w.quotaUsage(b, w.period)) === 3 || (await w.quotaUsage(b, currentPeriod())) === 3,
        "another tenant's quota moved",
      );
      // own execution under another workspace id: hidden workspace is a 404 too
      const own = await w.execution(a);
      const wsB = b.ws.id;
      const hidden = await attemptOf(() => svc.cancel(actorA, { id: own.id, workspaceId: wsB }));
      ok(
        p,
        isNotFound(hidden) && (await w.statusOf(own)) === "queued",
        "a mismatching workspace was not a 404 or changed the execution",
      );
      // permission denial on a visible execution: audited once, nothing changes
      const fpOwn = JSON.stringify(await w.row(own), (_k, v) =>
        typeof v === "bigint" ? v.toString() : v,
      );
      await svc.recordCancelPermissionDenied(actorA, { id: own.id });
      await svc.recordRetryPermissionDenied(actorA, { id: own.id });
      const denied = await w.audit(a, {
        action: { in: ["execution.cancel_denied", "execution.retry_denied"] },
      });
      ok(
        p,
        denied.length === 2 &&
          denied.every(
            (d) =>
              d.targetId === own.id &&
              d.actorUserId === a.user.id &&
              d.metadata?.reason === "permission_denied",
          ),
        "the permission denials were not audited once with reason and actor",
      );
      ok(
        p,
        JSON.stringify(await w.row(own), (_k, v) => (typeof v === "bigint" ? v.toString() : v)) ===
          fpOwn,
        "a denial changed the execution",
      );
      // finished and never-started executions
      const states = {
        succeeded: await failed(w, a, {}, "succeeded", null),
        failed: await failed(w, a),
        timed_out: await failed(w, a, {}, "timed_out", "execution_deadline"),
        partial: await failed(w, a, {}, "partial", "tasks_incomplete"),
        cancelled: await failed(w, a, {}, "cancelled", "user_cancelled"),
      };
      const never = {
        skipped: await w.execution(a, {
          status: "skipped",
          statusReason: "concurrency_skip",
          quotaConsumed: 0,
          quotaPeriod: null,
        }),
        blocked: await w.execution(a, {
          status: "blocked",
          statusReason: "quota_exceeded",
          quotaConsumed: 0,
          quotaPeriod: null,
        }),
      };
      const fpStates = await w.fingerprint(a);
      for (const [name, e] of Object.entries(states)) {
        const rr = await attemptOf(() => svc.cancel(actorA, { id: e.id }));
        ok(
          p,
          reasonOf(rr) === "already_finished",
          `${name} answered ${rr.error?.message ?? "success"}`,
        );
      }
      for (const [name, e] of Object.entries(never)) {
        const rr = await attemptOf(() => svc.cancel(actorA, { id: e.id }));
        ok(
          p,
          reasonOf(rr) === "not_cancellable",
          `${name} answered ${rr.error?.message ?? "success"}`,
        );
      }
      ok(p, (await w.fingerprint(a)) === fpStates, "a refused cancel changed rows");
      // controls: the tenant's own queued execution cancels, its own failed one retries
      const c1 = await attemptOf(() => svc.cancel(actorA, { id: own.id }));
      ok(p, c1.value?.outcome === "cancelled", `control: own cancel answered ${c1.error?.message}`);
      const c2 = await attemptOf(() => svc.retry(actorA, { id: states.failed.id }, "own-retry"));
      ok(
        p,
        c2.value?.execution.status === "queued",
        `control: own retry answered ${c2.error?.message}`,
      );
      return p;
    },
  },
  {
    id: "EXE-045",
    name: "cancel versus the clock and a hung engine (SPEC ER-14, ER-20, table 5.4): a graceful cancel that is still waiting for its grace period loses to the execution deadline (the execution ends timed_out execution_deadline, tasks timed_out, unstarted ones skipped, not cancelled); an attempt that ignores the abort signal is force-closed by the lease holder when the grace period ends (tasks cancelled, the execution cancelled, the attempt closed cancelled), and the late write of the hung attempt afterwards is rejected: no result row, no second completed event, no second terminal transition",
    async run(w) {
      const p = [];
      // (a) the deadline wins over a waiting graceful cancel
      {
        const svc = serviceOf(w, { cancelGraceSeconds: 40 });
        const tree = await w.tree("cdl", {
          config: w.config1({
            execution: { timeoutSeconds: 3, scanTaskTimeoutSeconds: 3, cancellation: "graceful" },
          }),
        });
        const e = await w.execution(tree, { entries: withScript({ slow: ["sbom", "sca"] }) });
        const orch = orchestratorOf(w);
        const scan = w.scanHandler();
        await orch.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
        const running = await startTasks(w, tree, scan);
        await until(
          async () => (await tasksOf(w, e)).filter((t) => t.status === "running").length === 2,
        );
        const r = await attemptOf(() => svc.cancel(actorOf(tree), { id: e.id }));
        ok(p, r.value?.outcome === "cancel_requested", "(a) the request was not recorded");
        ok(p, await within(running, 20000), "(a) the tasks did not end at the deadline");
        ok(p, await settle(w, tree, [orch], scan), "(a) the execution did not finish");
        const row = await w.row(e);
        const tasks = await tasksOf(w, e);
        ok(
          p,
          row.status === "timed_out" && row.statusReason === "execution_deadline",
          `(a) the execution ended ${row.status}/${row.statusReason}, the deadline did not win`,
        );
        ok(
          p,
          tasks.filter((t) => t.status === "timed_out").length === 2 &&
            tasks.filter((t) => t.status === "skipped").length === 2,
          "(a) the tasks are not timed_out/skipped",
        );
        ok(
          p,
          row.cancelRequestedAt !== null && row.quotaReleasedAt === null,
          "(a) the request was lost or a unit refunded",
        );
      }
      // (b) a hung attempt is force-closed when the grace period ends, and its late write is rejected
      {
        const svc = serviceOf(w, { cancelGraceSeconds: 1 });
        const tree = await w.tree("cdf", {
          config: w.config1({ scans: { sbom: { enabled: true } } }),
        });
        const e = await w.execution(tree, {
          entries: withScript({ deaf: ["sbom"], deafMs: 5000 }),
        });
        await w.setQuotaUsage(tree, 2);
        const orch = orchestratorOf(w);
        const scan = w.scanHandler();
        await orch.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
        const running = await startTasks(w, tree, scan);
        await until(
          async () => (await tasksOf(w, e)).filter((t) => t.status === "running").length === 1,
        );
        await svc.cancel(actorOf(tree), { id: e.id });
        await deliverCancelWakeup(w, tree, e, orch);
        const ended = await until(async () => {
          for (const entry of orch.owned()) await orch.drive(entry);
          return (await w.statusOf(e)) === "cancelled";
        }, 15000);
        ok(p, !!ended, "(b) the hung attempt was not force-closed after the grace period");
        const hung = await w.row(e);
        const forced = (await tasksOf(w, e))[0];
        const forcedAttempts = await attemptsOf(w, e);
        ok(
          p,
          forced.status === "cancelled" &&
            forced.statusReason === "user_cancelled" &&
            forcedAttempts.length === 1 &&
            forcedAttempts[0].status === "cancelled",
          "(b) the force-closed task or attempt is wrong",
        );
        ok(
          p,
          hung.status === "cancelled" && (await w.quotaUsage(tree)) === 2,
          "(b) the terminal state or quota is wrong",
        );
        // the hung engine finally returns: its write must change nothing
        const before = await w.fingerprint(tree);
        ok(p, await within(running, 20000), "(b) the hung handler never returned");
        const after = await w.fingerprint(tree);
        const results = await w.db.scanResult.findMany({ where: { executionId: e.id } });
        ok(
          p,
          results.length === 0 && (await w.completed(tree, e)).length === 1,
          "(b) the zombie attempt wrote a result or a second completed event",
        );
        ok(p, before === after, "(b) the late write of the hung attempt changed rows");
        const transitions = (await w.events(e)).filter(
          (ev) => ev.type === "transition" && ev.toStatus === "cancelled",
        );
        ok(p, transitions.length === 1, "(b) not exactly one terminal transition");
      }
      return p;
    },
  },
];
