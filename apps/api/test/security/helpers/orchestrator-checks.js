import { createEventEnvelope, parseMessage } from "@qmentisai/contracts";
import { Readable } from "node:stream";
import { NonRetryableError, findCredentials, walkTarGz } from "@qmentisai/infra";
import { ConfigError } from "../../../../workers/src/config.js";
import { selectPipelineHandler } from "../../../../workers/src/pipeline/index.js";
import { makeTarGz, sleep } from "./orchestrator.js";

/**
 * Execution orchestrator checks (ADR-008, docs/modules/executions/SPEC.md §14.1, part C): tenant isolation of the worker
 * (ownership re-validation of messages, claim re-validation), credential absence, lease fencing and reclaim exactly once, the
 * stale-queue guarantee, and the facts other modules rely on (the single completed event and `resolutionEligible`). Every
 * denial is paired with a control (the legitimate path works) so no denial is vacuous. Black box about outcomes: rows,
 * statuses and messages. The orchestrator, the scan handler, the ownership verifier and the outbox are the real ones; GitHub
 * is the local stub and the scan engine is a deterministic test engine.
 */

const json = (value) =>
  JSON.stringify(value, (_k, x) => (typeof x === "bigint" ? x.toString() : x));
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const script = (obj) => ({ name: "qm-test.json", content: JSON.stringify(obj) });
const BASE_ENTRIES = [
  { name: "README.md", content: "# repo\n" },
  { name: "src", dir: true },
  { name: "src/a.js", content: "console.log(1)\n" },
];
const withScript = (obj) => [...BASE_ENTRIES, script(obj)];
const TOKEN_SHAPES =
  /ghs_stub_|ghu_stub_|BEGIN (RSA )?PRIVATE KEY|authorization|secretRef|Bearer /i;
const requestedEnvelope = (w, tree, e) =>
  createEventEnvelope({
    messageId: `execution-requested-${e.id}`,
    type: "pipeline.execution.requested",
    schemaVersion: 1,
    tenantId: tree.tenant.id,
    workspaceId: tree.ws.id,
    repositoryId: tree.repo.id,
    pipelineId: e.pipelineId,
    executionId: e.id,
    initiator: { type: "system", id: "suite" },
    subject: { type: "execution", id: e.id },
    payload: {
      executionId: e.id,
      pipelineId: e.pipelineId,
      repositoryId: tree.repo.id,
      workspaceId: tree.ws.id,
      configVersion: e.configVersion,
      configHash: e.configHash,
      triggerType: e.triggerType,
      triggerKey: e.triggerKey,
      refType: e.refType,
      refName: e.refName,
      commitSha: e.commitSha,
      pullRequestNumber: e.pullRequestNumber,
      scanKind: e.scanKind,
      scanKindReason: e.scanKindReason,
      trust: e.trust,
    },
  });

/** Runs a scenario once and caches it (several checks read the same outcome). */
const cache = new Map();
async function scenario(w, name, build) {
  if (!cache.has(w)) cache.set(w, new Map());
  const mine = cache.get(w);
  if (!mine.has(name)) mine.set(name, build());
  return mine.get(name);
}
async function runScenario(w, name, { entries, exec = {}, config, over } = {}) {
  return scenario(w, name, async () => {
    const tree = await w.tree(name, config ? { config } : {});
    const execution = await w.execution(tree, { entries: entries ?? BASE_ENTRIES, ...exec });
    const result = await w.run(tree, execution, { over });
    const completed = await w.completed(tree, execution);
    return { tree, execution, ...result, completed, tasks: await w.taskRows(execution) };
  });
}

/** Executions prepared for the lost-worker checks; one wait lets every lease expire. */
async function lostWorld(w) {
  return scenario(w, "lost-world", async () => {
    const x = {};
    const lone = async (label, config) => {
      const tree = await w.tree(label, config ? { config } : {});
      const execution = await w.execution(tree);
      return { tree, execution };
    };
    // R: running, held by a worker that then dies
    x.R = await lone("lostR");
    x.hR = w.orchestrator();
    await x.hR.claimAndStart({ tenantId: x.R.tree.tenant.id, executionId: x.R.execution.id });
    x.hR.abandonAll();
    // P: preparing (claimed, nothing fetched yet), short lease
    x.P = await lone("lostP");
    await w.repo.claimQueued({
      tenantId: x.P.tree.tenant.id,
      executionId: x.P.execution.id,
      workerId: "dead-claimer",
      leaseTtlSeconds: 1,
      deadlineSeconds: 600,
      staleThresholdSeconds: 36 * 3600,
    });
    // B: another tenant's running execution with an expired lease
    x.B = await lone("lostB");
    x.hB = w.orchestrator();
    await x.hB.claimAndStart({ tenantId: x.B.tree.tenant.id, executionId: x.B.execution.id });
    x.hB.abandonAll();
    // W1: preparing, archive recorded but the object is missing
    x.W1 = await lone("lostW1");
    await w.repo.claimQueued({
      tenantId: x.W1.tree.tenant.id,
      executionId: x.W1.execution.id,
      workerId: "dead-claimer",
      leaseTtlSeconds: 1,
      deadlineSeconds: 600,
      staleThresholdSeconds: 36 * 3600,
    });
    await w.repo.recordArchive({
      tenantId: x.W1.tree.tenant.id,
      executionId: x.W1.execution.id,
      leaseEpoch: 1,
      sha256: "a".repeat(64),
      bytes: 10,
    });
    // Q: preparing, archive recorded but missing (for the quota race of EXE-031)
    x.Q = await lone("lostQ");
    await w.repo.claimQueued({
      tenantId: x.Q.tree.tenant.id,
      executionId: x.Q.execution.id,
      workerId: "dead-claimer",
      leaseTtlSeconds: 1,
      deadlineSeconds: 600,
      staleThresholdSeconds: 36 * 3600,
    });
    await w.repo.recordArchive({
      tenantId: x.Q.tree.tenant.id,
      executionId: x.Q.execution.id,
      leaseEpoch: 1,
      sha256: "c".repeat(64),
      bytes: 10,
    });
    // W2: running, will meet a reclaimer whose limit is 0
    x.W2 = await lone("lostW2");
    x.hW2 = w.orchestrator();
    await x.hW2.claimAndStart({ tenantId: x.W2.tree.tenant.id, executionId: x.W2.execution.id });
    x.hW2.abandonAll();
    // W3: running, a scan worker died holding a task, the reclaimer's engine is not idempotent
    x.W3 = await lone("lostW3");
    x.hW3 = w.orchestrator();
    await x.hW3.claimAndStart({ tenantId: x.W3.tree.tenant.id, executionId: x.W3.execution.id });
    x.hW3.abandonAll();
    const w3Tasks = await w.taskRows(x.W3.execution);
    await w.tasks.claimTask({
      tenantId: x.W3.tree.tenant.id,
      executionId: x.W3.execution.id,
      taskId: w3Tasks[0].id,
      attempt: 0,
      workerId: "dead-scan",
      leaseTtlSeconds: 1,
    });
    // W4: running with a cancel request, W5: preparing past its deadline
    x.W4 = await lone("lostW4");
    x.hW4 = w.orchestrator();
    await x.hW4.claimAndStart({ tenantId: x.W4.tree.tenant.id, executionId: x.W4.execution.id });
    x.hW4.abandonAll();
    await w.db
      .$executeRaw`UPDATE executions SET cancel_requested_at = now(), cancel_requested_by_user_id = ${x.W4.tree.user.id}::uuid, cancel_mode = 'immediate', cancel_grace_until = now() WHERE id = ${x.W4.execution.id}::uuid`;
    x.W5 = await lone("lostW5");
    await w.repo.claimQueued({
      tenantId: x.W5.tree.tenant.id,
      executionId: x.W5.execution.id,
      workerId: "dead-claimer",
      leaseTtlSeconds: 1,
      deadlineSeconds: 1,
      staleThresholdSeconds: 36 * 3600,
    });
    // Z: the zombie scenario: H1 is alive but stopped heartbeating
    x.Z = await lone("lostZ");
    x.h1 = w.orchestrator();
    await x.h1.claimAndStart({ tenantId: x.Z.tree.tenant.id, executionId: x.Z.execution.id });
    x.zEntry = x.h1.owned()[0];
    const zTasks = await w.taskRows(x.Z.execution);
    await w.tasks.claimTask({
      tenantId: x.Z.tree.tenant.id,
      executionId: x.Z.execution.id,
      taskId: zTasks[0].id,
      attempt: 0,
      workerId: "zombie-scan",
      leaseTtlSeconds: 1,
    });
    await sleep(4600);
    return x;
  });
}

const reclaimAll = (orchs, tree, e, epoch) =>
  Promise.all(
    orchs.map((o) => o.reclaimOne({ tenantId: tree.tenant.id, id: e.id, leaseEpoch: epoch })),
  );
const owners = (orchs, e) => orchs.filter((o) => o.owned().some((x) => x.executionId === e.id));

/** @type {{ id: string, name: string, run: (w: any) => Promise<string[]> }[]} */
export const ORCH_CHECKS = [
  {
    id: "EXE-032",
    name: "one-time first-enable stale sweep: with no marker the flag-off handler sweeps nothing; on enable the marker row appears and exactly the queued rows older than the threshold are cancelled expired_stale (each releasing its own unit once, one execution.expired audit entry in its own tenant, younger rows stay queued, a suspended tenant's old row too); the claim waits for the sweep; a sweeper that crashed mid-batch is continued by the next start; running the sweep again, concurrently or after a restart cancels, releases and writes nothing more",
    async run(w) {
      const p = [];
      if (await w.markers.getMarker())
        return ["fixture: the first-enable marker already exists in this database"];
      // queued rows older than the threshold that other worlds of this database left behind are swept too (and counted)
      const foreignStale = await w.db.execution.count({
        where: { status: "queued", requestedAt: { lt: new Date(Date.now() - 36 * 3600_000) } },
      });
      const A = await w.tree("sweepA");
      const B = await w.tree("sweepB");
      const S = await w.tree("sweepS", { tenantStatus: "suspended" });
      await Promise.all([w.setQuotaUsage(A, 5), w.setQuotaUsage(B, 3), w.setQuotaUsage(S, 2)]);
      const mk = (tree, ageHours, extra = {}) =>
        w.execution(tree, {
          ageHours,
          commitSha: null,
          archive: false,
          concurrencyGroup: `g-${Math.random()}`,
          ...extra,
        });
      const aOld1 = await mk(A, 48);
      const aOld2 = await mk(A, 50);
      const aYoung = await w.execution(A, { concurrencyGroup: "young" });
      const bOld = await mk(B, 49);
      const sOld = await mk(S, 60);
      const olds = [aOld1, aOld2, bOld, sOld];
      // flag off: the noop handler does nothing and no marker appears
      const off = w.config({ EXECUTION_ORCHESTRATOR_ENABLED: "false" });
      const noop = selectPipelineHandler({ config: off }, () => {
        throw new Error("the orchestrator was built while the flag is off");
      });
      await noop(requestedEnvelope(w, A, aOld1), { log: { info() {} } });
      ok(p, (await w.markers.getMarker()) === null, "the flag-off handler created the marker");
      ok(p, (await w.statusOf(aOld1)) === "queued", "the flag-off handler touched a queued row");

      // a sweeper that crashes after its first cancel (every later transaction fails)
      let transactions = 0;
      const crashing = new Proxy(w.db, {
        get(target, prop) {
          if (prop === "$transaction")
            return (fn, options) => {
              transactions += 1;
              if (transactions > 1) throw new Error("simulated crash");
              return target.$transaction(fn, options);
            };
          return Reflect.get(target, prop, target);
        },
      });
      const crashed = w.orchestrator({ EXECUTION_SWEEP_BATCH_SIZE: "1" }, { db: crashing });
      const crash = await crashed.ensureFirstEnableSweep().then(
        () => null,
        (e) => e,
      );
      ok(
        p,
        crash?.message === "simulated crash",
        `the crashing sweeper did not crash (${crash?.message})`,
      );
      const marker = await w.markers.getMarker();
      ok(
        p,
        marker && !marker.sweepCompletedAt && marker.sweepStartedAt,
        "after the crash the marker should show a started, uncompleted sweep",
      );
      // (other worlds of the disposable database may hold older queued rows too: count every row the sweep cancelled)
      const cancelledSoFar = await w.db.execution.count({
        where: { status: "cancelled", statusReason: "expired_stale" },
      });
      ok(
        p,
        cancelledSoFar === 1,
        `the crashed sweeper should have cancelled exactly one row, ${cancelledSoFar} were`,
      );

      // another worker: the sweep lease is still held, so the sweep is not ready and the claim waits
      const next = w.orchestrator();
      ok(
        p,
        (await next.ensureFirstEnableSweep()) === false,
        "a second worker swept while the first one's lease was live",
      );
      await next.handler(requestedEnvelope(w, A, aYoung), { log: { info() {} } });
      ok(p, (await w.statusOf(aYoung)) === "queued", "the claim ran before the sweep completed");
      await sleep(4600); // the crashed sweeper's lease expires
      ok(
        p,
        (await next.ensureFirstEnableSweep()) === true,
        "the next start did not complete the interrupted sweep",
      );

      // every old row cancelled exactly once, the young one untouched, per-tenant effects only
      const used = { A: await w.quotaUsage(A), B: await w.quotaUsage(B), S: await w.quotaUsage(S) };
      ok(
        p,
        used.A === 3 && used.B === 2 && used.S === 1,
        `usage after the sweep is ${JSON.stringify(used)}, expected A 3, B 2, S 1`,
      );
      for (const [tree, row] of [
        [A, aOld1],
        [A, aOld2],
        [B, bOld],
        [S, sOld],
      ]) {
        const now = await w.row(row);
        ok(
          p,
          now.status === "cancelled" && now.statusReason === "expired_stale" && now.quotaReleasedAt,
          `${row.id} is ${now.status}/${now.statusReason}, quota_released_at ${now.quotaReleasedAt}`,
        );
        const expired = await w.audit(tree, { action: "execution.expired", targetId: row.id });
        ok(
          p,
          expired.length === 1 && expired[0].metadata.reason === "expired_stale",
          `${row.id}: ${expired.length} execution.expired audit entries`,
        );
        ok(
          p,
          (await w.events(row, { type: "transition" })).length === 1,
          `${row.id}: not exactly one transition event`,
        );
      }
      ok(
        p,
        (await w.audit(B, { action: "execution.expired", targetId: aOld1.id })).length === 0,
        "tenant B has an audit entry about tenant A's row",
      );
      ok(p, (await w.statusOf(aYoung)) === "queued", "a young row was swept");
      const done = await w.markers.getMarker();
      ok(
        p,
        done.sweepCompletedAt && done.sweptCount === 4 + foreignStale,
        `marker swept_count ${done.sweptCount}, completed ${done.sweepCompletedAt}`,
      );
      ok(
        p,
        w.logs.some((l) => l.includes("First-enable stale sweep completed")),
        "the platform-level sweep log record is missing",
      );

      // again: concurrently, after a restart, with the flag toggled: nothing more happens
      const before = JSON.stringify([used, await Promise.all(olds.map((e) => w.events(e)))]);
      await Promise.all(Array.from({ length: 4 }, () => w.orchestrator().ensureFirstEnableSweep()));
      await w.orchestrator().handler(requestedEnvelope(w, A, aOld1), { log: { info() {} } });
      const after = JSON.stringify([
        { A: await w.quotaUsage(A), B: await w.quotaUsage(B), S: await w.quotaUsage(S) },
        await Promise.all(olds.map((e) => w.events(e))),
      ]);
      ok(p, before === after, "a repeated sweep changed usage or events");
      const again = await w.markers.getMarker();
      ok(
        p,
        again.sweptCount === 4 + foreignStale &&
          again.firstEnabledAt.getTime() === done.firstEnabledAt.getTime(),
        "the marker changed after the sweep completed",
      );
      // a restarted worker finds the completed marker: the sweep is "ready" at once, never runs again (a row that became stale
      // later is left to the steady-state path) and the claim proceeds
      const restarted = w.orchestrator();
      ok(
        p,
        (await restarted.ensureFirstEnableSweep()) === true,
        "a restarted worker did not see the completed sweep",
      );
      const late = await w.execution(A, {
        ageHours: 40,
        commitSha: null,
        archive: false,
        concurrencyGroup: "late",
      });
      await restarted.ensureFirstEnableSweep();
      ok(
        p,
        (await w.statusOf(late)) === "queued",
        "a completed sweep ran again and cancelled a later-stale row",
      );
      await restarted.handler(requestedEnvelope(w, B, await w.execution(B)), {
        log: { info() {} },
      });
      ok(
        p,
        (await w.db.execution.count({
          where: { tenantId: B.tenant.id, status: { in: ["preparing", "running"] } },
        })) === 1,
        "control: a restarted worker did not claim after the completed sweep",
      );
      // control: after the sweep the claim proceeds and the young row runs
      await next.handler(requestedEnvelope(w, A, aYoung), { log: { info() {} } });
      ok(
        p,
        ["preparing", "running"].includes(await w.statusOf(aYoung)),
        "control: the young row was not claimed after the sweep",
      );
      return p;
    },
  },
  {
    id: "EXE-033",
    name: "a stale queued request is never started: a row older than the threshold (also one of a suspended tenant) is cancelled queue_expired with its unit released once by the claim path, by a duplicate wake-up message and by the sweeper, and the claim statement itself refuses it (a race between the age gate and the claim cannot start it); a row under the threshold is claimed; another tenant is unaffected",
    async run(w) {
      const p = [];
      const A = await w.tree("staleA");
      const B = await w.tree("staleB");
      const S = await w.tree("staleS", { tenantStatus: "suspended" });
      await Promise.all([w.setQuotaUsage(A, 4), w.setQuotaUsage(B, 4), w.setQuotaUsage(S, 4)]);
      const stale = await w.execution(A, { ageHours: 40 });
      const staleSuspended = await w.execution(S, { ageHours: 40 });
      const viaMessage = await w.execution(A, { ageHours: 41, concurrencyGroup: "m" });
      const near = await w.execution(A, { ageHours: 35, concurrencyGroup: "near" });
      const bFresh = await w.execution(B);
      const sweeper = w.orchestrator();
      const calls = w.sourceCalls;
      const tarballsBefore = (await calls()).tarballs.length;
      // the claim statement refuses a stale row on its own (the race between the gate and the claim)
      const raw = await w.repo.claimQueued({
        tenantId: A.tenant.id,
        executionId: stale.id,
        workerId: "racer",
        leaseTtlSeconds: 4,
        deadlineSeconds: 60,
        staleThresholdSeconds: 36 * 3600,
      });
      ok(p, raw === null, "claimQueued started a stale row");
      ok(p, (await w.statusOf(stale)) === "queued", "the refused claim changed the row");
      const r1 = await sweeper.claimAndStart({ tenantId: A.tenant.id, executionId: stale.id });
      const r2 = await sweeper.claimAndStart({
        tenantId: S.tenant.id,
        executionId: staleSuspended.id,
      });
      await sweeper.handler(requestedEnvelope(w, A, viaMessage), { log: { info() {} } });
      for (const [label, row, tree] of [
        ["claim", stale, A],
        ["suspended tenant", staleSuspended, S],
        ["wake-up message", viaMessage, A],
      ]) {
        const now = await w.row(row);
        ok(
          p,
          now.status === "cancelled" && now.statusReason === "queue_expired" && now.quotaReleasedAt,
          `${label}: ${now.status}/${now.statusReason}`,
        );
        ok(
          p,
          (await w.events(row)).every((e) => e.toStatus !== "preparing"),
          `${label}: the row went through preparing`,
        );
        ok(p, (await w.taskRows(row)).length === 0, `${label}: tasks were created`);
        ok(
          p,
          (await w.audit(tree, { action: "execution.preparing", targetId: row.id })).length === 0,
          `${label}: a preparing audit entry exists`,
        );
      }
      ok(
        p,
        r1.outcome === "cancelled" && r2.outcome === "cancelled",
        `outcomes ${r1.outcome}/${r2.outcome}`,
      );
      ok(
        p,
        (await w.quotaUsage(A)) === 2 && (await w.quotaUsage(S)) === 3,
        `usage A ${await w.quotaUsage(A)} S ${await w.quotaUsage(S)}, expected 2 and 3 (one unit per cancelled row, released once)`,
      );
      await sweeper.claimAndStart({ tenantId: A.tenant.id, executionId: stale.id }); // a replay releases nothing more
      ok(p, (await w.quotaUsage(A)) === 2, "a replayed claim released a second time");
      ok(
        p,
        (await w.statusOf(bFresh)) === "queued" && (await w.quotaUsage(B)) === 4,
        "tenant B was affected",
      );
      ok(
        p,
        (await calls()).tarballs.length === tarballsBefore,
        "an archive was requested for a stale run",
      );
      // the sweeper's expiry pass takes the rows that aged out later
      const aged = await w.execution(B, { ageHours: 39, concurrencyGroup: "aged" });
      await sweeper.claimAndStart({ tenantId: B.tenant.id, executionId: aged.id });
      ok(p, (await w.row(aged)).statusReason === "queue_expired", "an aged row was not expired");
      // control: a row under the threshold is claimed and started
      const r3 = await sweeper.claimAndStart({ tenantId: A.tenant.id, executionId: near.id });
      ok(p, r3.outcome === "running", `control: the near-threshold row ended ${r3.outcome}`);
      return p;
    },
  },
  {
    id: "EXE-015",
    name: "worker ownership re-validation: a message of each execution type that names tenant A's execution under tenant B's envelope, or a workspace/pipeline/repository/execution that does not match the execution's chain, is refused resource-not-in-tenant and changes nothing (the handler also finds nothing by (tenant, id)); a suspended tenant's message is refused tenant-not-usable; the same messages with the right tenant pass",
    async run(w) {
      const p = [];
      const A = await w.tree("ownA");
      const B = await w.tree("ownB");
      const S = await w.tree("ownS", { tenantStatus: "suspended" });
      const execution = await w.execution(A);
      const orch = w.orchestrator();
      await orch.claimAndStart({ tenantId: A.tenant.id, executionId: execution.id });
      const [task] = await w.taskRows(execution);
      const chain = {
        pipelineId: execution.pipelineId,
        repositoryId: A.repo.id,
        workspaceId: A.ws.id,
      };
      const payloads = {
        "pipeline.execution.started": {
          executionId: execution.id,
          ...chain,
          startedAt: new Date().toISOString(),
          taskCount: 4,
        },
        "pipeline.execution.cancel_requested": {
          executionId: execution.id,
          pipelineId: chain.pipelineId,
          requestedAt: new Date().toISOString(),
          mode: "graceful",
        },
        "pipeline.execution.status_changed": {
          executionId: execution.id,
          workspaceId: chain.workspaceId,
          pipelineId: chain.pipelineId,
          status: "running",
          rev: 2,
        },
        "pipeline.execution.log_appended": {
          executionId: execution.id,
          workspaceId: chain.workspaceId,
          lastSeq: 1,
        },
        "scan.task.requested": {
          executionId: execution.id,
          taskId: task.id,
          scanType: task.scanType,
          attempt: 0,
          ...chain,
          trust: "trusted",
          deadlineAt: null,
        },
        "scan.task.completed": {
          executionId: execution.id,
          taskId: task.id,
          scanType: task.scanType,
          attempt: 0,
          status: "succeeded",
          resultId: null,
        },
        "scan.task.status_changed": {
          executionId: execution.id,
          taskId: task.id,
          workspaceId: chain.workspaceId,
          scanType: task.scanType,
          status: "queued",
          rev: 1,
        },
      };
      const requested = requestedEnvelope(w, A, execution);
      const messages = [
        ["pipeline.execution.requested", requested.payload],
        ...Object.entries(payloads),
      ];
      const build = (type, payload, over = {}, tree = A) =>
        parseMessage(w.envelope(type, tree, execution, payload, over));
      const refused = async (label, message, reason) => {
        const before = await w.fingerprint(A);
        const error = await w.verify(message).then(
          () => null,
          (e) => e,
        );
        ok(
          p,
          error instanceof NonRetryableError && error.reason === reason,
          `${label}: ${error ? `${error.name}/${error.reason}` : "accepted"}, expected ${reason}`,
        );
        ok(p, (await w.fingerprint(A)) === before, `${label}: rows of tenant A changed`);
      };
      for (const [type, payload] of messages) {
        await w.verify(build(type, payload)); // control: the right tenant passes
        await refused(
          `${type} under tenant B`,
          build(type, payload, { tenantId: B.tenant.id, workspaceId: B.ws.id }),
          "resource-not-in-tenant",
        );
        await refused(
          `${type} under suspended tenant`,
          build(type, payload, { tenantId: S.tenant.id, workspaceId: S.ws.id }),
          "tenant-not-usable",
        );
        if (payload.workspaceId !== undefined)
          await refused(
            `${type} with another workspace`,
            build(
              type,
              {
                ...payload,
                workspaceId: (
                  await w.db.workspace.create({
                    data: { tenantId: A.tenant.id, name: `other ${Math.random()}` },
                  })
                ).id,
              },
              { workspaceId: undefined },
            ),
            "resource-not-in-tenant",
          );
        if (payload.pipelineId !== undefined)
          await refused(
            `${type} with another pipeline`,
            build(type, { ...payload, pipelineId: B.pipeline.id }, { pipelineId: undefined }),
            "resource-not-in-tenant",
          );
        await refused(
          `${type} with a different envelope execution`,
          build(type, payload, { executionId: B.pipeline.id }),
          "resource-not-in-tenant",
        );
      }
      // the handler is a second line: a foreign tenant id finds nothing by (tenant, id)
      const before = await w.fingerprint(A);
      const foreign = await orch.claimAndStart({
        tenantId: B.tenant.id,
        executionId: (await w.execution(A, { concurrencyGroup: "x" })).id,
      });
      ok(
        p,
        foreign.outcome === "skipped",
        `the handler path accepted another tenant's execution (${foreign.outcome})`,
      );
      ok(p, (await w.outbox(B)).length === 0, "tenant B received an outbox row");
      ok(p, before !== null, "fingerprint");
      return p;
    },
  },
  {
    id: "EXE-016",
    name: "claim re-validation from the database: a deactivated tenant, an archived workspace, an unavailable/disconnected/disabled repository, a disabled or deleted pipeline, a removed entitlement and a stale row are never claimed and end cancelled with the matching reason and the unit released once; a suspended tenant's row stays queued; a snapshot whose hash differs or whose schema is invalid ends failed (config_snapshot_mismatch / config_invalid) with no task and no archive request; another tenant's rows are untouched; a healthy row is claimed",
    async run(w) {
      const p = [];
      const other = await w.tree("revalOther");
      const otherExec = await w.execution(other);
      const cases = [
        [
          "tenant_inactive",
          async (t) =>
            w.db.tenant.update({ where: { id: t.tenant.id }, data: { status: "deactivated" } }),
        ],
        [
          "workspace_archived",
          async (t) =>
            w.db.workspace.update({ where: { id: t.ws.id }, data: { status: "archived" } }),
        ],
        [
          "repository_inactive",
          async (t) =>
            w.db.repository.update({ where: { id: t.repo.id }, data: { status: "unavailable" } }),
        ],
        [
          "repository_inactive",
          async (t) =>
            w.db.repository.update({ where: { id: t.repo.id }, data: { status: "disconnected" } }),
          "disconnected",
        ],
        [
          "repository_disabled",
          async (t) =>
            w.db.repository.update({ where: { id: t.repo.id }, data: { enabled: false } }),
        ],
        [
          "pipeline_disabled",
          async (t) =>
            w.db.pipeline.update({ where: { id: t.pipeline.id }, data: { enabled: false } }),
        ],
        [
          "pipeline_deleted",
          async (t) =>
            w.db.pipeline.update({
              where: { id: t.pipeline.id },
              data: { deletedAt: new Date(), deletedByUserId: t.user.id },
            }),
        ],
        [
          "entitlement_required",
          async (t) =>
            w.db.tenantEntitlement.updateMany({
              where: { tenantId: t.tenant.id },
              data: { enabled: false },
            }),
        ],
      ];
      for (const [reason, mutate, label] of cases) {
        const tree = await w.tree("reval");
        await w.setQuotaUsage(tree, 3);
        const e = await w.execution(tree);
        await mutate(tree);
        const tarballs = (await w.sourceCalls()).tarballs.length;
        const r = await w
          .orchestrator()
          .claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
        const now = await w.row(e);
        const name = label ?? reason;
        ok(
          p,
          r.outcome === "cancelled" && now.status === "cancelled" && now.statusReason === reason,
          `${name}: ${now.status}/${now.statusReason} (${r.outcome}), expected cancelled/${reason}`,
        );
        ok(
          p,
          now.quotaReleasedAt && (await w.quotaUsage(tree)) === 2,
          `${name}: the unit was not released exactly once`,
        );
        ok(
          p,
          (await w.taskRows(e)).length === 0 &&
            (await w.sourceCalls()).tarballs.length === tarballs,
          `${name}: work was started`,
        );
      }
      // suspended: stays queued, nothing written
      const sus = await w.tree("revalSus");
      const susExec = await w.execution(sus);
      await w.db.tenant.update({ where: { id: sus.tenant.id }, data: { status: "suspended" } });
      const before = await w.fingerprint(sus);
      const sr = await w
        .orchestrator()
        .claimAndStart({ tenantId: sus.tenant.id, executionId: susExec.id });
      ok(
        p,
        sr.outcome === "deferred" &&
          (await w.statusOf(susExec)) === "queued" &&
          (await w.fingerprint(sus)) === before,
        `a suspended tenant's row was not left untouched (${sr.outcome})`,
      );
      // snapshot: a hash that differs, a schema that is invalid
      const snap = await w.tree("revalSnap");
      await w.setQuotaUsage(snap, 3);
      const wrongHash = await w.execution(snap, {
        configHash: "0".repeat(64),
        concurrencyGroup: "h",
      });
      const tarballs = (await w.sourceCalls()).tarballs.length;
      await w.orchestrator().claimAndStart({ tenantId: snap.tenant.id, executionId: wrongHash.id });
      let now = await w.row(wrongHash);
      ok(
        p,
        now.status === "failed" && now.statusReason === "prepare_failed:config_snapshot_mismatch",
        `hash mismatch: ${now.status}/${now.statusReason}`,
      );
      ok(
        p,
        (await w.taskRows(wrongHash)).length === 0 &&
          (await w.sourceCalls()).tarballs.length === tarballs,
        "hash mismatch: tasks or an archive request exist",
      );
      const badConfig = await w.tree("revalBad");
      const invalid = {
        schemaVersion: 1,
        triggers: [],
        scans: { sca: { enabled: true } },
        execution: {},
        notifications: {},
        extra: "not allowed",
      };
      const badVersion = await w.version(badConfig.pipeline, invalid, 2);
      const badExec = await w.execution(badConfig, { version: badVersion, archive: false });
      await w
        .orchestrator()
        .claimAndStart({ tenantId: badConfig.tenant.id, executionId: badExec.id });
      now = await w.row(badExec);
      ok(
        p,
        now.status === "failed" && now.statusReason === "prepare_failed:config_invalid",
        `invalid schema: ${now.status}/${now.statusReason}`,
      );
      ok(p, (await w.statusOf(otherExec)) === "queued", "another tenant's queued row was touched");
      // control
      const good = await w.tree("revalGood");
      const goodExec = await w.execution(good);
      const gr = await w
        .orchestrator()
        .claimAndStart({ tenantId: good.tenant.id, executionId: goodExec.id });
      ok(
        p,
        gr.outcome === "running" && (await w.statusOf(goodExec)) === "running",
        `control: a healthy row ended ${gr.outcome}`,
      );
      return p;
    },
  },
  {
    id: "EXE-017",
    name: "exactly-once claim: K concurrent claimers and duplicate wake-up messages on one execution produce one queued->preparing event, one archive request, one set of tasks (one per enabled scan type, at most the configured parallelism dispatched), one execution.started and one scan.task.requested per dispatched task; the execution then reaches a terminal state exactly once with one completed event",
    async run(w) {
      const p = [];
      const tree = await w.tree("once");
      const e = await w.execution(tree);
      const orchs = Array.from({ length: 6 }, () => w.orchestrator());
      const tarballs = (await w.sourceCalls()).tarballs.length;
      await Promise.all([
        ...orchs.map((o) => o.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id })),
        ...orchs
          .slice(0, 4)
          .map((o) => o.handler(requestedEnvelope(w, tree, e), { log: { info() {} } })),
      ]);
      const events = await w.events(e, { type: "transition" });
      ok(
        p,
        events.filter((x) => x.fromStatus === "queued" && x.toStatus === "preparing").length === 1,
        "not exactly one queued->preparing event",
      );
      ok(
        p,
        events.filter((x) => x.toStatus === "running").length === 1,
        "not exactly one preparing->running event",
      );
      ok(
        p,
        (await w.sourceCalls()).tarballs.length === tarballs + 1,
        "the archive was requested more than once",
      );
      const tasks = await w.taskRows(e);
      ok(
        p,
        tasks.map((t) => t.scanType).join() === "sbom,sca,sast,secrets",
        `tasks ${tasks.map((t) => t.scanType)}`,
      );
      const requests = await w.outbox(tree, { type: "scan.task.requested" });
      ok(
        p,
        requests.length === 2 &&
          requests.every((r) => ["sbom", "sca"].includes(r.payload.payload.scanType)),
        `${requests.length} scan.task.requested rows for the first dispatch (${requests.map((r) => r.payload.payload.scanType)}), expected the first two in catalog order`,
      );
      ok(
        p,
        (await w.audit(tree, { action: "execution.started" })).length === 1 &&
          (await w.audit(tree, { action: "execution.preparing" })).length === 1,
        "audit transitions are not exactly one each",
      );
      ok(p, owners(orchs, e).length === 1, `${owners(orchs, e).length} workers hold the execution`);
      const winner = owners(orchs, e)[0];
      await w.pump(tree, { orch: winner });
      const row = await w.row(e);
      ok(p, row.status === "succeeded" && row.finishedAt, `ended ${row.status}`);
      ok(
        p,
        (await w.completed(tree, e)).length === 1,
        "not exactly one pipeline.execution.completed",
      );
      ok(
        p,
        (await w.events(e, { type: "transition" })).length === 3,
        "not exactly three transition events",
      );
      ok(
        p,
        (await w.outbox(tree, { type: "scan.task.requested" })).length === 4,
        "not one scan.task.requested per task",
      );
      return p;
    },
  },
  {
    id: "EXE-018",
    name: "snapshot, not current configuration: after a request a new pipeline version with other scans and timeouts is published; the claimed execution's tasks and deadline equal the OLD version, and an execution requested after the edit uses the new one",
    async run(w) {
      const p = [];
      const tree = await w.tree("snap", {
        config: w.config1({
          scans: { sca: { enabled: true } },
          execution: { timeoutSeconds: 100, scanTaskTimeoutSeconds: 50 },
        }),
      });
      const first = await w.execution(tree);
      const next = w.config1({
        scans: { sast: { enabled: true }, secrets: { enabled: true } },
        execution: { timeoutSeconds: 200, scanTaskTimeoutSeconds: 80 },
      });
      const v2 = await w.version(
        tree.pipeline,
        (await import("../../../../workers/src/pipeline/execution-request.js")).CONFIG_SCHEMA.parse(
          next,
        ),
        2,
      );
      await w.db.pipeline.update({
        where: { id: tree.pipeline.id },
        data: { currentVersion: 2, currentVersionId: v2.id },
      });
      const second = await w.execution(tree, { version: v2, concurrencyGroup: "second" });
      const orch1 = w.orchestrator();
      await orch1.claimAndStart({ tenantId: tree.tenant.id, executionId: first.id });
      let tasks = await w.taskRows(first);
      let row = await w.row(first);
      ok(
        p,
        tasks.map((t) => t.scanType).join() === "sca" && tasks[0].timeoutSeconds === 50,
        `old execution tasks ${tasks.map((t) => `${t.scanType}/${t.timeoutSeconds}`)}`,
      );
      const seconds = (row.deadlineAt - row.claimedAt) / 1000;
      ok(p, Math.abs(seconds - 100) < 2, `old execution deadline is ${seconds}s, expected 100`);
      ok(p, row.configVersion === 1, "the execution's version changed");
      await w.pump(tree, { orch: orch1 }); // the first run ends (maxActive is 1), then the newer request is claimed: it uses the new version
      await w.orchestrator().claimAndStart({ tenantId: tree.tenant.id, executionId: second.id });
      tasks = await w.taskRows(second);
      row = await w.row(second);
      ok(
        p,
        tasks.map((t) => t.scanType).join() === "sast,secrets" && tasks[0].timeoutSeconds === 80,
        `new execution tasks ${tasks.map((t) => `${t.scanType}/${t.timeoutSeconds}`)}`,
      );
      ok(
        p,
        Math.abs((row.deadlineAt - row.claimedAt) / 1000 - 200) < 2,
        "the new execution's deadline is not the new version's",
      );
      return p;
    },
  },
  {
    id: "EXE-019",
    name: "no credentials anywhere: a fork pull request execution (trust untrusted_fork, fetched by its stored head SHA through the BASE repository with a contents:read token restricted to that repository, the redirect followed WITHOUT Authorization) and a trusted execution run end to end against the GitHub stub with recognisable installation tokens: no outbox payload, event row, log line, audit entry, result, item, task, execution row, scan context or captured worker log contains a token value, a private-key marker, an Authorization header, a secretRef or a URL with credentials; fork tasks go to scan-untrusted only; the fork's completed event is not resolution eligible",
    async run(w) {
      const p = [];
      const forkTree = await w.tree("fork");
      const forkExec = await w.fork(forkTree, { concurrencyGroup: "fork" });
      const logsBefore = w.logs.length;
      await w.stub("/__control/fail", { match: "/tarball/", status: 503, times: 1 }); // makes the worker log a retry
      const forkRun = await w.run(forkTree, forkExec);
      const trusted = await runScenario(w, "full");
      const calls = await w.sourceCalls();
      const tokens = calls.minted.map((m) => m.token);
      ok(p, tokens.length >= 2, "control: the stub minted no installation token");
      const forkTarballs = calls.tarballs.filter((t) => t.sha === forkExec.commitSha);
      ok(
        p,
        forkTarballs.length >= 1 &&
          forkTarballs.every(
            (t) =>
              t.scoped &&
              t.permissions?.contents === "read" &&
              Object.keys(t.permissions).length === 1,
          ),
        "control: the fork archive was not fetched with a token restricted to contents:read",
      );
      ok(
        p,
        calls.minted.some(
          (m) => m.repositories?.length === 1 && m.repositories[0] === forkTree.repoName,
        ),
        "control: the token was not restricted to the one repository",
      );
      ok(
        p,
        calls.codeload.length >= 2 && calls.codeload.every((c) => c.hasAuthorization === false),
        "the redirect target received an Authorization header",
      );
      ok(
        p,
        forkRun.row.status === "succeeded",
        `control: the fork execution ended ${forkRun.row.status}`,
      );
      const queues = (await w.outbox(forkTree, { type: "scan.task.requested" })).filter(
        (m) => m.payload.executionId === forkExec.id,
      );
      ok(
        p,
        queues.length === 4 && queues.every((m) => m.queue === "scan-untrusted"),
        `fork tasks went to ${[...new Set(queues.map((m) => m.queue))]}`,
      );
      const eligible = (await w.completed(forkTree, forkExec))[0]?.payload.payload
        .resolutionEligible;
      ok(p, eligible === false, "the fork execution was resolution eligible");
      for (const [label, tree] of [
        ["fork tenant", forkTree],
        ["trusted tenant", trusted.tree],
      ]) {
        const dump = await w.dump(tree);
        const text = dump + w.logs.slice(logsBefore).join("\n");
        for (const token of tokens)
          ok(p, !text.includes(token), `${label}: an installation token value is stored or logged`);
        ok(
          p,
          !TOKEN_SHAPES.test(dump),
          `${label}: ${dump.match(TOKEN_SHAPES)?.[0]} appears in stored rows`,
        );
        ok(
          p,
          !/:\/\/[^/\s:@"]+:[^/\s@"]+@/.test(dump),
          `${label}: a URL with credentials is stored`,
        );
      }
      ok(
        p,
        !TOKEN_SHAPES.test(w.logs.join("\n")),
        "a credential shape appears in the captured worker logs",
      );
      ok(
        p,
        w.logs.slice(logsBefore).some((l) => l.includes("retrying")),
        "control: the retry warning was not captured",
      );
      ok(
        p,
        w.contexts.length >= 8 && findCredentials(w.contexts).length === 0,
        "a scan context carries a credential",
      );
      const allowed = new Set([
        "executionId",
        "taskId",
        "attempt",
        "scanType",
        "engine",
        "severityThreshold",
        "trust",
        "deadlineSeconds",
        "sourceDir",
      ]);
      ok(
        p,
        w.contexts.every((c) => Object.keys(c).every((k) => allowed.has(k))),
        "a scan context carries a field outside the contract",
      );
      return p;
    },
  },
  {
    id: "EXE-020",
    name: "no repository code runs and the archive is hardened: an archive with a postinstall script, a Makefile, git hooks, an .npmrc, symlinks (one pointing outside), a hard link, ../ and absolute-path entries is scanned as data (no marker file appears, no link or escaping entry is extracted, nothing is written outside the work directory, extracted files are never executable); an oversize or bomb archive ends failed prepare_failed:archive_too_large (unit not given back), a wrong top directory archive_mismatch, a corrupt one archive_invalid; a benign archive is extracted and scanned",
    async run(w) {
      const p = [];
      const marker = `${w.tmp}/MARKER-executed`;
      const topDir = (tree, sha) => `${tree.org}-${tree.repoName}-${sha.slice(0, 7)}`;
      const tree = await w.tree("hard");
      const sha = w.sha();
      const dir = topDir(tree, sha);
      const hostile = [
        { name: "README.md", content: "# hostile\n" },
        {
          name: "package.json",
          content: JSON.stringify({ scripts: { postinstall: `touch ${marker}` } }),
        },
        { name: "Makefile", content: `all:\n\ttouch ${marker}\n` },
        { name: ".npmrc", content: "//registry.npmjs.org/:_authToken=npm_notatoken\n" },
        { name: ".git", dir: true },
        { name: ".git/hooks", dir: true },
        { name: ".git/hooks/post-checkout", content: `#!/bin/sh\ntouch ${marker}\n`, mode: 0o755 },
        { name: "src", dir: true },
        { name: "src/a.js", content: "x\n", mode: 0o755 },
        { name: "link", symlink: "/etc" },
        { name: "evil", symlink: "../../outside" },
        { name: "hard", hardlink: "README.md" },
        { name: `${dir}/../escape.txt`, raw: true, content: "x" },
        { name: "/abs-escape.txt", raw: true, content: "x" },
        { name: `${dir}/a/../../esc2.txt`, raw: true, content: "x" },
        { name: "qm-test.json", content: "{}" },
      ];
      const e = await w.execution(tree, { commitSha: sha, archive: false });
      await w.archive(tree, sha, hostile);
      const run = await w.run(tree, e);
      ok(
        p,
        run.row.status === "succeeded",
        `the hostile archive ended ${run.row.status}/${run.row.statusReason}`,
      );
      // the archive reader itself must never hand out an escaping or absolute path (a layer below the extractor's own check)
      const offered = [];
      await walkTarGz(Readable.from([makeTarGz(hostile, { topDir: dir })]), {
        onFile: ({ path: rel }) => {
          offered.push(rel);
          return null;
        },
        onDirectory: (rel) => offered.push(rel),
      });
      ok(
        p,
        offered.includes("README.md") &&
          offered.every((rel) => !rel.startsWith("/") && !rel.split("/").includes("..")),
        `the archive reader offered an unsafe path: ${offered.filter((rel) => rel.startsWith("/") || rel.split("/").includes(".."))}`,
      );
      const seen = w.fileTrees.filter((t) => t.executionId === e.id);
      ok(p, seen.length === 4, `${seen.length} scans received the tree`);
      const files = (seen[0]?.files ?? []).map((f) => f.path).sort();
      for (const want of [
        "README.md",
        "package.json",
        "Makefile",
        ".npmrc",
        ".git/hooks/post-checkout",
        "src/a.js",
      ])
        ok(p, files.includes(want), `control: ${want} was not extracted`);
      for (const bad of ["link", "evil", "hard", "escape.txt", "esc2.txt", "abs-escape.txt"])
        ok(p, !files.includes(bad), `${bad} was extracted`);
      ok(
        p,
        (seen[0]?.files ?? []).every(
          (f) => !f.symlink && (f.mode & 0o111) === 0 && (f.mode & 0o7000) === 0,
        ),
        "an extracted file is a link, executable or special",
      );
      const { stat } = await import("node:fs/promises");
      ok(p, !(await stat(marker).catch(() => null)), "repository code ran: the marker file exists");
      const found = [];
      const walk = async (d) => {
        const { readdir } = await import("node:fs/promises");
        for (const x of await readdir(d, { withFileTypes: true })) {
          if (["escape.txt", "esc2.txt", "abs-escape.txt"].includes(x.name)) found.push(x.name);
          if (x.isDirectory()) await walk(`${d}/${x.name}`);
        }
      };
      await walk(w.tmp);
      ok(
        p,
        found.length === 0 && !(await stat("/abs-escape.txt").catch(() => null)),
        `entries escaped the work directory: ${found}`,
      );
      ok(
        p,
        (await import("node:fs/promises").then((f) => f.readdir(w.scanTmp))).length === 0,
        "a scan work directory was left behind",
      );
      // hard limits
      const failing = async (label, entries, code, releases, buildOver = {}) => {
        const t = await w.tree(label);
        await w.setQuotaUsage(t, 3);
        const s = w.sha();
        const x = await w.execution(t, { commitSha: s, archive: false });
        const buffer = entries
          ? makeTarGz(entries, { topDir: buildOver.topDir ?? topDir(t, s) })
          : Buffer.from("this is not gzip data");
        await w.stub("/__control/archive", {
          fullName: t.fullName,
          sha: s,
          base64: buffer.toString("base64"),
        });
        await w.orchestrator().claimAndStart({ tenantId: t.tenant.id, executionId: x.id });
        const now = await w.row(x);
        ok(
          p,
          now.status === "failed" && now.statusReason === `prepare_failed:${code}`,
          `${label}: ${now.status}/${now.statusReason}, expected prepare_failed:${code}`,
        );
        ok(p, (await w.taskRows(x)).length === 0, `${label}: tasks exist`);
        ok(
          p,
          Boolean(now.quotaReleasedAt) === releases,
          `${label}: quota released ${Boolean(now.quotaReleasedAt)}, expected ${releases}`,
        );
        ok(
          p,
          !(await w.store.size({
            tenantId: t.tenant.id,
            executionId: x.id,
            name: "source.tar.gz",
          })),
          `${label}: the rejected archive was kept`,
        );
      };
      await failing(
        "oversize",
        [{ name: "big.bin", content: Buffer.alloc(2 * 1024 * 1024, 7) }],
        "archive_too_large",
        false,
      );
      await failing(
        "bomb",
        [
          { name: "zeros.bin", content: Buffer.alloc(900 * 1024) },
          { name: "more.bin", content: Buffer.alloc(900 * 1024) },
          { name: "again.bin", content: Buffer.alloc(900 * 1024) },
          { name: "last.bin", content: Buffer.alloc(900 * 1024) },
        ],
        "archive_too_large",
        false,
      );
      await failing("wrongdir", [{ name: "a.txt", content: "x" }], "archive_mismatch", false, {
        topDir: "someone-else-0000000",
      });
      await failing("corrupt", null, "archive_invalid", false);
      return p;
    },
  },
  {
    id: "EXE-034",
    name: "outcome aggregation and task orchestration: all tasks succeeded -> succeeded; one permanent failure with the others complete -> partial (tasks_incomplete) without a retry; no task succeeded -> failed (tasks_failed); a transient failure is retried once (attempt rows closed in order, the result ingested once) and a persistent one fails after the second attempt; tasks are dispatched in catalog order with at most two in flight; secret items keep at most a 4-character preview; exactly one completed event per execution",
    async run(w) {
      const p = [];
      const full = await runScenario(w, "full");
      const partial = await runScenario(w, "partial", { entries: withScript({ fail: ["sast"] }) });
      const failed = await runScenario(w, "failed", {
        entries: withScript({ fail: ["sbom", "sca", "sast", "secrets"] }),
      });
      const once = await runScenario(w, "transientOnce", {
        entries: withScript({ transientOnce: ["sca"] }),
      });
      const always = await runScenario(w, "transientAlways", {
        entries: withScript({ transientAlways: ["sca"] }),
      });
      const state = (s) => `${s.row.status}/${s.row.statusReason}`;
      ok(p, state(full) === "succeeded/null", `full: ${state(full)}`);
      ok(p, state(partial) === "partial/tasks_incomplete", `one failure: ${state(partial)}`);
      ok(p, state(failed) === "failed/tasks_failed", `all failed: ${state(failed)}`);
      ok(p, state(once) === "succeeded/null", `transient once: ${state(once)}`);
      ok(p, state(always) === "partial/tasks_incomplete", `transient always: ${state(always)}`);
      for (const s of [full, partial, failed, once, always])
        ok(p, s.completed.length === 1, `${state(s)}: ${s.completed.length} completed events`);
      ok(
        p,
        full.tasks.every((t) => t.status === "succeeded"),
        "full: a task did not succeed",
      );
      const attemptsOf = async (s, type) =>
        w.db.scanTaskAttempt.findMany({
          where: {
            executionId: s.execution.id,
            scanTaskId: s.tasks.find((t) => t.scanType === type).id,
          },
          orderBy: { attempt: "asc" },
        });
      const sastFail = await attemptsOf(partial, "sast");
      ok(
        p,
        sastFail.length === 1 &&
          sastFail[0].errorClass === "permanent" &&
          partial.tasks.find((t) => t.scanType === "sast").statusReason === "engine_rejected_input",
        "a permanent failure was retried or unclassified",
      );
      const retried = await attemptsOf(once, "sca");
      ok(
        p,
        retried.length === 2 &&
          retried[0].status === "failed" &&
          retried[0].errorClass === "transient" &&
          retried[1].status === "succeeded" &&
          retried[0].finishedAt,
        `transient once attempts: ${retried.map((a) => `${a.attempt}:${a.status}`)}`,
      );
      ok(
        p,
        (await w.db.scanResult.count({ where: { executionId: once.execution.id } })) === 4,
        "the retried task did not ingest exactly one result",
      );
      const reqs = (await w.outbox(once.tree, { type: "scan.task.requested" }))
        .filter((m) => m.payload.payload.scanType === "sca")
        .map((m) => m.payload.payload.attempt)
        .sort();
      ok(p, reqs.join() === "0,1", `sca requests ${reqs}`);
      const exhausted = await attemptsOf(always, "sca");
      ok(
        p,
        exhausted.length === 2 &&
          exhausted.every((a) => a.status === "failed") &&
          always.tasks.find((t) => t.scanType === "sca").status === "failed",
        "a persistent transient failure was not failed after two attempts",
      );
      // results and items: normalized, no secret value, one result per task
      const items = await w.db.scanResultItem.findMany({
        where: { executionId: full.execution.id },
      });
      const secret = items.find((i) => i.kind === "secret");
      ok(
        p,
        items.length === 4 &&
          secret &&
          !JSON.stringify(secret).includes("AKIAIOSFODNN7EXAMPLE") &&
          !("value" in secret.data) &&
          secret.data.preview === "AKIA",
        `secret item ${JSON.stringify(secret?.data)}`,
      );
      ok(
        p,
        (await w.db.scanResult.findMany({ where: { executionId: full.execution.id } })).every(
          (r) => r.completeness === "complete" && !r.truncated,
        ),
        "a full run has an incomplete result",
      );
      // dispatch order and the in-flight cap, from a fresh run: first dispatch is sbom + sca only
      const t = await w.tree("order");
      const e = await w.execution(t);
      const orch = w.orchestrator();
      await orch.claimAndStart({ tenantId: t.tenant.id, executionId: e.id });
      const queued = (await w.taskRows(e))
        .filter((x) => x.status === "queued")
        .map((x) => x.scanType);
      ok(p, queued.join() === "sbom,sca", `first dispatch ${queued}`);
      const scan = w.scanHandler();
      let maxInFlight = 0;
      await w.pump(t, {
        orch,
        scan,
        onRound: async () => {
          maxInFlight = Math.max(
            maxInFlight,
            await w.db.scanTask.count({
              where: { executionId: e.id, status: { in: ["queued", "running"] } },
            }),
          );
        },
      });
      ok(p, maxInFlight <= 2, `${maxInFlight} tasks in flight`);
      const order = (
        await w.db.scanTaskAttempt.findMany({
          where: { executionId: e.id },
          orderBy: { startedAt: "asc" },
          include: { task: true },
        })
      ).map((a) => a.task.scanType);
      ok(
        p,
        order.slice(0, 2).sort().join() === "sbom,sca" &&
          order.slice(2).sort().join() === "sast,secrets",
        `execution order ${order}`,
      );
      return p;
    },
  },
  {
    id: "EXE-025",
    name: "an incomplete scan never resolves: the single completed event carries resolutionEligible=false for partial, failed, timed_out, cancelled, incremental and untrusted_fork executions and true only for a fully succeeded, full, trusted one; no finding is touched",
    async run(w) {
      const p = [];
      const eligible = async (s) => s.completed[0]?.payload.payload.resolutionEligible;
      const full = await runScenario(w, "full");
      const incremental = await runScenario(w, "incremental", {
        exec: { scanKind: "incremental", scanKindReason: "no_baseline" },
      });
      const partial = await runScenario(w, "partial", { entries: withScript({ fail: ["sast"] }) });
      const failed = await runScenario(w, "failed", {
        entries: withScript({ fail: ["sbom", "sca", "sast", "secrets"] }),
      });
      const forkTree = await w.tree("eligFork");
      const forkExec = await w.fork(forkTree);
      const forkRun = await w.run(forkTree, forkExec);
      const fork = { completed: await w.completed(forkTree, forkExec), row: forkRun.row };
      // a fork run that is otherwise FULL and fully succeeded must still not be eligible (trust alone decides)
      const fullForkTree = await w.tree("eligForkFull");
      const fullForkExec = await w.fork(fullForkTree, {
        scanKind: "full",
        scanKindReason: "first_run",
      });
      const fullForkRun = await w.run(fullForkTree, fullForkExec);
      const fullFork = {
        completed: await w.completed(fullForkTree, fullForkExec),
        row: fullForkRun.row,
      };
      ok(
        p,
        fullFork.row.status === "succeeded" &&
          fullFork.row.scanKind === "full" &&
          fullFork.row.trust === "untrusted_fork" &&
          fullFork.completed.length === 1 &&
          fullFork.completed[0].payload.payload.resolutionEligible === false,
        `a full, fully succeeded fork run was eligible (${fullFork.row.status}/${fullFork.row.scanKind})`,
      );
      ok(
        p,
        (await eligible(full)) === true && full.row.status === "succeeded",
        "control: a full, trusted, fully succeeded run was not eligible",
      );
      for (const [label, s] of [
        ["incremental", incremental],
        ["partial", partial],
        ["failed", failed],
        ["fork", fork],
      ])
        ok(
          p,
          (await eligible(s)) === false && s.completed.length === 1,
          `${label}: eligible=${await eligible(s)} (${s.completed.length} events)`,
        );
      ok(
        p,
        fork.row.status === "succeeded" && fork.row.trust === "untrusted_fork",
        "the fork run was not a succeeded fork run",
      );
      // cancelled (the request honoured by the owner of the lease; the route is part D)
      const ct = await w.tree("eligCancel");
      const ce = await w.execution(ct);
      const corch = w.orchestrator();
      await corch.claimAndStart({ tenantId: ct.tenant.id, executionId: ce.id });
      await w.db
        .$executeRaw`UPDATE executions SET cancel_requested_at = now(), cancel_requested_by_user_id = ${ct.user.id}::uuid, cancel_mode = 'immediate', cancel_grace_until = now() WHERE id = ${ce.id}::uuid`;
      await corch.drive(corch.owned()[0]);
      const cancelled = { completed: await w.completed(ct, ce), row: await w.row(ce) };
      ok(
        p,
        cancelled.row.status === "cancelled" &&
          (await eligible(cancelled)) === false &&
          cancelled.completed[0].payload.payload.cancelRequested === true,
        `cancelled: ${cancelled.row.status}/${await eligible(cancelled)}`,
      );
      ok(p, !cancelled.row.quotaReleasedAt, "a cancelled running execution gave its unit back");
      // timed out
      const timed = await runScenario(w, "timeout-exec", {
        entries: withScript({ slow: ["sbom", "sca", "sast", "secrets"] }),
        config: w.config1({ execution: { timeoutSeconds: 2, scanTaskTimeoutSeconds: 2 } }),
      });
      ok(
        p,
        timed.row.status === "timed_out" &&
          (await eligible(timed)) === false &&
          timed.completed.length === 1,
        `timed_out: ${timed.row.status}/${await eligible(timed)}`,
      );
      return p;
    },
  },
  {
    id: "EXE-035",
    name: "timeouts: a task that exceeds its deadline ends timed_out with its partial result kept (incomplete) and the execution is partial; an execution past its deadline ends timed_out with the finished and timed-out tasks' results kept, unstarted tasks skipped, one completed event and no refund",
    async run(w) {
      const p = [];
      const task = await runScenario(w, "timeout-task", {
        entries: withScript({ slow: ["sca"] }),
        config: w.config1({ execution: { timeoutSeconds: 60, scanTaskTimeoutSeconds: 1 } }),
      });
      const sca = task.tasks.find((t) => t.scanType === "sca");
      ok(
        p,
        sca.status === "timed_out" && sca.statusReason === "task_deadline",
        `task: ${sca.status}/${sca.statusReason}`,
      );
      const result = await w.db.scanResult.findFirst({ where: { scanTaskId: sca.id } });
      ok(
        p,
        result && result.completeness === "incomplete" && result.itemCount === 1,
        "the timed-out task's partial result was not kept as incomplete",
      );
      ok(
        p,
        task.tasks.filter((t) => t.status === "succeeded").length === 3 &&
          task.row.status === "partial",
        `execution ${task.row.status} with ${task.tasks.map((t) => t.status)}`,
      );
      const exec = await runScenario(w, "timeout-exec", {
        entries: withScript({ slow: ["sbom", "sca", "sast", "secrets"] }),
        config: w.config1({ execution: { timeoutSeconds: 2, scanTaskTimeoutSeconds: 2 } }),
      });
      ok(
        p,
        exec.row.status === "timed_out" && exec.row.statusReason === "execution_deadline",
        `execution: ${exec.row.status}/${exec.row.statusReason}`,
      );
      const statuses = exec.tasks
        .map((t) => t.status)
        .sort()
        .join();
      ok(p, statuses === "skipped,skipped,timed_out,timed_out", `tasks ${statuses}`);
      ok(
        p,
        (await w.db.scanResult.count({ where: { executionId: exec.execution.id } })) === 2,
        "the timed-out tasks' results were not kept",
      );
      ok(
        p,
        exec.completed.length === 1 && !exec.row.quotaReleasedAt,
        "timed-out run: not exactly one completed event or the unit was refunded",
      );
      ok(
        p,
        exec.row.finishedAt && exec.row.taskCounts?.timed_out === 2,
        `task_counts ${JSON.stringify(exec.row.taskCounts)}`,
      );
      return p;
    },
  },
  {
    id: "EXE-024",
    name: "message allow-list: every message the orchestrator wrote (started, completed, status_changed, scan.task.requested/completed/status_changed) is accepted by the strict catalog schema, names the right tenant, contains only the documented payload fields and no credential, URL or free text",
    async run(w) {
      const p = [];
      await runScenario(w, "full");
      const FIELDS = {
        "pipeline.execution.started":
          "executionId,pipelineId,repositoryId,workspaceId,startedAt,taskCount",
        "pipeline.execution.completed":
          "executionId,pipelineId,repositoryId,workspaceId,status,statusReason,scanKind,trust,refType,refName,commitSha,pullRequestNumber,configVersion,configHash,startedAt,finishedAt,cancelRequested,resolutionEligible,tasks",
        "pipeline.execution.status_changed": "executionId,workspaceId,pipelineId,status,rev",
        "scan.task.requested":
          "executionId,taskId,scanType,attempt,pipelineId,repositoryId,workspaceId,trust,deadlineAt",
        "scan.task.completed": "executionId,taskId,scanType,attempt,status,resultId",
        "scan.task.status_changed": "executionId,taskId,workspaceId,scanType,status,rev",
      };
      const seen = new Set();
      for (const tree of w.allTrees) {
        for (const row of await w.outbox(tree)) {
          if (!FIELDS[row.type]) continue;
          seen.add(row.type);
          const message = row.payload;
          let parsed;
          try {
            parsed = parseMessage(message);
          } catch (error) {
            p.push(`${row.type}: not accepted by the catalog (${error.message})`);
            continue;
          }
          const keys = Object.keys(parsed.payload).sort().join();
          ok(
            p,
            keys === FIELDS[row.type].split(",").sort().join(),
            `${row.type}: payload fields ${keys}`,
          );
          ok(p, message.tenantId === tree.tenant.id, `${row.type}: wrong tenant in the envelope`);
          ok(
            p,
            findCredentials(message).length === 0 && !/https?:\/\//.test(JSON.stringify(message)),
            `${row.type}: credential or URL in the message`,
          );
          ok(
            p,
            !/"(message|log|logs|error|stack|title|body)"\s*:/.test(
              JSON.stringify(message.payload),
            ),
            `${row.type}: free text in the payload`,
          );
          const expectedQueue = {
            "scan.task.requested": ["scan", "scan-untrusted"],
            "scan.task.completed": ["pipeline"],
          }[row.type] ?? ["realtime"];
          ok(p, expectedQueue.includes(row.queue), `${row.type}: queued on ${row.queue}`);
        }
      }
      for (const type of Object.keys(FIELDS))
        ok(p, seen.has(type), `control: no ${type} message was produced`);
      return p;
    },
  },
  {
    id: "EXE-027",
    name: "lease reclaim exactly once: for a running and a preparing execution whose holder stopped heartbeating, eight parallel reclaimers produce exactly one epoch increment, one execution.lease_reclaimed audit entry and one recovered event, no duplicate task, archive request, outbox message or quota change; a repeated reclaim with the stale observed epoch and a reclaim of a live lease change nothing; another tenant's expired execution is untouched by tenant A's reclaimers; the single winner resumes and the execution ends once",
    async run(w) {
      const p = [];
      const x = await lostWorld(w);
      const orchs = Array.from({ length: 8 }, () => w.orchestrator());
      const snapshot = async (tree, e) => ({
        tasks: (await w.taskRows(e)).length,
        requests: (await w.outbox(tree, { type: "scan.task.requested" })).length,
        started: (await w.outbox(tree, { type: "pipeline.execution.started" })).length,
        usage: await w.quotaUsage(tree),
      });
      const beforeR = await snapshot(x.R.tree, x.R.execution);
      const beforeB = json(await w.row(x.B.execution));
      const tarballs = (await w.sourceCalls()).tarballs.filter(
        (t) => t.sha === x.P.execution.commitSha,
      ).length;
      await reclaimAll(orchs, x.R.tree, x.R.execution, 1);
      await reclaimAll(orchs, x.P.tree, x.P.execution, 1);
      for (const [label, e, tree] of [
        ["running", x.R.execution, x.R.tree],
        ["preparing", x.P.execution, x.P.tree],
      ]) {
        const row = await w.row(e);
        ok(p, row.leaseEpoch === 2, `${label}: lease_epoch ${row.leaseEpoch}, expected 2`);
        ok(
          p,
          (await w.audit(tree, { action: "execution.lease_reclaimed", targetId: e.id })).length ===
            1,
          `${label}: not exactly one lease_reclaimed audit entry`,
        );
        ok(
          p,
          (await w.events(e, { type: "recovered" })).length === 1,
          `${label}: not exactly one recovered event`,
        );
        ok(
          p,
          owners(orchs, e).length === 1,
          `${label}: ${owners(orchs, e).length} workers resumed it`,
        );
      }
      const afterR = await snapshot(x.R.tree, x.R.execution);
      ok(
        p,
        JSON.stringify(afterR) === JSON.stringify(beforeR),
        `running: reclaim duplicated work ${JSON.stringify([beforeR, afterR])}`,
      );
      const afterP = await snapshot(x.P.tree, x.P.execution);
      ok(
        p,
        afterP.tasks === 4 && afterP.started === 1 && afterP.requests === 2,
        `preparing: resumed with ${JSON.stringify(afterP)}`,
      );
      ok(
        p,
        (await w.sourceCalls()).tarballs.filter((t) => t.sha === x.P.execution.commitSha).length ===
          tarballs + 1,
        "preparing: the archive was requested more than once",
      );
      // stale epoch, live lease, other tenant
      await reclaimAll(orchs, x.R.tree, x.R.execution, 1);
      await reclaimAll(orchs, x.R.tree, x.R.execution, 2); // the lease taken a moment ago is live
      ok(
        p,
        (await w.row(x.R.execution)).leaseEpoch === 2,
        "a stale or live reclaim moved the epoch",
      );
      await reclaimAll(orchs, x.R.tree, x.B.execution, 1); // tenant A naming tenant B's execution
      ok(
        p,
        json(await w.row(x.B.execution)) === beforeB,
        "tenant A's reclaimers changed tenant B's expired execution",
      );
      // a reclaimer that observed epoch 1 must lose even when the epoch-2 lease has expired in the meantime
      const lone = await w.tree("reclaimEpoch");
      const le = await w.execution(lone);
      const ids = { tenantId: lone.tenant.id, executionId: le.id };
      await w.repo.claimQueued({
        ...ids,
        workerId: "a",
        leaseTtlSeconds: 1,
        deadlineSeconds: 600,
        staleThresholdSeconds: 36 * 3600,
      });
      await sleep(1200);
      const first = await w.repo.reclaimLease({
        ...ids,
        workerId: "b",
        observedEpoch: 1,
        leaseTtlSeconds: 1,
      });
      ok(p, first?.leaseEpoch === 2, "control: the first reclaim did not win");
      await sleep(1200);
      const stale = await w.repo.reclaimLease({
        ...ids,
        workerId: "c",
        observedEpoch: 1,
        leaseTtlSeconds: 1,
      });
      ok(
        p,
        stale === null && (await w.row(le)).leaseEpoch === 2,
        "a reclaimer with a stale observed epoch won",
      );
      const current = await w.repo.reclaimLease({
        ...ids,
        workerId: "d",
        observedEpoch: 2,
        leaseTtlSeconds: 60,
      });
      ok(p, current?.leaseEpoch === 3, "control: a reclaimer with the current epoch lost");
      // control: the winner resumes and the execution ends once
      const winner = owners(orchs, x.R.execution)[0];
      await w.pump(x.R.tree, { orch: winner });
      const done = await w.row(x.R.execution);
      ok(
        p,
        done.status === "succeeded" && (await w.completed(x.R.tree, x.R.execution)).length === 1,
        `control: ended ${done.status}`,
      );
      ok(
        p,
        (await w.events(x.R.execution, { type: "transition" })).filter((e) =>
          ["succeeded", "failed", "partial"].includes(e.toStatus),
        ).length === 1,
        "more than one terminal transition",
      );
      return p;
    },
  },
  {
    id: "EXE-028",
    name: "a zombie writer is rejected after a reclaim: a holder that stopped heartbeating past its TTL and wakes after another worker reclaimed its execution can no longer renew, drive, transition, create or queue tasks, record events, pin the commit, record the archive, release quota or close out tasks (every write is refused and the rows, events, outbox, audit, results and usage stay byte-identical); a scan worker's late result for the superseded attempt is refused by the database; the new holder's writes under the new epoch succeed",
    async run(w) {
      const p = [];
      const x = await lostWorld(w);
      const { tree, execution } = x.Z;
      const h2 = w.orchestrator();
      await h2.reclaimOne({ tenantId: tree.tenant.id, id: execution.id, leaseEpoch: 1 });
      ok(
        p,
        (await w.row(execution)).leaseEpoch === 2,
        "control: the reclaim did not take the lease",
      );
      const tasks = await w.taskRows(execution);
      ok(
        p,
        tasks[0].attempt === 1 && tasks[0].status === "queued",
        `control: the dead scan worker's task is ${tasks[0].status}/attempt ${tasks[0].attempt}, expected queued/1`,
      );
      const before = await w.fingerprint(tree);
      const usage = await w.quotaUsage(tree);
      const base = { tenantId: tree.tenant.id, executionId: execution.id, leaseEpoch: 1 };
      const refuses = async (label, fn) => {
        const error = await fn().then(
          () => null,
          (e) => e,
        );
        ok(
          p,
          error?.name === "LeaseLostError" || (error && /refused|not allowed/.test(error.message)),
          `${label} was accepted (${error?.name ?? "no error"})`,
        );
      };
      // the zombie holder, through its own process
      const renew = await w.repo.renewLease({
        ...base,
        workerId: x.h1.workerId,
        leaseTtlSeconds: 60,
      });
      ok(p, renew.renewed === false, "the zombie renewed the lease");
      await x.h1.heartbeat();
      await x.h1.drive(x.zEntry);
      // direct writes with the stale epoch
      const moved = await w.repo.transitionExecution({
        ...base,
        from: "running",
        to: "failed",
        reason: "suite_zombie",
      });
      ok(p, !moved.transitioned && !moved.quotaReleased, "a zombie transition succeeded");
      await refuses("createTasks", () =>
        w.db.$transaction((tx) => w.tasks.createTasks({ ...base, tasks: [] }, tx)),
      );
      await refuses("queuePending", () =>
        w.db.$transaction((tx) => w.tasks.queuePending({ ...base, limit: 2 }, tx)),
      );
      await refuses("closeOutTasks", () =>
        w.db.$transaction((tx) =>
          w.tasks.closeOutTasks(
            {
              ...base,
              runningTo: "timed_out",
              pendingTo: "skipped",
              reason: "suite_zombie",
              errorClass: "timeout",
              errorCode: "suite_zombie",
            },
            tx,
          ),
        ),
      );
      await refuses("recordEvent", () =>
        w.repo.recordEvent({ ...base, type: "recovered", details: {} }),
      );
      await refuses("pinCommit", () => w.repo.pinCommit({ ...base, commitSha: "b".repeat(40) }));
      await refuses("recordArchive", () =>
        w.repo.recordArchive({ ...base, sha256: "b".repeat(64), bytes: 1 }),
      );
      // a zombie scan worker: the superseded attempt 0 can finish nothing
      const sbom = tasks[0];
      const late = await w.tasks.finishTask({
        tenantId: tree.tenant.id,
        taskId: sbom.id,
        attempt: 0,
        status: "succeeded",
        result: {
          engineId: "default",
          engineVersion: "x",
          completeness: "complete",
          truncated: false,
          severityCounts: {},
          items: [],
        },
      });
      ok(p, late.finished === false, "a late result of the superseded attempt was ingested");
      const insert = await w.db
        .$executeRaw`INSERT INTO scan_results (id, tenant_id, workspace_id, repository_id, pipeline_id, execution_id, scan_task_id, attempt, scan_type, engine_id, engine_version, completeness)
        VALUES (gen_random_uuid(), ${tree.tenant.id}::uuid, ${tree.ws.id}::uuid, ${tree.repo.id}::uuid, ${execution.pipelineId}::uuid, ${execution.id}::uuid, ${sbom.id}::uuid, 0, 'sbom', 'default', 'x', 'complete')`.then(
        () => "inserted",
        (e) => String(e.message),
      );
      ok(
        p,
        insert !== "inserted" && /refused|not the running attempt/.test(insert),
        `the database accepted a result for a superseded attempt (${insert.slice(0, 80)})`,
      );
      const renewTask = await w.tasks.renewTaskLease({
        tenantId: tree.tenant.id,
        taskId: sbom.id,
        attempt: 0,
        workerId: "zombie-scan",
        leaseTtlSeconds: 60,
      });
      ok(p, renewTask.renewed === false, "the zombie scan worker renewed a superseded attempt");
      ok(
        p,
        (await w.fingerprint(tree)) === before && (await w.quotaUsage(tree)) === usage,
        "the zombie's attempts changed rows, events, outbox, audit, results or usage",
      );
      // attempt 1 is running (another scan worker); the zombie's late finish of attempt 0 must neither finish the task nor close
      // the new attempt's row
      const claimed1 = await w.tasks.claimTask({
        tenantId: tree.tenant.id,
        executionId: execution.id,
        taskId: sbom.id,
        attempt: 1,
        workerId: "new-scan",
        leaseTtlSeconds: 60,
      });
      ok(p, Boolean(claimed1), "control: attempt 1 was not claimable");
      const lateZombie = await w.tasks
        .finishTask({
          tenantId: tree.tenant.id,
          taskId: sbom.id,
          attempt: 0,
          status: "failed",
          reason: "zombie",
        })
        .then(
          (r) => r,
          (e) => ({ threw: e.message }),
        );
      const running1 = await w.db.scanTaskAttempt.findFirst({
        where: { scanTaskId: sbom.id, attempt: 1 },
      });
      ok(
        p,
        lateZombie.finished === false &&
          running1?.status === "running" &&
          (await w.db.scanTask.findUnique({ where: { id: sbom.id } })).status === "running",
        `a zombie's late finish of attempt 0 touched attempt 1 (${JSON.stringify(lateZombie)}, attempt row ${running1?.status})`,
      );
      const done1 = await w.tasks.finishTask({
        tenantId: tree.tenant.id,
        taskId: sbom.id,
        attempt: 1,
        status: "succeeded",
      });
      ok(p, done1.finished === true, "control: the current attempt could not finish");
      // the new holder's writes succeed and the run ends once
      await w.pump(tree, { orch: h2 });
      const row = await w.row(execution);
      ok(
        p,
        row.status === "succeeded" && row.leaseEpoch === 2,
        `control: the new holder ended ${row.status}`,
      );
      const attempts = await w.db.scanTaskAttempt.findMany({
        where: { scanTaskId: sbom.id },
        orderBy: { attempt: "asc" },
      });
      ok(
        p,
        attempts.length === 2 &&
          attempts[0].errorClass === "lease_expired" &&
          attempts[1].status === "succeeded",
        `attempts ${attempts.map((a) => `${a.attempt}:${a.status}/${a.errorClass}`)}`,
      );
      return p;
    },
  },
  {
    id: "EXE-029",
    name: "heartbeat and configuration: a renewal with the held epoch and owner moves the expiry and heartbeat forward without touching status_rev, events, audit or the epoch; a wrong owner or a stale epoch moves nothing; a holder that keeps heartbeating for several TTL lengths is never reclaimable and the run completes without a recovery; the worker configuration with TTL <= 3 x heartbeat is refused at start",
    async run(w) {
      const p = [];
      const tree = await w.tree("beat");
      const e = await w.execution(tree);
      const orch = w.orchestrator();
      await orch.claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
      const base = {
        tenantId: tree.tenant.id,
        executionId: e.id,
        workerId: orch.workerId,
        leaseEpoch: 1,
        leaseTtlSeconds: 4,
      };
      const before = await w.row(e);
      const eventsBefore = (await w.events(e)).length;
      const auditBefore = (await w.audit(tree)).length;
      await sleep(1100);
      const r = await w.repo.renewLease(base);
      const after = await w.row(e);
      ok(
        p,
        r.renewed &&
          after.leaseExpiresAt > before.leaseExpiresAt &&
          after.heartbeatAt > before.heartbeatAt,
        "a renewal did not move the lease forward",
      );
      ok(
        p,
        after.statusRev === before.statusRev &&
          after.leaseEpoch === 1 &&
          (await w.events(e)).length === eventsBefore &&
          (await w.audit(tree)).length === auditBefore,
        "a renewal changed status_rev, the epoch, events or audit",
      );
      const wrongOwner = await w.repo.renewLease({ ...base, workerId: "someone-else" });
      const staleEpoch = await w.repo.renewLease({ ...base, leaseEpoch: 0 });
      const frozen = await w.row(e);
      ok(
        p,
        !wrongOwner.renewed &&
          !staleEpoch.renewed &&
          frozen.leaseExpiresAt.getTime() === after.leaseExpiresAt.getTime(),
        "a wrong owner or a stale epoch moved the lease",
      );
      // several TTL lengths with the heartbeat running
      const thief = w.orchestrator();
      for (let i = 0; i < 7; i += 1) {
        await sleep(1300);
        await orch.heartbeat();
        await thief.reclaimOne({ tenantId: tree.tenant.id, id: e.id, leaseEpoch: 1 });
      }
      ok(
        p,
        (await w.row(e)).leaseEpoch === 1 &&
          (await w.events(e, { type: "recovered" })).length === 0,
        "a heartbeating holder was reclaimed",
      );
      await w.pump(tree, { orch });
      ok(
        p,
        (await w.statusOf(e)) === "succeeded" &&
          (await w.events(e, { type: "recovered" })).length === 0,
        "control: the run did not complete without a recovery",
      );
      // configuration
      const refused = (over) => {
        try {
          w.config(over);
          return null;
        } catch (error) {
          return error;
        }
      };
      const bad = refused({ EXECUTION_HEARTBEAT_SECONDS: "10", EXECUTION_LEASE_TTL_SECONDS: "30" });
      ok(
        p,
        bad instanceof ConfigError &&
          bad.problems.some((x) => x.variable === "EXECUTION_LEASE_TTL_SECONDS"),
        "TTL = 3 x heartbeat was accepted",
      );
      ok(
        p,
        refused({ EXECUTION_HEARTBEAT_SECONDS: "10", EXECUTION_LEASE_TTL_SECONDS: "31" }) === null,
        "control: TTL > 3 x heartbeat was refused",
      );
      ok(
        p,
        refused({ ARTIFACT_STORE_ROOT: "relative/path" }) instanceof ConfigError,
        "a relative artifact root was accepted while the orchestrator is enabled",
      );
      return p;
    },
  },
  {
    id: "EXE-030",
    name: "worker_lost decisions after a reclaim: a preparing execution whose recorded archive is missing, a running execution beyond the reclaim limit, and a running task of a non-idempotent engine end worker_lost (audit execution.worker_lost + execution.failed or the task failure plus the aggregated status, epoch/step/decision in the event details, own tenant only); a cancel-requested execution ends cancelled and a past-deadline one timed_out, not worker_lost; an idempotent preparing step is resumed (execution.recovered) and completes",
    async run(w) {
      const p = [];
      const x = await lostWorld(w);
      const ids = (s) => ({ tenantId: s.tree.tenant.id, id: s.execution.id });
      const reclaim = (s, orch, epoch = 1) => orch.reclaimOne({ ...ids(s), leaseEpoch: epoch });
      // W1
      await reclaim(x.W1, w.orchestrator());
      let row = await w.row(x.W1.execution);
      ok(
        p,
        row.status === "failed" && row.statusReason === "worker_lost",
        `missing archive: ${row.status}/${row.statusReason}`,
      );
      const lost = await w.audit(x.W1.tree, { targetId: x.W1.execution.id });
      ok(
        p,
        lost.some((a) => a.action === "execution.worker_lost") &&
          lost.some((a) => a.action === "execution.failed"),
        "missing archive: worker_lost/failed audit entries are missing",
      );
      const ev = (await w.events(x.W1.execution, { type: "transition", toStatus: "failed" }))[0];
      ok(
        p,
        ev?.details?.epoch === 2 &&
          ev.details.decision === "fail" &&
          ev.details.step === "preparing",
        `event details ${JSON.stringify(ev?.details)}`,
      );
      ok(
        p,
        !JSON.stringify(ev?.details ?? {}).match(TOKEN_SHAPES),
        "event details contain a credential shape",
      );
      ok(
        p,
        (await w.audit(x.B.tree, { action: "execution.worker_lost" })).length === 0,
        "another tenant has a worker_lost audit entry",
      );
      // W2: reclaim limit
      await reclaim(x.W2, w.orchestrator({ EXECUTION_MAX_RECLAIMS: "0" }));
      row = await w.row(x.W2.execution);
      ok(
        p,
        row.status === "failed" && row.statusReason === "worker_lost" && !row.quotaReleasedAt,
        `reclaim limit: ${row.status}/${row.statusReason} released ${row.quotaReleasedAt}`,
      );
      ok(
        p,
        (await w.taskRows(x.W2.execution)).every((t) => ["skipped", "failed"].includes(t.status)),
        "reclaim limit: tasks were left open",
      );
      // W3: non-idempotent engine
      const w3 = w.orchestrator({}, { engines: w.registry({ idempotent: false }) });
      await reclaim(x.W3, w3);
      const tasks = await w.taskRows(x.W3.execution);
      const sbom = tasks.find((t) => t.scanType === "sbom");
      ok(
        p,
        sbom.status === "failed" && sbom.statusReason === "worker_lost",
        `non-idempotent task ${sbom.status}/${sbom.statusReason}`,
      );
      const attempt = await w.db.scanTaskAttempt.findFirst({ where: { scanTaskId: sbom.id } });
      ok(
        p,
        attempt?.errorClass === "lease_expired" && attempt.finishedAt,
        "the lost task's attempt was not closed lease_expired",
      );
      await w.pump(x.W3.tree, { orch: w3 });
      row = await w.row(x.W3.execution);
      ok(
        p,
        row.status === "partial",
        `non-idempotent: execution ${row.status}, expected the aggregated partial`,
      );
      // W4, W5
      await reclaim(x.W4, w.orchestrator());
      row = await w.row(x.W4.execution);
      ok(
        p,
        row.status === "cancelled" && row.statusReason === "user_cancelled",
        `cancel requested: ${row.status}/${row.statusReason}`,
      );
      await reclaim(x.W5, w.orchestrator());
      row = await w.row(x.W5.execution);
      ok(
        p,
        row.status === "timed_out" &&
          row.statusReason === "execution_deadline" &&
          !row.quotaReleasedAt,
        `past deadline: ${row.status}/${row.statusReason}`,
      );
      // control: an idempotent preparing step is resumed and completes (execution P of EXE-027)
      const resumed = await w.row(x.P.execution);
      ok(
        p,
        ["running", "succeeded"].includes(resumed.status) &&
          (await w.audit(x.P.tree, { action: "execution.recovered" })).length === 1,
        `control: the resumed preparing execution is ${resumed.status}`,
      );
      return p;
    },
  },
  {
    id: "EXE-031",
    name: "quota is not double-released on lease loss: a preparing execution failed worker_lost releases its unit exactly once (eight parallel reclaimers, a zombie's late terminal and release attempt, a replay); a running worker_lost releases nothing; usage never falls below the pre-request value and another tenant's usage is unchanged",
    async run(w) {
      const p = [];
      const x = await lostWorld(w);
      const { tree, execution: e } = x.Q;
      const bUsage = await w.quotaUsage(x.B.tree);
      await w.setQuotaUsage(tree, 5);
      // eight reclaimers and the late terminal-plus-release of the stale holder race; whoever wins, the unit goes back once
      const racers = await Promise.all([
        ...Array.from({ length: 8 }, () =>
          w.orchestrator().reclaimOne({ tenantId: tree.tenant.id, id: e.id, leaseEpoch: 1 }),
        ),
        w.repo.transitionExecution({
          tenantId: tree.tenant.id,
          executionId: e.id,
          from: "preparing",
          to: "failed",
          reason: "zombie",
          leaseEpoch: 1,
          releaseQuota: true,
        }),
      ]);
      ok(p, racers.length === 9, "fixture");
      let row = await w.row(e);
      ok(
        p,
        row.status === "failed" && row.quotaReleasedAt,
        `ended ${row.status}/${row.statusReason}, released ${row.quotaReleasedAt}`,
      );
      ok(
        p,
        (await w.quotaUsage(tree)) === 4,
        `usage ${await w.quotaUsage(tree)} after the race, expected exactly one unit back (4)`,
      );
      ok(
        p,
        (await w.events(e, { type: "transition", toStatus: "failed" })).length === 1,
        "more than one terminal transition",
      );
      // replays and a zombie after the end release nothing more
      const late = await w.repo.transitionExecution({
        tenantId: tree.tenant.id,
        executionId: e.id,
        from: "preparing",
        to: "failed",
        reason: "worker_lost",
        leaseEpoch: 1,
        releaseQuota: true,
      });
      await Promise.all(
        Array.from({ length: 4 }, () =>
          w.orchestrator().reclaimOne({ tenantId: tree.tenant.id, id: e.id, leaseEpoch: 1 }),
        ),
      );
      ok(
        p,
        !late.transitioned && !late.quotaReleased && (await w.quotaUsage(tree)) === 4,
        "a zombie or a replay released a second time",
      );
      ok(p, (await w.quotaUsage(x.B.tree)) === bUsage, "tenant B's usage changed");
      // a running execution failed worker_lost does not give its unit back
      const usageW2 = await w.quotaUsage(x.W2.tree);
      await w
        .orchestrator({ EXECUTION_MAX_RECLAIMS: "0" })
        .reclaimOne({ tenantId: x.W2.tree.tenant.id, id: x.W2.execution.id, leaseEpoch: 1 });
      row = await w.row(x.W2.execution);
      ok(
        p,
        row.status === "failed" &&
          row.statusReason === "worker_lost" &&
          !row.quotaReleasedAt &&
          (await w.quotaUsage(x.W2.tree)) === usageW2,
        `a running worker_lost changed usage (${row.status}/${row.statusReason})`,
      );
      // control: the preparing worker_lost of a missing archive (EXE-030) releases exactly its own unit
      return p;
    },
  },
  {
    id: "EXE-036",
    name: "off by default and no engine, no work: with the flag off the pipeline queue handler is the no-op handler (the orchestrator is not even built) and the scan worker configuration neither requires nor accepts GitHub App settings; with the flag on but no engine registered every task is created unsupported and the execution ends failed (tasks_unsupported) instead of staying queued (SPEC §17.ab); the orchestrator configuration is validated (absolute artifact root, database)",
    async run(w) {
      const p = [];
      const tree = await w.tree("flagoff");
      const e = await w.execution(tree);
      const before = await w.fingerprint(tree);
      const off = w.config({ EXECUTION_ORCHESTRATOR_ENABLED: "false" });
      ok(p, off.execution.enabled === false, "the default flag is not false");
      const handler = selectPipelineHandler({ config: off }, () => {
        throw new Error("built");
      });
      await handler(requestedEnvelope(w, tree, e), { log: { info() {} }, attempt: 1 });
      ok(
        p,
        (await w.fingerprint(tree)) === before && (await w.statusOf(e)) === "queued",
        "the flag-off handler changed state",
      );
      const unset = w.baseEnv();
      delete unset.EXECUTION_ORCHESTRATOR_ENABLED;
      const { loadWorkerConfig } = await import("../../../../workers/src/config.js");
      ok(
        p,
        loadWorkerConfig(unset, { workerName: "pipeline" }).execution.enabled === false,
        "an unset flag is not off",
      );
      // the scan worker config ignores the GitHub App settings entirely
      const scanEnv = w.baseEnv({ GITHUB_APP_CLIENT_ID: "" });
      const scan = loadWorkerConfig(scanEnv, { workerName: "scan" });
      ok(
        p,
        scan.scm.enabled === false && !JSON.stringify(scan).includes(w.stubUrl),
        "the scan worker configuration carries GitHub settings",
      );
      let pipelineRefused = false;
      try {
        loadWorkerConfig(scanEnv, { workerName: "pipeline" });
      } catch (error) {
        pipelineRefused = error instanceof ConfigError;
      }
      ok(p, pipelineRefused, "control: the same environment is accepted by the pipeline worker");
      // enabled but no engine registered (SPEC §17.ab, amends EQ-7): NOT deferred; every task is created unsupported, nothing is
      // queued, the execution ends failed (tasks_unsupported: nothing could run) with its quota unit consumed
      const e2 = await w.execution(tree);
      const emptyOrch = w.orchestrator(
        {},
        {
          engines: (
            await import("../../../../workers/src/execution/engines.js")
          ).createEngineRegistry(),
        },
      );
      const r = await emptyOrch.claimAndStart({ tenantId: tree.tenant.id, executionId: e2.id });
      await w.pump(tree, { orch: emptyOrch });
      const emptyTasks = await w.taskRows(e2);
      ok(
        p,
        r.outcome === "failed" &&
          emptyTasks.length === 4 &&
          emptyTasks.every(
            (t) => t.status === "unsupported" && t.statusReason === "engine_not_registered",
          ) &&
          (await w.statusOf(e2)) === "failed" &&
          (await w.row(e2)).statusReason === "tasks_unsupported",
        `with no engine the execution was not run to its end by the unsupported rule (${r.outcome}, ${await w.statusOf(e2)})`,
      );
      const noRoot = (() => {
        try {
          w.config({ ARTIFACT_STORE_ROOT: "" });
          return null;
        } catch (error) {
          return error;
        }
      })();
      ok(p, noRoot instanceof ConfigError, "an empty artifact root was accepted");
      // control: with the engines registered the same row is claimed
      const on = await w
        .orchestrator()
        .claimAndStart({ tenantId: tree.tenant.id, executionId: e.id });
      ok(p, on.outcome === "running", `control: ${on.outcome}`);
      return p;
    },
  },
];
