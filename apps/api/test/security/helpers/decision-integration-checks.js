import { randomUUID } from "node:crypto";
import { createEventEnvelope, parseMessage } from "@qmentisai/contracts";
import { createExecutionCancellation, createScanDecisionRepository } from "@qmentisai/db";
import { findCredentials } from "@qmentisai/infra";
import { buildHint } from "../../../src/realtime/hints.js";
import { runtimeFor, scan, startLlm } from "./decision-agent-checks.js";
import { sleep } from "./orchestrator.js";

/**
 * The scan decision inside the Executions `preparing` state, safety properties only (ADR-008 area 17 as extended by AP-7,
 * docs/modules/scan-decisioning/SPEC.md 14.1 `DEC-S05`, `DEC-S06`, `DEC-S08`, `DEC-S09`, `DECDB-`; Part E). The real orchestrator,
 * repositories, outbox, ownership verifier and GitHub client run against the disposable database, the GitHub stub and a scripted
 * model stub (Ollama shape). What is proved:
 * - RECLAIM: a lease reclaim never makes a second model call (with a persisted record, with only the `decision_started` marker),
 *   the task set stays the decided one, and a marker-only reclaim ends `interrupted` with the floor;
 * - ATOMICITY: the decision row, the `decision_completed` event, the tasks and the `preparing -> running` transition are ONE unit
 *   (a failure at any step leaves none of them), and a zombie holder writes none of them;
 * - ZERO-SCAN: `succeeded` / `no_applicable_scans`, no task, the quota unit given back exactly once (also under concurrent
 *   reclaimers and a racing cancel), never resolution-eligible, one completed message;
 * - TASKS ONLY FOR THE DECIDED TYPES: a floor type always has a task, a type outside the final set has no task and no message,
 *   not selected is not partial;
 * - the database guards of `scan_decisions` and the amended status-reason and quota-release rules.
 * The floor's file-to-scan rule table is feature behavior and is NOT tested here (it is exercised in the live test).
 */

const ALL = ["sbom", "sca", "sast", "secrets"];
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const json = (value) =>
  JSON.stringify(value, (_k, x) => (typeof x === "bigint" ? x.toString() : x));
const docsOnly = [{ filename: "docs/readme.md", status: "modified", additions: 1, deletions: 0 }];
const modifiedCode = [{ filename: "src/a.js", status: "modified", additions: 2, deletions: 1 }];
const manifestAndCode = [
  { filename: "package.json", status: "modified", additions: 1, deletions: 0 },
  { filename: "src/a.js", status: "modified", additions: 2, deletions: 1 },
];
const removedCode = [{ filename: "src/a.js", status: "removed", additions: 0, deletions: 3 }];
const types = (rows) => rows.map((r) => r.scanType).join();
const dec = (db) => createScanDecisionRepository({ db });

/** An incremental push execution whose compare answer the stub knows. */
async function incremental(w, label, { files = docsOnly, config, exec = {} } = {}) {
  const tree = await w.tree(label, config ? { config } : {});
  const base = w.sha();
  const head = w.sha();
  await w.stub("/__control/compare", { fullName: tree.fullName, base, head, files });
  const execution = await w.execution(tree, {
    commitSha: head,
    baseSha: base,
    scanKind: "incremental",
    scanKindReason: "push",
    ...exec,
  });
  return { tree, execution, base, head };
}

const changeCalls = async (w, fullName) =>
  (await w.stub("/__control/change-calls", {})).calls.filter((c) => c.fullName === fullName).length;
const usedUnits = (w, tree) => w.quotaUsage(tree);

/** Claims an execution as a worker that then dies (short lease), leaving it `preparing` at epoch 1. */
const claimAndDie = (w, tree, execution, leaseTtlSeconds = 1) =>
  w.repo.claimQueued({
    tenantId: tree.tenant.id,
    executionId: execution.id,
    workerId: "dead-claimer",
    leaseTtlSeconds,
    deadlineSeconds: 600,
    staleThresholdSeconds: 36 * 3600,
  });

const decisionOf = (w, e) => w.db.scanDecision.findFirst({ where: { executionId: e.id } });
const eventTypes = async (w, e, type) =>
  w.db.executionEvent.count({ where: { executionId: e.id, type } });
const hintsOf = (w, tree, e) =>
  w
    .outbox(tree, { type: "pipeline.execution.decision_completed" })
    .then((rows) => rows.filter((m) => m.payload.executionId === e.id));

/** A valid decision to insert directly (the repository shape). */
const decisionFor = ({ floor = ["secrets"], added = [], enabled = ALL, final }) => {
  const finalTypes = final ?? ALL.filter((t) => floor.includes(t) || added.includes(t));
  return {
    diff: {
      source: "github_compare",
      status: "complete",
      changedTotal: 1,
      summary: {
        total: 1,
        byClass: { docs: 1 },
        byStatus: { modified: 1 },
        additions: 1,
        deletions: 0,
        samples: { docs: ["docs/readme.md"] },
      },
    },
    secretsRule: "any_change",
    floor: ALL.filter((t) => floor.includes(t)).map((scanType) => ({
      scanType,
      ruleIds: ["FL-3"],
    })),
    agent: {
      status: added.length ? "ok" : "not_configured",
      provider: added.length ? "ollama" : null,
      model: added.length ? "suite-model" : null,
      additions: added.map((scanType) => ({ scanType, reason: "needed" })),
      summary: null,
      usage: null,
    },
    finalTypes,
    notSelected: enabled
      .filter((t) => !finalTypes.includes(t))
      .map((scanType) => ({ scanType, reason: "no_matching_changes" })),
  };
};

/** A model stub that adds `sbom`; `calls()` is the number of requests it has seen. */
async function modelAdding(w, scanTypes = ["sbom"]) {
  const stub = await startLlm();
  stub.state.respond = (turn) => (turn === 1 ? { calls: scanTypes.map((t) => scan(t)) } : {});
  const runtime = runtimeFor(w, "ollama", stub);
  return { stub, runtime, calls: () => stub.requests.length, close: () => stub.close() };
}

/** Runs one orchestrator to the end for the tree (claim, prepare, pump). */
const runOnce = (w, tree, execution, options = {}) => w.run(tree, execution, options);

const ONE_STATUS_EVENT = (events, from, to) =>
  events.filter((ev) => ev.type === "transition" && ev.fromStatus === from && ev.toStatus === to)
    .length;

export const DECISION_INTEGRATION_CHECKS = [
  {
    id: "DEC-S05a",
    name: "decision reuse on reclaim, persisted record: a preparing execution whose holder died AFTER the decision was recorded is reclaimed; the new holder reuses the record (no diff request to GitHub, ZERO requests to the model provider stub), creates exactly the recorded final set as tasks and never decides again; a control run of the same shape with no record does call the model",
    async run(w) {
      const p = [];
      const model = await modelAdding(w, ["sca"]);
      try {
        // control: a normal run calls the model once and adds its type
        const ctl = await incremental(w, "reuseCtl");
        const ctlOrch = w.orchestrator({}, { decisionRuntime: model.runtime });
        await runOnce(w, ctl.tree, ctl.execution, { orch: ctlOrch });
        ok(p, model.calls() >= 1, "control: the model stub was not called by a normal decision");
        ok(
          p,
          types(await w.taskRows(ctl.execution)) === "sca,secrets",
          `control: tasks ${types(await w.taskRows(ctl.execution))}`,
        );
        // the record exists, the holder dies, a new holder reclaims
        const x = await incremental(w, "reuse");
        await claimAndDie(w, x.tree, x.execution);
        await w.db.$transaction((tx) =>
          dec(w.db).insertDecision(
            {
              tenantId: x.tree.tenant.id,
              executionId: x.execution.id,
              leaseEpoch: 1,
              decision: decisionFor({ floor: ["secrets"], added: ["sbom"] }),
            },
            tx,
          ),
        );
        const requestsBefore = model.calls();
        const diffBefore = await changeCalls(w, x.tree.fullName);
        await sleep(1300);
        const orch = w.orchestrator({}, { decisionRuntime: model.runtime });
        await orch.reclaimOne({
          tenantId: x.tree.tenant.id,
          id: x.execution.id,
          leaseEpoch: 1,
        });
        await w.pump(x.tree, { orch });
        ok(
          p,
          model.calls() === requestsBefore,
          `reclaim called the model ${model.calls() - requestsBefore} time(s)`,
        );
        ok(
          p,
          (await changeCalls(w, x.tree.fullName)) === diffBefore,
          "reclaim with a record asked GitHub for the diff again",
        );
        const tasks = await w.taskRows(x.execution);
        ok(
          p,
          types(tasks) === "sbom,secrets",
          `tasks ${types(tasks)}, expected the recorded sbom,secrets`,
        );
        ok(
          p,
          (await w.db.scanDecision.count({ where: { executionId: x.execution.id } })) === 1,
          "not exactly one record",
        );
        const row = await w.row(x.execution);
        ok(p, row.status === "succeeded", `status ${row.status}`);
      } finally {
        await model.close();
      }
      return p;
    },
  },
  {
    id: "DEC-S05b",
    name: "decision reuse on reclaim, marker only: when the previous holder died after writing decision_started and before committing, the new holder recomputes the floor (one diff request) but does NOT call the model (ZERO requests to the provider stub), records agent status interrupted, creates exactly the floor as tasks, and the task set equals the one a no-provider run decides",
    async run(w) {
      const p = [];
      const model = await modelAdding(w, ["sbom", "sca"]);
      try {
        const reference = await incremental(w, "interruptedRef");
        await runOnce(w, reference.tree, reference.execution);
        const refTasks = types(await w.taskRows(reference.execution));
        const x = await incremental(w, "interrupted");
        await claimAndDie(w, x.tree, x.execution);
        const marked = await dec(w.db).markDecisionStarted({
          tenantId: x.tree.tenant.id,
          executionId: x.execution.id,
          leaseEpoch: 1,
        });
        ok(p, marked === true, "control: the marker was not written");
        const diffBefore = await changeCalls(w, x.tree.fullName);
        await sleep(1300);
        const orch = w.orchestrator({}, { decisionRuntime: model.runtime });
        await orch.reclaimOne({ tenantId: x.tree.tenant.id, id: x.execution.id, leaseEpoch: 1 });
        await w.pump(x.tree, { orch });
        ok(
          p,
          model.calls() === 0,
          `an interrupted decision called the model ${model.calls()} time(s)`,
        );
        ok(
          p,
          (await changeCalls(w, x.tree.fullName)) === diffBefore + 1,
          "the floor was not recomputed with exactly one diff request",
        );
        const record = await decisionOf(w, x.execution);
        ok(p, record?.agentStatus === "interrupted", `agent status ${record?.agentStatus}`);
        ok(
          p,
          record?.agentProvider === null && record?.agentModel === null,
          "an interrupted decision names a provider",
        );
        const tasks = types(await w.taskRows(x.execution));
        ok(p, tasks === "secrets", `tasks ${tasks}, expected the floor secrets`);
        ok(
          p,
          tasks === refTasks,
          `the task set ${tasks} differs from a no-provider run's ${refTasks}`,
        );
        ok(
          p,
          (await eventTypes(w, x.execution, "decision_started")) === 1,
          "more than one decision_started marker",
        );
        ok(
          p,
          (await eventTypes(w, x.execution, "decision_completed")) === 1,
          "not exactly one decision_completed event",
        );
        // control: a fresh run with a provider adds its types, so the stub is wired
        const fresh = await incremental(w, "interruptedCtl");
        await runOnce(w, fresh.tree, fresh.execution, {
          orch: w.orchestrator({}, { decisionRuntime: model.runtime }),
        });
        ok(p, model.calls() >= 1, "control: a normal decision did not reach the model stub");
      } finally {
        await model.close();
      }
      return p;
    },
  },
  {
    id: "DEC-S05c",
    name: "decision marker before the call: a holder that dies WHILE the diff is in flight has already written decision_started, so the holder that reclaims the lease records agent status interrupted and makes ZERO model requests; the dead holder, when it wakes, writes nothing (lost lease)",
    async run(w) {
      const p = [];
      const model = await modelAdding(w, ["sbom"]);
      try {
        const x = await incremental(w, "midcall");
        let release;
        const hang = new Promise((resolve) => (release = resolve));
        const github = {
          openSourceSession: (...args) => w.github.openSourceSession(...args),
          listChangedFiles: async (...args) => {
            await hang;
            return w.github.listChangedFiles(...args);
          },
        };
        const holder = w.orchestrator({}, { github, decisionRuntime: model.runtime });
        const running = holder.claimAndStart({
          tenantId: x.tree.tenant.id,
          executionId: x.execution.id,
        });
        for (
          let i = 0;
          i < 100 && (await eventTypes(w, x.execution, "decision_started")) === 0;
          i += 1
        )
          await sleep(50);
        ok(
          p,
          (await eventTypes(w, x.execution, "decision_started")) === 1,
          "the marker was not written before the diff call",
        );
        ok(p, !(await decisionOf(w, x.execution)), "a record exists before the call returned");
        holder.abandonAll();
        await sleep(4600);
        const next = w.orchestrator({}, { decisionRuntime: model.runtime });
        await next.reclaimOne({
          tenantId: x.tree.tenant.id,
          id: x.execution.id,
          leaseEpoch: 1,
        });
        await w.pump(x.tree, { orch: next });
        release();
        await running.catch(() => {});
        const record = await decisionOf(w, x.execution);
        ok(p, record?.agentStatus === "interrupted", `agent status ${record?.agentStatus}`);
        ok(
          p,
          model.calls() === 0,
          `the reclaiming holder called the model ${model.calls()} time(s)`,
        );
        ok(p, types(await w.taskRows(x.execution)) === "secrets", "tasks are not the floor");
        ok(
          p,
          (await w.db.scanDecision.count({ where: { executionId: x.execution.id } })) === 1,
          "not exactly one record",
        );
        ok(
          p,
          (await eventTypes(w, x.execution, "decision_completed")) === 1,
          "the woken holder wrote a second decision_completed event",
        );
      } finally {
        await model.close();
      }
      return p;
    },
  },
  {
    id: "DEC-S05d",
    name: "decision kept across a transient retry: when the unit fails once with a transient storage error the same holder retries the preparation with the decision it already made (the model is asked once, the added type still gets its task) instead of reading its own marker as a dead holder",
    async run(w) {
      const p = [];
      const model = await modelAdding(w, ["sbom"]);
      try {
        const x = await incremental(w, "retryKeep");
        let failed = false;
        let armed = false;
        const github = {
          openSourceSession: (...args) => w.github.openSourceSession(...args),
          listChangedFiles: async (...args) => {
            const answer = await w.github.listChangedFiles(...args);
            armed = true;
            return answer;
          },
        };
        const wrapTx = (tx) =>
          new Proxy(tx, {
            get(target, prop) {
              const value = target[prop];
              if (prop === "scanDecision")
                return new Proxy(value, {
                  get(model, method) {
                    if (method === "create" && armed && !failed)
                      return () => {
                        failed = true;
                        throw Object.assign(new Error("transient storage failure"), {
                          code: "EAGAIN",
                        });
                      };
                    const fn = model[method];
                    return typeof fn === "function" ? fn.bind(model) : fn;
                  },
                });
              return typeof value === "function" ? value.bind(target) : value;
            },
          });
        const proxied = new Proxy(w.db, {
          get(target, prop) {
            if (prop === "$transaction")
              return (fn, options) => target.$transaction((tx) => fn(wrapTx(tx)), options);
            const value = target[prop];
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
        const orch = w.orchestrator({}, { db: proxied, github, decisionRuntime: model.runtime });
        await runOnce(w, x.tree, x.execution, { orch });
        ok(p, failed, "control: the transient failure never fired");
        // one decision with an accepted addition is two provider requests (the tool-call turn and the tool-result turn, SPEC 17.d item 6)
        ok(
          p,
          model.calls() === 2,
          `the model was called ${model.calls()} time(s), expected the 2 of ONE decision`,
        );
        ok(
          p,
          types(await w.taskRows(x.execution)) === "sbom,secrets",
          `tasks ${types(await w.taskRows(x.execution))}`,
        );
        const record = await decisionOf(w, x.execution);
        ok(p, record?.agentStatus === "ok", `agent status ${record?.agentStatus}`);
      } finally {
        await model.close();
      }
      return p;
    },
  },
  {
    id: "DEC-S08a",
    name: "decision atomicity: the decision row, the decision_completed event, the decided tasks, the preparing -> running transition and their audit entries and messages are ONE unit: a failure injected at each step (record insert, event, task creation, transition, audit entry, outbox message) leaves NONE of them behind and the execution does not run; a cancel recorded while the diff is in flight, or just before the unit opens, ends the execution cancelled with NO record, no task and the quota unit given back once",
    async run(w) {
      const p = [];
      const steps = {
        "decision insert": (name, args, target) => target === "scanDecision" && name === "create",
        "decision event": (name, args, target) =>
          target === "executionEvent" &&
          name === "create" &&
          args[0]?.data?.type === "decision_completed",
        "task creation": (name, args, target) => target === "scanTask" && name === "createMany",
        "transition to running": (name, args, target, strings, values) =>
          target === "$queryRaw" &&
          String(strings?.join?.("?")).includes("UPDATE executions") &&
          values?.includes("running"),
        "audit entry": (name, args, target) =>
          target === "auditLog" &&
          name === "create" &&
          args[0]?.data?.action === "execution.started",
        "outbox message": (name, args, target) => target === "outboxMessage" && name === "upsert",
      };
      for (const [label, fails] of Object.entries(steps)) {
        const x = await incremental(w, `atomic${label.replaceAll(" ", "")}`);
        // armed once the diff is done: the next transaction is the decision unit
        let armed = false;
        let failedHere = false;
        const wrapTx = (tx) =>
          new Proxy(tx, {
            get(target, prop) {
              const value = target[prop];
              if (prop === "$queryRaw")
                return (strings, ...values) => {
                  if (armed && fails("", [], "$queryRaw", strings, values)) {
                    failedHere = true;
                    armed = false;
                    throw new Error(`injected failure at ${label}`);
                  }
                  return value.call(target, strings, ...values);
                };
              if (value && typeof value === "object" && !Array.isArray(value))
                return new Proxy(value, {
                  get(model, method) {
                    const fn = model[method];
                    if (typeof fn !== "function") return fn;
                    return (...args) => {
                      if (armed && fails(method, args, String(prop))) {
                        failedHere = true;
                        armed = false;
                        throw new Error(`injected failure at ${label}`);
                      }
                      return fn.apply(model, args);
                    };
                  },
                });
              return typeof value === "function" ? value.bind(target) : value;
            },
          });
        const proxied = new Proxy(w.db, {
          get(target, prop) {
            if (prop === "$transaction")
              return (fn, options) => target.$transaction((tx) => fn(wrapTx(tx)), options);
            const value = target[prop];
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
        const github = {
          openSourceSession: (...args) => w.github.openSourceSession(...args),
          listChangedFiles: async (...args) => {
            const answer = await w.github.listChangedFiles(...args);
            armed = true;
            return answer;
          },
        };
        const orch = w.orchestrator({}, { db: proxied, github });
        await orch.claimAndStart({ tenantId: x.tree.tenant.id, executionId: x.execution.id });
        const row = await w.row(x.execution);
        const e = x.execution;
        ok(p, !(await decisionOf(w, e)), `${label}: a decision row survived`);
        ok(
          p,
          (await eventTypes(w, e, "decision_completed")) === 0,
          `${label}: a decision_completed event survived`,
        );
        ok(p, (await w.taskRows(e)).length === 0, `${label}: tasks survived`);
        ok(p, row.status !== "running", `${label}: the execution reached running`);
        ok(
          p,
          (await w.audit(x.tree, { targetId: e.id, action: "execution.decision_completed" }))
            .length === 0,
          `${label}: a decision audit entry survived`,
        );
        ok(
          p,
          (await w.outbox(x.tree, { type: "pipeline.execution.decision_completed" })).filter(
            (m) => m.payload.executionId === e.id,
          ).length === 0,
          `${label}: a decision hint survived`,
        );
        ok(
          p,
          (await w.outbox(x.tree, { type: "scan.task.requested" })).filter(
            (m) => m.payload.executionId === e.id,
          ).length === 0,
          `${label}: a task message survived`,
        );
        ok(
          p,
          failedHere,
          `${label}: control: the injected failure never fired (the step did not run)`,
        );
      }
      // control: a healthy run writes all of them
      const good = await incremental(w, "atomicOk");
      await runOnce(w, good.tree, good.execution);
      ok(p, Boolean(await decisionOf(w, good.execution)), "control: no decision row");
      ok(p, (await eventTypes(w, good.execution, "decision_completed")) === 1, "control: no event");
      ok(p, (await w.taskRows(good.execution)).length === 1, "control: no task");
      ok(p, (await hintsOf(w, good.tree, good.execution)).length === 1, "control: no hint");
      // a cancel recorded (1) while the diff is in flight and (2) just before the unit opens: both end `cancelled`, NO record, no task,
      // the quota unit given back once (usage 2 -> 1)
      const cancelAt = async (when) => {
        const c = await incremental(w, `atomicCancel${when}`);
        await w.setQuotaUsage(c.tree, 2);
        const request = () =>
          createExecutionCancellation({ db: w.db }).requestCancel({
            tenantId: c.tree.tenant.id,
            executionId: c.execution.id,
            userId: c.tree.user.id,
            mode: "immediate",
            graceSeconds: 0,
          });
        let armed = false;
        const github = {
          openSourceSession: (...args) => w.github.openSourceSession(...args),
          listChangedFiles: async (...args) => {
            if (when === "diff") await request();
            const answer = await w.github.listChangedFiles(...args);
            armed = true;
            return answer;
          },
        };
        let requested = false;
        const proxied = new Proxy(w.db, {
          get(target, prop) {
            if (prop === "$transaction")
              return async (fn, options) => {
                if (when === "unit" && armed && !requested) {
                  requested = true;
                  await request();
                }
                return target.$transaction(fn, options);
              };
            const value = target[prop];
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
        const orch = w.orchestrator({}, { db: proxied, github });
        await orch.claimAndStart({ tenantId: c.tree.tenant.id, executionId: c.execution.id });
        await w.pump(c.tree, { orch });
        const end = await w.row(c.execution);
        const label = `cancel ${when}`;
        ok(
          p,
          end.status === "cancelled" && end.statusReason === "user_cancelled",
          `${label}: ended ${end.status}/${end.statusReason}`,
        );
        ok(p, !(await decisionOf(w, c.execution)), `${label}: a cancelled execution kept a record`);
        ok(p, (await eventTypes(w, c.execution, "decision_completed")) === 0, `${label}: event`);
        ok(p, (await w.taskRows(c.execution)).length === 0, `${label}: tasks`);
        ok(p, (await usedUnits(w, c.tree)) === 1, `${label}: usage ${await usedUnits(w, c.tree)}`);
        ok(p, end.quotaReleasedAt !== null, `${label}: quota_released_at unset`);
        ok(p, (await w.completed(c.tree, c.execution)).length === 1, `${label}: completed count`);
      };
      await cancelAt("diff");
      await cancelAt("unit");
      return p;
    },
  },
  {
    id: "DEC-S08b",
    name: "decision zombie: a holder whose lease was taken over while it was deciding (during the diff) and a stale-epoch caller of every decision write (marker, record, event, tasks, zero-scan ending) write NOTHING: no record, no event, no task, no audit entry, no message, no transition, and the new holder's writes succeed",
    async run(w) {
      const p = [];
      const x = await incremental(w, "zombie");
      // the thief takes the lease during the diff call of the holder
      let stolen = false;
      const slowGithub = {
        openSourceSession: (...args) => w.github.openSourceSession(...args),
        listChangedFiles: async (...args) => {
          await w.db
            .$executeRaw`UPDATE executions SET lease_epoch = lease_epoch + 1, lease_owner = 'thief', lease_expires_at = now() + interval '1 hour', heartbeat_at = now() WHERE id = ${x.execution.id}::uuid`;
          stolen = true;
          return w.github.listChangedFiles(...args);
        },
      };
      const orch = w.orchestrator({}, { github: slowGithub });
      const outcome = await orch.claimAndStart({
        tenantId: x.tree.tenant.id,
        executionId: x.execution.id,
      });
      ok(p, stolen, "control: the lease was never taken during the decision");
      ok(p, outcome.outcome === "lost", `the zombie's outcome ${outcome.outcome}, expected lost`);
      const e = x.execution;
      ok(p, !(await decisionOf(w, e)), "a zombie wrote a decision record");
      ok(
        p,
        (await eventTypes(w, e, "decision_completed")) === 0,
        "a zombie wrote decision_completed",
      );
      ok(p, (await w.taskRows(e)).length === 0, "a zombie created tasks");
      const row = await w.row(e);
      ok(
        p,
        row.status === "preparing" && row.leaseOwner === "thief",
        `row ${row.status}/${row.leaseOwner}`,
      );
      ok(
        p,
        (await w.audit(x.tree, { targetId: e.id, action: "execution.started" })).length === 0,
        "a zombie audited a start",
      );
      ok(
        p,
        (await w.outbox(x.tree)).filter(
          (m) => m.payload?.executionId === e.id && m.type !== "pipeline.execution.status_changed",
        ).length === 0,
        "a zombie left messages",
      );
      // every decision write refuses the stale epoch (the thief holds epoch 2)
      const repo = dec(w.db);
      const t = x.tree.tenant.id;
      const refused = async (label, fn) => {
        const before = json(await w.db.executionEvent.count({ where: { executionId: e.id } }));
        const result = await w.db.$transaction(fn).then(
          () => "accepted",
          (error) => error.name,
        );
        ok(p, result === "LeaseLostError", `${label}: ${result}, expected LeaseLostError`);
        ok(
          p,
          json(await w.db.executionEvent.count({ where: { executionId: e.id } })) === before,
          `${label}: wrote an event`,
        );
      };
      await refused("marker", (tx) =>
        repo.markDecisionStarted({ tenantId: t, executionId: e.id, leaseEpoch: 1 }, tx),
      );
      await refused("record", (tx) =>
        repo.insertDecision(
          {
            tenantId: t,
            executionId: e.id,
            leaseEpoch: 1,
            decision: decisionFor({ floor: ["secrets"] }),
          },
          tx,
        ),
      );
      await refused("event", (tx) =>
        repo.recordDecisionCompleted(
          { tenantId: t, executionId: e.id, leaseEpoch: 1, details: {} },
          tx,
        ),
      );
      await refused("zero-scan ending", (tx) =>
        repo.finishZeroScan({ tenantId: t, executionId: e.id, leaseEpoch: 1 }, tx),
      );
      await refused("tasks", (tx) =>
        w.tasks.createDecidedTasks(
          { tenantId: t, executionId: e.id, leaseEpoch: 1, tasks: [] },
          tx,
        ),
      );
      ok(
        p,
        !(await decisionOf(w, e)) && (await w.taskRows(e)).length === 0,
        "a stale-epoch call wrote rows",
      );
      // control: the current holder (epoch 2) writes
      await w.db.$transaction((tx) =>
        repo.insertDecision(
          {
            tenantId: t,
            executionId: e.id,
            leaseEpoch: 2,
            decision: decisionFor({ floor: ["secrets"] }),
          },
          tx,
        ),
      );
      ok(
        p,
        Boolean(await decisionOf(w, e)),
        "control: the holder with the current epoch could not write",
      );
      return p;
    },
  },
  {
    id: "DEC-S08c",
    name: "deadline during the decision: an execution whose deadline passes while the diff is in flight ends timed_out with NO decision record, no task, no scan message and no start (the unit is not committed after the deadline)",
    async run(w) {
      const p = [];
      const x = await incremental(w, "deadline");
      await w.repo.claimQueued({
        tenantId: x.tree.tenant.id,
        executionId: x.execution.id,
        workerId: "dead-claimer",
        leaseTtlSeconds: 1,
        deadlineSeconds: 3,
        staleThresholdSeconds: 36 * 3600,
      });
      await sleep(1300);
      const github = {
        openSourceSession: (...args) => w.github.openSourceSession(...args),
        listChangedFiles: async (...args) => {
          // ignores the abort signal and answers after the deadline
          await sleep(2600);
          return w.github.listChangedFiles(...args);
        },
      };
      const orch = w.orchestrator({}, { github });
      await orch.reclaimOne({ tenantId: x.tree.tenant.id, id: x.execution.id, leaseEpoch: 1 });
      await w.pump(x.tree, { orch });
      const row = await w.row(x.execution);
      ok(
        p,
        row.status === "timed_out" && row.statusReason === "execution_deadline",
        `ended ${row.status}/${row.statusReason}`,
      );
      ok(p, !(await decisionOf(w, x.execution)), "a record was written after the deadline");
      ok(p, (await w.taskRows(x.execution)).length === 0, "tasks were created after the deadline");
      ok(
        p,
        (await eventTypes(w, x.execution, "decision_completed")) === 0,
        "decision_completed was written after the deadline",
      );
      ok(
        p,
        (await w.audit(x.tree, { targetId: x.execution.id, action: "execution.started" }))
          .length === 0,
        "a start was audited after the deadline",
      );
      return p;
    },
  },
  {
    id: "DEC-S09a",
    name: "zero-scan outcome: a change that selects no scan (a removed source file, no provider) ends the execution succeeded with the reason no_applicable_scans in one transaction preparing -> running -> succeeded with the same lease epoch (two transition events), no task and no scan message, task counts all zero, the quota unit given back exactly once, resolutionEligible false in the single completed message, one decision_completed event and one hint; the execution detail names no task",
    async run(w) {
      const p = [];
      const x = await incremental(w, "zero", { files: removedCode });
      await w.setQuotaUsage(x.tree, 2);
      const { row } = await runOnce(w, x.tree, x.execution);
      ok(
        p,
        row.status === "succeeded" && row.statusReason === "no_applicable_scans",
        `status ${row.status}/${row.statusReason}`,
      );
      ok(p, (await w.taskRows(x.execution)).length === 0, "a zero-scan execution has tasks");
      ok(
        p,
        (await w.outbox(x.tree, { type: "scan.task.requested" })).filter(
          (m) => m.payload.executionId === x.execution.id,
        ).length === 0,
        "a zero-scan execution queued a scan",
      );
      ok(
        p,
        row.taskCounts?.total === 0 && Object.values(row.taskCounts).every((n) => n === 0),
        `task counts ${json(row.taskCounts)}`,
      );
      ok(p, row.quotaReleasedAt !== null, "quota_released_at is not set");
      ok(
        p,
        (await usedUnits(w, x.tree)) === 1,
        `usage ${await usedUnits(w, x.tree)}, expected the unit given back`,
      );
      const events = await w.events(x.execution);
      ok(
        p,
        ONE_STATUS_EVENT(events, "preparing", "running") === 1,
        "not exactly one preparing -> running event",
      );
      ok(
        p,
        ONE_STATUS_EVENT(events, "running", "succeeded") === 1,
        "not exactly one running -> succeeded event",
      );
      const epochs = events
        .filter((ev) => ev.type === "transition" && ["running", "succeeded"].includes(ev.toStatus))
        .map((ev) => ev.details.epoch);
      ok(p, epochs.length === 2 && epochs.every((n) => n === row.leaseEpoch), `epochs ${epochs}`);
      ok(
        p,
        (await eventTypes(w, x.execution, "decision_completed")) === 1,
        "not exactly one decision_completed event",
      );
      const started = events.filter((ev) => ev.type === "decision_started");
      const finished = events.filter((ev) => ev.type === "decision_completed");
      ok(p, started.length === 1, `${started.length} decision_started markers, expected 1`);
      ok(
        p,
        started[0] && finished[0] && started[0].seq < finished[0].seq,
        "the decision_started marker was not written before decision_completed",
      );
      const completed = await w.completed(x.tree, x.execution);
      ok(p, completed.length === 1, `${completed.length} completed messages`);
      const payload = completed[0]?.payload?.payload ?? {};
      ok(
        p,
        payload.status === "succeeded" && payload.statusReason === "no_applicable_scans",
        `completed ${payload.status}/${payload.statusReason}`,
      );
      ok(
        p,
        payload.resolutionEligible === false && payload.tasks?.length === 0,
        "the completed event is eligible or lists tasks",
      );
      ok(
        p,
        (await w.db.executionLog.findMany({ where: { executionId: x.execution.id } })).every(
          (l) => !/registered engine/.test(l.message),
        ),
        "a zero-scan execution logged the unsupported-engine ending",
      );
      ok(p, (await hintsOf(w, x.tree, x.execution)).length === 1, "not exactly one decision hint");
      const record = await decisionOf(w, x.execution);
      ok(
        p,
        record && record.finalTypes.length === 0 && record.floor.length === 0,
        "the record is not an empty decision",
      );
      ok(
        p,
        record?.notSelected.map((n) => n.scanType).join() === "sbom,sca,sast,secrets",
        `not selected ${json(record?.notSelected)}`,
      );
      // the repository refuses the ending itself when a task exists (before the database trigger would), and writes nothing
      const t = await incremental(w, "zeroTask", { files: removedCode });
      await claimAndDie(w, t.tree, t.execution, 600);
      await w.db.$transaction((tx) =>
        dec(w.db).insertDecision(
          {
            tenantId: t.tree.tenant.id,
            executionId: t.execution.id,
            leaseEpoch: 1,
            decision: decisionFor({ floor: [] }),
          },
          tx,
        ),
      );
      await w.db.scanTask.create({
        data: {
          tenantId: t.tree.tenant.id,
          workspaceId: t.tree.ws.id,
          repositoryId: t.tree.repo.id,
          pipelineId: t.execution.pipelineId,
          executionId: t.execution.id,
          scanType: "sca",
          ordinal: 1,
          status: "pending",
          engineId: "e",
          engineProfile: "default",
          severityThreshold: "low",
          timeoutSeconds: 60,
        },
      });
      const refused = await w.db
        .$transaction((tx) =>
          dec(w.db).finishZeroScan(
            { tenantId: t.tree.tenant.id, executionId: t.execution.id, leaseEpoch: 1 },
            tx,
          ),
        )
        .then(
          () => "accepted",
          (error) => String(error.message),
        );
      ok(
        p,
        /cannot have scan tasks/.test(refused),
        `a zero-scan ending with a task: ${refused.slice(0, 120)}`,
      );
      ok(
        p,
        (await w.row(t.execution)).status === "preparing",
        "the refused ending moved the execution",
      );
      return p;
    },
  },
  {
    id: "DEC-S09b",
    name: "zero-scan quota, exactly once under races: eight parallel reclaimers of a zero-scan execution whose holder died, and a cancel request racing the zero-scan run at several moments, each end with the unit given back EXACTLY once (usage down by one, quota_released_at set, one terminal transition, one completed message) whichever side wins; a cancelled one has no decision record",
    async run(w) {
      const p = [];
      // reclaimers
      const r = await incremental(w, "zeroRace", { files: removedCode });
      await w.setQuotaUsage(r.tree, 2);
      await claimAndDie(w, r.tree, r.execution);
      await sleep(1300);
      const orchs = Array.from({ length: 8 }, () => w.orchestrator({}));
      await Promise.all(
        orchs.map((o) =>
          o.reclaimOne({ tenantId: r.tree.tenant.id, id: r.execution.id, leaseEpoch: 1 }),
        ),
      );
      const row = await w.row(r.execution);
      ok(
        p,
        row.status === "succeeded" && row.statusReason === "no_applicable_scans",
        `reclaim race ended ${row.status}/${row.statusReason}`,
      );
      ok(
        p,
        (await usedUnits(w, r.tree)) === 1,
        `reclaim race: usage ${await usedUnits(w, r.tree)}`,
      );
      ok(
        p,
        (await w.completed(r.tree, r.execution)).length === 1,
        "reclaim race: not one completed message",
      );
      ok(
        p,
        (await eventTypes(w, r.execution, "decision_completed")) === 1,
        "reclaim race: not one decision_completed event",
      );
      ok(
        p,
        (await w.db.scanDecision.count({ where: { executionId: r.execution.id } })) === 1,
        "reclaim race: not one record",
      );
      // a cancel racing the run, at several moments
      let cancelled = 0;
      let succeeded = 0;
      for (const delay of [0, 15, 40, 90, 200, 400]) {
        const c = await incremental(w, `zeroCancel${delay}`, { files: removedCode });
        await w.setQuotaUsage(c.tree, 2);
        const orch = w.orchestrator({});
        const run = orch.claimAndStart({ tenantId: c.tree.tenant.id, executionId: c.execution.id });
        await sleep(delay);
        await createExecutionCancellation({ db: w.db }).requestCancel({
          tenantId: c.tree.tenant.id,
          executionId: c.execution.id,
          userId: c.tree.user.id,
          mode: "immediate",
          graceSeconds: 0,
        });
        await run;
        await w.pump(c.tree, { orch });
        const end = await w.row(c.execution);
        const label = `cancel after ${delay} ms ended ${end.status}/${end.statusReason}`;
        ok(p, (await usedUnits(w, c.tree)) === 1, `${label}: usage ${await usedUnits(w, c.tree)}`);
        ok(p, end.quotaReleasedAt !== null, `${label}: quota_released_at unset`);
        ok(
          p,
          (await w.completed(c.tree, c.execution)).length === 1,
          `${label}: not one completed message`,
        );
        if (end.status === "cancelled") {
          cancelled += 1;
          ok(
            p,
            !(await decisionOf(w, c.execution)),
            `${label}: a cancelled execution kept a record`,
          );
        } else if (end.status === "succeeded" && end.statusReason === "no_applicable_scans")
          succeeded += 1;
        else p.push(`${label}: unexpected outcome`);
      }
      ok(p, cancelled + succeeded === 6, "control: every race ended in one of the two outcomes");
      return p;
    },
  },
  {
    id: "DEC-S09c",
    name: "all decided tasks unsupported (owner decision 2026-11-18): when the DECIDED set is not empty and no decided type has a registered engine (an incremental source change, the registry holds only the SBOM engine, the model adds sca) the execution ends failed with the reason tasks_unsupported in ONE transaction preparing -> failed, with the decision row, the decision_completed event, every decided task recorded unsupported (engine_not_registered) and visible in the history, task counts all unsupported, no scan message, no running transition, the quota unit given back exactly once, resolutionEligible false in the single completed message, one decision hint, and exactly one decision's model requests; a MIXED decided set (one registered engine among them) is the normal flow: it starts, its unsupported tasks are recorded and the quota unit is NOT given back",
    async run(w) {
      const p = [];
      const model = await modelAdding(w, ["sca"]);
      try {
        const x = await incremental(w, "allUnsupported", { files: modifiedCode });
        await w.setQuotaUsage(x.tree, 2);
        const orch = w.orchestrator(
          {},
          { decisionRuntime: model.runtime, engines: w.sbomRegistry() },
        );
        const { row } = await runOnce(w, x.tree, x.execution, { orch });
        ok(
          p,
          row.status === "failed" && row.statusReason === "tasks_unsupported",
          `status ${row.status}/${row.statusReason}`,
        );
        const tasks = await w.taskRows(x.execution);
        ok(p, types(tasks) === "sca,sast,secrets", `tasks ${types(tasks)}`);
        ok(
          p,
          tasks.every(
            (t) => t.status === "unsupported" && t.statusReason === "engine_not_registered",
          ),
          `task states ${tasks.map((t) => `${t.status}/${t.statusReason}`)}`,
        );
        ok(
          p,
          row.taskCounts?.total === 3 && row.taskCounts?.unsupported === 3,
          `task counts ${json(row.taskCounts)}`,
        );
        ok(p, row.quotaReleasedAt !== null, "quota_released_at is not set");
        ok(
          p,
          (await usedUnits(w, x.tree)) === 1,
          `usage ${await usedUnits(w, x.tree)}, expected the unit given back once`,
        );
        ok(p, row.startedAt === null, "the execution entered running (started_at is set)");
        const events = await w.events(x.execution);
        ok(
          p,
          ONE_STATUS_EVENT(events, "preparing", "failed") === 1,
          "not exactly one preparing -> failed event",
        );
        ok(
          p,
          ONE_STATUS_EVENT(events, "preparing", "running") === 0 &&
            ONE_STATUS_EVENT(events, "running", "failed") === 0,
          "the execution went through running",
        );
        ok(
          p,
          events.filter((ev) => ev.type === "task_unsupported").length === 3,
          "the history does not show the three unsupported tasks",
        );
        ok(
          p,
          (await eventTypes(w, x.execution, "decision_completed")) === 1,
          "not exactly one decision_completed event",
        );
        const record = await decisionOf(w, x.execution);
        ok(
          p,
          record?.finalTypes.join() === "sca,sast,secrets",
          `record ${json(record?.finalTypes)}`,
        );
        ok(
          p,
          (await w.outbox(x.tree, { type: "scan.task.requested" })).filter(
            (m) => m.payload.executionId === x.execution.id,
          ).length === 0,
          "a scan message was queued",
        );
        const completed = await w.completed(x.tree, x.execution);
        ok(p, completed.length === 1, `${completed.length} completed messages`);
        const payload = completed[0]?.payload?.payload ?? {};
        ok(
          p,
          payload.status === "failed" && payload.statusReason === "tasks_unsupported",
          `completed ${payload.status}/${payload.statusReason}`,
        );
        ok(p, payload.resolutionEligible === false, "the completed event is resolution-eligible");
        ok(
          p,
          payload.tasks?.length === 3 && payload.tasks.every((t) => t.status === "unsupported"),
          "the completed event does not list the three unsupported tasks",
        );
        ok(
          p,
          (await hintsOf(w, x.tree, x.execution)).length === 1,
          "not exactly one decision hint",
        );
        const audits = await w.audit(x.tree, {
          targetId: x.execution.id,
          action: "execution.failed",
        });
        ok(
          p,
          audits.length === 1 && audits[0].metadata?.quotaReleased === true,
          `${audits.length} failed audit entries`,
        );
        ok(
          p,
          model.calls() === 2,
          `the model saw ${model.calls()} requests, expected one decision (2)`,
        );
        const statusHints = (
          await w.outbox(x.tree, { type: "pipeline.execution.status_changed" })
        ).filter((m) => m.payload.executionId === x.execution.id);
        ok(
          p,
          statusHints.map((m) => m.payload.payload.status).join() === "preparing,failed" ||
            statusHints.map((m) => m.payload.payload.status).join() === "failed",
          `status hints ${statusHints.map((m) => m.payload.payload.status)}`,
        );
        ok(
          p,
          !(await w.store.size({
            tenantId: x.tree.tenant.id,
            executionId: x.execution.id,
            name: "source.tar.gz",
          })),
          "the source archive was kept after the execution ended",
        );
        const lines = (
          await w.db.executionLog.findMany({ where: { executionId: x.execution.id } })
        ).map((l) => l.message);
        ok(
          p,
          lines.some((l) => /no decided scan type has a registered engine/.test(l)) &&
            lines.filter((l) => /no engine is registered, the task is recorded unsupported/.test(l))
              .length === 3,
          `execution log ${json(lines)}`,
        );
        // control: the full run of the same pipeline (every type enabled and decided, registry of SBOM only) is NOT the new case
        // when a decided type has an engine: sbom decided -> normal flow (mixed)
        const m = await incremental(w, "mixedDecided", { files: manifestAndCode });
        await w.setQuotaUsage(m.tree, 2);
        const mixedOrch = w.orchestrator({}, { engines: w.sbomRegistry() });
        await mixedOrch.claimAndStart({ tenantId: m.tree.tenant.id, executionId: m.execution.id });
        const mixed = await w.row(m.execution);
        ok(p, mixed.status === "running", `mixed status ${mixed.status}`);
        ok(p, mixed.quotaReleasedAt === null, "mixed: the quota unit was given back");
        ok(p, (await usedUnits(w, m.tree)) === 2, `mixed: usage ${await usedUnits(w, m.tree)}`);
        const mixedTasks = await w.taskRows(m.execution);
        ok(
          p,
          mixedTasks.filter((t) => t.status === "unsupported").length === 3 &&
            mixedTasks.filter((t) => t.scanType === "sbom" && t.status !== "unsupported").length ===
              1,
          `mixed tasks ${mixedTasks.map((t) => `${t.scanType}/${t.status}`)}`,
        );
      } finally {
        await model.close();
      }
      return p;
    },
  },
  {
    id: "DEC-S09d",
    name: "all decided tasks unsupported, exactly once under races and no second decision: eight parallel reclaimers of an execution whose holder died AFTER the decision was recorded (the record names only unsupported types) reuse the record (ZERO model requests, no diff request) and end failed / tasks_unsupported with the unit given back EXACTLY once (one completed message, one record, three unsupported tasks, one terminal transition); a cancel request racing the same run at several moments ends cancelled or failed with the unit given back exactly once either way",
    async run(w) {
      const p = [];
      const model = await modelAdding(w, ["sca"]);
      try {
        const r = await incremental(w, "unsupRace", { files: modifiedCode });
        await w.setQuotaUsage(r.tree, 2);
        await claimAndDie(w, r.tree, r.execution);
        await w.db.$transaction((tx) =>
          dec(w.db).insertDecision(
            {
              tenantId: r.tree.tenant.id,
              executionId: r.execution.id,
              leaseEpoch: 1,
              decision: decisionFor({ floor: ["sast", "secrets"] }),
            },
            tx,
          ),
        );
        const diffBefore = await changeCalls(w, r.tree.fullName);
        const before = model.calls();
        await sleep(1300);
        const orchs = Array.from({ length: 8 }, () =>
          w.orchestrator({}, { decisionRuntime: model.runtime, engines: w.sbomRegistry() }),
        );
        await Promise.all(
          orchs.map((o) =>
            o.reclaimOne({ tenantId: r.tree.tenant.id, id: r.execution.id, leaseEpoch: 1 }),
          ),
        );
        const row = await w.row(r.execution);
        ok(
          p,
          row.status === "failed" && row.statusReason === "tasks_unsupported",
          `reclaim race ended ${row.status}/${row.statusReason}`,
        );
        ok(
          p,
          (await usedUnits(w, r.tree)) === 1,
          `reclaim race: usage ${await usedUnits(w, r.tree)}`,
        );
        ok(
          p,
          (await w.completed(r.tree, r.execution)).length === 1,
          "reclaim race: not one completed message",
        );
        ok(
          p,
          (await w.db.scanDecision.count({ where: { executionId: r.execution.id } })) === 1,
          "reclaim race: not one record",
        );
        const tasks = await w.taskRows(r.execution);
        ok(
          p,
          types(tasks) === "sast,secrets" && tasks.every((t) => t.status === "unsupported"),
          `reclaim race: tasks ${tasks.map((t) => `${t.scanType}/${t.status}`)}`,
        );
        ok(
          p,
          model.calls() === before,
          `reclaim called the model ${model.calls() - before} time(s)`,
        );
        ok(
          p,
          (await changeCalls(w, r.tree.fullName)) === diffBefore,
          "reclaim with a record asked GitHub for the diff again",
        );
        ok(
          p,
          ONE_STATUS_EVENT(await w.events(r.execution), "preparing", "failed") === 1,
          "reclaim race: not one preparing -> failed transition",
        );
        // a cancel racing the run
        let cancelled = 0;
        let failed = 0;
        for (const delay of [0, 15, 40, 90, 200, 400]) {
          const c = await incremental(w, `unsupCancel${delay}`, { files: modifiedCode });
          await w.setQuotaUsage(c.tree, 2);
          const orch = w.orchestrator({}, { engines: w.sbomRegistry() });
          const run = orch.claimAndStart({
            tenantId: c.tree.tenant.id,
            executionId: c.execution.id,
          });
          await sleep(delay);
          await createExecutionCancellation({ db: w.db }).requestCancel({
            tenantId: c.tree.tenant.id,
            executionId: c.execution.id,
            userId: c.tree.user.id,
            mode: "immediate",
            graceSeconds: 0,
          });
          await run;
          await w.pump(c.tree, { orch });
          const end = await w.row(c.execution);
          const label = `cancel after ${delay} ms ended ${end.status}/${end.statusReason}`;
          ok(
            p,
            (await usedUnits(w, c.tree)) === 1,
            `${label}: usage ${await usedUnits(w, c.tree)}`,
          );
          ok(p, end.quotaReleasedAt !== null, `${label}: quota_released_at unset`);
          ok(
            p,
            (await w.completed(c.tree, c.execution)).length === 1,
            `${label}: not one completed message`,
          );
          if (end.status === "cancelled") {
            cancelled += 1;
            ok(
              p,
              !(await decisionOf(w, c.execution)),
              `${label}: a cancelled execution kept a record`,
            );
          } else if (end.status === "failed" && end.statusReason === "tasks_unsupported")
            failed += 1;
          else p.push(`${label}: unexpected outcome`);
        }
        ok(p, cancelled + failed === 6, "control: every race ended in one of the two outcomes");
      } finally {
        await model.close();
      }
      return p;
    },
  },
  {
    id: "DEC-S09e",
    name: "all decided tasks unsupported, atomicity: the decision row, the decision_completed event, the unsupported tasks, the preparing -> failed transition, the quota release and their audit entry and outbox messages are ONE unit: a failure injected at each step leaves NONE of them behind (no record, no event, no task, no completed or hint message, no tasks_unsupported ending, no quota release)",
    async run(w) {
      const p = [];
      const sqlOf = (strings) => String(strings?.join?.("?"));
      const steps = {
        "decision insert": (m, a, t) => t === "scanDecision" && m === "create",
        "decision event": (m, a, t) =>
          t === "executionEvent" && m === "create" && a[0]?.data?.type === "decision_completed",
        "task creation": (m, a, t) => t === "scanTask" && m === "createMany",
        "unsupported marking": (m, a, t, s) =>
          t === "$queryRaw" && sqlOf(s).includes("SET status = 'unsupported'"),
        "transition to failed": (m, a, t, s, v) =>
          t === "$queryRaw" && sqlOf(s).includes("UPDATE executions") && v?.includes("failed"),
        "quota release": (m, a, t, s) =>
          t === "$executeRaw" && sqlOf(s).includes("UPDATE tenant_quota_usage"),
        "audit entry": (m, a, t) =>
          t === "auditLog" && m === "create" && a[0]?.data?.action === "execution.failed",
        "completed message": (m, a, t) =>
          t === "outboxMessage" &&
          m === "upsert" &&
          a[0]?.create?.type === "pipeline.execution.completed",
      };
      for (const [label, fails] of Object.entries(steps)) {
        const x = await incremental(w, `unsupAtomic${label.replaceAll(" ", "")}`, {
          files: modifiedCode,
        });
        await w.setQuotaUsage(x.tree, 2);
        let armed = false;
        let firedHere = false;
        const fire = () => {
          firedHere = true;
          armed = false;
          throw new Error(`injected failure at ${label}`);
        };
        const wrapTx = (tx) =>
          new Proxy(tx, {
            get(target, prop) {
              const value = target[prop];
              if (prop === "$queryRaw" || prop === "$executeRaw")
                return (strings, ...values) => {
                  if (armed && fails("", [], prop, strings, values)) fire();
                  return value.call(target, strings, ...values);
                };
              if (value && typeof value === "object" && !Array.isArray(value))
                return new Proxy(value, {
                  get(model, method) {
                    const fn = model[method];
                    if (typeof fn !== "function") return fn;
                    return (...args) => {
                      if (armed && fails(method, args, String(prop))) fire();
                      return fn.apply(model, args);
                    };
                  },
                });
              return typeof value === "function" ? value.bind(target) : value;
            },
          });
        const proxied = new Proxy(w.db, {
          get(target, prop) {
            if (prop === "$transaction")
              return (fn, options) => target.$transaction((tx) => fn(wrapTx(tx)), options);
            const value = target[prop];
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
        const github = {
          openSourceSession: (...args) => w.github.openSourceSession(...args),
          listChangedFiles: async (...args) => {
            const answer = await w.github.listChangedFiles(...args);
            armed = true;
            return answer;
          },
        };
        const orch = w.orchestrator({}, { db: proxied, github, engines: w.sbomRegistry() });
        await orch.claimAndStart({ tenantId: x.tree.tenant.id, executionId: x.execution.id });
        const e = x.execution;
        const row = await w.row(e);
        ok(p, firedHere, `${label}: control: the injected failure never fired`);
        ok(p, !(await decisionOf(w, e)), `${label}: a decision row survived`);
        ok(
          p,
          (await eventTypes(w, e, "decision_completed")) === 0,
          `${label}: a decision_completed event survived`,
        );
        ok(p, (await w.taskRows(e)).length === 0, `${label}: tasks survived`);
        // the unit was consumed and the failed unit rolled back its own release: nothing was given back (internal errors keep it)
        ok(
          p,
          (await usedUnits(w, x.tree)) === 2 && row.quotaReleasedAt === null,
          `${label}: a quota release survived (usage ${await usedUnits(w, x.tree)})`,
        );
        ok(
          p,
          (await eventTypes(w, e, "task_unsupported")) === 0,
          `${label}: task_unsupported events survived`,
        );
        ok(
          p,
          row.statusReason !== "tasks_unsupported",
          `${label}: the tasks_unsupported ending survived`,
        );
        ok(p, (await hintsOf(w, x.tree, e)).length === 0, `${label}: a decision hint survived`);
        ok(
          p,
          (await w.completed(x.tree, e)).every(
            (m) => m.payload.payload?.statusReason !== "tasks_unsupported",
          ),
          `${label}: a tasks_unsupported completed message survived`,
        );
        ok(
          p,
          (await w.audit(x.tree, { targetId: e.id, action: "execution.decision_completed" }))
            .length === 0,
          `${label}: a decision audit entry survived`,
        );
      }
      // control: a healthy run writes all of them
      const good = await incremental(w, "unsupAtomicOk", { files: modifiedCode });
      await w.setQuotaUsage(good.tree, 2);
      await runOnce(w, good.tree, good.execution, {
        orch: w.orchestrator({}, { engines: w.sbomRegistry() }),
      });
      const gr = await w.row(good.execution);
      ok(
        p,
        gr.status === "failed" &&
          gr.statusReason === "tasks_unsupported" &&
          (await decisionOf(w, good.execution)) &&
          (await usedUnits(w, good.tree)) === 1,
        "control: a healthy run did not write the whole unit",
      );
      return p;
    },
  },
  {
    id: "DEC-S12",
    name: "tasks only for the decided types: a floor type always has a task and a type outside the final set has none (no row, no scan message, no attempt); the ordinal is the catalog position (gaps expected); an addition by the model adds exactly its task; not selected is not partial (a docs-only incremental run succeeds, is never resolution-eligible); a full run decides every enabled type and stays eligible; the database refuses a task for an undecided type and a decided type without a task; a fork pull request decision never calls the model and goes to the untrusted queue with no credential in any decision surface",
    async run(w) {
      const p = [];
      const model = await modelAdding(w, ["sbom"]);
      try {
        // (a) floor only
        const a = await incremental(w, "decidedA");
        await runOnce(w, a.tree, a.execution);
        const aTasks = await w.taskRows(a.execution);
        ok(p, types(aTasks) === "secrets", `floor-only tasks ${types(aTasks)}`);
        ok(
          p,
          aTasks.map((t) => t.ordinal).join() === "3",
          `ordinals ${aTasks.map((t) => t.ordinal)}`,
        );
        const aRow = await w.row(a.execution);
        ok(
          p,
          aRow.status === "succeeded" && aRow.statusReason === null,
          `not selected made the run ${aRow.status}/${aRow.statusReason}`,
        );
        ok(
          p,
          (await w.outbox(a.tree, { type: "scan.task.requested" }))
            .filter((m) => m.payload.executionId === a.execution.id)
            .map((m) => m.payload.payload.scanType)
            .join() === "secrets",
          "a scan message exists for a type outside the final set",
        );
        ok(
          p,
          (await w.completed(a.tree, a.execution))[0]?.payload?.payload?.resolutionEligible ===
            false,
          "an incremental run was resolution-eligible",
        );
        // (b) an addition adds exactly its task, with a gap in the ordinals
        const b = await incremental(w, "decidedB");
        await runOnce(w, b.tree, b.execution, {
          orch: w.orchestrator({}, { decisionRuntime: model.runtime }),
        });
        const bTasks = await w.taskRows(b.execution);
        ok(p, types(bTasks) === "sbom,secrets", `added tasks ${types(bTasks)}`);
        ok(
          p,
          bTasks.map((t) => t.ordinal).join() === "0,3",
          `ordinals ${bTasks.map((t) => t.ordinal)}`,
        );
        const bRecord = await decisionOf(w, b.execution);
        ok(
          p,
          bRecord?.agentStatus === "ok" && bRecord.agentProvider === "ollama",
          `agent ${bRecord?.agentStatus}`,
        );
        // (c) a full run: every enabled type, eligible
        const full = await w.tree("decidedFull");
        const fe = await w.execution(full);
        await runOnce(w, full, fe, {
          orch: w.orchestrator({}, { decisionRuntime: model.runtime }),
        });
        ok(
          p,
          types(await w.taskRows(fe)) === "sbom,sca,sast,secrets",
          `full tasks ${types(await w.taskRows(fe))}`,
        );
        ok(
          p,
          (await w.completed(full, fe))[0]?.payload?.payload?.resolutionEligible === true,
          "control: a full run is not resolution-eligible",
        );
        const fr = await decisionOf(w, fe);
        ok(
          p,
          fr?.agentStatus === "nothing_to_add" && fr.diffStatus === "not_needed",
          `full decision ${fr?.agentStatus}/${fr?.diffStatus}`,
        );
        // (d) the database refuses an undecided or missing task
        const raw = await incremental(w, "decidedRaw");
        await claimAndDie(w, raw.tree, raw.execution, 60);
        const repo = dec(w.db);
        const t = raw.tree.tenant.id;
        const spec = (scanType) => ({
          scanType,
          ordinal: ALL.indexOf(scanType),
          engineId: "default",
          engineProfile: "default",
          severityThreshold: "low",
          timeoutSeconds: 60,
          maxAttempts: 1,
        });
        const create = (specs) =>
          w.db
            .$transaction((tx) =>
              w.tasks.createDecidedTasks(
                { tenantId: t, executionId: raw.execution.id, leaseEpoch: 1, tasks: specs },
                tx,
              ),
            )
            .then(
              () => "accepted",
              (e) => e.message,
            );
        ok(
          p,
          (await create([spec("secrets")])).includes("decision is recorded"),
          "tasks were accepted before a decision exists",
        );
        await w.db.$transaction((tx) =>
          repo.insertDecision(
            {
              tenantId: t,
              executionId: raw.execution.id,
              leaseEpoch: 1,
              decision: decisionFor({ floor: ["secrets"] }),
            },
            tx,
          ),
        );
        ok(
          p,
          (await create([spec("secrets"), spec("sast")])) !== "accepted",
          "a task for an undecided type was accepted",
        );
        ok(p, (await create([])) !== "accepted", "a decided type without a task was accepted");
        ok(p, (await create([spec("sca")])) !== "accepted", "a task for another type was accepted");
        ok(
          p,
          (await create([spec("secrets"), spec("secrets")])) !== "accepted",
          "a duplicate task for the decided type was accepted",
        );
        ok(p, (await w.taskRows(raw.execution)).length === 0, "a refused call created rows");
        ok(
          p,
          (await create([spec("secrets")])) === "accepted",
          "control: the decided task was refused",
        );
        // (e) a fork: floor only, the model is not called, untrusted queue, no credential in any decision surface
        const callsBefore = model.calls();
        const f = await incremental(w, "decidedFork", {
          exec: {
            trust: "untrusted_fork",
            triggerType: "pull_request",
            triggerKey: "pr",
            scmEventKind: "pull_request",
            refType: "pull_request",
            refName: "feature",
            pullRequestNumber: 7,
            baseRef: "main",
            scanKindReason: "pull_request",
          },
        });
        await w.stub("/__control/pull-files", {
          fullName: f.tree.fullName,
          number: 7,
          files: docsOnly,
        });
        await runOnce(w, f.tree, f.execution, {
          orch: w.orchestrator({}, { decisionRuntime: model.runtime }),
        });
        ok(p, model.calls() === callsBefore, "a fork pull request called the model");
        const fr2 = await decisionOf(w, f.execution);
        ok(p, fr2?.agentStatus === "skipped_fork", `fork agent status ${fr2?.agentStatus}`);
        ok(
          p,
          types(await w.taskRows(f.execution)) === "secrets",
          `fork tasks ${types(await w.taskRows(f.execution))}`,
        );
        const queues = (await w.outbox(f.tree, { type: "scan.task.requested" })).map(
          (m) => m.queue,
        );
        ok(
          p,
          queues.length > 0 && queues.every((q) => q === "scan-untrusted"),
          `fork queues ${queues}`,
        );
        const dump = await w.dump(f.tree);
        ok(
          p,
          findCredentials(dump).length === 0 && !/ghs_stub_|Authorization/i.test(dump),
          "a credential reached the fork execution's rows",
        );
      } finally {
        await model.close();
      }
      return p;
    },
  },
  {
    id: "DEC-S06a",
    name: "decision tenant scope in the data layer: another tenant's id (or the right tenant with a wrong workspace, repository or pipeline of the chain) finds no decision and no marker; a decision cannot be inserted for an execution of another tenant; the realtime hint and its ownership check follow the same chain (another tenant's envelope is refused, the hint carries ids and the revision only and goes to the workspace and execution rooms)",
    async run(w) {
      const p = [];
      const x = await incremental(w, "scopeA");
      const y = await incremental(w, "scopeB");
      await claimAndDie(w, x.tree, x.execution, 60);
      const repo = dec(w.db);
      const tA = x.tree.tenant.id;
      const tB = y.tree.tenant.id;
      await repo.markDecisionStarted({ tenantId: tA, executionId: x.execution.id, leaseEpoch: 1 });
      await w.db.$transaction((tx) =>
        repo.insertDecision(
          {
            tenantId: tA,
            executionId: x.execution.id,
            leaseEpoch: 1,
            decision: decisionFor({ floor: ["secrets"] }),
          },
          tx,
        ),
      );
      const chain = {
        tenantId: tA,
        executionId: x.execution.id,
        workspaceId: x.tree.ws.id,
        repositoryId: x.tree.repo.id,
        pipelineId: x.execution.pipelineId,
      };
      ok(
        p,
        Boolean(await repo.findDecision(chain)),
        "control: the owner does not find its decision",
      );
      ok(
        p,
        (await repo.hasDecisionStarted({ tenantId: tA, executionId: x.execution.id })) === true,
        "control: the marker is not found",
      );
      ok(
        p,
        (await repo.findDecision({ ...chain, tenantId: tB })) === null,
        "another tenant found the decision",
      );
      ok(
        p,
        (await repo.hasDecisionStarted({ tenantId: tB, executionId: x.execution.id })) === false,
        "another tenant found the marker",
      );
      ok(
        p,
        (await repo.findDecision({ ...chain, workspaceId: y.tree.ws.id })) === null,
        "a wrong workspace found the decision",
      );
      ok(
        p,
        (await repo.findDecision({ ...chain, repositoryId: y.tree.repo.id })) === null,
        "a wrong repository found the decision",
      );
      ok(
        p,
        (await repo.findDecision({ ...chain, pipelineId: y.execution.pipelineId })) === null,
        "a wrong pipeline found the decision",
      );
      const foreign = await w.db
        .$transaction((tx) =>
          repo.insertDecision(
            {
              tenantId: tB,
              executionId: x.execution.id,
              leaseEpoch: 1,
              decision: decisionFor({ floor: ["secrets"] }),
            },
            tx,
          ),
        )
        .then(
          () => "accepted",
          (e) => e.name,
        );
      ok(p, foreign === "LeaseLostError", `inserting for another tenant's execution: ${foreign}`);
      ok(
        p,
        !(await w.db.scanDecision.findFirst({ where: { tenantId: tB } })),
        "a decision exists under the other tenant",
      );
      // the hint
      const message = (tenantId, over = {}) =>
        createEventEnvelope({
          messageId: `decision-${randomUUID()}`,
          type: "pipeline.execution.decision_completed",
          schemaVersion: 1,
          tenantId,
          workspaceId: x.tree.ws.id,
          repositoryId: x.tree.repo.id,
          pipelineId: x.execution.pipelineId,
          executionId: x.execution.id,
          initiator: { type: "system", id: "suite" },
          subject: { type: "execution", id: x.execution.id },
          payload: {
            executionId: x.execution.id,
            workspaceId: x.tree.ws.id,
            pipelineId: x.execution.pipelineId,
            rev: 2,
            ...over,
          },
        });
      await w.verify(parseMessage(message(tA))).then(
        () => {},
        () => p.push("the owner's hint was refused"),
      );
      const bad = await w.verify(parseMessage(message(tB))).then(
        () => "accepted",
        (e) => e.name,
      );
      ok(p, bad !== "accepted", "another tenant's decision hint passed the ownership check");
      let extra = "accepted";
      try {
        parseMessage(message(tA, { summary: "model text" }));
      } catch {
        extra = "refused";
      }
      ok(p, extra === "refused", "the hint contract accepted a field with model text");
      const hint = buildHint(parseMessage(message(tA)), {
        tenantId: tA,
        workspaceId: x.tree.ws.id,
        executionId: x.execution.id,
        pipelineId: x.execution.pipelineId,
      });
      ok(
        p,
        hint?.event === "execution.decision" &&
          Object.keys(hint.payload).sort().join() === "executionId,pipelineId,rev,workspaceId",
        `hint ${json(hint)}`,
      );
      ok(
        p,
        hint?.rooms.length === 2 && hint.rooms.every((room) => room.includes(tA)),
        "the hint rooms are not scoped by the tenant",
      );
      return p;
    },
  },
  {
    id: "DECDB-01",
    name: "scan_decisions guards in the database: one row per execution (a second is refused), UPDATE is refused (insert-only), the composite chain must match (another tenant, workspace, repository or pipeline is a foreign key violation), the execution must be preparing, scan kind and trust equal the execution's, floor, additions, final and not-selected sets are arrays of known unique catalog types, the final set is exactly floor plus additions in catalog order, no addition is in the floor, the final and not-selected sets are exactly the snapshot's enabled types, additions need agent status ok, enumerations and lengths are enforced, and every credential shape is refused in the text columns",
    async run(w) {
      const p = [];
      const make = async (label, kind = "full") => {
        const tree = await w.tree(label);
        const execution = await w.execution(
          tree,
          kind === "full"
            ? {}
            : { scanKind: "incremental", scanKindReason: "push", baseSha: w.sha() },
        );
        await claimAndDie(w, tree, execution, 600);
        return { tree, e: await w.row(execution) };
      };
      const data = (e, over = {}) => ({
        tenantId: e.tenantId,
        workspaceId: e.workspaceId,
        repositoryId: e.repositoryId,
        pipelineId: e.pipelineId,
        executionId: e.id,
        scanKind: e.scanKind,
        trust: e.trust,
        diffSource: e.scanKind === "full" ? "none" : "github_compare",
        diffStatus: e.scanKind === "full" ? "not_needed" : "complete",
        changedTotal: e.scanKind === "full" ? 0 : 1,
        changeSummary: { total: 1 },
        secretsRule: "any_change",
        floor: [{ scanType: "secrets", ruleIds: ["FL-3"] }],
        agentStatus: "not_configured",
        agentAdditions: [],
        finalTypes: ["secrets"],
        notSelected: ["sbom", "sca", "sast"].map((scanType) => ({
          scanType,
          reason: "no_matching_changes",
        })),
        ...over,
      });
      const attempt = (row) =>
        w.db.scanDecision.create({ data: row, select: { id: true } }).then(
          () => "accepted",
          (e) => String(e.message),
        );
      const refuse = async (label, row, pattern) => {
        const result = await attempt(row);
        ok(
          p,
          result !== "accepted" && pattern.test(result),
          `${label}: ${result === "accepted" ? "accepted" : result.slice(-160)}`,
        );
      };
      const inc = await make("dbInc", "incremental");
      const e = inc.e;
      // sets
      await refuse(
        "floor type missing from final",
        data(e, {
          finalTypes: ["sbom"],
          notSelected: ["sca", "sast", "secrets"].map((scanType) => ({ scanType, reason: "r" })),
        }),
        /final set must contain every floor type|neither floor/,
      );
      await refuse(
        "a floor type missing from the final set while every other rule holds",
        data(e, {
          floor: [
            { scanType: "sbom", ruleIds: ["FL-1"] },
            { scanType: "secrets", ruleIds: ["FL-3"] },
          ],
          finalTypes: ["secrets"],
          notSelected: ["sbom", "sca", "sast"].map((scanType) => ({
            scanType,
            reason: "no_matching_changes",
          })),
        }),
        /final set must contain every floor type/,
      );
      await refuse(
        "addition inside the floor",
        data(e, { agentStatus: "ok", agentAdditions: [{ scanType: "secrets", reason: "x" }] }),
        /already in the floor/,
      );
      await refuse(
        "final type that is neither floor nor addition",
        data(e, {
          finalTypes: ["sbom", "secrets"],
          notSelected: ["sca", "sast"].map((scanType) => ({ scanType, reason: "r" })),
        }),
        /neither floor nor an addition/,
      );
      await refuse(
        "unknown scan type",
        data(e, { floor: [{ scanType: "dast", ruleIds: [] }], finalTypes: ["dast"] }),
        /unknown scan type/,
      );
      await refuse(
        "duplicate in floor",
        data(e, {
          floor: [
            { scanType: "secrets", ruleIds: [] },
            { scanType: "secrets", ruleIds: [] },
          ],
        }),
        /twice/,
      );
      await refuse(
        "final out of catalog order",
        data(e, {
          agentStatus: "ok",
          agentAdditions: [{ scanType: "sbom", reason: "x" }],
          finalTypes: ["secrets", "sbom"],
          notSelected: ["sca", "sast"].map((scanType) => ({ scanType, reason: "r" })),
        }),
        /catalog order/,
      );
      await refuse(
        "final and not selected overlap enabled set (a type missing)",
        data(e, { notSelected: [{ scanType: "sbom", reason: "r" }] }),
        /exactly the enabled/,
      );
      await refuse(
        "not selected overlaps final",
        data(e, {
          notSelected: ["sbom", "sca", "sast", "secrets"].map((scanType) => ({
            scanType,
            reason: "r",
          })),
        }),
        /exactly the enabled|at most four|twice/,
      );
      await refuse(
        "floor not an array",
        data(e, { floor: { scanType: "secrets" } }),
        /JSON arrays/,
      );
      await refuse(
        "floor entry not an object",
        data(e, { floor: ["secrets"] }),
        /malformed set entries/,
      );
      await refuse(
        "five entries",
        data(e, {
          notSelected: Array.from({ length: 5 }, () => ({ scanType: "sbom", reason: "r" })),
        }),
        /at most four/,
      );
      await refuse(
        "additions without agent status ok",
        data(e, {
          agentAdditions: [{ scanType: "sbom", reason: "x" }],
          finalTypes: ["sbom", "secrets"],
          notSelected: ["sca", "sast"].map((scanType) => ({ scanType, reason: "r" })),
        }),
        /values_check|additions/,
      );
      // enumerations and lengths
      for (const [label, over] of [
        ["diff source", { diffSource: "git_clone" }],
        ["diff status", { diffStatus: "partial" }],
        ["secrets rule", { secretsRule: "never" }],
        ["agent status", { agentStatus: "great" }],
        ["a complete diff naming no source", { diffSource: "unavailable" }],
        ["a changed total on a truncated diff", { diffStatus: "truncated", changedTotal: 5 }],
        ["a negative total", { changedTotal: -1 }],
        ["provider of 101 characters", { agentProvider: "p".repeat(101) }],
        ["model of 201 characters", { agentModel: "m".repeat(201) }],
        [
          "summary of 1001 characters",
          { agentStatus: "ok", agentAdditions: [], agentSummary: "s".repeat(1001) },
        ],
        ["an empty summary", { agentStatus: "ok", agentSummary: "" }],
        ["a summary without status ok", { agentSummary: "text" }],
      ])
        await refuse(label, data(e, over), /values_check|violates check|JSON|diff/);
      // credentials in every text-bearing column
      for (const [label, over] of [
        [
          "an AWS key id in the summary",
          { agentStatus: "ok", agentSummary: "AKIAIOSFODNN7EXAMPLE" },
        ],
        [
          "a GitHub token in the summary",
          { agentStatus: "ok", agentSummary: "ghp_abcdefghijklmnopqrstuvwxyz0123456789" },
        ],
        ["an API key in the model", { agentModel: "sk-ant-abcdefghijklmnopqrstuvwxyz0123" }],
        ["a bearer token in the provider", { agentProvider: "Bearer abcdefghijklmnop" }],
        [
          "a URL with credentials in a sample path",
          { changeSummary: { samples: { docs: ["https://user:secret@host/x"] } } },
        ],
        [
          "a private key in a reason",
          {
            agentStatus: "ok",
            agentAdditions: [{ scanType: "sbom", reason: "-----BEGIN RSA PRIVATE KEY-----" }],
            finalTypes: ["sbom", "secrets"],
            notSelected: ["sca", "sast"].map((scanType) => ({ scanType, reason: "r" })),
          },
        ],
        [
          "a token query in a not-selected reason",
          {
            notSelected: [
              { scanType: "sbom", reason: "?token=abcdef123456" },
              { scanType: "sca", reason: "r" },
              { scanType: "sast", reason: "r" },
            ],
          },
        ],
      ])
        await refuse(label, data(e, over), /no_credentials_check|violates check/);
      // scan kind and trust must equal the execution's, the chain must match
      await refuse(
        "scan kind differing from the execution's",
        data(e, {
          scanKind: "full",
          diffSource: "none",
          diffStatus: "not_needed",
          changedTotal: 0,
        }),
        /scan kind and trust/,
      );
      await refuse(
        "trust differing from the execution's",
        data(e, { trust: "untrusted_fork" }),
        /scan kind and trust/,
      );
      const other = await make("dbOther", "incremental");
      await refuse(
        "another tenant's execution",
        data(e, { tenantId: other.tree.tenant.id }),
        /foreign key|Foreign key/,
      );
      await refuse(
        "a wrong workspace",
        data(e, { workspaceId: other.e.workspaceId }),
        /foreign key|Foreign key/,
      );
      await refuse(
        "a wrong repository",
        data(e, { repositoryId: other.e.repositoryId }),
        /foreign key|Foreign key/,
      );
      await refuse(
        "a wrong pipeline",
        data(e, { pipelineId: other.e.pipelineId }),
        /foreign key|Foreign key/,
      );
      ok(
        p,
        (await w.db.scanDecision.count({ where: { executionId: e.id } })) === 0,
        "a refused insert left a row",
      );
      // the valid row is accepted once; a second and an update are refused
      ok(p, (await attempt(data(e))) === "accepted", "control: the valid decision was refused");
      await refuse("a second decision for the execution", data(e), /Unique constraint|unique/i);
      const upd = await w.db
        .$executeRaw`UPDATE scan_decisions SET agent_status = 'ok' WHERE execution_id = ${e.id}::uuid`.then(
        () => "accepted",
        (err) => String(err.message),
      );
      ok(p, upd !== "accepted" && /insert-only/.test(upd), `UPDATE: ${upd.slice(-120)}`);
      const del = await w.db.$executeRaw`TRUNCATE scan_decisions`.then(
        () => "accepted",
        (err) => String(err.message),
      );
      ok(p, del !== "accepted" && /TRUNCATE/.test(del), `TRUNCATE: ${del.slice(-120)}`);
      // the execution must be preparing: queued and running executions refuse a record
      const queued = await w.tree("dbQueued");
      const qe = await w.execution(queued);
      await refuse("an execution that is still queued", data(qe), /preparing|execution is queued/);
      const running = await make("dbRunning");
      await w.db
        .$executeRaw`UPDATE executions SET status = 'running' WHERE id = ${running.e.id}::uuid`;
      await refuse(
        "an execution that is running",
        data(running.e),
        /preparing|execution is running/,
      );
      // a full-run decision for a full execution (diff none) is accepted: control for the shapes
      const full = await make("dbFull");
      ok(
        p,
        (await attempt(
          data(full.e, {
            floor: ["sbom", "sca", "sast", "secrets"].map((scanType) => ({
              scanType,
              ruleIds: ["FL-5"],
            })),
            finalTypes: ["sbom", "sca", "sast", "secrets"],
            notSelected: [],
            agentStatus: "nothing_to_add",
          }),
        )) === "accepted",
        "control: a full-run decision was refused",
      );
      return p;
    },
  },
  {
    id: "DECDB-02",
    name: "the zero-scan ending in the database: succeeded may carry the reason no_applicable_scans and no other, no other status may carry it, the others keep their reason rule; the quota unit is released by running -> succeeded ONLY with that reason, a decision with an empty final set, no scan task, zero task counts and the unit given back in the same statement (any missing piece is refused, also on a copy of the statement with a different reason), no other running ending releases, and preparing -> succeeded stays outside the state graph",
    async run(w) {
      const p = [];
      const prepared = async (label) => {
        const tree = await w.tree(label);
        const execution = await w.execution(tree, { quotaConsumed: 1 });
        await w.setQuotaUsage(tree, 1);
        await claimAndDie(w, tree, execution, 600);
        return { tree, e: await w.row(execution) };
      };
      const emptyDecision = (e) =>
        w.db.scanDecision.create({
          data: {
            tenantId: e.tenantId,
            workspaceId: e.workspaceId,
            repositoryId: e.repositoryId,
            pipelineId: e.pipelineId,
            executionId: e.id,
            scanKind: e.scanKind,
            trust: e.trust,
            diffSource: "none",
            diffStatus: "not_needed",
            secretsRule: "any_change",
            floor: [],
            agentStatus: "not_configured",
            finalTypes: [],
            notSelected: ALL.map((scanType) => ({ scanType, reason: "no_matching_changes" })),
          },
        });
      const toRunning = (e) =>
        w.db.$executeRaw`UPDATE executions SET status = 'running' WHERE id = ${e.id}::uuid`;
      const end = (
        e,
        {
          status = "succeeded",
          reason = "no_applicable_scans",
          release = true,
          counts = '{"total":0}',
        } = {},
      ) =>
        w.db
          .$executeRawUnsafe(
            `UPDATE executions SET status = $2::execution_status, status_reason = $3, task_counts = $4::jsonb, lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL${release ? ", quota_released_at = now()" : ""} WHERE id = $1::uuid`,
            e.id,
            status,
            reason,
            counts,
          )
          .then(
            () => "accepted",
            (err) => String(err.message),
          );
      const rejected = (label, result, pattern = /./) =>
        ok(
          p,
          result !== "accepted" && pattern.test(result),
          `${label}: ${result === "accepted" ? "accepted" : result.slice(-170)}`,
        );
      // the CHECK
      const a = await prepared("zeroA");
      await emptyDecision(a.e);
      await toRunning(a.e);
      rejected(
        "a reason other than no_applicable_scans on succeeded",
        await end(a.e, { reason: "all_good", release: false }),
        /status_reason_check/,
      );
      rejected(
        "failed carrying no_applicable_scans",
        await end(a.e, { status: "failed", release: false }),
        /status_reason_check|ends a running execution as succeeded only/,
      );
      rejected(
        "partial carrying no_applicable_scans",
        await end(a.e, { status: "partial", release: false }),
        /status_reason_check|ends a running execution as succeeded only/,
      );
      rejected(
        "cancelled carrying no_applicable_scans",
        await end(a.e, { status: "cancelled", release: false }),
        /status_reason_check|ends a running execution as succeeded only/,
      );
      for (const status of ["blocked", "skipped"]) {
        const t = await w.tree(`zeroCheck${status}`);
        const created = await w.execution(t, { status, statusReason: "no_applicable_scans" }).then(
          () => "accepted",
          (err) => String(err.message),
        );
        rejected(`${status} created with no_applicable_scans`, created, /status_reason_check/);
      }
      const t2 = await w.tree("zeroCheckQueued");
      rejected(
        "queued created with a reason",
        await w.execution(t2, { statusReason: "no_applicable_scans" }).then(
          () => "accepted",
          (err) => String(err.message),
        ),
        /status_reason_check/,
      );
      rejected(
        "failed without a reason",
        await end(a.e, { status: "failed", reason: null, release: false }),
        /status_reason_check/,
      );
      // the trigger: the release needs the whole picture
      rejected(
        "the zero-scan reason without releasing the unit",
        await end(a.e, { release: false }),
        /quota unit given back/,
      );
      rejected(
        "running -> failed that releases the unit",
        await end(a.e, { status: "failed", reason: "x", release: true }),
        /quota_released_at/,
      );
      rejected(
        "running -> succeeded that releases the unit with another reason",
        await end(a.e, { reason: null, release: true }),
        /quota_released_at/,
      );
      rejected(
        "running -> cancelled that releases the unit",
        await end(a.e, { status: "cancelled", reason: "user_cancelled", release: true }),
        /quota_released_at/,
      );
      rejected(
        "task counts that are not zero",
        await end(a.e, { counts: '{"total":1}' }),
        /zero task counts/,
      );
      ok(p, (await end(a.e)) === "accepted", "control: the complete zero-scan ending was refused");
      ok(p, (await w.row(a.e)).quotaReleasedAt !== null, "control: the release was not recorded");
      // no decision
      const b = await prepared("zeroB");
      await toRunning(b.e);
      rejected("the zero-scan ending without a decision", await end(b.e), /empty final set/);
      // a decision with a non-empty final set
      const c = await prepared("zeroC");
      await w.db.scanDecision.create({
        data: {
          tenantId: c.e.tenantId,
          workspaceId: c.e.workspaceId,
          repositoryId: c.e.repositoryId,
          pipelineId: c.e.pipelineId,
          executionId: c.e.id,
          scanKind: c.e.scanKind,
          trust: c.e.trust,
          diffSource: "none",
          diffStatus: "not_needed",
          secretsRule: "any_change",
          floor: ALL.map((scanType) => ({ scanType, ruleIds: ["FL-5"] })),
          agentStatus: "nothing_to_add",
          finalTypes: ALL,
          notSelected: [],
        },
      });
      await toRunning(c.e);
      rejected(
        "the zero-scan ending with a non-empty final set",
        await end(c.e),
        /empty final set/,
      );
      // a task exists
      const d = await prepared("zeroD");
      await emptyDecision(d.e);
      await toRunning(d.e);
      await w.db.scanTask.create({
        data: {
          tenantId: d.e.tenantId,
          workspaceId: d.e.workspaceId,
          repositoryId: d.e.repositoryId,
          pipelineId: d.e.pipelineId,
          executionId: d.e.id,
          scanType: "sca",
          ordinal: 1,
          status: "pending",
          engineId: "e",
          engineProfile: "default",
          severityThreshold: "low",
          timeoutSeconds: 60,
        },
      });
      rejected("the zero-scan ending with a scan task", await end(d.e), /no scan task/);
      // the state graph is unchanged: preparing -> succeeded is not allowed, with or without the reason
      const f = await prepared("zeroF");
      await emptyDecision(f.e);
      rejected(
        "preparing -> succeeded (state graph)",
        await end(f.e),
        /transition preparing -> succeeded is not allowed|no_applicable_scans ends a running/,
      );
      // the normal succeeded and the old statuses keep their rules
      const g = await prepared("zeroG");
      await toRunning(g.e);
      ok(
        p,
        (await end(g.e, { reason: null, release: false, counts: '{"total":1}' })) === "accepted",
        "control: a normal succeeded (no reason) was refused",
      );
      // the helper functions and the shared table agree
      const { canReleaseQuotaOnTransition } = await import("@qmentisai/shared");
      ok(
        p,
        canReleaseQuotaOnTransition("running", "succeeded", "no_applicable_scans") === true,
        "shared: zero-scan release not allowed",
      );
      ok(
        p,
        canReleaseQuotaOnTransition("running", "succeeded", null) === false &&
          canReleaseQuotaOnTransition("running", "succeeded") === false,
        "shared: a plain succeeded releases",
      );
      ok(
        p,
        canReleaseQuotaOnTransition("running", "failed", "no_applicable_scans") === false,
        "shared: running -> failed releases",
      );
      ok(
        p,
        canReleaseQuotaOnTransition("preparing", "succeeded", "no_applicable_scans") === false,
        "shared: preparing -> succeeded releases",
      );
      return p;
    },
  },
  {
    id: "DECDB-03",
    name: "decision events: decision_started and decision_completed are accepted history types written only under the lease (a stale epoch writes nothing), an unknown type is refused by the database, the events are insert-only and refused for a terminal execution, and the details stay within the 4 KiB bound",
    async run(w) {
      const p = [];
      const tree = await w.tree("decEvents");
      const execution = await w.execution(tree);
      await claimAndDie(w, tree, execution, 600);
      const t = tree.tenant.id;
      for (const type of ["decision_started", "decision_completed"]) {
        const e = await w.repo.recordEvent({
          tenantId: t,
          executionId: execution.id,
          type,
          leaseEpoch: 1,
          details: {},
        });
        ok(p, e?.type === type, `${type} was not recorded`);
      }
      // the marker helper writes at most one marker per execution: a second call is a no-op
      const second = await w.execution(tree);
      await claimAndDie(w, tree, second, 600);
      const markers = () =>
        w.db.executionEvent.count({ where: { executionId: second.id, type: "decision_started" } });
      const firstMark = await dec(w.db).markDecisionStarted({
        tenantId: t,
        executionId: second.id,
        leaseEpoch: 1,
      });
      const again = await dec(w.db).markDecisionStarted({
        tenantId: t,
        executionId: second.id,
        leaseEpoch: 1,
      });
      ok(
        p,
        firstMark === true && again === false,
        `markers written: first ${firstMark}, second ${again}`,
      );
      ok(
        p,
        (await markers()) === 1,
        `${await markers()} decision_started markers for one execution`,
      );
      const stale = await w.repo
        .recordEvent({
          tenantId: t,
          executionId: execution.id,
          type: "decision_started",
          leaseEpoch: 7,
          details: {},
        })
        .then(
          () => "accepted",
          (e) => e.name,
        );
      ok(p, stale === "LeaseLostError", `a stale epoch wrote a decision event: ${stale}`);
      const unknown = await w.db
        .$executeRaw`INSERT INTO execution_events (id, tenant_id, workspace_id, repository_id, pipeline_id, execution_id, type, actor_type, details) VALUES (gen_random_uuid(), ${t}::uuid, ${execution.workspaceId}::uuid, ${execution.repositoryId}::uuid, ${execution.pipelineId}::uuid, ${execution.id}::uuid, 'decision_rewritten', 'system', '{}'::jsonb)`.then(
        () => "accepted",
        (e) => String(e.message),
      );
      ok(
        p,
        unknown !== "accepted" && /execution_events_type_check/.test(unknown),
        `an unknown type: ${unknown.slice(-120)}`,
      );
      const big = await w.repo
        .recordEvent({
          tenantId: t,
          executionId: execution.id,
          type: "decision_completed",
          leaseEpoch: 1,
          details: { summary: "x".repeat(5000) },
        })
        .then(
          () => "accepted",
          (e) => String(e.message),
        );
      ok(p, big !== "accepted", "a details object over 4 KiB was accepted");
      const upd = await w.db
        .$executeRaw`UPDATE execution_events SET details = '{}'::jsonb WHERE execution_id = ${execution.id}::uuid AND type = 'decision_started'`.then(
        () => "accepted",
        (e) => String(e.message),
      );
      ok(p, upd !== "accepted", "a decision event was updated");
      ok(
        p,
        (await w.repo
          .recordEvent({
            tenantId: tree.tenant.id,
            executionId: execution.id,
            type: "transition",
            leaseEpoch: 1,
          })
          .then(
            () => "accepted",
            (e) => e.name,
          )) === "TypeError",
        "recordEvent accepted a transition type",
      );
      return p;
    },
  },
  {
    id: "DECDB-04",
    name: "retention purge removes the decision with its execution: a terminal execution past the metadata retention that has a decision row is purged without a foreign key stop, and another tenant's decision survives",
    async run(w) {
      const p = [];
      const { createExecutionRetentionRepository } = await import("@qmentisai/db");
      const mk = async (label) => {
        const x = await incremental(w, label);
        await claimAndDie(w, x.tree, x.execution, 600);
        await w.db.$transaction((tx) =>
          dec(w.db).insertDecision(
            {
              tenantId: x.tree.tenant.id,
              executionId: x.execution.id,
              leaseEpoch: 1,
              decision: decisionFor({ floor: ["secrets"] }),
            },
            tx,
          ),
        );
        return x;
      };
      const old = await mk("retOld");
      const young = await mk("retYoung");
      await w.db
        .$executeRaw`UPDATE executions SET status = 'failed', status_reason = 'suite', lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = ${old.execution.id}::uuid`;
      await w.db.$transaction(async (tx) => {
        await tx.$executeRawUnsafe(`ALTER TABLE executions DISABLE TRIGGER USER`);
        await tx.$executeRawUnsafe(
          `UPDATE executions SET finished_at = now() - make_interval(days => 600), requested_at = now() - make_interval(days => 600) WHERE id = $1::uuid`,
          old.execution.id,
        );
        await tx.$executeRawUnsafe(`ALTER TABLE executions ENABLE TRIGGER USER`);
      });
      const result = await createExecutionRetentionRepository({ db: w.db })
        .purgeExpired({ metadataRetentionMonths: 13, batchSize: 50, maxBatches: 5 })
        .catch((e) => ({ error: e.message }));
      ok(p, !result.error, `purge failed: ${result.error}`);
      ok(
        p,
        !(await w.db.execution.findFirst({ where: { id: old.execution.id } })),
        "the old execution was not purged (its decision blocked the purge?)",
      );
      ok(p, !(await decisionOf(w, old.execution)), "the old decision survived its execution");
      ok(
        p,
        Boolean(await decisionOf(w, young.execution)),
        "another execution's decision was purged",
      );
      return p;
    },
  },
  {
    id: "DEC-S04c",
    name: "no credential in any stored surface of a TRUSTED run that used the diff token and the model (SPEC scan-decisioning DEC-S04): after an incremental trusted run whose decision added a type through the model, none of the installation tokens the diff step minted, no Authorization value and no credential shape appears in the decision record, the decision events, the audit entries, the outbox messages, the execution log, the tasks or any other row of the tenant (control: a token was minted and the decision has the model's addition)",
    async run(w) {
      const p = [];
      const model = await modelAdding(w, ["sbom"]);
      try {
        const x = await incremental(w, "tokenSweep");
        const before = (await w.sourceCalls()).minted.length;
        await runOnce(w, x.tree, x.execution, {
          orch: w.orchestrator({}, { decisionRuntime: model.runtime }),
        });
        const minted = (await w.sourceCalls()).minted.slice(before);
        ok(p, minted.length >= 1, "control: no installation token was minted for the diff");
        const record = await decisionOf(w, x.execution);
        ok(
          p,
          record?.agentStatus === "ok" && JSON.stringify(record.agentAdditions).includes("sbom"),
          `control: the decision does not carry the model's addition (${record?.agentStatus})`,
        );
        const decisions = await w.db.scanDecision.findMany({
          where: { tenantId: x.tree.tenant.id },
        });
        const dump = `${await w.dump(x.tree)}${JSON.stringify(decisions)}`;
        for (const m of minted)
          ok(
            p,
            typeof m.token === "string" && !dump.includes(m.token),
            "an installation token is stored",
          );
        ok(
          p,
          !/ghs_stub_|Authorization|Bearer /i.test(dump),
          "an Authorization value or token prefix is stored",
        );
        ok(p, findCredentials(dump).length === 0, "a credential shape is stored");
      } finally {
        await model.close();
      }
      return p;
    },
  },
  {
    id: "DEC-S03b",
    name: "fail safe inside the Executions preparing state (SPEC scan-decisioning 14.1 DEC-S03): a provider that answers HTTP 500, one that returns an invalid output (a floor type), one that never answers (the timeout) and a runtime whose provider resolution throws each leave the EXECUTION running to a normal ending (succeeded, no failure reason) with exactly the floor as tasks and the matching agent status in the decision record; the model never fails the run",
    async run(w) {
      const p = [];
      const stub = await startLlm();
      try {
        const cases = [
          ["http500", () => ({ status: 500 }), "error"],
          ["invalid", () => ({ calls: [scan("secrets")] }), "invalid_output"],
          ["hang", () => ({ hang: true }), "timeout"],
        ];
        for (const [label, respond, expected] of cases) {
          stub.state.respond = respond;
          const x = await incremental(w, `failSafe${label}`);
          await runOnce(w, x.tree, x.execution, {
            orch: w.orchestrator({}, { decisionRuntime: runtimeFor(w, "ollama", stub) }),
          });
          const row = await w.row(x.execution);
          const record = await decisionOf(w, x.execution);
          ok(
            p,
            row.status === "succeeded" && row.statusReason === null,
            `${label}: the execution ended ${row.status}/${row.statusReason}`,
          );
          ok(p, record?.agentStatus === expected, `${label}: agent status ${record?.agentStatus}`);
          ok(
            p,
            types(await w.taskRows(x.execution)) === "secrets",
            `${label}: tasks ${types(await w.taskRows(x.execution))}`,
          );
        }
        const x = await incremental(w, "failSafeThrow");
        const throwing = {
          resolveProvider: async () => {
            throw new Error("resolver exploded");
          },
        };
        await runOnce(w, x.tree, x.execution, {
          orch: w.orchestrator({}, { decisionRuntime: throwing }),
        });
        const row = await w.row(x.execution);
        const record = await decisionOf(w, x.execution);
        ok(p, row.status === "succeeded", `throwing resolver: the execution ended ${row.status}`);
        ok(p, record?.agentStatus === "error", `throwing resolver: ${record?.agentStatus}`);
        ok(
          p,
          types(await w.taskRows(x.execution)) === "secrets",
          "throwing resolver: tasks are not the floor",
        );
      } finally {
        await stub.close();
      }
      return p;
    },
  },
];
