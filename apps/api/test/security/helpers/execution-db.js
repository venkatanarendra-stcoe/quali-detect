import { randomBytes } from "node:crypto";
import {
  EXECUTION_STATUS_VALUES,
  SCAN_TASK_STATUS_VALUES,
  canTransitionExecution,
  canTransitionScanTask,
} from "@qmentisai/shared";
import { LeaseLostError, createExecutionRepository } from "@qmentisai/db";
import { attempt, buildPipelineDbWorld, mustAccept, mustReject, probe } from "./pipeline-db.js";

/** Like `mustReject`, but `needle` may list alternatives separated by `|`. */
function rej(problems, label, r, needle) {
  if (!needle || !needle.includes("|")) return mustReject(problems, label, r, needle);
  if (r.ok) return problems.push(`${label}: accepted`);
  if (!needle.split("|").some((n) => r.code === n || r.message.includes(n)))
    problems.push(
      `${label}: rejected for another reason (${r.code ?? r.message.trim().split("\n").pop().slice(0, 120)})`,
    );
}

/**
 * Executions: database integrity and the data-access helpers of the execution state machine (ADR-008 area 10, in-process;
 * `EXECDB-011..018`, docs/modules/executions/SPEC.md §7.3, §14.1 part B). The state-machine trigger, the immutability and
 * insert-only guards, the lease and attempt fences, the composite tenant-safe foreign keys and the orchestrator marker are
 * checked against the disposable database through SQL and the Prisma client; `EXECDB-016..018` additionally call the real
 * helpers of `@qmentisai/db` (claim, renew, reclaim, fence, transition with quota release) concurrently.
 *
 * Every denial is paired with a control (the same write, made legitimately, succeeds) so it cannot pass vacuously. The
 * transition table the checks expect is written out HERE (independent of the code under test); `EXECDB-012` compares it
 * with the SQL function and with `@qmentisai/shared`.
 */

const rand = (n = 4) => randomBytes(n).toString("hex");
const SHA = "a".repeat(40);
const bogusId = "00000000-0000-4000-8000-0000000000ff";
/** Hex digits as letters, so a random marker key matches the `^[a-z][a-z0-9_.]*$` CHECK without digits being required. */
const letters = (n = 6) => rand(n).replace(/[0-9]/g, (d) => "ghijklmnop"[Number(d)]);

/** The allowed execution transitions (SPEC §6.1), written out for the checks. */
const ALLOWED = new Set([
  "queued>preparing",
  "queued>cancelled",
  "preparing>running",
  "preparing>failed",
  "preparing>cancelled",
  "preparing>timed_out",
  "running>succeeded",
  "running>partial",
  "running>failed",
  "running>cancelled",
  "running>timed_out",
]);
const TERMINAL = ["succeeded", "failed", "partial", "cancelled", "timed_out", "blocked", "skipped"];
const OUTCOMES = ["succeeded", "failed", "partial", "cancelled", "timed_out"];
const STATES = ["queued", "preparing", "running", ...TERMINAL];
const NEEDS_REASON = new Set(["blocked", "skipped", "cancelled", "failed", "partial", "timed_out"]);
const RESTRICT_OR_CHECK = ["not allowed", "executions_not_cancelling_check", "violates check"];

/**
 * Moves an execution along the legal path to `target` (`preparing`, `running` or an outcome) through plain SQL, the way a
 * worker would: used by other checks that need a running or finished execution. A lease is taken at the claim and cleared when
 * the execution ends.
 * @param {any} db
 * @param {string} id
 * @param {"preparing" | "running" | "succeeded" | "failed" | "partial" | "cancelled" | "timed_out"} target
 * @param {string} [reason]
 */
export async function driveExecution(db, id, target, reason = "suite_fixture") {
  const [row] =
    await db.$queryRaw`SELECT status::text AS status FROM executions WHERE id = ${id}::uuid`;
  let status = row.status;
  if (status === "queued") {
    await db.$executeRaw`
      UPDATE executions SET status = 'preparing', claimed_at = now(), deadline_at = now() + interval '30 minutes',
        lease_owner = 'suite-worker', lease_epoch = lease_epoch + 1, heartbeat_at = now(), lease_expires_at = now() + interval '5 minutes'
      WHERE id = ${id}::uuid`;
    status = "preparing";
  }
  if (target === "preparing") return;
  if (status === "preparing") {
    await db.$executeRaw`UPDATE executions SET status = 'running' WHERE id = ${id}::uuid`;
    status = "running";
  }
  if (target === "running") return;
  await db.$executeRawUnsafe(
    `UPDATE executions SET status = $2::execution_status, status_reason = $3, lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = $1::uuid`,
    id,
    target,
    target === "succeeded" ? null : reason,
  );
}

/** The `chain` columns shared by every child table. @param {{ tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, id: string }} e */
const chain = (e) => ({
  tenantId: e.tenantId,
  workspaceId: e.workspaceId,
  repositoryId: e.repositoryId,
  pipelineId: e.pipelineId,
  executionId: e.id,
});

/** A published pipeline of tree `tree` (workspace `i`) and a queued execution on it. */
async function queuedExecution(c, tree, i = 0, extra = {}) {
  const { pipeline, version } = await c.published(tree, i);
  const execution = await c.execution(pipeline, version, extra);
  return { pipeline, version, execution };
}

/** An execution in `status`, created legitimately (blocked/skipped directly, others driven through the machine). */
async function inState(c, tree, status, i = 0) {
  if (status === "blocked" || status === "skipped") {
    const { execution } = await queuedExecution(c, tree, i, {
      status,
      statusReason: "suite_reason",
    });
    return execution;
  }
  const { execution } = await queuedExecution(c, tree, i);
  if (status !== "queued") await driveExecution(c.db, execution.id, status);
  return c.db.execution.findUnique({ where: { id: execution.id } });
}

const taskData = (e, scanType = "sca", extra = {}) => ({
  ...chain(e),
  scanType,
  ordinal: 0,
  status: "queued",
  engineId: "suite-engine",
  engineProfile: "default",
  severityThreshold: "low",
  timeoutSeconds: 900,
  ...extra,
});

/** A scan task of `execution`, driven to `running` at attempt 0 (the lease columns the CHECK requires are set). */
async function runningTask(c, execution, scanType = "sca") {
  const task = await c.db.scanTask.create({ data: taskData(execution, scanType) });
  await c.db.$executeRaw`
    UPDATE scan_tasks SET status = 'running', lease_owner = 'suite-worker', lease_expires_at = now() + interval '5 minutes', heartbeat_at = now()
    WHERE id = ${task.id}::uuid`;
  return c.db.scanTask.findUnique({ where: { id: task.id } });
}

const attemptData = (task, extra = {}) => ({
  tenantId: task.tenantId,
  workspaceId: task.workspaceId,
  repositoryId: task.repositoryId,
  pipelineId: task.pipelineId,
  executionId: task.executionId,
  scanTaskId: task.id,
  attempt: task.attempt,
  ...extra,
});

const resultData = (task, extra = {}) => ({
  ...attemptData(task),
  scanType: task.scanType,
  engineId: "suite-engine",
  engineVersion: "1.0.0",
  completeness: "complete",
  ...extra,
});

const itemData = (result, extra = {}) => ({
  tenantId: result.tenantId,
  executionId: result.executionId,
  scanResultId: result.id,
  ordinal: 0,
  kind: "vulnerability",
  severity: "low",
  title: "a finding-to-be",
  ...extra,
});

const eventData = (e, extra = {}) => ({ ...chain(e), type: "recovered", ...extra });

const eventCount = (db, id, where = "") =>
  db
    .$queryRawUnsafe(
      `SELECT count(*)::int AS n FROM execution_events WHERE execution_id = $1::uuid ${where}`,
      id,
    )
    .then((r) => r[0].n);

const shape = (db, id) =>
  db.execution
    .findUnique({ where: { id } })
    .then((r) => JSON.stringify(r, (_k, v) => (typeof v === "bigint" ? String(v) : v)));

/** A raw UPDATE of an execution: `set` is a SQL fragment (trusted constants of this file), `params` start at $2. */
const upd = (db, id, set, ...params) =>
  attempt(() =>
    db.$executeRawUnsafe(`UPDATE executions SET ${set} WHERE id = $1::uuid`, id, ...params),
  );

/** The extra SET clauses that make a legal move complete (claim columns, reason, lease cleared). */
function moveSet(from, to) {
  const set = [`status = '${to}'::execution_status`];
  if (NEEDS_REASON.has(to)) set.push("status_reason = 'suite_reason'");
  if (from === "queued" && to === "preparing")
    set.push(
      "claimed_at = now()",
      "deadline_at = now() + interval '30 minutes'",
      "lease_owner = 'suite-worker'",
      "lease_epoch = lease_epoch + 1",
      "heartbeat_at = now()",
      "lease_expires_at = now() + interval '5 minutes'",
    );
  if (TERMINAL.includes(to))
    set.push("lease_owner = NULL", "lease_expires_at = NULL", "heartbeat_at = NULL");
  return set.join(", ");
}

/** Builds tenants A and B (two workspaces, a repository each) with the pipeline-db row factories. @param {any} db */
export async function buildExecutionDbWorld(db) {
  const c = await buildPipelineDbWorld(db);
  c.repo = createExecutionRepository({ db });
  return c;
}

/** @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]} */
export const EXECDB_CHECKS = [
  {
    id: "EXECDB-011",
    name: "execution state machine in the database: of all ordered pairs of statuses only the 11 transitions of SPEC 6.1 are accepted; terminal rows reject every UPDATE; snapshot and one-time columns, status_rev and quota_released_at are guarded; `cancelling` can never be written; a permitted transition writes exactly one event row",
    async run(c) {
      const p = [];
      const { db, A } = c;
      // every ordered pair: the row is put in `from` legitimately, then ONE well-formed UPDATE moves it to `to`
      let accepted = 0;
      for (const from of STATES) {
        for (const to of EXECUTION_STATUS_VALUES) {
          if (to === from) continue; // not a transition: a no-op UPDATE of a live row is allowed, of a terminal row it is covered below
          const row = await inState(c, A, from);
          const before = await shape(db, row.id);
          const events = await eventCount(db, row.id);
          const r = await upd(db, row.id, moveSet(from, to));
          const expected = ALLOWED.has(`${from}>${to}`);
          if (expected) {
            mustAccept(p, `${from} -> ${to}`, r);
            accepted += r.ok ? 1 : 0;
            const after = await db.execution.findUnique({ where: { id: row.id } });
            if (after.status !== to) p.push(`${from} -> ${to}: status is ${after.status}`);
            if (after.statusRev !== row.statusRev + 1)
              p.push(`${from} -> ${to}: status_rev did not follow the status`);
            if (OUTCOMES.includes(to) && !after.finishedAt)
              p.push(`${from} -> ${to}: finished_at was not set`);
            if ((await eventCount(db, row.id)) !== events + 1)
              p.push(`${from} -> ${to}: not exactly one event row`);
            const [ev] = await db.executionEvent.findMany({
              where: { executionId: row.id },
              orderBy: { seq: "desc" },
              take: 1,
            });
            if (ev?.type !== "transition" || ev.fromStatus !== from || ev.toStatus !== to)
              p.push(`${from} -> ${to}: the event row does not describe it`);
          } else {
            rej(p, `${from} -> ${to}`, r, null);
            if (r.ok === false && !RESTRICT_OR_CHECK.some((n) => r.message.includes(n)))
              p.push(
                `${from} -> ${to}: rejected for another reason (${r.message.trim().split("\n").pop().slice(0, 100)})`,
              );
            if ((await shape(db, row.id)) !== before)
              p.push(`${from} -> ${to}: the row changed although it was rejected`);
            if ((await eventCount(db, row.id)) !== events)
              p.push(`${from} -> ${to}: an event row was written for a rejected change`);
          }
        }
      }
      if (accepted !== 11) p.push(`exactly 11 transitions must be accepted, ${accepted} were`);

      // a row can never be INSERTED in the legacy status either
      const { pipeline, version } = await c.published(A, 0);
      rej(
        p,
        "inserting a row with status cancelling",
        await attempt(() => c.execution(pipeline, version, { status: "cancelling" })),
        "executions_not_cancelling_check",
      );

      // terminal rows reject EVERY update, whichever column
      for (const status of TERMINAL) {
        const row = await inState(c, A, status);
        const before = await shape(db, row.id);
        for (const set of [
          "updated_at = now()",
          "status_reason = 'suite_other'",
          "commit_sha = '" + SHA + "'",
          "task_counts = '{}'::jsonb",
          "heartbeat_at = now()",
          "archive_sha256 = repeat('a', 64), archive_bytes = 1",
          "config_hash = 'x'",
        ])
          rej(p, `terminal ${status}: ${set}`, await upd(db, row.id, set), "terminal");
        if ((await shape(db, row.id)) !== before) p.push(`terminal ${status}: the row changed`);
      }

      // snapshot / identity columns never change, on any live row
      const live = await inState(c, A, "queued");
      for (const set of [
        "config_hash = 'x'",
        "trust = 'untrusted_fork'",
        "scan_kind = 'incremental'",
        "ref_name = 'other'",
        "trigger_type = 'manual'",
        "idempotency_key = 'k'",
        "quota_consumed = 4, quota_period = '2026-11'",
        "requested_at = now()",
        "workspace_id = gen_random_uuid()",
      ])
        rej(p, `queued: ${set}`, await upd(db, live.id, set), "lifecycle columns");

      // status_rev and status_reason follow the status
      rej(
        p,
        "status_rev without a status change",
        await upd(db, live.id, "status_rev = status_rev + 1"),
        "status_rev",
      );
      rej(
        p,
        "status_reason without a status change",
        await upd(db, live.id, "status_reason = 'suite_reason'"),
        "status_reason",
      );
      mustAccept(
        p,
        "the commit is pinned once (null to value)",
        await upd(db, live.id, "commit_sha = $2", SHA),
      );
      mustAccept(
        p,
        "pinning the same commit again",
        await upd(db, live.id, "commit_sha = $2", SHA),
      );
      rej(
        p,
        "changing a pinned commit",
        await upd(db, live.id, "commit_sha = $2", "b".repeat(40)),
        "already set",
      );
      rej(
        p,
        "a wrong status_rev with the status change",
        await upd(db, live.id, moveSet("queued", "preparing") + ", status_rev = status_rev + 2"),
        "status_rev must follow",
      );
      mustAccept(
        p,
        "the exact next status_rev with the status change",
        await upd(db, live.id, moveSet("queued", "preparing") + ", status_rev = status_rev + 1"),
      );

      // one-time columns on a live row: null to value only
      rej(
        p,
        "claimed_at moved after the claim",
        await upd(db, live.id, "claimed_at = now() + interval '1 hour'"),
        "set by the claim|already set",
      );
      rej(
        p,
        "deadline_at moved after the claim",
        await upd(db, live.id, "deadline_at = now() + interval '9 hours'"),
        "set by the claim|already set",
      );
      mustAccept(
        p,
        "the archive facts are recorded while preparing",
        await upd(db, live.id, "archive_sha256 = repeat('a', 64), archive_bytes = 10"),
      );
      rej(
        p,
        "the archive facts rewritten",
        await upd(db, live.id, "archive_sha256 = repeat('b', 64)"),
        "already set",
      );
      rej(
        p,
        "started_at outside preparing -> running",
        await upd(db, live.id, "started_at = now()"),
        "started_at",
      );
      rej(
        p,
        "task_counts before the execution ends",
        await upd(db, live.id, "task_counts = '{}'::jsonb"),
        "task_counts",
      );
      mustAccept(
        p,
        "the cancel request (all four columns) on a preparing execution",
        await upd(
          db,
          live.id,
          "cancel_requested_at = now(), cancel_requested_by_user_id = $2::uuid, cancel_mode = 'graceful', cancel_grace_until = now() + interval '1 minute'",
          A.user.id,
        ),
      );
      rej(
        p,
        "the cancel request moved",
        await upd(
          db,
          live.id,
          "cancel_requested_at = now() + interval '1 hour', cancel_grace_until = now() + interval '2 hours'",
        ),
        "already set",
      );
      const q2 = await inState(c, A, "queued");
      rej(
        p,
        "a cancel request on a queued execution",
        await upd(
          db,
          q2.id,
          "cancel_requested_at = now(), cancel_requested_by_user_id = $2::uuid, cancel_mode = 'graceful', cancel_grace_until = now()",
          A.user.id,
        ),
        "queued execution is cancelled directly",
      );
      const part = await inState(c, A, "preparing");
      rej(
        p,
        "a cancel request with only its time",
        await upd(db, part.id, "cancel_requested_at = now()"),
        "executions_cancel_check",
      );

      // quota_released_at: only by the statements that end an execution before any scan task started, once, with a unit consumed
      const unit = (status) =>
        queuedExecution(c, A, 0, { quotaPeriod: "2026-11", quotaConsumed: 1 }).then(
          async ({ execution }) => {
            if (status !== "queued") await driveExecution(db, execution.id, status);
            return execution;
          },
        );
      const withRelease = (from, to) => moveSet(from, to) + ", quota_released_at = now()";
      const q3 = await unit("queued");
      mustAccept(
        p,
        "queued -> cancelled that gives the unit back",
        await upd(db, q3.id, withRelease("queued", "cancelled")),
      );
      rej(
        p,
        "a second release on the terminal row",
        await upd(db, q3.id, "quota_released_at = now()"),
        "terminal",
      );
      const pr = await unit("preparing");
      mustAccept(
        p,
        "preparing -> failed that gives the unit back",
        await upd(db, pr.id, withRelease("preparing", "failed")),
      );
      const pt = await unit("preparing");
      rej(
        p,
        "preparing -> timed_out cannot give the unit back",
        await upd(db, pt.id, withRelease("preparing", "timed_out")),
        "quota_released_at",
      );
      const ru = await unit("running");
      rej(
        p,
        "running -> cancelled cannot give the unit back",
        await upd(db, ru.id, withRelease("running", "cancelled")),
        "quota_released_at",
      );
      rej(
        p,
        "running -> succeeded cannot give the unit back",
        await upd(db, ru.id, withRelease("running", "succeeded")),
        "quota_released_at",
      );
      const q4 = await inState(c, A, "queued");
      rej(
        p,
        "a release without a consumed unit (CHECK)",
        await upd(db, q4.id, withRelease("queued", "cancelled")),
        "executions_quota_release_check",
      );
      const q5 = await unit("queued");
      rej(
        p,
        "a release recorded without a status change",
        await upd(db, q5.id, "quota_released_at = now()"),
        "quota_released_at",
      );
      return p;
    },
  },
  {
    id: "EXECDB-012",
    name: "the SQL transition functions and the @qmentisai/shared tables are equal for every pair of statuses (executions and scan tasks), and the enum values are the documented ones",
    async run(c) {
      const p = [];
      const { db } = c;
      const labels = async (type) =>
        (
          await db.$queryRawUnsafe(
            `SELECT enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = '${type}' ORDER BY enumsortorder`,
          )
        ).map((r) => r.enumlabel);
      const exec = await labels("execution_status");
      const task = await labels("scan_task_status");
      if ([...exec].sort().join() !== [...EXECUTION_STATUS_VALUES].sort().join())
        p.push(`execution_status values differ: ${exec.join(",")}`);
      if ([...task].sort().join() !== [...SCAN_TASK_STATUS_VALUES].sort().join())
        p.push(`scan_task_status values differ: ${task.join(",")}`);
      let sqlAllowed = 0;
      for (const a of exec)
        for (const b of exec) {
          const [row] = await db.$queryRawUnsafe(
            `SELECT execution_transition_allowed('${a}'::execution_status, '${b}'::execution_status) AS ok`,
          );
          if (row.ok !== canTransitionExecution(a, b))
            p.push(`execution ${a} -> ${b}: SQL ${row.ok}, shared ${canTransitionExecution(a, b)}`);
          if (row.ok !== ALLOWED.has(`${a}>${b}`))
            p.push(`execution ${a} -> ${b}: SQL ${row.ok}, spec table ${ALLOWED.has(`${a}>${b}`)}`);
          sqlAllowed += row.ok ? 1 : 0;
        }
      for (const a of task)
        for (const b of task) {
          const [row] = await db.$queryRawUnsafe(
            `SELECT scan_task_transition_allowed('${a}'::scan_task_status, '${b}'::scan_task_status) AS ok`,
          );
          if (row.ok !== canTransitionScanTask(a, b))
            p.push(`task ${a} -> ${b}: SQL ${row.ok}, shared ${canTransitionScanTask(a, b)}`);
        }
      if (sqlAllowed !== 11)
        p.push(`the SQL function allows ${sqlAllowed} execution transitions, not 11 (control)`);
      return p;
    },
  },
  {
    id: "EXECDB-013",
    name: "chain integrity: a task, attempt, result, item or event whose tenant, workspace, repository, pipeline or execution does not match its parent is refused by foreign keys, an execution cannot be retried across tenants or pipelines, and matching rows insert",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      const { pipeline, version, execution } = await queuedExecution(c, A, 0);
      await driveExecution(db, execution.id, "running");
      const e = await db.execution.findUnique({ where: { id: execution.id } });
      const other = await queuedExecution(c, A, 1); // same tenant, other workspace/repository/pipeline
      const bee = await queuedExecution(c, B, 0);
      const FK = "P2003";
      const wrongs = {
        "another tenant": { tenantId: B.tenant.id },
        "another workspace of the tenant": { workspaceId: A.ws[1].id },
        "another repository of the tenant": { repositoryId: A.repo[1].id },
        "another pipeline of the tenant": { pipelineId: other.pipeline.id },
        "another execution id": { executionId: other.execution.id },
        "another tenant's execution": { executionId: bee.execution.id },
      };
      // controls: the matching rows
      const task = await attempt(() => db.scanTask.create({ data: taskData(e, "sca") }));
      mustAccept(p, "a task of its execution", task);
      for (const [label, over] of Object.entries(wrongs))
        rej(
          p,
          `a task naming ${label}`,
          await attempt(() => db.scanTask.create({ data: { ...taskData(e, "sbom"), ...over } })),
          FK,
        );
      mustAccept(
        p,
        "an event of its execution",
        await attempt(() => db.executionEvent.create({ data: eventData(e) })),
      );
      for (const [label, over] of Object.entries(wrongs))
        rej(
          p,
          `an event naming ${label}`,
          await attempt(() => db.executionEvent.create({ data: { ...eventData(e), ...over } })),
          FK,
        );
      // attempts, results and items hang off a RUNNING task
      const t = await runningTask(c, e, "sast");
      mustAccept(
        p,
        "an attempt of its task",
        await attempt(() => db.scanTaskAttempt.create({ data: attemptData(t) })),
      );
      for (const [label, over] of Object.entries(wrongs))
        rej(
          p,
          `an attempt naming ${label}`,
          await attempt(() =>
            db.scanTaskAttempt.create({ data: { ...attemptData(t, { attempt: 0 }), ...over } }),
          ),
          "P2002|P2003|violates",
        );
      const result = await db.scanResult.create({ data: resultData(t) }).catch((error) => {
        p.push(`control failed, a result of its task: ${error.message.trim().split("\n").pop()}`);
        return null;
      });
      const t2 = await runningTask(c, e, "secrets");
      for (const [label, over] of Object.entries(wrongs))
        rej(
          p,
          `a result naming ${label}`,
          await attempt(() => db.scanResult.create({ data: { ...resultData(t2), ...over } })),
          FK,
        );
      if (result) {
        mustAccept(
          p,
          "an item of its result",
          await attempt(() => db.scanResultItem.create({ data: itemData(result) })),
        );
        rej(
          p,
          "an item naming another tenant",
          await attempt(() =>
            db.scanResultItem.create({
              data: { ...itemData(result, { ordinal: 1 }), tenantId: B.tenant.id },
            }),
          ),
          FK,
        );
        rej(
          p,
          "an item naming another execution",
          await attempt(() =>
            db.scanResultItem.create({
              data: { ...itemData(result, { ordinal: 2 }), executionId: other.execution.id },
            }),
          ),
          FK,
        );
      }
      // retries: same tenant AND same pipeline only
      const retry = (parent, extra = {}) =>
        attempt(() =>
          c.execution(pipeline, version, {
            retryOfExecutionId: parent.id,
            requestedByUserId: A.user.id,
            scmEventId: null,
            scmDeliveryId: null,
            scmEventKind: null,
            triggerType: "manual",
            triggerKey: "manual",
            idempotencyKey: `retry:${rand()}`,
            ...extra,
          }),
        );
      rej(p, "a retry of another tenant's execution", await retry(bee.execution), FK);
      rej(
        p,
        "a retry of another pipeline's execution (same tenant)",
        await retry(other.execution),
        FK,
      );
      rej(p, "a retry of an execution that does not exist", await retry({ id: bogusId }), FK);
      mustAccept(p, "a retry of an execution of its own pipeline", await retry(e));
      rej(
        p,
        "a retry without the person who asked (CHECK)",
        await retry(e, { requestedByUserId: null }),
        "executions_requested_by_check",
      );
      return p;
    },
  },
  {
    id: "EXECDB-014",
    name: "children of finished executions and history: rows cannot be added for a terminal execution, terminal tasks and closed attempts are immutable, results, items and events are insert-only, nothing can be truncated, and a referenced execution cannot be deleted",
    async run(c) {
      const p = [];
      const { db, A } = c;
      const { execution } = await queuedExecution(c, A, 0);
      await driveExecution(db, execution.id, "running");
      const e = await db.execution.findUnique({ where: { id: execution.id } });
      // controls first: everything is accepted while the execution runs
      const task = await runningTask(c, e, "sca");
      const lateTask = await db.scanTask.create({
        data: taskData(e, "sbom", { status: "pending" }),
      });
      mustAccept(
        p,
        "an attempt while running",
        await attempt(() => db.scanTaskAttempt.create({ data: attemptData(task) })),
      );
      const result = await db.scanResult.create({ data: resultData(task) });
      mustAccept(
        p,
        "an item while running",
        await attempt(() => db.scanResultItem.create({ data: itemData(result) })),
      );
      mustAccept(
        p,
        "an event while running",
        await attempt(() => db.executionEvent.create({ data: eventData(e) })),
      );
      // insert-only tables
      rej(
        p,
        "UPDATE of a result",
        await attempt(() =>
          db.scanResult.update({ where: { id: result.id }, data: { itemCount: 9 } }),
        ),
        "insert-only",
      );
      rej(
        p,
        "UPDATE of an item",
        await attempt(() =>
          db.scanResultItem.updateMany({
            where: { scanResultId: result.id },
            data: { severity: "high" },
          }),
        ),
        "insert-only",
      );
      const ev = await db.executionEvent.findFirst({
        where: { executionId: e.id, type: "recovered" },
      });
      rej(
        p,
        "UPDATE of an event",
        await attempt(() =>
          db.executionEvent.update({ where: { id: ev.id }, data: { reason: "rewritten" } }),
        ),
        "insert-only",
      );
      // closing an attempt once
      rej(
        p,
        "closing an attempt as running again",
        await attempt(() =>
          db.scanTaskAttempt.updateMany({
            where: { scanTaskId: task.id },
            data: { errorCode: "x" },
          }),
        ),
        "only closing|cannot|not allowed",
      );
      mustAccept(
        p,
        "closing the attempt",
        await attempt(() =>
          db.scanTaskAttempt.updateMany({
            where: { scanTaskId: task.id },
            data: { status: "succeeded", finishedAt: new Date(), durationMs: 5 },
          }),
        ),
      );
      rej(
        p,
        "changing a closed attempt",
        await attempt(() =>
          db.scanTaskAttempt.updateMany({
            where: { scanTaskId: task.id },
            data: { status: "failed" },
          }),
        ),
        "closed",
      );
      // task machine and terminal tasks
      rej(
        p,
        "task pending -> succeeded (not a transition)",
        await attempt(() =>
          db.scanTask.update({ where: { id: lateTask.id }, data: { status: "succeeded" } }),
        ),
        "not allowed",
      );
      mustAccept(
        p,
        "task running -> succeeded",
        await attempt(() =>
          db.scanTask.update({
            where: { id: task.id },
            data: {
              status: "succeeded",
              leaseOwner: null,
              leaseExpiresAt: null,
              heartbeatAt: null,
            },
          }),
        ),
      );
      rej(
        p,
        "UPDATE of a terminal task",
        await attempt(() => db.scanTask.update({ where: { id: task.id }, data: { ordinal: 5 } })),
        "terminal",
      );
      rej(
        p,
        "a task identity change",
        await attempt(() =>
          db.scanTask.update({ where: { id: lateTask.id }, data: { engineId: "other" } }),
        ),
        "lifecycle columns",
      );
      // the execution ends
      await driveExecution(db, e.id, "failed");
      const events = await eventCount(db, e.id);
      const done = await db.execution.findUnique({ where: { id: e.id } });
      rej(
        p,
        "a task for a terminal execution",
        await attempt(() => db.scanTask.create({ data: taskData(done, "secrets") })),
        "terminal",
      );
      rej(
        p,
        "an event for a terminal execution",
        await attempt(() => db.executionEvent.create({ data: eventData(done) })),
        "terminal",
      );
      rej(
        p,
        "a forged second transition event for the terminal status",
        await attempt(() =>
          db.executionEvent.create({
            data: eventData(done, {
              type: "transition",
              fromStatus: "running",
              toStatus: "failed",
              reason: "suite_fixture",
            }),
          }),
        ),
        "terminal",
      );
      if ((await eventCount(db, e.id)) !== events)
        p.push("events were added for a terminal execution");
      const x2 = await queuedExecution(c, A, 1);
      await driveExecution(db, x2.execution.id, "running");
      const t2 = await runningTask(
        c,
        await db.execution.findUnique({ where: { id: x2.execution.id } }),
        "sast",
      );
      await driveExecution(db, t2.executionId, "timed_out");
      rej(
        p,
        "a result for a task of a terminal execution",
        await attempt(() => db.scanResult.create({ data: resultData(t2) })),
        "terminal",
      );
      rej(
        p,
        "an item for a terminal execution",
        await attempt(() =>
          db.scanResultItem.create({
            data: itemData(result, { ordinal: 7, executionId: result.executionId }),
          }),
        ),
        "terminal",
      );
      // truncate and delete
      for (const table of [
        "executions",
        "execution_events",
        "scan_tasks",
        "scan_task_attempts",
        "scan_results",
        "scan_result_items",
      ])
        rej(
          p,
          `TRUNCATE ${table}`,
          await probe(db, (tx) => tx.$executeRawUnsafe(`TRUNCATE TABLE "${table}" CASCADE`)),
          "not allowed",
        );
      rej(
        p,
        "deleting an execution that has history (RESTRICT)",
        await attempt(() => db.execution.delete({ where: { id: e.id } })),
        "23001",
      );
      const bare = (await queuedExecution(c, A, 0)).execution;
      mustAccept(
        p,
        "deleting an execution without history (the retention purge is not blocked by the guard)",
        await attempt(() => db.execution.delete({ where: { id: bare.id } })),
      );
      return p;
    },
  },
  {
    id: "EXECDB-015",
    name: "lease, fence and marker integrity: lease epochs only grow by one and never on a terminal row, terminal rows hold no lease, lease columns come together, a renewal never moves time backwards, the claim must increase the epoch, results and attempts of a superseded attempt or a non-running task are refused, and the orchestrator marker is set-once, undeletable and has no tenant column",
    async run(c) {
      const p = [];
      const { db, A } = c;
      const { execution } = await queuedExecution(c, A, 0);
      const id = execution.id;
      // the claim must raise the epoch by one
      const claim = moveSet("queued", "preparing");
      rej(
        p,
        "a claim that keeps the epoch",
        await upd(
          db,
          id,
          claim.replace("lease_epoch = lease_epoch + 1", "lease_epoch = lease_epoch"),
        ),
        "lease_epoch",
      );
      rej(
        p,
        "a claim that skips an epoch",
        await upd(
          db,
          id,
          claim.replace("lease_epoch = lease_epoch + 1", "lease_epoch = lease_epoch + 2"),
        ),
        "lease_epoch",
      );
      rej(
        p,
        "a claim without a deadline",
        await upd(
          db,
          id,
          claim.replace("deadline_at = now() + interval '30 minutes'", "deadline_at = NULL"),
        ),
        "deadline",
      );
      rej(
        p,
        "a claim without a lease (CHECK: preparing holds a lease)",
        await upd(
          db,
          id,
          "status = 'preparing', claimed_at = now(), deadline_at = now() + interval '1 hour', lease_epoch = lease_epoch + 1",
        ),
        "executions_lease_check",
      );
      mustAccept(p, "the legitimate claim", await upd(db, id, claim));
      const held = await db.execution.findUnique({ where: { id } });
      if (held.leaseEpoch !== 1) p.push(`the claim left lease_epoch ${held.leaseEpoch}`);
      // renewal and reclaim
      mustAccept(
        p,
        "a renewal (later expiry and heartbeat)",
        await upd(db, id, "heartbeat_at = now(), lease_expires_at = now() + interval '10 minutes'"),
      );
      rej(
        p,
        "a renewal that moves the expiry backwards",
        await upd(db, id, "lease_expires_at = now() + interval '1 minute'"),
        "backwards",
      );
      rej(
        p,
        "a renewal that moves the heartbeat backwards",
        await upd(db, id, "heartbeat_at = now() - interval '1 hour'"),
        "backwards",
      );
      rej(
        p,
        "lease_owner without an expiry and a heartbeat",
        await upd(db, id, "lease_expires_at = NULL, heartbeat_at = NULL"),
        "executions_lease_check",
      );
      rej(
        p,
        "an expiry without an owner",
        await upd(db, id, "lease_owner = NULL"),
        "executions_lease_check",
      );
      rej(p, "a decreasing epoch", await upd(db, id, "lease_epoch = 0"), "lease_epoch");
      rej(p, "a skipped epoch", await upd(db, id, "lease_epoch = lease_epoch + 2"), "lease_epoch");
      mustAccept(
        p,
        "a reclaim (epoch + 1, new owner)",
        await upd(
          db,
          id,
          "lease_owner = 'suite-other', lease_epoch = lease_epoch + 1, heartbeat_at = now(), lease_expires_at = now() + interval '20 minutes'",
        ),
      );
      if ((await db.execution.findUnique({ where: { id } })).leaseEpoch !== 2)
        p.push("the reclaim did not leave epoch 2");
      // ending the execution
      const wholeEnd = "status = 'failed', status_reason = 'suite_reason'";
      rej(
        p,
        "ending the execution without clearing the lease",
        await upd(db, id, wholeEnd),
        "holds no lease",
      );
      rej(
        p,
        "ending the execution with only the owner cleared",
        await upd(db, id, wholeEnd + ", lease_owner = NULL"),
        "executions_lease_check|holds no lease",
      );
      rej(
        p,
        "ending the execution while changing the epoch",
        await upd(
          db,
          id,
          wholeEnd +
            ", lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL, lease_epoch = lease_epoch + 1",
        ),
        "lease_epoch is kept",
      );
      mustAccept(
        p,
        "ending the execution with the lease cleared and the epoch kept",
        await upd(
          db,
          id,
          wholeEnd + ", lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL",
        ),
      );
      const ended = await db.execution.findUnique({ where: { id } });
      if (ended.leaseEpoch !== 2 || ended.leaseOwner)
        p.push("the terminal row lost its epoch or kept its lease");
      rej(
        p,
        "a queued row holding a lease (CHECK)",
        await upd(
          db,
          (await queuedExecution(c, A, 0)).execution.id,
          "lease_owner = 'x', lease_expires_at = now(), heartbeat_at = now()",
        ),
        "executions_lease_check",
      );

      // the attempt fence: results and attempts exist only for the task's CURRENT RUNNING attempt
      const run = await queuedExecution(c, A, 0);
      await driveExecution(db, run.execution.id, "running");
      const e = await db.execution.findUnique({ where: { id: run.execution.id } });
      const task = await runningTask(c, e, "sca");
      mustAccept(
        p,
        "an attempt for the current attempt of a running task",
        await attempt(() => db.scanTaskAttempt.create({ data: attemptData(task) })),
      );
      rej(
        p,
        "an attempt number that is not the task's",
        await attempt(() => db.scanTaskAttempt.create({ data: attemptData(task, { attempt: 1 }) })),
        "not the running attempt",
      );
      // a reclaim of the task raises its attempt: the old attempt is now a zombie
      mustAccept(
        p,
        "the task attempt grows on a reclaim",
        await attempt(() => db.scanTask.update({ where: { id: task.id }, data: { attempt: 1 } })),
      );
      rej(
        p,
        "the task attempt cannot skip",
        await attempt(() => db.scanTask.update({ where: { id: task.id }, data: { attempt: 3 } })),
        "attempt|check",
      );
      rej(
        p,
        "the zombie's result (old attempt 0)",
        await attempt(() => db.scanResult.create({ data: resultData(task, { attempt: 0 }) })),
        "not the running attempt",
      );
      rej(
        p,
        "closing the zombie's attempt row",
        await attempt(() =>
          db.scanTaskAttempt.updateMany({
            where: { scanTaskId: task.id, attempt: 0 },
            data: { status: "failed", finishedAt: new Date() },
          }),
        ),
        "not the running attempt",
      );
      mustAccept(
        p,
        "the new holder's result (attempt 1)",
        await attempt(() => db.scanResult.create({ data: resultData(task, { attempt: 1 }) })),
      );
      rej(
        p,
        "a second result for the same task",
        await attempt(() => db.scanResult.create({ data: resultData(task, { attempt: 1 }) })),
        "P2002",
      );
      const queuedTask = await db.scanTask.create({ data: taskData(e, "secrets") });
      rej(
        p,
        "a result for a task that is not running",
        await attempt(() =>
          db.scanResult.create({ data: resultData(queuedTask, { scanType: "secrets" }) }),
        ),
        "not the running attempt",
      );
      const sbomTask = await runningTask(c, e, "sbom");
      rej(
        p,
        "a result whose scan type differs from the task's",
        await attempt(() =>
          db.scanResult.create({ data: resultData(sbomTask, { scanType: "sast" }) }),
        ),
        "scan type",
      );
      rej(
        p,
        "a retry attempt beyond max_attempts",
        await attempt(() => db.scanTask.update({ where: { id: task.id }, data: { attempt: 2 } })),
        "attempt|check",
      );

      // the orchestrator marker
      const key = `suite.marker.${letters(8)}`;
      const marker = () => db.executionOrchestratorMarker.findUnique({ where: { markerKey: key } });
      const mu = (set) =>
        attempt(() =>
          db.$executeRawUnsafe(
            `UPDATE execution_orchestrator_markers SET ${set} WHERE marker_key = $1`,
            key,
          ),
        );
      try {
        mustAccept(
          p,
          "inserting the marker",
          await attempt(() =>
            db.executionOrchestratorMarker.create({
              data: { markerKey: key, firstEnabledAt: new Date() },
            }),
          ),
        );
        rej(
          p,
          "a second marker with the same key",
          await attempt(() =>
            db.executionOrchestratorMarker.create({
              data: { markerKey: key, firstEnabledAt: new Date() },
            }),
          ),
          "P2002",
        );
        rej(
          p,
          "changing first_enabled_at",
          await mu("first_enabled_at = now() + interval '1 day'"),
          "set once",
        );
        rej(
          p,
          "completing a sweep that never started",
          await mu("sweep_completed_at = now()"),
          "executions|violates check|execution_orchestrator_markers_check",
        );
        mustAccept(
          p,
          "starting the sweep",
          await mu(
            "sweep_started_at = now(), sweep_lease_owner = 'suite', sweep_lease_expires_at = now() + interval '1 minute'",
          ),
        );
        rej(
          p,
          "moving sweep_started_at",
          await mu("sweep_started_at = now() + interval '1 hour'"),
          "set once",
        );
        rej(
          p,
          "a decreasing swept_count after progress",
          await (async () => {
            await mu("swept_count = 5");
            return mu("swept_count = 4");
          })(),
          "only grows",
        );
        mustAccept(
          p,
          "completing the sweep",
          await mu(
            "sweep_completed_at = now(), sweep_lease_owner = NULL, sweep_lease_expires_at = NULL",
          ),
        );
        rej(
          p,
          "completing the sweep again / any change after completion",
          await mu("sweep_completed_at = now() + interval '1 hour'"),
          "completed",
        );
        rej(p, "changing swept_count after completion", await mu("swept_count = 9"), "completed");
        rej(
          p,
          "DELETE of the marker",
          await attempt(() => db.executionOrchestratorMarker.delete({ where: { markerKey: key } })),
          "permanent",
        );
        rej(
          p,
          "TRUNCATE of the markers",
          await probe(db, (tx) =>
            tx.$executeRawUnsafe('TRUNCATE TABLE "execution_orchestrator_markers"'),
          ),
          "not allowed",
        );
        if (!(await marker())?.sweepCompletedAt) p.push("the completed marker did not survive");
        const cols =
          await db.$queryRaw`SELECT column_name FROM information_schema.columns WHERE table_name = 'execution_orchestrator_markers'`;
        if (cols.some((r) => /tenant/.test(r.column_name)))
          p.push("the marker table has a tenant column");
      } finally {
        // the marker is permanent by design; the disposable database may drop the suite's own rows so later checks start clean
        await db.$transaction(async (tx) => {
          await tx.$executeRawUnsafe(
            'ALTER TABLE "execution_orchestrator_markers" DISABLE TRIGGER "execution_orchestrator_markers_guard"',
          );
          await tx.$executeRawUnsafe(
            `DELETE FROM "execution_orchestrator_markers" WHERE marker_key LIKE 'suite.marker.%'`,
          );
          await tx.$executeRawUnsafe(
            'ALTER TABLE "execution_orchestrator_markers" ENABLE TRIGGER "execution_orchestrator_markers_guard"',
          );
        });
      }
      return p;
    },
  },
  {
    id: "EXECDB-016",
    name: "claim helper: any number of parallel claims of one queued execution has exactly one winner (lease epoch 1, one transition event), another tenant's id claims nothing, a request older than the stale threshold is never claimed, the peek returns identifiers only",
    async run(c) {
      const p = [];
      const { db, A, B, repo } = c;
      const { execution } = await queuedExecution(c, A, 0);
      const args = (tenantId, executionId, workerId, over = {}) => ({
        tenantId,
        executionId,
        workerId,
        leaseTtlSeconds: 60,
        deadlineSeconds: 1800,
        staleThresholdSeconds: 86400,
        ...over,
      });
      // control: the peek sees it and returns ids only
      const peek = await repo.peekQueued({ limit: 10000, maxPerTenant: 10000 });
      const seen = peek.find((r) => r.id === execution.id);
      if (!seen) p.push("control failed: peekQueued did not return the queued execution");
      else if (Object.keys(seen).sort().join() !== "id,requestedAt,tenantId")
        p.push(`peekQueued returned ${Object.keys(seen).join(",")}`);
      const capped = await repo.peekQueued({ limit: 500, maxPerTenant: 1 });
      if (capped.filter((r) => r.tenantId === A.tenant.id).length > 1)
        p.push("maxPerTenant was not honoured");
      // another tenant's id and a wrong tenant claim nothing
      if ((await repo.claimQueued(args(B.tenant.id, execution.id, "intruder"))) !== null)
        p.push("a claim with another tenant's id succeeded");
      if ((await db.execution.findUnique({ where: { id: execution.id } })).status !== "queued")
        p.push("the execution left queued under a foreign tenant claim");
      // K parallel claims: one winner
      const results = await Promise.all(
        Array.from({ length: 10 }, (_, i) =>
          repo.claimQueued(args(A.tenant.id, execution.id, `w${i}`)),
        ),
      );
      const winners = results.filter(Boolean);
      if (winners.length !== 1) p.push(`${winners.length} claim winners instead of 1`);
      else if (
        winners[0].leaseEpoch !== 1 ||
        winners[0].status !== "preparing" ||
        !winners[0].deadlineAt ||
        !winners[0].leaseExpiresAt
      )
        p.push("the winner's row is not a fresh lease");
      const events = await db.executionEvent.findMany({ where: { executionId: execution.id } });
      if (events.length !== 1 || events[0].toStatus !== "preparing")
        p.push(`${events.length} events after the claim`);
      if ((await repo.claimQueued(args(A.tenant.id, execution.id, "late"))) !== null)
        p.push("a second claim after the first succeeded");
      // stale: older than the threshold is never claimed (the CAS itself refuses it); just under it is
      const old = await queuedExecution(c, A, 0, {
        requestedAt: new Date(Date.now() - 2 * 86400 * 1000),
      });
      if ((await repo.claimQueued(args(A.tenant.id, old.execution.id, "w"))) !== null)
        p.push("a stale request (older than the threshold) was claimed");
      if ((await db.execution.findUnique({ where: { id: old.execution.id } })).status !== "queued")
        p.push("the stale request left queued");
      const young = await queuedExecution(c, A, 0, {
        requestedAt: new Date(Date.now() - 23 * 3600 * 1000),
      });
      if (!(await repo.claimQueued(args(A.tenant.id, young.execution.id, "w"))))
        p.push("control failed: a request just under the threshold was not claimed");
      if ((await repo.claimQueued(args(A.tenant.id, bogusId, "w"))) !== null)
        p.push("an unknown id was claimed");
      return p;
    },
  },
  {
    id: "EXECDB-017",
    name: "lease helpers: a renewal by the holder extends the lease without a transition, a live lease cannot be reclaimed, parallel reclaimers of an expired lease have exactly one winner (epoch + 1, one recovered event), the stale epoch reclaims nothing, and the zombie holder is rejected everywhere (renew, transition, fence, event)",
    async run(c) {
      const p = [];
      const { db, A, B, repo } = c;
      const base = (execution, workerId, over = {}) => ({
        tenantId: A.tenant.id,
        executionId: execution.id,
        workerId,
        leaseTtlSeconds: 60,
        ...over,
      });
      const claim = (execution, workerId, ttl) =>
        repo.claimQueued({
          ...base(execution, workerId),
          leaseTtlSeconds: ttl,
          deadlineSeconds: 1800,
          staleThresholdSeconds: 86400,
        });
      const { execution } = await queuedExecution(c, A, 0);
      const first = await claim(execution, "holder-1", 60);
      if (!first) return ["control failed: the claim did not succeed"];
      // renewal
      const before = await db.execution.findUnique({ where: { id: execution.id } });
      const renewed = await repo.renewLease({
        ...base(execution, "holder-1"),
        leaseEpoch: 1,
        leaseTtlSeconds: 120,
      });
      const after = await db.execution.findUnique({ where: { id: execution.id } });
      if (!renewed.renewed || !(after.leaseExpiresAt > before.leaseExpiresAt))
        p.push("control failed: the holder's renewal did not extend the lease");
      if (
        after.statusRev !== before.statusRev ||
        after.leaseEpoch !== before.leaseEpoch ||
        (await eventCount(db, execution.id)) !== 1
      )
        p.push("a renewal changed status_rev, the epoch or the history");
      if ((await repo.renewLease({ ...base(execution, "someone-else"), leaseEpoch: 1 })).renewed)
        p.push("a renewal by another owner succeeded");
      if ((await repo.renewLease({ ...base(execution, "holder-1"), leaseEpoch: 0 })).renewed)
        p.push("a renewal with a stale epoch succeeded");
      if (
        (
          await repo.renewLease({
            ...base(execution, "holder-1"),
            tenantId: B.tenant.id,
            leaseEpoch: 1,
          })
        ).renewed
      )
        p.push("a renewal with another tenant's id succeeded");
      // a live lease cannot be reclaimed
      if (await repo.reclaimLease({ ...base(execution, "thief"), observedEpoch: 1 }))
        p.push("a live lease was reclaimed");
      if ((await repo.peekExpiredLeases({ limit: 5000 })).some((r) => r.id === execution.id))
        p.push("a live lease is listed as expired");

      // an expired lease: the holder simply stops renewing (0.4 s lease, no edit of the columns)
      const dead = (await queuedExecution(c, A, 0)).execution;
      await claim(dead, "zombie", 0.4);
      await new Promise((r) => setTimeout(r, 700));
      const expired = (await repo.peekExpiredLeases({ limit: 5000 })).find((r) => r.id === dead.id);
      if (!expired) return [...p, "control failed: the expired lease was not listed"];
      if (Object.keys(expired).sort().join() !== "id,leaseEpoch,tenantId")
        p.push(`peekExpiredLeases returned ${Object.keys(expired).join(",")}`);
      const foreign = await Promise.all(
        Array.from({ length: 3 }, (_, i) =>
          repo.reclaimLease({
            ...base(dead, `x${i}`),
            tenantId: B.tenant.id,
            observedEpoch: expired.leaseEpoch,
          }),
        ),
      );
      if (foreign.some(Boolean)) p.push("a reclaim with another tenant's id succeeded");
      const racers = await Promise.all(
        Array.from({ length: 10 }, (_, i) =>
          repo.reclaimLease({
            ...base(dead, `r${i}`),
            observedEpoch: expired.leaseEpoch,
            leaseTtlSeconds: 0.3, // the winner's lease expires again, so a STALE observed epoch is tested against an expired lease
            event: { details: { step: "suite" } },
          }),
        ),
      );
      const won = racers.filter(Boolean);
      if (won.length !== 1) p.push(`${won.length} reclaim winners instead of 1`);
      const row = await db.execution.findUnique({ where: { id: dead.id } });
      if (row.leaseEpoch !== expired.leaseEpoch + 1)
        p.push(`the epoch is ${row.leaseEpoch}, expected ${expired.leaseEpoch + 1}`);
      const recovered = await eventCount(db, dead.id, "AND type = 'recovered'");
      if (recovered !== 1) p.push(`${recovered} recovered events instead of 1`);
      await new Promise((r) => setTimeout(r, 600));
      if (await repo.reclaimLease({ ...base(dead, "late"), observedEpoch: expired.leaseEpoch }))
        p.push("the stale observed epoch reclaimed an expired lease of a later epoch");
      const second = await repo.reclaimLease({
        ...base(dead, "holder-3"),
        observedEpoch: expired.leaseEpoch + 1,
      });
      if (!second || second.leaseEpoch !== expired.leaseEpoch + 2)
        p.push("control failed: the current observed epoch could not reclaim the expired lease");
      // the zombie holders (epochs 1 and 2) are rejected after the reclaims, the new holder (epoch 3) is not
      const stateBefore = await shape(db, dead.id);
      const eventsBefore = await eventCount(db, dead.id);
      if ((await repo.renewLease({ ...base(dead, "zombie"), leaseEpoch: 1 })).renewed)
        p.push("the zombie renewed its lease");
      const zt = await repo.transitionExecution({
        tenantId: A.tenant.id,
        executionId: dead.id,
        from: "preparing",
        to: "running",
        leaseEpoch: 1,
      });
      if (zt.transitioned) p.push("the zombie's status transition succeeded");
      const zc = await repo.transitionExecution({
        tenantId: A.tenant.id,
        executionId: dead.id,
        from: "preparing",
        to: "failed",
        reason: "worker_lost",
        leaseEpoch: 1,
        releaseQuota: true,
      });
      if (zc.transitioned || zc.quotaReleased) p.push("the zombie's terminal transition succeeded");
      await db
        .$transaction(async (tx) => {
          await repo.fenceExecution(
            { tenantId: A.tenant.id, executionId: dead.id, leaseEpoch: 1 },
            tx,
          );
        })
        .then(
          () => p.push("the zombie passed the write fence"),
          (error) => {
            if (!(error instanceof LeaseLostError))
              p.push(`the fence threw ${error.name}, not LeaseLostError`);
          },
        );
      await repo
        .recordEvent({
          tenantId: A.tenant.id,
          executionId: dead.id,
          type: "limit_deferred",
          leaseEpoch: 1,
        })
        .then(
          () => p.push("the zombie wrote an event"),
          (error) => {
            if (!(error instanceof LeaseLostError))
              p.push(`the event write threw ${error.name}, not LeaseLostError`);
          },
        );
      if (
        (await shape(db, dead.id)) !== stateBefore ||
        (await eventCount(db, dead.id)) !== eventsBefore
      )
        p.push("the zombie's attempts changed the execution or its history");
      await db
        .$transaction((tx) =>
          repo.fenceExecution({ tenantId: A.tenant.id, executionId: dead.id, leaseEpoch: 3 }, tx),
        )
        .catch(() => p.push("control failed: the new holder was refused by the fence"));
      const ok = await repo.transitionExecution({
        tenantId: A.tenant.id,
        executionId: dead.id,
        from: "preparing",
        to: "running",
        leaseEpoch: 3,
      });
      if (!ok.transitioned) p.push("control failed: the new holder's transition did not succeed");
      if ((await eventCount(db, dead.id, "AND type = 'recovered'")) !== 1)
        p.push("a second recovered event appeared");
      // tenant B's executions are untouched by A's reclaimers
      const bee = (await queuedExecution(c, B, 0)).execution;
      await repo.claimQueued({
        tenantId: B.tenant.id,
        executionId: bee.id,
        workerId: "b",
        leaseTtlSeconds: 0.4,
        deadlineSeconds: 60,
        staleThresholdSeconds: 86400,
      });
      await new Promise((r) => setTimeout(r, 700));
      const bBefore = await shape(db, bee.id);
      await repo.reclaimLease({ ...base(bee, "a-reclaimer"), observedEpoch: 1 });
      if ((await shape(db, bee.id)) !== bBefore)
        p.push("tenant A's reclaimer changed tenant B's execution");
      return p;
    },
  },
  {
    id: "EXECDB-018",
    name: "quota is released exactly once: of racing terminal transitions one wins and gives the stored unit back (quota_released_at set once, usage falls by exactly the consumed amount), a loser or a zombie releases nothing, running endings and preparing timeouts never release, another tenant's usage is untouched",
    async run(c) {
      const p = [];
      const { db, A, B, repo } = c;
      const def = await db.quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
      if (!def) return ["control failed: the scans.monthly quota definition is missing"];
      const usage = async (tree, period) =>
        Number(
          (
            await db.tenantQuotaUsage.findFirst({
              where: { tenantId: tree.tenant.id, quotaDefinitionId: def.id, periodKey: period },
            })
          )?.used ?? 0,
        );
      const setUsage = (tree, period, used) =>
        db.tenantQuotaUsage.upsert({
          where: {
            tenantId_quotaDefinitionId_periodKey: {
              tenantId: tree.tenant.id,
              quotaDefinitionId: def.id,
              periodKey: period,
            },
          },
          create: {
            tenantId: tree.tenant.id,
            quotaDefinitionId: def.id,
            periodKey: period,
            used: BigInt(used),
          },
          update: { used: BigInt(used) },
        });
      const period = "2026-11";
      await setUsage(A, period, 5);
      await setUsage(A, "2026-10", 7);
      await setUsage(B, period, 9);
      const consumed = (extra = {}) =>
        queuedExecution(c, A, 0, { quotaPeriod: period, quotaConsumed: 1, ...extra }).then(
          (x) => x.execution,
        );
      const cancel = (e, over = {}) =>
        repo.transitionExecution({
          tenantId: A.tenant.id,
          executionId: e.id,
          from: "queued",
          to: "cancelled",
          reason: "user_cancelled",
          releaseQuota: true,
          ...over,
        });

      // a queued cancel: N racers plus a claim, one outcome
      const e = await consumed();
      const racers = await Promise.all([
        ...Array.from({ length: 8 }, () => cancel(e)),
        repo.claimQueued({
          tenantId: A.tenant.id,
          executionId: e.id,
          workerId: "w",
          leaseTtlSeconds: 60,
          deadlineSeconds: 60,
          staleThresholdSeconds: 86400,
        }),
      ]);
      const cancelWins = racers.slice(0, 8).filter((r) => r.transitioned).length;
      const claimWon = Boolean(racers[8]);
      const row = await db.execution.findUnique({ where: { id: e.id } });
      if (cancelWins + (claimWon ? 1 : 0) !== 1)
        p.push(
          `${cancelWins} cancels and ${claimWon ? 1 : 0} claim won; exactly one outcome expected`,
        );
      if (cancelWins === 1) {
        if (!row.quotaReleasedAt || row.status !== "cancelled")
          p.push("the winning cancel left no quota_released_at");
        if ((await usage(A, period)) !== 4)
          p.push(`usage is ${await usage(A, period)}, expected 4 (one unit back, once)`);
        if (racers.slice(0, 8).filter((r) => r.quotaReleased).length !== 1)
          p.push("more than one racer reported a release");
      } else if ((await usage(A, period)) !== 5) p.push("the claim won but quota changed");
      // a repeated cancel of the finished execution releases nothing
      const again = await cancel(e);
      if (
        again.transitioned ||
        again.quotaReleased ||
        (await usage(A, period)) !== (cancelWins === 1 ? 4 : 5)
      )
        p.push("a repeated cancel changed the quota");
      // control: a single cancel releases one unit of ITS OWN stored period (not the current one)
      const old = await consumed({ quotaPeriod: "2026-10" });
      const u0 = await usage(A, "2026-10");
      const cu = await cancel(old);
      if (!cu.transitioned || !cu.quotaReleased || (await usage(A, "2026-10")) !== u0 - 1)
        p.push("control failed: a single cancel did not return one unit of the stored period");
      if ((await usage(B, period)) !== 9) p.push("tenant B's usage changed");
      // no unit consumed: transition succeeds, nothing is released
      const free = (await queuedExecution(c, A, 0)).execution;
      const u1 = await usage(A, period);
      const cf = await cancel(free);
      if (!cf.transitioned || cf.quotaReleased || (await usage(A, period)) !== u1)
        p.push("an execution without a consumed unit released quota");
      // transitions that never refund are refused before anything is written
      const run = await consumed();
      await driveExecution(db, run.id, "running");
      const u2 = await usage(A, period);
      for (const [from, to, leaseEpoch] of [
        ["running", "cancelled", 1],
        ["running", "succeeded", 1],
        ["running", "failed", 1],
      ])
        await repo
          .transitionExecution({
            tenantId: A.tenant.id,
            executionId: run.id,
            from,
            to,
            reason: to === "succeeded" ? null : "x",
            leaseEpoch,
            releaseQuota: true,
          })
          .then(
            () => p.push(`${from} -> ${to} accepted releaseQuota`),
            (error) => {
              if (!(error instanceof TypeError)) p.push(`${from} -> ${to}: ${error.name}`);
            },
          );
      const ended = await repo.transitionExecution({
        tenantId: A.tenant.id,
        executionId: run.id,
        from: "running",
        to: "cancelled",
        reason: "user_cancelled",
        leaseEpoch: 1,
      });
      if (!ended.transitioned || ended.quotaReleased || (await usage(A, period)) !== u2)
        p.push("a running execution that ended released quota");
      // preparing -> failed releases once (platform-caused), the zombie after a reclaim does not
      const prep = await consumed();
      await repo.claimQueued({
        tenantId: A.tenant.id,
        executionId: prep.id,
        workerId: "w",
        leaseTtlSeconds: 60,
        deadlineSeconds: 60,
        staleThresholdSeconds: 86400,
      });
      const u3 = await usage(A, period);
      const stale = await repo.transitionExecution({
        tenantId: A.tenant.id,
        executionId: prep.id,
        from: "preparing",
        to: "failed",
        reason: "prepare_failed:storage",
        leaseEpoch: 0,
        releaseQuota: true,
      });
      if (stale.transitioned || (await usage(A, period)) !== u3)
        p.push("a transition with a stale epoch released quota");
      const fin = await Promise.all(
        Array.from({ length: 5 }, () =>
          repo.transitionExecution({
            tenantId: A.tenant.id,
            executionId: prep.id,
            from: "preparing",
            to: "failed",
            reason: "prepare_failed:storage",
            leaseEpoch: 1,
            releaseQuota: true,
          }),
        ),
      );
      if (fin.filter((r) => r.transitioned).length !== 1 || (await usage(A, period)) !== u3 - 1)
        p.push("preparing -> failed did not release exactly once");
      // never below the value before the request
      const wrong = await repo.transitionExecution({
        tenantId: B.tenant.id,
        executionId: (await consumed()).id,
        from: "queued",
        to: "cancelled",
        reason: "user_cancelled",
        releaseQuota: true,
      });
      if (wrong.transitioned || (await usage(B, period)) !== 9)
        p.push("another tenant's id cancelled or released");
      return p;
    },
  },
  {
    id: "EXECDB-019",
    name: "scan task status unsupported (SPEC executions §17.ab): pending -> unsupported and queued -> unsupported are the only ways in (reason engine_not_registered required, nothing else accepted, finished_at set, status_rev bumped), running -> unsupported and every way out are refused, a task cannot be inserted unsupported or hold a lease while unsupported, and no attempt or result can ever be written for it",
    async run(c) {
      const p = [];
      const { db, A } = c;
      const { execution } = await queuedExecution(c, A, 0);
      await driveExecution(db, execution.id, "running");
      const e = await db.execution.findUnique({ where: { id: execution.id } });
      const mark = (id, over = {}) =>
        attempt(() =>
          db.scanTask.update({
            where: { id },
            data: { status: "unsupported", statusReason: "engine_not_registered", ...over },
          }),
        );
      const pending = await db.scanTask.create({ data: taskData(e, "sca", { status: "pending" }) });
      const queued = await db.scanTask.create({ data: taskData(e, "sast", { status: "queued" }) });
      const strict = await db.scanTask.create({ data: taskData(e, "sbom", { status: "pending" }) });
      const running = await runningTask(c, e, "secrets");
      // refusals first (each is paired with the control below that marks the same kind of row legitimately)
      rej(p, "running -> unsupported", await mark(running.id), "not allowed");
      rej(
        p,
        "unsupported without a reason",
        await mark(strict.id, { statusReason: null }),
        "scan_tasks_status_reason_check",
      );
      rej(
        p,
        "unsupported with another reason",
        await mark(strict.id, { statusReason: "engine_failed" }),
        "scan_tasks_status_reason_check",
      );
      rej(
        p,
        "unsupported holding a lease",
        await mark(strict.id, {
          leaseOwner: "w",
          leaseExpiresAt: new Date(Date.now() + 60000),
          heartbeatAt: new Date(),
        }),
        "scan_tasks_lease_check",
      );
      const fresh = await queuedExecution(c, A, 0);
      for (const [label, create] of [
        ["create", (data) => db.scanTask.create({ data })],
        ["createMany", (data) => db.scanTask.createMany({ data: [data] })],
      ])
        rej(
          p,
          `a task inserted unsupported (${label})`,
          await attempt(() =>
            create(
              taskData(fresh.execution, "sbom", {
                status: "unsupported",
                statusReason: "engine_not_registered",
              }),
            ),
          ),
          "created pending or queued",
        );
      mustAccept(
        p,
        "a task inserted pending in the same execution",
        await attempt(() =>
          db.scanTask.create({ data: taskData(fresh.execution, "sbom", { status: "pending" }) }),
        ),
      );
      // controls: both legal entries
      mustAccept(p, "pending -> unsupported", await mark(pending.id));
      mustAccept(p, "queued -> unsupported", await mark(queued.id));
      for (const t of [pending, queued]) {
        const row = await db.scanTask.findUnique({ where: { id: t.id } });
        if (
          row.status !== "unsupported" ||
          row.statusReason !== "engine_not_registered" ||
          !row.finishedAt ||
          row.statusRev !== 1 ||
          row.attempt !== 0 ||
          row.leaseOwner !== null
        )
          p.push(
            `${t.scanType}: the unsupported task row is not terminal and untouched (${row.status}, rev ${row.statusRev})`,
          );
      }
      // terminal and immutable
      for (const to of ["queued", "running", "cancelled", "skipped", "failed", "pending"])
        rej(
          p,
          `unsupported -> ${to}`,
          await attempt(() =>
            db.scanTask.update({
              where: { id: pending.id },
              data: {
                status: to,
                statusReason: to === "queued" || to === "running" || to === "pending" ? null : "x",
              },
            }),
          ),
          "terminal",
        );
      rej(
        p,
        "a change of a column of an unsupported task",
        await attempt(() =>
          db.scanTask.update({ where: { id: pending.id }, data: { ordinal: 3 } }),
        ),
        "terminal",
      );
      rej(
        p,
        "a change of the reason of an unsupported task",
        await attempt(() =>
          db.scanTask.update({ where: { id: pending.id }, data: { statusReason: "other" } }),
        ),
        "terminal",
      );
      // no attempt, no result for an unsupported task
      rej(
        p,
        "an attempt for an unsupported task",
        await attempt(() => db.scanTaskAttempt.create({ data: attemptData(pending) })),
        "not the running attempt",
      );
      rej(
        p,
        "a result for an unsupported task",
        await attempt(() => db.scanResult.create({ data: resultData(pending) })),
        "not the running attempt",
      );
      // control: the strict row is still markable once the bad variants were refused
      mustAccept(p, "pending -> unsupported after the refusals", await mark(strict.id));
      return p;
    },
  },
];
