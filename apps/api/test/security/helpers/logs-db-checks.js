import { randomBytes } from "node:crypto";
import {
  LeaseLostError,
  createExecutionArtifactRepository,
  createExecutionLogRepository,
} from "@qmentisai/db";
import { createLogStore, createPostgresArtifactStore, findCredentials } from "@qmentisai/infra";
import { attempt, mustAccept } from "./pipeline-db.js";
import { chain, driveExecution, inState, runningTask } from "./execution-db.js";

/**
 * Execution logs and artifacts: database integrity and the stores (ADR-008 area 10, in-process; `EXECDB-020..025`,
 * docs/modules/executions/SPEC.md §7.4, §7.5, §17.ac). The tenant-safe composite keys, the hard ceilings (CHECK and counters),
 * the credential-shape CHECK, the insert-only and terminal guards are exercised with RAW writes (bypassing every store); the
 * LogStore and the Postgres ArtifactStore are then exercised on top: caps with ONE truncation marker per scope, the
 * `truncated` flag, redaction, the lease/attempt fence (a zombie writer writes nothing) and tenant/workspace/task scoping of the
 * reads. Every denial has a control (the same write made legitimately succeeds) so no check passes vacuously.
 */

const rand = (n = 4) => randomBytes(n).toString("hex");
const SMALL = {
  maxLinesPerExecution: 12,
  maxBytesPerExecution: 100000,
  maxLinesPerTask: 8,
  maxBytesPerTask: 50000,
};
const BIG = {
  maxLinesPerExecution: 20000,
  maxBytesPerExecution: 2097152,
  maxLinesPerTask: 10000,
  maxBytesPerTask: 1048576,
};

/** The refusal must come from the named constraint, trigger text or message. */
function rej(p, label, r, needle) {
  if (r.ok) return p.push(`${label}: accepted`);
  if (needle && !r.message.includes(needle))
    p.push(
      `${label}: rejected for another reason (${r.message.trim().split("\n").pop().slice(0, 140)})`,
    );
}

const logRow = (e, over = {}) => ({
  ...chain(e),
  level: "info",
  source: "platform",
  message: "suite line",
  ...over,
});
const insertLog = (db, e, over) => attempt(() => db.executionLog.create({ data: logRow(e, over) }));
const countLogs = (db, id) => db.executionLog.count({ where: { executionId: id } });

/** A running execution of tree `tree` (workspace `i`) with its tenant id. */
async function running(c, tree, i = 0) {
  const e = await inState(c, tree, "running", i);
  return e;
}
const counterOf = (db, e) =>
  db.executionLogCounter.findUnique({
    where: { tenantId_executionId: { tenantId: e.tenantId, executionId: e.id } },
  });
const taskCounterOf = (db, task) =>
  db.executionTaskLogCounter.findUnique({
    where: { tenantId_scanTaskId: { tenantId: task.tenantId, scanTaskId: task.id } },
  });

const storeOf = (db, limits = BIG) =>
  createLogStore({ repository: createExecutionLogRepository({ db }), limits });

export const LOGDB_CHECKS = [
  {
    id: "EXECDB-020",
    name: "execution_logs in the database (SPEC 17.ac): the tenant, workspace, repository, pipeline and execution chain and the task must match their parents (composite keys), seq is assigned by the database whatever the caller sends, level/source/message are validated (2000 characters, no control characters, no line breaks), every credential shape of credential-guard.js is refused by a CHECK even for a raw writer, the per-execution and per-task ceilings are CHECKs on the counters that bind every writer (the refused row leaves no trace), counters never move backwards, rows are insert-only and a terminal execution accepts no line",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      const e = await running(c, A, 0);
      const other = await running(c, A, 1);
      const foreign = await running(c, B, 0);
      const task = await runningTask(c, e, "sca");
      const foreignTask = await runningTask(c, foreign, "sca");

      // controls: a line, a task line; seq and counters follow
      mustAccept(p, "a valid line", await insertLog(db, e, { seq: 999, message: "first" }));
      mustAccept(
        p,
        "a valid task line",
        await insertLog(db, e, { scanTaskId: task.id, source: "scan", message: "from the task" }),
      );
      const lines = await db.executionLog.findMany({
        where: { executionId: e.id },
        orderBy: { seq: "asc" },
      });
      if (lines.map((l) => Number(l.seq)).join() !== "1,2")
        p.push(`seq was not assigned by the database (${lines.map((l) => l.seq)})`);
      const ex = await counterOf(db, e);
      if (ex?.lineCount !== 2 || ex.byteCount !== "first".length + "from the task".length)
        p.push("the execution counter does not follow the inserts");
      const tk = await taskCounterOf(db, task);
      if (tk?.lineCount !== 1) p.push("the task counter does not follow the inserts");

      // composite keys
      rej(
        p,
        "a line with another tenant's id on this execution",
        await insertLog(db, e, { tenantId: B.tenant.id }),
        "Foreign key",
      );
      rej(
        p,
        "a line naming another workspace of the same tenant",
        await insertLog(db, e, { workspaceId: other.workspaceId }),
        "Foreign key",
      );
      rej(
        p,
        "a line naming another pipeline",
        await insertLog(db, e, { pipelineId: other.pipelineId }),
        "Foreign key",
      );
      rej(
        p,
        "a line for a task of another tenant's execution",
        await insertLog(db, e, { scanTaskId: foreignTask.id, source: "scan" }),
        "Foreign key",
      );
      rej(
        p,
        "a line for a task of another execution of the same tenant",
        await insertLog(db, other, { scanTaskId: task.id, source: "scan" }),
        "Foreign key",
      );

      // values
      for (const [label, over] of [
        ["an unknown level", { level: "fatal" }],
        ["an unknown source", { source: "user" }],
        ["an empty message", { message: "" }],
        ["a 2001 character message", { message: "x".repeat(2001) }],
        ["a control character", { message: "bell\u0007here" }],
        ["a line break", { message: "two\nlines" }],
        ["a tab", { message: "tab\there" }],
      ])
        rej(p, label, await insertLog(db, e, over), "execution_logs_values_check");
      const shapes = [
        "token ghp_abcdefghijklmnop1234",
        "installation ghs_ABCDEFGH12345678",
        "github_pat_11ABCDEFG_abcdefgh",
        "Authorization: Bearer abcdefghijkl",
        "-----BEGIN RSA PRIVATE KEY-----",
        "key AKIAABCDEFGHIJKLMNOP",
        "clone https://user:p4ss@github.com/x/y.git",
        "GET /x?access_token=abcdef123",
        "GET /x?sig=abcdef123",
      ];
      for (const message of shapes) {
        const r = await insertLog(db, e, { message });
        rej(
          p,
          `a credential shape (${message.slice(0, 18)})`,
          r,
          "execution_logs_no_credentials_check",
        );
        if (findCredentials(message).length === 0)
          p.push(`fixture ${message.slice(0, 18)} is not a credential shape`);
      }
      for (const message of [
        "ghp_short",
        "Bearer tokens are fine",
        "github.com/x/y",
        "AKIA short",
        "ratio a=1&b=2",
      ])
        mustAccept(p, `a harmless line (${message})`, await insertLog(db, e, { message }));

      // counters never move backwards; the flag is one way; the key and chain are fixed
      const upd = (sql, ...a) => attempt(() => db.$executeRawUnsafe(sql, ...a));
      rej(
        p,
        "lowering a counter",
        await upd(
          `UPDATE execution_log_counters SET line_count = 0 WHERE execution_id = $1::uuid`,
          e.id,
        ),
        "may not lower",
      );
      rej(
        p,
        "moving a counter to another workspace",
        await upd(
          `UPDATE execution_log_counters SET workspace_id = $2::uuid WHERE execution_id = $1::uuid`,
          e.id,
          other.workspaceId,
        ),
        "may only change the counters",
      );
      rej(
        p,
        "dropped lines without the truncated flag",
        await upd(
          `UPDATE execution_log_counters SET dropped_lines = 3 WHERE execution_id = $1::uuid`,
          e.id,
        ),
        "execution_log_counters_caps_check",
      );
      mustAccept(
        p,
        "setting truncated and capped",
        await upd(
          `UPDATE execution_log_counters SET dropped_lines = 3, truncated = true, capped = true WHERE execution_id = $1::uuid`,
          e.id,
        ),
      );
      rej(
        p,
        "clearing capped",
        await upd(
          `UPDATE execution_log_counters SET capped = false WHERE execution_id = $1::uuid`,
          e.id,
        ),
        "may not lower",
      );
      rej(
        p,
        "clearing truncated",
        await upd(
          `UPDATE execution_log_counters SET truncated = false WHERE execution_id = $1::uuid`,
          e.id,
        ),
        "may not lower",
      );

      // insert-only
      rej(
        p,
        "updating a line",
        await upd(
          `UPDATE execution_logs SET message = 'edited' WHERE execution_id = $1::uuid`,
          e.id,
        ),
        "insert-only",
      );
      rej(p, "truncating the table", await upd(`TRUNCATE execution_logs`), "not allowed");

      // ceilings bind every writer (a raw insert, no store): execution lines, execution bytes, task lines, task bytes
      const ceil = async (label, execution, sets, over, needle) => {
        for (const sql of sets) await db.$executeRawUnsafe(sql, execution.id);
        const before = await db.executionLog.count({ where: { executionId: execution.id } });
        mustAccept(
          p,
          `${label}: the line that reaches the ceiling`,
          await insertLog(db, execution, over.ok),
        );
        const r = await insertLog(db, execution, over.bad);
        rej(p, `${label}: the line above the ceiling`, r, needle);
        if ((await db.executionLog.count({ where: { executionId: execution.id } })) !== before + 1)
          p.push(`${label}: the refused row left a trace`);
      };
      const e2 = await running(c, A, 0);
      await insertLog(db, e2, { message: "seed" });
      await ceil(
        "execution lines",
        e2,
        [`UPDATE execution_log_counters SET line_count = 99999 WHERE execution_id = $1::uuid`],
        { ok: { message: "one" }, bad: { message: "two" } },
        "execution_log_counters_caps_check",
      );
      const e3 = await running(c, A, 1);
      await insertLog(db, e3, { message: "seed" });
      await ceil(
        "execution bytes",
        e3,
        [
          `UPDATE execution_log_counters SET byte_count = 8388608 - 3 WHERE execution_id = $1::uuid`,
        ],
        { ok: { message: "abc" }, bad: { message: "d" } },
        "execution_log_counters_caps_check",
      );
      const e4 = await running(c, A, 0);
      const t4 = await runningTask(c, e4, "sca");
      await insertLog(db, e4, { scanTaskId: t4.id, source: "scan", message: "seed" });
      await ceil(
        "task lines",
        e4,
        [`UPDATE execution_task_log_counters SET line_count = 49999 WHERE execution_id = $1::uuid`],
        {
          ok: { scanTaskId: t4.id, source: "scan", message: "one" },
          bad: { scanTaskId: t4.id, source: "scan", message: "two" },
        },
        "execution_task_log_counters_caps_check",
      );
      const e5 = await running(c, A, 1);
      const t5 = await runningTask(c, e5, "sca");
      await insertLog(db, e5, { scanTaskId: t5.id, source: "scan", message: "seed" });
      await ceil(
        "task bytes",
        e5,
        [
          `UPDATE execution_task_log_counters SET byte_count = 4194304 - 3 WHERE execution_id = $1::uuid`,
        ],
        {
          ok: { scanTaskId: t5.id, source: "scan", message: "abc" },
          bad: { scanTaskId: t5.id, source: "scan", message: "d" },
        },
        "execution_task_log_counters_caps_check",
      );

      // a terminal execution accepts no line, and the counters stay as they were
      const done = await running(c, A, 0);
      await insertLog(db, done, { message: "before the end" });
      await driveExecution(db, done.id, "succeeded");
      const snap = JSON.stringify(await counterOf(db, done), (_k, v) =>
        typeof v === "bigint" ? String(v) : v,
      );
      rej(p, "a line for a terminal execution", await insertLog(db, done), "terminal");
      if (
        JSON.stringify(await counterOf(db, done), (_k, v) =>
          typeof v === "bigint" ? String(v) : v,
        ) !== snap
      )
        p.push("a refused line for a terminal execution changed the counters");
      // the retention purge may delete (control)
      mustAccept(
        p,
        "DELETE of a line (the retention purge needs it)",
        await upd(`DELETE FROM execution_logs WHERE execution_id = $1::uuid`, done.id),
      );
      return p;
    },
  },
  {
    id: "EXECDB-021",
    name: "execution_artifacts in the database (SPEC 17.ac): the chain must match the execution, the name is ONE safe path segment (no separator, no .., no leading dot or digit, no upper case, no trailing dot, at most 64 characters), size and hash are consistent and capped at 1 MiB, at most 20 objects and 8 MiB per execution even for concurrent writers, a duplicate name is refused, rows are insert-only and a terminal execution accepts none",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      const e = await running(c, A, 0);
      const other = await running(c, A, 1);
      const foreign = await running(c, B, 0);
      const row = (x, over = {}) => {
        const content = over.content ?? Buffer.from("hello");
        return {
          ...chain(x),
          name: `a-${rand(3)}`,
          mediaType: "text/plain",
          content,
          sizeBytes: content.length,
          sha256: "a".repeat(64),
          ...over,
        };
      };
      const put = (x, over) => attempt(() => db.executionArtifact.create({ data: row(x, over) }));
      mustAccept(p, "a valid artifact", await put(e, { name: "sbom.json" }));
      rej(p, "a duplicate name", await put(e, { name: "sbom.json" }), "Unique constraint");
      mustAccept(p, "the same name in another execution", await put(other, { name: "sbom.json" }));
      rej(p, "another tenant's id", await put(e, { tenantId: B.tenant.id }), "Foreign key");
      rej(
        p,
        "another workspace of the tenant",
        await put(e, { workspaceId: other.workspaceId }),
        "Foreign key",
      );
      rej(
        p,
        "a foreign execution's chain",
        await put(foreign, { tenantId: A.tenant.id }),
        "Foreign key",
      );
      const names = [
        "../etc/passwd",
        "a/b",
        "a\\b",
        "..",
        ".hidden",
        "a..b",
        "trailing.",
        "UPPER",
        "1digit",
        "",
        "x".repeat(65),
        "sp ace",
        "a%2fb",
        "tab\tname",
        "-dash",
      ];
      for (const name of names)
        rej(
          p,
          `the name ${JSON.stringify(name).slice(0, 24)}`,
          await put(e, { name }),
          "execution_artifacts_values_check",
        );
      for (const name of ["a", "report.json", "source.tar.gz", "x".repeat(64), "a_b-c.d"])
        mustAccept(p, `the name ${name.slice(0, 12)}`, await put(e, { name }));
      rej(
        p,
        "an unknown media type",
        await put(e, { mediaType: "text/html" }),
        "execution_artifacts_values_check",
      );
      rej(
        p,
        "a size that does not match the content",
        await put(e, { sizeBytes: 3 }),
        "execution_artifacts_values_check",
      );
      rej(
        p,
        "a malformed hash",
        await put(e, { sha256: "xyz" }),
        "execution_artifacts_values_check",
      );
      rej(
        p,
        "an artifact above 1 MiB",
        await put(e, { content: Buffer.alloc(1048577) }),
        "execution_artifacts_values_check",
      );
      const upd = (sql, ...a) => attempt(() => db.$executeRawUnsafe(sql, ...a));
      rej(
        p,
        "updating an artifact",
        await upd(
          `UPDATE execution_artifacts SET name = 'renamed' WHERE execution_id = $1::uuid`,
          e.id,
        ),
        "insert-only",
      );
      rej(p, "truncating the table", await upd(`TRUNCATE execution_artifacts`), "not allowed");

      // count cap: 20 per execution (6 exist already in e: sbom.json + 5 names), concurrent writers cannot overrun it
      const full = await running(c, A, 0);
      const results = await Promise.all(
        Array.from({ length: 24 }, (_, i) => put(full, { name: `n${i}` })),
      );
      const stored = await db.executionArtifact.count({ where: { executionId: full.id } });
      if (stored !== 20)
        p.push(`the count cap held ${stored} objects, not 20 (concurrent inserts)`);
      if (results.filter((r) => r.ok).length !== 20)
        p.push("the number of accepted inserts is not 20");
      if (!results.some((r) => !r.ok && r.message.includes("per-execution artifact cap")))
        p.push("the refusal does not name the per-execution cap");
      // byte cap: 8 MiB per execution
      const big = await running(c, A, 1);
      const chunk = Buffer.alloc(1048576, 97);
      const bytes = await Promise.all(
        Array.from({ length: 10 }, (_, i) => put(big, { name: `b${i}`, content: chunk })),
      );
      const total =
        await db.$queryRaw`SELECT COALESCE(sum(size_bytes), 0)::int AS n FROM execution_artifacts WHERE execution_id = ${big.id}::uuid`;
      if (total[0].n !== 8388608 || bytes.filter((r) => r.ok).length !== 8)
        p.push(
          `the byte cap held ${total[0].n} bytes in ${bytes.filter((r) => r.ok).length} objects, not 8 MiB in 8`,
        );

      // terminal: none accepted
      const done = await running(c, A, 0);
      await driveExecution(db, done.id, "failed");
      rej(p, "an artifact for a terminal execution", await put(done), "terminal");
      mustAccept(
        p,
        "DELETE of an artifact (the retention purge needs it)",
        await upd(`DELETE FROM execution_artifacts WHERE execution_id = $1::uuid`, other.id),
      );
      return p;
    },
  },
  {
    id: "EXECDB-022",
    name: "LogStore caps (SPEC 17.ac): per-task and per-execution line and byte caps drop the surplus with exactly ONE truncation marker per scope and set the truncated flag and the dropped count; the marker itself stays inside the cap; later lines of a capped scope are never written, a second task of the same execution still writes until the execution cap; seq stays contiguous; a line over 2000 characters is cut and flagged; total rows and bytes never exceed the configured caps",
    async run(c) {
      const p = [];
      const { db, A } = c;
      const store = storeOf(db, SMALL);
      const e = await running(c, A, 0);
      const t1 = await runningTask(c, e, "sca");
      const t2 = await runningTask(c, e, "sbom");
      const ref = (t) => ({
        tenantId: e.tenantId,
        executionId: e.id,
        taskId: t.id,
        attempt: t.attempt,
        workerId: "suite-worker",
      });
      const many = (n, prefix) =>
        Array.from({ length: n }, (_, i) => ({ level: "info", message: `${prefix} ${i}` }));

      const first = await store.appendTask(ref(t1), many(20, "t1"));
      if (first.fenced || first.appended !== 8 || first.dropped !== 13 || !first.truncated)
        p.push(
          `task cap: appended ${first.appended}, dropped ${first.dropped}, truncated ${first.truncated} (expected 8 incl. the marker, 13, true)`,
        );
      const again = await store.appendTask(ref(t1), many(5, "late"));
      if (again.appended !== 0 || again.dropped !== 5)
        p.push("a capped task wrote lines after its marker");
      let rows = await db.executionLog.findMany({
        where: { executionId: e.id },
        orderBy: { seq: "asc" },
      });
      const t1Rows = rows.filter((r) => r.scanTaskId === t1.id);
      if (
        t1Rows.length !== 8 ||
        t1Rows.filter((r) => /per-task log cap/.test(r.message)).length !== 1
      )
        p.push(
          `the task has ${t1Rows.length} rows and ${t1Rows.filter((r) => /per-task log cap/.test(r.message)).length} markers, not 8 and 1`,
        );
      if (rows.some((r) => r.message.startsWith("late"))) p.push("a dropped line was stored");
      const tc = await taskCounterOf(db, t1);
      if (!tc?.truncated || !tc.capped || tc.droppedLines !== 18)
        p.push(
          `task counter: truncated ${tc?.truncated}, capped ${tc?.capped}, dropped ${tc?.droppedLines}`,
        );
      const ec1 = await counterOf(db, e);
      if (!ec1?.truncated || ec1.capped)
        p.push("a capped task must flag the execution truncated but not capped");

      // the second task of the execution still writes, up to the execution cap (12 incl. its marker)
      const second = await store.appendTask(ref(t2), many(10, "t2"));
      rows = await db.executionLog.findMany({
        where: { executionId: e.id },
        orderBy: { seq: "asc" },
      });
      if (rows.length !== 12)
        p.push(`the execution holds ${rows.length} rows, not exactly its cap of 12`);
      if (rows.filter((r) => /per-execution log cap/.test(r.message)).length !== 1)
        p.push("not exactly one execution-level marker");
      if (second.appended !== 4 || second.dropped !== 7)
        p.push(
          `second task: appended ${second.appended}, dropped ${second.dropped} (expected 4 incl. the marker, 7)`,
        );
      if (rows.map((r) => Number(r.seq)).join() !== rows.map((_r, i) => i + 1).join())
        p.push("seq is not contiguous");
      const ec2 = await counterOf(db, e);
      if (!ec2?.capped || !ec2.truncated || ec2.lineCount !== 12)
        p.push("the execution counter is not capped at 12");
      const after = await store.appendTask(ref(t2), many(3, "after"));
      if (after.appended !== 0 || (await countLogs(db, e.id)) !== 12)
        p.push("a line was written after the execution cap");

      // byte caps
      const bytesStore = storeOf(db, {
        maxLinesPerExecution: 1000,
        maxBytesPerExecution: 1000,
        maxLinesPerTask: 1000,
        maxBytesPerTask: 800,
      });
      const e2 = await running(c, A, 1);
      const t3 = await runningTask(c, e2, "sca");
      const r3 = {
        tenantId: e2.tenantId,
        executionId: e2.id,
        taskId: t3.id,
        attempt: t3.attempt,
        workerId: "suite-worker",
      };
      const wide = Array.from({ length: 10 }, (_, i) => ({
        level: "info",
        message: `${i}`.padEnd(300, "w"),
      }));
      const wr = await bytesStore.appendTask(r3, wide);
      const sum =
        await db.$queryRaw`SELECT COALESCE(sum(octet_length(message)), 0)::int AS n, count(*)::int AS c FROM execution_logs WHERE execution_id = ${e2.id}::uuid`;
      if (sum[0].n > 800 || wr.dropped === 0 || !wr.truncated)
        p.push(`task byte cap: ${sum[0].n} bytes stored, ${wr.dropped} dropped`);
      if (sum[0].c !== 1 + 1)
        p.push(`task byte cap: ${sum[0].c} rows (1 line and the marker expected)`);

      // the per-line cap
      const e3 = await running(c, A, 0);
      const t4 = await runningTask(c, e3, "sca");
      const long = await storeOf(db, BIG).appendTask(
        {
          tenantId: e3.tenantId,
          executionId: e3.id,
          taskId: t4.id,
          attempt: 0,
          workerId: "suite-worker",
        },
        [
          { level: "warn", message: "L".repeat(5000) },
          { level: "info", message: "short" },
        ],
      );
      const stored = await db.executionLog.findMany({
        where: { executionId: e3.id },
        orderBy: { seq: "asc" },
      });
      if (
        long.appended !== 2 ||
        stored[0].message.length !== 2000 ||
        !stored[0].lineTruncated ||
        stored[1].lineTruncated
      )
        p.push("the per-line cap did not cut and flag exactly the long line");

      // configured caps above the ceilings are refused; below 2 are refused
      for (const bad of [
        { ...BIG, maxLinesPerExecution: 100001 },
        { ...BIG, maxBytesPerTask: 4194305 },
      ]) {
        const r = await attempt(() => storeOf(db, bad).appendTask(r3, many(1, "x")));
        if (r.ok) p.push("a cap above the database ceiling was accepted");
      }
      if (
        !(
          await attempt(() =>
            createLogStore({
              repository: createExecutionLogRepository({ db }),
              limits: { ...BIG, maxLinesPerTask: 1 },
            }),
          )
        ).ok === false
      )
        p.push("a cap below 2 was accepted");
      // the repository validates what it is given even when called without the store (level, source, text, size of a call)
      const repo = createExecutionLogRepository({ db });
      const direct = (lines, over = {}) =>
        attempt(() => repo.appendTaskLines({ ...r3, lines, limits: BIG, ...over }));
      const good = { level: "info", source: "scan", message: "direct" };
      for (const [label, lines] of [
        ["an unknown level", [{ ...good, level: "fatal" }]],
        ["an unknown source", [{ ...good, source: "user" }]],
        ["an empty message", [{ ...good, message: "" }]],
        ["501 lines in one call", Array.from({ length: 501 }, () => good)],
      ]) {
        const r = await direct(lines);
        if (r.ok || (!r.message.includes("log line") && !r.message.includes("at a time")))
          p.push(`the repository accepted ${label} (${r.message.slice(0, 80)})`);
      }
      mustAccept(p, "control: a valid direct call", await direct([good]));
      // control: the store with the default caps writes ordinary lines
      mustAccept(
        p,
        "ordinary lines under the default caps",
        await attempt(() => storeOf(db, BIG).appendTask(r3, many(3, "ok"))),
      );
      return p;
    },
  },
  {
    id: "EXECDB-023",
    name: "LogStore redaction on write (SPEC 17.ac): installation and personal tokens, Authorization headers (any scheme), Bearer tokens, whole private-key blocks, AWS key ids, URLs with credentials, token query parameters and password/secret/api_key pairs are replaced by [REDACTED] before the row is written, control characters and line breaks never reach a row, and no stored message of the execution still has a credential shape; harmless text is stored unchanged",
    async run(c) {
      const p = [];
      const { db, A } = c;
      const store = storeOf(db, BIG);
      const e = await running(c, A, 0);
      const t = await runningTask(c, e, "sca");
      const ref = {
        tenantId: e.tenantId,
        executionId: e.id,
        taskId: t.id,
        attempt: 0,
        workerId: "suite-worker",
      };
      const pem =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nZZZZsecretkeybodyZZZZ\n-----END RSA PRIVATE KEY-----";
      const secrets = [
        ["a personal token", "token ghp_abcdefghijklmnop1234 used", "ghp_abcdefghijklmnop1234"],
        ["an installation token", "got ghs_ABCDEFGH12345678 for the repo", "ghs_ABCDEFGH12345678"],
        [
          "a fine-grained token",
          "pat github_pat_11ABCDEFG_abcdefghij",
          "github_pat_11ABCDEFG_abcdefghij",
        ],
        ["a Bearer header", "Authorization: Bearer abcdefghijklmnopq", "abcdefghijklmnopq"],
        ["a Basic header", "authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"],
        ["a proxy header", "Proxy-Authorization: Digest realm-xyzzy-1234", "xyzzy-1234"],
        [
          "a private key block over several lines",
          `key follows ${pem} done`,
          "ZZZZsecretkeybodyZZZZ",
        ],
        ["an AWS key id", "id AKIAABCDEFGHIJKLMNOP end", "AKIAABCDEFGHIJKLMNOP"],
        ["a URL with credentials", "clone https://user:p4ssw0rd@github.com/x/y.git", "p4ssw0rd"],
        ["a token query parameter", "GET /x?access_token=abcdef123456&y=1", "abcdef123456"],
        ["a signature parameter", "GET /x?X-Amz-Signature=deadbeefdeadbeef", "deadbeefdeadbeef"],
        ["a password pair", "login password=hunter2hunter2 ok", "hunter2hunter2"],
        ["a quoted secret pair", `secret: "my secret value"`, "my secret value"],
        ["an api key pair", "api_key=zzzzzzzzzzzz", "zzzzzzzzzzzz"],
        ["a secretRef pair", "secretRef: sec_1234567890", "sec_1234567890"],
        // the passes leave "&sig=[REDACTED]" behind (still a credential shape): only the final guard turns it into a full redaction
        ["a shape left by the passes", "&sig=&sig=zyxwvutsrq12", "zyxwvutsrq12"],
      ];
      // exact stored text of the lines whose context must survive the redaction (it replaces the secret, not the sentence)
      const exact = {
        0: "token [REDACTED] used",
        1: "got [REDACTED] for the repo",
        7: "id [REDACTED] end",
        8: "clone [REDACTED]github.com/x/y.git",
        9: "GET /x[REDACTED]&y=1",
        11: "login password: [REDACTED] ok",
        15: "[REDACTED]",
      };
      const result = await store.appendTask(
        ref,
        secrets.map(([, message]) => ({ level: "info", message })),
      );
      if (result.fenced || result.appended < secrets.length)
        p.push(`control: ${result.appended} lines stored for ${secrets.length} inputs`);
      const stored = await db.executionLog.findMany({
        where: { executionId: e.id },
        orderBy: { seq: "asc" },
      });
      const text = stored.map((r) => r.message).join("\n");
      for (const [label, , secret] of secrets)
        if (text.includes(secret)) p.push(`${label}: the secret value was stored`);
      if (stored.some((r) => findCredentials(r.message).length > 0))
        p.push("a stored message still has a credential shape");
      for (const [i, want] of Object.entries(exact))
        if (stored[Number(i)]?.message !== want)
          p.push(
            `line ${i} was stored as ${JSON.stringify(stored[Number(i)]?.message)}, expected ${JSON.stringify(want)}`,
          );
      if (!text.includes("[REDACTED]")) p.push("no [REDACTED] marker was written at all");
      const harmless = [
        "Resolved 214 packages in 3.2s",
        "sbom: package-lock.json: malformed_json",
        "ratio a=1&b=2",
        "see https://github.com/x/y/blob/main/README.md",
      ];
      await store.appendTask(
        ref,
        harmless.map((message) => ({ level: "info", message })),
      );
      const back = (
        await db.executionLog.findMany({
          where: { executionId: e.id },
          orderBy: { seq: "desc" },
          take: 4,
        })
      )
        .map((r) => r.message)
        .reverse();
      if (back.join("|") !== harmless.join("|"))
        p.push(`harmless text was changed: ${back.join("|")}`);
      // control characters, line breaks and an unknown level
      await store.appendTask(ref, [
        { level: "bogus", message: "a\u0000b\u0007c\r\nnext line\u2028third" },
      ]);
      const tail = (
        await db.executionLog.findMany({
          where: { executionId: e.id },
          orderBy: { seq: "desc" },
          take: 2,
        })
      ).reverse();
      if (
        tail.map((r) => r.message).join("|") !== "a b c|next line third" ||
        tail.some((r) => r.level !== "info")
      )
        p.push(
          `a line break, a control character or an unknown level was not normalised: ${JSON.stringify(tail.map((r) => [r.level, r.message]))}`,
        );
      // the execution-level writer redacts too (platform and fetch sources)
      await db.$executeRaw`UPDATE executions SET lease_epoch = lease_epoch WHERE id = ${e.id}::uuid`;
      const lease = (await db.execution.findUnique({ where: { id: e.id } })).leaseEpoch;
      await store.appendExecution(
        { tenantId: e.tenantId, executionId: e.id, leaseEpoch: lease, source: "fetch" },
        [{ level: "info", message: "fetched with ghs_ABCDEFGH12345678" }],
      );
      const fetchRow = await db.executionLog.findFirst({
        where: { executionId: e.id, source: "fetch" },
      });
      if (!fetchRow || fetchRow.message.includes("ghs_") || fetchRow.scanTaskId !== null)
        p.push("the execution-level writer did not redact or mis-scoped the line");
      return p;
    },
  },
  {
    id: "EXECDB-024",
    name: "LogStore write fence (SPEC 17.ac, ER-30): a task writer writes only while its task is running exactly that attempt for exactly that worker in a preparing/running execution; a superseded attempt, another worker, a finished task, a terminal execution and another tenant's ids write nothing (fenced, no row, no counter); an execution-level writer is fenced by the lease epoch (LeaseLostError for a reclaimed lease)",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      const store = storeOf(db, BIG);
      const e = await running(c, A, 0);
      const t = await runningTask(c, e, "sca");
      const ref = (over = {}) => ({
        tenantId: e.tenantId,
        executionId: e.id,
        taskId: t.id,
        attempt: 0,
        workerId: "suite-worker",
        ...over,
      });
      const line = [{ level: "info", message: "hello" }];
      const none = async (label, r) => {
        if (!r.fenced || r.appended !== 0) p.push(`${label}: not fenced (${JSON.stringify(r)})`);
      };
      mustAccept(
        p,
        "control: the holder writes",
        await attempt(() => store.appendTask(ref(), line)),
      );
      if ((await countLogs(db, e.id)) !== 1) p.push("control: the holder's line is missing");
      await none("another worker", await store.appendTask(ref({ workerId: "zombie" }), line));
      await none("another attempt number", await store.appendTask(ref({ attempt: 1 }), line));
      await none(
        "another tenant's id",
        await store.appendTask(ref({ tenantId: B.tenant.id }), line),
      );
      await none(
        "an unknown task",
        await store.appendTask(ref({ taskId: "00000000-0000-4000-8000-0000000000ff" }), line),
      );
      if ((await countLogs(db, e.id)) !== 1) p.push("a fenced write left a row");

      // the attempt is superseded (retry / reclaim): attempt 0 is a zombie, attempt 1 holds the task
      await db.$executeRaw`UPDATE scan_tasks SET status = 'queued', attempt = 1, lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = ${t.id}::uuid`;
      await none("a task that is queued again", await store.appendTask(ref(), line));
      await db.$executeRaw`UPDATE scan_tasks SET status = 'running', lease_owner = 'suite-worker-2', lease_expires_at = now() + interval '5 minutes', heartbeat_at = now() WHERE id = ${t.id}::uuid`;
      await none("the superseded attempt 0 (zombie)", await store.appendTask(ref(), line));
      await none(
        "the old worker on the new attempt",
        await store.appendTask(ref({ attempt: 1 }), line),
      );
      const ok = await store.appendTask(ref({ attempt: 1, workerId: "suite-worker-2" }), line);
      if (ok.fenced || ok.appended !== 1) p.push("control: the new holder was refused");

      // the task finishes: no more lines
      await db.$executeRaw`UPDATE scan_tasks SET status = 'succeeded', lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = ${t.id}::uuid`;
      await none(
        "a finished task",
        await store.appendTask(ref({ attempt: 1, workerId: "suite-worker-2" }), line),
      );

      // execution-level lines: the lease epoch
      const before = await countLogs(db, e.id);
      const epoch = (await db.execution.findUnique({ where: { id: e.id } })).leaseEpoch;
      const exRef = (n) => ({
        tenantId: e.tenantId,
        executionId: e.id,
        leaseEpoch: n,
        source: "platform",
      });
      const good = await attempt(() => store.appendExecution(exRef(epoch), line));
      mustAccept(p, "control: the lease holder writes execution lines", good);
      await db.$executeRaw`UPDATE executions SET lease_owner = 'suite-worker-3', lease_epoch = lease_epoch + 1, heartbeat_at = now(), lease_expires_at = now() + interval '5 minutes' WHERE id = ${e.id}::uuid`;
      let lost = null;
      try {
        await store.appendExecution(exRef(epoch), line);
      } catch (error) {
        lost = error;
      }
      if (!(lost instanceof LeaseLostError))
        p.push("a zombie lease holder was not refused with LeaseLostError");
      if ((await countLogs(db, e.id)) !== before + 1)
        p.push("a zombie lease holder's line was stored");
      let foreign = null;
      try {
        await store.appendExecution({ ...exRef(epoch + 1), tenantId: B.tenant.id }, line);
      } catch (error) {
        foreign = error;
      }
      if (!(foreign instanceof LeaseLostError))
        p.push("another tenant's id was not refused as a lost lease");
      mustAccept(
        p,
        "control: the new lease holder writes",
        await attempt(() => store.appendExecution(exRef(epoch + 1), line)),
      );
      // a terminal execution: task and execution writers both refused
      const t2 = await runningTask(c, await running(c, A, 1), "sca");
      const ex2 = await db.execution.findUnique({ where: { id: t2.executionId } });
      await store.appendTask(
        {
          tenantId: ex2.tenantId,
          executionId: ex2.id,
          taskId: t2.id,
          attempt: 0,
          workerId: "suite-worker",
        },
        line,
      );
      await db.$executeRaw`UPDATE scan_tasks SET status = 'failed', status_reason = 'engine_failed', lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = ${t2.id}::uuid`;
      await driveExecution(db, ex2.id, "failed");
      await none(
        "a task of a terminal execution",
        await store.appendTask(
          {
            tenantId: ex2.tenantId,
            executionId: ex2.id,
            taskId: t2.id,
            attempt: 0,
            workerId: "suite-worker",
          },
          line,
        ),
      );
      return p;
    },
  },
  {
    id: "EXECDB-025",
    name: "LogStore and ArtifactStore reads are scoped (SPEC 17.ac): lines are listed by keyset on seq (pages are contiguous and complete, the cursor is only a position) and only for the tenant that owns the execution, the workspace it belongs to and, when named, the task; another tenant's or workspace's ids answer an empty page; artifacts are read, listed, sized, hashed and deleted only by their own tenant and execution, and never through a path-like name",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      const repo = createExecutionLogRepository({ db });
      const store = storeOf(db, BIG);
      const e = await running(c, A, 0);
      const t = await runningTask(c, e, "sca");
      const foreign = await running(c, B, 0);
      const ref = {
        tenantId: e.tenantId,
        executionId: e.id,
        taskId: t.id,
        attempt: 0,
        workerId: "suite-worker",
      };
      await store.appendTask(
        ref,
        Array.from({ length: 25 }, (_, i) => ({ level: "info", message: `task line ${i}` })),
      );
      await store.appendExecution(
        {
          tenantId: e.tenantId,
          executionId: e.id,
          leaseEpoch: (await db.execution.findUnique({ where: { id: e.id } })).leaseEpoch,
          source: "platform",
        },
        [{ level: "info", message: "platform line" }],
      );
      const seen = [];
      let after = 0;
      for (let i = 0; i < 20; i += 1) {
        const page = await store.read({
          tenantId: e.tenantId,
          workspaceId: e.workspaceId,
          executionId: e.id,
          afterSeq: after,
          limit: 10,
        });
        seen.push(...page.items.map((r) => r.seq));
        if (!page.hasMore) break;
        after = page.nextAfterSeq;
      }
      if (seen.join() !== Array.from({ length: 26 }, (_, i) => i + 1).join())
        p.push(`pages are not contiguous and complete: ${seen.join()}`);
      // the counters' flags are part of the scope too: a truncated log of this tenant must not show through another tenant's read
      await db.$executeRaw`UPDATE execution_log_counters SET truncated = true, dropped_lines = 4 WHERE execution_id = ${e.id}::uuid`;
      await db.$executeRaw`UPDATE execution_task_log_counters SET truncated = true, dropped_lines = 4 WHERE scan_task_id = ${t.id}::uuid`;
      const owner = await store.read({ tenantId: e.tenantId, executionId: e.id, limit: 1 });
      const ownerTask = await store.read({
        tenantId: e.tenantId,
        executionId: e.id,
        taskId: t.id,
        limit: 1,
      });
      if (
        !owner.truncated ||
        owner.droppedLines !== 4 ||
        !ownerTask.truncated ||
        ownerTask.droppedLines !== 4
      )
        p.push("control: the owner does not see the truncated flag and the dropped count");
      const onlyTask = await store.read({
        tenantId: e.tenantId,
        executionId: e.id,
        taskId: t.id,
        limit: 500,
      });
      if (onlyTask.items.length !== 25 || onlyTask.items.some((r) => r.taskId !== t.id))
        p.push("the task filter returned other lines");
      if (
        (await store.read({ tenantId: e.tenantId, executionId: e.id, limit: 9999 })).items.length >
        500
      )
        p.push("the page size is not clamped");
      const wrong = [
        ["another tenant", { tenantId: B.tenant.id, executionId: e.id }],
        [
          "another tenant naming this workspace",
          { tenantId: B.tenant.id, workspaceId: e.workspaceId, executionId: e.id },
        ],
        [
          "this tenant, another workspace",
          { tenantId: e.tenantId, workspaceId: foreign.workspaceId, executionId: e.id },
        ],
        [
          "this tenant, another tenant's execution id",
          { tenantId: e.tenantId, executionId: foreign.id },
        ],
        ["another tenant on a task", { tenantId: B.tenant.id, executionId: e.id, taskId: t.id }],
      ];
      for (const [label, q] of wrong) {
        const page = await store.read(q);
        if (page.items.length !== 0 || page.hasMore || page.truncated || page.droppedLines !== 0)
          p.push(`${label}: lines were returned`);
      }
      for (const bad of [-1, 1.5, "1"])
        if (
          !(
            await attempt(() =>
              repo.listLines({ tenantId: e.tenantId, executionId: e.id, afterSeq: bad }),
            )
          ).ok === false
        )
          p.push(`afterSeq ${bad} was accepted`);

      // artifacts
      const artifacts = createPostgresArtifactStore({
        repository: createExecutionArtifactRepository({ db }),
      });
      const aRef = (name, over = {}) => ({
        tenantId: e.tenantId,
        executionId: e.id,
        name,
        ...over,
      });
      const made = await artifacts.put(aRef("doc.json"), Buffer.from('{"a":1}'), {
        mediaType: "application/json",
      });
      if (!made.created || made.bytes !== 7 || !/^[0-9a-f]{64}$/.test(made.sha256))
        p.push("control: the artifact was not stored");
      const kept = await artifacts.put(aRef("doc.json"), Buffer.from("other"), { ifAbsent: true });
      if (kept.created || (await artifacts.size(aRef("doc.json"))) !== 7)
        p.push("ifAbsent replaced an existing artifact");
      if (
        !(await attempt(() => artifacts.put(aRef("doc.json"), Buffer.from("other")))).ok === false
      )
        p.push("a duplicate put without ifAbsent was accepted");
      const read = async (r) => {
        const chunks = [];
        for await (const chunk of artifacts.open(r)) chunks.push(chunk);
        return Buffer.concat(chunks).toString();
      };
      if ((await read(aRef("doc.json"))) !== '{"a":1}')
        p.push("control: the artifact cannot be read back");
      const foreignRef = aRef("doc.json", { tenantId: B.tenant.id });
      if (
        (await artifacts.size(foreignRef)) !== null ||
        (await artifacts.sha256(foreignRef)) !== null
      )
        p.push("another tenant sees the artifact");
      if (!(await attempt(() => read(foreignRef))).ok === false)
        p.push("another tenant read the artifact");
      const crossRef = aRef("doc.json", { executionId: foreign.id });
      if ((await artifacts.size(crossRef)) !== null)
        p.push("another tenant's execution id exposes the artifact");
      const nope = await artifacts.put(foreignRef, Buffer.from("x"));
      if (nope.created) p.push("an artifact was created for another tenant's execution");
      await artifacts.delete(foreignRef);
      await artifacts.deleteExecution({ tenantId: B.tenant.id, executionId: e.id });
      if ((await artifacts.size(aRef("doc.json"))) !== 7)
        p.push("another tenant deleted the artifact");
      const list = createExecutionArtifactRepository({ db });
      if ((await list.list({ tenantId: B.tenant.id, executionId: e.id })).items.length !== 0)
        p.push("another tenant lists the artifacts");
      if (
        (
          await list.list({
            tenantId: e.tenantId,
            workspaceId: foreign.workspaceId,
            executionId: e.id,
          })
        ).items.length !== 0
      )
        p.push("another workspace lists the artifacts");
      if (
        (await list.list({ tenantId: e.tenantId, workspaceId: e.workspaceId, executionId: e.id }))
          .items.length !== 1
      )
        p.push("control: the owner does not list the artifact");
      // text content is redacted before it is hashed and stored; the stored hash is of the stored bytes
      await artifacts.put(aRef("note.txt"), Buffer.from("fetched with ghs_ABCDEFGH12345678"), {
        mediaType: "text/plain",
      });
      const note = await read(aRef("note.txt"));
      if (note.includes("ghs_") || !note.includes("[REDACTED]"))
        p.push("text artifact content was not redacted");
      // the size cap
      const tooBig = await attempt(() => artifacts.put(aRef("big.bin"), Buffer.alloc(1048577)));
      if (
        tooBig.ok ||
        !/exceeds 1048576 bytes/.test(tooBig.message) ||
        (await artifacts.size(aRef("big.bin"))) !== null
      )
        p.push("an artifact above the cap was stored");
      await artifacts.delete(aRef("note.txt"));
      if ((await artifacts.size(aRef("note.txt"))) !== null)
        p.push("control: delete did not delete");
      return p;
    },
  },
];
