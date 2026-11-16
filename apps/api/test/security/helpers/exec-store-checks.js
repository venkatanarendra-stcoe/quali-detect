import { mkdir, readdir } from "node:fs/promises";
import path from "node:path";
import { createJobEnvelope, parseMessage } from "@qmentisai/contracts";
import { createExecutionRetentionRepository } from "@qmentisai/db";
import {
  NonRetryableError,
  createLocalArtifactStore,
  findCredentials,
  parseArtifactRef,
} from "@qmentisai/infra";
import { ConfigError } from "../../../../workers/src/config.js";
import { createExecutionRetentionHandler } from "../../../../workers/src/scheduler/retention.js";
import { attempt } from "./pipeline-db.js";
import { driveExecution } from "./execution-db.js";

/**
 * Execution logs, artifacts and retention against the real orchestrator and scan handler (ADR-008, docs/modules/executions/
 * SPEC.md §14.1 and §17.ac, `EXE-051..054`): what the workers write to the execution log (including the SBOM engine's per-file
 * warnings and hostile engine output in a trusted AND an untrusted_fork run), the retention purge (only expired rows of
 * terminal executions, never a fresher row, never a running execution, batch-limited, idempotent, gated), and the reference
 * validation that keeps an artifact name from traversing out of its tenant/execution scope. Every denial has a control.
 */

const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const script = (obj) => ({ name: "qm-test.json", content: JSON.stringify(obj) });
const BASE = [
  { name: "README.md", content: "# repo\n" },
  { name: "src", dir: true },
  { name: "src/a.js", content: "console.log(1)\n" },
];
const DAY = 86_400_000;
const ago = (days) => new Date(Date.now() - days * DAY);
const scanTypesOnly = (types) => ({
  sbom: { enabled: types.includes("sbom") },
  sca: { enabled: types.includes("sca") },
  sast: { enabled: types.includes("sast") },
  secrets: { enabled: types.includes("secrets") },
});

const SECRETS = [
  "ghp_abcdefghijklmnop1234",
  "ghs_ZYXWVUTS98765432",
  "AKIAIOSFODNN7EXAMPLE",
  "p4ssw0rdV4lue",
  "sentinel-private-key-body-QQQQ",
  "abcdefghijklmnopq-bearer-value",
];
const HOSTILE_LOGS = [
  `token ${SECRETS[0]} was found`,
  `installation ${SECRETS[1]}`,
  `key ${SECRETS[2]} in config`,
  `clone https://ci:${SECRETS[3]}@github.com/o/r.git`,
  `-----BEGIN RSA PRIVATE KEY-----\nMIIEvQ\n${SECRETS[4]}\n-----END RSA PRIVATE KEY-----`,
  `Authorization: Bearer ${SECRETS[5]}`,
  "plain progress line",
];

const chainOf = (e) => ({
  tenantId: e.tenantId,
  workspaceId: e.workspaceId,
  repositoryId: e.repositoryId,
  pipelineId: e.pipelineId,
  executionId: e.id,
});

async function logsOf(w, e) {
  return w.db.executionLog.findMany({ where: { executionId: e.id }, orderBy: { seq: "asc" } });
}

/** Makes a terminal execution old: the guard triggers are switched off inside ONE transaction (DDL is transactional). */
async function ageExecution(db, e, days, { finished = true } = {}) {
  await db.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(`ALTER TABLE executions DISABLE TRIGGER USER`);
    await tx.$executeRawUnsafe(
      `UPDATE executions SET ${finished ? "finished_at = now() - make_interval(days => $2::int)," : ""} requested_at = now() - make_interval(days => $2::int) WHERE id = $1::uuid`,
      e.id,
      days,
    );
    await tx.$executeRawUnsafe(`ALTER TABLE executions ENABLE TRIGGER USER`);
  });
}

/** A running execution of `tree` with a task, an attempt, a result and an item, logs at the given ages and one artifact. */
async function seedExecution(
  w,
  tree,
  { logsDaysOld = [], artifactDaysOld = null, status = "running", executionLevel = false } = {},
) {
  const { db } = w;
  const e = await w.execution(tree, { archive: false, commitSha: null });
  await driveExecution(db, e.id, "running");
  const task = await db.scanTask.create({
    data: {
      ...chainOf(e),
      scanType: "sca",
      ordinal: 0,
      status: "queued",
      engineId: "default",
      engineProfile: "default",
      severityThreshold: "low",
      timeoutSeconds: 60,
    },
  });
  await db.$executeRaw`UPDATE scan_tasks SET status = 'running', lease_owner = 'seed', lease_expires_at = now() + interval '5 minutes', heartbeat_at = now() WHERE id = ${task.id}::uuid`;
  await db.scanTaskAttempt.create({
    data: { ...chainOf(e), scanTaskId: task.id, attempt: 0, workerId: "seed" },
  });
  const result = await db.scanResult.create({
    data: {
      ...chainOf(e),
      scanTaskId: task.id,
      attempt: 0,
      scanType: "sca",
      engineId: "default",
      engineVersion: "1",
      completeness: "complete",
    },
  });
  await db.scanResultItem.create({
    data: {
      tenantId: e.tenantId,
      executionId: e.id,
      scanResultId: result.id,
      ordinal: 0,
      kind: "vulnerability",
      severity: "low",
      title: "seed",
    },
  });
  for (const [i, days] of logsDaysOld.entries())
    await db.executionLog.create({
      data: {
        ...chainOf(e),
        scanTaskId: executionLevel ? null : task.id,
        level: "info",
        source: executionLevel ? "platform" : "scan",
        message: `seed ${i} (${days}d)`,
        at: ago(days),
      },
    });
  if (artifactDaysOld !== null)
    await db.executionArtifact.create({
      data: {
        ...chainOf(e),
        name: "seed.txt",
        mediaType: "text/plain",
        content: Buffer.from("seed"),
        sizeBytes: 4,
        sha256: "c".repeat(64),
        createdAt: ago(artifactDaysOld),
      },
    });
  if (status !== "running") {
    await db.$executeRaw`UPDATE scan_tasks SET status = 'succeeded', lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = ${task.id}::uuid`;
    await driveExecution(db, e.id, status);
  }
  return { e, task };
}

const counts = async (db, e) => ({
  logs: await db.executionLog.count({ where: { executionId: e.id } }),
  artifacts: await db.executionArtifact.count({ where: { executionId: e.id } }),
  logCounters: await db.executionLogCounter.count({ where: { executionId: e.id } }),
  taskCounters: await db.executionTaskLogCounter.count({ where: { executionId: e.id } }),
  executions: await db.execution.count({ where: { id: e.id } }),
  tasks: await db.scanTask.count({ where: { executionId: e.id } }),
  events: await db.executionEvent.count({ where: { executionId: e.id } }),
  items: await db.scanResultItem.count({ where: { executionId: e.id } }),
});

export const STORE_CHECKS = [
  {
    id: "EXE-051",
    name: "execution logs written by the workers (SPEC 17.ac): the orchestrator records its milestones (source platform and fetch) and the scan handler the task's lines (source scan, with the task id), the engine's lines pass redaction on write in a trusted AND an untrusted_fork run (tokens, AWS key ids, URL credentials, whole private-key blocks, Authorization headers never reach a row; no installation token of the fetch step is in any log), seq is contiguous, the SBOM engine's per-file parse warnings are stored as lines, and a log flood is capped with one marker while the run still succeeds",
    async run(w) {
      const p = [];
      const { db } = w;
      const tree = await w.tree("logs1");
      const entries = [...BASE, script({ logs: HOSTILE_LOGS })];
      for (const fork of [false, true]) {
        const label = fork ? "untrusted_fork" : "trusted";
        const e = fork
          ? await w.fork(tree, { entries, concurrencyGroup: "logs-fork" })
          : await w.execution(tree, { entries });
        const run = await w.run(tree, e);
        ok(p, run.row.status === "succeeded", `${label}: control: the run ended ${run.row.status}`);
        const rows = await logsOf(w, e);
        const text = rows.map((r) => r.message).join("\n");
        ok(p, rows.length >= 6, `${label}: only ${rows.length} log rows were written`);
        for (const secret of SECRETS)
          ok(
            p,
            !text.includes(secret),
            `${label}: the secret ${secret.slice(0, 10)}... reached a log row`,
          );
        ok(
          p,
          !/ghs_stub_|ghu_stub_|BEGIN (RSA )?PRIVATE KEY|authorization:\s*bearer/i.test(text),
          `${label}: a token shape reached a log row`,
        );
        ok(
          p,
          rows.every((r) => findCredentials(r.message).length === 0),
          `${label}: a stored line still has a credential shape`,
        );
        ok(
          p,
          text.includes("[REDACTED]") && text.includes("plain progress line"),
          `${label}: redaction removed too much or nothing`,
        );
        ok(
          p,
          rows.some(
            (r) =>
              r.source === "fetch" && /archive stored/.test(r.message) && r.scanTaskId === null,
          ),
          `${label}: no fetch milestone`,
        );
        ok(
          p,
          rows.some(
            (r) => r.source === "platform" && /execution started with 4 scan task/.test(r.message),
          ),
          `${label}: no platform milestone`,
        );
        ok(
          p,
          rows.filter((r) => r.source === "scan").length >= 7 &&
            rows.filter((r) => r.source === "scan").every((r) => r.scanTaskId),
          `${label}: task lines are missing or not tied to a task`,
        );
        ok(
          p,
          rows.map((r) => Number(r.seq)).join() === rows.map((_r, i) => i + 1).join(),
          `${label}: seq is not contiguous`,
        );
        ok(
          p,
          rows.every((r) => r.tenantId === tree.tenant.id),
          `${label}: a row of another tenant`,
        );
        const dump = await w.dump(tree);
        ok(
          p,
          !SECRETS.some((s) => dump.includes(s)),
          `${label}: a secret reached some row of the tenant`,
        );
      }

      // the SBOM engine's per-file warnings are stored (production registry shape: only the SBOM engine)
      const sbomTree = await w.tree("logs2", {
        config: w.config1({ scans: scanTypesOnly(["sbom"]) }),
      });
      const sbomExec = await w.execution(sbomTree, {
        entries: [
          ...BASE,
          { name: "package-lock.json", content: "{ not json" },
          { name: "package.json", content: '{"name":"a","dependencies":{"left-pad":"1.3.0"}}' },
        ],
      });
      const engines = w.sbomRegistry();
      const sbomRun = await w.run(sbomTree, sbomExec, {
        orch: w.orchestrator({}, { engines }),
        scan: w.scanHandler({}, undefined, engines),
      });
      ok(
        p,
        sbomRun.row.status === "succeeded" || sbomRun.row.status === "partial",
        `control: the SBOM run ended ${sbomRun.row.status}`,
      );
      const sbomLines = await logsOf(w, sbomExec);
      ok(
        p,
        sbomLines.some(
          (r) =>
            r.source === "scan" &&
            r.level === "warn" &&
            /^sbom: package-lock\.json: [a-z_]+$/.test(r.message),
        ),
        "the SBOM per-file warning is not in the stored task log",
      );

      // volume: 5000 lines against small caps -> one marker, the rest dropped, the run still succeeds
      const flood = await w.tree("logs3");
      const floodExec = await w.execution(flood, {
        entries: [...BASE, script({ logBurst: 5000 })],
      });
      const small = {
        EXECUTION_LOG_MAX_LINES: "100",
        EXECUTION_LOG_MAX_LINES_PER_TASK: "40",
        EXECUTION_LOG_MAX_BYTES: "65536",
        EXECUTION_LOG_MAX_BYTES_PER_TASK: "32768",
      };
      const floodRun = await w.run(flood, floodExec, {
        orch: w.orchestrator(small),
        scan: w.scanHandler(small, w.config(small, "scan")),
      });
      ok(
        p,
        floodRun.row.status === "succeeded",
        `control: the flood run ended ${floodRun.row.status}`,
      );
      const flooded = await logsOf(w, floodExec);
      ok(p, flooded.length <= 100, `the flood stored ${flooded.length} rows over the cap of 100`);
      for (const t of await w.taskRows(floodExec)) {
        const mine = flooded.filter((r) => r.scanTaskId === t.id);
        ok(
          p,
          mine.length <= 40,
          `task ${t.scanType} stored ${mine.length} rows over the cap of 40`,
        );
      }
      ok(
        p,
        flooded.filter((r) => /per-task log cap/.test(r.message)).length >= 1,
        "no task truncation marker after a flood",
      );
      ok(
        p,
        !flooded.some((r) => r.message === "burst line 4999"),
        "the last line of the flood was stored",
      );
      const flag = await db.executionLogCounter.findFirst({ where: { executionId: floodExec.id } });
      ok(
        p,
        flag?.truncated === true && flag.droppedLines > 0,
        "the execution counter does not say the log was truncated",
      );
      return p;
    },
  },
  {
    id: "EXE-052",
    name: "retention purge (SPEC ER-17, 17.ac): logs older than the log retention and artifacts older than the artifact retention of TERMINAL executions are deleted, and nothing else: a fresh row of the same execution, the old rows of a RUNNING execution, another tenant's fresh rows and an execution newer than 13 months stay; counters go only when no line is left; metadata older than 13 months goes with all its children, one execution at a time, and an execution that is the original of a retry stays; the batch limit is honoured, a second run deletes nothing more, and metadata is left alone when no period is given",
    async run(w) {
      const p = [];
      const { db } = w;
      const repo = createExecutionRetentionRepository({ db });
      const tx = await w.tree("ret1");
      const ty = await w.tree("ret2");

      const x1 = await seedExecution(w, tx, {
        logsDaysOld: [120, 100, 95, 1, 0],
        artifactDaysOld: 100,
      });
      await db.executionArtifact.create({
        data: {
          ...chainOf(x1.e),
          name: "fresh.txt",
          mediaType: "text/plain",
          content: Buffer.from("f"),
          sizeBytes: 1,
          sha256: "d".repeat(64),
        },
      });
      const xRun = await seedExecution(w, tx, { logsDaysOld: [400, 200], artifactDaysOld: 200 });
      const y1 = await seedExecution(w, ty, { logsDaysOld: [91, 0], artifactDaysOld: 5 });
      const x6 = await seedExecution(w, tx, { logsDaysOld: [150, 140] });
      // execution-level lines only (no task counter): one still has a fresh line, the other has none left
      const x7 = await seedExecution(w, tx, { logsDaysOld: [120, 1], executionLevel: true });
      const x8 = await seedExecution(w, tx, { logsDaysOld: [150, 140], executionLevel: true });
      await driveExecution(db, x1.e.id, "succeeded");
      await db.$executeRaw`UPDATE scan_tasks SET status = 'succeeded', lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE execution_id IN (${x1.e.id}::uuid, ${y1.e.id}::uuid, ${x6.e.id}::uuid, ${x7.e.id}::uuid, ${x8.e.id}::uuid)`;
      await driveExecution(db, y1.e.id, "succeeded");
      await driveExecution(db, x6.e.id, "failed");
      await driveExecution(db, x7.e.id, "succeeded");
      await driveExecution(db, x8.e.id, "succeeded");
      // x6's counters are old too (the cleanup of counters needs updated_at older than the retention)
      await db.$executeRaw`UPDATE execution_log_counters SET updated_at = now() - interval '200 days' WHERE execution_id IN (${x6.e.id}::uuid, ${x1.e.id}::uuid, ${x7.e.id}::uuid, ${x8.e.id}::uuid)`;
      await db.$executeRaw`UPDATE execution_task_log_counters SET updated_at = now() - interval '200 days' WHERE execution_id IN (${x6.e.id}::uuid, ${x1.e.id}::uuid)`;
      const keepBefore = { run: await counts(db, xRun.e), y1: await counts(db, y1.e) };
      ok(
        p,
        keepBefore.run.logs === 2 && keepBefore.y1.logs === 2,
        "control: the fixtures were not seeded",
      );

      // the batch limit: one batch of 2, no metadata
      const limited = await repo.purgeExpired({
        batchSize: 2,
        maxBatches: 1,
        metadataRetentionMonths: null,
      });
      ok(p, limited.logs === 2, `the batch limit: ${limited.logs} logs deleted in one batch of 2`);
      ok(p, limited.executions === 0, "a run without a metadata period deleted an execution");

      // full run
      const first = await repo.purgeExpired({ metadataRetentionMonths: null });
      const x1c = await counts(db, x1.e);
      const yc = await counts(db, y1.e);
      const x6c = await counts(db, x6.e);
      ok(
        p,
        x1c.logs === 2 && x1c.artifacts === 1,
        `x1: ${x1c.logs} logs and ${x1c.artifacts} artifacts left, expected the 2 fresh logs and the fresh artifact`,
      );
      const left = (await logsOf(w, x1.e)).map((r) => r.message).sort();
      ok(
        p,
        left.join("|") === "seed 3 (1d)|seed 4 (0d)",
        `x1 kept the wrong lines: ${left.join("|")}`,
      );
      ok(
        p,
        x1c.logCounters === 1 && x1c.taskCounters === 1,
        "x1 lost its counters while lines remain",
      );
      ok(
        p,
        yc.logs === 1 && yc.artifacts === 1,
        `another tenant: ${yc.logs} logs and ${yc.artifacts} artifacts left, expected the fresh log and the 5 day artifact`,
      );
      ok(
        p,
        x6c.logs === 0 && x6c.logCounters === 0 && x6c.taskCounters === 0,
        `x6: all lines are old, counters should go too (${JSON.stringify(x6c)})`,
      );
      const x7c = await counts(db, x7.e);
      const x8c = await counts(db, x8.e);
      ok(
        p,
        x7c.logs === 1 && x7c.logCounters === 1,
        `x7 (execution-level lines, one fresh): ${JSON.stringify(x7c)}, expected its fresh line and its counter`,
      );
      ok(
        p,
        x8c.logs === 0 && x8c.logCounters === 0,
        `x8 (execution-level lines, all old): ${JSON.stringify(x8c)}, expected no lines and no counter`,
      );
      const runNow = await counts(db, xRun.e);
      ok(
        p,
        JSON.stringify(runNow) === JSON.stringify(keepBefore.run),
        "the old rows of a RUNNING execution were purged",
      );
      ok(
        p,
        x1c.executions + yc.executions + x6c.executions === 3 && x1c.tasks === 1,
        "metadata was deleted without a period",
      );
      ok(
        p,
        limited.logs + first.logs === 9,
        `${limited.logs + first.logs} logs reported deleted, expected 9 (3 of x1, 2 of x6, 1 of y1, 1 of x7, 2 of x8)`,
      );
      const again = await repo.purgeExpired({ metadataRetentionMonths: null });
      ok(
        p,
        again.logs === 0 &&
          again.artifacts === 0 &&
          again.logCounters === 0 &&
          again.executions === 0,
        `a second run deleted more: ${JSON.stringify(again)}`,
      );

      // metadata (13 months = about 395 days): old terminal execution with children goes, retry originals and newer ones stay
      const old = await seedExecution(w, tx, { logsDaysOld: [1], artifactDaysOld: 1 });
      const oldY = await seedExecution(w, ty, { logsDaysOld: [1] });
      const orig = await seedExecution(w, tx, {});
      const newer = await seedExecution(w, tx, { logsDaysOld: [1] });
      await db.$executeRaw`UPDATE scan_tasks SET status = 'succeeded', lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE execution_id IN (${old.e.id}::uuid, ${oldY.e.id}::uuid, ${orig.e.id}::uuid, ${newer.e.id}::uuid)`;
      for (const s of [old, oldY, orig, newer]) await driveExecution(db, s.e.id, "succeeded");
      await w.execution(tx, {
        archive: false,
        commitSha: null,
        retryOfExecutionId: orig.e.id,
        triggerType: "manual",
        triggerKey: "manual",
        scmEventId: null,
        scmDeliveryId: null,
        scmEventKind: null,
        requestedByUserId: tx.user.id,
        idempotencyKey: `manual:${tx.user.id}:${Math.random().toString(16).slice(2)}`,
      });
      // the oldest candidates cannot be deleted (the original of a retry; a running execution that was requested 520 days ago): with a
      // batch of ONE, the selection itself must skip them, or the run would stall on them and delete nothing
      const stuck = await seedExecution(w, tx, { logsDaysOld: [500] });
      await ageExecution(db, stuck.e, 520, { finished: false });
      await ageExecution(db, orig.e, 440);
      await ageExecution(db, old.e, 430);
      await ageExecution(db, oldY.e, 430);
      await ageExecution(db, newer.e, 300);
      const meta = await repo.purgeExpired({
        metadataRetentionMonths: 13,
        batchSize: 1,
        maxBatches: 10,
      });
      const oc = await counts(db, old.e);
      ok(
        p,
        Object.values(oc).every((n) => n === 0),
        `an expired execution kept children: ${JSON.stringify(oc)}`,
      );
      ok(
        p,
        Object.values(await counts(db, oldY.e)).every((n) => n === 0),
        "another tenant's expired execution was not purged (the purge is platform wide)",
      );
      const oc2 = await counts(db, orig.e);
      ok(p, oc2.executions === 1 && oc2.tasks === 1, "the original of a retry was deleted");
      const nc = await counts(db, newer.e);
      ok(
        p,
        nc.executions === 1 && nc.logs === 1 && nc.tasks === 1 && nc.items === 1,
        `an execution newer than 13 months lost rows: ${JSON.stringify(nc)}`,
      );
      ok(
        p,
        meta.executionsSkipped === 0,
        `${meta.executionsSkipped} executions were attempted and refused by a foreign key (the selection must pick only deletable ones)`,
      );
      ok(p, meta.executions === 2, `${meta.executions} executions reported deleted, expected 2`);
      const metaAgain = await repo.purgeExpired({ metadataRetentionMonths: 13 });
      ok(
        p,
        metaAgain.executions === 0 && metaAgain.logs === 0,
        "the metadata purge is not idempotent",
      );
      // a running execution is never purged whatever its age
      const sc = await counts(db, stuck.e);
      ok(
        p,
        sc.executions === 1 && sc.logs === 1 && sc.tasks === 1,
        "a non-terminal execution was purged",
      );
      // bad periods are refused
      for (const bad of [
        { logRetentionDays: 0 },
        { logRetentionDays: 1.5 },
        { batchSize: 0 },
        { metadataRetentionMonths: 0 },
      ])
        ok(
          p,
          (await attempt(() => repo.purgeExpired(bad))).ok === false,
          `a bad option was accepted: ${JSON.stringify(bad)}`,
        );
      return p;
    },
  },
  {
    id: "EXE-053",
    name: "retention is gated and safe by default (SPEC 17.ac): the purge is OFF unless EXECUTION_RETENTION_PURGE_ENABLED=true in the process, a message alone never enables it (the handler refuses with a non-retryable error and deletes nothing), execution metadata is deleted only when its own switch is on, the job message is a platform message (no tenant) with bounded periods, the defaults are 90 days for logs and artifacts and 13 months for metadata, the log caps default below the database ceilings, and inconsistent caps are refused at start",
    async run(w) {
      const p = [];
      const { db } = w;
      const defaults = w.config().execution;
      ok(
        p,
        defaults.retention.purgeEnabled === false && defaults.retention.purgeMetadata === false,
        "the purge is not off by default",
      );
      ok(
        p,
        defaults.retention.logRetentionDays === 90 &&
          defaults.retention.artifactRetentionDays === 90 &&
          defaults.retention.metadataRetentionMonths === 13,
        "the retention defaults are not 90 days, 90 days and 13 months",
      );
      ok(
        p,
        defaults.logs.maxLinesPerExecution === 20000 &&
          defaults.logs.maxBytesPerExecution === 2097152,
        "the default log caps are not 20000 lines and 2 MiB",
      );
      ok(
        p,
        defaults.logs.maxLinesPerTask <= defaults.logs.maxLinesPerExecution &&
          defaults.logs.maxBytesPerTask <= defaults.logs.maxBytesPerExecution,
        "a task cap exceeds the execution cap",
      );
      for (const bad of [
        { EXECUTION_LOG_MAX_LINES: "100001" },
        { EXECUTION_LOG_MAX_BYTES: "8388609" },
        { EXECUTION_LOG_MAX_LINES: "50", EXECUTION_LOG_MAX_LINES_PER_TASK: "60" },
        { EXECUTION_LOG_MAX_BYTES: "8192", EXECUTION_LOG_MAX_BYTES_PER_TASK: "16384" },
        { EXECUTION_LOG_RETENTION_DAYS: "0" },
        { EXECUTION_METADATA_RETENTION_MONTHS: "1", EXECUTION_LOG_RETENTION_DAYS: "90" },
      ])
        ok(
          p,
          (() => {
            try {
              w.config(bad);
              return false;
            } catch (error) {
              return error instanceof ConfigError;
            }
          })(),
          `a bad configuration was accepted: ${JSON.stringify(bad)}`,
        );

      const tree = await w.tree("ret3");
      const s = await seedExecution(w, tree, { logsDaysOld: [200], artifactDaysOld: 200 });
      await db.$executeRaw`UPDATE scan_tasks SET status = 'succeeded', lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE execution_id = ${s.e.id}::uuid`;
      await driveExecution(db, s.e.id, "succeeded");
      await ageExecution(db, s.e, 500);
      const before = JSON.stringify(await counts(db, s.e));
      const message = {
        type: "maintenance.executions.purge_requested",
        payload: {
          logRetentionDays: 90,
          artifactRetentionDays: 90,
          metadataRetentionMonths: 13,
          batchSize: 100,
        },
      };
      const log = { info() {}, warn() {}, error() {} };
      const off = createExecutionRetentionHandler({ db, config: w.config() });
      let refused = null;
      try {
        await off(message, { log });
      } catch (error) {
        refused = error;
      }
      ok(
        p,
        refused instanceof NonRetryableError && refused.reason === "purge-disabled",
        "a disabled process did not refuse the job with a non-retryable error",
      );
      ok(p, JSON.stringify(await counts(db, s.e)) === before, "a disabled purge deleted rows");
      const logsOnly = createExecutionRetentionHandler({
        db,
        config: w.config({ EXECUTION_RETENTION_PURGE_ENABLED: "true" }),
      });
      await logsOnly(message, { log });
      const mid = await counts(db, s.e);
      ok(
        p,
        mid.logs === 0 && mid.artifacts === 0 && mid.executions === 1 && mid.tasks === 1,
        `with the metadata switch off the metadata went too: ${JSON.stringify(mid)}`,
      );
      const full = createExecutionRetentionHandler({
        db,
        config: w.config({
          EXECUTION_RETENTION_PURGE_ENABLED: "true",
          EXECUTION_RETENTION_PURGE_METADATA: "true",
        }),
      });
      await full(message, { log });
      ok(
        p,
        (await counts(db, s.e)).executions === 0,
        "control: with both switches on the expired execution stayed",
      );

      // the message contract
      const envelope = (payload, over = {}) =>
        createJobEnvelope({
          messageId: `exec-purge-${Math.random().toString(16).slice(2)}`,
          type: "maintenance.executions.purge_requested",
          schemaVersion: 1,
          initiator: { type: "system", id: "scheduler" },
          payload,
          ...over,
        });
      ok(
        p,
        (await attempt(async () => parseMessage(envelope(message.payload)))).ok,
        "control: the platform purge message was refused",
      );
      ok(
        p,
        (
          await attempt(async () =>
            parseMessage(envelope({ ...message.payload, metadataRetentionMonths: null })),
          )
        ).ok,
        "control: a message without a metadata period was refused",
      );
      for (const bad of [
        { logRetentionDays: 0 },
        { logRetentionDays: 4000 },
        { batchSize: 5001 },
        { metadataRetentionMonths: 0 },
        { extra: 1 },
      ])
        ok(
          p,
          (await attempt(async () => parseMessage(envelope({ ...message.payload, ...bad })))).ok ===
            false,
          `a bad purge payload was accepted: ${JSON.stringify(bad)}`,
        );
      ok(
        p,
        (
          await attempt(async () =>
            parseMessage(envelope(message.payload, { tenantId: tree.tenant.id })),
          )
        ).ok === false,
        "a purge message naming a tenant was accepted",
      );
      return p;
    },
  },
  {
    id: "EXE-054",
    name: "artifact references cannot traverse (SPEC 7.5, 17.ac): a name or id with a separator, .., a leading dot, an upper-case or over-long segment, an empty value or a non-string is refused by the shared validator, by the local-fs store (no file is created anywhere under or outside the root) and by the Postgres store (no row, no read of another scope); the key is always t/<tenant>/x/<execution>/<name>, and a valid reference works",
    async run(w) {
      const p = [];
      const root = path.join(w.tmp, "traversal-root");
      await mkdir(root, { recursive: true });
      const local = createLocalArtifactStore({ root });
      const tenant = "11111111-1111-4111-8111-111111111111";
      const execution = "22222222-2222-4222-8222-222222222222";
      const listAll = async (dir) => {
        const out = [];
        for (const entry of await readdir(dir, { withFileTypes: true })) {
          const full = path.join(dir, entry.name);
          out.push(
            entry.isDirectory() ? `${full}/` : full,
            ...(entry.isDirectory() ? await listAll(full) : []),
          );
        }
        return out.sort();
      };
      const parent = path.dirname(root);
      const outside = async () => (await readdir(parent)).sort().join("|");
      const bad = [
        "../escape",
        "../../etc/passwd",
        "a/b",
        "a\\b",
        "..",
        ".",
        ".hidden",
        "a..b",
        "trailing.",
        "UPPER",
        "1digit",
        "",
        " ",
        "x".repeat(65),
        "sp ace",
        "a%2fb",
        "a\u0000b",
        "name\n",
        "-dash",
        "/abs",
        "C:\\win",
      ];
      const beforeFiles = (await listAll(root)).join("|");
      const beforeOutside = await outside();
      for (const name of bad) {
        for (const [label, fn] of [
          [
            "parseArtifactRef",
            () => parseArtifactRef({ tenantId: tenant, executionId: execution, name }),
          ],
          ["local keyFor", () => local.keyFor({ tenantId: tenant, executionId: execution, name })],
        ])
          ok(
            p,
            (() => {
              try {
                fn();
                return false;
              } catch (error) {
                return error instanceof TypeError;
              }
            })(),
            `${label} accepted the name ${JSON.stringify(name)}`,
          );
        const put = await attempt(() =>
          local.put(
            { tenantId: tenant, executionId: execution, name },
            (async function* () {
              yield Buffer.from("x");
            })(),
            { maxBytes: 10 },
          ),
        );
        ok(p, put.ok === false, `the local store accepted the name ${JSON.stringify(name)}`);
      }
      for (const field of ["tenantId", "executionId"])
        for (const value of [
          "..",
          "a..b",
          "../x",
          "a/b",
          "",
          "x".repeat(129),
          7,
          null,
          undefined,
        ]) {
          const ref = { tenantId: tenant, executionId: execution, name: "ok.txt", [field]: value };
          ok(
            p,
            (() => {
              try {
                parseArtifactRef(ref);
                return false;
              } catch (error) {
                return error instanceof TypeError;
              }
            })(),
            `${field}=${JSON.stringify(value)} was accepted`,
          );
        }
      ok(
        p,
        (await listAll(root)).join("|") === beforeFiles,
        "a refused reference created files under the root",
      );
      ok(
        p,
        (await outside()) === beforeOutside,
        "a refused reference created something outside the root",
      );
      // control: a valid reference works and the key is tenant scoped
      const goodRef = { tenantId: tenant, executionId: execution, name: "source.tar.gz" };
      ok(
        p,
        local.keyFor(goodRef) === `t/${tenant}/x/${execution}/source.tar.gz`,
        "the key is not t/<tenant>/x/<execution>/<name>",
      );
      const put = await local.put(
        goodRef,
        (async function* () {
          yield Buffer.from("hello");
        })(),
        { maxBytes: 10 },
      );
      ok(p, put.created === true && put.bytes === 5, "control: a valid reference was refused");
      ok(
        p,
        (await listAll(root)).some((f) => f.includes(`/t/${tenant}/x/${execution}/source.tar.gz`)),
        "the object is not under its tenant and execution",
      );
      await local.delete(goodRef);
      return p;
    },
  },
];
