import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import {
  CHANGED_PATHS_ARTIFACT_NAME,
  createExecutionArtifactRepository,
  createExecutionRetentionRepository,
  createScanResultDetailRepository,
  createScanResultItemRepository,
  createScanTaskRepository,
  ITEM_INSERT_BATCH,
  createScanToolRunRepository,
  DETAIL_INSERT_BATCH,
  finishTaskTimeoutMs,
} from "@qmentisai/db";
import { createPostgresArtifactStore } from "@qmentisai/infra";
import { jsonbTextBytes } from "@qmentisai/shared";
import {
  CHANGED_PATHS_NAME,
  readChangedPaths,
} from "../../../../workers/src/execution/changed-paths.js";
import {
  detailRowBytes,
  mergeTaskCandidates,
  toStorageRows,
} from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import { TASK_A } from "./ensemble-fakes.js";
import { driveExecution, inState, queuedExecution, runningTask, taskData } from "./execution-db.js";
import { attempt, mustAccept, mustReject, probe } from "./pipeline-db.js";

/**
 * Scan engines, part D, database parts (ADR-008 area 18, SPEC scan-engines 7.3, 14.1 ENG-S08): the tool-run table, the 1:1 detail
 * table, the ensemble columns of scan_results and the two artifact classes, in process against the disposable PostgreSQL.
 * Every denial has a control. NOT proved here: any HTTP route or DTO for these tables (none exists before part K), the live
 * behaviour with a real worker, or that the migration applies to a database with data in these tables (they are new and empty).
 */

const same = (p, label, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want))
    p.push(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
};
/** jsonb does not keep key order: compare objects with sorted keys. */
const canon = (v) =>
  v && typeof v === "object"
    ? Object.fromEntries(
        Object.keys(v)
          .sort()
          .map((k) => [k, canon(v[k])]),
      )
    : v;
const hex = (n) => randomBytes(n).toString("hex");
const ST = "2026-11-19T10:00:00.000Z";
const EN = "2026-11-19T10:00:05.000Z";
const toolRun = (over = {}) => ({
  toolId: "trivy",
  toolVersion: "0.58.0",
  imageDigest: `sha256:${hex(32)}`,
  configDigest: hex(32),
  status: "succeeded",
  reason: null,
  exitCode: 0,
  startedAt: ST,
  finishedAt: EN,
  durationMs: 5000,
  scope: { kind: "full" },
  recordsSeen: 10,
  recordsDropped: 1,
  findingsMapped: 9,
  severityCounts: { high: 2 },
  truncated: false,
  limits: { memoryMb: 1024 },
  capacityWaitMs: 0,
  ...over,
});
const prov = (over = {}) => ({
  toolId: "trivy",
  toolVersion: "0.58.0",
  imageDigestShort: "sha256:abababab",
  ruleId: "CVE-2021-23337",
  severityRaw: "HIGH",
  severityScale: "trivy",
  rawRef: { toolRunId: randomUUID(), ordinal: 0 },
  ...over,
});
const detail = (over = {}) => ({
  schemaVersion: 1,
  dedupKey: "sca|pkg:npm/lodash@4.17.20|CVE-2021-23337",
  confidence: "high",
  confidenceBasis: "tool",
  severityAssumed: false,
  provenance: [prov()],
  advisories: [{ id: "CVE-2021-23337", family: "CVE" }],
  cwe: [77],
  evidence: null,
  scmRef: null,
  url: "https://github.com/o/r/blob/" + "a".repeat(40) + "/package-lock.json",
  scope: { kind: "full", inScope: true },
  extra: {
    component: { purl: "pkg:npm/lodash@4.17.20", name: "lodash", ecosystem: "npm" },
    ruleTool: "trivy",
    rawRef: { toolRunId: randomUUID(), ordinal: 0 },
  },
  ...over,
});
const detailRaw = (item, d) => ({
  tenantId: item.tenantId,
  executionId: item.executionId,
  scanResultId: item.scanResultId,
  itemOrdinal: item.ordinal,
  schemaVersion: d.schemaVersion,
  dedupKey: d.dedupKey,
  confidence: d.confidence,
  confidenceBasis: d.confidenceBasis,
  severityAssumed: d.severityAssumed,
  provenance: d.provenance,
  advisories: d.advisories,
  cwe: d.cwe,
  evidence: d.evidence ?? undefined,
  scmRef: d.scmRef ?? undefined,
  url: d.url ?? undefined,
  scope: d.scope,
  extra: d.extra,
});
const GHP = "ghp_abcdefghijklmnopqrstuv1234";

async function resultWithItems(c, execution, task, count = 3, over = {}) {
  const { db } = c;
  const result = await db.scanResult.create({
    data: {
      tenantId: task.tenantId,
      workspaceId: task.workspaceId,
      repositoryId: task.repositoryId,
      pipelineId: task.pipelineId,
      executionId: task.executionId,
      scanTaskId: task.id,
      attempt: task.attempt,
      scanType: task.scanType,
      engineId: "suite-engine",
      engineVersion: "1.0.0",
      completeness: "complete",
      ...over,
    },
  });
  const items = [];
  for (let i = 0; i < count; i += 1)
    items.push(
      await db.scanResultItem.create({
        data: {
          tenantId: task.tenantId,
          executionId: task.executionId,
          scanResultId: result.id,
          ordinal: i,
          kind: "vulnerability",
          severity: "low",
          title: `item ${i}`,
        },
      }),
    );
  return { result, items };
}

/** Findings of an SBOM with `n` distinct components (clones of one merged two-tool finding with a unique purl): valid for the real storage projection. */
function sbomFindings(n) {
  const cands = ["syft", "trivy"].map((tool) => {
    const rawRef = {
      toolRunId: randomUUID(),
      ordinal: 0,
    };
    return {
      schemaVersion: 1,
      scanType: "sbom",
      kind: "component",
      dedupKey: "sbom|pkg:npm/pkg0@1.0.0",
      title: "pkg0@1.0.0",
      severity: "info",
      severityAssumed: false,
      confidence: "medium",
      confidenceBasis: "tool",
      rule: { id: "component", tool },
      location: { path: "d/package-lock.json" },
      component: { purl: "pkg:npm/pkg0@1.0.0", name: "pkg0", version: "1.0.0", ecosystem: "npm" },
      locations: [{ path: "d/package-lock.json" }],
      locationCount: 1,
      rawRef,
      provenance: [
        {
          toolId: tool,
          toolVersion: "1",
          imageDigestShort: "none",
          severityRaw: "",
          severityScale: "none",
          rawRef,
        },
      ],
      taskRef: TASK_A,
    };
  });
  const [base] = mergeTaskCandidates({
    taskRef: TASK_A,
    scanType: "sbom",
    candidates: cands,
  }).findings;
  const out = [];
  for (let i = 0; i < n; i += 1) {
    const purl = `pkg:npm/pkg${i}@1.0.0`;
    out.push({
      ...base,
      dedupKey: `sbom|${purl}`,
      title: `pkg${i}@1.0.0`,
      component: { ...base.component, purl, name: `pkg${i}` },
    });
  }
  return out;
}

/**
 * The most time the write of a FULL-CAP result (50000 items and 50000 detail rows, ONE transaction) may take on the suite's database
 * before the check fails. Measured: about 11 s after the bulk inserts (SPEC 17.f; roughly 4 s of it the database's own per-row CHECK,
 * foreign key and trigger work, 2 s the items, the rest validation and transfer); the row-by-row code needs more than 90 s (1.8 ms per
 * detail row), so 25 s fails it by a factor of four and leaves 14 s of slack to the measured value for a slower or shared machine.
 * The default interactive transaction budget (15 s) is NOT the bound: 11 s is under it but without comfortable slack, which is why
 * `finishTaskTimeoutMs` scales the budget with the rows (asserted below), and an owner decision is recorded in SPEC 17.f.
 */
export const FULL_CAP_BOUND_MS = 25_000;
const CAP = 50_000;

const ENGINE_RESULT = (rows, over = {}) => ({
  engineId: "suite-engine",
  engineVersion: "1.0.0",
  completeness: "complete",
  truncated: false,
  severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: rows.items.length },
  items: rows.items,
  details: rows.details,
  ...over,
});

export const ENSEMBLE_DB_CHECKS = [
  {
    id: "ENG-S08a",
    name: "scan_tool_runs: tenant isolation, the attempt fence and the shape of a tool run (SPEC scan-engines 7.3, ENG-S08, ER-30): the chain columns come from the task row and a foreign tenant's ids insert nothing (0 rows) and read nothing; a mismatched chain is refused by the composite key; one row per (task, attempt, tool); a zombie attempt, a task that is not running and a terminal execution are refused by the database; rows are insert-only and cannot be truncated; Grype and every excluded tool, an unknown status or reason, a succeeded run with a reason, a failed run without one, a malformed or missing image digest (allowed only for sbom-lite and for skipped or unavailable runs), a malformed config digest, an impossible exit code, counters that do not add up, a non-object scope or limits, an oversized limits object and any credential shape in the free-form columns are refused for a raw writer too; each denial has a control",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      const repo = createScanToolRunRepository({ db });
      const eA = await inState(c, A, "running", 0);
      const eB = await inState(c, B, "running", 0);
      const taskA = await runningTask(c, eA, "sca");
      const taskB = await runningTask(c, eB, "sca");
      const base = {
        tenantId: eA.tenantId,
        executionId: eA.id,
        scanTaskId: taskA.id,
        attempt: taskA.attempt,
      };

      // controls
      const ins = await repo.insertMany({
        ...base,
        runs: [
          toolRun({ toolId: "trivy" }),
          toolRun({ toolId: "osv-scanner", status: "partial", reason: "output_invalid" }),
        ],
      });
      if (ins.inserted !== 2) p.push(`control: inserted ${ins.inserted}`);
      const listed = await repo.listForTask({
        tenantId: eA.tenantId,
        executionId: eA.id,
        scanTaskId: taskA.id,
      });
      if (
        listed.length !== 2 ||
        listed[0].toolId !== "osv-scanner" ||
        listed[1].imageDigest === undefined
      )
        p.push(`control: listed ${JSON.stringify(listed.map((r) => r.toolId))}`);
      if (
        (
          await repo.listForTask({
            tenantId: eA.tenantId,
            executionId: eA.id,
            scanTaskId: taskA.id,
            attempt: 0,
          })
        ).length !== 2
      )
        p.push("control: the attempt filter");
      if (
        (
          await repo.listForTask({
            tenantId: eA.tenantId,
            executionId: eA.id,
            scanTaskId: taskA.id,
            attempt: 1,
          })
        ).length !== 0
      )
        p.push("the attempt filter returns another attempt");
      mustAccept(
        p,
        "sbom-lite without an image",
        await attempt(() =>
          repo.insertMany({ ...base, runs: [toolRun({ toolId: "sbom-lite", imageDigest: null })] }),
        ),
      );
      // isolation
      const foreign = await repo.insertMany({
        tenantId: eB.tenantId,
        executionId: eA.id,
        scanTaskId: taskA.id,
        attempt: 0,
        runs: [toolRun({ toolId: "bandit" })],
      });
      if (foreign.inserted !== 0) p.push("a foreign tenant inserted a tool run of tenant A's task");
      const crossTask = await repo.insertMany({
        tenantId: eA.tenantId,
        executionId: eB.id,
        scanTaskId: taskA.id,
        attempt: 0,
        runs: [toolRun({ toolId: "bandit" })],
      });
      if (crossTask.inserted !== 0) p.push("a task was used with another execution id");
      for (const q of [
        { tenantId: eB.tenantId, executionId: eA.id, scanTaskId: taskA.id },
        { tenantId: eA.tenantId, executionId: eB.id, scanTaskId: taskA.id },
        { tenantId: eA.tenantId, executionId: eA.id, scanTaskId: taskB.id },
      ])
        if ((await repo.listForTask(q)).length !== 0)
          p.push(`a read crossed a boundary: ${JSON.stringify(Object.keys(q))}`);
      const chainOf = (t) => ({
        tenantId: t.tenantId,
        workspaceId: t.workspaceId,
        repositoryId: t.repositoryId,
        pipelineId: t.pipelineId,
        executionId: t.executionId,
        scanTaskId: t.id,
        attempt: t.attempt,
      });
      const rawRow = (task, over = {}) => ({
        ...chainOf(task),
        toolId: "bandit",
        toolVersion: "1",
        imageDigest: `sha256:${hex(32)}`,
        configDigest: hex(32),
        status: "succeeded",
        startedAt: ST,
        finishedAt: EN,
        durationMs: 1,
        ...over,
      });
      mustAccept(
        p,
        "a raw row",
        await attempt(() => db.scanToolRun.create({ data: rawRow(taskA, { toolId: "gosec" }) })),
      );
      mustReject(
        p,
        "another tenant's workspace",
        await attempt(() =>
          db.scanToolRun.create({
            data: rawRow(taskA, { workspaceId: taskB.workspaceId, toolId: "opengrep" }),
          }),
        ),
        "P2003",
      );
      mustReject(
        p,
        "another tenant",
        await attempt(() =>
          db.scanToolRun.create({
            data: rawRow(taskA, { tenantId: taskB.tenantId, toolId: "opengrep" }),
          }),
        ),
        "P2003",
      );
      mustReject(
        p,
        "another execution",
        await attempt(() =>
          db.scanToolRun.create({
            data: rawRow(taskA, { executionId: eB.id, toolId: "opengrep" }),
          }),
        ),
        "P2003",
      );
      mustReject(
        p,
        "a duplicate tool for the attempt",
        await attempt(() => db.scanToolRun.create({ data: rawRow(taskA, { toolId: "gosec" }) })),
        "P2002",
      );
      // the fence
      mustReject(
        p,
        "a zombie attempt",
        await attempt(() =>
          db.scanToolRun.create({ data: rawRow(taskA, { attempt: 1, toolId: "opengrep" }) }),
        ),
        "not the running attempt",
      );
      const queued = await db.scanTask.create({ data: taskData(eA, "sast") });
      mustReject(
        p,
        "a task that is not running",
        await attempt(() =>
          db.scanToolRun.create({ data: rawRow(queued, { toolId: "opengrep" }) }),
        ),
        "not the running attempt",
      );
      const eC = await inState(c, A, "running", 1);
      const taskC = await runningTask(c, eC, "sca");
      mustAccept(
        p,
        "a tool run before the execution ends",
        await attempt(() => db.scanToolRun.create({ data: rawRow(taskC, { toolId: "trivy" }) })),
      );
      await driveExecution(db, eC.id, "failed");
      mustReject(
        p,
        "a tool run for a terminal execution",
        await attempt(() =>
          db.scanToolRun.create({ data: rawRow(taskC, { toolId: "osv-scanner" }) }),
        ),
        "terminal",
      );
      // insert-only
      mustReject(
        p,
        "an UPDATE",
        await attempt(
          () =>
            db.$executeRaw`UPDATE scan_tool_runs SET status = 'failed' WHERE scan_task_id = ${taskA.id}::uuid`,
        ),
        "insert-only",
      );
      mustReject(
        p,
        "a TRUNCATE",
        await probe(db, (tx) => tx.$executeRawUnsafe("TRUNCATE scan_tool_runs")),
        "not allowed",
      );
      // shapes (each tool id is a fresh one so only the rejected value differs)
      const bad = async (label, over, needle = "scan_tool_runs_values_check") =>
        mustReject(
          p,
          label,
          await attempt(() =>
            db.scanToolRun.create({ data: rawRow(taskA, { toolId: "detect-secrets", ...over }) }),
          ),
          needle,
        );
      await bad("Grype", { toolId: "grype" });
      for (const id of ["cdxgen", "trufflehog", "brakeman", "codeql", "semgrep-oss", "mystery", ""])
        await bad(`tool ${id}`, { toolId: id });
      await bad("unknown status", { status: "unsupported" });
      await bad("unknown reason", { status: "failed", reason: "tool said no" });
      await bad("succeeded with a reason", { status: "succeeded", reason: "timeout" });
      for (const s of ["failed", "timed_out", "unavailable", "skipped"])
        await bad(`${s} without a reason`, { status: s, reason: null });
      await bad("a tag as image", { imageDigest: "trivy:latest" });
      await bad("a short digest", { imageDigest: "sha256:abc" });
      await bad("an upper case digest", { imageDigest: `sha256:${"A".repeat(64)}` });
      await bad("no image for a container tool", { imageDigest: null });
      await bad("a short config digest", { configDigest: "abc" });
      await bad("a short rulepack digest", { rulepackDigest: "abc" });
      await bad("a short snapshot digest", { dbSnapshotSha256: "abc" });
      await bad("exit code 300", { exitCode: 300 });
      await bad("negative exit code", { exitCode: -1 });
      await bad("exit code 256", { exitCode: 256 });
      await bad("finished before started", { startedAt: EN, finishedAt: ST });
      await bad("negative duration", { durationMs: -1 });
      await bad("dropped above seen", { recordsSeen: 1, recordsDropped: 2 });
      await bad("mapped above seen", { recordsSeen: 1, findingsMapped: 2 });
      await bad("an empty version", { toolVersion: "" });
      await bad("a version with a control character", { toolVersion: "1\n2" });
      await bad("scope as an array", { scope: [] });
      await bad("limits as a string", { limits: "x" });
      await bad("limits over 4 KiB", { limits: { blob: "x".repeat(5000) } });
      await bad(
        "a credential in the version",
        { toolVersion: GHP },
        "scan_tool_runs_no_credentials_check",
      );
      await bad(
        "a credential in the scope",
        { scope: { note: `Bearer ${"a".repeat(20)}` } },
        "scan_tool_runs_no_credentials_check",
      );
      await bad(
        "a private key in the limits",
        { limits: { k: "-----BEGIN RSA PRIVATE KEY-----" } },
        "scan_tool_runs_no_credentials_check",
      );
      mustAccept(
        p,
        "skipped without an image (control)",
        await attempt(() =>
          db.scanToolRun.create({
            data: rawRow(taskA, {
              toolId: "detect-secrets",
              status: "skipped",
              reason: "no_applicable_files",
              imageDigest: null,
              exitCode: undefined,
            }),
          }),
        ),
      );
      // every accepted word is accepted (probes are rolled back): statuses, reasons, tools, exit codes, equal timestamps
      const eD = await inState(c, A, "running", 1);
      const taskD = await runningTask(c, eD, "sbom");
      const ok1 = (label, over) =>
        probe(db, (tx) =>
          tx.scanToolRun.create({ data: rawRow(taskD, { toolId: "gitleaks", ...over }) }),
        ).then((r) => mustAccept(p, label, r));
      for (const word of [
        "image_unavailable",
        "db_unavailable",
        "db_stale",
        "timeout",
        "out_of_memory",
        "exit_code",
        "output_invalid",
        "output_too_large",
        "sandbox_error",
        "killed",
        "no_applicable_files",
        "config_invalid",
        "capacity",
        "cancelled",
        "deadline",
      ])
        await ok1(`reason ${word}`, { status: "failed", reason: word });
      for (const status of ["succeeded", "partial", "cancelled"])
        await ok1(`status ${status}`, { status });
      for (const status of ["failed", "timed_out", "unavailable", "skipped"])
        await ok1(`status ${status}`, { status, reason: "timeout" });
      for (const toolId of [
        "syft",
        "trivy",
        "osv-scanner",
        "opengrep",
        "bandit",
        "gosec",
        "gitleaks",
        "detect-secrets",
      ])
        await ok1(`tool ${toolId}`, { toolId });
      await ok1("tool sbom-lite", { toolId: "sbom-lite", imageDigest: null });
      await ok1("unavailable without an image", {
        status: "unavailable",
        reason: "image_unavailable",
        imageDigest: null,
      });
      await ok1("exit code 0", { exitCode: 0 });
      await ok1("exit code 255", { exitCode: 255 });
      await ok1("equal start and finish", { startedAt: ST, finishedAt: ST, durationMs: 0 });
      await ok1("dropped equal to seen", { recordsSeen: 3, recordsDropped: 3, findingsMapped: 0 });
      await ok1("mapped equal to seen", { recordsSeen: 3, recordsDropped: 0, findingsMapped: 3 });
      await ok1("optional digests", {
        rulepackDigest: hex(32),
        dbSnapshotSha256: hex(32),
        dbBuiltAt: ST,
      });
      await ok1("limits of 4096 bytes", {
        limits: { blob: "x".repeat(4096 - jsonbTextBytes({ blob: "" })) },
      });
      await ok1("scope of 4096 bytes", {
        scope: { blob: "x".repeat(4096 - jsonbTextBytes({ blob: "" })) },
      });
      await ok1("severity counts of 1024 bytes", {
        severityCounts: { blob: "x".repeat(1024 - jsonbTextBytes({ blob: "" })) },
      });
      const over = (label, over2) =>
        probe(db, (tx) =>
          tx.scanToolRun.create({ data: rawRow(taskD, { toolId: "gitleaks", ...over2 }) }),
        ).then((r) => mustReject(p, label, r, "scan_tool_runs_values_check"));
      await over("limits of 4097 bytes", {
        limits: { blob: "x".repeat(4097 - jsonbTextBytes({ blob: "" })) },
      });
      await over("scope of 4097 bytes", {
        scope: { blob: "x".repeat(4097 - jsonbTextBytes({ blob: "" })) },
      });
      await over("severity counts of 1025 bytes", {
        severityCounts: { blob: "x".repeat(1025 - jsonbTextBytes({ blob: "" })) },
      });
      await over("a version of 101 characters", { toolVersion: "v".repeat(101) });
      await ok1("a version of 100 characters", { toolVersion: "v".repeat(100) });
      // the credential predicate itself: every shape, and the near misses
      const shape = async (text) =>
        (await db.$queryRaw`SELECT qm_has_credential_shape(${text}) AS hit`)[0].hit;
      for (const yes of [
        "x ghp_12345678 y",
        "ghs_ABCDEFGH",
        "gho_abcdefgh",
        "ghu_abcdefgh",
        "ghr_abcdefgh",
        "github_pat_12345678",
        "Bearer abcdefgh",
        "bearer   abcdefgh12",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "AKIAABCDEFGHIJKLMNOP",
        "https://user:secret@host/x",
        "ssh://u:p@h",
        "https://h/x?access_token=abcdef",
        "https://h/x?a=1&token=abcdef",
        "?X-Amz-Signature=abcdef",
        "&sig=abcdef",
      ])
        if (!(await shape(yes))) p.push(`credential shape not detected: ${yes}`);
      for (const no of [
        "plain text",
        "gha_12345678",
        "ghp_1234567",
        "github_pat_1234567",
        "Bearer abc",
        "-----BEGIN CERTIFICATE-----",
        "AKIAABCDEFGHIJKLMNO",
        "https://host/path",
        "https://user@host/x",
        "?token=abcde",
        "mailto:a@b.c",
      ])
        if (await shape(no)) p.push(`credential shape false positive: ${no}`);
      if ((await db.$queryRaw`SELECT qm_has_credential_shape(NULL) AS hit`)[0].hit !== false)
        p.push("a NULL text is a credential");
      // a minimal run: every optional counter and flag takes its default
      await repo.insertMany({
        ...base,
        runs: [
          {
            toolId: "bandit",
            toolVersion: "1",
            imageDigest: `sha256:${hex(32)}`,
            configDigest: hex(32),
            status: "succeeded",
            startedAt: ST,
            finishedAt: EN,
            durationMs: 1,
          },
        ],
      });
      const minimal = await db.scanToolRun.findFirst({
        where: { scanTaskId: taskA.id, toolId: "bandit" },
      });
      if (
        !minimal ||
        minimal.recordsSeen !== 0 ||
        minimal.recordsDropped !== 0 ||
        minimal.findingsMapped !== 0 ||
        minimal.truncated !== false ||
        minimal.capacityWaitMs !== 0 ||
        minimal.exitCode !== null ||
        minimal.reason !== null ||
        minimal.rulepackDigest !== null ||
        JSON.stringify(minimal.scope) !== "{}" ||
        JSON.stringify(minimal.limits) !== "{}" ||
        JSON.stringify(minimal.severityCounts) !== "{}"
      )
        p.push(`a minimal run did not take its defaults: ${JSON.stringify(minimal)}`);
      const n = await db.scanToolRun.count({ where: { scanTaskId: taskA.id } });
      if (n !== 6)
        p.push(
          `rows of the task: ${n}, expected 6 (trivy, osv-scanner, sbom-lite, gosec, detect-secrets skipped, bandit minimal)`,
        );
      return p;
    },
  },
  {
    id: "ENG-S08b",
    name: "scan_result_item_details, the ensemble columns of scan_results and the artifact classes (SPEC scan-engines 7.3, D-8, ENG-S08): a detail row is written only for an item of the same tenant, execution and result (a foreign tenant inserts and reads nothing; a wrong ordinal, tenant or result is refused by the composite keys), one per item, insert-only, no truncate and none for a terminal execution; schema version 1 only, confidence and basis words, 1 to 6 provenance entries of at most 600 bytes, at most 20 advisories and 10 CWE numbers, evidence at most 8 KiB, an https url, the whole row at most 16 KiB (each part valid alone) and any credential shape in any part are refused for a raw writer; a result with toolsDegraded above 0 must be incomplete, coverage needs schema version 2, a known state and well-formed parts; a manifest hash is 64 lower-case hex; the standard artifact class keeps 1 MiB / 20 objects / 8 MiB and the sbom_document class allows 16 MiB per document, 20 documents and 64 MiB per execution, independently of each other, through the store and for a raw writer",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      const repo = createScanResultDetailRepository({ db });
      const eA = await inState(c, A, "running", 0);
      const eB = await inState(c, B, "running", 0);
      const taskA = await runningTask(c, eA, "sca");
      const taskB = await runningTask(c, eB, "sca");
      const { result, items } = await resultWithItems(c, eA, taskA, 4);
      const resultB = await resultWithItems(c, eB, taskB, 2);
      const base = { tenantId: eA.tenantId, executionId: eA.id, scanResultId: result.id };
      // controls and isolation
      const ins = await repo.insertMany({
        ...base,
        details: [detail(), detail({ dedupKey: "sca|pkg:npm/a@1|CVE-1-1" })],
      });
      if (ins.inserted !== 2) p.push(`control: inserted ${ins.inserted}`);
      const listed = await repo.listForResult(base);
      if (
        listed.length !== 2 ||
        listed[0].ordinal !== 0 ||
        listed[1].title !== "item 1" ||
        listed[0].provenance.length !== 1
      )
        p.push(`control: listed ${JSON.stringify(listed.map((r) => r.ordinal))}`);
      // fields set through the repository are stored as given, absent ones take their defaults
      const viaRepo = await resultWithItems(c, eA, await runningTask(c, eA, "secrets"), 2);
      const fullBase = {
        tenantId: eA.tenantId,
        executionId: eA.id,
        scanResultId: viaRepo.result.id,
      };
      const withEverything = detail({
        severityAssumed: true,
        evidence: { kind: "line", snippet: "x" },
        scmRef: { provider: "github", repoFullName: "o/r", commitSha: "a".repeat(40) },
      });
      const bareDetail = {
        schemaVersion: 1,
        dedupKey: "sca|pkg:npm/a@1|CVE-1-1",
        confidence: "low",
        confidenceBasis: "tool",
        provenance: [prov()],
      };
      const stored = await repo.insertMany({ ...fullBase, details: [withEverything, bareDetail] });
      if (stored.inserted !== 2) p.push(`control: repository details ${stored.inserted}`);
      const rows = await repo.listForResult(fullBase);
      if (
        rows[0]?.severityAssumed !== true ||
        rows[0]?.evidence?.snippet !== "x" ||
        rows[0]?.scmRef?.provider !== "github" ||
        typeof rows[0]?.url !== "string"
      )
        p.push(`details set through the repository were not stored: ${JSON.stringify(rows[0])}`);
      if (
        rows[1]?.severityAssumed !== false ||
        rows[1]?.evidence !== null ||
        rows[1]?.scmRef !== null ||
        rows[1]?.url !== null ||
        rows[1]?.advisories?.length !== 0 ||
        rows[1]?.cwe?.length !== 0 ||
        JSON.stringify(rows[1]?.scope) !== "{}" ||
        JSON.stringify(rows[1]?.extra) !== "{}"
      )
        p.push(`absent detail fields did not take their defaults: ${JSON.stringify(rows[1])}`);
      if (
        (
          await repo.insertMany({
            tenantId: eB.tenantId,
            executionId: eA.id,
            scanResultId: result.id,
            details: [detail()],
          })
        ).inserted !== 0
      )
        p.push("a foreign tenant wrote a detail row");
      if (
        (
          await repo.insertMany({
            tenantId: eA.tenantId,
            executionId: eB.id,
            scanResultId: result.id,
            details: [detail()],
          })
        ).inserted !== 0
      )
        p.push("a detail row was written with another execution id");
      if (
        (await repo.insertMany({ ...base, details: [detail({ itemOrdinal: 99 })] })).inserted !== 0
      )
        p.push("a detail row without an item");
      for (const q of [
        { tenantId: eB.tenantId, executionId: eA.id, scanResultId: result.id },
        { tenantId: eA.tenantId, executionId: eB.id, scanResultId: result.id },
        { ...base, scanResultId: resultB.result.id },
      ])
        if ((await repo.listForResult(q)).length !== 0)
          p.push(`a detail read crossed a boundary: ${JSON.stringify(Object.keys(q))}`);
      const it = (ordinal, tenant = items[0].tenantId) => ({
        ...items[0],
        ordinal,
        tenantId: tenant,
      });
      mustReject(
        p,
        "a second detail for an ordinal",
        await attempt(() => db.scanResultItemDetail.create({ data: detailRaw(it(0), detail()) })),
        "P2002",
      );
      mustReject(
        p,
        "an ordinal without an item",
        await attempt(() => db.scanResultItemDetail.create({ data: detailRaw(it(50), detail()) })),
        "P2003",
      );
      mustReject(
        p,
        "another tenant's id",
        await attempt(() =>
          db.scanResultItemDetail.create({ data: detailRaw(it(2, eB.tenantId), detail()) }),
        ),
        "P2003",
      );
      mustReject(
        p,
        "another result of the same tenant",
        await attempt(() =>
          db.scanResultItemDetail.create({
            data: detailRaw({ ...it(2), executionId: eB.id }, detail()),
          }),
        ),
        "P2003",
      );
      mustReject(
        p,
        "an UPDATE",
        await attempt(
          () =>
            db.$executeRaw`UPDATE scan_result_item_details SET confidence = 'low' WHERE scan_result_id = ${result.id}::uuid`,
        ),
        "insert-only",
      );
      mustReject(
        p,
        "a TRUNCATE",
        await probe(db, (tx) => tx.$executeRawUnsafe("TRUNCATE scan_result_item_details")),
        "not allowed",
      );
      // shapes: ordinal 2 is never inserted by a rejected row, ordinal 3 is the exact-size control
      const bad = async (label, over, needle = "scan_result_item_details_values_check") =>
        mustReject(
          p,
          label,
          await attempt(() =>
            db.scanResultItemDetail.create({ data: detailRaw(it(2), detail(over)) }),
          ),
          needle,
        );
      await bad("schema version 2", { schemaVersion: 2 });
      await bad("schema version 0", { schemaVersion: 0 });
      await bad("confidence certain", { confidence: "certain" });
      await bad("basis other", { confidenceBasis: "magic" });
      await bad("empty dedup key", { dedupKey: "" });
      await bad("dedup key over 600", { dedupKey: "x".repeat(601) });
      await bad("provenance empty", { provenance: [] });
      await bad("provenance not an array", { provenance: { a: 1 } });
      await bad("provenance with 7 entries", {
        provenance: Array.from({ length: 7 }, () => prov()),
      });
      await bad("provenance entry over 600 bytes", {
        provenance: [prov({ ruleId: "x".repeat(700) })],
      });
      await bad("provenance entry not an object", { provenance: ["x"] });
      await bad("21 advisories", {
        advisories: Array.from({ length: 21 }, (_, i) => ({ id: `CVE-1-${i}`, family: "CVE" })),
      });
      await bad("advisories as an object", { advisories: {} });
      await bad("11 CWE numbers", { cwe: Array.from({ length: 11 }, (_, i) => i + 1) });
      await bad("evidence over 8 KiB", { evidence: { kind: "line", snippet: "x".repeat(8200) } });
      await bad("evidence as an array", { evidence: [] });
      await bad("http url", { url: "http://github.com/x" });
      await bad("javascript url", { url: "javascript:alert(1)" });
      await bad("url with a space", { url: "https://github.com/a b" });
      await bad("url over 2000", { url: `https://github.com/${"x".repeat(2000)}` });
      await bad("scope as an array", { scope: [] });
      await bad("extra as a string", { extra: "x" });
      await bad("a row over 16 KiB with every part valid", {
        provenance: Array.from({ length: 6 }, () => prov({ ruleId: "r".repeat(300) })),
        evidence: { kind: "block", snippet: "e".repeat(7500) },
        extra: { blob: "x".repeat(6000) },
      });
      await bad(
        "a credential in the dedup key",
        { dedupKey: `secrets|${GHP}` },
        "scan_result_item_details_no_credentials_check",
      );
      await bad(
        "a credential in the extra part",
        { extra: { note: GHP } },
        "scan_result_item_details_no_credentials_check",
      );
      await bad(
        "a private key in the evidence",
        { evidence: { kind: "line", snippet: "-----BEGIN PRIVATE KEY-----" } },
        "scan_result_item_details_no_credentials_check",
      );
      await bad(
        "an AWS key in the provenance",
        { provenance: [prov({ ruleId: "AKIAIOSFODNN7EXAMPLE" })] },
        "scan_result_item_details_no_credentials_check",
      );
      await bad(
        "basic auth in the scm reference",
        { scmRef: { provider: "github", repoFullName: "https://u:pw12345678@host/x" } },
        "scan_result_item_details_no_credentials_check",
      );
      mustAccept(
        p,
        "evidence of exactly 8192 bytes (control)",
        await attempt(() =>
          db.scanResultItemDetail.create({
            data: detailRaw(
              it(2),
              detail({
                evidence: {
                  kind: "line",
                  snippet: "x".repeat(8192 - jsonbTextBytes({ kind: "line", snippet: "" })),
                },
              }),
            ),
          }),
        ),
      );
      mustAccept(
        p,
        "six provenance entries (control)",
        await attempt(() =>
          db.scanResultItemDetail.create({
            data: detailRaw(
              it(3),
              detail({
                provenance: Array.from({ length: 6 }, () => prov()),
                cwe: Array.from({ length: 10 }, (_, i) => i + 1),
                advisories: Array.from({ length: 20 }, (_, i) => ({
                  id: `CVE-1-${i}`,
                  family: "CVE",
                })),
              }),
            ),
          }),
        ),
      );
      // a terminal execution takes no detail row
      const eT = await inState(c, A, "running", 1);
      const taskT = await runningTask(c, eT, "sca");
      const rt = await resultWithItems(c, eT, taskT, 2);
      mustAccept(
        p,
        "a detail row before the end (control)",
        await attempt(() =>
          repo.insertMany({
            tenantId: eT.tenantId,
            executionId: eT.id,
            scanResultId: rt.result.id,
            details: [detail()],
          }),
        ),
      );
      await driveExecution(db, eT.id, "failed");
      mustReject(
        p,
        "a detail row for a terminal execution",
        await attempt(() =>
          repo.insertMany({
            tenantId: eT.tenantId,
            executionId: eT.id,
            scanResultId: rt.result.id,
            details: [detail({ itemOrdinal: 1 })],
          }),
        ),
        "terminal",
      );
      // ---- scan_results: coverage and manifest
      const eR = await inState(c, A, "running", 0);
      const tasks = {
        sbom: await runningTask(c, eR, "sbom"),
        sast: await runningTask(c, eR, "sast"),
      };
      const mk = (task, over) => resultWithItems(c, eR, task, 0, over);
      const cov = (over = {}) => ({
        state: "complete",
        coverageGaps: [],
        toolsDegraded: 0,
        tools: [{ toolId: "syft", status: "succeeded" }],
        ...over,
      });
      const badR = async (label, over, needle = "scan_results_ensemble_check") =>
        mustReject(p, label, await attempt(() => mk(tasks.sbom, over)), needle);
      await badR("degraded but complete", {
        schemaVersion: 2,
        completeness: "complete",
        coverage: cov({ state: "degraded", toolsDegraded: 1 }),
      });
      await badR("coverage on a version 1 result", { schemaVersion: 1, coverage: cov() });
      await badR("a manifest on a version 1 result", {
        schemaVersion: 1,
        runManifestSha256: hex(32),
      });
      await badR("schema version 3", { schemaVersion: 3 });
      await badR("an unknown coverage state", {
        schemaVersion: 2,
        coverage: cov({ state: "great" }),
      });
      await badR("toolsDegraded as a string", {
        schemaVersion: 2,
        completeness: "incomplete",
        coverage: cov({ toolsDegraded: "1" }),
      });
      await badR("negative toolsDegraded", {
        schemaVersion: 2,
        completeness: "incomplete",
        coverage: cov({ toolsDegraded: -1 }),
      });
      await badR("toolsDegraded missing", {
        schemaVersion: 2,
        coverage: { state: "complete", coverageGaps: [], tools: [] },
      });
      await badR("coverage gaps not a list", {
        schemaVersion: 2,
        coverage: cov({ coverageGaps: {} }),
      });
      await badR("coverage as an array", { schemaVersion: 2, coverage: [] });
      await badR("more than 12 tools", {
        schemaVersion: 2,
        coverage: cov({
          tools: Array.from({ length: 13 }, () => ({ toolId: "x", status: "succeeded" })),
        }),
      });
      await badR("a short manifest hash", { schemaVersion: 2, runManifestSha256: "abc" });
      await badR("an upper case manifest hash", {
        schemaVersion: 2,
        runManifestSha256: "A".repeat(64),
      });
      mustAccept(
        p,
        "a degraded incomplete ensemble result (control)",
        await attempt(() =>
          mk(tasks.sbom, {
            schemaVersion: 2,
            completeness: "incomplete",
            runManifestSha256: hex(32),
            coverage: cov({ state: "degraded", toolsDegraded: 2 }),
          }),
        ),
      );
      mustAccept(
        p,
        "a complete ensemble result with no degraded tool (control)",
        await attempt(() =>
          mk(tasks.sast, {
            schemaVersion: 2,
            completeness: "complete",
            coverage: cov({ toolsDegraded: 0 }),
          }),
        ),
      );
      const eL = await inState(c, A, "running", 1);
      mustAccept(
        p,
        "a legacy result without the new columns (control)",
        await attempt(async () => resultWithItems(c, eL, await runningTask(c, eL, "sbom"), 1)),
      );
      // ---- artifact classes
      const eX = await inState(c, A, "running", 0);
      const eY = await inState(c, B, "running", 0);
      const store = createPostgresArtifactStore({
        repository: createExecutionArtifactRepository({ db }),
      });
      const repoForStore = createExecutionArtifactRepository({ db });
      for (const bad of [0, -1, 1.5, 16 * 1048576 + 1, "5"]) {
        const r = await attempt(async () =>
          createPostgresArtifactStore({ repository: repoForStore, sbomMaxBytes: bad }),
        );
        if (r.ok) p.push(`a store with sbomMaxBytes ${JSON.stringify(bad)} was created`);
        else if (!r.message.includes("sbomMaxBytes must be an integer between 1 and 16777216"))
          p.push(`sbomMaxBytes ${JSON.stringify(bad)}: ${r.message.slice(0, 80)}`);
      }
      mustAccept(
        p,
        "a store with sbomMaxBytes 1",
        await attempt(async () =>
          createPostgresArtifactStore({ repository: repoForStore, sbomMaxBytes: 1 }),
        ),
      );
      mustAccept(
        p,
        "a store with sbomMaxBytes 16 MiB",
        await attempt(async () =>
          createPostgresArtifactStore({ repository: repoForStore, sbomMaxBytes: 16 * 1048576 }),
        ),
      );
      const ref = (e, name) => ({ tenantId: e.tenantId, executionId: e.id, name });
      const MiB = 1048576;
      const put = (e, name, size, opts = {}) =>
        attempt(() =>
          store.put(ref(e, name), Buffer.alloc(size, 0x61), {
            mediaType: "application/octet-stream",
            ...opts,
          }),
        );
      mustAccept(p, "a standard object of 1 MiB (control)", await put(eX, "std-1", MiB));
      const tooBig = await put(eX, "std-2", MiB + 1);
      if (tooBig.ok || !tooBig.message.includes("exceeds"))
        p.push(`a standard object over 1 MiB: ${tooBig.message.slice(0, 80)}`);
      const viaClassName = await put(eX, "std-3", MiB + 1, { artifactClass: "weird" });
      if (viaClassName.ok) p.push("an unknown artifact class was accepted by the store");
      mustReject(
        p,
        "an unknown class for a raw writer",
        await attempt(() =>
          db.executionArtifact.create({
            data: {
              tenantId: eX.tenantId,
              workspaceId: eX.workspaceId,
              repositoryId: eX.repositoryId,
              pipelineId: eX.pipelineId,
              executionId: eX.id,
              name: "raw-class",
              mediaType: "text/plain",
              sizeBytes: 1,
              sha256: hex(32),
              content: Buffer.from("a"),
              artifactClass: "weird",
            },
          }),
        ),
        "execution_artifacts_values_check",
      );
      mustReject(
        p,
        "a raw standard object over 1 MiB",
        await attempt(() =>
          db.executionArtifact.create({
            data: {
              tenantId: eX.tenantId,
              workspaceId: eX.workspaceId,
              repositoryId: eX.repositoryId,
              pipelineId: eX.pipelineId,
              executionId: eX.id,
              name: "raw-big",
              mediaType: "application/octet-stream",
              sizeBytes: MiB + 1,
              sha256: hex(32),
              content: Buffer.alloc(MiB + 1),
            },
          }),
        ),
        "execution_artifacts_values_check",
      );
      const rawArtifact = (name, over = {}) => ({
        tenantId: eX.tenantId,
        workspaceId: eX.workspaceId,
        repositoryId: eX.repositoryId,
        pipelineId: eX.pipelineId,
        executionId: eX.id,
        name,
        mediaType: "text/plain",
        sizeBytes: 1,
        sha256: hex(32),
        content: Buffer.from("a"),
        ...over,
      });
      mustAccept(
        p,
        "a raw object (control)",
        await attempt(() => db.executionArtifact.create({ data: rawArtifact("raw-ok") })),
      );
      mustAccept(
        p,
        "an empty raw object (control)",
        await attempt(() =>
          db.executionArtifact.create({
            data: rawArtifact("raw-empty", { sizeBytes: 0, content: Buffer.alloc(0) }),
          }),
        ),
      );
      mustReject(
        p,
        "a media type outside the list",
        await attempt(() =>
          db.executionArtifact.create({ data: rawArtifact("raw-mt", { mediaType: "text/html" }) }),
        ),
        "execution_artifacts_values_check",
      );
      mustReject(
        p,
        "a size that differs from the content",
        await attempt(() =>
          db.executionArtifact.create({ data: rawArtifact("raw-size", { sizeBytes: 5 }) }),
        ),
        "execution_artifacts_values_check",
      );
      mustReject(
        p,
        "a malformed hash",
        await attempt(() =>
          db.executionArtifact.create({ data: rawArtifact("raw-sha", { sha256: "abc" }) }),
        ),
        "execution_artifacts_values_check",
      );
      mustAccept(
        p,
        "an sbom document over 1 MiB (control)",
        await put(eX, "sbom-1", MiB + 1, { artifactClass: "sbom_document" }),
      );
      mustAccept(
        p,
        "an sbom document of exactly 16 MiB (control)",
        await put(eX, "sbom-2", 16 * MiB, { artifactClass: "sbom_document" }),
      );
      const over16 = await put(eX, "sbom-3", 16 * MiB + 1, { artifactClass: "sbom_document" });
      if (over16.ok || !over16.message.includes("exceeds"))
        p.push("an sbom document over 16 MiB was accepted by the store");
      mustReject(
        p,
        "a raw sbom document over 16 MiB",
        await attempt(() =>
          db.executionArtifact.create({
            data: {
              tenantId: eX.tenantId,
              workspaceId: eX.workspaceId,
              repositoryId: eX.repositoryId,
              pipelineId: eX.pipelineId,
              executionId: eX.id,
              name: "raw-sbom-big",
              mediaType: "application/octet-stream",
              sizeBytes: 16 * MiB + 1,
              sha256: hex(32),
              content: Buffer.alloc(16 * MiB + 1),
              artifactClass: "sbom_document",
            },
          }),
        ),
        "execution_artifacts_values_check",
      );
      mustAccept(
        p,
        "a second 16 MiB document (control)",
        await put(eX, "sbom-4", 16 * MiB, { artifactClass: "sbom_document" }),
      );
      mustAccept(
        p,
        "a third 16 MiB document (control)",
        await put(eX, "sbom-5", 15 * MiB, {
          artifactClass: "sbom_document",
        }),
      );
      const used = (
        await db.$queryRaw`SELECT COALESCE(sum(size_bytes), 0)::bigint AS n FROM execution_artifacts WHERE execution_id = ${eX.id}::uuid AND artifact_class = 'sbom_document'`
      )[0].n;
      const rest = 64 * MiB - Number(used);
      if (rest < 1 || rest > 16 * MiB) p.push(`fixture: the remainder ${rest} is not a legal size`);
      else
        mustAccept(
          p,
          "the object that fills the execution to exactly 64 MiB (control)",
          await put(eX, "sbom-6", rest, { artifactClass: "sbom_document" }),
        );
      const full = await put(eX, "sbom-7", 1, { artifactClass: "sbom_document" });
      if (full.ok || !full.message.includes("artifact cap"))
        p.push(
          `one byte over 64 MiB per execution: ${full.ok ? "accepted" : full.message.slice(0, 100)}`,
        );
      // the classes count separately: the sbom class is full, a standard object still fits, and the 8 MiB / 20 caps of the standard class hold
      mustAccept(
        p,
        "a standard object while the sbom class is full (control)",
        await put(eX, "std-4", 1000),
      );
      for (let i = 0; i < 6; i += 1)
        mustAccept(p, `standard fill ${i}`, await put(eX, `fill-${i}`, MiB));
      // standard used: std-1 (1 MiB) + std-4 (1000 B) + 6 MiB; a 1 MiB object more is the 8 MiB boundary
      const standardUsed = Number(
        (
          await db.$queryRaw`SELECT COALESCE(sum(size_bytes), 0)::bigint AS n FROM execution_artifacts WHERE execution_id = ${eX.id}::uuid AND artifact_class = 'standard'`
        )[0].n,
      );
      const fillTo8 = 8 * MiB - standardUsed;
      mustAccept(
        p,
        "the object that fills the standard class to exactly 8 MiB (control)",
        await put(eX, "fill-last", fillTo8),
      );
      const std9 = await put(eX, "fill-over", 1);
      if (std9.ok || !std9.message.includes("artifact cap"))
        p.push("one byte over 8 MiB of the standard class");
      // 20 documents of the sbom class
      for (let i = 0; i < 20; i += 1)
        mustAccept(
          p,
          `sbom count ${i}`,
          await put(eY, `doc-${i}`, 10, { artifactClass: "sbom_document" }),
        );
      const doc21 = await put(eY, "doc-20", 10, { artifactClass: "sbom_document" });
      if (doc21.ok || !doc21.message.includes("artifact cap"))
        p.push("a 21st sbom document was accepted");
      mustAccept(
        p,
        "a standard object next to 20 sbom documents (control)",
        await put(eY, "std-a", 10),
      );
      // twenty standard objects fit, the 21st does not (the count cap of the standard class)
      const eZ = await inState(c, B, "running", 1);
      for (let i = 0; i < 20; i += 1)
        mustAccept(p, `standard count ${i}`, await put(eZ, `obj-${i}`, 10));
      const std21 = await put(eZ, "obj-20", 10);
      if (std21.ok || !std21.message.includes("artifact cap"))
        p.push("a 21st standard object was accepted");
      mustAccept(
        p,
        "an sbom document next to 20 standard objects (control)",
        await put(eZ, "doc-a", 10, { artifactClass: "sbom_document" }),
      );
      // ---- detail boundaries (probes are rolled back)
      const tSb = await runningTask(c, eA, "sbom");
      const rSb = await resultWithItems(c, eA, tSb, 1);
      const itB = rSb.items[0];
      const probeDetail = (d) =>
        probe(db, (tx) => tx.scanResultItemDetail.create({ data: detailRaw(itB, d) }));
      const okD = async (label, d) => mustAccept(p, label, await probeDetail(d));
      const noD = async (label, d) =>
        mustReject(p, label, await probeDetail(d), "scan_result_item_details");
      for (const confidence of ["low", "medium", "high"])
        await okD(`confidence ${confidence}`, detail({ confidence }));
      for (const confidenceBasis of ["tool", "multi_tool", "heuristic"])
        await okD(`basis ${confidenceBasis}`, detail({ confidenceBasis }));
      await okD("dedup key of 600", detail({ dedupKey: "x".repeat(600) }));
      await noD("dedup key of 601", detail({ dedupKey: "x".repeat(601) }));
      await okD("dedup key of 1", detail({ dedupKey: "x" }));
      await noD("scm reference as an array", detail({ scmRef: [] }));
      const covText = (target) => {
        const base = { state: "complete", coverageGaps: [""], toolsDegraded: 0, tools: [] };
        return { ...base, coverageGaps: ["x".repeat(target - jsonbTextBytes(base))] };
      };
      await okD("url of 2000", detail({ url: `https://${"y".repeat(1992)}` }));
      await noD("url of 2001", detail({ url: `https://${"y".repeat(1993)}` }));
      await okD("one provenance entry", detail({ provenance: [prov()] }));
      await okD(
        "evidence of 8192",
        detail({
          evidence: {
            kind: "line",
            snippet: "x".repeat(8192 - jsonbTextBytes({ kind: "line", snippet: "" })),
          },
        }),
      );
      await noD(
        "evidence of 8193",
        detail({
          evidence: {
            kind: "line",
            snippet: "x".repeat(8193 - jsonbTextBytes({ kind: "line", snippet: "" })),
          },
        }),
      );
      const entryOf = (target) => {
        const e = prov({ ruleId: "" });
        return prov({ ruleId: "x".repeat(target - jsonbTextBytes(e)) });
      };
      await okD("a provenance entry of 600 bytes", detail({ provenance: [entryOf(600)] }));
      await noD("a provenance entry of 601 bytes", detail({ provenance: [entryOf(601)] }));
      await okD(
        "scm reference",
        detail({ scmRef: { provider: "github", repoFullName: "o/r", commitSha: "a".repeat(40) } }),
      );
      const rowSize = (d) =>
        detailRowBytes({
          ...d,
          scmRef: d.scmRef ?? null,
          evidence: d.evidence ?? null,
          url: d.url ?? null,
        });
      const sized = (target) => {
        const d = detail({ extra: { blob: "" } });
        return detail({ extra: { blob: "x".repeat(target - rowSize(d)) } });
      };
      if (rowSize(sized(16384)) !== 16384) p.push(`fixture: row size ${rowSize(sized(16384))}`);
      await okD("a row of exactly 16384 bytes", sized(16384));
      await noD("a row of 16385 bytes", sized(16385));
      const sizedWith = (target, base) => {
        const d = { ...base, extra: { blob: "" } };
        return { ...d, extra: { blob: "x".repeat(target - rowSize(d)) } };
      };
      const withRef = detail({
        scmRef: { provider: "github", repoFullName: "o/r", commitSha: "a".repeat(40) },
      });
      await okD("a row of exactly 16384 bytes with an scm reference", sizedWith(16384, withRef));
      await noD("a row of 16385 bytes with an scm reference", sizedWith(16385, withRef));
      const noUrl = detail({ url: null });
      await okD("a row of exactly 16384 bytes without a url", sizedWith(16384, noUrl));
      await noD("a row of 16385 bytes without a url", sizedWith(16385, noUrl));
      // ---- coverage boundaries
      const covTools = (n) =>
        Array.from({ length: n }, () => ({ toolId: "syft", status: "succeeded" }));
      const eK = await inState(c, B, "running", 0);
      const kt = await runningTask(c, eK, "sbom");
      const covProbe = (over) =>
        probe(db, (tx) => resultWithItems({ ...c, db: tx }, eK, kt, 0, over));
      const state = (st, extra = {}) => ({
        schemaVersion: 2,
        completeness: "incomplete",
        coverage: { state: st, coverageGaps: [], toolsDegraded: 0, tools: covTools(1), ...extra },
      });
      for (const st of ["complete", "partial", "degraded", "nothing_to_scan", "language_gap"])
        mustAccept(p, `coverage state ${st}`, await covProbe(state(st)));
      mustAccept(p, "12 tools", await covProbe(state("complete", { tools: covTools(12) })));
      mustAccept(
        p,
        "toolsDegraded 0 on a complete result",
        await covProbe({ ...state("complete"), completeness: "complete" }),
      );
      mustAccept(p, "schema version 2 without coverage", await covProbe({ schemaVersion: 2 }));
      mustAccept(
        p,
        "a manifest hash on a version 2 result",
        await covProbe({ schemaVersion: 2, runManifestSha256: hex(32) }),
      );
      mustReject(
        p,
        "13 tools",
        await covProbe(state("complete", { tools: covTools(13) })),
        "scan_results_ensemble_check",
      );
      mustAccept(
        p,
        "coverage of exactly 4096 bytes",
        await covProbe({ schemaVersion: 2, completeness: "incomplete", coverage: covText(4096) }),
      );
      mustReject(
        p,
        "coverage of 4097 bytes",
        await covProbe({ schemaVersion: 2, completeness: "incomplete", coverage: covText(4097) }),
        "scan_results_ensemble_check",
      );
      // scoping: another tenant cannot see the document
      if (
        (await store.size({ tenantId: eY.tenantId, executionId: eX.id, name: "sbom-2" })) !== null
      )
        p.push("a tenant read another tenant's sbom document");
      if ((await store.size(ref(eX, "sbom-2"))) !== 16 * MiB) p.push("control: the stored size");
      return p;
    },
  },
  {
    id: "ENG-S08c",
    name: "retention and the new tables (SPEC scan-engines 7.5, Executions ER-17): an execution that is older than the metadata retention and has tool runs, a result with items and their detail rows and an sbom_document artifact is purged with all of them in one transaction (the foreign keys are RESTRICT, so a missed table would block the purge); an execution of another tenant that is young keeps every one of its rows; a second purge deletes nothing more",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      const seed = async (tree, i) => {
        const e = await inState(c, tree, "running", i);
        const task = await runningTask(c, e, "sca");
        await createScanToolRunRepository({ db }).insertMany({
          tenantId: e.tenantId,
          executionId: e.id,
          scanTaskId: task.id,
          attempt: 0,
          runs: [toolRun()],
        });
        const { result } = await resultWithItems(c, e, task, 2);
        await createScanResultDetailRepository({ db }).insertMany({
          tenantId: e.tenantId,
          executionId: e.id,
          scanResultId: result.id,
          details: [detail(), detail({ dedupKey: "sca|pkg:npm/a@1|CVE-1-1" })],
        });
        const store = createPostgresArtifactStore({
          repository: createExecutionArtifactRepository({ db }),
        });
        await store.put(
          { tenantId: e.tenantId, executionId: e.id, name: "sbom-doc" },
          Buffer.from("{}"),
          { mediaType: "application/json", artifactClass: "sbom_document" },
        );
        return { e, task, result };
      };
      const counts = async (e) => ({
        toolRuns: await db.scanToolRun.count({ where: { executionId: e.id } }),
        details: await db.scanResultItemDetail.count({ where: { executionId: e.id } }),
        items: await db.scanResultItem.count({ where: { executionId: e.id } }),
        artifacts: await db.executionArtifact.count({ where: { executionId: e.id } }),
      });
      const old = await seed(A, 0);
      const young = await seed(B, 0);
      for (const x of [old, young]) {
        const n = await counts(x.e);
        if (n.toolRuns !== 1 || n.details !== 2 || n.items !== 2 || n.artifacts !== 1)
          p.push(`control: seeded rows ${JSON.stringify(n)}`);
      }
      await driveExecution(db, old.e.id, "failed");
      await driveExecution(db, young.e.id, "failed");
      await db.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("ALTER TABLE executions DISABLE TRIGGER USER");
        await tx.$executeRawUnsafe(
          "UPDATE executions SET finished_at = now() - interval '600 days', requested_at = now() - interval '600 days' WHERE id = $1::uuid",
          old.e.id,
        );
        await tx.$executeRawUnsafe("ALTER TABLE executions ENABLE TRIGGER USER");
      });
      const repo = createExecutionRetentionRepository({ db });
      const first = await repo.purgeExpired({
        metadataRetentionMonths: 13,
        logRetentionDays: 3650,
        artifactRetentionDays: 3650,
      });
      if (first.executions < 1)
        p.push(`the old execution was not purged: ${JSON.stringify(first)}`);
      const gone = await counts(old.e);
      if (
        Object.values(gone).some((n) => n !== 0) ||
        (await db.execution.count({ where: { id: old.e.id } })) !== 0
      )
        p.push(`rows of the purged execution remain: ${JSON.stringify(gone)}`);
      const kept = await counts(young.e);
      if (kept.toolRuns !== 1 || kept.details !== 2 || kept.items !== 2 || kept.artifacts !== 1)
        p.push(`the young execution lost rows: ${JSON.stringify(kept)}`);
      const again = await repo.purgeExpired({
        metadataRetentionMonths: 13,
        logRetentionDays: 3650,
        artifactRetentionDays: 3650,
      });
      if (again.executions !== 0) p.push("a second purge deleted more");
      return p;
    },
  },
  {
    id: "ENG-S08e",
    name: "retention removes orphan changed-paths artifacts and never one a committed decision references (SPEC scan-engines 5.9 SE-22, owner decision 2026-11-20, Executions ER-17; real database): the artifact is written before the decision transaction, so an execution that ended without a committed decision referencing it leaves an orphan; one purge removes, at once and whatever their age, the changed-paths.json artifacts of TERMINAL executions that no committed decision of the same tenant and execution references with status complete (no decision at all, a truncated or unavailable decision that records no reference), of any tenant; it keeps the artifact a complete decision references (and the scan handler's reader returns its paths), every artifact with another name, and the artifact of an execution that is not terminal (a decision may still commit); a second purge removes nothing; the name constant of the database package equals the one of the worker contract; an orphan is never read: the reader takes the status and the reference from the decision row and does not touch the store for a missing decision, a truncated or unavailable one or a wrong reference",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      if (CHANGED_PATHS_ARTIFACT_NAME !== CHANGED_PATHS_NAME)
        p.push("the retention constant differs from the changed-paths contract");
      const store = createPostgresArtifactStore({
        repository: createExecutionArtifactRepository({ db }),
      });
      const doc = Buffer.from(JSON.stringify({ schemaVersion: 1, total: 1, paths: ["a/b.js"] }));
      const decisionOf = (e, over) =>
        db.scanDecision.create({
          data: {
            tenantId: e.tenantId,
            workspaceId: e.workspaceId,
            repositoryId: e.repositoryId,
            pipelineId: e.pipelineId,
            executionId: e.id,
            scanKind: "incremental",
            trust: "trusted",
            diffSource: "github_compare",
            diffStatus: "complete",
            changedTotal: 1,
            secretsRule: "any_change",
            floor: [],
            agentStatus: "not_configured",
            // the snapshot of the suite pipelines enables no scan type, so the decision is a zero-scan one
            finalTypes: [],
            notSelected: [],
            ...over,
          },
        });
      const make = async (tree, { name = CHANGED_PATHS_NAME, decision, terminal = true }) => {
        const { execution } = await queuedExecution(c, tree, 0, {
          scanKind: "incremental",
          scanKindReason: "push",
        });
        await driveExecution(db, execution.id, terminal ? "preparing" : "running");
        const e = await db.execution.findUnique({ where: { id: execution.id } });
        if (name !== null)
          await store.put({ tenantId: e.tenantId, executionId: e.id, name }, doc, {
            mediaType: "application/json",
          });
        if (decision) await decisionOf(e, decision);
        if (terminal) await driveExecution(db, e.id, "failed");
        return e;
      };
      const has = async (e, name = CHANGED_PATHS_NAME) =>
        (await store.size({ tenantId: e.tenantId, executionId: e.id, name })) !== null;
      const referenced = await make(A, {
        decision: { changedPathsStatus: "complete", changedPathsRef: CHANGED_PATHS_NAME },
      });
      const noDecision = await make(A, {});
      const truncated = await make(A, { decision: { changedPathsStatus: "truncated" } });
      const unavailable = await make(A, { decision: { changedPathsStatus: "unavailable" } });
      const otherName = await make(A, { name: "sbom-keep.cdx.json" });
      const otherTenant = await make(B, {});
      const running = await make(A, { terminal: false });
      for (const [label, e, name] of [
        ["referenced", referenced],
        ["no decision", noDecision],
        ["truncated", truncated],
        ["unavailable", unavailable],
        ["other name", otherName, "sbom-keep.cdx.json"],
        ["other tenant", otherTenant],
        ["running", running],
      ])
        if (!(await has(e, name))) p.push(`control: ${label} was not stored`);
      const repo = createExecutionRetentionRepository({ db });
      const first = await repo.purgeExpired({
        metadataRetentionMonths: null,
        logRetentionDays: 3650,
        artifactRetentionDays: 3650,
      });
      same(p, "orphans removed by the first purge", first.orphanChangedPaths >= 4, true);
      for (const [label, e, gone] of [
        ["referenced", referenced, false],
        ["no decision", noDecision, true],
        ["truncated", truncated, true],
        ["unavailable", unavailable, true],
        ["other tenant (no decision)", otherTenant, true],
        ["running execution", running, false],
      ])
        same(p, `${label}: artifact removed`, !(await has(e)), gone);
      same(p, "another name is kept", await has(otherName, "sbom-keep.cdx.json"), true);
      const second = await repo.purgeExpired({
        metadataRetentionMonths: null,
        logRetentionDays: 3650,
        artifactRetentionDays: 3650,
      });
      same(p, "a second purge removes no orphan", second.orphanChangedPaths, 0);
      // the reader goes through the decision row: the kept artifact is read, an orphan never
      const decisionRow = await db.scanDecision.findFirst({
        where: { tenantId: referenced.tenantId, executionId: referenced.id },
      });
      const read = await readChangedPaths({
        artifacts: store,
        tenantId: referenced.tenantId,
        executionId: referenced.id,
        decision: decisionRow,
      });
      same(p, "the referenced artifact is read", read, { status: "complete", paths: ["a/b.js"] });
      let opened = 0;
      const spy = {
        open: (ref) => {
          opened += 1;
          return store.open(ref);
        },
      };
      for (const [_label, decision] of [
        ["no decision", null],
        ["a decision that recorded nothing", { changedPathsStatus: null, changedPathsRef: null }],
        [
          "a truncated decision with a stale reference",
          { changedPathsStatus: "truncated", changedPathsRef: CHANGED_PATHS_NAME },
        ],
        ["an unavailable decision", { changedPathsStatus: "unavailable", changedPathsRef: null }],
        [
          "a complete decision with a foreign reference",
          { changedPathsStatus: "complete", changedPathsRef: "../x.json" },
        ],
      ])
        await readChangedPaths({
          artifacts: spy,
          tenantId: noDecision.tenantId,
          executionId: noDecision.id,
          decision,
        });
      same(p, "the store was never opened for an orphan", opened, 0);
      return p;
    },
  },
  {
    id: "ENG-S08d",
    name: "detail rows are tenant-owned and never readable across tenants; rows that existed before the migrations stay valid (SPEC scan-engines 7.3, owner decisions 2026-11-19, ENG-S08): scan_result_item_details.tenant_id is NOT NULL, equals the tenant of its item and of its result for every stored row, and a raw writer cannot attach a detail to another tenant's item or result (composite keys, both directions); every read of the repository needs the trusted tenant AND the execution AND the result, a twin result with the same ordinals in another tenant is never mixed in, and every SQL statement of the scan-engine repository over the three tables carries a tenant predicate (source guard); `extra` is validated strictly at write time by the repository (an unknown key, a secret-shaped key, a traversal path, an oversize or mistyped value inserts nothing); the new scan_results columns are nullable, the artifact class is defaulted, and legacy-shaped rows (schema version 1, no coverage, no manifest, standard artifacts) pass the migrations' CHECK constraints when those are re-applied to the existing rows (re-validated in a rolled-back transaction) and are unchanged by them",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      const repo = createScanResultDetailRepository({ db });
      const eA = await inState(c, A, "running", 0);
      const eB = await inState(c, B, "running", 0);
      const taskA = await runningTask(c, eA, "sca");
      const taskB = await runningTask(c, eB, "sca");
      const a = await resultWithItems(c, eA, taskA, 3);
      const b = await resultWithItems(c, eB, taskB, 3);
      const baseA = { tenantId: eA.tenantId, executionId: eA.id, scanResultId: a.result.id };
      const baseB = { tenantId: eB.tenantId, executionId: eB.id, scanResultId: b.result.id };
      // twin results: the same ordinals and the same dedup keys in two tenants
      const twin = [
        detail({ dedupKey: "sca|pkg:npm/twin@1|CVE-9-9" }),
        detail({ dedupKey: "sca|pkg:npm/twin@2|CVE-9-9" }),
      ];
      if ((await repo.insertMany({ ...baseA, details: twin })).inserted !== 2)
        p.push("control: A details");
      if ((await repo.insertMany({ ...baseB, details: twin })).inserted !== 2)
        p.push("control: B details");
      for (const [who, base, other] of [
        ["A", baseA, baseB],
        ["B", baseB, baseA],
      ]) {
        const own = await repo.listForResult(base);
        if (own.length !== 2) p.push(`control: ${who} reads ${own.length} of its own rows`);
        // every combination that mixes the tenant, the execution or the result of the other side reads nothing
        for (const q of [
          { ...base, tenantId: other.tenantId },
          { ...base, executionId: other.executionId },
          { ...base, scanResultId: other.scanResultId },
          {
            tenantId: other.tenantId,
            executionId: other.executionId,
            scanResultId: base.scanResultId,
          },
          {
            tenantId: base.tenantId,
            executionId: other.executionId,
            scanResultId: other.scanResultId,
          },
          {
            tenantId: other.tenantId,
            executionId: base.executionId,
            scanResultId: other.scanResultId,
          },
        ])
          if ((await repo.listForResult(q)).length !== 0)
            p.push(`${who}: a detail read crossed a boundary`);
        for (const missing of ["tenantId", "executionId", "scanResultId"])
          if ((await repo.listForResult({ ...base, [missing]: randomUUID() })).length !== 0)
            p.push(`${who}: an unknown ${missing} read rows`);
      }
      // the column is mandatory and every stored row agrees with its parents
      const nullable = async (table, column) =>
        (
          await db.$queryRaw`SELECT is_nullable AS n, column_default AS d FROM information_schema.columns WHERE table_name = ${table} AND column_name = ${column}`
        )[0];
      if ((await nullable("scan_result_item_details", "tenant_id"))?.n !== "NO")
        p.push("scan_result_item_details.tenant_id is nullable");
      for (const column of ["run_manifest_sha256", "coverage"]) {
        const r = await nullable("scan_results", column);
        if (r?.n !== "YES" || r?.d !== null)
          p.push(`scan_results.${column} is not a plain nullable column`);
      }
      const klass = await nullable("execution_artifacts", "artifact_class");
      if (klass?.n !== "NO" || !String(klass?.d).includes("standard"))
        p.push("execution_artifacts.artifact_class has no standard default");
      const mismatched = await db.$queryRaw`
        SELECT count(*)::int AS bad, (SELECT count(*)::int FROM scan_result_item_details) AS total FROM scan_result_item_details d
        WHERE NOT EXISTS (SELECT 1 FROM scan_result_items i WHERE i.tenant_id = d.tenant_id AND i.scan_result_id = d.scan_result_id AND i.ordinal = d.item_ordinal)
           OR NOT EXISTS (SELECT 1 FROM scan_results r WHERE r.tenant_id = d.tenant_id AND r.execution_id = d.execution_id AND r.id = d.scan_result_id)
           OR NOT EXISTS (SELECT 1 FROM executions x WHERE x.tenant_id = d.tenant_id AND x.id = d.execution_id)`;
      if (mismatched[0].total < 4 || mismatched[0].bad !== 0)
        p.push(`detail rows disagree with their parents: ${JSON.stringify(mismatched[0])}`);
      // a raw writer cannot attach a detail row to another tenant's item or result, in either direction
      const itemA = a.items[2];
      const itemB = b.items[2];
      mustReject(
        p,
        "tenant B's detail on tenant A's item",
        await attempt(() =>
          db.scanResultItemDetail.create({
            data: detailRaw({ ...itemA, tenantId: eB.tenantId }, detail()),
          }),
        ),
        "P2003",
      );
      mustReject(
        p,
        "tenant A's detail on tenant B's item",
        await attempt(() =>
          db.scanResultItemDetail.create({
            data: detailRaw({ ...itemB, tenantId: eA.tenantId }, detail()),
          }),
        ),
        "P2003",
      );
      mustReject(
        p,
        "tenant A's detail on tenant B's result",
        await attempt(() =>
          db.scanResultItemDetail.create({
            data: detailRaw({ ...itemA, executionId: eB.id, scanResultId: b.result.id }, detail()),
          }),
        ),
        "P2003",
      );
      mustAccept(
        p,
        "a detail on its own item",
        await attempt(() => db.scanResultItemDetail.create({ data: detailRaw(itemA, detail()) })),
      );
      // source guard: every statement over the scan tables names a BOUND tenant predicate; every INSERT (the batched ones too) takes
      // its tenant column from the parent row it selects, never from the caller, and scopes by execution as well
      const source = readFileSync(
        new URL("../../../../../packages/db/src/executions/scan-engines.js", import.meta.url),
        "utf8",
      );
      const guard = (src) => {
        const found = [];
        const statements =
          src.match(
            /(?:INSERT INTO|FROM|JOIN) scan_(?:tool_runs|result_item_details|result_items|results|tasks)\b[\s\S]*?(?:`|ORDER BY)/g,
          ) ?? [];
        if (statements.length < 5) found.push(`source guard found ${statements.length} statements`);
        for (const table of ["scan_tool_runs", "scan_result_item_details", "scan_result_items"])
          if (!statements.some((st) => st.includes(table)))
            found.push(`source guard missed ${table}`);
        for (const st of statements) {
          const label = st.slice(0, 60).replace(/\s+/g, " ");
          if (!/(?:\b[a-z]\.)?\btenant_id\s*=\s*\$\{tenantId\}::uuid/.test(st))
            found.push(`a statement has no bound tenant predicate: ${label}`);
          if (st.startsWith("INSERT INTO")) {
            const select = st.slice(st.indexOf("SELECT"), st.search(/\sFROM\s/));
            if (!/\b[a-z]\.tenant_id\b/.test(select) || select.includes("${tenantId}"))
              found.push(`an insert does not take its tenant from the parent row: ${label}`);
            if (!/\b[a-z]\.execution_id\s*=\s*\$\{executionId\}::uuid/.test(st))
              found.push(`an insert is not scoped by execution: ${label}`);
          }
        }
        const batched = statements.filter(
          (st) => st.startsWith("INSERT INTO") && /jsonb_to_recordset|unnest\(/.test(st),
        );
        if (batched.length < 2) found.push(`source guard found ${batched.length} batched inserts`);
        if (/\$queryRawUnsafe|\$executeRawUnsafe/.test(src))
          found.push("the repository uses unsafe raw SQL");
        return found;
      };
      p.push(...guard(source));
      // controls: the guard is not vacuous (each single defect in a copy of the source is found)
      for (const [label, from, to] of [
        [
          "a dropped tenant predicate of the detail insert",
          "WHERE i.tenant_id = ${tenantId}::uuid AND i.execution_id",
          "WHERE i.execution_id",
        ],
        [
          "a dropped tenant predicate of the item insert",
          "WHERE r.tenant_id = ${tenantId}::uuid AND r.execution_id",
          "WHERE r.execution_id",
        ],
        [
          "a tenant column taken from the caller",
          "SELECT gen_random_uuid(), r.tenant_id,",
          "SELECT gen_random_uuid(), ${tenantId}::uuid,",
        ],
        ["a dropped execution predicate", "AND r.execution_id = ${executionId}::uuid", ""],
        ["an unsafe raw call", "tx.$executeRaw`", "tx.$executeRawUnsafe`"],
      ]) {
        if (!source.includes(from))
          p.push(`guard control ${label}: the pattern is gone from the source`);
        else if (guard(source.replace(from, to)).length === 0)
          p.push(`guard control: ${label} was not detected`);
      }
      // `extra` is validated at write time by the repository
      const fresh = await resultWithItems(c, eA, await runningTask(c, eA, "secrets"), 2);
      const freshBase = {
        tenantId: eA.tenantId,
        executionId: eA.id,
        scanResultId: fresh.result.id,
      };
      const goodExtra = detail().extra;
      for (const [label, extra] of [
        ["an unknown key", { ...goodExtra, note: "x" }],
        ["a secret-shaped key", { ...goodExtra, secret: "hunter2hunter2" }],
        ["a value-length key", { ...goodExtra, valueLengthBucket: "<=16" }],
        ["a traversal path", { ...goodExtra, locations: [{ path: "../../etc/passwd" }] }],
        ["a mistyped value", { ...goodExtra, fix: "x" }],
        ["an unknown tool", { ...goodExtra, ruleTool: "grype" }],
        ["an oversize value", { ...goodExtra, ruleName: "x".repeat(5000) }],
        ["a string", "x"],
        ["an array", [goodExtra]],
        ["null", null],
      ]) {
        const r = await attempt(() =>
          repo.insertMany({ ...freshBase, details: [detail({ extra })] }),
        );
        if (r.ok) p.push(`the repository accepted extra with ${label}`);
      }
      if ((await repo.listForResult(freshBase)).length !== 0) p.push("a rejected extra left a row");
      mustAccept(
        p,
        "a valid extra",
        await attempt(() =>
          repo.insertMany({ ...freshBase, details: [detail({ extra: goodExtra })] }),
        ),
      );
      // rows that existed before the migrations: legacy-shaped rows stay valid when the CHECKs are applied to them
      const legacy = await resultWithItems(c, eA, await runningTask(c, eA, "sbom"), 1, {
        completeness: "incomplete",
      });
      const legacyRows =
        await db.$queryRaw`SELECT schema_version AS "schemaVersion", run_manifest_sha256 AS manifest, coverage FROM scan_results WHERE id = ${legacy.result.id}::uuid`;
      if (
        legacyRows[0]?.schemaVersion !== 1 ||
        legacyRows[0]?.manifest !== null ||
        legacyRows[0]?.coverage !== null
      )
        p.push(`a legacy-shaped result is not what it should be: ${JSON.stringify(legacyRows[0])}`);
      const store = createPostgresArtifactStore({
        repository: createExecutionArtifactRepository({ db }),
      });
      await store.put(
        { tenantId: eA.tenantId, executionId: eA.id, name: "legacy-doc" },
        Buffer.from("{}"),
        {
          mediaType: "application/json",
        },
      );
      const legacyArtifact =
        await db.$queryRaw`SELECT artifact_class AS class FROM execution_artifacts WHERE execution_id = ${eA.id}::uuid AND name = 'legacy-doc'`;
      if (legacyArtifact[0]?.class !== "standard")
        p.push("a default artifact is not the standard class");
      const defOf = async (name) =>
        (
          await db.$queryRaw`SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conname = ${name}`
        )[0]?.def;
      for (const [table, name] of [
        ["scan_results", "scan_results_ensemble_check"],
        ["execution_artifacts", "execution_artifacts_values_check"],
      ]) {
        const def = await defOf(name);
        if (!def) {
          p.push(`constraint ${name} not found`);
          continue;
        }
        // ADD CONSTRAINT validates every existing row, exactly as the migration did
        mustAccept(
          p,
          `${name} re-applied to the existing rows`,
          await probe(db, async (tx) => {
            await tx.$executeRawUnsafe(`ALTER TABLE ${table} DROP CONSTRAINT ${name}`);
            await tx.$executeRawUnsafe(`ALTER TABLE ${table} ADD CONSTRAINT ${name} ${def}`);
          }),
        );
      }
      // control: the same probe does fail for a row that violates the constraint (so a pass is not vacuous)
      mustReject(
        p,
        "control: the re-validation is not vacuous",
        await probe(db, async (tx) => {
          await tx.$executeRawUnsafe(
            "ALTER TABLE scan_results DROP CONSTRAINT scan_results_ensemble_check",
          );
          await tx.$executeRawUnsafe("ALTER TABLE scan_results DISABLE TRIGGER USER");
          await tx.$executeRawUnsafe(
            'UPDATE scan_results SET coverage = \'{"state":"complete"}\'::jsonb WHERE id = $1::uuid',
            legacy.result.id,
          );
          await tx.$executeRawUnsafe(
            "ALTER TABLE scan_results ADD CONSTRAINT scan_results_ensemble_check CHECK (coverage IS NULL)",
          );
        }),
        "scan_results_",
      );
      const after =
        await db.$queryRaw`SELECT schema_version AS "schemaVersion", coverage FROM scan_results WHERE id = ${legacy.result.id}::uuid`;
      if (after[0]?.schemaVersion !== 1 || after[0]?.coverage !== null)
        p.push("the legacy row changed");
      return p;
    },
  },
  {
    id: "ENG-S08f",
    name: "a FULL-CAP scan result is stored inside the transaction budget, in batches, and atomically (SPEC scan-engines 7.3, 17.f, ER-15; real database; the defect: finishTask inserted the detail rows one statement at a time, so about 8000 rows exceeded the 15 s transaction and a larger result was lost): the real storage projection of 50001 findings keeps exactly the default cap of 50000 (truncated, the 50001st is never written), and finishTask writes those 50000 items and 50000 detail rows in one transaction, succeeds and records the task as succeeded, in less than the stated bound (the measured time is printed); every row is there, row i belongs to ordinal i and the detail of ordinal i is the one of item i (determinism); a result of rows with every optional shape (null and present evidence, scm reference and url, empty and ordered CWE lists, assumed severity) across a batch boundary reads back exactly as given; rows for ordinals without an item of this tenant and result insert nothing and do not fail the batch; a failing row in the SECOND batch (a credential shape the database refuses) rolls back the whole finishTask (no result, no item, no detail, the task still running) and, for the repository on its own, leaves no row of the first batch; an invalid `extra` anywhere inserts nothing; the batched statement is tenant scoped (a foreign tenant's ids insert nothing)",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      const tasks = createScanTaskRepository({ db });
      const repo = createScanResultDetailRepository({ db });
      // ---- the statement size bounds and the transaction budget actually handed to the database client
      for (const [label, size] of [
        ["detail", DETAIL_INSERT_BATCH],
        ["item", ITEM_INSERT_BATCH],
      ])
        if (!Number.isInteger(size) || size < 100 || size > 5000)
          p.push(`the ${label} batch size ${size} is outside 100..5000 rows per statement`);
      {
        const seen = [];
        const spy = new Proxy(db, {
          get: (target, prop) =>
            prop === "$transaction"
              ? (fn, options) => {
                  seen.push(options?.timeout);
                  return target.$transaction(fn, options);
                }
              : target[prop],
        });
        const eT = await inState(c, A, "running", 0);
        const taskT = await runningTask(c, eT, "sca");
        const resultT = ENGINE_RESULT({
          items: [
            { kind: "vulnerability", severity: "low", title: "a" },
            { kind: "vulnerability", severity: "low", title: "b" },
          ],
          details: [detail({ dedupKey: "sca|a" })],
        });
        const doneT = await createScanTaskRepository({ db: spy }).finishTask({
          tenantId: eT.tenantId,
          taskId: taskT.id,
          attempt: taskT.attempt,
          status: "succeeded",
          result: resultT,
        });
        same(p, "a small result finishes", doneT.finished, true);
        same(p, "the budget handed to the transaction", seen, [15_002]);
      }
      // a schema version other than 1 is refused by the database (the batch never coerces it)
      {
        const eV = await inState(c, A, "running", 0);
        const resV = await resultWithItems(c, eV, await runningTask(c, eV, "sca"), 1);
        mustReject(
          p,
          "schema version 2",
          await attempt(() =>
            repo.insertMany({
              tenantId: eV.tenantId,
              executionId: eV.id,
              scanResultId: resV.result.id,
              details: [detail({ schemaVersion: 2 })],
            }),
          ),
          "values_check",
        );
      }
      // ---- the real projection of cap + 1 findings
      const findings = sbomFindings(CAP + 1);
      const rows = toStorageRows(findings, CAP);
      same(
        p,
        "cap + 1 projects to the cap",
        [rows.items.length, rows.details.length, rows.truncated],
        [CAP, CAP, true],
      );
      same(p, "the dropped item is the last one", rows.items.at(-1).title, `pkg${CAP - 1}@1.0.0`);
      // ---- the full-cap write
      const eA = await inState(c, A, "running", 0);
      const task = await runningTask(c, eA, "sbom");
      const started = performance.now();
      const done = await tasks.finishTask({
        tenantId: eA.tenantId,
        taskId: task.id,
        attempt: task.attempt,
        status: "succeeded",
        result: ENGINE_RESULT(rows, { truncated: true, completeness: "incomplete" }),
      });
      const elapsed = Math.round(performance.now() - started);
      console.log(
        `[ENG-S08f] full-cap finishTask (${CAP} items + ${CAP} detail rows, one transaction): ${elapsed} ms (check bound ${FULL_CAP_BOUND_MS} ms, default transaction budget 15000 ms, this transaction's budget ${finishTaskTimeoutMs({ items: rows.items, details: rows.details })} ms)`,
      );
      if (!done.finished || !done.resultId) p.push("the full-cap finishTask did not finish");
      if (elapsed >= FULL_CAP_BOUND_MS)
        p.push(`the full-cap write took ${elapsed} ms (bound ${FULL_CAP_BOUND_MS} ms)`);
      const counts = await db.$queryRaw`
        SELECT (SELECT count(*)::int FROM scan_result_items WHERE tenant_id = ${eA.tenantId}::uuid AND scan_result_id = ${done.resultId}::uuid) AS items,
          (SELECT count(*)::int FROM scan_result_item_details WHERE tenant_id = ${eA.tenantId}::uuid AND scan_result_id = ${done.resultId}::uuid) AS details,
          (SELECT count(*)::int FROM scan_result_item_details d JOIN scan_result_items i ON i.tenant_id = d.tenant_id AND i.scan_result_id = d.scan_result_id AND i.ordinal = d.item_ordinal
            WHERE d.tenant_id = ${eA.tenantId}::uuid AND d.scan_result_id = ${done.resultId}::uuid
              AND d.dedup_key = 'sbom|pkg:npm/pkg' || d.item_ordinal || '@1.0.0' AND i.title = 'pkg' || d.item_ordinal || '@1.0.0') AS aligned,
          (SELECT item_count FROM scan_results WHERE id = ${done.resultId}::uuid) AS "itemCount",
          (SELECT status::text FROM scan_tasks WHERE id = ${task.id}::uuid) AS status`;
      same(
        p,
        "the transaction budget of an empty and of a full-cap result",
        [
          finishTaskTimeoutMs(undefined),
          finishTaskTimeoutMs({ items: [], details: [] }),
          finishTaskTimeoutMs({ items: new Array(CAP), details: new Array(CAP) }),
          finishTaskTimeoutMs({ items: new Array(1), details: [] }),
          finishTaskTimeoutMs({ items: new Array(2), details: new Array(1) }),
          finishTaskTimeoutMs({ items: new Array(4) }),
        ],
        [15_000, 15_000, 15_000 + CAP, 15_001, 15_002, 15_002],
      );
      same(p, "full-cap rows", counts[0], {
        items: CAP,
        details: CAP,
        aligned: CAP,
        itemCount: CAP,
        status: "succeeded",
      });

      // ---- every optional shape across a batch boundary, read back as given
      const shapes = DETAIL_INSERT_BATCH + 5;
      const eS = await inState(c, A, "running", 0);
      const taskS = await runningTask(c, eS, "sca");
      const resS = await resultWithItems(c, eS, taskS, 0);
      await db.scanResultItem.createMany({
        data: Array.from({ length: shapes }, (_, ordinal) => ({
          tenantId: eS.tenantId,
          executionId: eS.id,
          scanResultId: resS.result.id,
          ordinal,
          kind: "vulnerability",
          severity: "low",
          title: `item ${ordinal}`,
        })),
      });
      const baseS = { tenantId: eS.tenantId, executionId: eS.id, scanResultId: resS.result.id };
      const shape = (i) =>
        detail({
          dedupKey: `sca|pkg:npm/shape${i}@1|CVE-1-${i}`,
          confidence: ["low", "medium", "high"][i % 3],
          severityAssumed: i % 2 === 0,
          cwe: i % 4 === 0 ? [] : i % 4 === 1 ? [79, 20, 77] : [89],
          evidence: i % 3 === 0 ? { kind: "line", snippet: `s${i}` } : null,
          scmRef:
            i % 5 === 0
              ? { provider: "github", repoFullName: "o/r", commitSha: "a".repeat(40) }
              : null,
          url: i % 7 === 0 ? undefined : i % 7 === 1 ? null : detail().url,
          advisories: i % 6 === 0 ? [] : [{ id: `CVE-1-${i}`, family: "CVE" }],
        });
      const wanted = Array.from({ length: shapes }, (_, i) => shape(i));
      // given out of order and with explicit ordinals for some rows: the insert is keyed by ordinal, not by position
      const reversed = wanted.map((d, i) => ({ ...d, itemOrdinal: i })).reverse();
      const insS = await repo.insertMany({ ...baseS, details: reversed });
      same(p, "shapes inserted", insS.inserted, shapes);
      const back = await repo.listForResult(baseS);
      same(p, "shapes read back", back.length, shapes);
      for (const i of [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        35,
        DETAIL_INSERT_BATCH - 1,
        DETAIL_INSERT_BATCH,
        shapes - 1,
      ]) {
        const w = wanted[i];
        const g = back[i];
        same(
          p,
          `shape ${i}`,
          [
            g.ordinal,
            g.dedupKey,
            g.confidence,
            g.severityAssumed,
            g.cwe,
            g.evidence,
            canon(g.scmRef),
            g.url,
            g.advisories,
          ],
          [
            i,
            w.dedupKey,
            w.confidence,
            w.severityAssumed,
            w.cwe,
            w.evidence ?? null,
            canon(w.scmRef ?? null),
            w.url ?? null,
            w.advisories,
          ],
        );
      }
      // ordinals without an item insert nothing and do not fail the batch
      const eB = await inState(c, B, "running", 0);
      const resB = await resultWithItems(c, eB, await runningTask(c, eB, "sca"), 2);
      const eG = await inState(c, A, "running", 0);
      const resG = await resultWithItems(c, eG, await runningTask(c, eG, "sca"), 2);
      // a SECOND result of the same execution with the same ordinals: the result predicate alone keeps the batch off it
      const resG2 = await resultWithItems(c, eG, await runningTask(c, eG, "secrets"), 2);
      const gaps = await repo.insertMany({
        tenantId: eG.tenantId,
        executionId: eG.id,
        scanResultId: resG.result.id,
        details: [
          detail({ itemOrdinal: 0 }),
          detail({ itemOrdinal: 99 }),
          detail({ itemOrdinal: 1 }),
        ],
      });
      same(p, "ordinals without an item", gaps.inserted, 2);
      same(
        p,
        "the other result of the execution",
        (
          await repo.listForResult({
            tenantId: eG.tenantId,
            executionId: eG.id,
            scanResultId: resG2.result.id,
          })
        ).length,
        0,
      );
      // exactly one wrong coordinate inserts nothing
      for (const [label, q] of [
        ["tenant", { tenantId: eB.tenantId, executionId: eG.id, scanResultId: resG.result.id }],
        ["execution", { tenantId: eG.tenantId, executionId: eS.id, scanResultId: resG.result.id }],
        ["result", { tenantId: eG.tenantId, executionId: eG.id, scanResultId: randomUUID() }],
      ]) {
        const r = await repo.insertMany({ ...q, details: [detail({ itemOrdinal: 0 })] });
        same(p, `a wrong ${label}`, r.inserted, 0);
      }
      // a foreign tenant's ids insert nothing (the batched statement is tenant scoped)
      const foreign = await repo.insertMany({
        tenantId: eA.tenantId,
        executionId: eB.id,
        scanResultId: resB.result.id,
        details: [detail(), detail()],
      });
      same(p, "a foreign tenant's result", foreign.inserted, 0);
      same(
        p,
        "nothing readable there",
        (
          await repo.listForResult({
            tenantId: eB.tenantId,
            executionId: eB.id,
            scanResultId: resB.result.id,
          })
        ).length,
        0,
      );

      // ---- the item repository: every field, the batch boundary, the foreign ids
      const itemRepo = createScanResultItemRepository({ db });
      const eI = await inState(c, A, "running", 0);
      const resI = await resultWithItems(c, eI, await runningTask(c, eI, "sca"), 0);
      const baseI = { tenantId: eI.tenantId, executionId: eI.id, scanResultId: resI.result.id };
      const manyItems = Array.from({ length: ITEM_INSERT_BATCH + 3 }, (_, i) => ({
        kind: "vulnerability",
        severity: "low",
        title: `item ${i}`,
      }));
      manyItems[1] = {
        kind: "code_issue",
        ruleId: "rule-1",
        severity: "high",
        title: "all fields",
        path: "src/a.js",
        startLine: 3,
        endLine: 5,
        componentPurl: "pkg:npm/a@1",
        componentVersion: "1",
        data: { k: "v" },
      };
      for (const [label, q] of [
        ["tenant", { ...baseI, tenantId: eB.tenantId }],
        ["execution", { ...baseI, executionId: eG.id }],
        ["result", { ...baseI, scanResultId: randomUUID() }],
        [
          "foreign result",
          { tenantId: eA.tenantId, executionId: eB.id, scanResultId: resB.result.id },
        ],
      ]) {
        const r = await itemRepo.insertMany({ ...q, items: manyItems });
        same(p, `items with a wrong ${label}`, r.inserted, 0);
      }
      mustReject(
        p,
        "an item with an unknown field",
        await attempt(() =>
          itemRepo.insertMany({ ...baseI, items: [{ ...manyItems[0], extra: 1 }] }),
        ),
        "unknown field",
      );
      same(
        p,
        "nothing inserted yet",
        await db.scanResultItem.count({ where: { scanResultId: resI.result.id } }),
        0,
      );
      same(
        p,
        "items inserted",
        (await itemRepo.insertMany({ ...baseI, items: manyItems })).inserted,
        manyItems.length,
      );
      const stored = await db.scanResultItem.findMany({
        where: { scanResultId: resI.result.id },
        orderBy: { ordinal: "asc" },
      });
      same(
        p,
        "item ordinals",
        stored.map((r) => r.ordinal),
        manyItems.map((_, i) => i),
      );
      same(
        p,
        "item titles follow the ordinals",
        stored.map((r) => r.title),
        manyItems.map((i) => i.title),
      );
      const full = stored[1];
      same(
        p,
        "every item field",
        [
          full.kind,
          full.ruleId,
          full.severity,
          full.path,
          full.startLine,
          full.endLine,
          full.componentPurl,
          full.componentVersion,
          full.data,
          full.tenantId,
          full.executionId,
        ],
        [
          "code_issue",
          "rule-1",
          "high",
          "src/a.js",
          3,
          5,
          "pkg:npm/a@1",
          "1",
          { k: "v" },
          eI.tenantId,
          eI.id,
        ],
      );
      same(
        p,
        "absent item fields are null and data defaults",
        [
          stored[0].ruleId,
          stored[0].path,
          stored[0].startLine,
          stored[0].endLine,
          stored[0].componentPurl,
          stored[0].componentVersion,
          stored[0].data,
        ],
        [null, null, null, null, null, null, {}],
      );
      same(p, "item ids are distinct", new Set(stored.map((r) => r.id)).size, manyItems.length);

      // ---- atomicity: a failure in the SECOND batch rolls everything back
      const n = DETAIL_INSERT_BATCH + 500;
      const bad = Array.from({ length: n }, (_, i) =>
        detail({
          dedupKey:
            i === DETAIL_INSERT_BATCH + 100 ? `sca|${GHP}` : `sca|pkg:npm/r${i}@1|CVE-2-${i}`,
        }),
      );
      // repository on its own
      const eR = await inState(c, A, "running", 0);
      const resR = await resultWithItems(c, eR, await runningTask(c, eR, "sca"), 0);
      await db.scanResultItem.createMany({
        data: Array.from({ length: n }, (_, ordinal) => ({
          tenantId: eR.tenantId,
          executionId: eR.id,
          scanResultId: resR.result.id,
          ordinal,
          kind: "vulnerability",
          severity: "low",
          title: `item ${ordinal}`,
        })),
      });
      const baseR = { tenantId: eR.tenantId, executionId: eR.id, scanResultId: resR.result.id };
      mustReject(
        p,
        "a credential shape in the second batch",
        await attempt(() => repo.insertMany({ ...baseR, details: bad })),
        "no_credentials_check",
      );
      same(p, "the first batch was rolled back", (await repo.listForResult(baseR)).length, 0);
      mustAccept(
        p,
        "control: the same rows without the bad one",
        await attempt(() =>
          repo.insertMany({
            ...baseR,
            details: bad.map((d, i) =>
              i === DETAIL_INSERT_BATCH + 100
                ? detail({ dedupKey: "sca|pkg:npm/ok@1|CVE-2-1" })
                : d,
            ),
          }),
        ),
      );
      same(p, "control rows", (await repo.listForResult(baseR)).length, n);
      // an invalid `extra` anywhere inserts nothing (validated before the first statement)
      const eX = await inState(c, A, "running", 0);
      const resX = await resultWithItems(c, eX, await runningTask(c, eX, "sca"), 3);
      const baseX = { tenantId: eX.tenantId, executionId: eX.id, scanResultId: resX.result.id };
      mustReject(
        p,
        "an invalid extra in the last row",
        await attempt(() =>
          repo.insertMany({
            ...baseX,
            details: [detail(), detail(), detail({ extra: { note: "x" } })],
          }),
        ),
        "",
      );
      same(p, "an invalid extra left rows", (await repo.listForResult(baseX)).length, 0);
      // finishTask as a whole
      const eF = await inState(c, A, "running", 0);
      const taskF = await runningTask(c, eF, "sca");
      const rowsF = {
        items: Array.from({ length: n }, (_, i) => ({
          kind: "vulnerability",
          severity: "low",
          title: `item ${i}`,
        })),
        details: bad,
      };
      mustReject(
        p,
        "finishTask with a bad second batch",
        await attempt(() =>
          tasks.finishTask({
            tenantId: eF.tenantId,
            taskId: taskF.id,
            attempt: taskF.attempt,
            status: "succeeded",
            result: ENGINE_RESULT(rowsF),
          }),
        ),
        "no_credentials_check",
      );
      const left = await db.$queryRaw`
        SELECT (SELECT count(*)::int FROM scan_results WHERE scan_task_id = ${taskF.id}::uuid) AS results,
          (SELECT count(*)::int FROM scan_result_items WHERE execution_id = ${eF.id}::uuid) AS items,
          (SELECT count(*)::int FROM scan_result_item_details WHERE execution_id = ${eF.id}::uuid) AS details,
          (SELECT status::text FROM scan_tasks WHERE id = ${taskF.id}::uuid) AS status,
          (SELECT count(*)::int FROM scan_task_attempts WHERE scan_task_id = ${taskF.id}::uuid AND finished_at IS NOT NULL) AS closed`;
      same(p, "finishTask rolled back", left[0], {
        results: 0,
        items: 0,
        details: 0,
        status: "running",
        closed: 0,
      });
      return p;
    },
  },
];
