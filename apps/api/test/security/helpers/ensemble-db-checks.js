import { randomBytes, randomUUID } from "node:crypto";
import {
  createExecutionArtifactRepository,
  createExecutionRetentionRepository,
  createScanResultDetailRepository,
  createScanToolRunRepository,
} from "@qmentisai/db";
import { createPostgresArtifactStore } from "@qmentisai/infra";
import { jsonbTextBytes } from "@qmentisai/shared";
import { detailRowBytes } from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import { driveExecution, inState, runningTask, taskData } from "./execution-db.js";
import { attempt, mustAccept, mustReject, probe } from "./pipeline-db.js";

/**
 * Scan engines, part D, database parts (ADR-008 area 18, SPEC scan-engines 7.3, 14.1 ENG-S08): the tool-run table, the 1:1 detail
 * table, the ensemble columns of scan_results and the two artifact classes, in process against the disposable PostgreSQL.
 * Every denial has a control. NOT proved here: any HTTP route or DTO for these tables (none exists before part K), the live
 * behaviour with a real worker, or that the migration applies to a database with data in these tables (they are new and empty).
 */

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
  extra: { component: { name: "lodash" } },
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
];
