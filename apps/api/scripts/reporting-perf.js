/**
 * Measurement helper of the Reporting module (docs/modules/reporting-dashboards/SPEC.md 14, AS_BUILT_E.md section 3). NOT part of the security
 * suite and not run by CI: it starts its OWN ephemeral PostgreSQL cluster (like `security-suite.js`), applies the migrations, generates ONE
 * tenant with ONE workspace holding `--findings` findings (default 100,000: about half open, all severities and types, SLA clocks set, a
 * history row each, 20 percent approved reviews, 20,000 executions over 90 days, 3 repositories, 6 pipelines with a published
 * configuration), runs `ANALYZE` and then times the read endpoints over the REAL read routes, acting as `qm_reporting_ro` (the fixture of the
 * Part B checks), cache OFF, sequential calls, a few warm-ups, `--samples` timed calls each (p95 is the ceil(0.95 n)-th sample).
 *
 * Usage (from apps/api): `node scripts/reporting-perf.js [--findings N] [--samples N] [--only name,name]`. Prints a JSON table.
 * It never touches any database but its own temporary cluster, which is removed at the end.
 */
import { execFileSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createDbClient } from "@qmentisai/db";
import { startReadApi } from "../test/security/helpers/reporting/reporting-b-fixtures.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : args[i + 1];
};
const TOTAL = Number(opt("findings", "100000"));
const SAMPLES = Number(opt("samples", "30"));
const ONLY = opt("only", "").split(",").filter(Boolean);
const DAY = 86_400_000;

const freePort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });

function postgresBin() {
  if (process.env.PG_BIN_DIR) return process.env.PG_BIN_DIR;
  const root = "/usr/lib/postgresql";
  const versions = existsSync(root)
    ? readdirSync(root)
        .filter((v) => /^\d+$/.test(v))
        .sort((a, b) => Number(b) - Number(a))
    : [];
  for (const v of versions)
    if (existsSync(path.join(root, v, "bin", "initdb"))) return path.join(root, v, "bin");
  throw new Error("no PostgreSQL binaries found (set PG_BIN_DIR)");
}

const cleanups = [];
async function main() {
  const bin = postgresBin();
  const dir = mkdtempSync(path.join(os.tmpdir(), "qmentis-perf-pg-"));
  const port = await freePort();
  const run = (cmd, a) =>
    execFileSync(path.join(bin, cmd), a, {
      stdio: "pipe",
      env: { PATH: process.env.PATH, LANG: "C" },
    });
  run("initdb", ["-D", dir, "-A", "trust", "-U", "postgres", "--no-sync"]);
  cleanups.push(() => {
    try {
      run("pg_ctl", ["-D", dir, "-m", "immediate", "stop"]);
    } catch {
      /* already stopped */
    }
    rmSync(dir, { recursive: true, force: true });
  });
  run("pg_ctl", [
    "-D",
    dir,
    "-o",
    `-p ${port} -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c fsync=off`,
    "-l",
    path.join(dir, "server.log"),
    "-w",
    "start",
  ]);
  run("createdb", ["-h", "127.0.0.1", "-p", String(port), "-U", "postgres", "qmentis_perf_test"]);
  const url = `postgresql://postgres@127.0.0.1:${port}/qmentis_perf_test`;
  execFileSync("pnpm", ["--filter", "@qmentisai/db", "db:migrate:deploy"], {
    cwd: repoRoot,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, DATABASE_URL: url },
    stdio: "pipe",
  });
  const db = createDbClient({ datasourceUrl: url });
  cleanups.push(() => db.$disconnect());

  // ---- the dataset ------------------------------------------------------------------------------------------------------------
  const sfx = randomBytes(3).toString("hex");
  const tenant = await db.tenant.create({ data: { slug: `perf-${sfx}`, name: `Perf ${sfx}` } });
  const user = await db.user.create({ data: { email: `perf-${sfx}@perf.example`, name: "Perf" } });
  const installation = await db.scmInstallation.create({
    data: {
      provider: "github",
      externalInstallationId: `perf-${sfx}`,
      accountExternalId: `perf-${sfx}`,
      accountLogin: "perf-org",
      accountType: "organization",
      repositorySelection: "all",
    },
  });
  const link = await db.scmInstallationLink.create({
    data: { tenantId: tenant.id, installationId: installation.id, linkedByUserId: user.id },
  });
  const ws = await db.workspace.create({ data: { tenantId: tenant.id, name: "Perf workspace" } });
  const wl = await db.scmWorkspaceLink.create({
    data: { tenantId: tenant.id, workspaceId: ws.id, linkId: link.id, linkedByUserId: user.id },
  });
  const repos = [];
  for (let i = 0; i < 3; i += 1)
    repos.push(
      await db.repository.create({
        data: {
          tenantId: tenant.id,
          workspaceId: ws.id,
          linkId: link.id,
          workspaceLinkId: wl.id,
          provider: "github",
          externalRepoId: `perf-${sfx}-${i}`,
          fullName: `perf-org/repo-${i}`,
          name: `repo-${i}`,
          ownerLogin: "perf-org",
          connectedByUserId: user.id,
          ...(i === 2 ? { archived: true } : {}),
        },
      }),
    );
  const pipelines = [];
  for (let i = 0; i < 6; i += 1) {
    const pipeline = await db.pipeline.create({
      data: {
        tenantId: tenant.id,
        workspaceId: ws.id,
        repositoryId: repos[i % 3].id,
        name: `pipe-${i}`,
        nameNormalized: `pipe-${i}`,
        createdByUserId: user.id,
      },
    });
    const version = await db.pipelineConfigVersion.create({
      data: {
        tenantId: tenant.id,
        pipelineId: pipeline.id,
        version: 1,
        schemaVersion: 1,
        config: {
          schemaVersion: 1,
          triggers: [],
          scans: {
            sast: { enabled: true },
            sca: { enabled: i % 2 === 0 },
            secrets: { enabled: true },
            sbom: { enabled: i % 3 === 0 },
          },
        },
        configHash: `perf-${i}`,
        createdByUserId: user.id,
      },
    });
    pipelines.push(
      await db.pipeline.update({
        where: { id: pipeline.id },
        data: { currentVersion: 1, currentVersionId: version.id },
      }),
    );
  }
  const versions = await db.pipelineConfigVersion.findMany({ where: { tenantId: tenant.id } });
  const now = Date.now();
  const SEV = [
    ["critical", 4],
    ["high", 3],
    ["medium", 2],
    ["low", 1],
    ["info", 0],
  ];
  const STATUSES = [
    "new",
    "new",
    "in_review",
    "approved",
    "reopened",
    "fixed_pending_verification",
    "verified_fixed",
    "verified_fixed",
    "false_positive",
    "new",
  ];
  const TYPES = [
    ["sast", "code_issue"],
    ["sca", "vulnerability"],
    ["secrets", "secret"],
  ];
  const hex = (n) => randomBytes(n).toString("hex");
  const findings = [];
  const history = [];
  const reviews = [];
  for (let i = 0; i < TOTAL; i += 1) {
    const pipeline = pipelines[i % 6];
    const [sev, rank] = SEV[i % 5 === 4 ? 2 : i % 4];
    const [scanType, kind] = TYPES[i % 3];
    const status = STATUSES[i % STATUSES.length];
    const detected = new Date(now - (1 + (i % 120)) * DAY - (i % 24) * 3_600_000);
    const slaDue = new Date(detected.getTime() + (rank + 1) * 7 * DAY);
    const id = randomUUID();
    findings.push({
      id,
      tenantId: tenant.id,
      workspaceId: ws.id,
      repositoryId: pipeline.repositoryId,
      pipelineId: pipeline.id,
      fingerprint: `fp1:${hex(32)}`,
      correlationKey: hex(32),
      scanType,
      kind,
      ruleId: `rule.${i % 50}`,
      title: `Finding ${i}`,
      toolSeverity: sev,
      severity: sev,
      severityRank: rank,
      confidence: "medium",
      anchorKind: "focus_text",
      path: `src/file${i % 500}.js`,
      startLine: 1 + (i % 200),
      endLine: 1 + (i % 200),
      status,
      statusChangedAt: detected,
      firstDetectedAt: detected,
      firstExecutionId: randomUUID(),
      firstCommitSha: "a".repeat(40),
      lastSeenAt: new Date(now - (i % 5) * DAY),
      lastSeenExecutionId: randomUUID(),
      lastSeenCommitSha: "a".repeat(40),
      slaStartedAt: detected,
      slaDueAt: slaDue,
      ...(status === "verified_fixed"
        ? {
            verifiedAt: new Date(detected.getTime() + 3 * DAY),
            closedAt: new Date(detected.getTime() + 3 * DAY),
          }
        : {}),
      ...(scanType === "sca"
        ? {
            componentPurl: `pkg:npm/p${i % 300}@1.0.0`,
            componentName: `p${i % 300}`,
            componentVersion: "1.0.0",
            ecosystem: "npm",
          }
        : {}),
    });
    const base = {
      tenantId: tenant.id,
      workspaceId: ws.id,
      repositoryId: pipeline.repositoryId,
      pipelineId: pipeline.id,
      findingId: id,
    };
    history.push({
      ...base,
      rev: 0,
      fromStatus: null,
      toStatus: "new",
      actorType: "system",
      actorCode: "ingestion",
      reasonCode: "detected",
      createdAt: detected,
    });
    if (i % 5 === 0)
      reviews.push({
        ...base,
        reviewerUserId: user.id,
        decision: i % 10 === 0 ? "true_positive" : "false_positive",
        rationale: "Perf review rationale.",
        state: "approved",
        createdAt: new Date(detected.getTime() + DAY),
        decidedAt: new Date(detected.getTime() + 2 * DAY),
      });
  }
  const batches = (rows, size = 5000) =>
    Array.from({ length: Math.ceil(rows.length / size) }, (_, k) =>
      rows.slice(k * size, (k + 1) * size),
    );
  const withoutTriggers = (fn) =>
    db.$transaction(
      async (tx) => {
        await tx.$executeRaw`SELECT set_config('session_replication_role', 'replica', true)`;
        return fn(tx);
      },
      { timeout: 600_000, maxWait: 60_000 },
    );
  for (const b of batches(findings))
    await withoutTriggers((tx) => tx.finding.createMany({ data: b }));
  for (const b of batches(history))
    await withoutTriggers((tx) => tx.findingStatusHistory.createMany({ data: b }));
  for (const b of batches(reviews))
    await withoutTriggers((tx) => tx.findingReview.createMany({ data: b }));
  const executions = [];
  for (let i = 0; i < 20_000; i += 1) {
    const pipeline = pipelines[i % 6];
    const version = versions.find((v) => v.pipelineId === pipeline.id);
    const requested = new Date(now - (i % 90) * DAY - (i % 1440) * 60_000);
    executions.push({
      tenantId: tenant.id,
      workspaceId: ws.id,
      repositoryId: pipeline.repositoryId,
      pipelineId: pipeline.id,
      configVersionId: version.id,
      configVersion: 1,
      configHash: version.configHash,
      triggerType: "push",
      triggerKey: "push-main",
      scmEventId: randomUUID(),
      scmDeliveryId: `d-${i}-${sfx}`,
      scmEventKind: "push",
      refType: "branch",
      refName: "main",
      scanKind: "full",
      scanKindReason: "first_run",
      concurrencyGroup: "ref:refs/heads/main",
      idempotencyKey: `perf:${sfx}:${i}`,
      status: i % 7 === 0 ? "failed" : "succeeded",
      ...(i % 7 === 0 ? { statusReason: "tool_failed" } : {}),
      requestedAt: requested,
      startedAt: new Date(requested.getTime() + 5000),
      finishedAt: new Date(requested.getTime() + 65_000),
    });
  }
  for (const b of batches(executions, 2000))
    await withoutTriggers((tx) => tx.execution.createMany({ data: b }));
  await db.$executeRawUnsafe("ANALYZE");
  const counts = {
    findings: await db.finding.count(),
    open: await db.finding.count({
      where: {
        status: {
          in: [
            "new",
            "in_review",
            "awaiting_approval",
            "approved",
            "assigned",
            "in_remediation",
            "fixed_pending_verification",
            "reopened",
          ],
        },
      },
    }),
    reviews: await db.findingReview.count(),
    executions: await db.execution.count(),
    history: await db.findingStatusHistory.count(),
  };

  // ---- the measurement ----------------------------------------------------------------------------------------------------------
  const api = await startReadApi(db, { redis: null });
  cleanups.push(() => api.close());
  api.register("perf", {
    userId: user.id,
    tenantId: tenant.id,
    tenant: ["dashboard.view"],
    workspaces: [
      {
        id: ws.id,
        permissions: ["finding.view", "finding.assign", "execution.view", "security_review.view"],
      },
    ],
  });
  const W = ws.id;
  const endpoints = [
    ["posture", `/reporting/posture?workspaceId=${W}`],
    ["coverage", `/reporting/coverage?workspaceId=${W}`],
    ["sla", `/reporting/sla?workspaceId=${W}`],
    ["remediation 90 d", `/reporting/remediation?workspaceId=${W}&period=90`],
    ["trends 90 d", `/reporting/trends?workspaceId=${W}&period=90`],
    ["aging", `/reporting/aging?workspaceId=${W}`],
    ["scan-activity 90 d", `/reporting/scan-activity?workspaceId=${W}&period=90`],
    ["quality 90 d", `/reporting/quality?workspaceId=${W}&period=90`],
    ["breakdown repository", `/reporting/breakdown?workspaceId=${W}&by=repository`],
    ["top-risk", `/reporting/top-risk?workspaceId=${W}`],
    ["workload", `/reporting/workload?workspaceId=${W}`],
    ["overview 30 d", "/reporting/overview?period=30"],
  ].filter(([name]) => ONLY.length === 0 || ONLY.some((o) => name.startsWith(o)));
  const results = [];
  for (const [name, url] of endpoints) {
    for (let i = 0; i < 3; i += 1) await api.get("perf", url);
    const ms = [];
    let status = 0;
    for (let i = 0; i < SAMPLES; i += 1) {
      const t = process.hrtime.bigint();
      const r = await api.get("perf", url);
      ms.push(Number(process.hrtime.bigint() - t) / 1e6);
      status = r.status;
    }
    ms.sort((a, b) => a - b);
    results.push({
      endpoint: name,
      status,
      p50: Math.round(ms[Math.floor(ms.length / 2)]),
      p95: Math.round(ms[Math.ceil(0.95 * ms.length) - 1]),
      max: Math.round(ms.at(-1)),
    });
  }
  console.log(JSON.stringify({ counts, samples: SAMPLES, results }, null, 2));
}

try {
  await main();
} finally {
  for (const fn of cleanups.reverse()) await Promise.resolve(fn()).catch(() => {});
}
process.exit(0);
