import { spawn } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, readdir, stat } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { inflateSync } from "node:zlib";
import { createJobEnvelope, parseMessage } from "@qmentisai/contracts";
import {
  createReportingExportWorkerRepository,
  createReportingReadRepository,
  createReportingRollupRepository,
} from "@qmentisai/db";
import {
  CSV_BOM,
  addDays,
  dayCloseInstant,
  csvSafeCell,
  getPermission,
  isValidTimeZone,
  localDayOf,
} from "@qmentisai/shared";
import { createRouteKit } from "../../../../src/lib/route-kit.js";
import { createAuthorization } from "../../../../src/middleware/authorization.js";
import { createExportAuthorization } from "../../../../src/modules/reporting/export-authorization.js";
import {
  createReportObjectReader,
  reportObjectKey as apiKey,
} from "../../../../src/modules/reporting/export-object-reader.js";
import { holdsExport } from "../../../../src/modules/reporting/services/export.js";
import { toTrendPoints } from "../../../../src/modules/reporting/mappers/read.js";
import { reportingRoutes } from "../../../../src/modules/reporting/routes/index.js";
import {
  createCsvStream,
  csvColumnsFor,
} from "../../../../../workers/src/reporting/export/csv-writer.js";
import {
  buildExportHandler,
  failureCodeOf,
} from "../../../../../workers/src/reporting/export/handler.js";
import {
  ReportTooLargeError,
  pdfText,
} from "../../../../../workers/src/reporting/export/pdf-kit.js";
import {
  createReportObjectStore,
  reportObjectKey as workerKey,
} from "../../../../../workers/src/reporting/export/object-store.js";
import { createRollupHandler } from "../../../../../workers/src/reporting/rollup/index.js";
import {
  buildRollupTick,
  runFileRetention,
} from "../../../../../workers/src/reporting/rollup/tick.js";
import { start as startReportingWorker } from "../../../../../workers/src/reporting/index.js";
import { FAKE } from "../../fixtures/scan-engines/secrets/tree-builder.js";
import { createClient } from "../http.js";
import { buildWorld } from "../world.js";

/**
 * Reporting Part E (cross-cutting) checks, ADR-008 area 20 (docs/modules/reporting-dashboards/SPEC.md 16.2, AS_BUILT_E.md):
 *  - `RPT-S13a`/`RPT-S13b` cross-part isolation: two tenants whose workspace, repository and pipeline NAMES overlap are rolled up by the REAL
 *    rollup handler and read, listed and exported through a REAL second API process (`REPORTING_ENABLED=true`): nothing of one tenant appears
 *    in the other's rollup rows, DTOs, CSV or PDF bytes (inflated and decoded), and a report id of one is the identical 404 for the other;
 *  - `RPT-S14a` the flag-off sweep and `RPT-S14b` the route inventory sweep (every reporting route is enumerated, gated and tenant scoped; a
 *    route that is not in the manifest fails the suite, so a future route cannot ship ungated);
 *  - `RPT-S10f` a tenant time-zone rebuild voids the run coverage of the range (the days read as unknown again, not as covered zeros);
 *  - `RPT-S08h` the hourly tick expires and deletes the report files of a tenant that never exports again;
 *  - `RPT-SM*` the checks added for the security-critical survivors of the mutation sweep (MUTATION_BACKLOG.md).
 * The checks run the REAL code. NOT proved here: a human reading of a PDF, a real broker, Redis or password-authenticated reporting logins
 * (docs/modules/reporting-dashboards/LIVE_TEST_PLAN.md).
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const apiDir = path.resolve(here, "../../../..");

const j = (v) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? String(x) : x));
const same = (p, label, got, want) => {
  if (j(got) !== j(want))
    p.push(`${label}: got ${j(got)?.slice(0, 300)}, want ${j(want)?.slice(0, 300)}`);
};
const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const hex = (n = 4) => randomBytes(n).toString("hex");
const quiet = { info() {}, warn() {}, error() {}, debug() {} };
const MSG = "reporting.rollup.requested";

/** A client that runs every statement as a restricted group role (the privileges of `qm_reporting` / `qm_reporting_ro`). */
const roleDb = (db, role) => {
  const run =
    (method) =>
    (...args) =>
      db.$transaction(
        async (tx) => {
          await tx.$executeRawUnsafe(`SET LOCAL ROLE ${role}`);
          return tx[method](...args);
        },
        { timeout: 120000, maxWait: 20000 },
      );
  return {
    $queryRaw: run("$queryRaw"),
    $executeRaw: run("$executeRaw"),
    $queryRawUnsafe: run("$queryRawUnsafe"),
    $executeRawUnsafe: run("$executeRawUnsafe"),
    $transaction: (fn, options) =>
      db.$transaction(async (tx) => {
        await tx.$executeRawUnsafe(`SET LOCAL ROLE ${role}`);
        return fn(tx);
      }, options),
  };
};

/** A real, catalogue-validated rollup envelope. */
const rollupMessage = (tenantId, payload, payloadTenant = tenantId) =>
  parseMessage(
    createJobEnvelope({
      messageId: `suite-e-${randomUUID()}`,
      type: MSG,
      schemaVersion: 1,
      tenantId,
      initiator: { type: "system", id: "suite" },
      payload: { tenantId: payloadTenant, ...payload },
    }),
  );

const setZone = (db, tenantId, zone) =>
  db.$executeRaw`INSERT INTO tenant_reporting_settings (tenant_id, reporting_timezone) VALUES (${tenantId}::uuid, ${zone}) ON CONFLICT (tenant_id) DO UPDATE SET reporting_timezone = ${zone}`;

// ---- PDF analysis (structure only, NOT a rendering) -----------------------------------------------------------------------------
function decodeStrings(chunk) {
  let out = "";
  for (const m of chunk.matchAll(/<([0-9a-fA-F\s]*)>|\(((?:\\.|[^\\)])*)\)/g)) {
    if (m[1] !== undefined) {
      const hexText = m[1].replace(/\s+/g, "");
      out += Buffer.from(hexText.length % 2 ? `${hexText}0` : hexText, "hex").toString("latin1");
    } else out += m[2].replace(/\\(.)/g, "$1");
  }
  return out;
}

/** Everything searchable in a PDF: its raw text, every stream (inflated when Flate) and the strings drawn on the pages. */
export function pdfCorpus(buf) {
  const s = buf.toString("latin1");
  const parts = [s];
  const re = /(?<!end)stream\r?\n/g;
  let m;
  while ((m = re.exec(s))) {
    const start = m.index + m[0].length;
    const end = s.indexOf("endstream", start);
    if (end < 0) break;
    let body = buf.subarray(start, end);
    try {
      body = inflateSync(body);
    } catch {
      /* not a Flate stream: the raw bytes stay */
    }
    const text = body.toString("latin1");
    parts.push(text);
    for (const arr of text.matchAll(/\[([^\]]*)\]\s*TJ/g)) parts.push(decodeStrings(arr[1]));
    for (const t of text.matchAll(/(<[0-9a-fA-F\s]*>|\((?:\\.|[^\\)])*\))\s*Tj/g))
      parts.push(decodeStrings(t[1]));
    re.lastIndex = end + "endstream".length;
  }
  return parts.join("\n");
}

// ---- the second API process (the module ON) -------------------------------------------------------------------------------------
const freePort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });

const need = (name) => {
  if (!process.env[name]) throw new Error(`${name} is not set (run through pnpm test:security)`);
  return process.env[name];
};

/** Starts `src/server.js` with `REPORTING_ENABLED=true` against the suite's disposable database (the pattern of Part C). */
async function startApi() {
  const keys = JSON.parse(need("SECURITY_CURSOR_KEYS"));
  const port = await freePort();
  const root = await mkdtemp(path.join(os.tmpdir(), "rpt-e-http-"));
  const output = [];
  const child = spawn(process.execPath, ["src/server.js"], {
    cwd: apiDir,
    env: {
      PATH: process.env.PATH,
      NODE_ENV: "test",
      API_HOST: "127.0.0.1",
      API_PORT: String(port),
      LOG_LEVEL: "warn",
      DATABASE_URL: need("SECURITY_DATABASE_URL"),
      MOCK_AUTH_PASSWORD: need("SECURITY_TENANT_PASSWORD"),
      MOCK_PLATFORM_AUTH_PASSWORD: need("SECURITY_PLATFORM_PASSWORD"),
      MOCK_PLATFORM_MFA_CODE: need("SECURITY_MFA_CODE"),
      CURSOR_SIGNING_SECRET: `${keys.current},${keys.previous}`,
      RATE_LIMIT_MAX: "100000",
      RATE_LIMIT_AUTH_MAX: "500",
      RATE_LIMIT_AUTH_WINDOW_MS: "5000",
      RATE_LIMIT_WRITE_MAX: "100000",
      REPORTING_ENABLED: "true",
      ARTIFACT_STORE_ROOT: root,
      PGSSLMODE: process.env.PGSSLMODE ?? "",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const collect = (chunk) => output.push(...String(chunk).split("\n").filter(Boolean));
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  child.stdout.unref();
  child.stderr.unref();
  child.unref();
  process.once("exit", () => child.kill("SIGTERM"));
  const baseUrl = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 120; i += 1) {
    if (child.exitCode !== null)
      throw new Error(`The reporting API exited (${output.slice(-5).join(" | ")})`);
    try {
      if ((await fetch(`${baseUrl}/health`)).ok) break;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return { baseUrl, root, output };
}

/** The twelve workspace reads and the overview of Part B: name, the key the route needs, the path of a workspace. */
const READS = Object.freeze([
  { name: "posture", path: (ws) => `/reporting/posture?workspaceId=${ws}` },
  { name: "trends", path: (ws) => `/reporting/trends?workspaceId=${ws}&period=30` },
  { name: "remediation", path: (ws) => `/reporting/remediation?workspaceId=${ws}&period=30` },
  { name: "sla", path: (ws) => `/reporting/sla?workspaceId=${ws}` },
  { name: "aging", path: (ws) => `/reporting/aging?workspaceId=${ws}` },
  { name: "scan-activity", path: (ws) => `/reporting/scan-activity?workspaceId=${ws}&period=7` },
  { name: "coverage", path: (ws) => `/reporting/coverage?workspaceId=${ws}` },
  { name: "sbom", path: (ws) => `/reporting/sbom?workspaceId=${ws}&period=7` },
  { name: "quality", path: (ws) => `/reporting/quality?workspaceId=${ws}&period=30` },
  {
    name: "breakdown-repository",
    path: (ws) => `/reporting/breakdown?workspaceId=${ws}&by=repository`,
  },
  {
    name: "breakdown-pipeline",
    path: (ws) => `/reporting/breakdown?workspaceId=${ws}&by=pipeline`,
  },
  { name: "top-risk", path: (ws) => `/reporting/top-risk?workspaceId=${ws}` },
  { name: "workload", path: (ws) => `/reporting/workload?workspaceId=${ws}` },
  { name: "overview", path: () => "/reporting/overview?period=7" },
]);

const SHARED = Object.freeze({
  workspace: "RPT-E Shared Workspace",
  repository: "shared-org/shared-api",
  pipeline: "shared-pipeline",
});
const RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * Two tenants (the demo tenant and the API-built tenant B of a SECOND world) with OVERLAPPING workspace, repository and pipeline names and
 * different counts, plus the second API process. Every tenant owns one tag string that appears in its finding titles, paths, rule ids, one
 * repository name and one pipeline name, so what leaks is searchable. Built once per world.
 */
function eWorld(c) {
  c.__rptE ??= (async () => {
    const { db } = c;
    const api = await startApi();
    const client = createClient({ baseUrl: api.baseUrl, origin: need("SECURITY_ORIGIN") });
    const w = await buildWorld(client, {
      tenantPassword: need("SECURITY_TENANT_PASSWORD"),
      platformPassword: need("SECURITY_PLATFORM_PASSWORD"),
      mfaCode: need("SECURITY_MFA_CODE"),
    });
    const demo = await db.tenant.findFirst({ where: { slug: "demo" } });
    const meId = async (cookie) => (await client.api("GET", "/me", { cookie })).json.data.user.id;
    const seed = async (tenant, cookie, tag, plan) => {
      const userId = await meId(cookie);
      const sfx = hex(3);
      const installation = await db.scmInstallation.create({
        data: {
          provider: "github",
          externalInstallationId: `rpte-${tag}-${sfx}`,
          accountExternalId: `rpte-${tag}-${sfx}`,
          accountLogin: `rpte-${tag}-org`,
          accountType: "organization",
          repositorySelection: "all",
        },
      });
      const link = await db.scmInstallationLink.create({
        data: { tenantId: tenant.id, installationId: installation.id, linkedByUserId: userId },
      });
      const ws = await db.workspace.create({
        data: { tenantId: tenant.id, name: SHARED.workspace },
      });
      const wl = await db.scmWorkspaceLink.create({
        data: { tenantId: tenant.id, workspaceId: ws.id, linkId: link.id, linkedByUserId: userId },
      });
      const repo = (n, fullName) =>
        db.repository.create({
          data: {
            tenantId: tenant.id,
            workspaceId: ws.id,
            linkId: link.id,
            workspaceLinkId: wl.id,
            provider: "github",
            externalRepoId: `rpte-${tag}-${n}-${sfx}`,
            fullName,
            name: fullName.split("/")[1],
            ownerLogin: fullName.split("/")[0],
            connectedByUserId: userId,
          },
        });
      const repoShared = await repo("s", SHARED.repository);
      const repoUnique = await repo("u", `${tag}-org/${tag}-svc`);
      const tree = {
        tenant: { id: tenant.id },
        user: { id: userId },
        ws: [ws, ws],
        repo: [repoShared, repoUnique],
      };
      const pipeNames = [SHARED.pipeline, `${tag}-pipe`];
      const pipelines = [];
      for (const [i, name] of pipeNames.entries())
        pipelines.push(await c.pipeline(tree, i, { name, nameNormalized: name }));
      const findings = [];
      let n = 0;
      for (const [pi, severity] of plan) {
        n += 1;
        findings.push(
          await c.finding(pipelines[pi], {
            title: `${tag} finding ${n}`,
            ruleId: `rule.${tag}.${n}`,
            path: `src/${tag}/file${n}.js`,
            severity,
            toolSeverity: severity,
            severityRank: RANK[severity],
          }),
        );
      }
      const ids = [
        tenant.id,
        ws.id,
        repoShared.id,
        repoUnique.id,
        ...pipelines.map((x) => x.id),
        ...findings.map((x) => x.id),
      ];
      return {
        tenantId: tenant.id,
        cookie,
        userId,
        tag,
        workspaceId: ws.id,
        pipelines,
        findings,
        ids,
        total: plan.length,
        uniqueNames: [tag, `${tag}-org/${tag}-svc`, `${tag}-pipe`],
      };
    };
    // A: 3 findings, B: 5 findings (the counts differ, so a mix-up cannot sum to the right number by chance)
    const A = await seed(demo, w.sessions.admin, `alpha${hex(3)}`, [
      [0, "high"],
      [0, "high"],
      [1, "low"],
    ]);
    const B = await seed({ id: w.B.id }, w.sessions.bOwner, `beta${hex(3)}`, [
      [0, "critical"],
      [1, "medium"],
      [1, "medium"],
      [1, "medium"],
      [0, "medium"],
    ]);
    // the REAL rollup handler on the restricted role, for both tenants
    const workerDb = roleDb(db, "qm_reporting");
    const repo = createReportingRollupRepository({ db: workerDb });
    const now = new Date();
    const handler = createRollupHandler({
      rollupRepository: repo,
      config: { reporting: { enabled: true, rollupRetentionMonths: 25 } },
      logger: quiet,
      now: () => now,
      options: { throttleMs: 0 },
    });
    const today = localDayOf(now, "UTC");
    for (const T of [A, B]) {
      await setZone(db, T.tenantId, "UTC");
      await handler(
        rollupMessage(T.tenantId, { mode: "backfill", from: addDays(today, -2), to: today }),
        { log: quiet },
      );
      await handler(rollupMessage(T.tenantId, { mode: "incremental", day: today }), { log: quiet });
    }
    const exportHandler = buildExportHandler({
      exportRepository: createReportingExportWorkerRepository({ db: workerDb }),
      config: {
        execution: { artifactStoreRoot: api.root },
        reporting: { exportRetentionDays: 30 },
      },
      logger: quiet,
      store: createReportObjectStore({ root: api.root }),
    });
    return { ...api, client, w, api: client.api, A, B, demo, today, exportHandler, handler, now };
  })();
  return c.__rptE;
}

/** The body of a response without the per-request correlation id (what must be identical across two 404s). */
const bare = (r) =>
  j({ status: r.status, ...r.json, meta: { ...r.json?.meta, correlationId: undefined } });

/** The strings of `needles` found in `text`. */
const found = (text, needles) => needles.filter((n) => n && text.includes(n));

// ------------------------------------------------------------------------------------------------------------------------------------
// the checks
// ------------------------------------------------------------------------------------------------------------------------------------

const UNKNOWN = "00000000-0000-4000-8000-0000000000e1";

/** The report requests of S13b: a CSV, a PDF of the same template and the executive PDF. */
const EXPORT_REQUESTS = (ws) => [
  { template: "findings_by_pipeline", format: "csv", workspaceId: ws },
  { template: "findings_by_pipeline", format: "pdf", workspaceId: ws },
  { template: "executive_summary", format: "pdf", workspaceId: ws, period: "30" },
];

/** Generates the reports of a tenant (request through the real API, worker handler in process) and reads every file back. */
async function generateReports(e, T) {
  T.reports ??= [];
  if (T.reports.length > 0) return T.reports;
  for (const body of EXPORT_REQUESTS(T.workspaceId)) {
    const r = await e.api("POST", "/reporting/reports", {
      cookie: T.cookie,
      body,
      headers: { "Idempotency-Key": `rpte-${hex(8)}` },
    });
    if (r.status !== 202)
      throw new Error(`report request answered ${r.status} ${r.text.slice(0, 600)}`);
    const id = r.json.data.reportId;
    await e.exportHandler({ tenantId: T.tenantId, payload: { reportId: id } }, { log: quiet });
    const status = await e.api("GET", `/reporting/reports/${id}`, { cookie: T.cookie });
    const dl = await fetch(`${e.baseUrl}/api/v1/reporting/reports/${id}/download`, {
      headers: { cookie: T.cookie, origin: need("SECURITY_ORIGIN") },
    });
    const bytes = Buffer.from(await dl.arrayBuffer());
    T.reports.push({
      id,
      body,
      state: status.json?.data?.status,
      downloadStatus: dl.status,
      bytes,
      text: body.format === "csv" ? bytes.toString("utf8") : pdfCorpus(bytes),
    });
  }
  return T.reports;
}

const S13A = {
  id: "RPT-S13a",
  name: "Cross-part isolation of the rollup and the reads (SPEC 16.2 RPT-S13, ADR-003, ADR-015): two tenants with the SAME workspace, repository and pipeline names and different counts are rolled up by the REAL rollup handler on the restricted role, and read through the REAL API process (REPORTING_ENABLED=true): every rollup row of a tenant belongs to its own pipelines and sums to its own count, no row names a pipeline of the other, every one of the 14 read DTOs answers 200 for the owner and carries none of the other tenant's ids or unique names (and the shared names and own names ARE present, so the search is not vacuous), and the other tenant's session gets the identical 404 for every workspace read",
  async run(c) {
    const p = [];
    const e = await eWorld(c);
    const { db } = c;
    for (const [T, O] of [
      [e.A, e.B],
      [e.B, e.A],
    ]) {
      const label = T.tag;
      const rows =
        await db.$queryRaw`SELECT pipeline_id::text AS pid, workspace_id::text AS wid, day::text AS day, open_count FROM report_daily_findings WHERE tenant_id = ${T.tenantId}::uuid AND workspace_id = ${T.workspaceId}::uuid`;
      ok(p, rows.length > 0, `${label}: the rollup wrote no row (a vacuous check)`);
      const mine = new Set(T.pipelines.map((x) => x.id));
      ok(
        p,
        rows.every((r) => mine.has(r.pid)),
        `${label}: a rollup row of the workspace names a pipeline that is not the workspace's`,
      );
      same(
        p,
        `${label}: open findings of today in the rollup`,
        rows.filter((r) => r.day === e.today).reduce((a, r) => a + Number(r.open_count), 0),
        T.total,
      );
      for (const table of [
        "report_daily_findings",
        "report_daily_executions",
        "report_daily_decisions",
        "report_daily_sbom",
      ]) {
        const leaked = await db.$queryRawUnsafe(
          `SELECT count(*)::int AS n FROM ${table} WHERE tenant_id = $1::uuid AND (pipeline_id = ANY($2::uuid[]) OR workspace_id = $3::uuid)`,
          T.tenantId,
          O.pipelines.map((x) => x.id),
          O.workspaceId,
        );
        same(
          p,
          `${label}: rows of ${table} naming the other tenant's pipelines or workspace`,
          leaked[0].n,
          0,
        );
      }
      const runs =
        await db.$queryRaw`SELECT count(*)::int AS n FROM report_rollup_runs WHERE tenant_id = ${T.tenantId}::uuid AND status = 'succeeded'`;
      ok(p, runs[0].n >= 2, `${label}: the rollup runs of the tenant are missing`);
    }
    // the reads: the owner reads 200 and no byte of the other tenant appears
    for (const [T, O] of [
      [e.A, e.B],
      [e.B, e.A],
    ]) {
      const label = T.tag;
      let corpus = "";
      let posture = null;
      for (const read of READS) {
        const r = await e.api("GET", read.path(T.workspaceId), { cookie: T.cookie });
        same(p, `${label} ${read.name} status`, r.status, 200);
        if (read.name === "posture") posture = r.json?.data;
        corpus += `\n${r.text}`;
      }
      same(p, `${label}: ids of the other tenant in the DTOs`, found(corpus, O.ids), []);
      same(
        p,
        `${label}: unique names of the other tenant in the DTOs`,
        found(corpus, O.uniqueNames),
        [],
      );
      ok(
        p,
        corpus.includes(T.uniqueNames[1]),
        `${label}: own repository name missing from the reads (a vacuous search)`,
      );
      ok(
        p,
        corpus.includes(T.uniqueNames[2]),
        `${label}: own pipeline name missing from the reads (a vacuous search)`,
      );
      ok(
        p,
        corpus.includes(SHARED.repository) && corpus.includes(SHARED.pipeline),
        `${label}: the shared names are missing (the overlap is not exercised)`,
      );
      ok(
        p,
        j(posture).includes(`:${T.total}`),
        `${label}: the posture does not carry the tenant's own count ${T.total}: ${j(posture)?.slice(0, 200)}`,
      );
      // the other tenant's session: the identical 404 on every workspace read
      for (const read of READS.filter((x) => x.name !== "overview")) {
        const foreign = await e.api("GET", read.path(T.workspaceId), { cookie: O.cookie });
        same(
          p,
          `${read.name} of ${label}'s workspace by the other tenant`,
          [foreign.status, foreign.json?.error?.code],
          [404, "RESOURCE_NOT_FOUND"],
        );
        const ref = await e.api("GET", read.path(UNKNOWN), { cookie: O.cookie });
        same(p, `${read.name}: a foreign workspace equals an unknown id`, bare(foreign), bare(ref));
      }
    }
    return p;
  },
};

const S13B = {
  id: "RPT-S13b",
  name: "Cross-part isolation of the exports (SPEC 16.2 RPT-S13, ADR-003): each of the two tenants generates a CSV and two PDFs through the real API (the worker handler in process), the files are read back (the PDFs are inflated and their page strings decoded): every report is ready and downloads with 200, the files carry the tenant's own unique names (control) and none of the other tenant's ids, titles, paths or unique names, the CSV has exactly the tenant's own rows, and a report id of one tenant is the identical 404 for the other on read, download and delete (the report survives the attempt) and never appears in the other's list",
  async run(c) {
    const p = [];
    const e = await eWorld(c);
    for (const T of [e.A, e.B]) await generateReports(e, T);
    for (const [T, O] of [
      [e.A, e.B],
      [e.B, e.A],
    ]) {
      const label = T.tag;
      for (const r of T.reports) {
        const what = `${label} ${r.body.template}.${r.body.format}`;
        same(p, `${what} state and download`, [r.state, r.downloadStatus], ["ready", 200]);
        same(p, `${what}: ids of the other tenant`, found(r.text, O.ids), []);
        same(p, `${what}: unique names of the other tenant`, found(r.text, O.uniqueNames), []);
        same(
          p,
          `${what}: the other tenant's finding text`,
          found(r.text, [`${O.tag} finding`, `src/${O.tag}`, `rule.${O.tag}`]),
          [],
        );
        if (r.body.format === "pdf")
          ok(p, r.bytes.subarray(0, 5).toString() === "%PDF-", `${what} is not a PDF`);
      }
      const csv = T.reports.find((r) => r.body.format === "csv");
      same(
        p,
        `${label} CSV: the rows of the tenant`,
        (csv.text.match(new RegExp(`${T.tag} finding \\d+`, "g")) ?? []).length,
        T.total,
      );
      ok(
        p,
        csv.text.includes(SHARED.repository) && csv.text.includes(`${T.tag}-org/${T.tag}-svc`),
        `${label} CSV: the repository names are missing (a vacuous search)`,
      );
      const byPipeline = T.reports.find(
        (r) => r.body.template === "findings_by_pipeline" && r.body.format === "pdf",
      );
      ok(
        p,
        byPipeline.text.includes(`${T.tag}-pipe`),
        `${label} PDF: the tenant's own pipeline name is missing from the decoded page text (a vacuous search)`,
      );
      // the other tenant's session on this tenant's report ids
      const id = T.reports[0].id;
      for (const [method, suffix] of [
        ["GET", ""],
        ["GET", "/download"],
        ["DELETE", ""],
      ]) {
        const r = await e.api(method, `/reporting/reports/${id}${suffix}`, { cookie: O.cookie });
        same(
          p,
          `${method} ${suffix || "report"} of ${label}'s report by the other tenant`,
          [r.status, r.json?.error?.code],
          [404, "RESOURCE_NOT_FOUND"],
        );
        const unknown = await e.api(method, `/reporting/reports/${UNKNOWN}${suffix}`, {
          cookie: O.cookie,
        });
        same(
          p,
          `${method} ${suffix || "report"}: another tenant's id equals an unknown id`,
          bare(r),
          bare(unknown),
        );
      }
      const list = await e.api("GET", `/reporting/reports?workspaceId=${O.workspaceId}`, {
        cookie: O.cookie,
      });
      same(p, `the list of ${O.tag}`, list.status, 200);
      const listed = (list.json?.data?.items ?? list.json?.data ?? []).map(
        (x) => x.id ?? x.reportId,
      );
      same(
        p,
        `${label}'s report ids in the other tenant's list`,
        listed.filter((x) => T.reports.some((r) => r.id === x)),
        [],
      );
      ok(
        p,
        O.reports.every((r) => listed.includes(r.id)),
        `${O.tag}: its own reports are missing from its list (${listed.length} listed; a vacuous search)`,
      );
      const foreignList = await e.api("GET", `/reporting/reports?workspaceId=${T.workspaceId}`, {
        cookie: O.cookie,
      });
      const unknownList = await e.api("GET", `/reporting/reports?workspaceId=${UNKNOWN}`, {
        cookie: O.cookie,
      });
      same(
        p,
        "a foreign workspace list equals an unknown one",
        bare(foreignList),
        bare(unknownList),
      );
      same(p, "a foreign workspace list status", foreignList.status, 404);
    }
    // the attempts above deleted nothing: both tenants still download every report
    for (const T of [e.A, e.B])
      for (const r of T.reports) {
        const dl = await fetch(`${e.baseUrl}/api/v1/reporting/reports/${r.id}/download`, {
          headers: { cookie: T.cookie, origin: need("SECURITY_ORIGIN") },
        });
        same(
          p,
          `${T.tag} report ${r.body.template}.${r.body.format} still downloads`,
          dl.status,
          200,
        );
      }
    return p;
  },
};

// ---- RPT-S10f: the rebuild voids the run coverage -----------------------------------------------------------------------------------

const S10F = {
  id: "RPT-S10f",
  name: "A tenant time-zone rebuild voids the run coverage of its range (SPEC 7.2, RPT-020, AS_BUILT_AM.md 'not verified', Part E fix 1): a tenant with live (close and incremental) runs of the old zone reads its state series as KNOWN on those days; after the switch to Pacific/Auckland and the rebuild (`timezone_changed`) the state series of every day of the rebuilt range reads null again (never a covered zero), the first exact day is gone until a live run of the new zone exists, the flow series is covered by the rebuild's own backfill runs, the voided runs are `failed`/`invalid_range` (never deleted), a later live run restores the state of ITS day only, and an ordinary `clearRange` (no flag) leaves the ledger alone",
  async run(c) {
    const p = [];
    const { db } = c;
    const T = c.A.tenant.id;
    const workerDb = roleDb(db, "qm_reporting");
    const repo = createReportingRollupRepository({ db: workerDb });
    const readRepo = createReportingReadRepository({ db: roleDb(db, "qm_reporting_ro") });
    const clock = { now: new Date() };
    const handler = createRollupHandler({
      rollupRepository: repo,
      config: { reporting: { enabled: true, rollupRetentionMonths: 25 } },
      logger: quiet,
      now: () => clock.now,
      options: { throttleMs: 0 },
    });
    const run = (payload) => handler(rollupMessage(T, payload), { log: quiet });
    const clean = async () => {
      await repo.clearRange({ tenantId: T, from: "2000-01-01", to: "2099-12-31" });
      await db.$executeRaw`DELETE FROM report_rollup_runs WHERE tenant_id = ${T}::uuid`;
    };
    const series = async (zone, from, to) => {
      const ws = c.A.ws[0].id;
      const fresh = await readRepo.getRollupFreshness({ tenantId: T });
      const raw = await readRepo.getTrends({ tenantId: T, workspaceId: ws, from, to });
      const points = toTrendPoints(raw, {
        from,
        to,
        series: ["flow", "severity", "backlog"],
        firstExactDay: fresh.firstExactDay,
      });
      void zone;
      return { fresh, points };
    };
    try {
      await clean();
      await setZone(db, T, "Europe/Berlin");
      const pipeline = await c.pipeline(c.A, 0);
      await c.finding(pipeline, { title: "rebuild coverage", severity: "high", severityRank: 3 });
      const today = localDayOf(clock.now, "Europe/Berlin");
      const D = (n) => addDays(today, -n);
      // the live history of the OLD zone: a close per day for six days and an incremental today, plus ten days of flow
      // each close runs one hour after ITS day ended (within the lag): a close that comes later cannot write exact state and is recorded as a
      // one-day backfill, not as a close (RPT-S10 family), so the live history of the old zone must be built the way a live worker builds it
      const realNow = clock.now;
      for (let n = 6; n >= 1; n -= 1) {
        clock.now = new Date(dayCloseInstant(D(n), "Europe/Berlin").getTime() + 60 * 60 * 1000);
        await run({ mode: "close", day: D(n) });
      }
      clock.now = realNow;
      await run({ mode: "incremental", day: today });
      await run({ mode: "backfill", from: D(9), to: today });
      const before = await series("Europe/Berlin", D(9), today);
      same(p, "the first exact day before the rebuild", before.fresh.firstExactDay, D(6));
      ok(
        p,
        before.points.slice(3).every((x) => x.open !== null && x.openBySeverity !== null),
        `the state series is not known from the first exact day before the rebuild (a vacuous check): ${j(before.points.map((x) => x.open))}`,
      );
      // a plain clear (no flag) does not touch the ledger
      await repo.clearRange({ tenantId: T, from: D(1), to: D(1) });
      const stillRuns =
        await db.$queryRaw`SELECT count(*)::int AS n FROM report_rollup_runs WHERE tenant_id = ${T}::uuid AND status = 'succeeded' AND mode = 'close' AND day = ${D(1)}::date`;
      same(p, "a clearRange without voidCoverage leaves the run ledger alone", stillRuns[0].n, 1);
      // the switch and the rebuild
      await setZone(db, T, "Pacific/Auckland");
      const newToday = localDayOf(clock.now, "Pacific/Auckland");
      const N = (n) => addDays(newToday, -n);
      await run({ mode: "backfill", from: D(9), to: newToday, reason: "timezone_changed" });
      const after = await series("Pacific/Auckland", N(9), newToday);
      same(p, "the first exact day after the rebuild", after.fresh.firstExactDay, null);
      ok(
        p,
        after.points.every((x) => x.open === null && x.openBySeverity === null),
        `a day of the rebuilt range still reads a known state series (a covered zero): ${j(after.points.map((x) => x.open))}`,
      );
      ok(
        p,
        after.points.every((x) => x.new !== null && x.fixed !== null),
        `the flow series of the rebuilt range is not covered by the rebuild's backfill: ${j(after.points.map((x) => x.new))}`,
      );
      const voided =
        await db.$queryRaw`SELECT mode, status, error_code FROM report_rollup_runs WHERE tenant_id = ${T}::uuid AND mode IN ('close', 'incremental')`;
      ok(
        p,
        voided.length >= 7,
        `the old runs were deleted instead of voided (${voided.length} left)`,
      );
      ok(
        p,
        voided.every((r) => r.status === "failed" && r.error_code === "invalid_range"),
        `a live run of the old zone is still counted: ${j(voided)}`,
      );
      // a live run of the new zone restores the state of its own day only
      await run({ mode: "incremental", day: newToday });
      const restored = await series("Pacific/Auckland", N(9), newToday);
      same(p, "the first exact day after a live run", restored.fresh.firstExactDay, newToday);
      ok(
        p,
        restored.points.slice(0, -1).every((x) => x.open === null),
        `a day before the restart reads a state again: ${j(restored.points.map((x) => x.open))}`,
      );
      ok(p, restored.points.at(-1).open !== null, "the restart day has no state");
      // a repeated rebuild is stable
      await run({ mode: "backfill", from: D(9), to: newToday, reason: "timezone_changed" });
      same(
        p,
        "a repeated rebuild voids the new live run too",
        (await series("Pacific/Auckland", N(9), newToday)).fresh.firstExactDay,
        null,
      );
    } finally {
      await clean().catch(() => {});
      await db.$executeRaw`DELETE FROM tenant_reporting_settings WHERE tenant_id = ${T}::uuid`.catch(
        () => {},
      );
    }
    return p;
  },
};

// ---- RPT-S08h: the tick deletes the files of a tenant that never exports again -------------------------------------------------------

const S08H = {
  id: "RPT-S08h",
  name: "File retention from the hourly tick (SPEC 8.6, owner ruling 30 days, Part E fix 2): a tenant that never exports again has a ready report past its expiry; the REAL tick (`buildRollupTick`, with no tenant to roll up) marks it `expired` and removes its file, leaves a live report of the same tenant and the file of a tenant it must not touch, touches nothing while REPORTING_ENABLED is false or the store root is unset, is bounded, and a failing store never stops the tick",
  async run(c) {
    const p = [];
    const { db } = c;
    const root = await mkdtemp(path.join(os.tmpdir(), "rpt-e-ret-"));
    const store = createReportObjectStore({ root });
    const exportRepository = createReportingExportWorkerRepository({
      db: roleDb(db, "qm_reporting"),
    });
    const tenantA = c.A.tenant.id;
    const tenantB = c.B.tenant.id;
    const make = async (T, ws, userId, { expired, format = "csv" }) => {
      const id = randomUUID();
      const ref = { tenantId: T, reportId: id, format };
      const put = await store.put(ref, Readable.from([Buffer.from("a,b\n1,2\n")]), {
        maxBytes: 1024,
      });
      await db.reportExport.create({
        data: {
          id,
          tenantId: T,
          workspaceId: ws,
          template: "findings_by_pipeline",
          format,
          status: "ready",
          requestedByUserId: userId,
          startedAt: new Date(Date.now() - 5000),
          finishedAt: new Date(Date.now() - 4000),
          expiresAt: new Date(Date.now() + (expired ? -60_000 : 86_400_000)),
          objectKey: put.key,
          bytes: put.bytes,
          sha256: put.sha256,
          rowCount: 1,
        },
      });
      return ref;
    };
    const status = async (ref) =>
      (await db.reportExport.findFirst({ where: { tenantId: ref.tenantId, id: ref.reportId } }))
        ?.status;
    const exists = async (ref) => (await store.size(ref)) !== null;
    const logs = [];
    const logger = { info() {}, warn: (...a) => logs.push(a), error() {}, debug() {} };
    const idleRollup = { listActiveTenants: async () => [] };
    const wait = async (cond) => {
      for (let i = 0; i < 100; i += 1) {
        if (await cond()) return true;
        await new Promise((r) => setTimeout(r, 50));
      }
      return false;
    };
    const configOn = {
      reporting: { enabled: true },
      execution: { artifactStoreRoot: root },
    };
    const expiredA = await make(tenantA, c.A.ws[0].id, c.A.user.id, { expired: true });
    const expiredPdf = await make(tenantA, c.A.ws[0].id, c.A.user.id, {
      expired: true,
      format: "pdf",
    });
    const liveA = await make(tenantA, c.A.ws[0].id, c.A.user.id, { expired: false });
    const expiredB = await make(tenantB, c.B.ws[0].id, c.B.user.id, { expired: true });
    ok(p, (await exists(expiredA)) && (await exists(liveA)), "the fixture files are missing");
    // the flag off and no store root: nothing happens
    same(
      p,
      "the retention pass with the module off",
      await runFileRetention({
        exportRepository,
        config: { ...configOn, reporting: { enabled: false } },
        logger,
      }),
      { expired: 0, removed: 0 },
    );
    same(
      p,
      "the retention pass without a store root",
      await runFileRetention({
        exportRepository,
        config: { reporting: { enabled: true } },
        logger,
      }),
      { expired: 0, removed: 0 },
    );
    same(
      p,
      "an expired report is untouched while the module is off",
      [await status(expiredA), await exists(expiredA)],
      ["ready", true],
    );
    same(
      p,
      "the tick does not even start while the module is off",
      buildRollupTick({
        db,
        rollupRepository: idleRollup,
        exportRepository,
        config: { ...configOn, reporting: { enabled: false } },
        logger,
      }),
      null,
    );
    // the real tick
    const tick = buildRollupTick({
      db,
      rollupRepository: idleRollup,
      exportRepository,
      config: configOn,
      logger,
    });
    ok(p, tick !== null, "the tick did not start with the module on");
    try {
      const gone = await wait(
        async () => (await status(expiredA)) === "expired" && !(await exists(expiredA)),
      );
      ok(
        p,
        gone,
        `the tick did not expire and delete the file (${await status(expiredA)}, file ${await exists(expiredA)})`,
      );
      await wait(async () => (await status(expiredB)) === "expired");
    } finally {
      await tick?.stop();
    }
    same(
      p,
      "the expired pdf of the tenant",
      [await status(expiredPdf), await exists(expiredPdf)],
      ["expired", false],
    );
    same(
      p,
      "the expired report of the other tenant (its own file, its own row)",
      [await status(expiredB), await exists(expiredB)],
      ["expired", false],
    );
    same(
      p,
      "the live report of the tenant",
      [await status(liveA), await exists(liveA)],
      ["ready", true],
    );
    // a store that fails never stops the tick: the pass reports and returns
    const failing = {
      delete: async () => {
        throw new Error("store down");
      },
    };
    const stuck = await make(tenantA, c.A.ws[0].id, c.A.user.id, { expired: true });
    const result = await runFileRetention({
      exportRepository,
      config: configOn,
      logger,
      store: failing,
    });
    same(p, "a failing store", [result.expired, result.removed], [1, 0]);
    void stuck;
    // bounded loop: 105 expired reports (more than one call of 100) are all done by ONE pass
    const many = Array.from({ length: 105 }, () => randomUUID());
    await db.reportExport.createMany({
      data: many.map((id) => ({
        id,
        tenantId: tenantA,
        workspaceId: c.A.ws[0].id,
        template: "findings_by_pipeline",
        format: "csv",
        status: "ready",
        requestedByUserId: c.A.user.id,
        startedAt: new Date(Date.now() - 5000),
        finishedAt: new Date(Date.now() - 4000),
        expiresAt: new Date(Date.now() - 60_000),
        objectKey: `reports/${tenantA}/${id}.csv`,
        bytes: 1,
        sha256: "a".repeat(64),
        rowCount: 1,
      })),
    });
    const pass = await runFileRetention({ exportRepository, config: configOn, logger });
    same(p, "105 expired reports in one pass", [pass.expired, pass.removed], [105, 105]);
    same(
      p,
      "none of them is left ready",
      await db.reportExport.count({ where: { id: { in: many }, status: "ready" } }),
      0,
    );
    return p;
  },
};

// ---- the route manifest of the module ---------------------------------------------------------------------------------------------

/**
 * EVERY reporting route, written out here (SPEC 7.1, 7.3, 12, 3): method, path, the permission the route's central gate asks for, the scope
 * of that permission, the rate-limit profile and whether the route takes an idempotency key. A route that exists in the app and is not in
 * this table fails RPT-S14b, so a new route cannot ship ungated or untested for tenant scope. `probe(ws, id)` builds a valid request.
 * @type {ReadonlyArray<{ method: string, url: string, permission: string, scope: "workspace" | "tenant", rateLimit: string, idempotent: boolean, probe: (ws: string, id: string) => { path: string, body?: any } }>}
 */
export const REPORTING_ROUTE_MANIFEST = Object.freeze([
  ...[
    ["posture", "finding.view", (ws) => `workspaceId=${ws}`],
    ["trends", "finding.view", (ws) => `workspaceId=${ws}&period=30`],
    ["remediation", "finding.view", (ws) => `workspaceId=${ws}&period=30`],
    ["sla", "finding.view", (ws) => `workspaceId=${ws}`],
    ["aging", "finding.view", (ws) => `workspaceId=${ws}`],
    ["scan-activity", "execution.view", (ws) => `workspaceId=${ws}&period=7`],
    ["coverage", "execution.view", (ws) => `workspaceId=${ws}`],
    ["sbom", "execution.view", (ws) => `workspaceId=${ws}&period=7`],
    ["quality", "security_review.view", (ws) => `workspaceId=${ws}&period=30`],
    ["breakdown", "finding.view", (ws) => `workspaceId=${ws}&by=repository`],
    ["top-risk", "finding.view", (ws) => `workspaceId=${ws}`],
    ["workload", "finding.assign", (ws) => `workspaceId=${ws}`],
  ].map(([name, permission, query]) =>
    Object.freeze({
      method: "GET",
      url: `/reporting/${name}`,
      permission,
      scope: "workspace",
      rateLimit: "read",
      idempotent: false,
      probe: (ws) => ({ path: `/reporting/${name}?${query(ws)}` }),
    }),
  ),
  Object.freeze({
    method: "GET",
    url: "/reporting/overview",
    permission: "dashboard.view",
    scope: "tenant",
    rateLimit: "read",
    idempotent: false,
    probe: () => ({ path: "/reporting/overview?period=7" }),
  }),
  Object.freeze({
    method: "POST",
    url: "/reporting/reports",
    permission: "report.export",
    scope: "workspace",
    rateLimit: "write",
    idempotent: true,
    probe: (ws) => ({
      path: "/reporting/reports",
      body: { template: "findings_by_pipeline", format: "csv", workspaceId: ws },
    }),
  }),
  Object.freeze({
    method: "GET",
    url: "/reporting/reports",
    permission: "report.view",
    scope: "workspace",
    rateLimit: "read",
    idempotent: false,
    probe: (ws) => ({ path: `/reporting/reports?workspaceId=${ws}` }),
  }),
  Object.freeze({
    method: "GET",
    url: "/reporting/reports/:id",
    permission: "report.view",
    scope: "workspace",
    rateLimit: "read",
    idempotent: false,
    probe: (_ws, id) => ({ path: `/reporting/reports/${id}` }),
  }),
  Object.freeze({
    method: "GET",
    url: "/reporting/reports/:id/download",
    permission: "report.view",
    scope: "workspace",
    rateLimit: "write",
    idempotent: false,
    probe: (_ws, id) => ({ path: `/reporting/reports/${id}/download` }),
  }),
  Object.freeze({
    method: "DELETE",
    url: "/reporting/reports/:id",
    permission: "report.view",
    scope: "workspace",
    rateLimit: "write",
    idempotent: false,
    probe: (_ws, id) => ({ path: `/reporting/reports/${id}` }),
  }),
]);

/**
 * Compares the routes an app registers with the manifest (pure, so a planted deviation proves the comparison can fail). `routes` are the
 * records of the route kit (`method`, `url` under `/api/v1`, `audience`, `permission`, `rateLimit`, `idempotent`).
 * @param {any[]} routes @param {ReadonlyArray<any>} manifest @returns {string[]}
 */
export function inventoryProblems(routes, manifest) {
  const p = [];
  const key = (r) => `${r.method} ${r.url.replace(/^\/api\/v1/, "")}`;
  const got = routes.map(key).sort();
  const want = manifest.map(key).sort();
  for (const k of got)
    if (!want.includes(k)) p.push(`route ${k} is registered but not in the manifest`);
  for (const k of want)
    if (!got.includes(k)) p.push(`route ${k} is in the manifest but not registered`);
  if (new Set(got).size !== got.length) p.push("a route is registered twice");
  for (const r of routes) {
    const row = manifest.find((m) => key(m) === key(r));
    if (r.url.startsWith("/api/v1/platform") || r.url.startsWith("/platform"))
      p.push(`${key(r)} sits under /platform`);
    if (r.audience !== "tenant") p.push(`${key(r)} audience is ${r.audience}, not tenant`);
    if (!r.permission) p.push(`${key(r)} has no permission gate`);
    else {
      const entry = getPermission(r.permission);
      if (!entry || (entry.scope !== "workspace" && entry.scope !== "tenant"))
        p.push(`${key(r)} asks for ${r.permission}, which is not a tenant or workspace permission`);
      else if (row && entry.scope !== row.scope)
        p.push(`${key(r)} gate scope is ${entry.scope}, the manifest says ${row.scope}`);
    }
    if (!row) continue;
    if (r.permission !== row.permission)
      p.push(`${key(r)} permission is ${r.permission}, the manifest says ${row.permission}`);
    if (r.rateLimit !== row.rateLimit)
      p.push(`${key(r)} rate limit is ${r.rateLimit}, the manifest says ${row.rateLimit}`);
    if (Boolean(r.idempotent) !== row.idempotent)
      p.push(`${key(r)} idempotency flag is ${r.idempotent}, the manifest says ${row.idempotent}`);
  }
  for (const r of routes) {
    if (r.method !== "GET" && r.rateLimit !== "write")
      p.push(`${key(r)} is a write without the write limit`);
    if (r.method === "POST" && !r.idempotent)
      p.push(`${key(r)} is a POST without an idempotency key`);
  }
  return p;
}

/** Registers the REAL reporting routes against a recorder (module ON) and returns the route kit's table. */
async function recordRoutes(enabled) {
  const pass = (_req, _res, next) => next();
  const kit = createRouteKit({
    chains: { public: [pass], user: [pass], tenant: [pass], platform: [pass] },
    limiters: { forRoute: () => pass },
    idempotency: { forRoute: () => pass },
  });
  const tripwire = new Proxy(
    {},
    {
      get() {
        throw new Error("the recorder never touches the database");
      },
    },
  );
  await reportingRoutes({
    db: tripwire,
    readDb: () => tripwire,
    authz: createAuthorization({ db: tripwire }),
    audit: null,
    outbox: null,
    entitlements: null,
    config: { reporting: { enabled } },
    log: quiet,
  })(kit.registrar("/api/v1"));
  return kit.table;
}

const OPENAPI_KEY = (method, urlPath) =>
  `${method.toUpperCase()} ${urlPath.replace(/^\/api\/v1/, "").replace(/\{id\}/g, ":id")}`;
/** The `/reporting` operations of an OpenAPI document as `METHOD /path` keys. */
const reportingOperations = (doc) =>
  Object.entries(doc?.paths ?? {})
    .filter(([urlPath]) => urlPath.startsWith("/api/v1/reporting"))
    .flatMap(([urlPath, ops]) =>
      Object.keys(ops)
        .filter((m) => ["get", "post", "put", "patch", "delete"].includes(m))
        .map((m) => OPENAPI_KEY(m, urlPath)),
    )
    .sort();

const REPORT_TABLES = [
  "report_daily_findings",
  "report_daily_executions",
  "report_daily_decisions",
  "report_daily_sbom",
  "report_rollup_runs",
  "report_exports",
];
const tableCounts = async (db) => {
  const out = {};
  for (const t of REPORT_TABLES)
    out[t] = (await db.$queryRawUnsafe(`SELECT count(*)::int AS n FROM ${t}`))[0].n;
  out.outbox_reporting = (
    await db.$queryRaw`SELECT count(*)::int AS n FROM outbox_messages WHERE queue = 'reporting'`
  )[0].n;
  return out;
};

const S14A = {
  id: "RPT-S14a",
  name: "Flag-off sweep (SPEC 12 item 1, ADR-015, RPT-S14): with REPORTING_ENABLED not exactly true (a) the tick does not start (also for 'true' as a string, a missing section and an empty config) and the worker entry starts nothing, (b) the rollup handler refuses every mode without calling the repository (a tripwire) and without writing a row to the real database, (c) the retention pass is a no-op, (d) on the suite's own API EVERY operation under /reporting that the OpenAPI document lists answers the byte-identical 404 RESOURCE_NOT_FOUND after authentication (valid requests, so it is the flag and not validation) and 401 without a session, and the whole sweep leaves every report_* table and the reporting outbox queue unchanged; the document lists exactly the manifest's operations",
  async run(c) {
    const p = [];
    const { db } = c;
    const before = await tableCounts(db);
    const trip = new Proxy(
      {},
      {
        get(_t, name) {
          throw new Error(`the repository was touched while the module is off: ${String(name)}`);
        },
      },
    );
    // (a) the tick and the worker entry
    for (const config of [
      { reporting: { enabled: false } },
      { reporting: { enabled: "true" } },
      { reporting: {} },
      {},
    ])
      same(
        p,
        `the tick with ${j(config)}`,
        buildRollupTick({
          db: trip,
          rollupRepository: trip,
          exportRepository: trip,
          config,
          logger: quiet,
        }),
        null,
      );
    for (const env of [
      {},
      { REPORTING_ENABLED: "false" },
      { REPORTING_ENABLED: "TRUE" },
      { REPORTING_ENABLED: "1" },
    ]) {
      const log = console.log;
      console.log = () => {};
      try {
        const started = await startReportingWorker(env);
        ok(
          p,
          typeof started?.stop === "function",
          `the worker entry with ${j(env)} did not return a stop hook`,
        );
        await started?.stop();
      } catch (error) {
        p.push(`the worker entry with ${j(env)} threw: ${error?.message}`);
      } finally {
        console.log = log;
      }
    }
    // (b) the rollup handler
    const T = c.A.tenant.id;
    const realRepo = createReportingRollupRepository({ db: roleDb(db, "qm_reporting") });
    const today = localDayOf(new Date(), "UTC");
    for (const [name, repo] of [
      ["a tripwire repository", trip],
      ["the real repository", realRepo],
    ]) {
      const handler = createRollupHandler({
        rollupRepository: repo,
        config: { reporting: { enabled: false, rollupRetentionMonths: 25 } },
        logger: quiet,
        options: { throttleMs: 0 },
      });
      for (const payload of [
        { mode: "incremental", day: today },
        { mode: "close", day: addDays(today, -1) },
        { mode: "backfill", from: addDays(today, -3), to: today },
        { mode: "backfill", from: addDays(today, -3), to: today, reason: "timezone_changed" },
      ]) {
        try {
          await handler(rollupMessage(T, payload), { log: quiet });
        } catch (error) {
          p.push(
            `the rollup handler (${name}, ${payload.mode}) threw while off: ${error?.message}`,
          );
        }
      }
    }
    // (c) the retention pass
    same(
      p,
      "the retention pass while off",
      await runFileRetention({
        exportRepository: trip,
        config: { reporting: { enabled: false }, execution: { artifactStoreRoot: os.tmpdir() } },
        logger: quiet,
      }),
      { expired: 0, removed: 0 },
    );
    same(p, "the database after the handlers and the tick", await tableCounts(db), before);
    // (d) the suite's own API (the module is off)
    const client = createClient({
      baseUrl: need("SECURITY_API_URL"),
      origin: need("SECURITY_ORIGIN"),
    });
    const login = await client.api("POST", "/auth/login", {
      body: { email: "demo.admin@demo.example", password: need("SECURITY_TENANT_PASSWORD") },
    });
    ok(p, login.cookie, "the demo administrator could not sign in");
    const doc = (await client.api("GET", "/openapi.json")).json;
    const listed = reportingOperations(doc);
    same(
      p,
      "the OpenAPI document lists exactly the manifest's reporting operations",
      listed,
      REPORTING_ROUTE_MANIFEST.map((m) => `${m.method} ${m.url}`).sort(),
    );
    const ws = c.A.ws[0].id;
    const id = randomUUID();
    const bodies = new Set();
    for (const op of listed) {
      const row = REPORTING_ROUTE_MANIFEST.find((m) => `${m.method} ${m.url}` === op);
      if (!row) {
        p.push(`${op} is listed by the app but has no probe in the manifest`);
        continue;
      }
      const { path: url, body } = row.probe(ws, id);
      const headers = row.idempotent ? { "Idempotency-Key": `off-${hex(8)}` } : {};
      const anon = await client.api(row.method, url, { body, headers });
      same(p, `${op} without a session`, anon.status, 401);
      const r = await client.api(row.method, url, { cookie: login.cookie, body, headers });
      same(
        p,
        `${op} while the module is off`,
        [r.status, r.json?.error?.code],
        [404, "RESOURCE_NOT_FOUND"],
      );
      bodies.add(bare(r));
    }
    same(p, "the 404 bodies are identical for every operation", bodies.size, 1);
    same(p, "the whole sweep wrote nothing", await tableCounts(db), before);
    return p;
  },
};

const S14B = {
  id: "RPT-S14b",
  name: "Route inventory sweep (SPEC 7.1, 7.3, 12, RPT-S14): the routes the REAL reporting router registers (module ON, on a recorder) equal the manifest exactly (method, path, tenant audience, the central permission and its scope, rate limit, idempotency key on every POST, the write limit on every write, nothing under /platform), planted deviations are each reported (a missing route, an extra one, a changed permission, a null gate, a changed scope, a route under /platform, a public audience, a dropped idempotency flag), the OpenAPI document of the live second process lists the same operations (nothing is registered outside the module), and on the live process EVERY manifest row answers 401 without a session, the identical 404 to another tenant's owner on a workspace, report id or unknown id, 404 (workspace routes) or 403 (the tenant overview) to a member of the tenant without any role, never writes on a denial, and works for the owner (the control)",
  async run(c) {
    const p = [];
    const e = await eWorld(c);
    const { db } = c;
    const table = await recordRoutes(true);
    same(
      p,
      "inventory problems of the real router",
      inventoryProblems(table, REPORTING_ROUTE_MANIFEST),
      [],
    );
    same(p, "the number of routes", [table.length, REPORTING_ROUTE_MANIFEST.length], [18, 18]);
    // the comparison itself can fail
    const plant = (label, mutate, expect) => {
      const copy = table.map((r) => ({ ...r }));
      const manifest = [...REPORTING_ROUTE_MANIFEST];
      mutate(copy, manifest);
      const found2 = inventoryProblems(copy, manifest);
      ok(
        p,
        found2.some((x) => x.includes(expect)),
        `planted deviation not reported: ${label} (${j(found2)})`,
      );
    };
    plant("a route missing from the app", (rs) => rs.pop(), "not registered");
    plant(
      "an extra route",
      (rs) => rs.push({ ...rs[0], url: "/api/v1/reporting/extra" }),
      "not in the manifest",
    );
    plant("a changed permission", (rs) => (rs[0].permission = "finding.comment"), "permission is");
    plant("no gate", (rs) => (rs[1].permission = null), "no permission gate");
    plant("a changed scope", (rs) => (rs[0].permission = "dashboard.view"), "gate scope is");
    plant(
      "a route under /platform",
      (rs) => (rs[2].url = "/api/v1/platform/reporting/trends"),
      "sits under /platform",
    );
    plant("a public route", (rs) => (rs[3].audience = "public"), "audience is");
    plant(
      "a dropped idempotency flag",
      (rs) => (rs.find((r) => r.method === "POST").idempotent = false),
      "idempotency",
    );
    plant(
      "a write without the write limit",
      (rs) => (rs.find((r) => r.method === "DELETE").rateLimit = "read"),
      "rate limit is",
    );
    // the app of the second process lists the same operations
    const doc = (await e.api("GET", "/openapi.json")).json;
    same(
      p,
      "the live OpenAPI operations equal the manifest",
      reportingOperations(doc),
      REPORTING_ROUTE_MANIFEST.map((m) => `${m.method} ${m.url}`).sort(),
    );
    // the live sweep
    const reportA = (await generateReports(e, e.A))[0].id;
    const roleless = await db.user.create({
      data: { email: `rpte-${hex(6)}@rpte.example`, name: "No role" },
    });
    await db.tenantMembership.create({
      data: { tenantId: e.A.tenantId, userId: roleless.id, status: "active", joinedAt: new Date() },
    });
    const loginRoleless = await e.api("POST", "/auth/login", {
      body: { email: roleless.email, password: need("SECURITY_TENANT_PASSWORD") },
    });
    const rolelessCookie = loginRoleless.cookie;
    if (rolelessCookie) {
      await e.api("PUT", "/me/active-tenant", {
        cookie: rolelessCookie,
        body: { tenantId: e.A.tenantId },
      });
    } else p.push(`the member without a role could not sign in (${loginRoleless.status})`);
    const before = await tableCounts(db);
    const call = (row, cookie, ws, id) => {
      const { path: url, body } = row.probe(ws, id);
      const headers = row.idempotent ? { "Idempotency-Key": `sweep-${hex(8)}` } : {};
      return e.api(row.method, url, { cookie, body, headers });
    };
    for (const row of REPORTING_ROUTE_MANIFEST) {
      const op = `${row.method} ${row.url}`;
      const needsId = row.url.includes(":id");
      same(
        p,
        `${op} without a session`,
        (await call(row, undefined, e.A.workspaceId, reportA)).status,
        401,
      );
      if (row.scope === "workspace") {
        const unknown = await call(row, e.B.cookie, UNKNOWN, needsId ? UNKNOWN : UNKNOWN);
        const foreign = await call(row, e.B.cookie, e.A.workspaceId, needsId ? reportA : UNKNOWN);
        same(
          p,
          `${op} by another tenant's owner`,
          [foreign.status, foreign.json?.error?.code],
          [404, "RESOURCE_NOT_FOUND"],
        );
        same(p, `${op}: a foreign resource equals an unknown one`, bare(foreign), bare(unknown));
        if (rolelessCookie) {
          const hidden = await call(
            row,
            rolelessCookie,
            e.A.workspaceId,
            needsId ? reportA : UNKNOWN,
          );
          same(
            p,
            `${op} by a member without a role`,
            [hidden.status, hidden.json?.error?.code],
            [404, "RESOURCE_NOT_FOUND"],
          );
        }
      } else if (rolelessCookie) {
        const denied = await call(row, rolelessCookie, e.A.workspaceId, reportA);
        same(
          p,
          `${op} by a member without the tenant key`,
          [denied.status, denied.json?.error?.code],
          [403, "FORBIDDEN"],
        );
      }
    }
    same(p, "the denials wrote nothing", await tableCounts(db), before);
    // the control: the owner is never refused on a legitimate request (the delete goes last, on a report of its own)
    for (const row of REPORTING_ROUTE_MANIFEST.filter((m) => m.method !== "DELETE")) {
      const r = await call(row, e.A.cookie, e.A.workspaceId, reportA);
      ok(
        p,
        r.status === 200 || r.status === 202,
        `${row.method} ${row.url} by the owner answered ${r.status} (the control)`,
      );
    }
    const own = await e.api("POST", "/reporting/reports", {
      cookie: e.A.cookie,
      body: { template: "findings_by_pipeline", format: "csv", workspaceId: e.A.workspaceId },
      headers: { "Idempotency-Key": `sweep-${hex(8)}` },
    });
    await e.exportHandler(
      { tenantId: e.A.tenantId, payload: { reportId: own.json?.data?.reportId } },
      { log: quiet },
    );
    const del = await e.api("DELETE", `/reporting/reports/${own.json?.data?.reportId}`, {
      cookie: e.A.cookie,
    });
    ok(p, del.status === 200, `DELETE by the owner answered ${del.status} (the control)`);
    return p;
  },
};

// ---- checks added for the security-critical survivors of the mutation sweep (MUTATION_BACKLOG.md, starred) -------------------------

const collect = async (readable) => {
  const chunks = [];
  for await (const chunk of readable) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
};

const SM01 = {
  id: "RPT-SM01",
  name: "CSV safety and column gating on the exact edges (mutation sweep, starred: CSV safety, redaction, assignee privacy; SPEC 12 items 2 and 3, O-6): a cell that starts with a tab or a carriage return alone is neutralised like a formula, a text cell is credential-redacted AND neutralised, a non-text cell is neutralised too, the header row is neutralised, the assignee column exists only when the requester held `finding.assign` (the default is without it), every other column of the template is kept, and no row is written for a record with a hostile value outside the columns",
  async run() {
    const p = [];
    for (const lead of ["\t", "\r"]) {
      const cell = csvSafeCell(`${lead}cmd`);
      ok(
        p,
        cell.startsWith(`"'`),
        `a cell starting with ${j(lead)} is not neutralised: ${j(cell)}`,
      );
    }
    for (const v of ["=1+1", "+1", "-1", "@x", " =1", "​=1"])
      ok(
        p,
        csvSafeCell(v).includes("'"),
        `a formula cell ${j(v)} is not neutralised: ${j(csvSafeCell(v))}`,
      );
    same(p, "a plain cell", csvSafeCell("ok"), "ok");
    const template = "findings_by_pipeline";
    const without = csvColumnsFor(template).map((c) => c.key);
    const withAssignee = csvColumnsFor(template, { includeAssignee: true }).map((c) => c.key);
    ok(p, !without.includes("assignee"), "the assignee column is present by default");
    ok(
      p,
      withAssignee.includes("assignee"),
      "the assignee column is missing for a holder of finding.assign",
    );
    same(
      p,
      "the other columns are kept",
      without,
      withAssignee.filter((k) => k !== "assignee"),
    );
    ok(p, without.length >= 10, "the template lost its columns");
    const columns = csvColumnsFor(template, { includeAssignee: true });
    const bad = (c) =>
      c.key === "start_line"
        ? "=1+1"
        : c.key === "age_days"
          ? "+cmd"
          : c.type === "text"
            ? `=HYPERLINK("x") ${FAKE.github}`
            : "=1";
    const record = Object.fromEntries(columns.map((c) => [c.key, bad(c)]));
    record.not_a_column = "LEAKED-OUTSIDE";
    let rows = 0;
    const text = await collect(
      createCsvStream({
        columns,
        records: (async function* () {
          yield record;
        })(),
        bom: true,
        onRow: () => {
          rows += 1;
        },
      }),
    );
    ok(p, text.startsWith(CSV_BOM), "the byte order mark was requested and is missing");
    same(p, "rows counted", rows, 1);
    ok(p, !text.includes(FAKE.github), "a credential shape survived in a CSV text cell");
    ok(p, !text.includes("LEAKED-OUTSIDE"), "a key outside the columns was written");
    const lines = text.slice(CSV_BOM.length).split("\r\n");
    same(p, "header and one row and the terminator", lines.length, 3);
    const body = lines[1];
    ok(
      p,
      !/(^|,)"?[=+@-]/.test(body),
      `a data cell still starts with a formula sign: ${body.slice(0, 200)}`,
    );
    ok(
      p,
      body.includes(`"'=1+1"`) || body.includes("'=1+1"),
      "the number column was not neutralised",
    );
    // the no-BOM default
    const plain = await collect(
      createCsvStream({
        columns: columns.slice(0, 2),
        records: (async function* () {})(),
      }),
    );
    ok(p, !plain.startsWith(CSV_BOM), "a BOM was written without being asked");
    // a long file is streamed in more than one chunk and loses nothing
    const many = (async function* () {
      for (let i = 0; i < 4000; i += 1) yield { id: `id-${i}`, title: "x".repeat(40) };
    })();
    const stream = createCsvStream({ columns: columns.slice(0, 2), records: many });
    let chunks = 0;
    let total = "";
    for await (const chunk of stream) {
      chunks += 1;
      total += Buffer.from(chunk).toString("utf8");
    }
    ok(p, chunks > 1, `a 4000 row file came in ${chunks} chunk`);
    same(p, "rows of the long file", total.split("\r\n").length - 1, 4001);
    return p;
  },
};

const SM02 = {
  id: "RPT-SM02",
  name: "Object key validation and the store's limits (mutation sweep, starred: object key validation, limits; SPEC 12 item 5): the key of a report is built only from two lower-case canonical UUIDs (a string, never an array or an object that prints as one) and a known format, in the worker's store AND the API's reader; a file of exactly the cap is stored and one byte more is refused with the size error and leaves no temporary file; the tenant directory and the object are created private (0700 and 0600); `size` of a missing object is null, `delete` is idempotent and removes only that object; a replacement is atomic",
  async run() {
    const p = [];
    const t = randomUUID();
    const r = randomUUID();
    for (const [name, key] of [
      ["worker", workerKey],
      ["api", apiKey],
    ]) {
      same(
        p,
        `${name} key`,
        key({ tenantId: t, reportId: r, format: "csv" }),
        `reports/${t}/${r}.csv`,
      );
      same(
        p,
        `${name} pdf key`,
        key({ tenantId: t, reportId: r, format: "pdf" }),
        `reports/${t}/${r}.pdf`,
      );
      const refused = [
        ["an array tenant", { tenantId: [t], reportId: r, format: "csv" }],
        ["an object tenant", { tenantId: { toString: () => t }, reportId: r, format: "csv" }],
        ["an array report", { tenantId: t, reportId: [r], format: "csv" }],
        ["an object report", { tenantId: t, reportId: { toString: () => r }, format: "csv" }],
        ["a number tenant", { tenantId: 1, reportId: r, format: "csv" }],
        ["a missing tenant", { reportId: r, format: "csv" }],
        ["an upper-case tenant", { tenantId: t.toUpperCase(), reportId: r, format: "csv" }],
        ["a traversal tenant", { tenantId: `${t}/../${t}`, reportId: r, format: "csv" }],
        ["a traversal report", { tenantId: t, reportId: `../${r}`, format: "csv" }],
        ["a separator in the format", { tenantId: t, reportId: r, format: "csv/../x" }],
        ["an unknown format", { tenantId: t, reportId: r, format: "html" }],
        ["a trailing newline", { tenantId: `${t}\n`, reportId: r, format: "csv" }],
      ];
      for (const [label, ref] of refused) {
        let threw = null;
        try {
          key(ref);
        } catch (error) {
          threw = error?.name;
        }
        ok(p, threw === "TypeError", `${name}: ${label} was not refused (${threw})`);
      }
    }
    const root = await mkdtemp(path.join(os.tmpdir(), "rpt-sm02-"));
    const store = createReportObjectStore({ root });
    const ref = { tenantId: t, reportId: r, format: "csv" };
    const cap = 1000;
    const exact = await store.put(ref, Readable.from([Buffer.alloc(cap, 97)]), { maxBytes: cap });
    same(p, "a file of exactly the cap", exact.bytes, cap);
    same(p, "its size", await store.size(ref), cap);
    const other = { tenantId: t, reportId: randomUUID(), format: "csv" };
    let refusedBig = null;
    try {
      await store.put(other, Readable.from([Buffer.alloc(cap + 1, 97)]), { maxBytes: cap });
    } catch (error) {
      refusedBig = error?.name;
    }
    same(p, "one byte over the cap", refusedBig, "ArtifactTooLargeError");
    same(p, "no object for the refused file", await store.size(other), null);
    const leftovers = (await readdir(path.join(root, "reports", t))).filter((n) =>
      n.includes(".tmp-"),
    );
    same(p, "no temporary file is left behind", leftovers, []);
    same(p, "a missing object", await store.size({ ...ref, reportId: randomUUID() }), null);
    same(
      p,
      "the object is private",
      (await stat(path.join(root, "reports", t, `${r}.csv`))).mode & 0o777,
      0o600,
    );
    same(
      p,
      "the tenant directory is private",
      (await stat(path.join(root, "reports", t))).mode & 0o777,
      0o700,
    );
    same(p, "the root is private", (await stat(root)).mode & 0o777, 0o700);
    // replacement and deletion
    const again = await store.put(ref, Readable.from([Buffer.from("new")]), { maxBytes: cap });
    same(p, "a replacement", [again.bytes, await store.size(ref)], [3, 3]);
    const sibling = { tenantId: t, reportId: randomUUID(), format: "pdf" };
    await store.put(sibling, Readable.from([Buffer.from("pdf")]), { maxBytes: cap });
    await store.delete(ref);
    same(p, "the deleted object", await store.size(ref), null);
    same(p, "its sibling stays", await store.size(sibling), 3);
    await store.delete(ref);
    await store.delete({ ...ref, reportId: randomUUID() });
    // the API's reader sees the same object read-only and refuses what the key refuses
    const reader = createReportObjectReader({ root });
    same(p, "the reader sees the sibling", await reader.size(sibling), 3);
    same(p, "the reader sees nothing for a missing object", await reader.size(ref), null);
    return p;
  },
};

const SM03 = {
  id: "RPT-SM03",
  name: "PDF text safety, stable failure codes and time-zone validation on the exact edges (mutation sweep, starred: PDF safety, redaction, input validation; SPEC 12 items 2 and 4, 7.4): `pdfText` keeps printable ASCII and Latin-1 and the listed typographic marks, turns tab, line feed, carriage return and every other control character, DEL and C1 into spaces, replaces anything above Latin-1 (an emoji is one mark) with `?`, and redacts credential shapes; `failureCodeOf` maps only the stable codes (timeouts, an unreachable source, too large) and anything else to `internal` without ever returning a message; `isValidTimeZone` refuses non-strings, the empty string and over-long names",
  async run() {
    const p = [];
    same(
      p,
      "pdfText of the edges",
      pdfText("A~B\u0000C\u001fD\u007fE\u009fF GÿHĀI\u{1F600}J\tK\nL\rM N…–—‘’“”•"),
      "A~B C D E F\u00a0GÿH?I?J K L M N…–—‘’“”•",
    );
    same(p, "pdfText of null", pdfText(null), "");
    ok(
      p,
      !pdfText(`token ${FAKE.github} end`).includes(FAKE.github),
      "pdfText leaves a credential shape",
    );
    same(p, "a sentence", pdfText("Use of eval in src/app.js:10"), "Use of eval in src/app.js:10");
    const code = (e) => failureCodeOf(e);
    same(p, "TimeoutError", code({ name: "TimeoutError" }), "timeout");
    same(p, "AbortError", code({ name: "AbortError" }), "timeout");
    same(p, "SQLSTATE 57014", code({ code: "57014" }), "timeout");
    same(
      p,
      "a statement timeout text",
      code({ message: "canceling statement due to statement timeout" }),
      "timeout",
    );
    same(p, "P1001", code({ code: "P1001" }), "source_unavailable");
    same(p, "ECONNRESET", code({ message: "read ECONNRESET" }), "source_unavailable");
    same(p, "a page cap", code(new ReportTooLargeError()), "too_large");
    same(p, "anything else", code(new Error(`boom ${FAKE.github}`)), "internal");
    same(p, "nothing", code(undefined), "internal");
    same(p, "another name is not a timeout", code({ name: "SomethingError" }), "internal");
    same(p, "another SQLSTATE is not a timeout", code({ code: "23505" }), "internal");
    for (const zone of [
      "UTC",
      "Europe/Berlin",
      "Pacific/Auckland",
      "America/Argentina/Buenos_Aires",
    ])
      ok(p, isValidTimeZone(zone), `${zone} was refused`);
    for (const zone of [
      undefined,
      null,
      5,
      "",
      "x".repeat(65),
      "Not/AZone",
      "Europe/Berlin; DROP",
      " UTC",
      "../etc",
    ])
      ok(p, !isValidTimeZone(zone), `${j(zone)} was accepted`);
    return p;
  },
};

const SM04 = {
  id: "RPT-SM04",
  name: "The export gates call the next handler exactly once or refuse (mutation sweep, starred: permission gates, tenant scope; SPEC 3, 9, AUTHORIZATION 404 and 403), on stub authorization: the module switch passes only when the flag is exactly true (else the 404 error and no `next`), `create` with a workspace delegates to the workspace gate, the tenant-wide create needs `dashboard.view` and `report.export` in EVERY workspace and is refused (403, no `next`) when one is missing or the tenant has no workspace at all, `item` loads by tenant and id, answers the 404 error for a missing, deleted or invisible report and for a tenant-wide report without `dashboard.view`, 403 without `report.view`, and otherwise calls `next` once with a frozen minimal resource; `holdsExport` edges",
  async run() {
    const p = [];
    const perms = (workspaces, tenant = []) => ({
      tenant,
      allWorkspaces: [],
      workspaces: workspaces.map(([id, keys]) => ({
        id,
        name: id,
        status: "active",
        permissions: ["workspace.view", ...keys],
      })),
    });
    const spy = () => {
      const s = { calls: 0 };
      s.next = () => {
        s.calls += 1;
      };
      return s;
    };
    const attempt = async (fn, req, nextSpy) => {
      try {
        await fn(req, {}, nextSpy.next);
        return "returned";
      } catch (error) {
        return error?.constructor?.name;
      }
    };
    const gateFor = ({ enabled = true, permissions, row, count = 1 }) => {
      const delegated = [];
      const authz = {
        authorize: (key) =>
          async function stub(req, _res, next) {
            delegated.push(key);
            req.authz = { permissions };
            next();
          },
        loadPermissions: async () => permissions,
      };
      const gate = createExportAuthorization({
        authz,
        exports: { getExport: async () => row ?? null },
        support: { workspaceCount: async () => count },
        config: { reporting: { enabled } },
      });
      return { gate, delegated };
    };
    const req = (over = {}) => ({
      principal: { tenant: { id: "t" } },
      params: { id: "r" },
      body: {},
      query: {},
      ...over,
    });
    // the module switch
    for (const [enabled, want] of [
      [true, ["returned", 1]],
      [false, ["NotFoundError", 0]],
      ["true", ["NotFoundError", 0]],
      [1, ["NotFoundError", 0]],
      [null, ["NotFoundError", 0]],
    ]) {
      const s = spy();
      const { gate } = gateFor({ enabled, permissions: perms([]) });
      same(
        p,
        `the module switch with ${j(enabled)}`,
        [await attempt(gate.moduleEnabled, req(), s), s.calls],
        want,
      );
    }
    // create with a workspace: the workspace gate decides and next is called by it
    {
      const s = spy();
      const { gate, delegated } = gateFor({ permissions: perms([["w1", ["report.export"]]]) });
      await attempt(gate.create, req({ body: { workspaceId: "w1" } }), s);
      same(
        p,
        "create with a workspace asks the workspace gate",
        [delegated, s.calls],
        [["report.export"], 1],
      );
    }
    // tenant-wide create
    const tenantWide = async (permissions, count) => {
      const s = spy();
      const { gate } = gateFor({ permissions, count });
      return [await attempt(gate.create, req(), s), s.calls];
    };
    same(
      p,
      "tenant-wide create with every key",
      await tenantWide(
        perms(
          [
            ["w1", ["report.export"]],
            ["w2", ["report.export"]],
          ],
          ["dashboard.view"],
        ),
        2,
      ),
      ["returned", 1],
    );
    same(
      p,
      "tenant-wide create missing one workspace key",
      await tenantWide(
        perms(
          [
            ["w1", ["report.export"]],
            ["w2", []],
          ],
          ["dashboard.view"],
        ),
        2,
      ),
      ["ForbiddenError", 0],
    );
    same(
      p,
      "tenant-wide create that sees fewer workspaces than exist",
      await tenantWide(perms([["w1", ["report.export"]]], ["dashboard.view"]), 2),
      ["ForbiddenError", 0],
    );
    same(
      p,
      "tenant-wide create in a tenant without workspaces",
      await tenantWide(perms([], ["dashboard.view"]), 0),
      ["ForbiddenError", 0],
    );
    same(
      p,
      "tenant-wide create without dashboard.view",
      await tenantWide(perms([["w1", ["report.export"]]]), 1),
      ["ForbiddenError", 0],
    );
    same(
      p,
      "holdsExport in a workspace",
      [
        holdsExport(perms([["w1", ["report.export"]]]), "w1", 1),
        holdsExport(perms([["w1", []]]), "w1", 1),
      ],
      [true, false],
    );
    same(
      p,
      "holdsExport tenant-wide with no workspaces",
      holdsExport(perms([], ["dashboard.view"]), null, 0),
      false,
    );
    // the list gate
    {
      const s = spy();
      const { gate, delegated } = gateFor({ permissions: perms([["w1", ["report.view"]]]) });
      await attempt(gate.list, req({ query: { workspaceId: "w1" } }), s);
      await attempt(gate.list, req(), s);
      same(
        p,
        "list asks report.view in a workspace and dashboard.view tenant-wide",
        [delegated, s.calls],
        [["report.view", "dashboard.view"], 2],
      );
    }
    // the item gate
    const item = async ({ permissions, row }) => {
      const s = spy();
      const { gate } = gateFor({ permissions, row });
      const r = req();
      const outcome = await attempt(gate.item, r, s);
      return [outcome, s.calls, r.authz?.resource ?? null, Object.isFrozen(r.authz ?? {})];
    };
    const mine = { id: "r", workspaceId: "w1", deletedAt: null };
    same(
      p,
      "item in a visible workspace with the key",
      await item({ permissions: perms([["w1", ["report.view"]]]), row: mine }),
      ["returned", 1, { id: "r", workspaceId: "w1" }, true],
    );
    same(
      p,
      "item without the key",
      (await item({ permissions: perms([["w1", []]]), row: mine })).slice(0, 2),
      ["ForbiddenError", 0],
    );
    same(
      p,
      "item in a workspace the caller cannot see",
      (await item({ permissions: perms([["w9", ["report.view"]]]), row: mine })).slice(0, 2),
      ["NotFoundError", 0],
    );
    same(
      p,
      "a missing report",
      (await item({ permissions: perms([["w1", ["report.view"]]]), row: null })).slice(0, 2),
      ["NotFoundError", 0],
    );
    same(
      p,
      "a deleted report",
      (
        await item({
          permissions: perms([["w1", ["report.view"]]]),
          row: { ...mine, deletedAt: new Date() },
        })
      ).slice(0, 2),
      ["NotFoundError", 0],
    );
    const wide = { id: "r", workspaceId: null, deletedAt: null };
    same(
      p,
      "a tenant-wide report without dashboard.view",
      (await item({ permissions: perms([["w1", ["report.view"]]]), row: wide })).slice(0, 2),
      ["NotFoundError", 0],
    );
    same(
      p,
      "a tenant-wide report with dashboard.view",
      (await item({ permissions: perms([["w1", []]], ["dashboard.view"]), row: wide })).slice(0, 2),
      ["returned", 1],
    );
    return p;
  },
};

/** A database double that records every statement and answers an empty result. */
const recordingDb = () => {
  const log = [];
  const db = new Proxy(
    {},
    {
      get(_t, name) {
        return (...args) => {
          log.push({ name: String(name), arg: args[0] });
          if (name === "$transaction") return args[0](db);
          return Promise.resolve([]);
        };
      },
    },
  );
  return { db, log };
};

const SM05 = {
  id: "RPT-SM05",
  name: "Tenant scope and input validation of every repository method before any statement (mutation sweep, starred: tenant scope; ADR-003, SPEC 7, 8): on a recording database double, EVERY method of the read and rollup repositories refuses a tenant id that is not a UUID without sending a statement (only `listActiveTenants` and `purgeExpired`, which take no tenant, are exempt and listed), every workspace read refuses a workspace id that is not a UUID, the series reads refuse a malformed day, the page size and run range of the rollup are bounded, the export worker repository refuses ids that are not UUIDs, and the same methods with valid arguments DO reach the database (the control)",
  async run() {
    const p = [];
    const uuid = () => randomUUID();
    const valid = () => ({
      tenantId: uuid(),
      workspaceId: uuid(),
      id: uuid(),
      pipelineId: uuid(),
      runId: uuid(),
      day: "2026-01-02",
      from: "2026-01-01",
      to: "2026-01-02",
      limit: 5,
      rows: [],
      now: new Date(),
      timeZone: "UTC",
      mode: "incremental",
      status: "succeeded",
      rowsWritten: 0,
      instant: new Date(),
    });
    const EXEMPT = new Set(["listActiveTenants", "purgeExpired", "expireExports"]);
    const WORKSPACE_READS = [
      "getPosture",
      "getPostureAsOf",
      "getTrends",
      "getRemediation",
      "getSla",
      "getAging",
      "getScanActivity",
      "getCoverage",
      "getSbom",
      "getQuality",
      "getBreakdown",
      "getTopRisk",
      "getWorkload",
    ];
    const run = async (repo, name, args) => {
      try {
        await repo[name](args);
        return "ok";
      } catch (error) {
        return error?.name ?? "error";
      }
    };
    for (const [label, factory, extra] of [
      [
        "read",
        createReportingReadRepository,
        {
          start: new Date(),
          endExclusive: new Date(),
          by: "repository",
          series: ["flow"],
          windowDays: 30,
          workspaceIds: [randomUUID()],
        },
      ],
      ["rollup", createReportingRollupRepository, {}],
    ]) {
      const { db, log } = recordingDb();
      const repo = factory({ db });
      for (const name of Object.keys(repo)) {
        if (EXEMPT.has(name)) continue;
        log.length = 0;
        const outcome = await run(repo, name, { ...valid(), ...extra, tenantId: "nope" });
        ok(
          p,
          outcome !== "ok" && log.length === 0,
          `${label}.${name} did not refuse a tenant id that is not a UUID before a statement (${outcome}, ${log.length} statements)`,
        );
        if (WORKSPACE_READS.includes(name)) {
          log.length = 0;
          const w = await run(repo, name, { ...valid(), ...extra, workspaceId: "nope" });
          ok(
            p,
            w !== "ok" && log.length === 0,
            `${label}.${name} did not refuse a workspace id that is not a UUID before a statement (${w}, ${log.length} statements)`,
          );
        }
        log.length = 0;
        await run(repo, name, { ...valid(), ...extra });
        ok(
          p,
          log.length > 0,
          `${label}.${name} never reached the database with valid arguments (the control)`,
        );
      }
      same(
        p,
        `${label}: the exempt methods exist or are not part of this repository`,
        [...EXEMPT].filter((n) => n in repo && !["listActiveTenants", "purgeExpired"].includes(n)),
        [],
      );
    }
    {
      const { db, log } = recordingDb();
      const read = createReportingReadRepository({ db });
      const outcome = await run(read, "getOverview", {
        ...valid(),
        workspaceIds: [randomUUID(), "nope"],
      });
      ok(
        p,
        outcome !== "ok" && log.length === 0,
        "getOverview accepted a workspace id that is not a UUID",
      );
    }
    // the series reads refuse a malformed day (the check is on the first statement)
    {
      const { db, log } = recordingDb();
      const read = createReportingReadRepository({ db });
      for (const bad of ["yesterday", "2026-1-1", ""]) {
        log.length = 0;
        const outcome = await run(read, "getTrends", { ...valid(), from: bad });
        ok(p, outcome !== "ok" && log.length === 0, `getTrends accepted the day ${j(bad)}`);
        log.length = 0;
        const asOf = await run(read, "getPostureAsOf", { ...valid(), day: bad });
        ok(p, asOf !== "ok" && log.length === 0, `getPostureAsOf accepted the day ${j(bad)}`);
      }
    }
    // the rollup bounds
    {
      const { db, log } = recordingDb();
      const rollup = createReportingRollupRepository({ db });
      for (const limit of [0, -1, 1001, 1.5, "5"]) {
        log.length = 0;
        const outcome = await run(rollup, "listActiveTenants", { limit });
        ok(
          p,
          outcome !== "ok" && log.length === 0,
          `listActiveTenants accepted the page size ${j(limit)}`,
        );
      }
      for (const limit of [1, 1000]) {
        log.length = 0;
        await run(rollup, "listActiveTenants", { limit });
        ok(p, log.length === 1, `listActiveTenants refused the page size ${limit}`);
      }
      const t = randomUUID();
      for (const [label, args] of [
        ["a range that ends before it starts", { day: "2026-01-05", rangeTo: "2026-01-01" }],
        ["a range end that is not a day", { day: "2026-01-05", rangeTo: "soon" }],
        ["a start that is not a day", { day: "5 Jan" }],
        ["an unknown mode", { day: "2026-01-05", mode: "weekly" }],
      ]) {
        log.length = 0;
        const outcome = await run(rollup, "startRun", {
          tenantId: t,
          mode: "incremental",
          timeZone: "UTC",
          now: new Date(),
          ...args,
        });
        ok(p, outcome !== "ok" && log.length === 0, `startRun accepted ${label}`);
      }
      log.length = 0;
      await run(rollup, "startRun", {
        tenantId: t,
        mode: "backfill",
        day: "2026-01-05",
        rangeTo: "2026-01-05",
        timeZone: "UTC",
        now: new Date(),
      });
      ok(p, log.length > 0, "startRun refused a valid one-day range (the control)");
      for (const [label, args] of [
        ["a day range that is reversed", { from: "2026-01-05", to: "2026-01-01" }],
        ["a day that is not a day", { from: "x", to: "2026-01-01" }],
      ]) {
        log.length = 0;
        const outcome = await run(rollup, "clearRange", { tenantId: t, ...args });
        ok(p, outcome !== "ok" && log.length === 0, `clearRange accepted ${label}`);
      }
    }
    // the export worker repository
    {
      const { db, log } = recordingDb();
      const worker = createReportingExportWorkerRepository({ db });
      for (const name of [
        "claimExport",
        "getExportForWorker",
        "countExportRows",
        "readExportPage",
        "completeExport",
        "failExport",
      ]) {
        log.length = 0;
        const outcome = await run(worker, name, {
          ...valid(),
          tenantId: "nope",
          template: "findings_by_pipeline",
          objectKey: "x",
          errorCode: "internal",
          bytes: 1,
          sha256: "a".repeat(64),
          rowCount: 1,
          expiresAt: new Date(),
          params: {},
        });
        ok(
          p,
          outcome !== "ok" && log.length === 0,
          `worker.${name} did not refuse ids that are not UUIDs (${outcome}, ${log.length} statements)`,
        );
      }
    }
    return p;
  },
};

const SM06 = {
  id: "RPT-SM06",
  name: "Export worker repository: object key scoping and assignee privacy (mutation sweep, starred: object key validation, redaction; SPEC 12 items 2 and 5, O-6): `completeExport` stores a key only when it has the exact shape `reports/<tenant>/<id>.<csv|pdf>` for THAT tenant and report (another tenant's key, another report's key, a traversal, a key without the shape are each refused with no statement), a good key is written; the assignee display name is selected only when the request carried `includeAssignee: true` (anything else, including the string 'true', reads NULL)",
  async run() {
    const p = [];
    const { db, log } = recordingDb();
    const worker = createReportingExportWorkerRepository({ db });
    const t = randomUUID();
    const other = randomUUID();
    const id = randomUUID();
    const complete = async (objectKey, over = {}) => {
      log.length = 0;
      try {
        await worker.completeExport({
          tenantId: t,
          id,
          objectKey,
          bytes: 10,
          sha256: "a".repeat(64),
          rowCount: 1,
          expiresAt: new Date(),
          now: new Date(),
          ...over,
        });
        return "ok";
      } catch (error) {
        return error?.name;
      }
    };
    same(p, "a good csv key", [await complete(`reports/${t}/${id}.csv`), log.length], ["ok", 1]);
    same(p, "a good pdf key", [await complete(`reports/${t}/${id}.pdf`), log.length], ["ok", 1]);
    for (const [label, key] of [
      ["another tenant's key", `reports/${other}/${id}.csv`],
      ["another report's key", `reports/${t}/${randomUUID()}.csv`],
      ["a traversal", `reports/${t}/../${other}/${id}.csv`],
      ["an absolute path", `/reports/${t}/${id}.csv`],
      ["an unknown extension", `reports/${t}/${id}.html`],
      ["a bare name", `${id}.csv`],
      ["a key with a suffix", `reports/${t}/${id}.csv/extra`],
      ["a non-string", 42],
    ]) {
      const outcome = await complete(key);
      ok(
        p,
        outcome === "TypeError" && log.length === 0,
        `${label} was not refused without a statement (${outcome}, ${log.length})`,
      );
    }
    const sqlOf = () => String(log[0]?.arg?.sql ?? "");
    const page = async (params) => {
      log.length = 0;
      await worker.readExportPage({
        tenantId: t,
        workspaceId: randomUUID(),
        template: "findings_by_pipeline",
        params,
        after: null,
        limit: 5,
        timeZone: "UTC",
      });
      return sqlOf();
    };
    ok(
      p,
      /f\.assignee_display_name/.test(await page({ includeAssignee: true })),
      "the assignee column was not selected for a request that carries it",
    );
    for (const params of [
      {},
      { includeAssignee: false },
      { includeAssignee: "true" },
      { includeAssignee: 1 },
    ]) {
      const text = await page(params);
      ok(
        p,
        !/f\.assignee_display_name/.test(text) && /NULL::text AS assignee_display_name/.test(text),
        `the assignee column was selected for ${j(params)}`,
      );
    }
    return p;
  },
};

export const REPORTING_E_CHECKS = [
  S13A,
  S13B,
  S14A,
  S14B,
  S10F,
  S08H,
  SM01,
  SM02,
  SM03,
  SM04,
  SM05,
  SM06,
];
