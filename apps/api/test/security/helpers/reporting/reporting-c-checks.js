import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inflateSync } from "node:zlib";
import { ERROR_CODES, QUEUE_NAMES, parseMessage } from "@qmentisai/contracts";
import {
  createOutboxRepository,
  createReportingExportWorkerRepository,
  createReportingExportsRepository,
} from "@qmentisai/db";
import { createOutbox } from "@qmentisai/infra";
import {
  REPORTING_LIMITS,
  REPORT_TEMPLATES,
  csvRow,
  localDayOf,
  redactCredentialShapes,
} from "@qmentisai/shared";
import { createAuditService } from "../../../../src/audit/audit-service.js";
import { createExportAuthorization } from "../../../../src/modules/reporting/export-authorization.js";
import {
  createReportObjectReader,
  reportObjectKey as apiReportObjectKey,
} from "../../../../src/modules/reporting/export-object-reader.js";
import { createReportExportSupport } from "../../../../src/modules/reporting/repositories/export.js";
import { createReportExportService } from "../../../../src/modules/reporting/services/export.js";
import {
  createCsvStream,
  csvColumnsFor,
} from "../../../../../workers/src/reporting/export/csv-writer.js";
import { buildExportHandler } from "../../../../../workers/src/reporting/export/handler.js";
import {
  createReportObjectStore,
  reportObjectKey as workerReportObjectKey,
} from "../../../../../workers/src/reporting/export/object-store.js";
import {
  ReportTooLargeError,
  createPdfReport,
} from "../../../../../workers/src/reporting/export/pdf-kit.js";
import { expireReportFiles } from "../../../../../workers/src/reporting/export/retention.js";
import { FAKE } from "../../fixtures/scan-engines/secrets/tree-builder.js";
import { createClient } from "../http.js";
import { buildWorld } from "../world.js";

/**
 * Reporting Part C (exports) checks, ADR-008 area 20: `RPT-S05` (the redaction canary across every template and both formats), `RPT-S06`
 * (CSV formula injection and PDF safety), `RPT-S07` (export object scoping and traversal), `RPT-S08` (limits, authenticated download,
 * expiry), `RPT-S12` (audit entries), plus extras with letter suffixes. They run the REAL code: the export service and the worker handler in
 * process against the disposable database (the worker as the restricted `qm_reporting` role through a `SET LOCAL ROLE` proxy, the API's
 * row-count read as `qm_reporting_ro`), and the REAL HTTP routes of a second API process started by the check with `REPORTING_ENABLED=true`
 * (the suite's own API keeps the module OFF, which RPT-S08f proves). NOT proved here: how a PDF looks to a person, a production object
 * store, the broker delivery of the message (the outbox ROW is what is checked), the 250,000-row boundary on real rows (a stubbed count
 * proves the refusal; the measurement helper of the work item generated the real dataset).
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const apiDir = path.resolve(here, "../../../..");

const same = (p, label, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want))
    p.push(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
};
const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
/** A cell that starts (after white space, no-break and zero-width spaces) with a formula sign. */
const FORMULA_LEAD = new RegExp("^[\\s\\u00A0\\u200B\\uFEFF]*[=+\\-@]");
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

// ------------------------------------------------------------------------------------------------------------------------------------
// shared machinery
// ------------------------------------------------------------------------------------------------------------------------------------

/** A database client that runs every statement as a restricted group role (the privileges of `qm_reporting` / `qm_reporting_ro`). */
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
  };
};

/** A Pino-shaped logger that keeps every call, so the checks can search what was logged. */
const captureLogger = () => {
  const lines = [];
  const make =
    (level) =>
    (...args) => {
      lines.push(
        JSON.stringify({ level, args }, (_k, v) => (typeof v === "bigint" ? String(v) : v)),
      );
    };
  return {
    lines,
    info: make("info"),
    warn: make("warn"),
    error: make("error"),
    debug: make("debug"),
  };
};

/** The permission set of a user who holds the given workspace keys in one workspace (the shape of `resolveEffectivePermissions`). */
const permissionsIn = (workspaceId, keys, tenantKeys = []) => ({
  tenant: tenantKeys,
  workspaces: [{ id: workspaceId, permissions: keys }],
});
const EXPORTER = [
  "workspace.view",
  "report.view",
  "report.export",
  "finding.view",
  "finding.assign",
];

/** Everything an in-process export needs, built once per world. */
function inproc(c) {
  c.__rptInproc ??= (async () => {
    const { db } = c;
    const root = await mkdtemp(path.join(os.tmpdir(), "rpt-c-"));
    const logger = captureLogger();
    const readDb = roleDb(db, "qm_reporting_ro");
    const workerDb = roleDb(db, "qm_reporting");
    const exportsRepo = createReportingExportsRepository({ db });
    const support = createReportExportSupport({ db, readDb: () => readDb });
    const state = { count: null };
    const counter = {
      countExportRows: (args) =>
        state.count !== null
          ? Promise.resolve(state.count)
          : createReportingExportWorkerRepository({ db: readDb }).countExportRows(args),
    };
    const audit = createAuditService({ db, logger });
    const outbox = createOutbox({ repository: createOutboxRepository({ db }) });
    const reader = createReportObjectReader({ root });
    const store = createReportObjectStore({ root });
    const workerRepo = createReportingExportWorkerRepository({ db: workerDb });
    const handler = buildExportHandler({
      exportRepository: workerRepo,
      config: { execution: { artifactStoreRoot: root }, reporting: { exportRetentionDays: 30 } },
      logger,
      store,
    });
    const service = (over = {}) =>
      createReportExportService({
        db,
        exports: exportsRepo,
        counter,
        support,
        audit,
        outbox,
        reader,
        ...over,
      });
    return {
      db,
      root,
      logger,
      exportsRepo,
      support,
      state,
      counter,
      audit,
      outbox,
      reader,
      store,
      workerRepo,
      handler,
      service,
    };
  })();
  return c.__rptInproc;
}

/** Requests a report through the service and runs the worker handler on it. @returns {Promise<{ id: string, row: any, file: Buffer | null }>} */
async function generate(env, actor, body) {
  const { reportId } = await env.service().create(actor, body);
  await env.handler({ tenantId: actor.tenantId, payload: { reportId } }, { log: env.logger });
  const row = await env.exportsRepo.getExport({ tenantId: actor.tenantId, id: reportId });
  const file =
    row?.status === "ready"
      ? await readFile(path.join(env.root, ...row.objectKey.split("/")))
      : null;
  return { id: reportId, row, file };
}

const today = () => localDayOf(new Date(), "UTC");
/** The request body of every v1 template and format for a workspace. */
function allRequests(workspaceId) {
  const out = [];
  for (const t of REPORT_TEMPLATES.filter((x) => x.v1))
    for (const format of t.formats)
      out.push({
        template: t.id,
        format,
        workspaceId,
        ...(t.periodMode === "period" ? { period: 30 } : {}),
        ...(t.periodMode === "asOfDay" ? { asOfDay: today() } : {}),
      });
  return out;
}

// ---- PDF analysis (structure only: this is NOT a rendering) ----------------------------------------------------------------------

/** The PDF split into its non-stream text, its streams (inflated when they are Flate) and the text drawn on the pages. */
function analysePdf(buf) {
  const s = buf.toString("latin1");
  const streams = [];
  let objects = "";
  let last = 0;
  const re = /(?<!end)stream\r?\n/g;
  let m;
  while ((m = re.exec(s))) {
    const start = m.index + m[0].length;
    const end = s.indexOf("endstream", start);
    if (end < 0) break;
    objects += s.slice(last, m.index);
    let body = buf.subarray(start, end);
    try {
      body = inflateSync(body);
    } catch {
      /* not a Flate stream: keep the raw bytes */
    }
    streams.push(body.toString("latin1"));
    last = end + "endstream".length;
    re.lastIndex = last;
  }
  objects += s.slice(last);
  // text of the pages: the strings of every TJ array (hex or literal, kerning numbers dropped) and of every Tj
  let text = "";
  for (const stream of streams) {
    for (const arr of stream.matchAll(/\[([^\]]*)\]\s*TJ/g)) text += `${decodeStrings(arr[1])}\n`;
    for (const t of stream.matchAll(/(<[0-9a-fA-F\s]*>|\((?:\\.|[^\\)])*\))\s*Tj/g))
      text += `${decodeStrings(t[1])}\n`;
  }
  return { raw: s, objects, streams, text };
}
function decodeStrings(chunk) {
  let out = "";
  for (const m of chunk.matchAll(/<([0-9a-fA-F\s]*)>|\(((?:\\.|[^\\)])*)\)/g)) {
    if (m[1] !== undefined) {
      const hex = m[1].replace(/\s+/g, "");
      out += Buffer.from(hex.length % 2 ? `${hex}0` : hex, "hex").toString("latin1");
    } else out += m[2].replace(/\\(.)/g, "$1");
  }
  return out;
}

/** The operators of a content stream, read with a tokenizer that treats strings as strings (so a hostile text cannot hide an operator). */
function contentOperators(stream) {
  const ops = new Set();
  let i = 0;
  const n = stream.length;
  while (i < n) {
    const ch = stream[i];
    if (/\s/.test(ch)) i += 1;
    else if (ch === "%") {
      ops.add("%comment");
      while (i < n && stream[i] !== "\n" && stream[i] !== "\r") i += 1;
    } else if (ch === "(") {
      let depth = 1;
      i += 1;
      while (i < n && depth > 0) {
        if (stream[i] === "\\") i += 2;
        else {
          if (stream[i] === "(") depth += 1;
          else if (stream[i] === ")") depth -= 1;
          i += 1;
        }
      }
    } else if (ch === "<" && stream[i + 1] !== "<") {
      i = stream.indexOf(">", i) + 1 || n;
    } else if (ch === "<" || ch === ">") {
      ops.add("%dictionary");
      i += 2;
    } else if (ch === "[" || ch === "]") i += 1;
    else if (ch === "/") {
      i += 1;
      while (i < n && !/[\s/[\]<>()]/.test(stream[i])) i += 1;
    } else {
      let j = i;
      while (j < n && !/[\s/[\]<>()%]/.test(stream[j])) j += 1;
      const token = stream.slice(i, j);
      if (!/^[-+.\d]/.test(token)) ops.add(token);
      i = Math.max(j, i + 1);
    }
  }
  return ops;
}
const ALLOWED_OPERATORS = new Set([
  "q",
  "Q",
  "cm",
  "BT",
  "ET",
  "Tf",
  "Tm",
  "Td",
  "TD",
  "T*",
  "Tj",
  "TJ",
  "Tc",
  "Tw",
  "Tz",
  "TL",
  "Tr",
  "Ts",
  "re",
  "m",
  "l",
  "c",
  "v",
  "y",
  "h",
  "f",
  "F",
  "f*",
  "S",
  "s",
  "B",
  "b",
  "n",
  "W",
  "W*",
  "w",
  "J",
  "j",
  "M",
  "d",
  "i",
  "g",
  "G",
  "rg",
  "RG",
  "k",
  "K",
  "cs",
  "CS",
  "sc",
  "scn",
  "SC",
  "SCN",
  "gs",
]);
/** Names and keys that would make a PDF active content (pdfkit's catalog holds an EMPTY `/Names << /Dests ... >>` destination tree, which is inert: `/JavaScript` and `/EmbeddedFiles` under it ARE in this list). */
const ACTIVE_CONTENT =
  /\/(JavaScript|JS|URI|Launch|EmbeddedFile|EmbeddedFiles|OpenAction|AA|SubmitForm|ImportData|GoToR|GoToE|RichMedia|XFA|AcroForm|Annots|Filespec|Movie|Sound|Rendition)\b/;

/** An independent RFC 4180 parser (the writer is not trusted to read its own output). @param {string} text @returns {string[][]} */
function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i += 1;
        } else quoted = false;
      } else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(cell);
      cell = "";
    } else if (ch === "\r" && text[i + 1] === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      i += 1;
    } else cell += ch;
  }
  if (cell !== "" || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

/** Every way a secret may show up in bytes: plain, hex, base64, URL-encoded, reversed. @param {string} secret */
const variants = (secret) => [
  secret,
  Buffer.from(secret).toString("hex"),
  Buffer.from(secret).toString("base64").replace(/=+$/, ""),
  encodeURIComponent(secret),
  [...secret].reverse().join(""),
];
const leaksOf = (corpus, secrets) =>
  secrets.flatMap((s) =>
    variants(s)
      .filter((v) => corpus.includes(v))
      .map(() => s.slice(0, 8)),
  );

/** Writes `fn`, and if the database refuses (a CHECK against a credential shape) writes the fallback. Returns the string that is stored. */
async function plant(planted, label, fake, write) {
  try {
    await write(fake);
    planted.push({ label, value: fake, shaped: true });
    return fake;
  } catch {
    const plain = `CANARY-${label}-${randomBytes(4).toString("hex")}`;
    await write(plain);
    planted.push({ label, value: plain, shaped: false });
    return plain;
  }
}

// ---- the second API process (the module ON) -----------------------------------------------------------------------------------------

const freePort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });

/** Starts `src/server.js` with `REPORTING_ENABLED=true` against the suite's disposable database and signs the demo users in. */
function httpWorld(c) {
  c.__rptHttp ??= (async () => {
    const need = (name) => {
      if (!process.env[name])
        throw new Error(`${name} is not set (run through pnpm test:security)`);
      return process.env[name];
    };
    const keys = JSON.parse(need("SECURITY_CURSOR_KEYS"));
    const port = await freePort();
    const root = await mkdtemp(path.join(os.tmpdir(), "rpt-c-http-"));
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
    const client = createClient({ baseUrl, origin: need("SECURITY_ORIGIN") });
    const w = await buildWorld(client, {
      tenantPassword: need("SECURITY_TENANT_PASSWORD"),
      platformPassword: need("SECURITY_PLATFORM_PASSWORD"),
      mfaCode: need("SECURITY_MFA_CODE"),
    });
    const { db } = c;
    const tenant = await db.tenant.findFirst({ where: { slug: "demo" } });
    const meId = async (cookie) => (await client.api("GET", "/me", { cookie })).json.data.user.id;
    const users = {};
    for (const name of ["admin", "manager", "lead", "developer", "viewer"])
      users[name] = await meId(w.sessions[name]);
    // a repository and a pipeline in the demo "Payments Platform" workspace, so that findings can exist there
    const wsRow = await db.workspace.findFirst({
      where: { tenantId: tenant.id, id: w.A.paymentsWs },
    });
    const sfx = randomBytes(4).toString("hex");
    const installation = await db.scmInstallation.create({
      data: {
        provider: "github",
        externalInstallationId: `rptc-${sfx}`,
        accountExternalId: `rptc-${sfx}`,
        accountLogin: "rptc-org",
        accountType: "organization",
        repositorySelection: "all",
      },
    });
    const link = await db.scmInstallationLink.create({
      data: { tenantId: tenant.id, installationId: installation.id, linkedByUserId: users.admin },
    });
    const wl = await db.scmWorkspaceLink.create({
      data: {
        tenantId: tenant.id,
        workspaceId: wsRow.id,
        linkId: link.id,
        linkedByUserId: users.admin,
      },
    });
    const repo = await db.repository.create({
      data: {
        tenantId: tenant.id,
        workspaceId: wsRow.id,
        linkId: link.id,
        workspaceLinkId: wl.id,
        provider: "github",
        externalRepoId: `rptc-${sfx}`,
        fullName: "rptc-org/payments-api",
        name: "payments-api",
        ownerLogin: "rptc-org",
        connectedByUserId: users.admin,
      },
    });
    const tree = { tenant, user: { id: users.admin }, ws: [wsRow], repo: [repo] };
    const pipeline = await c.pipeline(tree, 0);
    await c.finding(pipeline, { title: "Use of eval", severity: "high", severityRank: 3 });
    const env = await inproc(c);
    // the in-process worker writes where the API reads
    const store = createReportObjectStore({ root });
    const handler = buildExportHandler({
      exportRepository: createReportingExportWorkerRepository({ db: roleDb(db, "qm_reporting") }),
      config: { execution: { artifactStoreRoot: root }, reporting: { exportRetentionDays: 30 } },
      logger: env.logger,
      store,
    });
    /** Runs the worker on every queued report of the demo tenant (a stand-in for the broker delivery of the outbox message). */
    const drain = async () => {
      const queued = await db.reportExport.findMany({
        where: { tenantId: tenant.id, status: "queued" },
        select: { id: true },
      });
      for (const q of queued)
        await handler({ tenantId: tenant.id, payload: { reportId: q.id } }, { log: env.logger });
      return queued.length;
    };
    const post = (cookie, body, key = `key-${randomBytes(6).toString("hex")}`) =>
      client.api("POST", "/reporting/reports", {
        cookie,
        body,
        headers: { "Idempotency-Key": key },
      });
    return {
      client,
      api: client.api,
      w,
      tenant,
      users,
      pay: w.A.paymentsWs,
      ident: w.A.identityWs,
      root,
      drain,
      post,
      handler,
      store,
      output,
      pipeline,
      env,
    };
  })();
  return c.__rptHttp;
}

const REQ = (ws, over = {}) => ({
  template: "findings_by_pipeline",
  format: "csv",
  workspaceId: ws,
  ...over,
});
/** A real user row (the audit trail has a foreign key to the actor), one per actor so the hourly limit of one user is never shared. */
const freshUser = async (c) =>
  (
    await c.db.user.create({
      data: { email: `rptc-${randomBytes(6).toString("hex")}@rptc.example`, name: "Report tester" },
    })
  ).id;
const ACTOR = (tenantId, userId, permissions) => ({
  tenantId,
  userId,
  permissions,
  requestId: randomUUID(),
  ip: "127.0.0.1",
});

// ------------------------------------------------------------------------------------------------------------------------------------
// the checks
// ------------------------------------------------------------------------------------------------------------------------------------

/**
 * Reporting Part C (exports) checks.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const REPORTING_C_CHECKS = [
  {
    id: "RPT-S05a",
    name: "Exports leak no planted secret (RPT-011, SPEC 12 item 2): the fake tokens of the suite are planted in finding evidence, a review rationale, a comment body, an advisory reasoning, an exception justification, a status note, the title, rule name, rule id and path of a finding (a column that refuses a credential shape by CHECK gets a plain canary instead); EVERY v1 template in EVERY format is generated through the real service and the worker handler as the restricted role; the secret (plain, hex, base64, URL-encoded and reversed) appears in no CSV byte, no PDF byte, no inflated PDF stream, no decoded PDF text, no report row, no audit entry, no captured log line and no outbox message; each file exists and the findings export proves the finding was exported with its title redacted (control)",
    async run(c) {
      const p = [];
      const env = await inproc(c);
      const { db } = c;
      const pa = (await c.published(c.A, 0)).pipeline;
      const planted = [];
      const findings = [];
      const mk = (over) => (v) =>
        c
          .finding(pa, {
            severity: "high",
            severityRank: 3,
            slaStartedAt: new Date(Date.now() - 864e5),
            slaDueAt: new Date(Date.now() - 36e5),
            ...over(v),
          })
          .then((x) => findings.push(x));
      await plant(
        planted,
        "title",
        `Use of ${FAKE.github} here`,
        mk((v) => ({ title: v })),
      );
      await plant(
        planted,
        "rulename",
        `Rule ${FAKE.stripe}`,
        mk((v) => ({ ruleName: v })),
      );
      await plant(
        planted,
        "ruleid",
        `rule.${FAKE.slack}`,
        mk((v) => ({ ruleId: v })),
      );
      await plant(
        planted,
        "path",
        `src/${FAKE.aws}/app.js`,
        mk((v) => ({ path: v })),
      );
      const finding = findings[0];
      await plant(planted, "evidence", FAKE.github, (v) =>
        db.findingEvidence.create({
          data: {
            ...c.chainOf(finding),
            kind: "block",
            capturedExecutionId: randomUUID(),
            capturedAt: new Date(),
            snippet: `T="${v}"`,
            scmRef: { blob: v },
            url: `https://example.test/${v}`,
          },
        }),
      );
      await plant(planted, "rationale", FAKE.aws, (v) => c.review(finding, { rationale: v }));
      await plant(planted, "comment", FAKE.stripe, (v) =>
        db.findingComment.create({
          data: { ...c.chainOf(finding), authorUserId: randomUUID(), body: v },
        }),
      );
      await plant(planted, "reasoning", FAKE.slack, (v) =>
        db.findingAiAdvisory.create({
          data: {
            ...c.chainOf(finding),
            inputHash: randomBytes(32).toString("hex"),
            status: "ok",
            suggestion: "likely_false_positive",
            confidence: 90,
            reasoning: v,
            egressLevel: "metadata",
            provider: "ollama",
            model: "m",
          },
        }),
      );
      await plant(planted, "justification", FAKE.password, (v) =>
        c.exception(finding, { justification: v, compensatingControls: v }),
      );
      await plant(planted, "note", FAKE.apiKey, (v) => c.step(finding, "in_review", { note: v }));
      // a title or path the database refuses as credential-shaped (CHECK) is replaced by a plain canary: that value is ORDINARY TEXT, which a
      // findings export legitimately carries (the control below proves it does), so it is not a secret to search for
      const secrets = planted
        .filter((x) => x.shaped || !["title", "path"].includes(x.label))
        .map((x) => x.value);
      const exportedPlain = planted
        .filter((x) => !x.shaped && ["title", "path"].includes(x.label))
        .map((x) => x.value);
      same(p, "canaries planted", planted.length, 10);
      ok(
        p,
        planted.some((x) => x.shaped),
        "no credential-shaped canary could be planted anywhere",
      );

      const actor = ACTOR(pa.tenantId, await freshUser(c), permissionsIn(pa.workspaceId, EXPORTER));
      const corpus = { csv: "", pdf: "", rows: "", audit: "", logs: "", outbox: "" };
      const made = [];
      for (const body of allRequests(pa.workspaceId)) {
        const r = await generate(env, actor, body);
        made.push({ body, ...r });
        ok(
          p,
          r.row?.status === "ready",
          `${body.template} ${body.format} did not finish: ${r.row?.status} ${r.row?.errorCode ?? ""}`,
        );
        if (!r.file) continue;
        ok(p, r.file.length > 0, `${body.template} ${body.format} is empty`);
        if (body.format === "csv") corpus.csv += r.file.toString("utf8");
        else {
          const a = analysePdf(r.file);
          corpus.pdf += `${a.raw}\n${a.streams.join("\n")}\n${a.text}\n`;
          ok(p, r.file.subarray(0, 5).toString() === "%PDF-", `${body.template} is not a PDF`);
        }
      }
      same(
        p,
        "templates generated",
        made.length,
        REPORT_TEMPLATES.filter((x) => x.v1).reduce((n, t) => n + t.formats.length, 0),
      );
      corpus.rows = JSON.stringify(
        await db.reportExport.findMany({ where: { tenantId: pa.tenantId } }),
        (_k, v) => (typeof v === "bigint" ? String(v) : v),
      );
      corpus.audit = JSON.stringify(
        await db.auditLog.findMany({
          where: { tenantId: pa.tenantId, action: { startsWith: "report." } },
        }),
      );
      corpus.outbox = JSON.stringify(
        await db.outboxMessage.findMany({
          where: { tenantId: pa.tenantId, type: "reporting.export.requested" },
        }),
      );
      corpus.logs = env.logger.lines.join("\n");
      for (const [name, text] of Object.entries(corpus)) {
        ok(p, text.length > 0, `the ${name} corpus is empty (control)`);
        same(p, `secret leaks in ${name}`, leaksOf(text, secrets), []);
      }
      const csv = made.find(
        (m) => m.body.template === "findings_by_pipeline" && m.body.format === "csv",
      );
      const rows = parseCsv(csv.file.toString("utf8"));
      const line = rows.find((r) => r[0] === finding.id);
      ok(p, Boolean(line), "the findings export lacks the planted finding (control)");
      if (planted[0].shaped)
        ok(
          p,
          line?.[1]?.includes("[REDACTED]"),
          "the credential-shaped title was not redacted in the CSV",
        );
      const pathRow = rows.find((r) => r[0] === findings[3].id);
      if (planted[3].shaped)
        ok(
          p,
          pathRow?.[7]?.includes("[REDACTED]"),
          "the credential-shaped path was not redacted in the CSV",
        );
      for (const value of exportedPlain)
        ok(
          p,
          corpus.csv.includes(value),
          "a plain (non-secret) title or path is missing from the findings export (control)",
        );
      same(p, "audit entries are one per report", JSON.parse(corpus.audit).length, made.length);
      same(p, "outbox messages are one per report", JSON.parse(corpus.outbox).length, made.length);
      for (const m of JSON.parse(corpus.outbox))
        same(p, "outbox payload", m.payload.payload, { reportId: m.payload.payload.reportId });
      return p;
    },
  },
  {
    id: "RPT-S05b",
    name: "Redaction is structural, not a filter (RPT-011): the restricted worker role can read the report views and nothing else (a source table, the evidence, the comments and the advisory reasoning are all `permission denied`, with a control that the views answer), every table the export SQL names is a `report_*_v` view (the SQL text is scanned), and the credential redaction applied by both writers removes every shaped fake token from a hostile cell (plain, in the middle of text and inside a quoted assignment) while leaving ordinary text untouched",
    async run(c) {
      const p = [];
      const { db } = c;
      const workerDb = roleDb(db, "qm_reporting");
      const tryQuery = async (sql) => {
        try {
          await workerDb.$queryRawUnsafe(sql);
          return "ok";
        } catch (error) {
          return String(error?.message ?? error);
        }
      };
      same(
        p,
        "control: the findings view answers the worker role",
        await tryQuery("SELECT 1 FROM report_findings_v LIMIT 1"),
        "ok",
      );
      for (const table of [
        "findings",
        "finding_evidence",
        "finding_comments",
        "finding_reviews",
        "finding_ai_advisories",
        "finding_exceptions",
        "users",
        "audit_logs",
        "executions",
      ]) {
        const result = await tryQuery(`SELECT 1 FROM ${table} LIMIT 1`);
        ok(
          p,
          /permission denied/i.test(result),
          `the worker role read ${table}: ${result.slice(0, 80)}`,
        );
      }
      const source = await readFile(
        path.resolve(here, "../../../../../../packages/db/src/reporting/exports/datasets.js"),
        "utf8",
      );
      const tables = [...source.matchAll(/\b(?:FROM|JOIN)\s+([a-z_][a-z0-9_]*)/g)]
        .map((m) => m[1])
        .filter(
          (t) =>
            ![
              "unnest",
              "t",
              "ev",
              "st",
              "chg",
              "sev_at",
              "has_chg",
              "snap",
              "base",
              "o",
              "cl",
            ].includes(t),
        );
      ok(p, tables.length > 10, "the scan found too few table names (control)");
      same(
        p,
        "tables named by the export SQL that are not report views",
        [...new Set(tables)].filter((t) => !/^report_[a-z_]+_v$/.test(t)),
        [],
      );
      const secretsInCells = [
        FAKE.github,
        FAKE.aws,
        FAKE.stripe,
        FAKE.slack,
        `token = "${FAKE.password}"`,
        FAKE.dbUrl,
        FAKE.jwt,
      ];
      for (const s of secretsInCells) {
        const cell = `before ${s} after`;
        ok(
          p,
          !redactCredentialShapes(cell).includes(s.replace(/^token = "/, "").replace(/"$/, "")),
          `the redaction kept ${s.slice(0, 10)}...`,
        );
      }
      same(
        p,
        "ordinary text",
        redactCredentialShapes("Use of eval in src/app.js:10"),
        "Use of eval in src/app.js:10",
      );
      const csv = [];
      for await (const chunk of createCsvStream({
        columns: csvColumnsFor("findings_by_pipeline", { includeAssignee: true }),
        records: (async function* () {
          yield {
            id: "x",
            title: `a ${FAKE.github} b`,
            path: FAKE.aws,
            rule_id: FAKE.slack,
            repository: FAKE.stripe,
            assignee: FAKE.jwt,
            secret_column: FAKE.aws,
          };
        })(),
      }))
        csv.push(chunk);
      same(
        p,
        "secrets in a written CSV",
        leaksOf(Buffer.concat(csv).toString("utf8"), [
          FAKE.github,
          FAKE.aws,
          FAKE.slack,
          FAKE.stripe,
          FAKE.jwt,
        ]),
        [],
      );
      return p;
    },
  },
  {
    id: "RPT-S06a",
    name: "CSV injection (RPT-S06, SPEC 12 item 3): hostile cell values (a leading = + - @, a tab, a carriage return, a no-break and a zero-width space before the sign, quotes, commas, embedded newlines, a NUL and C0 controls, a 5,000-character value) written through the real streaming writer and read back with an independent RFC 4180 parser give exactly the cells that were meant, every dangerous cell begins with a single quote, no cell outside the template's columns is written, the assignee column exists only when the requester held finding.assign, numbers stay numbers (a negative number is not neutralised), the BOM is written only when asked, and the header row is the catalogue's; the same strings in a finding title exported end to end are neutralised too",
    async run(c) {
      const p = [];
      const hostile = [
        '=HYPERLINK("http://evil.test","x")',
        "+1+1",
        "-2+3",
        "@SUM(A1:A9)",
        "\t=1+1",
        "\r=1+1",
        " =1",
        " =1",
        "​=1",
        'say "hi", then = go',
        "line1\nline2",
        "a\u0000b\u0007c",
        "x".repeat(5000),
        "ok text",
      ];
      const columns = csvColumnsFor("findings_by_pipeline", { includeAssignee: false });
      same(
        p,
        "assignee column without the permission",
        columns.some((x) => x.key === "assignee"),
        false,
      );
      same(
        p,
        "assignee column with the permission",
        csvColumnsFor("findings_by_pipeline", { includeAssignee: true }).some(
          (x) => x.key === "assignee",
        ),
        true,
      );
      const write = async (records, options = {}) => {
        const chunks = [];
        for await (const chunk of createCsvStream({
          columns,
          records: (async function* () {
            yield* records;
          })(),
          ...options,
        }))
          chunks.push(chunk);
        return Buffer.concat(chunks).toString("utf8");
      };
      const text = await write(
        hostile.map((title) => ({
          id: "11111111-1111-4111-8111-111111111111",
          title,
          path: title,
          start_line: -5,
          secret_column: "=leak",
        })),
      );
      const rows = parseCsv(text);
      same(
        p,
        "header",
        rows[0],
        columns.map((x) => x.header),
      );
      same(p, "record count", rows.length, hostile.length + 1);
      ok(
        p,
        !text.includes("=leak") && !text.includes("secret_column"),
        "a column outside the template was written",
      );
      hostile.forEach((title, i) => {
        const cell = rows[i + 1]?.[1] ?? "";
        const clean = redactCredentialShapes(title);
        const dangerous = FORMULA_LEAD.test(clean) || clean[0] === "\t" || clean[0] === "\r";
        ok(
          p,
          dangerous ? cell === `'${clean}` : cell === clean,
          `cell ${i} (${JSON.stringify(title.slice(0, 20))}) read back as ${JSON.stringify(cell.slice(0, 30))}`,
        );
        ok(p, !/^[=+\-@\t\r]/.test(cell), `cell ${i} starts with a formula character`);
        same(p, `cell ${i} line number`, rows[i + 1]?.[8], "-5");
      });
      ok(p, !(await write([])).startsWith("﻿"), "a BOM was written without the option");
      ok(p, (await write([], { bom: true })).startsWith("﻿"), "the BOM option was ignored");
      same(p, "csvRow of the shared helper agrees", csvRow(["=1", "a,b"]), '"\'=1","a,b"\r\n');

      // end to end: the same strings as finding titles
      const env = await inproc(c);
      const pa = (await c.published(c.A, 0)).pipeline;
      let stored = 0;
      for (const title of hostile.filter(
        (t) => !t.includes("\u0000") && !t.includes("\u0007") && t.length < 400,
      )) {
        try {
          await c.finding(pa, { title });
          stored += 1;
        } catch {
          /* a title the findings table refuses cannot reach a report */
        }
      }
      ok(p, stored >= 6, `only ${stored} hostile titles could be stored (control)`);
      const actor = ACTOR(
        pa.tenantId,
        await freshUser(c),
        permissionsIn(pa.workspaceId, ["workspace.view", "report.view", "report.export"]),
      );
      const made = await generate(env, actor, {
        template: "findings_by_pipeline",
        format: "csv",
        workspaceId: pa.workspaceId,
      });
      const exported = parseCsv(made.file.toString("utf8"));
      const titles = exported.slice(1).map((r) => r[1]);
      ok(
        p,
        titles.some((t) => t.startsWith("'=")),
        "no neutralised title in the exported file (control)",
      );
      ok(
        p,
        titles.every((t) => !/^[=+\-@\t\r]/.test(t)),
        "an exported title starts with a formula character",
      );
      same(
        p,
        "no assignee column in the file of a requester without finding.assign",
        exported[0].includes("Assignee"),
        false,
      );
      return p;
    },
  },
  {
    id: "RPT-S06b",
    name: "PDF safety (RPT-S06, SPEC 12 item 4): hostile strings (PDF operators, an unbalanced parenthesis, a backslash, a fake endstream and %PDF, a dictionary with /JS and /URI, hex brackets, NUL and C0 controls, bidirectional and emoji characters, a 5,000-character value) drawn through the real PDF writer and through a generated report leave a document whose content streams use only drawing, text, colour and state operators (read with a string-aware tokenizer), whose objects name no script, URI action, launch, embedded file, form, annotation or open action, whose page tree is intact (the pages that were drawn, no stray page), whose metadata is the non-personal title without an author, which draws the hostile text AS text, and whose truncated cells are counted and printed",
    async run(c) {
      const p = [];
      const hostile = [
        "(A) Tj /JS (app.alert(1)) Tj",
        ") ] TJ ET Q q /URI << /S /URI /URI (http://evil.test) >> /A << /S /JavaScript >>",
        "\\) Tj \\(",
        "%PDF-1.7 endstream endobj 9 0 obj << /Type /Action /S /Launch >>",
        "<</S/JavaScript/JS(x)>> <00> >> ",
        "a\u0000b\u0007c\u001B[31m",
        "‮evil‬ rtl",
        "emoji 😀 and 中文",
        "x".repeat(5000),
      ];
      const kit = createPdfReport({
        title: "QmentisAI hostile test report",
        subtitle: ["Scope: test"],
        generatedAt: new Date(),
      });
      const chunks = [];
      kit.doc.on("data", (d) => chunks.push(d));
      const ended = new Promise((resolve) => kit.doc.on("end", resolve));
      kit.begin();
      kit.heading(hostile[0]);
      kit.paragraph(hostile.join(" "));
      kit.table({
        columns: [
          { key: "a", header: hostile[1], width: 3 },
          { key: "b", header: "Other", width: 3, mono: true },
        ],
        rows: hostile.map((h) => ({ a: h, b: h })),
      });
      kit.barChart({
        title: hostile[2],
        bars: [{ label: hostile[3], value: 5, color: "#B3202D", pattern: "solid" }],
      });
      kit.finish("Hostile template");
      await ended;
      const buf = Buffer.concat(chunks);
      const a = analysePdf(buf);
      ok(p, buf.subarray(0, 5).toString() === "%PDF-", "the document is not a PDF");
      ok(p, a.streams.length > 0, "no content stream found (control)");
      for (const stream of a.streams) {
        if (!stream.includes(" Tf") && !stream.includes(" re")) continue;
        const bad = [...contentOperators(stream)].filter((op) => !ALLOWED_OPERATORS.has(op));
        same(p, "operators outside the drawing set", bad, []);
      }
      same(
        p,
        "active content names in the objects",
        a.objects.match(ACTIVE_CONTENT)?.[0] ?? null,
        null,
      );
      ok(p, !/\/Author/.test(a.objects), "the document has an author");
      ok(p, /\/Title/.test(a.objects), "the document has no title");
      same(
        p,
        "pages in the page tree",
        (a.objects.match(/\/Type \/Page\b/g) ?? []).length,
        kit.pageCount,
      );
      ok(
        p,
        a.text.includes("app.alert(1)") && a.text.includes("/URI"),
        "the hostile text was not drawn as text",
      );
      ok(
        p,
        kit.state.truncatedCells > 0 && a.text.includes("…".replace("…", "\u0085")),
        `truncated cells are not counted and marked (${kit.state.truncatedCells})`,
      );

      // through a generated report: a breached finding with a hostile title appears in the SLA PDF
      const env = await inproc(c);
      const pa = (await c.published(c.A, 0)).pipeline;
      await c.finding(pa, {
        title: hostile[0],
        severity: "high",
        severityRank: 3,
        slaStartedAt: new Date(Date.now() - 864e5),
        slaDueAt: new Date(Date.now() - 36e5),
      });
      const actor = ACTOR(pa.tenantId, await freshUser(c), permissionsIn(pa.workspaceId, EXPORTER));
      const made = await generate(env, actor, {
        template: "sla_compliance",
        format: "pdf",
        workspaceId: pa.workspaceId,
        period: 30,
      });
      same(p, "report status", made.row?.status, "ready");
      const b = analysePdf(made.file);
      ok(
        p,
        b.text.includes("app.alert(1)"),
        "the hostile title is absent from the generated PDF (control)",
      );
      for (const stream of b.streams)
        same(
          p,
          "generated PDF operators",
          [...contentOperators(stream)].filter((op) => !ALLOWED_OPERATORS.has(op)),
          [],
        );
      same(p, "generated PDF active content", b.objects.match(ACTIVE_CONTENT)?.[0] ?? null, null);
      return p;
    },
  },
  {
    id: "RPT-S06c",
    name: "PDF page cap and charts (SPEC 7.3, 12): a table that needs more than 40 pages raises the too-large error (the handler maps it to the stable code too_large, never a truncated file), the page counter never exceeds the cap in a smaller report, the document uses only the built-in fonts and no image, and the chart colours are the light-theme design tokens (the severity text variants and the neutral chart series, no accent colour anywhere in the file)",
    async run() {
      const p = [];
      const kit = createPdfReport({ title: "cap", subtitle: [], generatedAt: new Date() });
      kit.doc.on("data", () => {});
      kit.begin();
      let thrown = null;
      try {
        kit.table({
          columns: [{ key: "a", header: "A", width: 1 }],
          rows: Array.from({ length: 4000 }, (_, i) => ({ a: `row ${i}` })),
        });
      } catch (error) {
        thrown = error;
      }
      ok(
        p,
        thrown instanceof ReportTooLargeError,
        `no too-large error for a 4000-row table (${thrown?.name})`,
      );
      ok(
        p,
        kit.pageCount <= REPORTING_LIMITS.pdfMaxPages + 1,
        `the page count ran away (${kit.pageCount})`,
      );
      kit.doc.destroy();
      const { failureCodeOf } =
        await import("../../../../../workers/src/reporting/export/handler.js");
      same(
        p,
        "failure code of the too-large error",
        failureCodeOf(new ReportTooLargeError()),
        "too_large",
      );

      const small = createPdfReport({ title: "small", subtitle: [], generatedAt: new Date() });
      const chunks = [];
      small.doc.on("data", (d) => chunks.push(d));
      const ended = new Promise((resolve) => small.doc.on("end", resolve));
      small.begin();
      small.barChart({
        bars: ["critical", "high", "medium", "low", "info"].map((s, i) => ({
          label: s,
          value: 10 - i,
          color: {
            critical: "#B3202D",
            high: "#A8440A",
            medium: "#7A5800",
            low: "#1257B5",
            info: "#47535F",
          }[s],
          pattern: "solid",
        })),
      });
      small.stackedArea({
        days: ["2026-11-01", "2026-11-02"],
        series: [{ label: "A", color: "#3D4A50", pattern: "solid", values: [1, 2] }],
      });
      small.finish("Small");
      await ended;
      const a = analysePdf(Buffer.concat(chunks));
      const fonts = [...a.objects.matchAll(/\/BaseFont \/([A-Za-z-]+)/g)].map((m) => m[1]);
      ok(
        p,
        fonts.length > 0 &&
          fonts.every((f) => ["Helvetica", "Helvetica-Bold", "Courier"].includes(f)),
        `fonts: ${fonts.join(",")}`,
      );
      ok(
        p,
        !/\/FontFile|\/Subtype \/Image|\/XObject/.test(a.objects),
        "an embedded font file or image was found",
      );
      const colours = new Set(
        a.streams.flatMap((s) =>
          [...s.matchAll(/([\d.]+) ([\d.]+) ([\d.]+) (?:rg|RG|scn|SCN)/g)].map((m) =>
            [m[1], m[2], m[3]]
              .map((x) => Math.round(Number(x) * 255))
              .map((n) => n.toString(16).padStart(2, "0"))
              .join(""),
          ),
        ),
      );
      const allowed = new Set([
        "b3202d",
        "a8440a",
        "7a5800",
        "1257b5",
        "47535f",
        "3d4a50",
        "5e6f78",
        "8a9aa3",
        "c7d1d6",
        "dde4e3",
        "f5f7f7",
        "000000",
        "151b1b",
        "586565",
        "6b7777",
        "ffffff",
      ]);
      same(
        p,
        "colours outside the light-theme tokens",
        [...colours].filter((x) => !allowed.has(x)),
        [],
      );
      ok(
        p,
        !colours.has("087f70") && !colours.has("40e0c0"),
        "the accent colour was used in a chart",
      );
      return p;
    },
  },
  {
    id: "RPT-S07a",
    name: "Export object keys cannot traverse (RPT-S07, SPEC 12 item 5): the worker store and the API reader build the SAME key reports/<tenant>/<report>.<csv|pdf> from two canonical lower-case ids and a closed format list, and both refuse (TypeError, no file anywhere) a separator, .., a leading dot, an upper-case id, an over-long or empty or non-string value, an encoded separator, a NUL, a name instead of an id and an unknown format; nothing is created under or outside the store root by a refused reference; a valid reference works and a written object is exactly where the key says, owner-only, with the size and hash the store reports",
    async run() {
      const p = [];
      const root = await mkdtemp(path.join(os.tmpdir(), "rpt-trav-"));
      const parent = path.dirname(root);
      const store = createReportObjectStore({ root });
      const reader = createReportObjectReader({ root });
      const t = randomUUID();
      const r = randomUUID();
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
        t.toUpperCase(),
        "",
        " ",
        "x".repeat(65),
        "sp ace",
        "a%2fb",
        "a\u0000b",
        `${t}\n`,
        `${t}/../${t}`,
        "report",
        5,
        null,
        undefined,
        {},
      ];
      const listing = async () => (await readdir(parent)).sort().join("|");
      const before = await listing();
      for (const value of bad) {
        for (const ref of [
          { tenantId: value, reportId: r, format: "csv" },
          { tenantId: t, reportId: value, format: "csv" },
        ]) {
          for (const [name, fn] of [
            ["worker key", () => workerReportObjectKey(ref)],
            ["api key", () => apiReportObjectKey(ref)],
            [
              "store put",
              () =>
                store.put(
                  ref,
                  (async function* () {
                    yield Buffer.from("x");
                  })(),
                  { maxBytes: 10 },
                ),
            ],
            ["reader size", () => reader.size(ref)],
          ]) {
            let refused = false;
            try {
              await fn();
            } catch (error) {
              refused = error instanceof TypeError;
            }
            ok(p, refused, `${name} accepted ${JSON.stringify(value)}`);
          }
        }
      }
      for (const format of ["exe", "CSV", "csv/../x", "", null, "pdf "]) {
        let refused = false;
        try {
          workerReportObjectKey({ tenantId: t, reportId: r, format });
        } catch {
          refused = true;
        }
        ok(p, refused, `the format ${JSON.stringify(format)} was accepted`);
      }
      same(p, "files created outside the root by refused references", await listing(), before);
      same(p, "files created under the root by refused references", await readdir(root), []);
      same(
        p,
        "the two key builders agree",
        workerReportObjectKey({ tenantId: t, reportId: r, format: "pdf" }),
        apiReportObjectKey({ tenantId: t, reportId: r, format: "pdf" }),
      );
      same(
        p,
        "the key",
        workerReportObjectKey({ tenantId: t, reportId: r, format: "csv" }),
        `reports/${t}/${r}.csv`,
      );
      const put = await store.put(
        { tenantId: t, reportId: r, format: "csv" },
        (async function* () {
          yield Buffer.from("a,b\r\n1,2\r\n");
        })(),
        { maxBytes: 100 },
      );
      same(p, "put key", put.key, `reports/${t}/${r}.csv`);
      same(p, "put hash", put.sha256, sha256(Buffer.from("a,b\r\n1,2\r\n")));
      same(
        p,
        "reader size",
        await reader.size({ tenantId: t, reportId: r, format: "csv" }),
        put.bytes,
      );
      same(
        p,
        "object on disk",
        (await readFile(path.join(root, "reports", t, `${r}.csv`))).toString(),
        "a,b\r\n1,2\r\n",
      );
      same(
        p,
        "file mode",
        ((await stat(path.join(root, "reports", t, `${r}.csv`))).mode & 0o777).toString(8),
        "600",
      );
      same(
        p,
        "another tenant's reader sees nothing",
        await reader.size({ tenantId: randomUUID(), reportId: r, format: "csv" }),
        null,
      );
      let tooLarge = null;
      try {
        await store.put(
          { tenantId: t, reportId: randomUUID(), format: "csv" },
          (async function* () {
            yield Buffer.alloc(50);
          })(),
          { maxBytes: 10 },
        );
      } catch (error) {
        tooLarge = error?.name;
      }
      same(p, "an oversize object is refused", tooLarge, "ArtifactTooLargeError");
      same(p, "no temporary file left", (await readdir(path.join(root, "reports", t))).length, 1);
      await rm(root, { recursive: true, force: true });
      return p;
    },
  },
  {
    id: "RPT-S07b",
    name: "Another tenant cannot reach a report (RPT-S07, ADR-003): tenant B's owner asking for tenant A's report by its exact id (read, download and delete) and for a workspace of A in the list gets 404 responses byte-identical in code and message to a random unknown id, a guessed id never reveals existence, the repository finds nothing for the wrong tenant, the reader finds no object under another tenant's key, and tenant A's own admin still reads the report (control)",
    async run(c) {
      const p = [];
      const h = await httpWorld(c);
      const made = await h.post(h.w.sessions.admin, REQ(h.pay));
      same(p, "create", made.status, 202);
      const id = made.json.data.reportId;
      await h.drain();
      const b = h.w.sessions.bOwner;
      const unknown = randomUUID();
      for (const [method, suffix] of [
        ["GET", ""],
        ["GET", "/download"],
        ["DELETE", ""],
      ]) {
        const real = await h.api(method, `/reporting/reports/${id}${suffix}`, { cookie: b });
        const none = await h.api(method, `/reporting/reports/${unknown}${suffix}`, { cookie: b });
        same(p, `${method}${suffix} status`, [real.status, none.status], [404, 404]);
        same(
          p,
          `${method}${suffix} body`,
          [real.json?.error?.code, real.json?.error?.message],
          [none.json?.error?.code, none.json?.error?.message],
        );
      }
      const list = await h.api("GET", `/reporting/reports?workspaceId=${h.pay}`, { cookie: b });
      const listNone = await h.api("GET", `/reporting/reports?workspaceId=${randomUUID()}`, {
        cookie: b,
      });
      same(
        p,
        "list of another tenant's workspace",
        [list.status, list.json?.error?.code],
        [listNone.status, listNone.json?.error?.code],
      );
      same(p, "list status", list.status, 404);
      const post = await h.post(b, REQ(h.pay));
      same(p, "create in another tenant's workspace", post.status, 404);
      const bTenantId = (await h.env.db.tenant.findFirst({ where: { id: h.w.B.id } })).id;
      same(
        p,
        "repository by the wrong tenant",
        await h.env.exportsRepo.getExport({ tenantId: bTenantId, id }),
        null,
      );
      const ref = { tenantId: bTenantId, reportId: id, format: "csv" };
      same(
        p,
        "reader under the wrong tenant",
        await createReportObjectReader({ root: h.root }).size(ref),
        null,
      );
      same(
        p,
        "control: the owner reads",
        (await h.api("GET", `/reporting/reports/${id}`, { cookie: h.w.sessions.admin })).status,
        200,
      );
      const row = await h.env.db.reportExport.findFirst({ where: { id } });
      same(p, "no row of tenant A was changed by tenant B", row.deletedAt, null);
      return p;
    },
  },
  {
    id: "RPT-S08a",
    name: "Concurrency limit (RPT-S08, ruling 2026-11-26): with three reports queued or running in a tenant the fourth request is refused with 429 REPORT_LIMIT_REACHED BEFORE queuing (no row, no outbox message, no audit entry), six simultaneous requests queue exactly three (the per-tenant lock), and once the worker finishes them a new request is accepted",
    async run(c) {
      const p = [];
      const h = await httpWorld(c);
      await h.drain();
      const counts = async () => ({
        rows: await h.env.db.reportExport.count({ where: { tenantId: h.tenant.id } }),
        outbox: await h.env.db.outboxMessage.count({
          where: { tenantId: h.tenant.id, type: "reporting.export.requested" },
        }),
        audit: await h.env.db.auditLog.count({
          where: { tenantId: h.tenant.id, action: "report.generated" },
        }),
      });
      const first = await Promise.all(
        [1, 2, 3, 4, 5, 6].map(() => h.post(h.w.sessions.manager, REQ(h.pay))),
      );
      same(
        p,
        "simultaneous statuses",
        first.map((r) => r.status).sort(),
        [202, 202, 202, 429, 429, 429],
      );
      same(
        p,
        "the refusal code",
        first.find((r) => r.status === 429)?.json?.error?.code,
        "REPORT_LIMIT_REACHED",
      );
      const before = await counts();
      const fourth = await h.post(h.w.sessions.lead, REQ(h.pay));
      same(
        p,
        "fourth",
        [fourth.status, fourth.json?.error?.code, fourth.json?.error?.details?.reason],
        [429, "REPORT_LIMIT_REACHED", "tenant_concurrent"],
      );
      same(p, "nothing written by the refusal", await counts(), before);
      ok(p, (await h.drain()) === 3, "the worker did not find the three queued reports");
      same(
        p,
        "accepted after they finished",
        (await h.post(h.w.sessions.lead, REQ(h.pay))).status,
        202,
      );
      await h.drain();
      return p;
    },
  },
  {
    id: "RPT-S08b",
    name: "Per-user hourly limit (RPT-S08): a user with nineteen requests in the last hour may make the twentieth and the twenty-first is refused with 429 REPORT_LIMIT_REACHED (reason user_hourly) before queuing, another user of the tenant is unaffected, and requests older than an hour do not count",
    async run(c) {
      const p = [];
      const h = await httpWorld(c);
      await h.drain();
      const lead = h.users.lead;
      const make = (createdAt) =>
        h.env.db.reportExport.create({
          data: {
            tenantId: h.tenant.id,
            workspaceId: h.pay,
            template: "findings_by_pipeline",
            format: "csv",
            status: "failed",
            errorCode: "internal",
            requestedByUserId: lead,
            createdAt,
          },
        });
      for (let i = 0; i < 5; i += 1) await make(new Date(Date.now() - 2 * 3600e3));
      const existing = await h.env.db.reportExport.count({
        where: {
          tenantId: h.tenant.id,
          requestedByUserId: lead,
          createdAt: { gte: new Date(Date.now() - 3600e3) },
        },
      });
      for (let i = 0; i < 19 - existing; i += 1) await make(new Date(Date.now() - i * 1000));
      same(p, "the twentieth", (await h.post(h.w.sessions.lead, REQ(h.pay))).status, 202);
      const twenty1 = await h.post(h.w.sessions.lead, REQ(h.pay));
      same(
        p,
        "the twenty-first",
        [twenty1.status, twenty1.json?.error?.code, twenty1.json?.error?.details?.reason],
        [429, "REPORT_LIMIT_REACHED", "user_hourly"],
      );
      await h.drain();
      same(p, "another user", (await h.post(h.w.sessions.manager, REQ(h.pay))).status, 202);
      await h.drain();
      return p;
    },
  },
  {
    id: "RPT-S08c",
    name: "The row cap refuses, never truncates (RPT-S08, ruling 2026-11-26): with the row count at the cap (250,000) a CSV request is accepted and with 250,001 it is refused with 422 REPORT_TOO_LARGE before anything is written (no row, no message); the worker, given a report whose count is over the cap, fails it with the stable code too_large and writes no file; a PDF is not subject to the row cap; the real count function agrees with the rows of a small world",
    async run(c) {
      const p = [];
      const env = await inproc(c);
      const pa = (await c.published(c.B, 0)).pipeline;
      const actor = ACTOR(pa.tenantId, await freshUser(c), permissionsIn(pa.workspaceId, EXPORTER));
      const rowsBefore = async () =>
        env.db.reportExport.count({ where: { tenantId: pa.tenantId } });
      env.state.count = REPORTING_LIMITS.csvMaxRows + 1;
      const n0 = await rowsBefore();
      let refused = null;
      try {
        await env.service().create(actor, {
          template: "findings_by_pipeline",
          format: "csv",
          workspaceId: pa.workspaceId,
        });
      } catch (error) {
        refused = { code: error.code, status: error.statusCode };
      }
      same(p, "over the cap", refused, { code: ERROR_CODES.REPORT_TOO_LARGE, status: 422 });
      same(p, "rows written by the refusal", await rowsBefore(), n0);
      env.state.count = REPORTING_LIMITS.csvMaxRows;
      const edge = await env.service().create(actor, {
        template: "findings_by_pipeline",
        format: "csv",
        workspaceId: pa.workspaceId,
      });
      ok(p, typeof edge.reportId === "string", "a request AT the cap was refused");
      // the worker refuses a report whose real count is over the cap: queue one, then make the worker's count answer over the cap
      const workerSide = createReportingExportWorkerRepository({
        db: roleDb(env.db, "qm_reporting"),
      });
      const overCount = {
        ...workerSide,
        countExportRows: async () => REPORTING_LIMITS.csvMaxRows + 1,
      };
      const handler = buildExportHandler({
        exportRepository: overCount,
        config: { execution: { artifactStoreRoot: env.root }, reporting: {} },
        logger: env.logger,
        store: env.store,
      });
      await handler(
        { tenantId: pa.tenantId, payload: { reportId: edge.reportId } },
        { log: env.logger },
      );
      const row = await env.exportsRepo.getExport({ tenantId: pa.tenantId, id: edge.reportId });
      same(
        p,
        "worker outcome",
        [row.status, row.errorCode, row.objectKey],
        ["failed", "too_large", null],
      );
      same(
        p,
        "no file written",
        await env.reader.size({ tenantId: pa.tenantId, reportId: edge.reportId, format: "csv" }),
        null,
      );
      env.state.count = REPORTING_LIMITS.csvMaxRows + 1;
      const pdf = await env.service().create(actor, {
        template: "findings_by_pipeline",
        format: "pdf",
        workspaceId: pa.workspaceId,
      });
      ok(p, typeof pdf.reportId === "string", "a PDF was subject to the CSV row cap");
      env.state.count = null;
      await env.handler(
        { tenantId: pa.tenantId, payload: { reportId: pdf.reportId } },
        { log: env.logger },
      );
      // the real count agrees with the rows of the world
      const pb = (await c.published(c.B, 1)).pipeline;
      await c.finding(pb, { title: "one" });
      await c.finding(pb, { title: "two" });
      const real = await createReportingExportWorkerRepository({
        db: roleDb(env.db, "qm_reporting_ro"),
      }).countExportRows({
        tenantId: pb.tenantId,
        template: "findings_by_pipeline",
        workspaceId: pb.workspaceId,
        params: {},
        periodFrom: null,
        periodTo: null,
        asOfDay: null,
        timeZone: "UTC",
      });
      same(p, "count of a workspace with two findings", real, 2);
      return p;
    },
  },
  {
    id: "RPT-S08d",
    name: "Idempotent request (RPT-S08, SPEC 9): POST /reporting/reports without an Idempotency-Key is 400, the same key and body twice give the same report id with Idempotent-Replayed and exactly one row and one outbox message, the same key with another body is 409 IDEMPOTENCY_CONFLICT, and a request is accepted with 202 and {reportId} only",
    async run(c) {
      const p = [];
      const h = await httpWorld(c);
      await h.drain();
      const noKey = await h.api("POST", "/reporting/reports", {
        cookie: h.w.sessions.admin,
        body: REQ(h.pay),
      });
      same(p, "without a key", [noKey.status, noKey.json?.error?.code], [400, "VALIDATION_FAILED"]);
      const key = `idem-${randomBytes(6).toString("hex")}`;
      const a = await h.post(h.w.sessions.admin, REQ(h.pay), key);
      const b = await h.post(h.w.sessions.admin, REQ(h.pay), key);
      same(p, "statuses", [a.status, b.status], [202, 202]);
      same(p, "data shape", Object.keys(a.json.data), ["reportId"]);
      same(p, "same report", b.json.data.reportId, a.json.data.reportId);
      same(p, "replay header", b.headers.get("idempotent-replayed"), "true");
      same(
        p,
        "rows for the report",
        await h.env.db.reportExport.count({ where: { id: a.json.data.reportId } }),
        1,
      );
      same(
        p,
        "outbox messages for the report",
        await h.env.db.outboxMessage.count({
          where: { messageId: `reporting-export-${a.json.data.reportId}` },
        }),
        1,
      );
      const other = await h.post(
        h.w.sessions.admin,
        REQ(h.pay, { template: "sla_compliance", period: "30" }),
        key,
      );
      same(
        p,
        "same key, other body",
        [other.status, other.json?.error?.code],
        [409, "IDEMPOTENCY_CONFLICT"],
      );
      const message = (
        await h.env.db.outboxMessage.findFirst({
          where: { messageId: `reporting-export-${a.json.data.reportId}` },
        })
      ).payload;
      const parsed = parseMessage(message);
      same(
        p,
        "message",
        [parsed.type, parsed.tenantId, parsed.payload, parsed.kind],
        ["reporting.export.requested", h.tenant.id, { reportId: a.json.data.reportId }, "job"],
      );
      same(
        p,
        "queue",
        (
          await h.env.db.outboxMessage.findFirst({
            where: { messageId: `reporting-export-${a.json.data.reportId}` },
          })
        ).queue,
        QUEUE_NAMES.REPORTING,
      );
      await h.drain();
      return p;
    },
  },
  {
    id: "RPT-S08e",
    name: "Authenticated download only, with the right checks (RPT-S08, D-3): no session is 401; the requester and a report.export holder download a ready report with 200, attachment, a server-built filename (template id, day and eight characters of the id: no user text), the format's Content-Type, no-store and nosniff, and the bytes hash to the stored SHA-256; a member who can only view is 403 and the response never carries the object key or hash; a queued report is 409 REPORT_NOT_READY; an expired one is 410 REPORT_EXPIRED; a deleted one is 404; a user who cannot see the workspace is the identical 404; a tenant-wide report needs the tenant key",
    async run(c) {
      const p = [];
      const h = await httpWorld(c);
      await h.drain();
      const made = await h.post(h.w.sessions.manager, REQ(h.pay));
      const id = made.json.data.reportId;
      const queued = await h.api("GET", `/reporting/reports/${id}/download`, {
        cookie: h.w.sessions.manager,
      });
      same(p, "queued", [queued.status, queued.json?.error?.code], [409, "REPORT_NOT_READY"]);
      await h.drain();
      const url = `/reporting/reports/${id}/download`;
      same(p, "no session", (await h.api("GET", url)).status, 401);
      const row = await h.env.db.reportExport.findFirst({ where: { id } });
      same(p, "status", row.status, "ready");
      for (const who of ["manager", "admin"]) {
        const r = await h.api("GET", url, { cookie: h.w.sessions[who] });
        same(p, `${who} status`, r.status, 200);
        same(p, `${who} content type`, r.headers.get("content-type"), "text/csv; charset=utf-8");
        same(p, `${who} cache`, r.headers.get("cache-control"), "no-store");
        same(p, `${who} nosniff`, r.headers.get("x-content-type-options"), "nosniff");
        ok(
          p,
          /^attachment; filename="qmentisai-findings-by-pipeline-\d{8}-[0-9a-f]{8}\.csv"$/.test(
            r.headers.get("content-disposition") ?? "",
          ),
          `${who} disposition ${r.headers.get("content-disposition")}`,
        );
        same(p, `${who} hash`, sha256(Buffer.from(r.text, "utf8")), row.sha256);
      }
      for (const who of ["developer", "viewer"]) {
        const r = await h.api("GET", url, { cookie: h.w.sessions[who] });
        same(p, `${who} download`, [r.status, r.json?.error?.code], [403, "FORBIDDEN"]);
        const g = await h.api("GET", `/reporting/reports/${id}`, { cookie: h.w.sessions[who] });
        same(p, `${who} may read the run`, [g.status, g.json.data.canDownload], [200, false]);
        const text = JSON.stringify(g.json);
        ok(
          p,
          !text.includes(row.sha256) &&
            !text.includes(row.objectKey) &&
            !text.includes("objectKey") &&
            !text.includes("sha256"),
          `${who} saw a file fact`,
        );
      }
      same(
        p,
        "the requester sees canDownload",
        (await h.api("GET", `/reporting/reports/${id}`, { cookie: h.w.sessions.manager })).json.data
          .canDownload,
        true,
      );
      // expiry
      await h.env.db.reportExport.update({
        where: { tenantId_id: { tenantId: h.tenant.id, id } },
        data: { expiresAt: new Date(Date.now() - 60000) },
      });
      const expired = await h.api("GET", url, { cookie: h.w.sessions.manager });
      same(p, "expired", [expired.status, expired.json?.error?.code], [410, "REPORT_EXPIRED"]);
      same(
        p,
        "an expired report cannot be downloaded by the list either",
        (await h.api("GET", `/reporting/reports/${id}`, { cookie: h.w.sessions.manager })).json.data
          .canDownload,
        false,
      );
      // delete: a viewer cannot, the requester can, afterwards 404
      const second = (await h.post(h.w.sessions.manager, REQ(h.pay))).json.data.reportId;
      await h.drain();
      same(
        p,
        "delete by a viewer",
        (await h.api("DELETE", `/reporting/reports/${second}`, { cookie: h.w.sessions.viewer }))
          .status,
        403,
      );
      same(
        p,
        "delete by the requester",
        (await h.api("DELETE", `/reporting/reports/${second}`, { cookie: h.w.sessions.manager }))
          .status,
        200,
      );
      same(
        p,
        "read after delete",
        (await h.api("GET", `/reporting/reports/${second}`, { cookie: h.w.sessions.manager }))
          .status,
        404,
      );
      same(
        p,
        "download after delete",
        (
          await h.api("GET", `/reporting/reports/${second}/download`, {
            cookie: h.w.sessions.admin,
          })
        ).status,
        404,
      );
      const pending = (await h.post(h.w.sessions.manager, REQ(h.pay))).json.data.reportId;
      same(
        p,
        "delete while queued",
        (await h.api("DELETE", `/reporting/reports/${pending}`, { cookie: h.w.sessions.manager }))
          .status,
        409,
      );
      await h.drain();
      // a tenant-wide report: the admin only
      const wide = await h.post(h.w.sessions.admin, {
        template: "findings_by_pipeline",
        format: "csv",
      });
      same(p, "tenant-wide by the admin", wide.status, 202);
      same(
        p,
        "tenant-wide by a manager",
        (await h.post(h.w.sessions.manager, { template: "findings_by_pipeline", format: "csv" }))
          .status,
        403,
      );
      await h.drain();
      same(
        p,
        "a manager cannot see a tenant-wide report",
        (
          await h.api("GET", `/reporting/reports/${wide.json.data.reportId}`, {
            cookie: h.w.sessions.manager,
          })
        ).status,
        404,
      );
      const listed = await h.api("GET", "/reporting/reports", { cookie: h.w.sessions.admin });
      ok(
        p,
        listed.json?.data?.items?.some((r) => r.id === wide.json.data.reportId),
        "the tenant-wide list lacks the report",
      );
      same(
        p,
        "the tenant-wide list for a manager",
        (await h.api("GET", "/reporting/reports", { cookie: h.w.sessions.manager })).status,
        403,
      );
      return p;
    },
  },
  {
    id: "RPT-S08f",
    name: "The module is off by default (REPORTING_ENABLED=false): on the suite's own API every export route answers the identical 404 RESOURCE_NOT_FOUND after authentication (unauthenticated is still 401), nothing is queued and no row is written",
    async run(c) {
      const p = [];
      const need = (n) => process.env[n];
      const client = createClient({
        baseUrl: need("SECURITY_API_URL"),
        origin: need("SECURITY_ORIGIN"),
      });
      const login = await client.api("POST", "/auth/login", {
        body: { email: "demo.admin@demo.example", password: need("SECURITY_TENANT_PASSWORD") },
      });
      const cookie = login.cookie;
      const id = randomUUID();
      const before = await c.db.reportExport.count();
      for (const [method, url, body] of [
        ["POST", "/reporting/reports", { template: "findings_by_pipeline", format: "csv" }],
        ["GET", "/reporting/reports", undefined],
        ["GET", `/reporting/reports/${id}`, undefined],
        ["GET", `/reporting/reports/${id}/download`, undefined],
        ["DELETE", `/reporting/reports/${id}`, undefined],
      ]) {
        const anon = await client.api(method, url, {
          body,
          headers: { "Idempotency-Key": "key-off-aaaaaaaa" },
        });
        same(p, `${method} ${url} unauthenticated`, anon.status, 401);
        const r = await client.api(method, url, {
          cookie,
          body,
          headers: { "Idempotency-Key": "key-off-aaaaaaaa" },
        });
        same(p, `${method} ${url}`, [r.status, r.json?.error?.code], [404, "RESOURCE_NOT_FOUND"]);
      }
      same(p, "rows written while off", await c.db.reportExport.count(), before);
      return p;
    },
  },
  {
    id: "RPT-S08g",
    name: "Worker safety (RPT-S07, ADR-011): the handler loads the report by the envelope's tenant AND the report id (a message that names another tenant's report builds nothing and leaves the row queued; a tenant in the payload that differs is refused as non-retryable), claims the run atomically (a repeated message does nothing: the file and its hash are unchanged), a report whose template is not a v1 template fails with the stable code internal and writes no file, a failure leaves no object and no secret in the row, a deleted-while-queued row is not built, and the retention pass marks expired and deleted reports expired and removes exactly their files",
    async run(c) {
      const p = [];
      const env = await inproc(c);
      const pa = (await c.published(c.A, 1)).pipeline;
      const pb = (await c.published(c.B, 0)).pipeline;
      await c.finding(pa, { title: "worker safety" });
      const actorA = ACTOR(
        pa.tenantId,
        await freshUser(c),
        permissionsIn(pa.workspaceId, EXPORTER),
      );
      const { reportId } = await env.service().create(actorA, REQ(pa.workspaceId));
      await env.handler({ tenantId: pb.tenantId, payload: { reportId } }, { log: env.logger });
      const untouched = await env.exportsRepo.getExport({ tenantId: pa.tenantId, id: reportId });
      same(
        p,
        "another tenant's message",
        [untouched.status, untouched.objectKey],
        ["queued", null],
      );
      same(
        p,
        "no object under either tenant",
        [
          await env.reader.size({ tenantId: pa.tenantId, reportId, format: "csv" }),
          await env.reader.size({ tenantId: pb.tenantId, reportId, format: "csv" }),
        ],
        [null, null],
      );
      let refused = null;
      try {
        await env.handler(
          { tenantId: pa.tenantId, payload: { reportId, tenantId: pb.tenantId } },
          { log: env.logger },
        );
      } catch (error) {
        refused = error?.name ?? String(error);
      }
      ok(
        p,
        refused === "NonRetryableError",
        `a tenant in the payload was not refused (${refused})`,
      );
      await env.handler({ tenantId: pa.tenantId, payload: { reportId } }, { log: env.logger });
      const done = await env.exportsRepo.getExport({ tenantId: pa.tenantId, id: reportId });
      same(
        p,
        "built",
        [done.status, done.objectKey],
        ["ready", `reports/${pa.tenantId}/${reportId}.csv`],
      );
      const file = path.join(env.root, ...done.objectKey.split("/"));
      const first = await readFile(file);
      same(p, "hash recorded", sha256(first), done.sha256);
      await env.handler({ tenantId: pa.tenantId, payload: { reportId } }, { log: env.logger });
      same(
        p,
        "a repeated message changed nothing",
        [
          sha256(await readFile(file)),
          (
            await env.exportsRepo.getExport({ tenantId: pa.tenantId, id: reportId })
          ).finishedAt?.getTime(),
        ],
        [done.sha256, done.finishedAt?.getTime()],
      );
      // an unknown template fails with the stable code
      const bad = randomUUID();
      await env.db.reportExport.create({
        data: {
          id: bad,
          tenantId: pa.tenantId,
          workspaceId: pa.workspaceId,
          template: "not_a_template",
          format: "csv",
          requestedByUserId: randomUUID(),
        },
      });
      await env.handler({ tenantId: pa.tenantId, payload: { reportId: bad } }, { log: env.logger });
      const failed = await env.exportsRepo.getExport({ tenantId: pa.tenantId, id: bad });
      same(
        p,
        "unknown template",
        [failed.status, failed.errorCode, failed.objectKey],
        ["failed", "internal", null],
      );
      same(
        p,
        "no file for the failed run",
        await env.reader.size({ tenantId: pa.tenantId, reportId: bad, format: "csv" }),
        null,
      );
      // a deleted report is not built
      const gone = (await env.service().create(actorA, REQ(pa.workspaceId))).reportId;
      await env.db.reportExport.update({
        where: { tenantId_id: { tenantId: pa.tenantId, id: gone } },
        data: { deletedAt: new Date() },
      });
      await env.handler(
        { tenantId: pa.tenantId, payload: { reportId: gone } },
        { log: env.logger },
      );
      same(
        p,
        "a deleted report",
        (await env.exportsRepo.getExport({ tenantId: pa.tenantId, id: gone })).status,
        "queued",
      );
      // retention: expire and delete
      const old = await generate(env, actorA, REQ(pa.workspaceId));
      const del = await generate(env, actorA, REQ(pa.workspaceId));
      const keep = await generate(env, actorA, REQ(pa.workspaceId));
      await env.db.reportExport.update({
        where: { tenantId_id: { tenantId: pa.tenantId, id: old.id } },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      await env.exportsRepo.softDeleteExport({
        tenantId: pa.tenantId,
        id: del.id,
        now: new Date(),
      });
      const result = await expireReportFiles({
        exportRepository: createReportingExportWorkerRepository({
          db: roleDb(env.db, "qm_reporting"),
        }),
        store: env.store,
        now: new Date(),
        limit: 100,
      });
      ok(
        p,
        result.expired >= 2 && result.removed === result.expired,
        `the retention pass expired ${result.expired} and removed ${result.removed}`,
      );
      same(
        p,
        "expired row",
        (await env.exportsRepo.getExport({ tenantId: pa.tenantId, id: old.id })).status,
        "expired",
      );
      same(
        p,
        "deleted row",
        (await env.exportsRepo.getExport({ tenantId: pa.tenantId, id: del.id })).status,
        "expired",
      );
      same(
        p,
        "their files",
        [
          await env.reader.size({ tenantId: pa.tenantId, reportId: old.id, format: "csv" }),
          await env.reader.size({ tenantId: pa.tenantId, reportId: del.id, format: "csv" }),
        ],
        [null, null],
      );
      ok(
        p,
        (await env.reader.size({ tenantId: pa.tenantId, reportId: keep.id, format: "csv" })) > 0,
        "the retention pass removed a live report's file",
      );
      same(
        p,
        "the live report",
        (await env.exportsRepo.getExport({ tenantId: pa.tenantId, id: keep.id })).status,
        "ready",
      );
      return p;
    },
  },
  {
    id: "RPT-S08i",
    name: "The export authorization gate (SPEC 3, docs/AUTHORIZATION.md): a report of a workspace the caller cannot see is the identical 404, a visible workspace without report.view is 403, an unknown and a deleted report are the same 404, a tenant-wide report is hidden without the tenant key, a tenant-wide request needs dashboard.view AND report.export in every workspace of the tenant (a caller who lacks it in one workspace is 403), and the disabled module is the 404 of an unknown route before any database access",
    async run() {
      const p = [];
      const t = randomUUID();
      const ws1 = randomUUID();
      const ws2 = randomUUID();
      const rows = {
        a: { id: "a", tenantId: t, workspaceId: ws1, deletedAt: null },
        b: { id: "b", tenantId: t, workspaceId: ws2, deletedAt: null },
        d: { id: "d", tenantId: t, workspaceId: ws1, deletedAt: new Date() },
        w: { id: "w", tenantId: t, workspaceId: null, deletedAt: null },
      };
      let queries = 0;
      const exportsRepo = {
        getExport: async ({ tenantId, id }) => (
          (queries += 1),
          tenantId === t ? (rows[id] ?? null) : null
        ),
      };
      let perms = null;
      const authz = {
        authorize: () => async () => {
          throw new Error("not used");
        },
        loadPermissions: async () => perms,
      };
      const support = { workspaceCount: async () => 2 };
      const gate = (enabled = true) =>
        createExportAuthorization({
          authz,
          exports: exportsRepo,
          support,
          config: { reporting: { enabled } },
        });
      const req = (id, body) => ({ params: { id }, body, principal: { tenant: { id: t } } });
      const run = async (fn, r) => {
        try {
          await fn(r, {}, () => {});
          return "ok";
        } catch (error) {
          return `${error.statusCode}`;
        }
      };
      const g = gate();
      perms = { tenant: [], workspaces: [{ id: ws1, permissions: ["report.view"] }] };
      same(p, "visible workspace with report.view", await run(g.item, req("a")), "ok");
      same(p, "another workspace of the tenant (not visible)", await run(g.item, req("b")), "404");
      same(p, "unknown report", await run(g.item, req("zz")), "404");
      same(p, "deleted report", await run(g.item, req("d")), "404");
      same(p, "tenant-wide report without the tenant key", await run(g.item, req("w")), "404");
      perms = {
        tenant: [],
        workspaces: [
          { id: ws1, permissions: ["workspace.view"] },
          { id: ws2, permissions: ["report.view"] },
        ],
      };
      same(p, "visible workspace without report.view", await run(g.item, req("a")), "403");
      perms = {
        tenant: ["dashboard.view"],
        workspaces: [
          { id: ws1, permissions: ["report.view", "report.export"] },
          { id: ws2, permissions: ["report.view"] },
        ],
      };
      same(p, "tenant-wide report with the tenant key", await run(g.item, req("w")), "ok");
      // the tenant-wide create rule: the engine's dashboard.view check is replaced here by the same `can`, so the loader supplies the set
      const wideAuthz = {
        ...authz,
        authorize: (key) => async (r, _res, next) => {
          r.authz = { permissions: perms };
          if (key === "dashboard.view" && !perms.tenant.includes("dashboard.view"))
            throw Object.assign(new Error("f"), { statusCode: 403 });
          next();
        },
      };
      const wide = createExportAuthorization({
        authz: wideAuthz,
        exports: exportsRepo,
        support,
        config: { reporting: { enabled: true } },
      });
      same(
        p,
        "tenant-wide create, export missing in one workspace",
        await run(wide.create, { body: {}, principal: { tenant: { id: t } } }),
        "403",
      );
      perms = {
        tenant: ["dashboard.view"],
        workspaces: [
          { id: ws1, permissions: ["report.view", "report.export"] },
          { id: ws2, permissions: ["report.view", "report.export"] },
        ],
      };
      same(
        p,
        "tenant-wide create, export everywhere",
        await run(wide.create, { body: {}, principal: { tenant: { id: t } } }),
        "ok",
      );
      perms = {
        tenant: [],
        workspaces: [
          { id: ws1, permissions: ["report.view", "report.export"] },
          { id: ws2, permissions: ["report.view", "report.export"] },
        ],
      };
      same(
        p,
        "tenant-wide create without the tenant key",
        await run(wide.create, { body: {}, principal: { tenant: { id: t } } }),
        "403",
      );
      const before = queries;
      same(p, "disabled module", await run(gate(false).moduleEnabled, req("a")), "404");
      same(p, "the disabled module touched the database", queries, before);
      same(p, "enabled module", await run(gate(true).moduleEnabled, req("a")), "ok");
      return p;
    },
  },
  {
    id: "RPT-S12a",
    name: "Export audit trail (RPT-S12, SPEC 12 item 6, RPT-012): generating, downloading and deleting a report each write exactly one audit entry (report.generated, report.downloaded, report.deleted) with the actor, the report as target, the workspace, the request correlation and only allow-listed metadata keys (template, format, scope, period days, row and byte counts), in the tenant of the actor; the entries contain no title, path, repository name, row value, file name or object key; a refused request writes none; and a request whose audit write fails leaves no report row and no outbox message (one transaction)",
    async run(c) {
      const p = [];
      const h = await httpWorld(c);
      await h.drain();
      const { db } = h.env;
      const since = new Date(Date.now() - 1000);
      const made = await h.post(h.w.sessions.manager, REQ(h.pay));
      const id = made.json.data.reportId;
      await h.drain();
      const dl = await h.api("GET", `/reporting/reports/${id}/download`, {
        cookie: h.w.sessions.manager,
      });
      same(p, "download", dl.status, 200);
      const refused = await h.api("GET", `/reporting/reports/${id}/download`, {
        cookie: h.w.sessions.viewer,
      });
      same(p, "refused download", refused.status, 403);
      same(
        p,
        "delete",
        (await h.api("DELETE", `/reporting/reports/${id}`, { cookie: h.w.sessions.manager }))
          .status,
        200,
      );
      const entries = await db.auditLog.findMany({
        where: { targetId: id },
        orderBy: { createdAt: "asc" },
      });
      same(
        p,
        "actions",
        entries.map((e) => e.action),
        ["report.generated", "report.downloaded", "report.deleted"],
      );
      const ALLOWED = [
        "template",
        "format",
        "scope",
        "periodFrom",
        "periodTo",
        "asOfDay",
        "estimatedRows",
        "bytes",
        "rowCount",
      ];
      for (const e of entries) {
        same(p, `${e.action} tenant`, e.tenantId, h.tenant.id);
        same(p, `${e.action} actor`, e.actorUserId, h.users.manager);
        same(p, `${e.action} target`, e.targetType, "report");
        same(p, `${e.action} workspace`, e.workspaceId, h.pay);
        ok(p, e.correlationId !== null || e.metadata?.requestId, `${e.action} has no correlation`);
        const keys = Object.keys(e.metadata ?? {}).filter((k) => k !== "requestId");
        same(
          p,
          `${e.action} unexpected metadata keys`,
          keys.filter((k) => !ALLOWED.includes(k)),
          [],
        );
        const text = JSON.stringify(e);
        ok(
          p,
          !/Use of eval|payments-api|src\/app\.js|qmentisai-findings|reports\/|\.csv/.test(text),
          `${e.action} entry carries a value, a name or a key`,
        );
      }
      same(
        p,
        "no entry for the refused download",
        await db.auditLog.count({
          where: { action: "report.downloaded", targetId: id, createdAt: { gte: since } },
        }),
        1,
      );
      // atomicity: a failing audit writer leaves nothing behind
      const env = await inproc(c);
      const pb = (await c.published(c.B, 1)).pipeline;
      const failing = {
        tenant: {
          record: async () => {
            throw new Error("audit down");
          },
        },
      };
      const rowsBefore = await db.reportExport.count({ where: { tenantId: pb.tenantId } });
      const outboxBefore = await db.outboxMessage.count({ where: { tenantId: pb.tenantId } });
      let thrown = null;
      try {
        await env
          .service({ audit: failing })
          .create(
            ACTOR(pb.tenantId, await freshUser(c), permissionsIn(pb.workspaceId, EXPORTER)),
            REQ(pb.workspaceId),
          );
      } catch (error) {
        thrown = error.message;
      }
      same(p, "the failing audit", thrown, "audit down");
      same(
        p,
        "rows after the failed audit",
        await db.reportExport.count({ where: { tenantId: pb.tenantId } }),
        rowsBefore,
      );
      same(
        p,
        "outbox messages after the failed audit",
        await db.outboxMessage.count({ where: { tenantId: pb.tenantId } }),
        outboxBefore,
      );
      return p;
    },
  },
];
