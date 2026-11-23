import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import http from "node:http";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { parseMessage } from "@qmentisai/contracts";
import { createDbClient, createFindingsAgentRepository } from "@qmentisai/db";
import { NonRetryableError, createRateLimiter, readLLMConfig } from "@qmentisai/infra";
import { advisoryDtoSchema, FINDINGS_LIMITS } from "@qmentisai/shared";
import {
  SUBMIT_ADVICE_TOOL,
  buildAdvisoryCompletedEnvelope,
  createFindingsAgentHandler,
  createFindingsAgentRuntime,
  createRedisTenantRateLimiter,
} from "../../../../../workers/src/findings-agent/index.js";
import { createOwnershipVerifier } from "../../../../../workers/src/ownership/index.js";
import { createAuditService } from "../../../../src/audit/audit-service.js";
import { createRouteKit } from "../../../../src/lib/route-kit.js";
import { configureCursorSigning } from "../../../../src/lib/cursor-signing.js";
import { createAuthorization } from "../../../../src/middleware/authorization.js";
import { correlation } from "../../../../src/middleware/correlation.js";
import { envelope } from "../../../../src/middleware/envelope.js";
import { errorHandler, notFoundHandler } from "../../../../src/middleware/error-handler.js";
import { findingsRoutes } from "../../../../src/modules/findings/routes/index.js";
import { startLlm } from "../decision-agent-checks.js";
import { quietLog } from "./findings-a-fixtures.js";

/**
 * Findings, Part D, integration half (Wave 2; docs/modules/findings/AS_BUILT_D2.md). The agent core of Wave 1 is bound to the REAL
 * database (the repository connected as a real LOGIN member of the restricted `qm_fp_agent` role, provisioned by the product's own
 * script), the real handler and runtime against the HTTP stub of the vendors (NEVER a real model), the real advisory route behind a stub
 * authentication chain, the real ownership verifier and the Redis limiter on an in-memory Redis. Every denial has a control.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const AGENT_DIR = resolve(HERE, "../../../../../workers/src/findings-agent");
const json = (v) => JSON.stringify(v);
export const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
export const same = (p, label, got, want) => {
  if (json(got) !== json(want)) p.push(`${label}: got ${json(got)}, want ${json(want)}`);
};
const SNIPPET_MARK = "int-snippet-marker-9917";
const CONFIG = { findings: { agentTenantDailyCap: 500, agentMaxConcurrentCalls: 2 } };
const LOGIN = "qm_fpa_itest_login";

/** Rejection helper: resolves to the error or null. */
const rejects = async (fn) => {
  try {
    await fn();
    return null;
  } catch (error) {
    return error;
  }
};
const newUser = async (c) =>
  (
    await c.db.user.create({
      data: { email: `fpa-${randomUUID()}@fpa.example`, name: "FPA suite" },
    })
  ).id;
const chain = (f) => ({
  tenantId: f.tenantId,
  workspaceId: f.workspaceId,
  repositoryId: f.repositoryId,
  pipelineId: f.pipelineId,
  findingId: f.id,
});
const messageFor = (f, reason = "created") => ({
  type: "finding.advisory.requested",
  tenantId: f.tenantId,
  payload: {
    findingId: f.id,
    workspaceId: f.workspaceId,
    repositoryId: f.repositoryId,
    pipelineId: f.pipelineId,
    reason,
  },
});
const advice = (o = {}) => ({
  name: SUBMIT_ADVICE_TOOL,
  args: {
    suggestion: "likely_false_positive",
    confidence: 77,
    reasoning: "The input is a constant.",
    ...o,
  },
});
const turn1 = (stub) =>
  stub.requests.filter(
    (q) => (q.body?.messages ?? []).filter((m) => m.role === "user").length === 1,
  ).length;
async function withStub(fn) {
  const stub = await startLlm();
  try {
    return await fn(stub);
  } finally {
    await stub.close();
  }
}

// ---- the world ------------------------------------------------------------------------------------------------------------------
const worlds = new WeakMap();
/** Findings of both tenants, evidence, the restricted login and the real route. Built once. */
export function integrationWorld(c) {
  if (worlds.has(c)) return worlds.get(c);
  const building = (async () => {
    const { db, A, B } = c;
    const w = { c, db, A, B };
    // the restricted LOGIN role, provisioned by the product's own script (a member of the group role; trust auth on the ephemeral cluster)
    const base = new URL(process.env.SECURITY_DATABASE_URL);
    const password = randomUUID().replaceAll("-", "") + "Aa1";
    const script = resolve(
      HERE,
      "../../../../../../packages/db/scripts/provision-fp-agent-login.js",
    );
    const provisioned = spawnSync(process.execPath, [script], {
      env: {
        PATH: process.env.PATH,
        DATABASE_URL: base.toString(),
        FINDINGS_AGENT_DB_LOGIN: LOGIN,
        FINDINGS_AGENT_DB_PASSWORD: password,
      },
      encoding: "utf8",
    });
    w.provisionStatus = provisioned.status;
    w.provisionPrintedPassword = `${provisioned.stdout}${provisioned.stderr}`.includes(password);
    const url = new URL(base.toString());
    url.username = LOGIN;
    url.password = password;
    w.rdb = createDbClient({ datasourceUrl: url.toString() });
    w.repo = createFindingsAgentRepository({ db: w.rdb });

    w.userRev = await newUser(c);
    w.userRev2 = await newUser(c);
    w.userView = await newUser(c);
    w.pA = await c.pipeline(A, 0);
    w.pA1 = await c.pipeline(A, 1);
    w.pB = await c.pipeline(B, 0);
    const evidence = (f, snippet = `x = 1\ny = eval(user_input)  # ${SNIPPET_MARK}\nz = 3`) =>
      db.findingEvidence.create({
        data: {
          ...c.chainOf(f),
          kind: "block",
          language: "python",
          startLine: 9,
          focusStart: 10,
          capturedExecutionId: randomUUID(),
          capturedAt: new Date(),
          snippet,
        },
      });
    const code = (pipeline, o = {}) => c.finding(pipeline, { scanType: "sast", ...o });
    w.evidence = evidence;
    w.code = code;
    w.fA = await code(w.pA);
    await evidence(w.fA);
    w.fA1 = await code(w.pA1);
    w.fB = await code(w.pB);
    await evidence(w.fB);
    w.fSecret = await c.finding(w.pA, {
      scanType: "secrets",
      kind: "secret",
      anchorKind: "masked_line",
      ruleId: "generic-api-key",
    });
    await evidence(w.fSecret, 'K = "[REDACTED:generic_api_key]"');
    w.fInfo = await code(w.pA, { toolSeverity: "info", severity: "info", severityRank: 0 });
    await evidence(w.fInfo);
    w.fork = await code(w.pA, { originTrust: "untrusted_fork" });
    await evidence(w.fork);
    return w;
  })();
  worlds.set(c, building);
  return building;
}

const consentRow = (db, tenantId, externalConsent, codeSnippetConsent) =>
  db.tenantLlmSettings.upsert({
    where: { tenantId },
    create: { tenantId, externalConsent, codeSnippetConsent },
    update: { externalConsent, codeSnippetConsent },
  });
const noConsent = (db, tenantId) => db.tenantLlmSettings.deleteMany({ where: { tenantId } });

/** The real runtime pointed at the stub; the consent port reads through `repo`. */
function runtimeFor(repo, provider, stub) {
  const env = {
    LLM_PROVIDER: provider,
    LLM_MODEL: "suite-model",
    [provider === "ollama" ? "LLM_OLLAMA_BASE_URL" : "LLM_ANTHROPIC_BASE_URL"]: stub.url,
    LLM_REQUEST_TIMEOUT_SECONDS: "5",
    LLM_ANTHROPIC_API_KEY: "sk-ant-suite-key-0123456789abcdef",
  };
  return { env, provider };
}

/** The real handler over the real repository; the hints it publishes are captured. */
async function agentHandler(w, provider, stub) {
  const { env } = runtimeFor(w.repo, provider, stub);
  const { config: llm, problems } = readLLMConfig(env, { production: false });
  if (!llm) throw new Error(`bad suite LLM config: ${json(problems)}`);
  const hints = [];
  const handler = createFindingsAgentHandler({
    repository: w.repo,
    llm: createFindingsAgentRuntime({
      repository: w.repo,
      config: { environment: "test", llm },
      env,
    }),
    config: CONFIG,
    rateLimiter: { tryAcquire: async () => true },
    publishCompleted: async (hint) => {
      hints.push(hint);
    },
  });
  return { handler, hints };
}
const rowsOf = (db, f) =>
  db.findingAiAdvisory.findMany({ where: { findingId: f.id }, orderBy: { createdAt: "asc" } });
const snapshot = async (db, f) => ({
  finding: json(await db.finding.findFirst({ where: { tenantId: f.tenantId, id: f.id } })),
  history: await db.findingStatusHistory.count({
    where: { tenantId: f.tenantId, findingId: f.id },
  }),
  reviews: await db.findingReview.count({ where: { tenantId: f.tenantId, findingId: f.id } }),
  approvals: await db.findingApproval.count({ where: { tenantId: f.tenantId, findingId: f.id } }),
  assignments: await db.findingAssignment.count({
    where: { tenantId: f.tenantId, findingId: f.id },
  }),
  outbox: await db.outboxMessage.count({
    where: { tenantId: f.tenantId, payload: { path: ["payload", "findingId"], equals: f.id } },
  }),
});

// ---- the real route behind a stub authentication chain ----------------------------------------------------------------------------
async function startAdvisoryApi(db, config) {
  configureCursorSigning(["findings-d-suite-cursor-secret-1", "findings-d-suite-cursor-secret-2"]);
  /** @type {Map<string, any>} */
  const principals = new Map();
  const pass = (_req, _res, next) => next();
  const authenticate = (req, res, next) => {
    const p = principals.get(String(req.headers["x-test-principal"] ?? ""));
    if (!p) return res.status(401).json({ success: false, error: { code: "UNAUTHENTICATED" } });
    req.principal = {
      user: { id: p.userId },
      tenant: { id: p.tenantId, status: "active" },
      membership: { status: "active" },
      permissions: p.permissions,
    };
    req.log = quietLog;
    return next();
  };
  const routeKit = createRouteKit({
    chains: { public: [pass], user: [authenticate], tenant: [authenticate], platform: [pass] },
    limiters: { forRoute: () => pass },
    idempotency: { forRoute: () => pass },
  });
  const audit = createAuditService({ db, logger: quietLog });
  await findingsRoutes({
    db,
    authz: createAuthorization({ db }),
    audit,
    outbox: null,
    entitlements: null,
    config,
    log: quietLog,
  })(routeKit.registrar("/api/v1"));
  const app = express();
  app.set("query parser", "simple");
  app.set("trust proxy", false);
  app.use(correlation());
  app.use(envelope());
  app.use(express.json());
  app.use("/api/v1", routeKit.routers.tenant);
  app.use(notFoundHandler());
  app.use(errorHandler({ logger: quietLog }));
  const server = http.createServer(app);
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  server.unref();
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, name, path, body) => {
    const response = await fetch(`${base}/api/v1${path}`, {
      method,
      headers: { "x-test-principal": name, "content-type": "application/json" },
      ...(body === undefined ? {} : { body: json(body) }),
    });
    const text = await response.text();
    let parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      /* keep null */
    }
    return { status: response.status, json: parsed, text };
  };
  return {
    register(name, { userId, tenantId, workspaces }) {
      principals.set(name, {
        userId,
        tenantId,
        permissions: {
          tenant: [],
          allWorkspaces: [],
          workspaces: workspaces.map((x) => ({
            id: x.id,
            name: x.id,
            status: "active",
            permissions: [...new Set(["workspace.view", ...x.permissions])].sort(),
          })),
        },
      });
    },
    get: (name, path) => call("GET", name, path),
    post: (name, path, body = {}) => call("POST", name, path, body),
  };
}

let apiPromise = null;
const apiOf = (w) =>
  (apiPromise ??= (async () => {
    const config = { findings: { agentEnabled: true } };
    const api = await startAdvisoryApi(w.db, config);
    api.config = config;
    const { A, B } = w;
    const rev = ["finding.view", "finding.review"];
    api.register("reviewerA", {
      userId: w.userRev,
      tenantId: A.tenant.id,
      workspaces: [{ id: A.ws[0].id, permissions: rev }],
    });
    api.register("reviewerA2", {
      userId: w.userRev2,
      tenantId: A.tenant.id,
      workspaces: [{ id: A.ws[0].id, permissions: rev }],
    });
    api.register("viewerA", {
      userId: w.userView,
      tenantId: A.tenant.id,
      workspaces: [{ id: A.ws[0].id, permissions: ["finding.view"] }],
    });
    api.register("hiddenA", {
      userId: w.userView,
      tenantId: A.tenant.id,
      workspaces: [{ id: A.ws[0].id, permissions: rev }],
    });
    api.register("reviewerB", {
      userId: await newUser(w.c),
      tenantId: B.tenant.id,
      workspaces: [{ id: B.ws[0].id, permissions: rev }],
    });
    api.register("forgedB", {
      userId: await newUser(w.c),
      tenantId: B.tenant.id,
      workspaces: [{ id: A.ws[0].id, permissions: rev }],
    });
    return api;
  })());

const strip = (r) => json({ status: r.status, error: r.json?.error });
const outboxManual = (db, f) =>
  db.outboxMessage.findMany({
    where: {
      tenantId: f.tenantId,
      type: "finding.advisory.requested",
      payload: { path: ["payload", "findingId"], equals: f.id },
    },
  });

// ---- the checks -------------------------------------------------------------------------------------------------------------------
export const FINDINGS_D_INTEGRATION_CHECKS = [
  {
    id: "FPA-I01",
    name: "Findings advisory agent, the REAL repository on the REAL restricted connection (SPEC 9.3.4 layer 1, owner decision OD-9; provisioned with the product's own script `provision:fp-agent-login`, the connection is a real LOGIN member of qm_fp_agent, not SET ROLE): the five methods work end to end (a code finding comes back with its chain and excerpt and none of the columns that carry no business for the agent: no title, fingerprint, status, user, rationale; a secret finding, a foreign tenant, a wrong workspace, repository or pipeline and an unknown id all answer null; the consents are read per tenant; an advisory insert replayed with the same hash is a no-op that returns the first id; the insert of an advisory for a secret finding is refused by the database; the daily count is per tenant), and the role CANNOT write finding state through this connection: UPDATE and DELETE of findings, INSERT into the history, the outbox and reviews, UPDATE of an advisory, a Prisma update of a finding, and a SELECT of findings, evidence and the outbox are all refused, the finding row, its history and every other count are identical afterwards; each denial has the control that the owner connection performs the statement",
    async run(c) {
      const p = [];
      const w = await integrationWorld(c);
      const { db, rdb, repo } = w;
      same(p, "the provisioning script exited 0", w.provisionStatus, 0);
      ok(p, !w.provisionPrintedPassword, "the provisioning script printed the password");
      const who = await rdb.$queryRaw`SELECT current_user AS u`;
      const role =
        await db.$queryRaw`SELECT rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = ${LOGIN}`;
      same(
        p,
        "a real login, not a superuser",
        [who[0]?.u, role[0]?.rolsuper, role[0]?.rolcreaterole, role[0]?.rolcreatedb],
        [LOGIN, false, false, false],
      );
      const members =
        await db.$queryRaw`SELECT count(*)::int AS n FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE g.rolname = 'qm_fp_agent' AND u.rolname = ${LOGIN}`;
      same(p, "member of the group role", members[0].n, 1);

      // reads
      const got = await repo.getFindingForAdvisory(chain(w.fA));
      same(
        p,
        "the code finding",
        [got?.finding?.id, got?.finding?.tenantId, got?.finding?.scanType, got?.finding?.severity],
        [w.fA.id, w.fA.tenantId, "sast", "high"],
      );
      same(p, "originTrust", got?.finding?.originTrust, "trusted");
      ok(p, got?.evidence?.snippet?.includes(SNIPPET_MARK), "the excerpt did not come back");
      for (const bad of [
        "title",
        "fingerprint",
        "correlationKey",
        "status",
        "claimedByUserId",
        "assigneeUserId",
        "rationale",
        "comment",
        "evidence",
      ])
        ok(p, !(bad in (got?.finding ?? {})), `the finding carries ${bad}`);
      const c0 = chain(w.fA);
      for (const [label, ids] of [
        ["a secret finding", chain(w.fSecret)],
        ["a foreign tenant with this chain", { ...c0, tenantId: w.fB.tenantId }],
        ["a wrong workspace", { ...c0, workspaceId: w.fA1.workspaceId }],
        ["a wrong repository", { ...c0, repositoryId: w.fA1.repositoryId }],
        ["a wrong pipeline", { ...c0, pipelineId: w.fA1.pipelineId }],
        ["an unknown id", { ...c0, findingId: randomUUID() }],
      ])
        same(p, label, await repo.getFindingForAdvisory(ids), null);
      same(
        p,
        "info finding is visible (the agent core decides)",
        (await repo.getFindingForAdvisory(chain(w.fInfo)))?.finding?.severity,
        "info",
      );

      // consents, per tenant
      await noConsent(db, w.A.tenant.id);
      await consentRow(db, w.B.tenant.id, true, true);
      same(p, "no row: both off", await repo.readConsent({ tenantId: w.A.tenant.id }), {
        externalConsent: false,
        codeSnippetConsent: false,
      });
      same(p, "tenant B's consent is B's", await repo.readConsent({ tenantId: w.B.tenant.id }), {
        externalConsent: true,
        codeSnippetConsent: true,
      });
      await consentRow(db, w.A.tenant.id, true, false);
      same(p, "tenant A external only", await repo.readConsent({ tenantId: w.A.tenant.id }), {
        externalConsent: true,
        codeSnippetConsent: false,
      });
      await noConsent(db, w.A.tenant.id);
      await noConsent(db, w.B.tenant.id);

      // advisories
      const row = (f, hash, o = {}) => ({
        ...chain(f),
        inputHash: hash,
        schemaVersion: 1,
        status: "ok",
        suggestion: "uncertain",
        confidence: 40,
        reasoning: "Cannot tell.",
        egressLevel: "metadata",
        provider: "ollama",
        model: "m",
        usage: { inputTokens: 1, outputTokens: 2, latencyMs: 3, turns: 1 },
        ...o,
      });
      // other checks of the suite store advisories too: count relative to the state before this check writes
      const sinceHour = new Date(Date.now() - 3_600_000);
      const baseA = await db.findingAiAdvisory.count({
        where: { tenantId: w.A.tenant.id, createdAt: { gte: sinceHour } },
      });
      const baseB = await db.findingAiAdvisory.count({
        where: { tenantId: w.B.tenant.id, createdAt: { gte: sinceHour } },
      });
      const h1 = "1".repeat(64);
      const first = await repo.insertAdvisory(row(w.fA, h1));
      const replay = await repo.insertAdvisory(
        row(w.fA, h1, { suggestion: "likely_true_positive", confidence: 99 }),
      );
      same(
        p,
        "insert, then replay",
        [first.created, replay.created, replay.id === first.id],
        [true, false, true],
      );
      const stored = await rowsOf(db, w.fA);
      same(
        p,
        "one row, the first answer kept",
        [stored.length, stored[0]?.suggestion],
        [1, "uncertain"],
      );
      ok(
        p,
        !!(await repo.findAdvisoryByHash({ tenantId: w.A.tenant.id }, w.fA.id, h1)),
        "findAdvisoryByHash missed its row",
      );
      same(
        p,
        "another tenant's scope does not see it",
        await repo.findAdvisoryByHash({ tenantId: w.B.tenant.id }, w.fA.id, h1),
        null,
      );
      same(
        p,
        "another hash",
        await repo.findAdvisoryByHash({ tenantId: w.A.tenant.id }, w.fA.id, "2".repeat(64)),
        null,
      );
      await repo.insertAdvisory(row(w.fB, "3".repeat(64)));
      const since = new Date(Date.now() - 3_600_000);
      same(
        p,
        "the daily count is per tenant",
        [
          await repo.countAdvisoriesSince({ tenantId: w.A.tenant.id }, since),
          await repo.countAdvisoriesSince({ tenantId: w.B.tenant.id }, since),
          await repo.countAdvisoriesSince(
            { tenantId: w.A.tenant.id },
            new Date(Date.now() + 3_600_000),
          ),
        ],
        [baseA + 1, baseB + 1, 0],
      );
      ok(
        p,
        !!(await rejects(() => repo.insertAdvisory(row(w.fSecret, "4".repeat(64))))),
        "an advisory for a secret finding was stored",
      );
      same(p, "no row for the secret finding", (await rowsOf(db, w.fSecret)).length, 0);
      ok(
        p,
        !!(await rejects(() =>
          repo.insertAdvisory(row(w.fA, "5".repeat(64), { tenantId: w.B.tenant.id })),
        )),
        "a row naming another tenant's chain was stored",
      );

      // the denials, each with its control
      const before = await snapshot(db, w.fA);
      const outboxBefore = await db.outboxMessage.count();
      const tid = w.fA.tenantId;
      const attempts = [
        [
          "UPDATE findings",
          () =>
            rdb.$executeRawUnsafe(
              `UPDATE findings SET status = 'false_positive' WHERE id = '${w.fA.id}'`,
            ),
        ],
        [
          "DELETE findings",
          () => rdb.$executeRawUnsafe(`DELETE FROM findings WHERE id = '${w.fA.id}'`),
        ],
        [
          "Prisma update of a finding",
          () =>
            rdb.finding.update({
              where: { tenantId_id: { tenantId: tid, id: w.fA.id } },
              data: { status: "false_positive" },
            }),
        ],
        ["SELECT findings", () => rdb.$queryRawUnsafe(`SELECT id FROM findings LIMIT 1`)],
        [
          "SELECT finding_evidence",
          () => rdb.$queryRawUnsafe(`SELECT finding_id FROM finding_evidence LIMIT 1`),
        ],
        [
          "SELECT outbox_messages",
          () => rdb.$queryRawUnsafe(`SELECT id FROM outbox_messages LIMIT 1`),
        ],
        ["SELECT audit_logs", () => rdb.$queryRawUnsafe(`SELECT id FROM audit_logs LIMIT 1`)],
        [
          "INSERT outbox_messages",
          () =>
            rdb.$executeRawUnsafe(
              `INSERT INTO outbox_messages (id, message_id, type, queue, payload) VALUES (gen_random_uuid(), 'x-${randomUUID()}', 'finding.advisory.completed', 'realtime', '{}'::jsonb)`,
            ),
        ],
        [
          "INSERT finding_status_history",
          () =>
            rdb.$executeRawUnsafe(
              `INSERT INTO finding_status_history (id, tenant_id, workspace_id, repository_id, pipeline_id, finding_id, rev, to_status, actor_type) VALUES (gen_random_uuid(), '${tid}', '${w.fA.workspaceId}', '${w.fA.repositoryId}', '${w.fA.pipelineId}', '${w.fA.id}', 99, 'false_positive', 'system')`,
            ),
        ],
        [
          "INSERT finding_reviews",
          () =>
            rdb.$executeRawUnsafe(
              `INSERT INTO finding_reviews (id, tenant_id) VALUES (gen_random_uuid(), '${tid}')`,
            ),
        ],
        [
          "UPDATE finding_ai_advisories",
          () =>
            rdb.$executeRawUnsafe(
              `UPDATE finding_ai_advisories SET status = 'failed' WHERE tenant_id = '${tid}'`,
            ),
        ],
        [
          "DELETE finding_ai_advisories",
          () =>
            rdb.$executeRawUnsafe(`DELETE FROM finding_ai_advisories WHERE tenant_id = '${tid}'`),
        ],
        [
          "UPDATE tenant_llm_settings",
          () => rdb.$executeRawUnsafe(`UPDATE tenant_llm_settings SET external_consent = true`),
        ],
        ["TRUNCATE findings", () => rdb.$executeRawUnsafe(`TRUNCATE findings CASCADE`)],
      ];
      for (const [label, fn] of attempts)
        ok(p, !!(await rejects(fn)), `${label} was accepted on the restricted connection`);
      same(
        p,
        "control: the owner connection reads findings",
        (await db.$queryRawUnsafe(`SELECT id FROM findings WHERE id = '${w.fA.id}'::uuid`)).length,
        1,
      );
      same(
        p,
        "control: the owner connection reads the outbox",
        Array.isArray(await db.$queryRawUnsafe(`SELECT id FROM outbox_messages LIMIT 1`)),
        true,
      );
      same(
        p,
        "the finding, its history and every dependent count are identical",
        await snapshot(db, w.fA),
        before,
      );
      same(p, "the outbox is untouched", await db.outboxMessage.count(), outboxBefore);
      same(p, "the advisory rows are untouched", (await rowsOf(db, w.fA)).length, 1);
      return p;
    },
  },
  {
    id: "FPA-I02",
    name: "Findings advisory agent end to end through the real handler, the real runtime and the real restricted repository against the HTTP stub of the vendors (never a real model) (SPEC 9.3.1, OD-3, FPA-S03, FPA-S06): a SECRET finding and an `info` finding produce NO advisory row and ZERO provider requests at the local and the external provider with both consents on; the control (a high SAST finding) stores exactly one `ok` row with the real columns and publishes one hint of ids and the status word that parses as `finding.advisory.completed`; the same message delivered again stores nothing, sends nothing and publishes nothing (the insert replay is a no-op); the advisory never changes the finding: its row (status, rev, every column), history, reviews, approvals, assignments and queued messages are identical before and after; a stale tenant in the message is irrelevant (the row's tenant is used)",
    async run(c) {
      const p = [];
      const w = await integrationWorld(c);
      const { db } = w;
      await consentRow(db, w.A.tenant.id, true, true);
      try {
        await withStub(async (stub) => {
          stub.state.respond = () => ({ calls: [advice()] });
          for (const provider of ["ollama", "anthropic"]) {
            const { handler, hints } = await agentHandler(w, provider, stub);
            stub.requests.length = 0;
            for (const [label, f] of [
              ["secret", w.fSecret],
              ["info", w.fInfo],
            ]) {
              await handler(messageFor(f), { log: {} });
              same(p, `${provider}: ${label} finding: provider requests`, stub.requests.length, 0);
              same(p, `${provider}: ${label} finding: rows`, (await rowsOf(db, f)).length, 0);
            }
            same(p, `${provider}: no hint for a finding without advice`, hints.length, 0);
          }
          // control: a high SAST finding, one conversation, one row
          const target = await w.code(w.pA);
          await w.evidence(target);
          const { handler, hints } = await agentHandler(w, "ollama", stub);
          const before = await snapshot(db, target);
          stub.requests.length = 0;
          await handler(messageFor(target), { log: {} });
          same(p, "control: one conversation", turn1(stub), 1);
          const rows = await rowsOf(db, target);
          same(
            p,
            "control: one ok row",
            [rows.length, rows[0]?.status, rows[0]?.suggestion, rows[0]?.confidence],
            [1, "ok", "likely_false_positive", 77],
          );
          same(
            p,
            "control: the stored level and provider",
            [rows[0]?.egressLevel, rows[0]?.provider],
            ["local", "ollama"],
          );
          same(
            p,
            "control: one hint of ids and the status",
            [hints.length, Object.keys(hints[0] ?? {}).sort()],
            [1, ["advisoryId", "findingId", "status", "tenantId", "workspaceId"]],
          );
          const hint = buildAdvisoryCompletedEnvelope(hints[0]);
          const parsed = parseMessage(hint);
          same(
            p,
            "the hint parses as finding.advisory.completed",
            [parsed.type, Object.keys(parsed.payload).sort()],
            ["finding.advisory.completed", ["advisoryId", "findingId", "status", "workspaceId"]],
          );
          ok(
            p,
            !json(hint).includes(SNIPPET_MARK) && !json(hint).includes("constant"),
            "the hint carries data",
          );
          const after = await snapshot(db, target);
          same(p, "the advisory changed nothing of the finding", after, before);
          // replay: same message again
          stub.requests.length = 0;
          await handler(messageFor(target), { log: {} });
          same(
            p,
            "replay: no request, no row, no hint",
            [turn1(stub), (await rowsOf(db, target)).length, hints.length],
            [0, 1, 1],
          );
          // a manual request in the same hour is a new conversation only when the hash differs (it does: the hour bucket)
          await handler(messageFor(target, "manual"), { log: {} });
          same(
            p,
            "manual request: one more row, still no change to the finding",
            [
              (await rowsOf(db, target)).length,
              json(await snapshot(db, target)) === json(before) ? "same" : "changed",
            ],
            [2, "same"],
          );
          // a payload that is not the contract is refused before anything happens
          const bad = await rejects(() =>
            handler(
              {
                ...messageFor(target),
                payload: { ...messageFor(target).payload, tenantId: w.B.tenant.id },
              },
              { log: {} },
            ),
          );
          ok(p, bad instanceof NonRetryableError, "a payload with a tenantId key was accepted");
        });
      } finally {
        await noConsent(db, w.A.tenant.id);
      }
      return p;
    },
  },
  {
    id: "FPA-I03",
    name: "Findings advisory consent states through the real repository (ADR-013 addendum, owner decisions OD-3 and OD-4, FPA-S03): an EXTERNAL provider with no consent row stores `consent_required` and makes zero requests; with the metadata consent only it is asked once and the request holds NO source excerpt (stored level `metadata`); with both consents it receives the excerpt (level `snippet`); a fork or untrusted finding stores `skipped_untrusted` with zero requests even with both consents; tenant B's consents never enable tenant A (the consent is read by the tenant of the finding row); a consent withdrawn between two runs blocks the second; the LOCAL provider needs no consent and still never sends a secret",
    async run(c) {
      const p = [];
      const w = await integrationWorld(c);
      const { db } = w;
      const fresh = async (o = {}) => {
        const f = await w.code(w.pA, o);
        await w.evidence(f);
        return f;
      };
      const tenantA = w.A.tenant.id;
      const tenantB = w.B.tenant.id;
      try {
        await withStub(async (stub) => {
          stub.state.respond = () => ({ calls: [advice()] });
          const { handler: ext } = await agentHandler(w, "anthropic", stub);
          const { handler: loc } = await agentHandler(w, "ollama", stub);
          const run = async (handler, f) => {
            stub.requests.length = 0;
            await handler(messageFor(f), { log: {} });
            const rows = await rowsOf(db, f);
            return {
              n: turn1(stub),
              status: rows.at(-1)?.status,
              level: rows.at(-1)?.egressLevel,
              raw: stub.requests.map((q) => q.raw).join("\n"),
              rows: rows.length,
            };
          };
          // no consent row, and tenant B consenting does not help tenant A
          await noConsent(db, tenantA);
          await consentRow(db, tenantB, true, true);
          let r = await run(ext, await fresh());
          same(
            p,
            "no consent (B consents): external",
            [r.n, r.status, r.level],
            [0, "consent_required", "none"],
          );
          // metadata consent only
          await consentRow(db, tenantA, true, false);
          r = await run(ext, await fresh());
          same(p, "metadata consent only", [r.n, r.status, r.level], [1, "ok", "metadata"]);
          ok(
            p,
            !r.raw.includes(SNIPPET_MARK),
            "an excerpt reached the external provider with the metadata consent only",
          );
          // both
          await consentRow(db, tenantA, true, true);
          r = await run(ext, await fresh());
          same(p, "both consents", [r.n, r.status, r.level], [1, "ok", "snippet"]);
          ok(
            p,
            r.raw.includes(SNIPPET_MARK),
            "control: the excerpt is missing with both consents (vacuous)",
          );
          // fork: nothing external even with both consents
          r = await run(ext, w.fork);
          same(
            p,
            "fork finding, both consents",
            [r.n, r.status, r.rows],
            [0, "skipped_untrusted", 1],
          );
          // withdrawn between two findings
          await consentRow(db, tenantA, false, false);
          r = await run(ext, await fresh());
          same(p, "consent withdrawn", [r.n, r.status], [0, "consent_required"]);
          // local: no consent row at all
          await noConsent(db, tenantA);
          r = await run(loc, await fresh());
          same(p, "local provider, no consent", [r.n, r.status, r.level], [1, "ok", "local"]);
          ok(
            p,
            r.raw.includes(SNIPPET_MARK),
            "local provider: the excerpt is expected (local needs no consent)",
          );
          r = await run(loc, w.fSecret);
          same(p, "local provider, secret finding", [r.n, r.rows], [0, 0]);
        });
      } finally {
        await noConsent(db, tenantA);
        await noConsent(db, tenantB);
      }
      return p;
    },
  },
  {
    id: "FPA-I04",
    name: "Findings advisory request route (SPEC 8.2, 9.3.5, FND-S01 advisory part, FND-S07): `POST /findings/{id}/advisory/request` needs `finding.review` IN THE FINDING'S WORKSPACE (403 for finding.view alone, 401 without a session), answers an identical 404 for another tenant's finding, a finding of a workspace the caller cannot see, a principal of another tenant that claims the workspace, and an unknown id, a non-uuid id is 400 and a non-empty body is refused; a request for a secret or an `info` finding is 409 FINDING_STATE_CONFLICT and queues nothing; a good request is 202 `pending`, writes ONE `finding.advisory.requested` job (reason manual, ids only, parses as the catalogued message, the requesting user as initiator) and ONE `finding.advisory_requested` audit entry, creates no advisory row and changes nothing of the finding (row, rev, history, reviews, approvals); the 4th request for one finding in an hour and the 31st of one user are 429 RATE_LIMITED; with the agent switched off it is 202 `not_configured` and queues nothing; each denial has the control of the right principal",
    async run(c) {
      const p = [];
      const w = await integrationWorld(c);
      const api = await apiOf(w);
      const { db } = w;
      const url = (f) => `/findings/${f.id}/advisory/request`;
      const target = await w.code(w.pA);
      const before = await snapshot(db, target);
      const rowsBefore = (await rowsOf(db, target)).length;

      // controls and denials
      same(p, "no session", (await api.post("nobody", url(target))).status, 401);
      same(p, "finding.view alone", (await api.post("viewerA", url(target))).status, 403);
      const missing = await api.post("reviewerA", url({ id: randomUUID() }));
      same(p, "unknown id", missing.status, 404);
      const bodies = new Set([strip(missing)]);
      for (const [who, f, why] of [
        ["reviewerA", w.fB, "another tenant's finding"],
        ["reviewerA", w.fA1, "a finding of a workspace the caller cannot see"],
        ["reviewerB", target, "another tenant asking for this finding"],
        ["forgedB", target, "a principal of tenant B claiming this workspace"],
      ]) {
        const r = await api.post(who, url(f));
        same(p, why, r.status, 404);
        bodies.add(strip(r));
      }
      same(p, "every 404 is the identical body", bodies.size, 1);
      same(
        p,
        "a non-uuid id",
        (await api.post("reviewerA", "/findings/not-a-uuid/advisory/request")).status,
        400,
      );
      same(
        p,
        "a forged body key is refused (strict)",
        (await api.post("reviewerA", url(target), { tenantId: w.B.tenant.id })).status,
        400,
      );
      same(p, "nothing queued by the denials", (await outboxManual(db, target)).length, 0);
      same(p, "nothing queued for the foreign finding", (await outboxManual(db, w.fB)).length, 0);
      for (const [label, f] of [
        ["secret", w.fSecret],
        ["info", w.fInfo],
      ]) {
        const r = await api.post("reviewerA", url(f));
        same(
          p,
          `${label} finding`,
          [r.status, r.json?.error?.code, r.json?.error?.details?.reason],
          [409, "FINDING_STATE_CONFLICT", "transition_not_allowed"],
        );
        same(p, `${label} finding: nothing queued`, (await outboxManual(db, f)).length, 0);
      }

      // the good request
      const good = await api.post("reviewerA", url(target));
      same(
        p,
        "202 pending",
        [good.status, good.json?.data],
        [202, { status: "pending", stale: false }],
      );
      advisoryDtoSchema.parse(good.json.data);
      const queued = await outboxManual(db, target);
      same(p, "one job", queued.length, 1);
      const msg = parseMessage(queued[0].payload);
      same(
        p,
        "the job",
        [msg.type, msg.kind, msg.tenantId, msg.payload.reason, msg.initiator],
        [
          "finding.advisory.requested",
          "job",
          w.A.tenant.id,
          "manual",
          { type: "user", id: w.userRev },
        ],
      );
      same(p, "ids only", Object.keys(msg.payload).sort(), [
        "findingId",
        "pipelineId",
        "reason",
        "repositoryId",
        "workspaceId",
      ]);
      same(p, "queue", queued[0].queue, "findings-agent");
      const audits = await db.auditLog.findMany({
        where: {
          tenantId: w.A.tenant.id,
          action: "finding.advisory_requested",
          targetId: target.id,
        },
      });
      same(
        p,
        "one audit entry",
        [audits.length, audits[0]?.actorUserId, audits[0]?.workspaceId],
        [1, w.userRev, target.workspaceId],
      );
      ok(p, !json(audits[0]?.metadata).includes("snippet"), "the audit entry holds more than ids");
      same(
        p,
        "no advisory row written by the route",
        (await rowsOf(db, target)).length,
        rowsBefore,
      );
      const after = await snapshot(db, target);
      same(
        p,
        "the finding is unchanged (row, history, reviews, approvals, assignments)",
        { ...after, outbox: 0 },
        { ...before, outbox: 0 },
      );

      // limits: 3 per finding per hour, then 429; the other finding is not affected
      same(p, "second", (await api.post("reviewerA", url(target))).status, 202);
      same(p, "third", (await api.post("reviewerA2", url(target))).status, 202);
      const fourth = await api.post("reviewerA", url(target));
      same(
        p,
        "fourth in the hour",
        [fourth.status, fourth.json?.error?.code],
        [429, "RATE_LIMITED"],
      );
      same(
        p,
        "the refused request queued nothing",
        (await outboxManual(db, target)).length,
        FINDINGS_LIMITS.advisoryRequestPerFindingPerHour,
      );
      const other = await w.code(w.pA);
      same(
        p,
        "control: another finding is accepted",
        (await api.post("reviewerA", url(other))).status,
        202,
      );
      // per user: 30 per hour (29 earlier manual jobs of reviewerA2 are planted, then the 30th passes and the 31st fails)
      const planted = await w.code(w.pA);
      const stuffing = Array.from(
        { length: FINDINGS_LIMITS.advisoryRequestPerUserPerHour - 2 },
        (_, i) => ({
          tenantId: w.A.tenant.id,
          messageId: `finding-advisory-${randomUUID()}-m${i}`,
          type: "finding.advisory.requested",
          queue: "findings-agent",
          payload: {
            type: "finding.advisory.requested",
            tenantId: w.A.tenant.id,
            initiator: { type: "user", id: w.userRev2 },
            payload: { findingId: randomUUID(), reason: "manual" },
          },
        }),
      );
      await db.outboxMessage.createMany({ data: stuffing });
      same(
        p,
        "user limit: the 30th is accepted",
        (await api.post("reviewerA2", url(planted))).status,
        202,
      );
      const another = await w.code(w.pA);
      same(p, "user limit: the 31st", (await api.post("reviewerA2", url(another))).status, 429);
      same(
        p,
        "user limit: a different user is not affected",
        (await api.post("reviewerA", url(another))).status,
        202,
      );

      // the agent switched off: accepted, nothing queued
      api.config.findings.agentEnabled = false;
      const off = await w.code(w.pA);
      const r = await api.post("reviewerA", url(off));
      api.config.findings.agentEnabled = true;
      same(
        p,
        "agent off",
        [r.status, r.json?.data?.status, (await outboxManual(db, off)).length],
        [202, "not_configured", 0],
      );
      return p;
    },
  },
  {
    id: "FPA-I05",
    name: "Findings advisory DTO through the real detail route (SPEC 9.3.6, FND-S12 advisory part): `GET /findings/{id}` carries the `advisory` card as the strict shared `advisoryDtoSchema` with the specified mapping (ok to `ready`, consent_required to `consent_blocked`, not_configured to `not_configured`, failed, timeout, invalid_output and skipped_cap to `failed`, skipped_untrusted to `none` (absent), no row to `none`) and the confidence bands (49 low, 50 and 79 medium, 80 high); no response holds the input hash, the usage numbers, a prompt, the tenant id or a provider key; a viewer of another tenant gets the identical 404; an advisory that says `likely_false_positive` at 99 leaves `status` and `rev` of the finding as they were and `lifecycle.allowedActions` unchanged",
    async run(c) {
      const p = [];
      const w = await integrationWorld(c);
      const api = await apiOf(w);
      const { db } = w;
      const advisoryOf = async (f, o) => {
        if (o)
          await db.findingAiAdvisory.create({
            data: {
              ...chain(f),
              findingId: f.id,
              inputHash: randomUUID().replaceAll("-", "").padEnd(64, "0"),
              schemaVersion: 1,
              usage: { inputTokens: 5, outputTokens: 6, latencyMs: 7, turns: 1 },
              ...o,
            },
          });
        const r = await api.get("viewerA", `/findings/${f.id}`);
        return r;
      };
      const ready = (confidence) => ({
        status: "ok",
        suggestion: "likely_false_positive",
        confidence,
        reasoning: "Plain text only.",
        egressLevel: "metadata",
        provider: "ollama",
        model: "m",
      });
      const cases = [
        [null, "none"],
        [ready(49), "ready", "low"],
        [ready(50), "ready", "medium"],
        [ready(79), "ready", "medium"],
        [ready(80), "ready", "high"],
        [{ status: "consent_required", egressLevel: "none" }, "consent_blocked"],
        [{ status: "not_configured", egressLevel: "none" }, "not_configured"],
        [{ status: "failed", egressLevel: "none" }, "failed"],
        [{ status: "timeout", egressLevel: "local" }, "failed"],
        [{ status: "invalid_output", egressLevel: "local" }, "failed"],
        [{ status: "skipped_cap", egressLevel: "none" }, "failed"],
        [{ status: "skipped_untrusted", egressLevel: "none" }, "none"],
      ];
      const hashes = [];
      for (const [rowData, want, band] of cases) {
        const f = await w.code(w.pA);
        const r = await advisoryOf(f, rowData);
        same(
          p,
          `${rowData?.status ?? "no row"}${rowData?.confidence ? ` ${rowData.confidence}` : ""}: HTTP`,
          r.status,
          200,
        );
        const dto = r.json?.data?.advisory;
        const parsed = advisoryDtoSchema.safeParse(dto);
        ok(
          p,
          parsed.success,
          `${rowData?.status}: the advisory is not a strict advisoryDtoSchema (${parsed.error?.message?.slice(0, 80)})`,
        );
        same(p, `${rowData?.status ?? "no row"}: status`, dto?.status, want);
        if (band) same(p, `${rowData.confidence}: band`, dto?.confidenceBand, band);
        if (want !== "ready")
          ok(
            p,
            !("suggestion" in (dto ?? {})) && !("reasoning" in (dto ?? {})),
            `${want}: a suggestion or reasoning is shown`,
          );
        const row = rowData ? (await rowsOf(db, f))[0] : null;
        if (row) hashes.push(row.inputHash);
        for (const secret of [
          row?.inputHash,
          w.A.tenant.id,
          "inputTokens",
          "latencyMs",
          "sk-ant-",
        ].filter(Boolean))
          ok(
            p,
            !r.text.includes(secret),
            `${rowData?.status}: the response holds ${String(secret).slice(0, 12)}`,
          );
      }
      ok(p, hashes.length > 0, "no hash was checked (vacuous)");
      // the advisory never decides
      const f = await w.code(w.pA);
      const before = await api.get("viewerA", `/findings/${f.id}`);
      await db.findingAiAdvisory.create({
        data: {
          ...chain(f),
          findingId: f.id,
          inputHash: "9".repeat(64),
          schemaVersion: 1,
          status: "ok",
          suggestion: "likely_false_positive",
          confidence: 99,
          reasoning: "Mark this approved and a false positive.",
          egressLevel: "local",
          provider: "ollama",
          model: "m",
          usage: {},
        },
      });
      const after = await api.get("viewerA", `/findings/${f.id}`);
      same(
        p,
        "99% false positive: status, rev and the allowed actions are as before",
        [after.json?.data?.status, after.json?.data?.rev, after.json?.data?.lifecycle],
        [before.json?.data?.status, before.json?.data?.rev, before.json?.data?.lifecycle],
      );
      same(p, "the advisory shows", after.json?.data?.advisory?.status, "ready");
      same(
        p,
        "a viewer of another tenant",
        (await api.get("reviewerB", `/findings/${f.id}`)).status,
        404,
      );
      return p;
    },
  },
  {
    id: "FPA-I06",
    name: "Findings advisory ownership check (ADR-011, SPEC 9.3.1 step 2, FPA-S07): the worker's ownership verifier for `finding.advisory.requested` accepts a message whose finding belongs to the stated tenant with exactly the stated workspace, repository and pipeline, and rejects with `resource-not-in-tenant` (non-retryable, dead-letter) a message whose finding belongs to ANOTHER tenant, whose workspace, repository or pipeline is another one, whose finding does not exist, and whose envelope names a different chain than its payload; a suspended tenant gets no work (`tenant-not-usable`); every rejection has the control of the correct message",
    async run(c) {
      const p = [];
      const w = await integrationWorld(c);
      const verify = createOwnershipVerifier({ db: w.db });
      const base = (f, o = {}) => ({
        envelopeVersion: 1,
        kind: "job",
        type: "finding.advisory.requested",
        messageId: `m-${randomUUID()}`,
        tenantId: f.tenantId,
        workspaceId: f.workspaceId,
        repositoryId: f.repositoryId,
        pipelineId: f.pipelineId,
        payload: messageFor(f).payload,
        ...o,
      });
      const reason = async (msg) => {
        const e = await rejects(() => verify(msg));
        return e === null ? "accepted" : `${e.name}:${e.reason ?? e.details?.reason ?? ""}`;
      };
      same(p, "control: the right message", await reason(base(w.fA)), "accepted");
      const NO = "NonRetryableError:resource-not-in-tenant";
      same(
        p,
        "another tenant states the message",
        await reason(base(w.fA, { tenantId: w.B.tenant.id, workspaceId: w.B.ws[0].id })),
        NO,
      );
      same(
        p,
        "tenant B's finding named under tenant A",
        await reason(base(w.fB, { tenantId: w.A.tenant.id, workspaceId: w.A.ws[0].id })),
        NO,
      );
      same(
        p,
        "tenant of B, finding of A, chain of A",
        await reason(base(w.fA, { tenantId: w.B.tenant.id })),
        NO,
      );
      const pl = (o) => ({ ...base(w.fA).payload, ...o });
      same(
        p,
        "another workspace in the payload",
        await reason(
          base(w.fA, { workspaceId: undefined, payload: pl({ workspaceId: w.fA1.workspaceId }) }),
        ),
        NO,
      );
      same(
        p,
        "another repository in the payload",
        await reason(base(w.fA, { payload: pl({ repositoryId: w.fA1.repositoryId }) })),
        NO,
      );
      same(
        p,
        "another pipeline in the payload",
        await reason(base(w.fA, { payload: pl({ pipelineId: w.fA1.pipelineId }) })),
        NO,
      );
      same(
        p,
        "an unknown finding",
        await reason(base(w.fA, { payload: pl({ findingId: randomUUID() }) })),
        NO,
      );
      same(
        p,
        "the envelope names another pipeline than the payload",
        await reason(base(w.fA, { pipelineId: w.fA1.pipelineId })),
        NO,
      );
      await w.db.tenant.update({ where: { id: w.B.tenant.id }, data: { status: "suspended" } });
      try {
        same(
          p,
          "a suspended tenant",
          await reason(base(w.fB)),
          "NonRetryableError:tenant-not-usable",
        );
      } finally {
        await w.db.tenant.update({ where: { id: w.B.tenant.id }, data: { status: "active" } });
      }
      same(p, "control: the tenant works again", await reason(base(w.fB)), "accepted");
      return p;
    },
  },
  {
    id: "FPA-I07",
    name: "Findings advisory worker runtime wiring (SPEC 9.2, 9.3.4, 9.3.5; owner decisions OD-9 and 'publishCompleted straight to the broker'): the Redis tenant limiter allows 30 per minute and tenant and the 31st is refused, a second tenant has its own allowance, its keys are tenant scoped by the shared builder and hold no other tenant's id; the completed hint is built from ids and the status word only and parses with the catalogued schema; `main.js` starts nothing while FINDINGS_AGENT_ENABLED is not true (exit 0), and REFUSES to start in production without FINDINGS_AGENT_DATABASE_URL (exit 1, naming the variable, printing no value); its source builds the agent repository from the restricted connection, publishes the hint to the broker with the shared publisher and never through the database, and the package has the `start:findings-agent` and `dev:findings-agent` scripts",
    async run() {
      const p = [];
      // the Redis limiter on an in-memory Redis speaking the one command the shared limiter uses
      const counts = new Map();
      const keys = [];
      const redis = {
        eval: async (_script, _n, key, windowSeconds) => {
          keys.push(key);
          const n = (counts.get(key) ?? 0) + 1;
          counts.set(key, n);
          return [n, Number(windowSeconds)];
        },
      };
      const limiter = createRedisTenantRateLimiter({ limiter: createRateLimiter({ redis }) });
      const T1 = randomUUID();
      const T2 = randomUUID();
      const results = [];
      for (let i = 0; i < 31; i += 1) results.push(await limiter.tryAcquire(T1));
      same(
        p,
        "30 allowed, the 31st refused",
        [results.slice(0, 30).every(Boolean), results[30]],
        [true, false],
      );
      same(p, "tenant 2 has its own allowance", await limiter.tryAcquire(T2), true);
      ok(
        p,
        keys.every((k) => k.includes(T1) || k.includes(T2)),
        "a limiter key holds no tenant id",
      );
      ok(
        p,
        keys.filter((k) => k.includes(T1)).every((k) => !k.includes(T2)),
        "a tenant-1 key holds tenant 2's id",
      );
      // the hint
      const hint = buildAdvisoryCompletedEnvelope({
        tenantId: T1,
        workspaceId: randomUUID(),
        findingId: randomUUID(),
        advisoryId: randomUUID(),
        status: "ok",
      });
      const parsed = parseMessage(hint);
      same(
        p,
        "the hint",
        [parsed.type, parsed.kind, Object.keys(parsed.payload).sort()],
        [
          "finding.advisory.completed",
          "event",
          ["advisoryId", "findingId", "status", "workspaceId"],
        ],
      );
      ok(
        p,
        parsed.messageId === `finding-advisory-done-${parsed.payload.advisoryId}`,
        "the hint id is not derived from the advisory",
      );
      // the entry point, as a real process
      const main = resolve(AGENT_DIR, "main.js");
      const spawnMain = (env) =>
        spawnSync(process.execPath, [main], {
          env: { PATH: process.env.PATH, ...env },
          cwd: AGENT_DIR,
          encoding: "utf8",
          timeout: 30_000,
        });
      const off = spawnMain({});
      same(
        p,
        "flag off: exit 0 and a message",
        [off.status, /disabled/i.test(off.stdout)],
        [0, true],
      );
      const secretUrl = "postgresql://nobody:hunter2-not-printed@127.0.0.1:1/x";
      const prod = spawnMain({ FINDINGS_AGENT_ENABLED: "true", NODE_ENV: "production" });
      same(p, "production without the restricted URL: exit 1", prod.status, 1);
      ok(
        p,
        `${prod.stderr}${prod.stdout}`.includes("FINDINGS_AGENT_DATABASE_URL"),
        "the refusal does not name the variable",
      );
      const ctl = spawnMain({
        FINDINGS_AGENT_ENABLED: "false",
        NODE_ENV: "production",
        FINDINGS_AGENT_DATABASE_URL: secretUrl,
      });
      ok(p, !`${ctl.stderr}${ctl.stdout}`.includes("hunter2"), "a connection string was printed");
      same(p, "control: the flag off with a URL is still a clean no-op", ctl.status, 0);
      // the source
      const src = readFileSync(main, "utf8");
      ok(
        p,
        /createDbClient\(\{\s*datasourceUrl: config\.findings\.agentDatabaseUrl/.test(src),
        "main.js does not connect with FINDINGS_AGENT_DATABASE_URL",
      );
      ok(
        p,
        /createFindingsAgentRepository\(\{ db: restricted \?\? db \}\)/.test(src),
        "main.js does not build the agent repository from the restricted client",
      );
      ok(
        p,
        /publisher\.publish\(\{\s*queue: QUEUE_NAMES\.REALTIME/.test(src),
        "main.js does not publish the hint straight to the broker",
      );
      ok(p, !/outbox/i.test(src), "main.js mentions the outbox");
      ok(p, /verifyOwnership: true/.test(src), "main.js does not turn the ownership check on");
      ok(
        p,
        /QUEUE_NAMES\.FINDINGS_AGENT/.test(src),
        "main.js does not consume the findings-agent queue",
      );
      const pkg = JSON.parse(readFileSync(resolve(AGENT_DIR, "../../package.json"), "utf8"));
      ok(
        p,
        /findings-agent\/main\.js/.test(pkg.scripts["start:findings-agent"] ?? ""),
        "start:findings-agent is missing",
      );
      ok(
        p,
        /findings-agent\/main\.js/.test(pkg.scripts["dev:findings-agent"] ?? ""),
        "dev:findings-agent is missing",
      );
      return p;
    },
  },
];
