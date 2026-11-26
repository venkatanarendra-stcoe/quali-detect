import { randomBytes, randomUUID } from "node:crypto";
import http from "node:http";
import express from "express";
import pino from "pino";
import { permissionKeysByScope } from "@qmentisai/shared";
import { configureCursorSigning } from "../../../../src/lib/cursor-signing.js";
import { createRouteKit } from "../../../../src/lib/route-kit.js";
import { correlation } from "../../../../src/middleware/correlation.js";
import { createAuthorization } from "../../../../src/middleware/authorization.js";
import { envelope } from "../../../../src/middleware/envelope.js";
import { errorHandler, notFoundHandler } from "../../../../src/middleware/error-handler.js";
import { reportingReadRoutes } from "../../../../src/modules/reporting/routes/read.routes.js";
import { driveExecution } from "../execution-db.js";

/**
 * Fixtures of the Reporting part B checks (docs/modules/reporting-dashboards/SPEC.md 16.2: `RPT-S01` to `RPT-S04`, `RPT-S11`): the REAL reporting
 * read routes behind a stub authentication chain (the permissions of a principal are given by the check) with the real authorization
 * middleware, scope resolvers, route kit validation, services, repository, mappers and error handler. The read client of the routes is the
 * suite database ACTING AS the `qm_reporting_ro` role (`SET LOCAL ROLE` in every transaction), so every statement of every endpoint runs with
 * exactly the grants of the read login (a statement on a source table would fail with "permission denied"). The cache Redis is an in-memory
 * double that can fail or hang. Nothing talks to a real broker, Redis or GitHub.
 */

export const rand = (n = 4) => randomBytes(n).toString("hex");
export const silent = pino({ level: process.env.RPT_DEBUG ? "info" : "silent" });
export const DAY = 86_400_000;
export const daysAgo = (n) => new Date(Date.now() - n * DAY);
export const daysAhead = (n) => new Date(Date.now() + n * DAY);
export const hoursAgo = (n) => new Date(Date.now() - n * 3_600_000);
const dayString = (d) => d.toISOString().slice(0, 10);
export const today = () => dayString(new Date());
export const dayOffset = (n) => dayString(new Date(Date.now() - n * DAY));

/** An in-memory Redis double: strings with expiry, counters, a multi chain, a call log, and failure modes. */
export function createFakeRedis() {
  /** @type {Map<string, { value: string, expiresAt: number | null }>} */
  const store = new Map();
  const state = { mode: "ok", calls: /** @type {string[][]} */ ([]) };
  const guard = async (name, args, fn) => {
    state.calls.push([name, ...args.map(String)]);
    if (state.mode === "error") throw new Error("redis is down");
    if (state.mode === "hang") return new Promise(() => {});
    return fn();
  };
  const live = (key) => {
    const e = store.get(key);
    if (!e) return null;
    if (e.expiresAt !== null && e.expiresAt <= Date.now()) {
      store.delete(key);
      return null;
    }
    return e;
  };
  const redis = {
    state,
    store,
    get: (key) => guard("get", [key], async () => live(key)?.value ?? null),
    set: (key, value, ...rest) =>
      guard("set", [key, ...rest], async () => {
        const ex = rest[0] === "EX" ? Number(rest[1]) : null;
        store.set(key, { value: String(value), expiresAt: ex ? Date.now() + ex * 1000 : null });
        return "OK";
      }),
    del: (key) => guard("del", [key], async () => (store.delete(key) ? 1 : 0)),
    incr: (key) =>
      guard("incr", [key], async () => {
        const next = Number(live(key)?.value ?? 0) + 1;
        store.set(key, { value: String(next), expiresAt: store.get(key)?.expiresAt ?? null });
        return next;
      }),
    expire: (key, seconds) =>
      guard("expire", [key, seconds], async () => {
        const e = live(key);
        if (e) e.expiresAt = Date.now() + Number(seconds) * 1000;
        return e ? 1 : 0;
      }),
    multi() {
      const ops = [];
      const chain = {
        incr: (k) => (ops.push(() => redis.incr(k)), chain),
        expire: (k, s) => (ops.push(() => redis.expire(k, s)), chain),
        exec: async () => {
          const out = [];
          for (const op of ops) out.push([null, await op()]);
          return out;
        },
      };
      return chain;
    },
    keys: () => [...store.keys()],
  };
  return redis;
}

/** A user of the tenant with an active membership (display names are what the workload shows). */
export async function makeUser(db, tree, label) {
  const sfx = rand(4);
  const user = await db.user.create({
    data: { email: `rpt-b-${label}-${sfx}@rpt.example`.toLowerCase(), name: `${label} ${sfx}` },
  });
  await db.tenantMembership.create({
    data: { tenantId: tree.tenant.id, userId: user.id, status: "active", joinedAt: new Date() },
  });
  return user;
}

/**
 * The real reporting read routes on a minimal Express app. `register` names a principal; `get` calls as that principal.
 * @param {any} db the suite database client
 * @param {{ redis?: any, enabled?: boolean, readAsRole?: boolean }} [options]
 */
export async function startReadApi(db, { redis = null, enabled = true, readAsRole = true } = {}) {
  configureCursorSigning([
    "reporting-b-suite-cursor-secret-1",
    "reporting-b-suite-cursor-secret-2",
  ]);
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
    req.log = silent;
    return next();
  };
  const statements = [];
  const roDb = {
    $transaction: (fn, options) =>
      db.$transaction(async (tx) => {
        if (readAsRole) await tx.$executeRawUnsafe("SET LOCAL ROLE qm_reporting_ro");
        statements.push("BEGIN-AS-READ-ROLE");
        return fn(tx);
      }, options),
  };
  const routeKit = createRouteKit({
    chains: { public: [pass], user: [authenticate], tenant: [authenticate], platform: [pass] },
    limiters: { forRoute: () => pass },
    idempotency: { forRoute: () => pass },
  });
  const authz = createAuthorization({ db });
  await reportingReadRoutes({
    db,
    readDb: () => roDb,
    authz,
    audit: null,
    outbox: null,
    entitlements: null,
    config: { reporting: { enabled, cacheRedis: redis } },
    log: silent,
  })(routeKit.registrar("/api/v1"));
  const app = express();
  app.set("query parser", "simple");
  app.set("trust proxy", false);
  app.use(correlation());
  app.use(envelope());
  app.use("/api/v1", routeKit.routers.tenant);
  app.use(notFoundHandler());
  app.use(errorHandler({ logger: silent }));
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  server.unref();
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    routeTable: routeKit.table,
    roDb,
    statements,
    /**
     * @param {string} name
     * @param {{ userId: string, tenantId: string, tenant?: readonly string[], workspaces: Array<{ id: string, name?: string, permissions: readonly string[] }> }} spec
     */
    register(name, { userId, tenantId, tenant = [], workspaces }) {
      principals.set(name, {
        userId,
        tenantId,
        permissions: {
          tenant: [...tenant],
          allWorkspaces: [],
          workspaces: workspaces.map((w) => ({
            id: w.id,
            name: w.name ?? w.id,
            status: "active",
            permissions: [...new Set(["workspace.view", ...w.permissions])].sort(),
          })),
        },
      });
    },
    async get(name, path, { headers } = {}) {
      const response = await fetch(`${base}/api/v1${path}`, {
        headers: { "x-test-principal": name, ...headers },
      });
      const json = await response.json().catch(() => null);
      return { status: response.status, json, headers: response.headers };
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** Workspace-scope and tenant-scope keys of a bundle (the catalog's own split). @param {readonly string[]} keys */
export function splitKeys(keys) {
  const ws = new Set(permissionKeysByScope("workspace"));
  const tn = new Set(permissionKeysByScope("tenant"));
  return {
    workspace: keys.filter((k) => ws.has(k)),
    tenant: keys.filter((k) => tn.has(k)),
  };
}

// ---- the data -------------------------------------------------------------------------------------------------------------------

const hex64 = () => randomBytes(32).toString("hex");

/**
 * Sets columns of a finding with the transition triggers off for this transaction (a fixture, not a lifecycle: the reporting reads care only
 * about the row). The table's CHECK constraints still apply.
 */
async function force(db, f, data) {
  await db.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT set_config('session_replication_role', 'replica', true)`;
    await tx.finding.update({ where: { tenantId_id: { tenantId: f.tenantId, id: f.id } }, data });
  });
}

/** Canary strings planted in every excluded field (RPT-011); assembled at run time so no literal secret is in the source. */
export const CANARY_TAG = `CANARY${rand(6)}`;

/**
 * The hand-built dataset the checks run on. Tenant A, workspace 0: 14 findings (9 open) in two repositories, executions, rollup rows and runs;
 * workspace 1: 20 approved review decisions (14 false positive) with advisories; tenant B: one finding, one workspace.
 * @param {any} c the pipelines world (`A`, `B`, `pipeline`, `published`, `finding`, `review`, `exception`, `step`, `chainOf`, `execution`, `version`)
 */
export async function buildReportingData(c) {
  const { db, A, B } = c;
  const wsA0 = A.ws[0].id;
  const wsA1 = A.ws[1].id;
  const wsB0 = B.ws[0].id;
  const u1 = await makeUser(db, A, "dev-one");
  const u2 = await makeUser(db, A, "dev-two");

  // a second repository in workspace 0 (top risk and coverage need two)
  const wl = await db.scmWorkspaceLink.findFirst({
    where: { tenantId: A.tenant.id, workspaceId: wsA0 },
  });
  const repo2 = await db.repository.create({
    data: {
      tenantId: A.tenant.id,
      workspaceId: wsA0,
      linkId: A.link.id,
      workspaceLinkId: wl.id,
      provider: "github",
      externalRepoId: `rpt-b-${rand(4)}`,
      fullName: "pdb-org/a-extra",
      name: "a-extra",
      ownerLogin: "pdb-org",
      connectedByUserId: A.user.id,
    },
  });
  const publish = async (tree, i, extra = {}) => {
    const pipeline = await c.pipeline(tree, i, extra);
    const version = await c.version(pipeline, 1);
    const updated = await db.pipeline.update({
      where: { id: pipeline.id },
      data: { currentVersion: 1, currentVersionId: version.id },
    });
    return { pipeline: updated, version };
  };
  const p1 = await publish(A, 0);
  const p1b = await publish(A, 0);
  const p2 = await publish(A, 0, { repositoryId: repo2.id });
  const pa1 = await publish(A, 1);
  const pb = await publish(B, 0);

  const mk = async (p, o) => {
    const f = await c.finding(p.pipeline, {
      toolSeverity: o.severity,
      severityRank: { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[o.severity],
      ...o,
    });
    return f;
  };
  const F = {};
  const spec = [
    // key, pipeline, scan type + kind, severity, age days, sla state, extras
    [
      "f1",
      p1,
      "sast",
      "critical",
      {
        firstDetectedAt: daysAgo(40),
        slaStartedAt: daysAgo(40),
        slaDueAt: daysAgo(33),
        title: "Use of eval",
      },
    ],
    [
      "f2",
      p1,
      "sca",
      "critical",
      { firstDetectedAt: daysAgo(5), slaStartedAt: daysAgo(5), slaDueAt: daysAhead(2) },
    ],
    [
      "f3",
      p1,
      "sast",
      "high",
      { firstDetectedAt: daysAgo(29), slaStartedAt: daysAgo(29), slaDueAt: daysAhead(1) },
    ],
    [
      "f4",
      p1,
      "secrets",
      "medium",
      { firstDetectedAt: daysAgo(100), slaStartedAt: daysAgo(100), slaDueAt: daysAhead(50) },
    ],
    [
      "f5",
      p1b,
      "sca",
      "low",
      { firstDetectedAt: daysAgo(3), slaStartedAt: daysAgo(3), slaDueAt: daysAhead(30) },
    ],
    [
      "f6",
      p1b,
      "sca",
      "high",
      { firstDetectedAt: daysAgo(20), slaStartedAt: daysAgo(20), slaDueAt: daysAgo(1) },
    ],
    ["f7", p1b, "sast", "info", { firstDetectedAt: hoursAgo(2) }],
    ["f8", p1b, "sast", "critical", { firstDetectedAt: daysAgo(15) }],
    ["f9", p1, "sast", "high", { firstDetectedAt: daysAgo(20), slaStartedAt: daysAgo(20) }],
    ["f10", p1, "sca", "critical", { firstDetectedAt: daysAgo(40), slaStartedAt: daysAgo(40) }],
    ["f11", p1, "sast", "low", { firstDetectedAt: daysAgo(30) }],
    ["f12", p1, "sast", "low", { firstDetectedAt: daysAgo(30) }],
    ["f13", p1, "sca", "medium", { firstDetectedAt: daysAgo(30) }],
    ["f14", p1, "sast", "high", { firstDetectedAt: daysAgo(12) }],
    // the second repository
    [
      "g1",
      p2,
      "sca",
      "high",
      { firstDetectedAt: daysAgo(9), slaStartedAt: daysAgo(9), slaDueAt: daysAhead(20) },
    ],
    [
      "g2",
      p2,
      "sast",
      "high",
      { firstDetectedAt: daysAgo(8), slaStartedAt: daysAgo(8), slaDueAt: daysAhead(20) },
    ],
  ];
  for (const [key, p, scanType, severity, extra] of spec) {
    const kind =
      scanType === "sca" ? "vulnerability" : scanType === "secrets" ? "secret" : "code_issue";
    F[key] = await mk(p, {
      scanType,
      kind,
      severity,
      ...(scanType === "sca"
        ? { componentPurl: `pkg:npm/lib-${key}@1.0.0`, ecosystem: "npm" }
        : {}),
      ...(scanType === "secrets" ? { anchorKind: "masked_line", ruleId: "generic-api-key" } : {}),
      ...extra,
    });
  }
  // states
  await force(db, F.f1, {});
  await force(db, F.f3, { status: "in_review" });
  await force(db, F.f4, { status: "approved" });
  await force(db, F.f5, { status: "assigned", assigneeUserId: u1.id, assignedAt: new Date() });
  await force(db, F.f6, {
    status: "in_remediation",
    assigneeUserId: u1.id,
    assignedAt: new Date(),
  });
  await force(db, F.f8, { status: "fixed_pending_verification", fixClaimedAt: daysAgo(3) });
  await force(db, F.f9, {
    status: "verified_fixed",
    verifiedAt: daysAgo(2),
    fixClaimedAt: daysAgo(4),
    closedAt: daysAgo(2),
    slaDueAt: null,
  });
  await force(db, F.f10, {
    status: "verified_fixed",
    verifiedAt: daysAgo(5),
    fixClaimedAt: daysAgo(6),
    closedAt: daysAgo(5),
    reopenCount: 1,
    slaDueAt: null,
  });
  await force(db, F.f13, { status: "false_positive" });
  await force(db, F.g2, { status: "assigned", assigneeUserId: u2.id, assignedAt: new Date() });
  const review14 = await c.review(F.f14, { reviewerUserId: u1.id, state: "pending" });
  await force(db, F.f14, { status: "awaiting_approval", pendingReviewId: review14.id });
  const ex11 = await c.exception(F.f11, {
    state: "approved",
    decidedAt: new Date(),
    expiresAt: daysAhead(10),
  });
  await force(db, F.f11, {
    status: "accepted_risk",
    activeExceptionId: ex11.id,
    exceptionExpiresAt: daysAhead(10),
    acceptedSeverity: "high",
  });
  const ex12 = await c.exception(F.f12, {
    kind: "suppress",
    state: "approved",
    decidedAt: new Date(),
    expiresAt: daysAhead(60),
    acceptedSeverity: "low",
  });
  await force(db, F.f12, {
    status: "suppressed",
    activeExceptionId: ex12.id,
    exceptionExpiresAt: daysAhead(60),
    acceptedSeverity: "low",
  });

  // canaries in every excluded field (on findings of workspace 0)
  const canary = (label) => `${CANARY_TAG}-${label}`;
  await db.findingEvidence.create({
    data: {
      ...c.chainOf(F.f1),
      kind: "block",
      capturedExecutionId: randomUUID(),
      capturedAt: new Date(),
      snippet: canary("snippet"),
      scmRef: { blob: canary("scmref") },
      url: `https://example.test/${canary("url")}`,
    },
  });
  await c.review(F.f9, {
    reviewerUserId: u1.id,
    rationale: canary("rationale"),
    state: "approved",
    decision: "true_positive",
    decidedAt: daysAgo(14),
    createdAt: daysAgo(15),
  });
  await c.review(F.f10, {
    reviewerUserId: u1.id,
    state: "approved",
    decision: "true_positive",
    decidedAt: daysAgo(8),
    createdAt: daysAgo(9),
  });
  await c.review(F.f13, {
    reviewerUserId: u2.id,
    state: "approved",
    decision: "false_positive",
    decidedAt: daysAgo(7),
    createdAt: daysAgo(8),
  });
  await db.findingComment.create({
    data: { ...c.chainOf(F.f1), authorUserId: u1.id, body: canary("comment") },
  });
  await db.findingAiAdvisory.create({
    data: {
      ...c.chainOf(F.f1),
      inputHash: hex64(),
      status: "ok",
      suggestion: "likely_false_positive",
      confidence: 85,
      reasoning: canary("reasoning"),
      egressLevel: "metadata",
      provider: "ollama",
      model: "m",
    },
  });
  await c.exception(F.f3, {
    state: "pending",
    justification: canary("justification"),
    compensatingControls: canary("controls"),
  });

  // workspace 1: 20 approved decisions (14 false positive, 6 true positive), 10 with an advisory
  const decisions = [];
  for (let i = 0; i < 20; i += 1) {
    const f = await mk(pa1, {
      scanType: "sast",
      kind: "code_issue",
      severity: "medium",
      ruleId: "noisy.rule",
      firstDetectedAt: daysAgo(20),
    });
    const fp = i < 14;
    decisions.push({ f, fp, i });
  }
  // story: i 0..5 (human FP): advisory FP; i 14..15 (human TP): advisory TP; i 16 (human TP): advisory FP confident (override); i 6 (human FP): advisory uncertain
  const story = new Map([
    ...[0, 1, 2, 3, 4, 5].map((i) => [i, { suggestion: "likely_false_positive", confidence: 90 }]),
    ...[14, 15].map((i) => [i, { suggestion: "likely_true_positive", confidence: 90 }]),
    [16, { suggestion: "likely_false_positive", confidence: 90 }],
    [6, { suggestion: "uncertain", confidence: 40 }],
  ]);
  for (const d of decisions) {
    const s = story.get(d.i);
    let advisoryId = null;
    if (s) {
      const a = await db.findingAiAdvisory.create({
        data: {
          ...c.chainOf(d.f),
          inputHash: hex64(),
          status: "ok",
          suggestion: s.suggestion,
          confidence: s.confidence,
          reasoning: canary("reasoning-b"),
          egressLevel: "metadata",
          provider: "ollama",
          model: "m",
        },
      });
      advisoryId = a.id;
    }
    await c.review(d.f, {
      reviewerUserId: u1.id,
      state: "approved",
      decision: d.fp ? "false_positive" : "true_positive",
      decidedAt: daysAgo(3),
      createdAt: daysAgo(4),
      advisoryIdAtDecision: advisoryId,
    });
  }

  // tenant B: a finding in its workspace
  const fb = await mk(pb, {
    scanType: "sast",
    kind: "code_issue",
    severity: "critical",
    firstDetectedAt: daysAgo(10),
    slaStartedAt: daysAgo(10),
    slaDueAt: daysAhead(1),
  });

  // executions of workspace 0: p1 succeeded (latest), p1b failed, p2 failed (so repo 2 has no recent success)
  const run = async (p, status, started, extra = {}) => {
    const e = await c.execution(p.pipeline, p.version, { requestedAt: started, ...extra });
    await driveExecution(db, e.id, "running");
    await driveExecution(db, e.id, status);
    return e;
  };
  await run(p1, "succeeded", hoursAgo(30));
  await run(p1, "succeeded", hoursAgo(5));
  await run(p1b, "failed", hoursAgo(6));
  await run(p2, "failed", hoursAgo(7));

  // rollup rows and runs: days d3, d1, d0 covered; d2 has NO run (a gap)
  const d = (n) => dayOffset(n);
  const runRow = (tenantId, day, mode) =>
    db.$executeRaw`INSERT INTO report_rollup_runs (id, tenant_id, day, mode, status, started_at, finished_at, rows_written, time_zone)
      VALUES (${randomUUID()}::uuid, ${tenantId}::uuid, ${day}::date, ${mode}, 'succeeded', now() - interval '10 minutes', now() - interval '5 minutes', 1, 'UTC')`;
  await runRow(A.tenant.id, d(3), "close");
  await runRow(A.tenant.id, d(1), "close");
  await runRow(A.tenant.id, d(0), "incremental");
  const fday = (p, day, scanType, severity, v) =>
    db.$executeRaw`INSERT INTO report_daily_findings (tenant_id, workspace_id, repository_id, pipeline_id, day, scan_type, severity,
        open_count, backlog_count, wip_count, awaiting_verification_count, exceptions_in_force, new_count, fixed_count, closed_other_count, reopened_count)
      VALUES (${A.tenant.id}::uuid, ${wsA0}::uuid, ${p.pipeline.repositoryId}::uuid, ${p.pipeline.id}::uuid, ${day}::date, ${scanType}::finding_scan_type, ${severity}::finding_severity,
        ${v.open ?? 0}, ${v.backlog ?? v.open ?? 0}, ${v.wip ?? 0}, ${v.av ?? 0}, ${v.exc ?? 0}, ${v.new ?? 0}, ${v.fixed ?? 0}, ${v.closed ?? 0}, ${v.reopened ?? 0})`;
  await fday(p1, d(3), "sast", "critical", { open: 2, new: 2 });
  await fday(p1, d(1), "sast", "critical", { open: 3, new: 1 });
  await fday(p1, d(1), "sca", "high", { open: 1, closed: 1 });
  await fday(p1, d(0), "sast", "critical", { open: 3, fixed: 1 });
  const eday = (p, day, v) =>
    db.$executeRaw`INSERT INTO report_daily_executions (tenant_id, workspace_id, repository_id, pipeline_id, day, total, succeeded_count, failed_count, partial_count, eligible_count, result_complete_count, result_partial_count)
      VALUES (${A.tenant.id}::uuid, ${wsA0}::uuid, ${p.pipeline.repositoryId}::uuid, ${p.pipeline.id}::uuid, ${day}::date, ${v.total}, ${v.ok}, ${v.failed}, ${v.partial}, ${v.eligible}, ${v.complete}, ${v.incomplete})`;
  await eday(p1, d(1), {
    total: 5,
    ok: 3,
    failed: 1,
    partial: 1,
    eligible: 4,
    complete: 4,
    incomplete: 1,
  });
  await eday(p1b, d(0), {
    total: 2,
    ok: 1,
    failed: 1,
    partial: 0,
    eligible: 1,
    complete: 1,
    incomplete: 0,
  });
  await db.$executeRaw`INSERT INTO report_daily_sbom (tenant_id, workspace_id, repository_id, pipeline_id, day, components, components_vulnerable)
    VALUES (${A.tenant.id}::uuid, ${wsA0}::uuid, ${p1.pipeline.repositoryId}::uuid, ${p1.pipeline.id}::uuid, ${d(1)}::date, 120, 7)`;

  return {
    A,
    B,
    wsA0,
    wsA1,
    wsB0,
    F,
    fb,
    u1,
    u2,
    p1,
    p1b,
    p2,
    pa1,
    pb,
    repo2,
    tenantA: A.tenant.id,
    tenantB: B.tenant.id,
  };
}
