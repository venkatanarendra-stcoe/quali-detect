import { randomUUID } from "node:crypto";
import * as dbPackage from "@qmentisai/db";
import { buildAdvisoryInput, evaluateCoverage } from "@qmentisai/shared";
import {
  createConcurrencyLimiter,
  runAdvisory,
} from "../../../../../workers/src/findings-agent/index.js";
import { createFindingsIngestHandler } from "../../../../../workers/src/findings/handler.js";
import { findingsRoutes } from "../../../../src/modules/findings/routes/index.js";
import { createExceptionExpiryHandler } from "../../../../../workers/src/findings/expiry.js";
import { PERMS, makeUser, startWriteApi } from "./findings-b-fixtures.js";
import {
  at,
  handlerConfig,
  ingest,
  runExecution,
  sast,
  scenario,
  secret,
} from "./findings-a-fixtures.js";

/**
 * Findings checks of part F (cross-cutting sweep) (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1, 16.2): the checks no building part
 * owns. They are written as SWEEPS over an enumeration, so a route or a repository function added later cannot ship without being
 * classified here and swept:
 *  - `FND-S01c` the route manifest (every findings route, its permission, scope, rate limit, idempotency, params schema; nothing under
 *    `/platform`), compared with the REAL router registered on a recorder, with planted-deviation controls;
 *  - `FND-S01d` the cross-tenant, cross-workspace and permission sweep over EVERY route of the manifest on the real HTTP stack: another
 *    tenant's finding, a hidden workspace and an unknown id answer one identical 404, a visible resource without the key is 403, a denial
 *    writes nothing, the legitimate call is never a 404 (the control); the bulk calls report a foreign finding as not found, never forbidden;
 *  - `FND-S16b` an archived workspace refuses EVERY workspace write route of the manifest (part B proved its own routes), reads still work,
 *    and the restored workspace writes again;
 *  - `FND-S18` every function of the findings repositories is classified (the "every function has a check" rule: a new function fails
 *    until it names the check that covers it) and every tenant-owned query carries the tenant.
 * Every denial has a control (the same call made legitimately is not refused) so a check cannot pass vacuously.
 *
 * A check is `{ id, name, run }`. `run(c)` receives the findings world (`findings-world.js`: the pipeline-db tenants A and B plus finding
 * factories) and returns the list of problems (empty means it passed).
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const j = (v) => JSON.stringify(v);
const eq = (p, label, got, want) => {
  if (j(got) !== j(want)) p.push(`${label}: got ${j(got)}, want ${j(want)}`);
};
const DAY = 86_400_000;
const RATIONALE = "Reachable from user input; confirmed by reading the handler and the call site.";
const JUSTIFICATION = "The code path is behind an internal-only gateway until the next quarter.";

/** Every permission key a findings route asks for (the "full" principal of the sweep holds them all). */
const ALL_KEYS = Object.freeze([
  "finding.view",
  "finding.comment",
  "finding.review",
  "security_review.view",
  "approval.view",
  "approval.approve",
  "approval.reject",
  "finding.accept_risk",
  "finding.suppress",
  "finding.assign",
  "finding.remediate",
  "remediation.view",
]);

// ---------------------------------------------------------------------------------------------------------------------------------
// The route manifest. A row is [method, path, permission, rate limit, idempotent, params schema, handler, scope kind, probe].
// The scope kind says where the workspace comes from: `params` (the finding is loaded by tenant and id, then authorized in ITS workspace),
// `query` (the workspace named in the query), `body` (named in the body), `by-kind-gate` (the exception request: a gate that picks the
// accept-risk or suppression key from the validated body, then the params scope), `tenant` (a tenant setting, no workspace).
// `probe(e)` builds the call for an entity set `e` (the real finding, review and exception of one workspace).
// ---------------------------------------------------------------------------------------------------------------------------------

const REV = (n) => ({ expectedRev: n });
/** @type {ReadonlyArray<{ method: string, path: string, permission: string, rateLimit: string, idempotent: boolean, params: boolean, handler: string, scope: string, probe: (e: any) => { path: string, body?: any } }>} */
export const FINDINGS_ROUTE_MANIFEST = Object.freeze(
  [
    [
      "GET",
      "/findings",
      "finding.view",
      "read",
      false,
      false,
      "list",
      "query",
      (e) => ({ path: `/findings?workspaceId=${e.ws}` }),
    ],
    [
      "GET",
      "/findings/summary",
      "finding.view",
      "read",
      false,
      false,
      "summary",
      "query",
      (e) => ({ path: `/findings/summary?workspaceId=${e.ws}` }),
    ],
    [
      "GET",
      "/findings/:id",
      "finding.view",
      "read",
      false,
      true,
      "get",
      "params",
      (e) => ({ path: `/findings/${e.f.id}` }),
    ],
    [
      "GET",
      "/findings/:id/history",
      "finding.view",
      "read",
      false,
      true,
      "history",
      "params",
      (e) => ({ path: `/findings/${e.f.id}/history` }),
    ],
    [
      "GET",
      "/findings/:id/comments",
      "finding.view",
      "read",
      false,
      true,
      "comments",
      "params",
      (e) => ({ path: `/findings/${e.f.id}/comments` }),
    ],
    [
      "GET",
      "/findings/:id/similar",
      "finding.view",
      "read",
      false,
      true,
      "similar",
      "params",
      (e) => ({ path: `/findings/${e.f.id}/similar` }),
    ],
    [
      "GET",
      "/review-queue",
      "security_review.view",
      "read",
      false,
      false,
      "reviewQueue",
      "query",
      (e) => ({ path: `/review-queue?workspaceId=${e.ws}` }),
    ],
    [
      "POST",
      "/findings/bulk/claim",
      "finding.review",
      "write",
      true,
      false,
      "bulkClaim",
      "body",
      (e) => ({ path: "/findings/bulk/claim", body: { workspaceId: e.ws, findingIds: [e.f.id] } }),
    ],
    [
      "POST",
      "/findings/:id/claim",
      "finding.review",
      "write",
      true,
      true,
      "claim",
      "params",
      (e) => ({ path: `/findings/${e.f.id}/claim`, body: REV(0) }),
    ],
    [
      "POST",
      "/findings/:id/reviews",
      "finding.review",
      "write",
      true,
      true,
      "createReview",
      "params",
      (e) => ({
        path: `/findings/${e.f.id}/reviews`,
        body: { decision: "true_positive", rationale: RATIONALE, expectedRev: 0 },
      }),
    ],
    [
      "POST",
      "/findings/:id/reviews/:reviewId/withdraw",
      "finding.review",
      "write",
      true,
      true,
      "withdrawReview",
      "params",
      (e) => ({ path: `/findings/${e.r.f.id}/reviews/${e.r.reviewId}/withdraw`, body: REV(1) }),
    ],
    [
      "POST",
      "/findings/:id/reopen-review",
      "finding.review",
      "write",
      true,
      true,
      "reopenReview",
      "params",
      (e) => ({
        path: `/findings/${e.f.id}/reopen-review`,
        body: { reason: "Look again.", expectedRev: 0 },
      }),
    ],
    [
      "POST",
      "/findings/:id/comments",
      "finding.comment",
      "write",
      true,
      true,
      "addComment",
      "params",
      (e) => ({ path: `/findings/${e.f.id}/comments`, body: { body: "A note." } }),
    ],
    [
      "GET",
      "/approvals",
      "approval.view",
      "read",
      false,
      false,
      "approvals",
      "query",
      (e) => ({ path: `/approvals?workspaceId=${e.ws}` }),
    ],
    [
      "POST",
      "/findings/:id/reviews/:reviewId/approve",
      "approval.approve",
      "write",
      true,
      true,
      "approveReview",
      "params",
      (e) => ({ path: `/findings/${e.r.f.id}/reviews/${e.r.reviewId}/approve`, body: REV(1) }),
    ],
    [
      "POST",
      "/findings/:id/reviews/:reviewId/reject",
      "approval.reject",
      "write",
      true,
      true,
      "rejectReview",
      "params",
      (e) => ({
        path: `/findings/${e.r.f.id}/reviews/${e.r.reviewId}/reject`,
        body: { comment: "No.", expectedRev: 1 },
      }),
    ],
    [
      "POST",
      "/findings/:id/exceptions",
      "finding.accept_risk",
      "write",
      true,
      true,
      "request",
      "by-kind-gate",
      (e) => ({
        path: `/findings/${e.f.id}/exceptions`,
        body: {
          kind: "accept_risk",
          justification: JUSTIFICATION,
          expiresAt: new Date(Date.now() + 30 * DAY).toISOString(),
          expectedRev: 0,
        },
      }),
    ],
    [
      "POST",
      "/findings/:id/exceptions/:exceptionId/withdraw",
      "finding.view",
      "write",
      true,
      true,
      "withdraw",
      "params",
      (e) => ({ path: `/findings/${e.x.f.id}/exceptions/${e.x.exceptionId}/withdraw`, body: {} }),
    ],
    [
      "POST",
      "/findings/:id/exceptions/:exceptionId/approve",
      "approval.approve",
      "write",
      true,
      true,
      "approve",
      "params",
      (e) => ({
        path: `/findings/${e.x.f.id}/exceptions/${e.x.exceptionId}/approve`,
        body: REV(1),
      }),
    ],
    [
      "POST",
      "/findings/:id/exceptions/:exceptionId/reject",
      "approval.reject",
      "write",
      true,
      true,
      "reject",
      "params",
      (e) => ({
        path: `/findings/${e.x.f.id}/exceptions/${e.x.exceptionId}/reject`,
        body: { comment: "No.", expectedRev: 1 },
      }),
    ],
    [
      "POST",
      "/findings/:id/exceptions/:exceptionId/revoke",
      "finding.view",
      "write",
      true,
      true,
      "revoke",
      "params",
      (e) => ({
        path: `/findings/${e.x.f.id}/exceptions/${e.x.exceptionId}/revoke`,
        body: { reason: "No longer true.", expectedRev: 1 },
      }),
    ],
    [
      "GET",
      "/remediation/board",
      "remediation.view",
      "read",
      false,
      false,
      "board",
      "query",
      (e) => ({ path: `/remediation/board?workspaceId=${e.ws}` }),
    ],
    [
      "GET",
      "/remediation/board/:column",
      "remediation.view",
      "read",
      false,
      true,
      "boardColumn",
      "query",
      (e) => ({ path: `/remediation/board/assigned?workspaceId=${e.ws}` }),
    ],
    [
      "POST",
      "/findings/bulk/assign",
      "finding.assign",
      "write",
      true,
      false,
      "bulkAssign",
      "body",
      (e) => ({
        path: "/findings/bulk/assign",
        body: { workspaceId: e.ws, findingIds: [e.f.id], assigneeUserId: e.dev },
      }),
    ],
    [
      "POST",
      "/findings/:id/assignments",
      "finding.assign",
      "write",
      true,
      true,
      "assign",
      "params",
      (e) => ({
        path: `/findings/${e.f.id}/assignments`,
        body: { assigneeUserId: e.dev, expectedRev: 0 },
      }),
    ],
    [
      "POST",
      "/findings/:id/assignments/clear",
      "finding.assign",
      "write",
      true,
      true,
      "clear",
      "params",
      (e) => ({ path: `/findings/${e.f.id}/assignments/clear`, body: REV(0) }),
    ],
    [
      "POST",
      "/findings/:id/remediation/start",
      "finding.remediate",
      "write",
      true,
      true,
      "start",
      "params",
      (e) => ({ path: `/findings/${e.f.id}/remediation/start`, body: REV(0) }),
    ],
    [
      "POST",
      "/findings/:id/remediation/submit",
      "finding.remediate",
      "write",
      true,
      true,
      "submit",
      "params",
      (e) => ({ path: `/findings/${e.f.id}/remediation/submit`, body: REV(0) }),
    ],
    [
      "GET",
      "/settings/findings-sla",
      "tenant_settings.view",
      "read",
      false,
      false,
      "get",
      "tenant",
      () => ({ path: "/settings/findings-sla" }),
    ],
    [
      "PUT",
      "/settings/findings-sla",
      "tenant_settings.manage",
      "write",
      false,
      false,
      "put",
      "tenant",
      () => ({
        path: "/settings/findings-sla",
        body: { targets: [{ severity: "high", hours: 720 }] },
      }),
    ],
    [
      "POST",
      "/findings/:id/advisory/request",
      "finding.review",
      "write",
      true,
      true,
      "request",
      "params",
      (e) => ({ path: `/findings/${e.f.id}/advisory/request`, body: {} }),
    ],
  ].map(([method, path, permission, rateLimit, idempotent, params, handler, scope, probe]) =>
    Object.freeze({
      method,
      path,
      permission,
      rateLimit,
      idempotent,
      params,
      handler,
      scope,
      probe,
    }),
  ),
);

/** Records the routes the REAL findings router registers (the same recorder idea as EXE-073) and what each gate was built with. */
async function recordRoutes() {
  const recorded = [];
  const app = {};
  for (const method of ["get", "post", "put", "patch", "delete"])
    app[method] = (path, options, handler) =>
      recorded.push({ method: method.toUpperCase(), path, options, handler });
  const authz = {
    context: Object.assign(function context() {}, { permission: null }),
    authorize: (permission, scope) => Object.assign(function guard() {}, { permission, scope }),
    scopes: {},
  };
  const stub = new Proxy(
    {},
    {
      get: () => () => {
        throw new Error("no data access while registering");
      },
    },
  );
  await findingsRoutes({
    db: stub,
    authz,
    audit: null,
    outbox: null,
    entitlements: null,
    config: {},
    log: console,
  })(app);
  return recorded;
}

/** Where a route's workspace comes from, read from the resolver the route was built with (not from its name). */
function scopeKindOf(route) {
  const scope = route.options.preHandler?.scope;
  if (!scope) return route.path.startsWith("/settings") ? "tenant" : "by-kind-gate";
  const src = String(scope.resolve);
  if (src.includes("request.query")) return "query";
  if (src.includes("request.body")) return "body";
  if (src.includes("request.params")) return "params";
  return "unknown";
}

/**
 * Compares the recorded routes with a manifest. Pure, so a planted deviation proves the comparison can fail.
 * @param {any[]} routes @param {ReadonlyArray<any>} manifest @returns {string[]}
 */
export function routeManifestProblems(routes, manifest) {
  const p = [];
  const key = (r) => `${r.method} ${r.path}`;
  const want = manifest.map(key).sort();
  const got = routes.map(key).sort();
  eq(p, "the routes the findings router registers equal the manifest", got, want);
  for (const route of routes) {
    const row = manifest.find((r) => r.method === route.method && r.path === route.path);
    if (!row) continue;
    const label = key(route);
    ok(p, route.options.config?.audience === "tenant", `${label}: not a tenant-audience route`);
    ok(p, !route.path.includes("/platform"), `${label}: a finding route under /platform`);
    eq(p, `${label}: permission`, route.options.preHandler?.permission ?? null, row.permission);
    eq(p, `${label}: rate limit`, route.options.rateLimit ?? null, row.rateLimit);
    eq(p, `${label}: idempotent`, Boolean(route.options.idempotent), row.idempotent);
    eq(p, `${label}: params schema`, Boolean(route.options.schema?.params), row.params);
    eq(p, `${label}: handler`, route.handler?.name, row.handler);
    eq(p, `${label}: workspace scope`, scopeKindOf(route), row.scope);
    // every write has the write limit and a read has the read limit; a write that creates takes an idempotency key (the only exception
    // is the naturally idempotent PUT of the SLA targets)
    const write = route.method !== "GET";
    eq(
      p,
      `${label}: limit profile follows the method`,
      route.options.rateLimit,
      write ? "write" : "read",
    );
    if (write && route.method === "POST")
      ok(p, route.options.idempotent === true, `${label}: a POST without an idempotency key`);
    ok(p, Boolean(route.options.schema), `${label}: no validation schema`);
  }
  return p;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The sweep world
// ---------------------------------------------------------------------------------------------------------------------------------

/** The body of an error answer without the per-request correlation id (what must be identical across the three kinds of 404). */
const stripped = (r) =>
  j({ status: r.status, error: r.json?.error ?? null, success: r.json?.success });

/** Builds (once) the API, the principals and the entities the sweeps share. */
export function fWorld(c) {
  c.__fndF ??= (async () => {
    const { db, A, B } = c;
    const wsA = A.ws[0].id;
    const wsA2 = A.ws[1].id;
    const wsB = B.ws[0].id;
    const pipeA = await c.pipeline(A, 0);
    const pipeA2 = await c.pipeline(A, 1);
    const pipeB = await c.pipeline(B, 0);
    const api = await startWriteApi(db);
    const users = {};
    const reg = async (name, perms, tree = A, ws = wsA, tenantPermissions = []) => {
      const u = await makeUser(db, tree, name);
      users[name] = u.id;
      api.register(name, {
        userId: u.id,
        tenantId: tree.tenant.id,
        workspaces: [{ id: ws, permissions: perms }],
        tenantPermissions,
      });
    };
    const settingsKeys = ["tenant_settings.view", "tenant_settings.manage"];
    await reg("fFull", ALL_KEYS, A, wsA, settingsKeys);
    await reg("fAnalyst", PERMS.analyst);
    await reg("fDev", PERMS.developer);
    await reg("fViewer", ["finding.view"]);
    await reg("fNoView", []);
    await reg("fFullB", ALL_KEYS, B, wsB, settingsKeys);
    await reg("fFull2", ALL_KEYS, A, wsA2); // sees ONLY the second workspace of tenant A: the "hidden workspace" of the first
    await reg("fAnalyst2", PERMS.analyst, A, wsA2);
    await reg("fDev2", PERMS.developer, A, wsA2);
    const row = (f) =>
      db.finding.findUnique({ where: { tenantId_id: { tenantId: f.tenantId, id: f.id } } });
    /** One finding, one with a pending review and one with a pending exception request, made through the real API. */
    const entities = async (ws, pipe, analyst, dev) => {
      const f = await c.finding(pipe);
      const rf = await c.finding(pipe);
      const rr = await api.post(analyst, `/findings/${rf.id}/reviews`, {
        decision: "true_positive",
        rationale: RATIONALE,
        expectedRev: 0,
      });
      if (rr.status !== 201)
        throw new Error(`the review of the sweep world answered ${rr.status} ${j(rr.json)}`);
      const xf = await c.finding(pipe);
      const xr = await api.post(analyst, `/findings/${xf.id}/exceptions`, {
        kind: "accept_risk",
        justification: JUSTIFICATION,
        expiresAt: new Date(Date.now() + 30 * DAY).toISOString(),
        expectedRev: 0,
      });
      if (xr.status !== 201)
        throw new Error(`the exception of the sweep world answered ${xr.status} ${j(xr.json)}`);
      return {
        ws,
        f,
        dev: users[dev],
        r: { f: rf, reviewId: rr.json.data.review.current.id },
        x: { f: xf, exceptionId: xr.json.data.exception.id },
      };
    };
    const eA = await entities(wsA, pipeA, "fAnalyst", "fDev");
    const eA2 = await entities(wsA2, pipeA2, "fAnalyst2", "fDev2");
    const foreign = await c.finding(pipeB);
    return { c, db, A, B, wsA, wsA2, wsB, api, users, row, eA, eA2, foreign };
  })();
  return c.__fndF;
}

/** The same call with the ids of a resource that does not exist (the finding, or the workspace for the collection and bulk routes). */
function unknownVariant(row, e) {
  const nowhere = randomUUID();
  if (row.scope === "query" || row.scope === "body") return { ...e, ws: nowhere };
  return {
    ...e,
    f: { ...e.f, id: nowhere },
    r: { ...e.r, f: { ...e.r.f, id: nowhere } },
    x: { ...e.x, f: { ...e.x.f, id: nowhere } },
  };
}

/** A fingerprint of everything the denial phase must not change: revisions, history, audit and outbox of both tenants. */
async function stateOf(w) {
  const { db } = w;
  const revs = [];
  for (const e of [w.eA, w.eA2])
    for (const f of [e.f, e.r.f, e.x.f]) revs.push((await w.row(f)).rev);
  const count = async (table, extra = "") =>
    (await db.$queryRawUnsafe(`SELECT count(*)::int AS n FROM ${table} ${extra}`))[0].n;
  return j([
    revs,
    await count("finding_status_history"),
    await count("finding_reviews"),
    await count("finding_exceptions"),
    await count("finding_comments"),
    await count("audit_logs", "WHERE action LIKE 'finding.%'"),
    await count("outbox_messages", "WHERE type LIKE 'finding.%'"),
  ]);
}

const isAbsent = (r) => r.status === 404 && r.json?.error?.code === "RESOURCE_NOT_FOUND";

// ---------------------------------------------------------------------------------------------------------------------------------
// FND-S18: the repository functions
// ---------------------------------------------------------------------------------------------------------------------------------

/** Each repository function and the checks that exercise it. A new function must be added here, with a check that covers it. */
const REPOSITORY_COVERAGE = Object.freeze({
  "createFindingsRepository.list": ["FND-S13a", "FND-S01a"],
  "createFindingsRepository.hydrate": ["FND-S07c"],
  "createFindingsRepository.summary": ["FND-S13b", "FND-S01a"],
  "createFindingsRepository.getDetail": ["FND-S12", "FND-S01b"],
  "createFindingsRepository.getForWrite": ["FND-S08a"],
  "createFindingsRepository.history": ["FND-S12", "FND-S01b"],
  "createFindingsRepository.comments": ["FND-S12", "FND-S01b"],
  "createFindingsRepository.similar": ["FND-S12", "FND-S01b"],
  "createFindingsRepository.reviewQueue": ["FND-S02b"],
  "createFindingsIngestionRepository.loadExecutionFacts": ["FND-S06a", "FND-S03"],
  "createFindingsIngestionRepository.loadObservedItems": ["FND-S05a"],
  "createFindingsIngestionRepository.loadExisting": ["FND-S05a", "FND-S03"],
  "createFindingsIngestionRepository.lockAndCheck": ["FND-S05a"],
  "createFindingsIngestionRepository.recordFailure": ["FND-S05a"],
  "createFindingsIngestionRepository.applyPlan": ["FND-S05b", "FND-S06b"],
  "createFindingsAgentRepository.getFindingForAdvisory": ["FPA-I01", "FPA-I06"],
  "createFindingsAgentRepository.readConsent": ["FPA-I03"],
  "createFindingsAgentRepository.findAdvisoryByHash": ["FPA-I01"],
  "createFindingsAgentRepository.countAdvisoriesSince": ["FPA-I01"],
  "createFindingsAgentRepository.insertAdvisory": ["FPA-I01"],
  "createFindingReviewsRepository.claim": ["FND-S08a"],
  "createFindingReviewsRepository.record": ["FND-S07a", "FND-S08b"],
  "createFindingReviewsRepository.withdraw": ["FND-S07a"],
  "createFindingReviewsRepository.decide": ["FND-S07a", "FND-S08a"],
  "createFindingReviewsRepository.reopenForReview": ["FND-S08b"],
  "createFindingReviewsRepository.reviewerIds": ["FND-S07a"],
  "createFindingReviewsRepository.sodBlockedIds": ["FND-S07c"],
  "createFindingReviewsRepository.pendingApprovals": ["FND-S02b"],
  "createFindingReviewsRepository.addComment": ["FND-S10a"],
  "createFindingExceptionsRepository.request": ["FND-S09a"],
  "createFindingExceptionsRepository.withdraw": ["FND-S09a"],
  "createFindingExceptionsRepository.decide": ["FND-S07b", "FND-S09a"],
  "createFindingExceptionsRepository.end": ["FND-S09a", "FND-S09b"],
  "createFindingExceptionsRepository.revoke": ["FND-S09a"],
  "createFindingExceptionsRepository.expireIfDue": ["FND-S09b"],
  "createFindingExceptionsRepository.dueForExpiry": ["FND-S09b"],
  "createFindingExceptionsRepository.expireDue": ["FND-S09b"],
  "createFindingAssignmentsRepository.assign": ["FND-S08c"],
  "createFindingAssignmentsRepository.clear": ["FND-S08c"],
  "createFindingAssignmentsRepository.board": ["FND-S12c"],
  "createFindingAssignmentsRepository.boardCounts": ["FND-S12c"],
  "createFindingAssignmentsRepository.readSlaTargets": ["FND-S14c"],
  "createFindingAssignmentsRepository.writeSlaTargets": ["FND-S14c"],
  "createFindingAssignmentsRepository.dueForSweep": ["FND-S14b"],
  "createFindingAssignmentsRepository.notifySla": ["FND-S14b"],
  "createFindingRemediationRepository.record": ["FND-S08d"],
  "createFindingRemediationRepository.verifications": ["FND-S06b"],
  "createFindingAdvisoriesRepository.latest": ["FND-S12d"],
  "createFindingAdvisoriesRepository.latestFor": ["FND-S12d", "FPA-I05"],
  "createFindingAdvisoriesRepository.requestAllowed": ["FPA-I04"],
  "createFindingAdvisoriesRepository.transaction": ["FPA-I04"],
  "createFindingAdvisoriesRepository.lockForRequest": ["FPA-I04"],
  "createFindingAdvisoriesRepository.workspaceStatus": ["FND-S16b"],
  "createFindingAdvisoriesRepository.enqueueManual": ["FPA-I04"],
});

/**
 * Functions whose own source does not name the tenant because they only delegate to a function that does (the tenant stays an argument of
 * the delegate), with the reason. Every other function must name `tenantId` in its source.
 */
const TENANT_BY_DELEGATION = Object.freeze({
  "createFindingsRepository.list": "builds its where clause through the scoped list helper",
  "createFindingsRepository.hydrate": "maps rows already loaded under a tenant scope",
  "createFindingsRepository.reviewQueue":
    "calls list with the queue's fixed filter and the caller's scope",
  "createFindingAssignmentsRepository.boardCounts": "a helper of board, called with the same scope",
  "createFindingReviewsRepository.reopenForReview": "calls the transition function with the scope",
  "createFindingReviewsRepository.addComment": "calls the comment writer with the scope",
  "createFindingExceptionsRepository.revoke": "calls end with the scope",
  "createFindingAdvisoriesRepository.latest": "calls latestFor with the scope",
  "createFindingAdvisoriesRepository.requestAllowed": "calls the counting helper with the scope",
  "createFindingAdvisoriesRepository.transaction": "opens a transaction, no data access",
});

/**
 * Compares the enumerated repository functions with the coverage table. Pure, for the planted controls.
 * @param {Record<string, { tenant: boolean }>} found @param {Record<string, string[]>} coverage @param {Set<string>} knownChecks
 */
export function repositoryProblems(
  found,
  coverage,
  knownChecks,
  delegation = TENANT_BY_DELEGATION,
) {
  const p = [];
  for (const [name, info] of Object.entries(found)) {
    ok(
      p,
      name in coverage,
      `${name} has no entry in the coverage table (name the check that covers it)`,
    );
    ok(
      p,
      info.tenant || name in delegation,
      `${name} does not name the tenant and is not a recorded delegation`,
    );
    if (info.tenant)
      ok(
        p,
        !(name in delegation),
        `${name} names the tenant but is also listed as a delegation: remove it from the table`,
      );
  }
  for (const [name, ids] of Object.entries(coverage)) {
    ok(p, name in found, `the coverage table names ${name}, which no longer exists`);
    ok(p, ids.length > 0, `${name} names no covering check`);
    for (const id of ids)
      ok(p, knownChecks.has(id), `${name} names the check ${id}, which is not registered`);
  }
  return p;
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------------------------------------------------------------

export const FINDINGS_F_CHECKS = [
  {
    id: "FND-S01c",
    name: "every findings route is enumerated with its authorization (SPEC 14.1 FND-S01, part F): the REAL findings router is registered against a recorder and must equal the manifest exactly (method, path, tenant audience, the central permission, the workspace scope read from the resolver the route was built with, rate limit profile, idempotency, params schema, handler) so a new route cannot ship without being classified and swept by FND-S01d and FND-S16b; every route has a validation schema, every write the write limit and every POST an idempotency key, every read the read limit, and no finding route sits under /platform; planted deviations (a missing route, an extra route, a changed permission, a dropped idempotency flag, a route under /platform, a changed scope) are each reported",
    async run() {
      const p = [];
      const routes = await recordRoutes();
      p.push(...routeManifestProblems(routes, FINDINGS_ROUTE_MANIFEST));
      ok(
        p,
        routes.length === 31 && FINDINGS_ROUTE_MANIFEST.length === 31,
        `control: ${routes.length} routes and ${FINDINGS_ROUTE_MANIFEST.length} manifest rows`,
      );
      ok(
        p,
        new Set(FINDINGS_ROUTE_MANIFEST.map((r) => `${r.method} ${r.path}`)).size === 31,
        "the manifest lists a route twice",
      );
      // negative controls: the comparison must fail on each planted deviation
      const clone = (r) => ({ ...r, options: { ...r.options, schema: { ...r.options.schema } } });
      const plant = (label, mutate, expectSub) => {
        const copy = routes.map(clone);
        const manifest = [...FINDINGS_ROUTE_MANIFEST];
        mutate(copy, manifest);
        const found = routeManifestProblems(copy, manifest);
        ok(
          p,
          found.some((m) => m.includes(expectSub)),
          `negative control "${label}" was not reported (${j(found.slice(0, 2))})`,
        );
      };
      plant("a route missing from the router", (rs) => rs.pop(), "equal the manifest");
      plant(
        "an extra route",
        (rs) => rs.push({ ...rs[0], path: "/findings/extra" }),
        "equal the manifest",
      );
      plant(
        "a changed permission",
        (rs) => {
          rs[1].options.preHandler = Object.assign(function guard() {}, {
            permission: "finding.comment",
            scope: rs[1].options.preHandler.scope,
          });
        },
        "permission",
      );
      plant(
        "a dropped idempotency flag",
        (rs) => {
          rs.find((r) => r.method === "POST").options.idempotent = false;
        },
        "idempotent",
      );
      plant(
        "a route under /platform",
        (rs) => {
          rs[0].path = "/platform/findings";
          rs[0].method = "GET";
        },
        "/platform",
      );
      plant(
        "a changed scope",
        (rs) => {
          rs[2].options.preHandler = Object.assign(function guard() {}, {
            permission: "finding.view",
            scope: { resolve: "request.query" },
          });
        },
        "workspace scope",
      );
      plant(
        "a write on the read limit",
        (rs) => {
          rs.find((r) => r.method === "POST").options.rateLimit = "read";
        },
        "rate limit",
      );
      return p;
    },
  },
  {
    id: "FND-S01d",
    name: "cross-tenant, cross-workspace and permission sweep over EVERY findings route of the manifest on the real HTTP stack (SPEC 14.1 FND-S01, FND-S02, FS-1, FS-2, part F): for each route, another tenant's finding (or workspace), a workspace the caller cannot see and an unknown id answer ONE identical 404 RESOURCE_NOT_FOUND (the same error body, valid request bodies throughout), a visible resource without the route's key is 403, the whole denial phase writes nothing (revisions, history, reviews, exceptions, comments, audit and outbox unchanged), and the legitimate call by a principal holding every key is never a 404 (the control); the two bulk routes report another tenant's finding inside an own workspace as a per-item RESOURCE_NOT_FOUND and never as forbidden, and leave it untouched; the SLA settings routes answer 403 without their tenant key",
    async run(c) {
      const p = [];
      const w = await fWorld(c);
      const { api, eA } = w;
      const before = await stateOf(w);
      for (const row of FINDINGS_ROUTE_MANIFEST) {
        const label = `${row.method} ${row.path}`;
        const call = (name, e) => {
          const { path, body } = row.probe(e);
          return api[row.method.toLowerCase()](name, path, body);
        };
        if (row.scope === "tenant") {
          const denied = await call("fViewer", eA);
          eq(
            p,
            `${label}: without the tenant key`,
            [denied.status, denied.json?.error?.code],
            [403, "FORBIDDEN"],
          );
          continue;
        }
        const baseline = await call("fFull", unknownVariant(row, eA));
        ok(
          p,
          isAbsent(baseline),
          `${label}: an unknown id answered ${baseline.status} ${baseline.json?.error?.code}`,
        );
        const foreign = await call("fFullB", eA);
        eq(
          p,
          `${label}: another tenant's resource equals the unknown id`,
          stripped(foreign),
          stripped(baseline),
        );
        const hidden = await call("fFull2", eA);
        eq(
          p,
          `${label}: a workspace the caller cannot see equals the unknown id`,
          stripped(hidden),
          stripped(baseline),
        );
        const lacking = row.permission === "finding.view" ? "fNoView" : "fViewer";
        const denied = await call(lacking, eA);
        eq(
          p,
          `${label}: a visible resource without ${row.permission}`,
          [denied.status, denied.json?.error?.code],
          [403, "FORBIDDEN"],
        );
      }
      eq(p, "the denial phase wrote nothing", await stateOf(w), before);
      // the bulk routes: another tenant's finding named inside an own workspace is a per-item not found, never forbidden, never touched
      const foreignBefore = j(await w.row(w.foreign));
      for (const path of ["/findings/bulk/claim", "/findings/bulk/assign"]) {
        const body = {
          workspaceId: w.wsA,
          findingIds: [w.foreign.id, randomUUID()],
          ...(path.endsWith("assign") ? { assigneeUserId: eA.dev } : {}),
        };
        const r = await api.post("fFull", path, body);
        eq(p, `${path} with a foreign finding: status`, r.status, 200);
        const items = r.json?.data?.results ?? [];
        eq(
          p,
          `${path} with a foreign finding: per-item results`,
          items.map((i) => [i.ok, i.errorCode]),
          [
            [false, "RESOURCE_NOT_FOUND"],
            [false, "RESOURCE_NOT_FOUND"],
          ],
        );
      }
      eq(
        p,
        "the foreign finding was not touched by the bulk calls",
        j(await w.row(w.foreign)),
        foreignBefore,
      );
      // controls: the legitimate call is never "not found" (a read is 200), so the 404 above is the scope and not a blanket answer
      for (const row of FINDINGS_ROUTE_MANIFEST) {
        const { path, body } = row.probe(eA);
        const r = await api[row.method.toLowerCase()]("fFull", path, body);
        const label = `${row.method} ${row.path}`;
        ok(
          p,
          r.status !== 404 && r.status !== 401 && r.status < 500,
          `control ${label}: the legitimate call answered ${r.status} ${r.json?.error?.code ?? ""}`,
        );
        if (row.method === "GET") eq(p, `control ${label}: a read`, r.status, 200);
      }
      return p;
    },
  },
  {
    id: "FND-S16b",
    name: "an archived workspace refuses EVERY workspace write route of the manifest (SPEC 14.1 FND-S16, AUTHORIZATION 5.7, part F; part B proved its own routes): with the workspace archived, each of the 19 workspace write routes (reviews, approvals, exceptions, comments, assignment, remediation, the bulk calls and the advisory request, D-F1 fixed 2026-11-24) answers 409 CONFLICT workspace_archived for a principal holding every key, and nothing changes (revisions, history, reviews, exceptions, comments, audit, outbox: no job queued and no audit entry for the advisory request); the advisory request of the restored, non-archived workspace is accepted (202, the control); the reads of the same workspace still answer 200 by permission; the restored workspace writes again (the control)",
    async run(c) {
      const p = [];
      const w = await fWorld(c);
      const { api, eA2 } = w;
      const writes = FINDINGS_ROUTE_MANIFEST.filter(
        (r) => r.method !== "GET" && r.scope !== "tenant",
      );
      ok(
        p,
        writes.length === 19,
        `control: ${writes.length} workspace write routes in the manifest`,
      );
      const before = await stateOf(w);
      // the agent is ON for this check, so an advisory request that was not refused WOULD queue an outbox job and write an audit entry
      // (with the agent off the request answers `not_configured` and writes nothing: the "nothing written" proof would be vacuous)
      const agentWas = process.env.FINDINGS_AGENT_ENABLED;
      process.env.FINDINGS_AGENT_ENABLED = "true";
      await w.db.workspace.update({
        where: { id: w.wsA2 },
        data: { status: "archived", archivedAt: new Date() },
      });
      try {
        for (const row of writes) {
          const { path, body } = row.probe(eA2);
          const r = await api.post("fFull2", path, body);
          const label = `${row.method} ${row.path}`;
          if (row.scope === "body") {
            // a bulk call answers per item; every item is refused with the same conflict
            const items = r.json?.data?.results ?? [];
            eq(
              p,
              `${label}: archived workspace (per item)`,
              [r.status, items.map((i) => [i.ok, i.errorCode, i.reason])],
              [200, [[false, "CONFLICT", "workspace_archived"]]],
            );
          } else {
            eq(
              p,
              `${label}: archived workspace`,
              [r.status, r.json?.error?.code, r.json?.error?.details?.reason],
              [409, "CONFLICT", "workspace_archived"],
            );
          }
        }
        // D-F1 fixed 2026-11-24: the advisory request is refused like every other write, so NOTHING changed, the outbox and the audit log
        // included (stateOf covers revisions, history, reviews, exceptions, comments, audit and outbox)
        eq(
          p,
          "an archived workspace changed nothing (no outbox row, no audit row)",
          await stateOf(w),
          before,
        );
        for (const row of FINDINGS_ROUTE_MANIFEST.filter(
          (r) => r.method === "GET" && r.scope !== "tenant",
        )) {
          const { path } = row.probe(eA2);
          const r = await api.get("fFull2", path);
          eq(p, `GET ${row.path} in an archived workspace`, r.status, 200);
        }
      } finally {
        await w.db.workspace.update({
          where: { id: w.wsA2 },
          data: { status: "active", archivedAt: null },
        });
      }
      try {
        // control (D-F1): the same advisory request in the restored, non-archived workspace is accepted, so the 409 above is the archive and not a
        // blanket refusal of the route
        const advisoryRow = writes.find((r) => r.path.endsWith("/advisory/request"));
        const advisoryProbe = advisoryRow.probe(eA2);
        const accepted = await api.post("fFull2", advisoryProbe.path, advisoryProbe.body);
        eq(
          p,
          "control: the advisory request of a non-archived workspace is accepted",
          accepted.status,
          202,
        );
        const afterAccepted = JSON.parse(await stateOf(w));
        eq(
          p,
          "control: the accepted request queued one job and one audit entry (so the empty comparison above is not vacuous)",
          [afterAccepted[5] - JSON.parse(before)[5], afterAccepted[6] - JSON.parse(before)[6]],
          [1, 1],
        );
        const again = await api.post("fFull2", `/findings/${eA2.f.id}/claim`, {
          expectedRev: (await w.row(eA2.f)).rev,
        });
        ok(
          p,
          again.status === 200 || again.status === 201,
          `control: the restored workspace writes (claim answered ${again.status} ${again.json?.error?.code ?? ""})`,
        );
      } finally {
        if (agentWas === undefined) delete process.env.FINDINGS_AGENT_ENABLED;
        else process.env.FINDINGS_AGENT_ENABLED = agentWas;
      }
      return p;
    },
  },
  {
    id: "FND-S14d",
    name: "events reconcile with the rows across every writer of status (SPEC 14.1 FND-S14, 6.2, 9.1, part F; ingestion also writes finding.created, finding.verified and finding.reopened, so only status_changed rows are counted against transitions): over a chain that mixes the system actor (ingestion: created, a fix pending, verified, reopened) and users (claim, review, approval, assignment, start, submit, an exception request, its approval) and the expiry job, the finding.status_changed rows equal the history rows that have a source status one for one (finding, revision, from, to, actor kind; none for the creation, none for an observation or a pending request that only raised the revision), finding.created is one per finding, finding.verified and finding.reopened follow their transitions, each domain event type appears the expected number of times, and every event payload has exactly its catalogued ids-and-enums keys (no rationale, justification, snippet or long text)",
    async run(c) {
      const p = [];
      const w = await fWorld(c);
      const { api, db } = w;
      const scn = await scenario(c);
      const items = ["a", "b", "c", "d"].map((n, i) =>
        sast({ path: `src/${n}.py`, line: i + 1, code: `${n}(${i})` }),
      );
      const run = async (list, minutes) => {
        const e = await runExecution(scn, {
          types: { sca: { items: [] }, sast: { items: list }, secrets: { items: [] } },
          startedAt: at(minutes),
        });
        await ingest(scn, e);
      };
      await run(items, 0);
      await run([items[0]], 10);
      await run([items[0]], 20);
      await run(items, 30);
      const all = await db.finding.findMany({
        where: { tenantId: scn.tenantId, pipelineId: scn.pipeline.id },
        orderBy: { path: "asc" },
      });
      const [fa, fb, fc] = all;
      const post = async (name, path, body) => {
        const r = await api.post(name, path, body);
        if (r.status >= 300)
          throw new Error(
            `the chain of FND-S14d: ${path} answered ${r.status} ${r.json?.error?.code}`,
          );
        return r;
      };
      const rev = async (f) => (await w.row(f)).rev;
      await post("fAnalyst", `/findings/${fa.id}/claim`, { expectedRev: await rev(fa) });
      const rr = await post("fAnalyst", `/findings/${fa.id}/reviews`, {
        decision: "true_positive",
        rationale: RATIONALE,
        expectedRev: await rev(fa),
      });
      await post("fFull", `/findings/${fa.id}/reviews/${rr.json.data.review.current.id}/approve`, {
        expectedRev: await rev(fa),
      });
      await post("fFull", `/findings/${fa.id}/assignments`, {
        assigneeUserId: w.users.fDev,
        expectedRev: await rev(fa),
      });
      await post("fDev", `/findings/${fa.id}/remediation/start`, { expectedRev: await rev(fa) });
      await post("fDev", `/findings/${fa.id}/remediation/submit`, { expectedRev: await rev(fa) });
      const xr = await post("fAnalyst", `/findings/${fb.id}/exceptions`, {
        kind: "accept_risk",
        justification: JUSTIFICATION,
        expiresAt: new Date(Date.now() + 30 * DAY).toISOString(),
        expectedRev: await rev(fb),
      });
      await post("fFull", `/findings/${fb.id}/exceptions/${xr.json.data.exception.id}/approve`, {
        expectedRev: await rev(fb),
      });
      await createExceptionExpiryHandler({ db, clock: () => new Date(Date.now() + 31 * DAY) })(
        { type: "findings.exception.expire" },
        { log: { info() {}, error() {}, warn() {} } },
      );
      await post("fFull", `/findings/${fc.id}/assignments`, {
        assigneeUserId: w.users.fDev,
        expectedRev: await rev(fc),
      });
      await post("fDev", `/findings/${fc.id}/remediation/start`, { expectedRev: await rev(fc) });
      await run(items, 40);
      const ids = all.map((f) => f.id);
      const hist = await db.findingStatusHistory.findMany({
        where: { tenantId: scn.tenantId, findingId: { in: ids } },
      });
      const out = (await db.outboxMessage.findMany({ where: { tenantId: scn.tenantId } })).filter(
        (r) => ids.includes(r.payload?.payload?.findingId),
      );
      const byType = (t) => out.filter((r) => r.type === t);
      // (1) exactly one `finding.status_changed` per status transition: the history rows with a source status (creation has none and
      // emits `finding.created`); ingestion also writes created, verified and reopened, which are NOT counted as status hints
      const transitions = hist.filter((h) => h.fromStatus !== null);
      const hintKey = (findingId, rev, from, to, actor) =>
        `${findingId}|${rev}|${from}|${to}|${actor}`;
      const hints = byType("finding.status_changed").map((r) => {
        const m = r.payload.payload;
        return hintKey(m.findingId, m.rev, m.fromStatus, m.toStatus, m.actorType);
      });
      eq(p, "no transition has two hints", hints.length, new Set(hints).size);
      eq(
        p,
        "the status hints equal the transitions (finding, revision, from, to, actor kind)",
        [...hints].sort(),
        transitions
          .map((h) => hintKey(h.findingId, h.rev, h.fromStatus, h.toStatus, h.actorType))
          .sort(),
      );
      ok(
        p,
        transitions.length >= 18,
        `control: only ${transitions.length} transitions were driven`,
      );
      ok(
        p,
        ["system", "user"].every((k) => transitions.some((h) => h.actorType === k)),
        "control: the chain has both ingestion and human transitions",
      );
      // (2) the domain events written beside them follow their own rows
      eq(p, "one finding.created per finding", byType("finding.created").length, ids.length);
      eq(
        p,
        "one finding.verified per verification transition",
        byType("finding.verified").length,
        transitions.filter((h) => h.toStatus === "verified_fixed").length,
      );
      eq(
        p,
        "one finding.reopened per reopen transition (ingestion and expiry)",
        byType("finding.reopened").length,
        transitions.filter((h) => h.toStatus === "reopened").length,
      );
      for (const [type, n] of [
        ["finding.review_recorded", 1],
        ["finding.approval_decided", 1],
        ["finding.assigned", 2],
        ["finding.fix_submitted", 1],
        ["finding.exception_requested", 1],
        ["finding.exception_decided", 1],
        ["finding.exception_expired", 1],
      ])
        eq(p, `${type} events`, byType(type).length, n);
      ok(
        p,
        byType("finding.created").every(
          (r) =>
            !hints.some(
              (h) => h.split("|")[1] === "0" && h.startsWith(r.payload.payload.findingId),
            ),
        ),
        "creation emitted a status hint",
      );
      // (3) the events carry ids, enums and the redacted title only: the exact key sets, short values, never a rationale or snippet
      const KEYS = {
        "finding.created": "findingId,pipelineId,repositoryId,scanType,severity,title,workspaceId",
        "finding.status_changed": "actorType,findingId,fromStatus,rev,toStatus,workspaceId",
        "finding.verified": "findingId,rev,verificationId,workspaceId",
        "finding.reopened": "findingId,reason,rev,workspaceId",
        "finding.review_recorded": "decision,findingId,rev,reviewId,workspaceId",
        "finding.approval_decided": "approvalId,decision,findingId,kind,rev,workspaceId",
        "finding.assigned": "assigneeUserId,assignmentId,findingId,rev,workspaceId",
        "finding.fix_submitted": "findingId,remediationId,rev,workspaceId",
        "finding.exception_requested": "exceptionId,findingId,kind,rev,workspaceId",
        "finding.exception_decided": "decision,exceptionId,findingId,kind,rev,workspaceId",
        "finding.exception_expired": "exceptionId,findingId,kind,rev,workspaceId",
      };
      for (const r of out) {
        const keys = Object.keys(r.payload.payload).sort().join(",");
        eq(p, `${r.type}: payload keys`, keys, KEYS[r.type]);
        const text = j(r.payload);
        ok(
          p,
          !text.includes(RATIONALE) && !text.includes(JUSTIFICATION) && text.length < 1500,
          `${r.type}: the payload carries text or is large (${text.length})`,
        );
      }
      return p;
    },
  },
  {
    id: "FND-S10e",
    name: "no secret anywhere along the whole chain, ingestion to DTOs to advisory input to logs (SPEC 14.1 FND-S10, FS-5, SE-40, OD-3, part F; canary credentials assembled at run time): a SAST item whose title carries a Stripe key, a Slack token, an AWS key id and a GitHub token (and whose excerpt carries the shapes the scan layer lets through) is ingested through the real handler; the canaries (plain, base64 and URL-encoded) appear in NO row of the 14 findings tables, the outbox or the audit log (title redacted, history, events, audit clean), in NO response of the list, summary, board, review queue, approvals, history, comments and similar routes nor in the detail (evidence included), in the advisory input at the snippet and the metadata level, in the advisory view row, or in the ingestion logs; a secret finding is unreadable for the agent; controls prove the excerpt itself is stored, shown and sent. D-F2 FIXED 2026-11-24 (MUTATION_BACKLOG 5, AS_BUILT_FIX1): the SAST excerpt passes the FULL shared redaction at ingestion, so the Stripe, Slack, JWT, AWS temporary key, quoted secret and Bandit-style password canaries of the excerpt are in NO row of finding_evidence and not in the detail DTO either (the redaction marker and the non-secret lines are stored: the positive control)",
    async run(c) {
      const p = [];
      const w = await fWorld(c);
      const { api, db } = w;
      const scn = await scenario(c);
      // canary credentials assembled at run time (no literal secret in the source)
      const CANARY = {
        aws: `${"AKIA"}${"QWERTYUIOP123456"}`,
        github: `${"ghp"}_${"q1w2e3r4t5".repeat(4)}`,
        stripe: `${"sk"}_${"live"}_${"Zq8Lm3".repeat(5)}`,
        slack: `${"xox"}${"b"}-1234567890-0987654321-${"Ab1Cd2".repeat(4)}`,
        awsTemp: `${"ASIA"}${"ZXCVBNMASD789012"}`,
        jwt: `${"eyJ"}${"hbGciOiJIUzI1NiJ9"}.${"eyJ"}${"zdWIiOiJxbWVudGlzIn0"}.${"sig9Xk2Lm4Qw7Rt"}`,
        quoted: `${"Zk9xP2mQ"}-${"7vLwT3nB"}`,
        bandit: `${"hunter2"}-${"hunter2"}-${"hunter2"}`,
      };
      // the value shapes go into the title as they are; the two assignments only make sense inside code, so they are in the excerpt only
      const TITLE_KEYS = ["aws", "github", "stripe", "slack"]; // a title is at most 200 characters (a scan result CHECK)
      // the excerpt: the classes the scan layer's own CHECK lets through, each in its natural spelling (D-F2, SPEC 9.3.2)
      const EXCERPT = [
        `charge_key = "${CANARY.stripe}"`,
        `client = WebClient(token="${CANARY.slack}")`,
        `session_id = "${CANARY.awsTemp}"`,
        `header = "${CANARY.jwt}"`,
        `secret = "${CANARY.quoted}"`,
        `const dbPassword = "${CANARY.bandit}";`,
      ];
      const BENIGN_LINE = "total = sum(values)  # an ordinary line stays byte for byte";
      const MARK = "marker_call_7f3a(user_input)";
      const lines = [];
      const log = {
        info: (...a) => lines.push(j(a)),
        warn: (...a) => lines.push(j(a)),
        error: (...a) => lines.push(j(a)),
        debug: (...a) => lines.push(j(a)),
        trace: (...a) => lines.push(j(a)),
        child() {
          return log;
        },
      };
      // the scan layer's own CHECK refuses some credential shapes in an evidence excerpt before a finding could ever see them (and none in
      // a title): the excerpt carries the shapes the scan layer lets through, the title carries the value shapes. Control: every
      // excerpt canary really passes that CHECK, so the finding sees it (the test is not vacuous)
      for (const line of EXCERPT) {
        const flagged = (await db.$queryRaw`SELECT qm_has_credential_shape(${line}) AS x`)[0].x;
        ok(
          p,
          !flagged,
          `control: the scan layer's CHECK lets the excerpt line through (${line.slice(0, 14)})`,
        );
      }
      const leaky = sast({
        path: "src/leaky.py",
        line: 5,
        code: MARK,
        title: `Hardcoded ${TITLE_KEYS.map((k) => CANARY[k]).join(" ")} in config`,
      });
      leaky.detail.evidence.snippet = `${BENIGN_LINE}\n${EXCERPT.join("\n")}\n${MARK}`;
      const plain = sast({ path: "src/plain.py", line: 7, code: `${MARK}_b` });
      const sec = secret({ path: "config/app.env", line: 3, preview: "AKIA" });
      const e = await runExecution(scn, {
        types: { sca: { items: [] }, sast: { items: [leaky, plain] }, secrets: { items: [sec] } },
        startedAt: at(0),
      });
      const message = {
        type: "pipeline.execution.completed",
        tenantId: scn.tenantId,
        payload: { ...scn.ids(e.id), resolutionEligible: true },
      };
      await createFindingsIngestHandler({ db, config: handlerConfig() })(message, { log }).catch(
        (err) => lines.push(`HANDLER-THREW ${err.message}`),
      );
      const found = await db.finding.findMany({
        where: { tenantId: scn.tenantId, pipelineId: scn.pipeline.id },
        orderBy: { path: "asc" },
      });
      ok(p, found.length === 3, `control: ${found.length} findings were ingested`);
      const leakyRow = found.find((f) => f.path === "src/leaky.py");
      ok(p, !!leakyRow, "control: the finding with the canary title exists");
      const shapes = (v) => [v, Buffer.from(v).toString("base64"), encodeURIComponent(v)];
      /**
       * Looks for every canary (plain, base64, URL-encoded) in a text. NO surface is exempt any more (D-F2 fixed 2026-11-24: the evidence
       * excerpt is redacted with the full shared list before it is stored).
       */
      const leaks = (label, text) => {
        for (const [name, value] of Object.entries(CANARY))
          for (const n of shapes(value))
            if (text.includes(n)) p.push(`${label} holds the ${name} canary credential`);
      };
      // rows of every findings table of the tenant, the outbox and the audit log
      const tables = (
        await db.$queryRaw`SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' AND column_name = 'tenant_id' AND (table_name LIKE 'finding%' OR table_name IN ('remediation_records', 'verification_records')) ORDER BY 1`
      ).map((r) => r.table_name);
      ok(p, tables.length >= 12, `control: only ${tables.length} findings tables were searched`);
      for (const t of [...tables, "outbox_messages", "audit_logs"]) {
        const rows = await db.$queryRawUnsafe(
          `SELECT row_to_json(t)::text AS r FROM "${t}" t WHERE tenant_id = $1::uuid`,
          scn.tenantId,
        );
        leaks(`the table ${t}`, rows.map((r) => r.r).join("\n"));
      }
      const evidenceRows = await db.findingEvidence.findMany({ where: { tenantId: scn.tenantId } });
      ok(
        p,
        evidenceRows.some((r) => r.snippet?.includes(MARK)),
        "control: the excerpt itself is stored (the marker is in the evidence copy)",
      );
      // positive control (D-F2): the non-secret text of the excerpt is stored intact, the secret lines keep their names and lose their values
      const leakySnippet = evidenceRows.find((r) => r.findingId === leakyRow?.id)?.snippet ?? "";
      ok(
        p,
        leakySnippet.includes(BENIGN_LINE),
        "control: the ordinary excerpt line is stored byte for byte",
      );
      ok(
        p,
        leakySnippet.includes("client = WebClient(token=") &&
          leakySnippet.includes("const dbPassword = ") &&
          leakySnippet.includes("secret = "),
        "control: the code around a secret is kept",
      );
      eq(
        p,
        "every secret line of the excerpt carries the redaction marker",
        (leakySnippet.match(/\[REDACTED\]/g) ?? []).length >= EXCERPT.length,
        true,
      );
      // the DTOs of every read route
      const ids = found.map((f) => f.id);
      const reads = [
        `/findings?workspaceId=${w.wsA}&pipelineId=${scn.pipeline.id}&pageSize=100`,
        `/findings/summary?workspaceId=${w.wsA}`,
        `/remediation/board?workspaceId=${w.wsA}`,
        `/review-queue?workspaceId=${w.wsA}`,
        `/approvals?workspaceId=${w.wsA}`,
        ...ids.flatMap((id) => [
          `/findings/${id}/history`,
          `/findings/${id}/comments`,
          `/findings/${id}/similar`,
        ]),
      ];
      for (const path of reads) {
        const r = await api.get("fFull", path);
        ok(p, r.status === 200, `control: GET ${path} answered ${r.status}`);
        leaks(`GET ${path.split("?")[0]}`, j(r.json));
      }
      const listed = await api.get(
        "fFull",
        `/findings?workspaceId=${w.wsA}&pipelineId=${scn.pipeline.id}&pageSize=100`,
      );
      ok(
        p,
        ids.every((id) => j(listed.json).includes(id)),
        "control: the list shows the ingested findings",
      );
      let detailHasMarker = false;
      for (const id of ids) {
        const r = await api.get("fFull", `/findings/${id}`);
        ok(p, r.status === 200, `control: the detail answered ${r.status}`);
        // the whole detail, its evidence included, is clean (D-F2 fixed)
        leaks("the detail DTO", j(r.json));
        if (j(r.json?.data?.evidence ?? null).includes(MARK)) detailHasMarker = true;
      }
      ok(p, detailHasMarker, "control: the detail DTO carries the stored excerpt (marker)");
      // the advisory input: the excerpt reaches it only through the redaction (a SAST finding at the snippet level), and a secret
      // finding is not readable by the agent at all
      const agent = dbPackage.createFindingsAgentRepository({ db });
      const chainOf = (f) => ({
        tenantId: f.tenantId,
        workspaceId: f.workspaceId,
        repositoryId: f.repositoryId,
        pipelineId: f.pipelineId,
        findingId: f.id,
      });
      const loaded = await agent.getFindingForAdvisory(chainOf(leakyRow));
      ok(p, !!loaded, "control: the agent view returns the SAST finding");
      if (loaded) {
        const input = buildAdvisoryInput(loaded.finding, loaded.evidence, "snippet", new Date());
        ok(
          p,
          j(input).includes(MARK),
          "control: the excerpt reaches the advisory input at the snippet level",
        );
        leaks("the advisory input (snippet level)", j(input));
        leaks(
          "the advisory input (metadata level)",
          j(buildAdvisoryInput(loaded.finding, loaded.evidence, "metadata", new Date())),
        );
        leaks("the advisory view row", j(loaded.finding));
      }
      const secretRow = found.find((f) => f.scanType === "secrets");
      eq(
        p,
        "the agent cannot read a secret finding",
        await agent.getFindingForAdvisory(chainOf(secretRow)),
        null,
      );
      // the logs of the ingestion handler
      ok(p, lines.length > 0, "control: the ingestion handler logged");
      leaks("the ingestion logs", lines.join("\n"));
      return p;
    },
  },
  {
    id: "FND-S19",
    name: "the advisory agent trusts a loaded finding only when it carries the WHOLE chain of the message (SPEC 9.3.1 steps 1 and 2, FPA-S07, ADR-003, part F; kills the survivors of the mutation sweep on the five comparisons of runAdvisory): a repository that hands back a row whose tenant, workspace, repository, pipeline or id differs from the message in exactly ONE of the five (a buggy or hostile port, however unlikely) gets the request dropped, with no provider resolved, no consent read and no advisory stored, and a row with the whole chain proceeds (the control)",
    async run() {
      const p = [];
      const T = randomUUID();
      const row = (over = {}) => ({
        tenantId: T,
        workspaceId: randomUUID(),
        repositoryId: randomUUID(),
        pipelineId: randomUUID(),
        id: randomUUID(),
        scanType: "sast",
        severity: "high",
        originTrust: "trusted",
        ruleId: "python.lang.security.eval",
        ruleName: "Use of eval",
        toolSeverity: "high",
        confidence: "medium",
        toolCount: 1,
        cwe: [95],
        advisoryIds: [],
        path: "src/app.py",
        startLine: 10,
        endLine: 10,
        occurrenceCount: 1,
        firstDetectedAt: new Date(Date.now() - 86_400_000),
        reopenCount: 0,
        ...over,
      });
      const messageFor = (f) => ({
        tenantId: f.tenantId,
        payload: {
          findingId: f.id,
          workspaceId: f.workspaceId,
          repositoryId: f.repositoryId,
          pipelineId: f.pipelineId,
          reason: "created",
        },
      });
      const attempt = async (messageRow, returnedRow) => {
        const seen = { resolved: 0, consent: 0, inserted: 0 };
        const outcome = await runAdvisory({
          message: messageFor(messageRow),
          repository: {
            getFindingForAdvisory: async () => ({ finding: returnedRow, evidence: null }),
            readConsent: async () => {
              seen.consent += 1;
              return { externalConsent: false, codeSnippetConsent: false };
            },
            findAdvisoryByHash: async () => null,
            countAdvisoriesSince: async () => 0,
            insertAdvisory: async () => {
              seen.inserted += 1;
              return { id: randomUUID(), created: true };
            },
          },
          llm: {
            providerKind: "local",
            resolveProvider: async () => {
              seen.resolved += 1;
              return { provider: null, status: "not_configured" };
            },
          },
          config: { findings: { agentTenantDailyCap: 500 } },
          limiter: createConcurrencyLimiter(2),
          rateLimiter: { tryAcquire: async () => true },
          now: () => new Date(),
        });
        return { outcome: outcome.outcome, ...seen };
      };
      const base = row();
      const control = await attempt(base, base);
      ok(
        p,
        control.outcome !== "dropped",
        `control: a row with the whole chain was dropped (${j(control)})`,
      );
      for (const field of ["tenantId", "workspaceId", "repositoryId", "pipelineId", "id"]) {
        const got = await attempt(base, { ...base, [field]: randomUUID() });
        eq(p, `a row that differs in ${field}`, got, {
          outcome: "dropped",
          resolved: 0,
          consent: 0,
          inserted: 0,
        });
      }
      eq(p, "a missing row", (await attempt(base, null)).outcome, "dropped");
      return p;
    },
  },
  {
    id: "FND-S20",
    name: "resolution coverage, every refusal and the gap matching (SPEC 5.4, D-2, D-25, OD-5, part F; kills the survivors of the mutation sweep on evaluateCoverage): from one eligible, complete, covering, undegraded full-tree baseline result that reports a finding absent, ONE condition at a time (event disagreement, not eligible, not baseline, a stale watermark including the equal start, a disabled type, no result, incomplete, truncated, coverage not complete, a degraded tool, a partial scope, a tool that did not run or has no run) answers not absent with its own reason; a coverage gap equal to the finding's ecosystem (any case) or equal to its path or a directory prefix of it blocks the resolution, while a sibling directory that merely shares the prefix, an empty gap and a gap of another ecosystem do not",
    async run() {
      const p = [];
      const finding = {
        scanType: "sca",
        ecosystem: "npm",
        path: "services/api/package-lock.json",
        lastSeenTools: ["trivy"],
      };
      const execution = {
        resolutionEligible: true,
        isBaseline: true,
        startedAt: new Date("2026-11-23T10:00:00Z"),
        resolutionWatermarkStartedAt: new Date("2026-11-23T09:00:00Z"),
        typeEnabled: true,
      };
      const result = {
        completeness: "complete",
        truncated: false,
        fullTree: true,
        coverage: { state: "complete", coverageGaps: [], toolsDegraded: 0 },
      };
      const runs = [{ toolId: "trivy", status: "succeeded" }];
      const ask = (f = {}, e = {}, r = {}, t = runs) =>
        evaluateCoverage(
          { ...finding, ...f },
          { ...execution, ...e },
          r === null
            ? null
            : {
                ...result,
                ...r,
                coverage: r.coverage === undefined ? result.coverage : r.coverage,
              },
          t,
        );
      eq(p, "control: every condition holds", ask(), { absent: true });
      const refusals = [
        ["eligibility_disagrees", ask({}, { eligibilityDisagrees: true })],
        ["not_eligible", ask({}, { resolutionEligible: false })],
        ["not_baseline", ask({}, { isBaseline: false })],
        [
          "stale_watermark",
          ask({}, { resolutionWatermarkStartedAt: new Date("2026-11-23T11:00:00Z") }),
        ],
        [
          "stale_watermark",
          ask({}, { resolutionWatermarkStartedAt: new Date("2026-11-23T10:00:00Z") }),
        ],
        ["type_disabled", ask({}, { typeEnabled: false })],
        ["no_result", ask({}, {}, null)],
        ["incomplete", ask({}, {}, { completeness: "incomplete" })],
        ["truncated", ask({}, {}, { truncated: true })],
        ["coverage_not_complete", ask({}, {}, { coverage: null })],
        [
          "coverage_not_complete",
          ask({}, {}, { coverage: { state: "partial", coverageGaps: [], toolsDegraded: 0 } }),
        ],
        [
          "tools_degraded",
          ask({}, {}, { coverage: { state: "complete", coverageGaps: [], toolsDegraded: 1 } }),
        ],
        ["tools_degraded", ask({}, {}, { coverage: { state: "complete", coverageGaps: [] } })],
        ["partial_scope", ask({}, {}, { fullTree: false })],
        ["tool_not_run", ask({}, {}, {}, [{ toolId: "trivy", status: "failed" }])],
        ["tool_not_run", ask({}, {}, {}, [])],
      ];
      for (const [reason, got] of refusals)
        eq(p, `refusal ${reason}`, got, { absent: false, reason });
      // a watermark strictly before the start is fine, and so is no watermark at all
      eq(p, "no watermark", ask({}, { resolutionWatermarkStartedAt: null }), { absent: true });
      const gap = (g, f = {}) =>
        ask(f, {}, { coverage: { state: "complete", coverageGaps: g, toolsDegraded: 0 } });
      const blocked = { absent: false, reason: "coverage_gap" };
      eq(p, "a gap equal to the ecosystem", gap(["npm"]), blocked);
      eq(p, "a gap equal to the ecosystem in another case", gap(["NPM"]), blocked);
      eq(p, "a gap equal to the path", gap(["services/api/package-lock.json"]), blocked);
      eq(p, "a gap that is a directory prefix of the path", gap(["services/api"]), blocked);
      eq(p, "a gap with a trailing path of another directory", gap(["services/ap"]), {
        absent: true,
      });
      eq(p, "a sibling directory sharing the prefix", gap(["services/api-legacy"]), {
        absent: true,
      });
      eq(p, "an empty gap", gap([""]), { absent: true });
      eq(p, "a gap of another ecosystem", gap(["pypi"]), { absent: true });
      eq(
        p,
        "a gap on a finding without a path or ecosystem",
        gap(["npm"], { ecosystem: null, path: null }),
        { absent: true },
      );
      eq(p, "no gaps listed", gap([]), { absent: true });
      return p;
    },
  },
  {
    id: "FND-S18",
    name: "every function of the findings repositories is classified (the suite's 'every function has a check' rule, SPEC 14.1, part F): the functions of the eight repositories of @qmentisai/db are enumerated and each is in the coverage table with at least one registered check that exercises it (a new function fails until it is added), the table names no function that no longer exists, and every function either names the tenant in its source or is a recorded delegation to one that does; planted violations (an unclassified function, a stale entry, an unregistered check id, a function with no tenant) are each reported",
    async run() {
      const p = [];
      const stub = new Proxy(
        {},
        {
          get: () => () => {
            throw new Error("no data access while enumerating");
          },
        },
      );
      const found = {};
      const factories = Object.keys(dbPackage)
        .filter((k) => /^createFinding/.test(k))
        .sort();
      eq(p, "the repository factories", factories, [
        "createFindingAdvisoriesRepository",
        "createFindingAssignmentsRepository",
        "createFindingExceptionsRepository",
        "createFindingRemediationRepository",
        "createFindingReviewsRepository",
        "createFindingsAgentRepository",
        "createFindingsIngestionRepository",
        "createFindingsRepository",
      ]);
      for (const factory of factories) {
        const repo = dbPackage[factory]({ db: stub });
        for (const [name, fn] of Object.entries(repo))
          if (typeof fn === "function")
            found[`${factory}.${name}`] = { tenant: /tenantId|tenant_id/.test(String(fn)) };
      }
      const { FINDINGS_CHECKS } = await import("./index.js");
      const known = new Set(FINDINGS_CHECKS.map((x) => x.id));
      p.push(...repositoryProblems(found, REPOSITORY_COVERAGE, known));
      ok(
        p,
        Object.keys(found).length >= 50,
        `control: only ${Object.keys(found).length} functions were enumerated`,
      );
      // planted violations must each be reported
      const planted = (label, mutate, sub) => {
        const f = structuredClone(found);
        const cov = structuredClone(REPOSITORY_COVERAGE);
        mutate(f, cov);
        const out = repositoryProblems(f, cov, known);
        ok(
          p,
          out.some((m) => m.includes(sub)),
          `negative control "${label}" was not reported`,
        );
      };
      planted(
        "an unclassified function",
        (f) => {
          f["createFindingsRepository.exportAll"] = { tenant: true };
        },
        "no entry",
      );
      planted(
        "a stale entry",
        (_f, cov) => {
          cov["createFindingsRepository.gone"] = ["FND-S12"];
        },
        "no longer exists",
      );
      planted(
        "an unregistered check",
        (_f, cov) => {
          cov["createFindingsRepository.list"] = ["FND-S99"];
        },
        "not registered",
      );
      planted(
        "a function with no tenant",
        (f) => {
          f["createFindingsRepository.getForWrite"] = { tenant: false };
        },
        "does not name the tenant",
      );
      return p;
    },
  },
];
