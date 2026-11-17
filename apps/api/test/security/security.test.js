/**
 * Security regression suite (ADR-008). Scope, deliberately narrow: tenant isolation, 404/403 authorization behavior,
 * platform/tenant session separation, segregation of duties and the progressive sign-in/MFA throttling (ADR-010). Black box over HTTP against a running API: `scripts/security-suite.js` provisions a
 * disposable database, starts the API and sets SECURITY_* variables. Run with `pnpm test:security`.
 *
 * 68 of the 77 checks come from the audit in docs/STATUS_PHASE_1-4.md plus 9 THR (ADR-010) and 6 RST (tenant restore window, AUTHORIZATION Q25) checks added later. Controls (not counted in the 68) prove the legitimate
 * requests SUCCEED, so a transport that stops mounting routes cannot make the "expect 404 / 401" checks pass vacuously.
 */
import assert from "node:assert/strict";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { after, before, describe, it } from "node:test";
import { createJobEnvelope, parseMessage } from "@qmentisai/contracts";
import { getDbClient } from "@qmentisai/db";
import { jitterOffsetSeconds, nextFireAfter, previousFireBefore } from "@qmentisai/shared";
import { assertSecretFreeMessage, resolveFromMessage, toSecretResponse } from "@qmentisai/infra";
import { createGitHubClient } from "@qmentisai/infra";
import { createAuditService } from "../../src/audit/audit-service.js";
import { createNotificationHandler } from "../../../workers/src/notification/handler.js";
import { createOwnershipVerifier } from "../../../workers/src/ownership/index.js";
import { createPipelineTriggerHandler } from "../../../workers/src/pipeline/router.js";
import { enqueuePlatformJob } from "../../../workers/src/scheduler/jobs.js";
import { createScheduleHandler } from "../../../workers/src/scheduler/schedules.js";
import { createScmEventHandler } from "../../../workers/src/scm/events.js";
import { createScmJobHandler } from "../../../workers/src/scm/jobs.js";
import { createSecrets } from "../../src/runtime/secrets.js";
import { createClient } from "./helpers/http.js";
import { buildDalEntries, buildDalWorld, runDalEntry } from "./helpers/direct-repos.js";
import { STATE_CHECKS, buildStateWorld } from "./helpers/repo-state.js";
import { BROKER_CHECKS, buildBrokerWorld } from "./helpers/broker-topology.js";
import { buildPipelineDbWorld, PIPDB_CHECKS } from "./helpers/pipeline-db.js";
import { buildExecutionDbWorld, driveExecution, EXECDB_CHECKS } from "./helpers/execution-db.js";
import { buildOrchestratorWorld } from "./helpers/orchestrator.js";
import { ORCH_CHECKS } from "./helpers/orchestrator-checks.js";
import { CANCEL_RETRY_CHECKS } from "./helpers/cancel-retry-checks.js";
import { SBOM_CHECKS } from "./helpers/sbom-checks.js";
import { PART_I_CHECKS } from "./helpers/exec-audit-checks.js";
import { LOGDB_CHECKS } from "./helpers/logs-db-checks.js";
import { STORE_CHECKS } from "./helpers/exec-store-checks.js";
import { buildRealtimeWorld, REALTIME_CHECKS } from "./helpers/realtime-checks.js";
import { buildExecHttpChecks } from "./helpers/exec-http-checks.js";
import {
  DAY_FIRES,
  NEXT_FIRES,
  OVERLAP_WALKS,
  runEvaluationFixtures,
  runJitterFixtures,
  runPlanFixtures,
} from "./helpers/schedule-fixtures.js";
import { buildPaginationChecks } from "./helpers/pagination.js";
import { buildOverviewChecks } from "./helpers/overview-checks.js";
import { buildLlmConsentChecks } from "./helpers/llm-consent-checks.js";
import { buildPreferenceChecks } from "./helpers/user-preferences.js";
import { buildWorld } from "./helpers/world.js";

const EXPECTED_CHECKS = 727;
const env = (name) => {
  const value = process.env[name];
  if (!value)
    throw new Error(
      `${name} is not set. Run the suite through "pnpm test:security" (scripts/security-suite.js).`,
    );
  return value;
};

const client = createClient({ baseUrl: env("SECURITY_API_URL"), origin: env("SECURITY_ORIGIN") });
/** @type {Awaited<ReturnType<typeof buildWorld>>} */
let w;

/** @typedef {{ status: number, code?: string, reason?: string }} Expected */
const groups = [];
/** @param {string} title @param {{ setup?: (w: any) => Promise<void>, noLeakOf?: "A" | "B" }} [options] */
function group(title, options = {}) {
  const g = { title, checks: [], ...options };
  groups.push(g);
  const add = (id, name, expected, run, verify) =>
    g.checks.push({ id, name, expected, run, verify, group: title, noLeakOf: g.noLeakOf });
  return add;
}
const S = (name) => (world) => world.sessions[name];
const NOT_FOUND = { status: 404, code: "RESOURCE_NOT_FOUND" };
const FORBIDDEN = { status: 403, code: "FORBIDDEN" };
const UNAUTHENTICATED = { status: 401, code: "UNAUTHENTICATED" };
const INVALID = { status: 400, code: "VALIDATION_FAILED" };
const ids = (obj) => Object.values(obj).filter((v) => typeof v === "string" && v.length > 8);

// ---------------------------------------------------------------------------------------------------------------------
// 1. A tenant-A administrator against tenant B's resources, by id (33 checks)
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Tenant A administrator vs tenant B resources", { noLeakOf: "B" });
  const asA = (world, method, path, options) =>
    world.api(method, path, { cookie: S("admin")(world), ...options });
  add("ISO-001", "GET workspace of B", NOT_FOUND, (x) => asA(x, "GET", `/workspaces/${x.B.ws}`));
  add("ISO-002", "PATCH workspace of B", NOT_FOUND, (x) =>
    asA(x, "PATCH", `/workspaces/${x.B.ws}`, { body: { name: "pwned" } }),
  );
  add("ISO-003", "POST archive workspace of B", NOT_FOUND, (x) =>
    asA(x, "POST", `/workspaces/${x.B.ws}/archive`),
  );
  add("ISO-004", "GET members of B's workspace", NOT_FOUND, (x) =>
    asA(x, "GET", `/workspaces/${x.B.ws}/members`),
  );
  add("ISO-005", "GET role-assignments of B's workspace", NOT_FOUND, (x) =>
    asA(x, "GET", `/workspaces/${x.B.ws}/role-assignments`),
  );
  add("ISO-006", "DELETE role-assignment inside B's workspace", NOT_FOUND, (x) =>
    asA(x, "DELETE", `/workspaces/${x.B.ws}/role-assignments/${x.B.assignment}`),
  );
  add("ISO-007", "GET user of B", NOT_FOUND, (x) => asA(x, "GET", `/users/${x.B.userId}`));
  add("ISO-008", "PATCH (suspend) user of B", NOT_FOUND, (x) =>
    asA(x, "PATCH", `/users/${x.B.userId}`, { body: { status: "suspended" } }),
  );
  add("ISO-009", "DELETE user of B", NOT_FOUND, (x) => asA(x, "DELETE", `/users/${x.B.userId}`));
  add("ISO-010", "GET effective-permissions of B's user", NOT_FOUND, (x) =>
    asA(x, "GET", `/users/${x.B.userId}/effective-permissions`),
  );
  add("ISO-011", "GET group of B", NOT_FOUND, (x) => asA(x, "GET", `/groups/${x.B.group}`));
  add("ISO-012", "PATCH group of B", NOT_FOUND, (x) =>
    asA(x, "PATCH", `/groups/${x.B.group}`, { body: { name: "x" } }),
  );
  add("ISO-013", "DELETE group of B", NOT_FOUND, (x) => asA(x, "DELETE", `/groups/${x.B.group}`));
  add("ISO-014", "GET members of B's group", NOT_FOUND, (x) =>
    asA(x, "GET", `/groups/${x.B.group}/members`),
  );
  add("ISO-015", "PUT B's user into A's own group", NOT_FOUND, (x) =>
    asA(x, "PUT", `/groups/${x.A.group}/members/${x.B.userId}`),
  );
  add("ISO-016", "GET custom role of B", NOT_FOUND, (x) => asA(x, "GET", `/roles/${x.B.role}`));
  add("ISO-017", "PATCH custom role of B", NOT_FOUND, (x) =>
    asA(x, "PATCH", `/roles/${x.B.role}`, { body: { description: "pwned" } }),
  );
  add("ISO-018", "DELETE custom role of B", NOT_FOUND, (x) =>
    asA(x, "DELETE", `/roles/${x.B.role}`),
  );
  add("ISO-019", "POST role cloned from B's role", NOT_FOUND, (x) =>
    asA(x, "POST", "/roles", {
      body: { name: `Clone ${x.suffix}`, description: "d", cloneFromRoleId: x.B.role },
    }),
  );
  add("ISO-020", "DELETE B's assignment id on the tenant route", NOT_FOUND, (x) =>
    asA(x, "DELETE", `/role-assignments/${x.B.assignment}`),
  );
  add("ISO-021", "PATCH B's assignment id on the tenant route", NOT_FOUND, (x) =>
    asA(x, "PATCH", `/role-assignments/${x.B.assignment}`, { body: { status: "suspended" } }),
  );
  add("ISO-022", "POST assignment to B's user", NOT_FOUND, (x) =>
    asA(x, "POST", "/role-assignments", {
      body: { subjectType: "user", subjectId: x.B.userId, roleId: x.guestRoleId },
    }),
  );
  add("ISO-023", "POST assignment to B's group", NOT_FOUND, (x) =>
    asA(x, "POST", "/role-assignments", {
      body: { subjectType: "group", subjectId: x.B.group, roleId: x.guestRoleId },
    }),
  );
  add("ISO-024", "POST assignment using B's custom role", NOT_FOUND, (x) =>
    asA(x, "POST", "/role-assignments", {
      body: { subjectType: "user", subjectId: x.A.user, roleId: x.B.role },
    }),
  );
  add("ISO-025", "PUT B's user into A's own workspace", NOT_FOUND, (x) =>
    asA(x, "PUT", `/workspaces/${x.A.paymentsWs}/members/${x.B.userId}`),
  );
  add("ISO-026", "PATCH A's workspace owner = B's user", INVALID, (x) =>
    asA(x, "PATCH", `/workspaces/${x.A.paymentsWs}`, { body: { ownerUserId: x.B.userId } }),
  );
  add("ISO-027", "PUT /me/active-tenant = B (no membership)", NOT_FOUND, (x) =>
    asA(x, "PUT", "/me/active-tenant", { body: { tenantId: x.B.id } }),
  );
  add("ISO-028", "POST accept invitation of B (not invited)", NOT_FOUND, (x) =>
    asA(x, "POST", `/me/invitations/${x.B.id}/accept`),
  );
  add(
    "ISO-029",
    "workspace list never contains B's workspace",
    { status: 200 },
    (x) => asA(x, "GET", "/workspaces?pageSize=100"),
    (r, x) =>
      r.json.data.some((row) => row.id === x.B.ws) ? ["B's workspace appears in A's list"] : [],
  );
  add(
    "ISO-030",
    "user list never contains B's user",
    { status: 200 },
    (x) => asA(x, "GET", "/users?pageSize=100"),
    (r, x) =>
      r.json.data.some((row) => row.userId === x.B.userId) ? ["B's user appears in A's list"] : [],
  );
  add(
    "ISO-031",
    "x-tenant-id header naming B is ignored",
    { status: 200 },
    (x) => asA(x, "GET", "/workspaces?pageSize=100", { headers: { "x-tenant-id": x.B.id } }),
    (r, x) =>
      r.json.data.some((row) => row.id === x.B.ws) ||
      !r.json.data.some((row) => row.id === x.A.paymentsWs)
        ? ["the header changed the tenant context"]
        : [],
  );
  add("ISO-032", "?tenantId=B query parameter rejected", INVALID, (x) =>
    asA(x, "GET", `/workspaces?tenantId=${x.B.id}`),
  );
  add("ISO-033", "tenantId in a POST body rejected", INVALID, (x) =>
    asA(x, "POST", "/workspaces", { body: { name: `Smuggle ${x.suffix}`, tenantId: x.B.id } }),
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 2. Symmetry: tenant B's administrator against tenant A (4 checks)
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Tenant B administrator vs tenant A resources", { noLeakOf: "A" });
  const asB = (x, method, path) => x.api(method, path, { cookie: S("bOwner")(x) });
  add("ISO-034", "GET A's workspace", NOT_FOUND, (x) =>
    asB(x, "GET", `/workspaces/${x.A.paymentsWs}`),
  );
  add("ISO-035", "GET A's user", NOT_FOUND, (x) => asB(x, "GET", `/users/${x.A.user}`));
  add("ISO-036", "GET A's group", NOT_FOUND, (x) => asB(x, "GET", `/groups/${x.A.group}`));
  add("ISO-037", "DELETE A's role-assignment", NOT_FOUND, (x) =>
    asB(x, "DELETE", `/role-assignments/${x.A.assignment}`),
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 3. Same tenant: hidden workspaces answer 404, visible-but-forbidden answers 403 (15 checks)
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Same tenant: workspace visibility (404) and permissions (403)");
  const asManager = (x, method, path, options) =>
    x.api(method, path, { cookie: S("manager")(x), ...options });
  add("AUTHZ-001", "manager (sees only Payments) GET hidden Identity workspace", NOT_FOUND, (x) =>
    asManager(x, "GET", `/workspaces/${x.A.identityWs}`),
  );
  add("AUTHZ-002", "manager PATCH hidden workspace", NOT_FOUND, (x) =>
    asManager(x, "PATCH", `/workspaces/${x.A.identityWs}`, { body: { description: "x" } }),
  );
  add("AUTHZ-003", "manager POST archive hidden workspace", NOT_FOUND, (x) =>
    asManager(x, "POST", `/workspaces/${x.A.identityWs}/archive`),
  );
  add("AUTHZ-004", "manager GET members of hidden workspace", NOT_FOUND, (x) =>
    asManager(x, "GET", `/workspaces/${x.A.identityWs}/members`),
  );
  add("AUTHZ-005", "manager POST assignment in hidden workspace", NOT_FOUND, (x) =>
    asManager(x, "POST", `/workspaces/${x.A.identityWs}/role-assignments`, {
      body: { subjectType: "user", subjectId: x.A.user, roleId: x.guestRoleId },
    }),
  );
  add("AUTHZ-006", "manager GET a workspace that does not exist", NOT_FOUND, (x) =>
    asManager(x, "GET", `/workspaces/${x.UNKNOWN}`),
  );
  add(
    "AUTHZ-007",
    "hidden and non-existent workspaces return the identical error body",
    NOT_FOUND,
    (x) => asManager(x, "GET", `/workspaces/${x.A.identityWs}`),
    async (hidden, x) => {
      const unknown = await asManager(x, "GET", `/workspaces/${x.UNKNOWN}`);
      return hidden.json.error.code === unknown.json.error.code &&
        hidden.json.error.message === unknown.json.error.message &&
        JSON.stringify(hidden.json.error.details) === JSON.stringify(unknown.json.error.details)
        ? []
        : ["the 404 for a hidden workspace differs from the 404 for a missing one"];
    },
  );
  add("AUTHZ-008", "developer PATCH visible workspace (lacks workspace.update)", FORBIDDEN, (x) =>
    x.api("PATCH", `/workspaces/${x.A.paymentsWs}`, {
      cookie: S("developer")(x),
      body: { description: "x" },
    }),
  );
  add("AUTHZ-009", "viewer PUT workspace member (lacks workspace.manage_members)", FORBIDDEN, (x) =>
    x.api("PUT", `/workspaces/${x.A.paymentsWs}/members/${x.A.user}`, { cookie: S("viewer")(x) }),
  );
  add("AUTHZ-010", "viewer POST /workspaces (lacks workspace.create)", FORBIDDEN, (x) =>
    x.api("POST", "/workspaces", { cookie: S("viewer")(x), body: { name: `Nope ${x.suffix}` } }),
  );
  add("AUTHZ-011", "viewer GET /users (tenant-level permission)", FORBIDDEN, (x) =>
    x.api("GET", "/users", { cookie: S("viewer")(x) }),
  );
  add("AUTHZ-012", "lead PUT workspace member (visible, lacks manage_members)", FORBIDDEN, (x) =>
    x.api("PUT", `/workspaces/${x.A.paymentsWs}/members/${x.A.user}`, { cookie: S("lead")(x) }),
  );
  add("AUTHZ-013", "assignment of workspace X used under workspace Y", NOT_FOUND, (x) =>
    x.api(
      "DELETE",
      `/workspaces/${x.A.paymentsWs}/role-assignments/${x.A.identityAssignment ?? x.UNKNOWN}`,
      { cookie: S("admin")(x) },
    ),
  );
  add("AUTHZ-014", "workspace-scope assignment id used on the tenant-scope route", NOT_FOUND, (x) =>
    x.api("DELETE", `/role-assignments/${x.A.assignment}`, { cookie: S("admin")(x) }),
  );
  add(
    "AUTHZ-015",
    "SOD-3: admin assigns themselves a role holding keys they lack",
    { status: 403, code: "ROLE_ESCALATION" },
    async (x) => {
      const created = await x.api("POST", "/roles", {
        cookie: S("admin")(x),
        body: {
          name: `Approver audit ${x.suffix}`,
          description: "holds approval keys the admin lacks",
          permissions: ["workspace.view", "approval.approve"],
        },
      });
      if (created.status !== 201)
        throw new Error(`Fixture "approver role" expected 201 but got ${created.status}`);
      return x.api("POST", "/role-assignments", {
        cookie: S("admin")(x),
        body: { subjectType: "user", subjectId: x.A.adminUserId, roleId: created.json.data.id },
      });
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 4. Platform and tenant session separation (13 checks)
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Platform and tenant session separation");
  const tenantOnPlatform = (x, method, path, body) =>
    x.api(method, path, { cookie: S("admin")(x), ...(body ? { body } : {}) });
  add("SESS-001", "platform route with a TENANT session: GET /platform/me", NOT_FOUND, (x) =>
    tenantOnPlatform(x, "GET", "/platform/me"),
  );
  add("SESS-002", "platform route with a TENANT session: GET /platform/tenants", NOT_FOUND, (x) =>
    tenantOnPlatform(x, "GET", "/platform/tenants"),
  );
  add("SESS-003", "platform route with a TENANT session: POST /platform/tenants", NOT_FOUND, (x) =>
    tenantOnPlatform(x, "POST", "/platform/tenants", {
      name: "X",
      slug: "xxx",
      admin: { email: "a@b.co", name: "A" },
    }),
  );
  add("SESS-004", "tenant route with a PLATFORM session: GET /me", UNAUTHENTICATED, (x) =>
    x.api("GET", "/me", { cookie: S("sa")(x) }),
  );
  add("SESS-005", "tenant route with a PLATFORM session: GET /workspaces", UNAUTHENTICATED, (x) =>
    x.api("GET", "/workspaces", { cookie: S("sa")(x) }),
  );
  add("SESS-006", "tenant route with a PLATFORM session: GET /users", UNAUTHENTICATED, (x) =>
    x.api("GET", "/users", { cookie: S("sa")(x) }),
  );
  add("SESS-007", "tenant route with no session", UNAUTHENTICATED, (x) =>
    x.api("GET", "/workspaces"),
  );
  add("SESS-008", "platform route with no session", UNAUTHENTICATED, (x) =>
    x.api("GET", "/platform/tenants"),
  );
  add(
    "SESS-009",
    "platform route with a session that has NOT passed MFA",
    UNAUTHENTICATED,
    async (x) => x.api("GET", "/platform/tenants", { cookie: await x.platformLoginOnly() }),
    (r) => {
      const problems = [];
      if (r.json?.error?.details?.reason !== "mfa_required")
        problems.push(
          `expected details.reason "mfa_required", got ${JSON.stringify(r.json?.error?.details)}`,
        );
      if (r.json?.data) problems.push("data was returned before MFA");
      return problems;
    },
  );
  add("SESS-010", "platform token presented under the tenant cookie name", UNAUTHENTICATED, (x) =>
    x.api("GET", "/me", { cookie: `qm_session=${S("sa")(x).split("=")[1]}` }),
  );
  add("SESS-011", "a tenant user cannot sign in to the platform", UNAUTHENTICATED, (x) =>
    x.api("POST", "/platform/auth/login", {
      body: { email: "demo.admin@demo.example", password: x.secrets.tenantPassword },
    }),
  );
  add("SESS-012", "a platform user cannot sign in as a tenant user", UNAUTHENTICATED, (x) =>
    x.api("POST", "/auth/login", {
      body: { email: "superadmin@qmentis.example", password: x.secrets.platformPassword },
    }),
  );
  add("SESS-013", "cross-site Origin on an unsafe request (CSRF)", FORBIDDEN, (x) =>
    x.api("POST", "/auth/logout", { headers: { origin: "http://evil.example" } }),
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 5. Suspension (3 checks). Runs last: it suspends tenant B.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Tenant suspension", {
    async setup(x) {
      const response = await x.api("POST", `/platform/tenants/${x.B.id}/suspend`, {
        cookie: S("sa")(x),
        body: { reason: "security regression suite", confirm: x.B.name },
      });
      if (response.status !== 200)
        throw new Error(`Fixture "suspend tenant B" expected 200 but got ${response.status}`);
    },
  });
  const suspended = { status: 403, code: "TENANT_SUSPENDED" };
  add("SUSP-001", "suspended tenant: an existing session is refused", suspended, (x) =>
    x.api("GET", "/me", { cookie: S("bOwner")(x) }),
  );
  add("SUSP-002", "suspended tenant: an API call is refused", suspended, (x) =>
    x.api("GET", "/workspaces", { cookie: S("bOwner")(x) }),
  );
  add("SUSP-003", "tenant A is unaffected by B's suspension", { status: 200 }, (x) =>
    x.api("GET", "/workspaces", { cookie: S("admin")(x) }),
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 6. Progressive throttling (9 checks, ADR-010). Runs after suspension and uses short waits: the runner configures
//    3 free failures, then waits of 1 s, 2 s, 4 s (cap). Existing and non-existing accounts must be indistinguishable.
// ---------------------------------------------------------------------------------------------------------------------
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const RATE_LIMITED = { status: 429, code: "RATE_LIMITED" };
const median = (values) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
const memo = new Map();
const once = (key, fn) => {
  if (!memo.has(key)) memo.set(key, fn());
  return memo.get(key);
};

/**
 * One scripted streak against a sign-in endpoint: 4 wrong attempts (3 free + the one that arms the wait), an immediate
 * 5th (refused), the CORRECT credentials during the wait, a burst of refused attempts, then the correct credentials
 * after the wait. `credentials(isRight)` builds the request body.
 */
async function streak(x, path, credentials, { cookie } = {}) {
  const timed = async (body) => {
    const started = performance.now();
    const response = await x.api("POST", path, { body, cookie });
    return { response, ms: performance.now() - started };
  };
  const wrong = [];
  for (let i = 0; i < 5; i += 1) wrong.push(await timed(credentials(false)));
  const duringWait = await timed(credentials(true));
  const burst = [];
  for (let i = 0; i < 4; i += 1) burst.push(await timed(credentials(false)));
  const waitSeconds = wrong.at(-1).response.json?.error?.details?.retryAfterSeconds ?? 1;
  await sleep(waitSeconds * 1000 + 400);
  const afterWait = await timed(credentials(true));
  return { wrong, duringWait, burst, afterWait };
}
const statuses = (run) => run.wrong.map((a) => a.response.status);
const refusal = (run) => run.wrong.at(-1).response;
const tenantStreak = (email, exists) =>
  once(`tenant:${email}`, () =>
    streak(w, "/auth/login", (right) => ({
      email,
      password: right && exists ? w.secrets.tenantPassword : "definitely-wrong-password",
    })),
  );
const platformStreak = (email, exists) =>
  once(`platform:${email}`, () =>
    streak(w, "/platform/auth/login", (right) => ({
      email,
      password: right && exists ? w.secrets.platformPassword : "definitely-wrong-password",
    })),
  );
const EXPECTED_STATUSES = [401, 401, 401, 401, 429];
const retryAfterOf = (response) => response.json?.error?.details?.retryAfterSeconds;
const sanitized = (response) => ({ status: response.status, error: response.json?.error });

{
  const add = group("Progressive throttling");
  const ghostEmail = (x) => `ghost.${x.suffix}@nowhere.example`;
  const existingEmail = "demo.analyst@demo.example";

  add(
    "THR-001",
    "existing tenant account: wrong passwords are refused with 429 after the free attempts",
    RATE_LIMITED,
    async () => {
      const run = await tenantStreak(existingEmail, true);
      const problems = [];
      if (JSON.stringify(statuses(run)) !== JSON.stringify(EXPECTED_STATUSES))
        problems.push(`statuses ${statuses(run)}`);
      return Object.assign(refusal(run), { problems });
    },
    (r) => {
      const problems = [...(r.problems ?? [])];
      if (!(retryAfterOf(r) >= 1 && retryAfterOf(r) <= 4))
        problems.push(`retryAfterSeconds ${retryAfterOf(r)} is not within 1..cap`);
      return problems;
    },
  );
  add(
    "THR-002",
    "non-existing tenant account: the same 429 after the same number of attempts",
    RATE_LIMITED,
    async (x) => {
      const run = await tenantStreak(ghostEmail(x), false);
      return Object.assign(refusal(run), {
        problems:
          JSON.stringify(statuses(run)) !== JSON.stringify(EXPECTED_STATUSES)
            ? [`statuses ${statuses(run)}`]
            : [],
      });
    },
    (r) => r.problems ?? [],
  );
  add(
    "THR-003",
    "no account enumeration: existing and non-existing accounts get identical errors, retry hints and comparable timing",
    { status: 200 },
    async (x) => {
      const real = await tenantStreak(existingEmail, true);
      const ghost = await tenantStreak(ghostEmail(x), false);
      const problems = [];
      real.wrong.forEach((a, i) => {
        const b = ghost.wrong[i];
        if (JSON.stringify(sanitized(a.response)) !== JSON.stringify(sanitized(b.response)))
          problems.push(
            `attempt ${i + 1} differs: ${JSON.stringify(sanitized(a.response))} vs ${JSON.stringify(sanitized(b.response))}`,
          );
      });
      const gap = Math.abs(
        median(real.wrong.map((a) => a.ms)) - median(ghost.wrong.map((a) => a.ms)),
      );
      if (gap > 150) problems.push(`median response times differ by ${Math.round(gap)} ms`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "THR-004",
    "correct credentials are also refused while the wait lasts",
    RATE_LIMITED,
    async () => (await tenantStreak(existingEmail, true)).duringWait.response,
  );
  add(
    "THR-005",
    "refused attempts do not extend the wait (no hard lock by spamming)",
    { status: 200 },
    async () => {
      const run = await tenantStreak(existingEmail, true);
      const first = retryAfterOf(refusal(run));
      const problems = run.burst
        .filter((a) => a.response.status !== 429 || retryAfterOf(a.response) > first)
        .map(
          (a) =>
            `burst attempt answered ${a.response.status} retry ${retryAfterOf(a.response)} (first wait ${first})`,
        );
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "THR-006",
    "after the wait the correct password signs in (the account was never locked)",
    { status: 200 },
    async () => (await tenantStreak(existingEmail, true)).afterWait.response,
  );
  add(
    "THR-007",
    "per-IP limit: failures across many different accounts end in 429 for a never-seen account",
    RATE_LIMITED,
    async (x) => {
      let last;
      let attempts = 0;
      for (; attempts < 40; attempts += 1) {
        last = await x.api("POST", "/auth/login", {
          body: {
            email: `spray.${attempts}.${x.suffix}@nowhere.example`,
            password: "definitely-wrong-password",
          },
        });
        if (last.status === 429) break;
      }
      await sleep((retryAfterOf(last) ?? 1) * 1000 + 400);
      return Object.assign(last, { attempts });
    },
    (r) => (r.attempts >= 1 && r.attempts < 40 ? [] : [`no 429 after ${r.attempts} attempts`]),
  );
  add(
    "THR-008",
    "platform MFA: wrong codes are throttled progressively, the right code works after the wait",
    { status: 200 },
    async (x) => {
      const cookie = await x.platformLoginOnly();
      const run = await streak(
        x,
        "/platform/auth/mfa/verify",
        (right) => ({ code: right ? x.secrets.mfaCode : "000000" }),
        { cookie },
      );
      const problems = [];
      if (JSON.stringify(statuses(run)) !== JSON.stringify(EXPECTED_STATUSES))
        problems.push(`statuses ${statuses(run)}`);
      if (run.duringWait.response.status !== 429)
        problems.push(`right code during the wait answered ${run.duringWait.response.status}`);
      if (run.afterWait.response.status !== 200)
        problems.push(`right code after the wait answered ${run.afterWait.response.status}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "THR-009",
    "platform sign-in: existing and non-existing accounts are indistinguishable",
    { status: 200 },
    async (x) => {
      const real = await platformStreak("superadmin@qmentis.example", true);
      const ghost = await platformStreak(`ghost.${x.suffix}@nowhere.example`, false);
      const problems = [];
      if (JSON.stringify(statuses(real)) !== JSON.stringify(EXPECTED_STATUSES))
        problems.push(`statuses ${statuses(real)}`);
      real.wrong.forEach((a, i) => {
        if (
          JSON.stringify(sanitized(a.response)) !==
          JSON.stringify(sanitized(ghost.wrong[i].response))
        )
          problems.push(`attempt ${i + 1} differs`);
      });
      if (real.afterWait.response.status !== 200)
        problems.push("the platform account was locked out");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 7. Tenant restore window (6 checks, AUTHORIZATION Q25). A fresh tenant is deactivated and restored by a Platform Super
//    Admin inside the window (the runner sets 4 s), then deactivated again and left past the window.
// ---------------------------------------------------------------------------------------------------------------------
{
  const scenario = () =>
    once("restore-window", async () => {
      const t = await w.provisionTenant("restore");
      const asSa = (path, body) =>
        w.api("POST", `/platform/tenants/${t.id}/${path}`, { cookie: S("sa")(w), body });
      const deactivate = () =>
        asSa("deactivate", { reason: "restore window check", confirm: t.name });
      const out = { t };
      out.activeRestore = await asSa("restore", { reason: "restore an active tenant" });
      out.tenantRoute = await w.api("POST", `/platform/tenants/${t.id}/restore`, {
        cookie: t.owner,
        body: { reason: "tenant session" },
      });
      out.deactivated = await deactivate();
      out.sessionWhileDeactivated = await w.api("GET", "/me", { cookie: t.owner });
      out.restored = await asSa("restore", { reason: "restore inside the window" });
      out.sessionAfterRestore = await w.api("GET", "/workspaces", { cookie: t.owner });
      out.deactivatedAgain = await deactivate();
      await sleep(4600);
      out.expired = await asSa("restore", { reason: "restore after the window" });
      out.sessionAfterExpiry = await w.api("GET", "/me", { cookie: t.owner });
      return out;
    });
  const add = group("Tenant restore window");
  add(
    "RST-001",
    "Super Admin restores a deactivated tenant inside the window (status back to active or trial)",
    { status: 200 },
    async () => (await scenario()).restored,
    (r) => {
      const tenant = r.json?.data?.tenant;
      return ["active", "trial"].includes(tenant?.status) && tenant?.deactivatedAt === null
        ? []
        : [`unexpected tenant ${JSON.stringify(tenant)}`];
    },
  );
  add(
    "RST-002",
    "while deactivated, a tenant session is refused",
    { status: 403, code: "TENANT_SUSPENDED" },
    async () => (await scenario()).sessionWhileDeactivated,
  );
  add(
    "RST-003",
    "after the restore the tenant session works again",
    { status: 200 },
    async () => (await scenario()).sessionAfterRestore,
  );
  add(
    "RST-004",
    "after the window the restore is refused with TENANT_DEACTIVATION_EXPIRED and the tenant stays unusable",
    { status: 409, code: "TENANT_DEACTIVATION_EXPIRED" },
    async () => {
      const run = await scenario();
      return Object.assign(run.expired, { stillRefused: run.sessionAfterExpiry.status });
    },
    (r) =>
      r.stillRefused === 403 ? [] : [`tenant session answered ${r.stillRefused} after expiry`],
  );
  add(
    "RST-005",
    "a tenant session cannot reach the platform restore route",
    NOT_FOUND,
    async () => (await scenario()).tenantRoute,
  );
  add(
    "RST-006",
    "restoring a tenant that is not deactivated is a conflict",
    { status: 409, code: "CONFLICT" },
    async () => (await scenario()).activeRestore,
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 8. Secret storage foundation (9 checks, ADR-009). The store has no HTTP surface yet, so these run in-process against the
//    same disposable database: tenant isolation of secretRefs, AAD binding, no plaintext at rest / in views / in audit.
// ---------------------------------------------------------------------------------------------------------------------
let secretDb;
const suiteDb = () => (secretDb ??= getDbClient({ datasourceUrl: env("SECURITY_DATABASE_URL") }));
const secretsWorld = () =>
  once("secrets", async () => {
    suiteDb();
    const quiet = { warn() {}, error() {}, info() {} };
    const store = createSecrets({
      config: {
        secrets: {
          enabled: true,
          masterKey: randomBytes(32).toString("base64"),
          masterKeyVersion: 1,
        },
      },
      infra: { db: secretDb },
      audit: createAuditService({ db: secretDb, logger: quiet }),
    });
    const me = await w.api("GET", "/me", { cookie: S("admin")(w) });
    const tenantA = me.json.data.tenant.id;
    const tenantB = w.B.id;
    const actor = { userId: me.json.data.user.id };
    const attempt = async (fn) => {
      try {
        return { ok: true, value: await fn() };
      } catch (error) {
        return { ok: false, name: error.name, message: error.message };
      }
    };
    const valueA = `sk-live-${randomBytes(12).toString("hex")}`;
    const purpose = "integration.test.token";
    const a1 = await store.put({ tenantId: tenantA, purpose, plaintext: valueA, actor });
    const a2 = await store.put({ tenantId: tenantA, purpose, plaintext: `other-${valueA}`, actor });
    const a3 = await store.put({
      tenantId: tenantA,
      purpose: "integration.test.other",
      plaintext: valueA,
      actor,
    });
    const b1 = await store.put({ tenantId: tenantB, purpose, plaintext: `b-${valueA}`, actor });
    const out = { store, tenantA, tenantB, valueA, purpose, a1, a2, b1 };
    out.crossTenant = await attempt(() =>
      store.resolve({ tenantId: tenantB, secretRef: a1.secretRef, purpose }),
    );
    out.randomRef = await attempt(() =>
      store.resolve({
        tenantId: tenantB,
        secretRef: "00000000-0000-4000-8000-0000000000aa",
        purpose,
      }),
    );
    out.wrongPurpose = await attempt(() =>
      store.resolve({
        tenantId: tenantA,
        secretRef: a1.secretRef,
        purpose: "integration.test.other",
      }),
    );
    // Same tenant, same DEK: copy secret 1's ciphertext into secret 2's row. Only the AAD (secretId) differs.
    const row1 = await secretDb.secret.findFirst({
      where: { id: a1.secretRef, tenantId: tenantA },
    });
    await secretDb.secret.updateMany({
      where: { id: a2.secretRef, tenantId: tenantA },
      data: { ciphertext: row1.ciphertext, nonce: row1.nonce },
    });
    out.swappedRow = await attempt(() =>
      store.resolve({ tenantId: tenantA, secretRef: a2.secretRef, purpose }),
    );
    // Another tenant's row carrying tenant A's ciphertext.
    const rowB = await secretDb.secret.findFirst({
      where: { id: b1.secretRef, tenantId: tenantB },
    });
    await secretDb.secret.updateMany({
      where: { id: b1.secretRef, tenantId: tenantB },
      data: { ciphertext: row1.ciphertext, nonce: row1.nonce, dekVersion: rowB.dekVersion },
    });
    out.movedToTenantB = await attempt(() =>
      store.resolve({ tenantId: tenantB, secretRef: b1.secretRef, purpose }),
    );
    out.rawRows = JSON.stringify([
      await secretDb.secret.findMany({ where: { tenantId: tenantA } }),
      await secretDb.tenantDataKey.findMany({ where: { tenantId: tenantA } }),
    ]);
    out.metadata = await store.describe({ tenantId: tenantA, secretRef: a3.secretRef });
    // rotate + delete on secret 3, then read the audit trail.
    const rotatedValue = `rotated-${randomBytes(8).toString("hex")}`;
    await store.rotate({
      tenantId: tenantA,
      secretRef: a3.secretRef,
      plaintext: rotatedValue,
      actor,
    });
    out.afterRotate = await attempt(() =>
      store.resolve({
        tenantId: tenantA,
        secretRef: a3.secretRef,
        purpose: "integration.test.other",
      }),
    );
    out.rotatedValue = rotatedValue;
    await store.delete({ tenantId: tenantA, secretRef: a3.secretRef, actor });
    out.afterDelete = await attempt(() =>
      store.resolve({
        tenantId: tenantA,
        secretRef: a3.secretRef,
        purpose: "integration.test.other",
      }),
    );
    out.audit = await secretDb.auditLog.findMany({
      where: { tenantId: tenantA, targetType: "secret" },
    });
    return out;
  });
const done = (problems) => ({ status: 200, json: null, problems });
{
  const add = group("Secret storage foundation");
  const ok = { status: 200 };
  add(
    "SEC-001",
    "another tenant's secretRef cannot be resolved, and answers like a reference that does not exist",
    ok,
    async () => {
      const x = await secretsWorld();
      const problems = [];
      if (x.crossTenant.ok) problems.push("tenant B resolved tenant A's secret");
      if (x.crossTenant.name !== "SecretNotFoundError")
        problems.push(`error was ${x.crossTenant.name}`);
      if (JSON.stringify(x.crossTenant) !== JSON.stringify(x.randomRef))
        problems.push("cross-tenant and missing references answer differently");
      return done(problems);
    },
    (r) => r.problems,
  );
  add(
    "SEC-002",
    "a secret cannot be resolved under a different purpose",
    ok,
    async () => {
      const x = await secretsWorld();
      return done(x.wrongPurpose.ok ? ["resolved with the wrong purpose"] : []);
    },
    (r) => r.problems,
  );
  add(
    "SEC-003",
    "a ciphertext copied into another secret record of the same tenant fails authentication (AAD binds the secret id)",
    ok,
    async () => {
      const x = await secretsWorld();
      const problems = [];
      if (x.swappedRow.ok) problems.push("a swapped ciphertext decrypted");
      if (x.swappedRow.name !== "SecretCryptoError")
        problems.push(`error was ${x.swappedRow.name}`);
      return done(problems);
    },
    (r) => r.problems,
  );
  add(
    "SEC-004",
    "tenant A's ciphertext placed in tenant B's record cannot be decrypted (per-tenant keys and AAD)",
    ok,
    async () => {
      const x = await secretsWorld();
      return done(x.movedToTenantB.ok ? ["a cross-tenant ciphertext decrypted"] : []);
    },
    (r) => r.problems,
  );
  add(
    "SEC-005",
    "the database holds no plaintext: secret rows and wrapped data keys do not contain the value",
    ok,
    async () => {
      const x = await secretsWorld();
      return done(x.rawRows.includes(x.valueA) ? ["plaintext found in stored rows"] : []);
    },
    (r) => r.problems,
  );
  add(
    "SEC-006",
    "the metadata and the API view of a secret contain neither the value nor key versions",
    ok,
    async () => {
      const x = await secretsWorld();
      const view = JSON.stringify(toSecretResponse(x.metadata));
      const problems = [];
      if (view.includes(x.valueA)) problems.push("the view contains the value");
      if (/dekVersion|keyVersion|masterKey|ciphertext|nonce/i.test(view))
        problems.push(`the view exposes internals: ${view}`);
      return done(problems);
    },
    (r) => r.problems,
  );
  add(
    "SEC-007",
    "create, rotate and delete are audited and the audit entries never contain a value",
    ok,
    async () => {
      const x = await secretsWorld();
      const actions = new Set(x.audit.map((a) => a.action));
      const problems = ["secret.created", "secret.rotated", "secret.deleted"]
        .filter((a) => !actions.has(a))
        .map((a) => `no ${a} audit entry`);
      const dump = JSON.stringify(x.audit);
      if (dump.includes(x.valueA) || dump.includes(x.rotatedValue))
        problems.push("an audit entry contains a value");
      return done(problems);
    },
    (r) => r.problems,
  );
  add(
    "SEC-008",
    "rotation replaces the value under the same reference and a deleted secret stops resolving",
    ok,
    async () => {
      const x = await secretsWorld();
      const problems = [];
      if (!x.afterRotate.ok || x.afterRotate.value !== x.rotatedValue)
        problems.push("the rotated value did not resolve");
      if (x.afterDelete.ok || x.afterDelete.name !== "SecretNotFoundError")
        problems.push("a deleted secret still resolves");
      return done(problems);
    },
    (r) => r.problems,
  );
  add(
    "SEC-009",
    "messages carry references only: credential fields are refused and a foreign tenant in a message cannot resolve",
    ok,
    async () => {
      const x = await secretsWorld();
      const problems = [];
      let refused = false;
      try {
        assertSecretFreeMessage({ tenantId: x.tenantA, nested: { apiKey: "sk-x" } });
      } catch {
        refused = true;
      }
      if (!refused) problems.push("a message with a credential field was accepted");
      const foreign = await resolveFromMessage(
        x.store,
        { tenantId: x.tenantB, secretRef: x.a1.secretRef },
        { purpose: x.purpose },
      ).then(
        () => "resolved",
        (error) => error.name,
      );
      if (foreign !== "SecretNotFoundError") problems.push(`foreign message answered ${foreign}`);
      return done(problems);
    },
    (r) => r.problems,
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 9. HTTP edge (20 checks): audit-log isolation (AUD), Idempotency-Key scoping (IDM), entitlements (ENT), CORS (COR) and the
//    per-route rate limit (RATE).
// ---------------------------------------------------------------------------------------------------------------------
const ALLOWED_ORIGIN = "http://localhost:5173";
const EVIL_ORIGIN = "https://evil.example";
const KEY = (label) => `suite-${label}-${randomBytes(6).toString("hex")}`;
const edgeTenant = () => once("edge-tenant", () => w.provisionTenant("edge"));
const tenantIdOf = (x, who) =>
  x.api("GET", "/me", { cookie: S(who)(x) }).then((r) => r.json.data.tenant.id);
{
  const add = group("HTTP edge: audit logs", { noLeakOf: "B" });
  const asA = (x, path) => x.api("GET", path, { cookie: S("admin")(x) });
  add(
    "AUD-001",
    "tenant A's audit log lists only tenant A entries and no identifier of tenant B",
    { status: 200 },
    (x) => asA(x, "/audit-logs?pageSize=100"),
    async (r, x) => {
      const a = await tenantIdOf(x, "admin");
      const problems =
        r.json.data.length === 0 ? ["no audit entries returned (the check would be vacuous)"] : [];
      for (const entry of r.json.data)
        if (entry.tenantId !== a) problems.push(`entry ${entry.id} belongs to ${entry.tenantId}`);
      return problems;
    },
  );
  add(
    "AUD-002",
    "another tenant's owner sees only that tenant's entries, none of tenant A's",
    { status: 200 },
    async (x) => x.api("GET", "/audit-logs?pageSize=100", { cookie: (await edgeTenant()).owner }),
    async (r, x) => {
      const edge = await edgeTenant();
      const problems = r.json.data.length === 0 ? ["no audit entries returned"] : [];
      const body = JSON.stringify(r.json);
      for (const id of ids({
        ws: x.A.paymentsWs,
        ws2: x.A.identityWs,
        group: x.A.group,
        user: x.A.user,
        admin: x.A.adminUserId,
      }))
        if (body.includes(id)) problems.push(`leaks tenant A id ${id}`);
      for (const entry of r.json.data)
        if (entry.tenantId !== edge.id)
          problems.push(`entry ${entry.id} belongs to ${entry.tenantId}`);
      return problems;
    },
  );
  add("AUD-003", "a tenant parameter cannot select another tenant's log", INVALID, (x) =>
    asA(x, `/audit-logs?tenantId=${x.B.id}`),
  );
  add(
    "AUD-004",
    "filtering by another tenant's actor returns nothing, not tenant B's entries",
    { status: 200 },
    (x) => asA(x, `/audit-logs?actor=${x.B.userId}`),
    (r) => (r.json.data.length === 0 ? [] : [`${r.json.data.length} entries returned`]),
  );
  add("AUD-005", "a user without audit_log.view_all is refused", FORBIDDEN, (x) =>
    x.api("GET", "/audit-logs", { cookie: S("viewer")(x) }),
  );
}
{
  const add = group("HTTP edge: platform audit log");
  add("AUD-006", "the platform audit log is not reachable with a tenant session", NOT_FOUND, (x) =>
    x.api("GET", "/platform/audit-logs", { cookie: S("admin")(x) }),
  );
  add(
    "AUD-007",
    "the platform audit log lists platform events only and never a tenant's own audit entries",
    { status: 200 },
    (x) => x.api("GET", "/platform/audit-logs?pageSize=100", { cookie: S("sa")(x) }),
    (r) => {
      const problems = r.json.data.length === 0 ? ["no platform entries returned"] : [];
      for (const entry of r.json.data)
        if (/^(workspace|role|role_assignment|user|group|secret)\./.test(entry.action))
          problems.push(`tenant action ${entry.action} in the platform log`);
      return problems;
    },
  );
}
{
  const add = group("HTTP edge: Idempotency-Key");
  const post = (x, who, path, body, key, extra = {}) =>
    x.api("POST", path, { cookie: S(who)(x), body, headers: { "idempotency-key": key }, ...extra });
  /** A second Admin in the fresh tenant: invited by the owner, accepts, then receives the built-in Admin role at tenant scope. */
  const secondAdmin = () =>
    once("edge-second-admin", async () => {
      const t = await edgeTenant();
      const email = `second.${w.suffix}@iso.example`;
      const invited = await w.api("POST", "/users", {
        cookie: t.owner,
        body: { email, name: "Second Admin" },
      });
      if (invited.status !== 201) throw new Error(`invite answered ${invited.status}`);
      const login = await w.api("POST", "/auth/login", {
        body: { email, password: w.secrets.tenantPassword },
      });
      await w.api("POST", `/me/invitations/${t.id}/accept`, { cookie: login.cookie });
      await w.api("PUT", "/me/active-tenant", { cookie: login.cookie, body: { tenantId: t.id } });
      const me = await w.api("GET", "/me", { cookie: login.cookie });
      const role = (await w.api("GET", "/roles?q=Admin", { cookie: t.owner })).json.data.find(
        (r) => r.name === "Admin",
      );
      const assigned = await w.api("POST", "/role-assignments", {
        cookie: t.owner,
        body: { subjectType: "user", subjectId: me.json.data.user.id, roleId: role.id },
      });
      if (assigned.status !== 201) throw new Error(`assignment answered ${assigned.status}`);
      return { cookie: login.cookie };
    });
  const withCookie = (cookie, path, body, key) =>
    w.api("POST", path, { cookie, body, headers: { "idempotency-key": key } });
  const scenario = () =>
    once("idem", async () => {
      const t = await edgeTenant();
      const second = await secondAdmin();
      const key = KEY("same");
      const body = { name: `Idem group ${w.suffix}` };
      const first = await post(w, "admin", "/groups", body, key);
      const replay = await post(w, "admin", "/groups", body, key);
      const different = await post(w, "admin", "/groups", { name: `Other group ${w.suffix}` }, key);
      const shared = KEY("shared");
      const sharedBody = { name: `Shared key group ${w.suffix}` };
      const mine = await post(w, "admin", "/groups", sharedBody, shared);
      const otherTenant = await withCookie(t.owner, "/groups", sharedBody, shared);
      const actorKey = KEY("actors");
      const byOwner = await withCookie(
        t.owner,
        "/groups",
        { name: `Actor group owner ${w.suffix}` },
        actorKey,
      );
      const bySecond = await withCookie(
        second.cookie,
        "/groups",
        { name: `Actor group second ${w.suffix}` },
        actorKey,
      );
      const bad = await post(w, "admin", "/groups", body, "x");
      return {
        first,
        second: replay,
        different,
        mine,
        otherTenant,
        byAdmin: byOwner,
        byManager: bySecond,
        bad,
      };
    });
  add(
    "IDM-001",
    "same key and same request replays the stored response and creates nothing twice",
    { status: 201 },
    async () => (await scenario()).second,
    async (r) => {
      const { first } = await scenario();
      const problems = [];
      if (first.status !== 201) problems.push(`first answered ${first.status}`);
      if (r.json.data.id !== first.json.data.id)
        problems.push("the replay returned a different resource");
      if (r.headers.get("idempotent-replayed") !== "true")
        problems.push("missing Idempotent-Replayed header");
      if (first.headers.get("idempotent-replayed"))
        problems.push("the first response claims to be a replay");
      return problems;
    },
  );
  add(
    "IDM-002",
    "same key with a different request is refused",
    { status: 409, code: "IDEMPOTENCY_CONFLICT" },
    async () => (await scenario()).different,
    (r) =>
      r.json.error.details?.reason === "different_request"
        ? []
        : [`reason ${r.json.error.details?.reason}`],
  );
  add(
    "IDM-003",
    "the same key used by another tenant never replays tenant A's response",
    { status: 201 },
    async () => (await scenario()).otherTenant,
    async (r) => {
      const { mine } = await scenario();
      const problems = [];
      if (r.json.data.id === mine.json.data.id)
        problems.push("tenant B received tenant A's resource");
      if (r.headers.get("idempotent-replayed")) problems.push("tenant B got a replay");
      if (JSON.stringify(r.json).includes(mine.json.data.id))
        problems.push("tenant A's id appears in tenant B's response");
      return problems;
    },
  );
  add(
    "IDM-004",
    "the same key used by another administrator of the same tenant is a separate key (no replay, no conflict)",
    { status: 201 },
    async () => (await scenario()).byManager,
    async (r) => {
      const { byAdmin } = await scenario();
      const problems = [];
      if (byAdmin.status !== 201) problems.push(`owner answered ${byAdmin.status}`);
      if (r.json.data.id === byAdmin.json.data.id)
        problems.push("the second administrator received the owner's resource");
      if (r.headers.get("idempotent-replayed"))
        problems.push("the second administrator got a replay");
      return problems;
    },
  );
  add(
    "IDM-005",
    "a malformed Idempotency-Key is rejected before anything is created",
    INVALID,
    async () => (await scenario()).bad,
  );
}
{
  const add = group("HTTP edge: entitlements");
  const noPlan = () =>
    once("no-plan-tenant", () => w.provisionTenant("noplan", { withPlan: false }));
  const limited = () =>
    once("limited-tenant", async () => {
      const t = await w.provisionTenant("limited");
      const db = suiteDb();
      const entry = await db.entitlementCatalog.findUnique({ where: { key: "workspaces.max" } });
      await db.tenantEntitlement.create({
        data: {
          tenantId: t.id,
          entitlementId: entry.id,
          enabled: true,
          limitValue: 1n,
          source: "security-suite",
        },
      });
      const first = await w.api("POST", "/workspaces", {
        cookie: t.owner,
        body: { name: `First ${w.suffix}` },
      });
      const second = await w.api("POST", "/workspaces", {
        cookie: t.owner,
        body: { name: `Second ${w.suffix}` },
      });
      return { first, second };
    });
  add(
    "ENT-001",
    "a tenant without a plan cannot create a workspace",
    { status: 403, code: "ENTITLEMENT_REQUIRED" },
    async () =>
      w.api("POST", "/workspaces", {
        cookie: (await noPlan()).owner,
        body: { name: `Nope ${w.suffix}` },
      }),
    (r) =>
      r.json.error.details?.entitlement === "workspaces.max"
        ? []
        : [`details ${JSON.stringify(r.json.error.details)}`],
  );
  add(
    "ENT-002",
    "a tenant without a plan cannot invite users",
    { status: 403, code: "ENTITLEMENT_REQUIRED" },
    async () =>
      w.api("POST", "/users", {
        cookie: (await noPlan()).owner,
        body: { email: `nope.${w.suffix}@iso.example`, name: "Nope" },
      }),
  );
  add(
    "ENT-003",
    "a tenant at its workspace limit is refused with QUOTA_EXCEEDED while the first workspace was allowed",
    { status: 403, code: "QUOTA_EXCEEDED" },
    async () => (await limited()).second,
    async (r) => {
      const { first } = await limited();
      const problems = first.status === 201 ? [] : [`the first workspace answered ${first.status}`];
      if (r.json.error.details?.limit !== 1) problems.push(`limit ${r.json.error.details?.limit}`);
      return problems;
    },
  );
  add(
    "ENT-004",
    "quota consumption is atomic and refuses beyond the limit (scans.monthly)",
    { status: 200 },
    async () => {
      const t = await w.provisionTenant("quota");
      const { createEntitlementService, createEntitlementRepository } =
        await import("@qmentisai/db");
      const service = createEntitlementService({
        repository: createEntitlementRepository({ db: suiteDb() }),
      });
      const def = await suiteDb().quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
      await suiteDb().tenantQuota.create({
        data: { tenantId: t.id, quotaDefinitionId: def.id, limitValue: 3n },
      });
      const results = await Promise.all(
        Array.from({ length: 6 }, () =>
          service
            .consumeQuota({ tenantId: t.id, quotaKey: "scans.monthly", periodKey: "2026-11" })
            .then(
              () => "ok",
              (e) => e.code,
            ),
        ),
      );
      const used = (
        await suiteDb().tenantQuotaUsage.findFirst({
          where: { tenantId: t.id, quotaDefinitionId: def.id },
        })
      )?.used;
      const problems = [];
      if (results.filter((v) => v === "ok").length !== 3)
        problems.push(`allowed ${results.filter((v) => v === "ok").length} of 6, expected 3`);
      if (results.filter((v) => v === "QUOTA_EXCEEDED").length !== 3)
        problems.push(`refusals: ${results}`);
      if (used !== 3n) problems.push(`recorded usage ${used}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "ENT-005",
    "quota consumption through a transaction client is atomic with the caller's writes, refuses beyond the limit, stays inside its tenant and cannot overshoot under a race",
    { status: 200 },
    async () => {
      const { createEntitlementService, createEntitlementRepository } =
        await import("@qmentisai/db");
      const db = suiteDb();
      const service = createEntitlementService({
        repository: createEntitlementRepository({ db }),
      });
      const x = await w.provisionTenant("quotatx-x");
      const y = await w.provisionTenant("quotatx-y");
      const def = await db.quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
      for (const t of [x, y])
        await db.tenantQuota.create({
          data: { tenantId: t.id, quotaDefinitionId: def.id, limitValue: 3n },
        });
      const periodKey = "2026-12";
      const usage = async (t) =>
        Number(
          (
            await db.tenantQuotaUsage.findFirst({
              where: { tenantId: t.id, quotaDefinitionId: def.id, periodKey },
            })
          )?.used ?? 0,
        );
      const consume = (t, client, amount = 1) =>
        service.consumeQuota(
          { tenantId: t.id, quotaKey: "scans.monthly", amount, periodKey },
          client,
        );
      const ROLLBACK = new Error("rollback");
      const rolledBack = (fn) =>
        db
          .$transaction(async (tx) => {
            await fn(tx);
            throw ROLLBACK;
          })
          .then(
            () => "committed",
            (e) => (e === ROLLBACK ? "rolled back" : Promise.reject(e)),
          );
      const problems = [];
      const expect = (label, actual, wanted) => {
        if (actual !== wanted) problems.push(`${label}: ${actual}, expected ${wanted}`);
      };

      // (a) consumed inside a transaction that is rolled back: usage unchanged (the control proves the consume itself worked).
      let inside = null;
      expect(
        "(a) transaction",
        await rolledBack(async (tx) => {
          inside = (await consume(x, tx)).used;
        }),
        "rolled back",
      );
      expect("(a) usage seen inside the transaction", inside, 1);
      expect("(a) usage after rollback", await usage(x), 0);

      // (b) committed: exactly the consumed amount persists.
      await db.$transaction(async (tx) => {
        await consume(x, tx, 2);
      });
      expect("(b) usage after commit", await usage(x), 2);

      // (c) a consume that would exceed the limit inside a transaction is refused and consumes nothing.
      const refused = await db
        .$transaction(async (tx) => {
          await consume(x, tx, 1);
          return consume(x, tx, 2);
        })
        .then(
          () => "ok",
          (e) => e.code,
        );
      expect("(c) over-limit consume", refused, "QUOTA_EXCEEDED");
      expect("(c) usage after the refused transaction", await usage(x), 2);

      // (d) a release inside a transaction is rolled back with it.
      let released = null;
      await rolledBack(async (tx) => {
        await service.releaseQuota(
          { tenantId: x.id, quotaKey: "scans.monthly", amount: 2, periodKey },
          tx,
        );
        released = await tx.tenantQuotaUsage.findFirst({
          where: { tenantId: x.id, quotaDefinitionId: def.id, periodKey },
        });
      });
      expect("(d) usage seen inside the transaction after release", Number(released?.used), 0);
      expect("(d) usage after rollback", await usage(x), 2);

      // (e) another tenant's consumption never touches X, and two transactions racing for the last unit: exactly one wins.
      await db.$transaction(async (tx) => {
        await consume(y, tx, 2);
      });
      expect("(e) usage of Y", await usage(y), 2);
      expect("(e) usage of X after Y consumed", await usage(x), 2);
      const racer = (t) =>
        db
          .$transaction(async (tx) => {
            await consume(t, tx);
            await new Promise((r) => setTimeout(r, 200));
          })
          .then(
            () => "ok",
            (e) => e.code,
          );
      const race = await Promise.all([racer(x), racer(x)]);
      expect("(e) racers that won", race.filter((v) => v === "ok").length, 1);
      expect("(e) racers refused", race.filter((v) => v === "QUOTA_EXCEEDED").length, 1);
      expect("(e) usage of X after the race", await usage(x), 3);
      expect("(e) usage of Y after the race", await usage(y), 2);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}
{
  const add = group("HTTP edge: CORS and route limits");
  const preflight = (origin) =>
    client.request("OPTIONS", "/api/v1/me", {
      headers: { origin, "access-control-request-method": "GET" },
    });
  add(
    "COR-001",
    "a preflight from an unknown origin gets no CORS permission",
    { status: 200 },
    () => preflight(EVIL_ORIGIN),
    (r) => {
      const problems = [];
      if (r.headers.get("access-control-allow-origin"))
        problems.push(`allow-origin ${r.headers.get("access-control-allow-origin")}`);
      if (r.headers.get("access-control-allow-credentials")) problems.push("credentials allowed");
      return problems;
    },
  );
  add(
    "COR-002",
    "a preflight from the configured tenant-web origin is allowed with credentials, for that origin only",
    { status: 204 },
    () => preflight(ALLOWED_ORIGIN),
    (r) => {
      const problems = [];
      if (r.headers.get("access-control-allow-origin") !== ALLOWED_ORIGIN)
        problems.push(`allow-origin ${r.headers.get("access-control-allow-origin")}`);
      if (r.headers.get("access-control-allow-credentials") !== "true")
        problems.push("credentials not allowed");
      return problems;
    },
  );
  add(
    "COR-003",
    "a response to an unknown origin carries no CORS headers (the browser cannot read it)",
    { status: 200 },
    () => client.request("GET", "/health", { headers: { origin: EVIL_ORIGIN } }),
    (r) =>
      r.headers.get("access-control-allow-origin") ||
      r.headers.get("access-control-allow-credentials")
        ? ["CORS headers present"]
        : [],
  );
  add(
    "RATE-001",
    "the per-route auth limit answers 429 RATE_LIMITED (scope route) after the configured number of requests, then recovers",
    RATE_LIMITED,
    async () => {
      let last;
      let count = 0;
      for (; count < 400; count += 1) {
        last = await w.api("POST", "/auth/logout");
        if (last.status === 429) break;
      }
      await sleep(5400);
      const after = await w.api("POST", "/auth/logout");
      return Object.assign(last, { count, after });
    },
    (r) => {
      const problems = [];
      if (r.json.error.details?.scope !== "route")
        problems.push(`scope ${r.json.error.details?.scope}`);
      if (!(r.count >= 100 && r.count <= 210)) problems.push(`limited after ${r.count} requests`);
      if (r.after.status !== 200)
        problems.push(`still limited after the window (${r.after.status})`);
      return problems;
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 10. GitHub integration: workspace-level linking (SCM, SPEC §18). The App is a local stub (no network); see helpers/github-stub.js.
// ---------------------------------------------------------------------------------------------------------------------
const STUB = env("SECURITY_GITHUB_STUB_URL");
const stubCtl = (path, body) =>
  fetch(STUB + path, { method: "POST", body: JSON.stringify(body) }).then((r) => r.json());
let installationCounter = 0;
const nextInstallationId = () => 700000000 + (Date.now() % 1000000) * 10 + installationCounter++;
const ghPath = (workspaceId) => `/workspaces/${workspaceId}/integrations/github`;
/** A fresh sign-in (a new session) of one of the seeded tenant-A users. */
const loginAs = async (email) => {
  const response = await w.api("POST", "/auth/login", {
    body: { email, password: w.secrets.tenantPassword },
  });
  assert.equal(response.status, 200, `fixture: sign-in of ${email} answered ${response.status}`);
  return response.cookie;
};
/** A workspace of the edge tenant (another tenant) the suite can link GitHub into. */
const edgeWorkspace = () =>
  once("edge-scm-workspace", async () => {
    const edge = await edgeTenant();
    const response = await w.api("POST", "/workspaces", {
      cookie: edge.owner,
      body: { name: `Edge SCM ${w.suffix}` },
    });
    assert.equal(response.status, 201, `fixture: edge workspace answered ${response.status}`);
    return response.json.data.id;
  });
const meId = async (cookie) => (await w.api("GET", "/me", { cookie })).json.data.user.id;
const tenantIdA = () => once("tenant-a-id", () => tenantIdOf(w, "admin"));
/**
 * Steps 1 and 2 of the documented linking sequence against the stub: set up GitHub's side, then ask for our single-use state
 * in a workspace. `orgRole`: the user's role in the organization ("admin", "member"); omit for a personal account. Omit
 * `installationId` for a new installation; pass it (without `repos`) to reuse an installation that is already set up.
 */
async function mintState(
  cookie,
  { workspaceId, installationId, account, user, orgRole, listed = true, repos },
) {
  const fresh = installationId === undefined;
  const id = installationId ?? nextInstallationId();
  await stubCtl("/__control/installation", {
    id,
    account,
    ...(repos ? { repos } : fresh ? { repos: [] } : {}),
  });
  const code = `code-${randomBytes(6).toString("hex")}`;
  await stubCtl("/__control/code", {
    code,
    user,
    installationIds: listed ? [id] : [],
    orgRoles: orgRole ? { [account.login]: { role: orgRole, state: "active" } } : {},
  });
  const auth = await w.api("POST", `${ghPath(workspaceId)}/authorize`, {
    cookie,
    body: { installationId: String(id) },
  });
  const state =
    auth.status === 200 ? new URL(auth.json.data.authorizeUrl).searchParams.get("state") : null;
  return { auth, state, code, installationId: id, workspaceId };
}
/** Step 3: verify and link. The workspace comes only from the stored state. */
const consumeState = (cookie, { code, state }) =>
  w.api("POST", "/integrations/github/links", { cookie, body: { code, state } });
/** The whole sequence. The result carries `auth` and, when a state was issued, `state`, `code` and `link`. */
async function linkFlow(cookie, options) {
  const minted = await mintState(cookie, options);
  if (!minted.state) return minted;
  return { ...minted, link: await consumeState(cookie, minted) };
}
const orgAccount = (label) => ({
  id: 880000 + Math.floor(Math.random() * 90000),
  login: `acme-${label}-${randomBytes(3).toString("hex")}`,
  type: "Organization",
});
const ghUser = () => ({
  id: 550000 + Math.floor(Math.random() * 90000),
  login: `dev-${randomBytes(3).toString("hex")}`,
});
/** Replaces the allow-list of a workspace link. */
const putAllowList = (cookie, workspaceId, workspaceLinkId, ids) =>
  w.api("PUT", `${ghPath(workspaceId)}/links/${workspaceLinkId}/repositories`, {
    cookie,
    body: { externalRepoIds: ids.map(String) },
  });
const connectRepo = (cookie, workspaceId, workspaceLinkId, externalRepoId, key) =>
  w.api("POST", `/workspaces/${workspaceId}/repositories`, {
    cookie,
    body: { workspaceLinkId, externalRepoId: String(externalRepoId) },
    ...(key ? { headers: { "idempotency-key": key } } : {}),
  });
/** Runs `fn` while `userCookie`'s owner also holds a role (assigned by the tenant-A administrator), then removes it. */
async function withRole({ userId, roleId, workspaceId }, fn) {
  const admin = S("admin")(w);
  const path = workspaceId ? `/workspaces/${workspaceId}/role-assignments` : "/role-assignments";
  const made = await w.api("POST", path, {
    cookie: admin,
    body: { subjectType: "user", subjectId: userId, roleId },
  });
  assert.equal(
    made.status,
    201,
    `fixture: role assignment answered ${made.status} ${JSON.stringify(made.json?.error)}`,
  );
  try {
    return await fn();
  } finally {
    const removed = await w.api("DELETE", `${path}/${made.json.data.id}`, { cookie: admin });
    assert.ok(
      removed.status < 300,
      `fixture: removing the role assignment answered ${removed.status} ${JSON.stringify(removed.json?.error)}`,
    );
  }
}
/** A custom role holding only workspace_integration.manage (and what it needs to see the workspace). */
const integrationManagerRoleId = () =>
  once("scm-integration-manager-role", async () => {
    const made = await w.api("POST", "/roles", {
      cookie: S("admin")(w),
      body: {
        name: `SCM integration manager ${w.suffix}`,
        description: "workspace_integration.manage only",
        permissions: [
          "workspace.view",
          "workspace_integration.view",
          "workspace_integration.manage",
        ],
      },
    });
    assert.equal(made.status, 201, `fixture: custom role answered ${made.status}`);
    return made.json.data.id;
  });
/** A tenant-scope custom role holding only integration.view (the read-only list of installations). */
const viewOnlyRoleId = () =>
  once("scm-view-only-role", async () => {
    const made = await w.api("POST", "/roles", {
      cookie: S("admin")(w),
      body: {
        name: `SCM view only ${w.suffix}`,
        description: "integration.view only",
        permissions: ["integration.view"],
      },
    });
    assert.equal(made.status, 201, `fixture: custom role answered ${made.status}`);
    return made.json.data.id;
  });
{
  const add = group("GitHub integration: linking");
  const asA = () => S("admin")(w);
  const PAY = () => w.A.paymentsWs;
  const IDN = () => w.A.identityWs;
  const scenario = () =>
    once("scm-linking", async () => {
      const edge = await edgeTenant();
      const edgeWs = await edgeWorkspace();
      const user = ghUser();
      const account = orgAccount("a");
      const adminLink = await linkFlow(asA(), {
        workspaceId: PAY(),
        account,
        user,
        orgRole: "admin",
      });
      // tenant E (a different tenant) tries to link the very same installation with a perfectly valid GitHub user
      const sameInstallation = await linkFlow(edge.owner, {
        workspaceId: edgeWs,
        installationId: adminLink.installationId,
        account,
        user,
        orgRole: "admin",
      });
      const memberAccount = orgAccount("m");
      const memberLink = await linkFlow(asA(), {
        workspaceId: PAY(),
        account: memberAccount,
        user: ghUser(),
        orgRole: "member",
      });
      const personalUser = ghUser();
      const personalMismatch = await linkFlow(asA(), {
        workspaceId: PAY(),
        account: { id: personalUser.id + 1, login: personalUser.login, type: "User" },
        user: personalUser,
      });
      const personalOwn = await linkFlow(asA(), {
        workspaceId: PAY(),
        account: { id: personalUser.id, login: personalUser.login, type: "User" },
        user: personalUser,
      });
      const notListed = await linkFlow(asA(), {
        workspaceId: PAY(),
        account: orgAccount("n"),
        user: ghUser(),
        orgRole: "admin",
        listed: false,
      });
      // state: single use, and bound to the tenant that asked for it
      const stateUse = await linkFlow(asA(), {
        workspaceId: PAY(),
        account: orgAccount("s"),
        user: ghUser(),
        orgRole: "admin",
      });
      const reused = await consumeState(asA(), stateUse);
      const foreignState = await (async () => {
        const minted = await mintState(asA(), {
          workspaceId: PAY(),
          account: orgAccount("f"),
          user: ghUser(),
          orgRole: "admin",
        });
        return consumeState(edge.owner, minted);
      })();
      const viewerStart = await w.api("POST", `${ghPath(PAY())}/start`, {
        cookie: S("viewer")(w),
      });
      const listA = await w.api("GET", "/integrations/github/installations", { cookie: asA() });
      const listEdge = await w.api("GET", "/integrations/github/installations", {
        cookie: edge.owner,
      });
      const edgeOverview = await w.api("GET", ghPath(edgeWs), { cookie: edge.owner });
      const paymentsOverview = await w.api("GET", ghPath(PAY()), { cookie: asA() });
      return {
        stateUse,
        memberAccount,
        adminLink,
        sameInstallation,
        memberLink,
        personalMismatch,
        personalOwn,
        notListed,
        reused,
        foreignState,
        viewerStart,
        listA,
        listEdge,
        edgeOverview,
        paymentsOverview,
        account,
      };
    });
  add(
    "SCM-005",
    "linking an installation that is already linked to another tenant is a generic 409 and leaves the first link untouched",
    { status: 409, code: "CONFLICT" },
    async () => (await scenario()).sameInstallation.link,
    async (r) => {
      const x = await scenario();
      const problems = [];
      if (x.adminLink.link.status !== 201)
        problems.push(`the first link answered ${x.adminLink.link.status}`);
      if (r.json.error.details?.reason !== "installation_unavailable")
        problems.push(`reason ${r.json.error.details?.reason}`);
      const text = JSON.stringify(r.json);
      const first = x.adminLink.link.json.data;
      if (
        text.includes(x.account.login) ||
        text.includes(first.id) ||
        text.includes(first.installationLinkId)
      )
        problems.push("the refusal reveals the other tenant's link or account");
      if (
        !x.listA.json.data.items.some(
          (l) => l.id === first.installationLinkId && l.status === "linked",
        )
      )
        problems.push("the first tenant's link changed");
      if (x.listEdge.json.data.items.some((l) => l.account.login === x.account.login))
        problems.push("the second tenant ended up with a link");
      if (x.edgeOverview.json.data.items.length !== 0)
        problems.push("the second tenant's workspace ended up with a link");
      return problems;
    },
  );
  add(
    "SCM-013",
    "linking an organization installation as a plain member of that organization is refused and creates no link",
    FORBIDDEN,
    async () => (await scenario()).memberLink.link,
    async () => {
      const x = await scenario();
      return x.listA.json.data.items.some((l) => l.account.login === x.memberAccount.login) ||
        x.paymentsOverview.json.data.items.some((l) => l.account.login === x.memberAccount.login)
        ? ["a link was created for the organization"]
        : [];
    },
  );
  add(
    "SCM-014",
    "linking a personal-account installation whose account is not the authorized user is refused, while the account owner can link it",
    FORBIDDEN,
    async () => (await scenario()).personalMismatch.link,
    async () => {
      const x = await scenario();
      return x.personalOwn.link.status === 201
        ? []
        : [`the account owner got ${x.personalOwn.link.status}`];
    },
  );
  add(
    "SCM-018",
    "an installation the authorized user cannot see is refused",
    FORBIDDEN,
    async () => (await scenario()).notListed.link,
  );
  add(
    "SCM-019",
    "the single-use state works once only, and another tenant cannot consume it",
    { status: 400, code: "BAD_REQUEST" },
    async () => (await scenario()).reused,
    async () => {
      const x = await scenario();
      const problems = [];
      if (x.stateUse.link.status !== 201)
        problems.push(`the first use answered ${x.stateUse.link.status}`);
      if (x.foreignState.status !== 400)
        problems.push(`another tenant's use answered ${x.foreignState.status}`);
      return problems;
    },
  );
  add(
    "SCM-020",
    "only holders of workspace_integration.manage can start linking: a viewer gets 403",
    FORBIDDEN,
    async () => (await scenario()).viewerStart,
  );

  // ---- who may link (SPEC §18.3 items 2 and 3)
  const managerScenario = () =>
    once("scm-manager-link", async () => {
      const manager = S("manager")(w);
      const account = orgAccount("mg");
      const user = ghUser();
      const own = await linkFlow(manager, { workspaceId: PAY(), account, user, orgRole: "admin" });
      const hidden = await linkFlow(manager, {
        workspaceId: IDN(),
        account: orgAccount("mh"),
        user: ghUser(),
        orgRole: "admin",
      });
      return {
        own,
        hidden,
        account,
        paymentsOverview: await w.api("GET", ghPath(PAY()), { cookie: manager }),
        identityOverview: await w.api("GET", ghPath(IDN()), { cookie: asA() }),
        tenantList: await w.api("GET", "/integrations/github/installations", { cookie: manager }),
        tenantSettings: await w.api("PUT", "/integrations/settings", {
          cookie: manager,
          body: { allowWorkspaceLinking: true },
        }),
      };
    });
  add(
    "SCM-027",
    "a workspace-scoped Manager without tenant Admin completes the whole link flow (201) in their own workspace, and gets 404 for a workspace they cannot see",
    { status: 201 },
    async () => (await managerScenario()).own.link,
    async () => {
      const x = await managerScenario();
      const problems = [];
      if (x.own.link.json.data.workspaceId !== PAY())
        problems.push("the link is in another workspace");
      if (x.hidden.auth.status !== 404)
        problems.push(`a workspace they cannot see answered ${x.hidden.auth.status}`);
      if (x.identityOverview.json.data.items.some((l) => l.account.login === x.account.login))
        problems.push("the link also appears in another workspace");
      if (!x.paymentsOverview.json.data.items.some((l) => l.account.login === x.account.login))
        problems.push("the workspace overview does not show the new link");
      // the Manager really holds no tenant keys: the tenant installation list and the tenant setting are refused
      if (x.tenantList.status !== 403) problems.push(`tenant list answered ${x.tenantList.status}`);
      if (x.tenantSettings.status !== 403)
        problems.push(`tenant setting answered ${x.tenantSettings.status}`);
      return problems;
    },
  );
  add(
    "SCM-028",
    "Viewer, Developer, Lead, Dev Lead and Security Analyst cannot start or authorize linking in a workspace they can see (403), the Manager can",
    FORBIDDEN,
    async () => {
      const devLead = await loginAs("demo.devlead@demo.example");
      const analyst = await loginAs("demo.analyst@demo.example");
      const who = {
        viewer: S("viewer")(w),
        developer: S("developer")(w),
        lead: S("lead")(w),
        devLead,
        analyst,
      };
      const results = {};
      for (const [name, cookie] of Object.entries(who)) {
        results[name] = {
          start: await w.api("POST", `${ghPath(PAY())}/start`, { cookie }),
          authorize: await w.api("POST", `${ghPath(PAY())}/authorize`, {
            cookie,
            body: { installationId: "1" },
          }),
        };
      }
      const control = await w.api("POST", `${ghPath(PAY())}/start`, { cookie: S("manager")(w) });
      return Object.assign({}, results.viewer.start, { results, control });
    },
    (r) => {
      const problems = [];
      for (const [name, res] of Object.entries(r.results))
        for (const [op, answer] of Object.entries(res))
          if (answer.status !== 403) problems.push(`${name} ${op} answered ${answer.status}`);
      if (r.control.status !== 200)
        problems.push(`the manager's start answered ${r.control.status}`);
      return problems;
    },
  );
  const secondScenario = () =>
    once("scm-second-ws", async () => {
      const admin = asA();
      const account = orgAccount("sw");
      const user = ghUser();
      const first = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user,
        orgRole: "admin",
        repos: [],
      });
      // D5 is evaluated again for the second workspace, for the person linking: an organization member is refused
      const memberSecond = await linkFlow(admin, {
        workspaceId: IDN(),
        installationId: first.installationId,
        account,
        user: ghUser(),
        orgRole: "member",
      });
      const identityAfterMember = await w.api("GET", ghPath(IDN()), { cookie: admin });
      const second = await linkFlow(admin, {
        workspaceId: IDN(),
        installationId: first.installationId,
        account,
        user,
        orgRole: "admin",
      });
      return {
        account,
        first,
        memberSecond,
        identityAfterMember,
        second,
        list: await w.api("GET", "/integrations/github/installations", { cookie: admin }),
        paymentsOverview: await w.api("GET", ghPath(PAY()), { cookie: admin }),
        identityOverview: await w.api("GET", ghPath(IDN()), { cookie: admin }),
      };
    });
  add(
    "SCM-029",
    "the same tenant linking a second workspace to the same installation reuses it (201, no 409): one installation record, two workspace links",
    { status: 201 },
    async () => (await secondScenario()).second.link,
    async () => {
      const x = await secondScenario();
      const problems = [];
      const a = x.first.link.json?.data;
      const b = x.second.link.json?.data;
      if (x.first.link.status !== 201)
        problems.push(`the first link answered ${x.first.link.status}`);
      if (a?.installationLinkId !== b?.installationLinkId)
        problems.push("the second workspace did not reuse the tenant installation link");
      if (a?.id === b?.id || a?.workspaceId === b?.workspaceId)
        problems.push("the two workspaces share one workspace link");
      const items = x.list.json.data.items.filter((l) => l.account.login === x.account.login);
      if (items.length !== 1 || items[0].workspaceCount !== 2)
        problems.push(`installations ${items.length}, workspaces ${items[0]?.workspaceCount}`);
      return problems;
    },
  );
  add(
    "SCM-030",
    "linking a second workspace evaluates the GitHub-side ownership checks again for that person: an organization member is refused and no link is created",
    FORBIDDEN,
    async () => (await secondScenario()).memberSecond.link,
    async () => {
      const x = await secondScenario();
      const problems = [];
      if (x.first.link.status !== 201) problems.push("the first link was not created");
      if (x.identityAfterMember.json.data.items.length !== 0)
        problems.push("the refused person left a link behind");
      if (x.second.link.status !== 201)
        problems.push(`the organization admin got ${x.second.link.status}`);
      return problems;
    },
  );
  const bindingScenario = () =>
    once("scm-state-binding", async () => {
      const admin = asA();
      const manager = S("manager")(w);
      const account = orgAccount("sb");
      const user = ghUser();
      const installationId = nextInstallationId();
      const mint = (cookie = admin, workspaceId = PAY()) =>
        mintState(cookie, {
          workspaceId,
          installationId,
          account,
          user,
          orgRole: "admin",
        });
      await stubCtl("/__control/installation", { id: installationId, account, repos: [] });
      const byOtherUser = await (async () => consumeState(manager, await mint()))();
      const otherSession = await loginAs("demo.admin@demo.example");
      const byOtherSession = await (async () => consumeState(otherSession, await mint()))();
      // the consume request cannot name a workspace: an extra field is refused before the state is touched
      const withWorkspace = await (async () => {
        const minted = await mint();
        const refused = await w.api("POST", "/integrations/github/links", {
          cookie: admin,
          body: { code: minted.code, state: minted.state, workspaceId: IDN() },
        });
        return { minted, refused, accepted: await consumeState(admin, minted) };
      })();
      return {
        byOtherUser,
        byOtherSession,
        withWorkspace,
        account,
        identityOverview: await w.api("GET", ghPath(IDN()), { cookie: admin }),
        paymentsOverview: await w.api("GET", ghPath(PAY()), { cookie: admin }),
      };
    });
  add(
    "SCM-031",
    "a linking state cannot be consumed by another user or in another session, cannot be pointed at another workspace, and links only the workspace it was minted for",
    { status: 400, code: "BAD_REQUEST" },
    async () => (await bindingScenario()).byOtherUser,
    async () => {
      const x = await bindingScenario();
      const problems = [];
      if (x.byOtherSession.status !== 400)
        problems.push(`the same user in another session got ${x.byOtherSession.status}`);
      if (x.withWorkspace.refused.status !== 400)
        problems.push(`naming a workspace answered ${x.withWorkspace.refused.status}`);
      if (x.withWorkspace.accepted.status !== 201)
        problems.push(`the right user and session got ${x.withWorkspace.accepted.status}`);
      else if (x.withWorkspace.accepted.json.data.workspaceId !== PAY())
        problems.push("the link landed in another workspace");
      if (x.identityOverview.json.data.items.some((l) => l.account.login === x.account.login))
        problems.push("another workspace got a link");
      if (!x.paymentsOverview.json.data.items.some((l) => l.account.login === x.account.login))
        problems.push("the minted workspace got no link");
      return problems;
    },
  );
  const lostKeyScenario = () =>
    once("scm-lost-key", async () => {
      const analystId = w.A.user;
      const managerRole = await integrationManagerRoleId();
      const account = orgAccount("lk");
      const user = ghUser();
      const analyst = await loginAs("demo.analyst@demo.example");
      const withKey = await withRole(
        { userId: analystId, roleId: managerRole, workspaceId: IDN() },
        () => linkFlow(analyst, { workspaceId: IDN(), account, user, orgRole: "admin" }),
      );
      const lost = await (async () => {
        const account2 = orgAccount("lk2");
        let minted;
        await withRole({ userId: analystId, roleId: managerRole, workspaceId: IDN() }, async () => {
          minted = await mintState(analyst, {
            workspaceId: IDN(),
            account: account2,
            user,
            orgRole: "admin",
          });
        });
        // the assignment is gone now: the state is still valid, the person no longer holds the key
        return { minted, consume: await consumeState(analyst, minted), account: account2 };
      })();
      return {
        withKey,
        lost,
        identityOverview: await w.api("GET", ghPath(IDN()), { cookie: S("admin")(w) }),
      };
    });
  add(
    "SCM-032",
    "consuming a state re-checks workspace_integration.manage: a person who lost the key after minting is refused (403) and nothing is linked",
    FORBIDDEN,
    async () => (await lostKeyScenario()).lost.consume,
    async () => {
      const x = await lostKeyScenario();
      const problems = [];
      if (x.withKey.auth.status !== 200 || x.withKey.link.status !== 201)
        problems.push(
          `with the key: authorize ${x.withKey.auth.status}, link ${x.withKey.link?.status}`,
        );
      if (x.lost.minted.auth.status !== 200) problems.push("the state could not be minted");
      if (x.identityOverview.json.data.items.some((l) => l.account.login === x.lost.account.login))
        problems.push("a link was created without the key");
      return problems;
    },
  );
  add(
    "SCM-046",
    "the setup URL's installation_id is only a hint: authorize needs a signed-in holder of workspace_integration.manage, and a tampered, truncated, garbage, foreign or reused state links nothing",
    UNAUTHENTICATED,
    async () => {
      const admin = S("admin")(w);
      const developer = S("developer")(w);
      const unauthenticated = await w.api("POST", `${ghPath(w.A.paymentsWs)}/authorize`, {
        body: { installationId: "123456" },
      });
      const account = orgAccount("h");
      const minted = await mintState(admin, {
        workspaceId: w.A.paymentsWs,
        account,
        user: ghUser(),
        orgRole: "admin",
      });
      const state = minted.state;
      const flipped = state.slice(0, -1) + (state.at(-1) === "A" ? "B" : "A");
      const attempts = {
        tampered: await consumeState(admin, { code: minted.code, state: flipped }),
        truncated: await consumeState(admin, { code: minted.code, state: state.slice(0, 30) }),
        garbage: await consumeState(admin, { code: minted.code, state: "x".repeat(40) }),
        // someone else presents the genuine state (it is single use and bound to user and session)
        foreign: await consumeState(developer, { code: minted.code, state }),
        // after that the owner cannot use it either
        reused: await consumeState(admin, { code: minted.code, state }),
      };
      const linkedAfter = await suiteDb().scmInstallation.count({
        where: { accountLogin: account.login },
      });
      // control: a fresh, genuine run by the same administrator links
      const control = await linkFlow(admin, {
        workspaceId: w.A.paymentsWs,
        account: orgAccount("hc"),
        user: ghUser(),
        orgRole: "admin",
      });
      return Object.assign({}, unauthenticated, { attempts, linkedAfter, control });
    },
    (r) => {
      const problems = [];
      for (const [name, res] of Object.entries(r.attempts))
        if (res.status !== 400) problems.push(`${name} state answered ${res.status}, not 400`);
      if (r.linkedAfter !== 0)
        problems.push("a refused state still created an installation record");
      if (r.control.link?.status !== 201)
        problems.push(`the control link answered ${r.control.link?.status}`);
      return problems;
    },
  );
  add(
    "SCM-033",
    "an expired linking state is refused (400) while a fresh one is accepted",
    { status: 400, code: "BAD_REQUEST" },
    async () => {
      const account = orgAccount("ex");
      const user = ghUser();
      const fresh = await linkFlow(asA(), { workspaceId: PAY(), account, user, orgRole: "admin" });
      const stale = await mintState(asA(), {
        workspaceId: PAY(),
        installationId: fresh.installationId,
        account,
        user,
        orgRole: "admin",
      });
      await sleep(3600); // SCM_LINK_STATE_TTL_SECONDS is 3 in this run (scripts/security-suite.js)
      return Object.assign(await consumeState(asA(), stale), { fresh });
    },
    (r) => (r.fresh.link?.status === 201 ? [] : [`the fresh state got ${r.fresh.link?.status}`]),
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 10b. GitHub integration: the tenant setting "allow workspace admins to link source control" (SPEC §18.6, Q28).
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("GitHub integration: tenant linking setting");
  const asA = () => S("admin")(w);
  const PAY = () => w.A.paymentsWs;
  const IDN = () => w.A.identityWs;
  const setting = (cookie, value) =>
    w.api("PUT", "/integrations/settings", { cookie, body: { allowWorkspaceLinking: value } });
  const defaultScenario = () =>
    once("scm-setting-default", async () => {
      const edge = await edgeTenant();
      const read = {
        admin: await w.api("GET", "/integrations/settings", { cookie: asA() }),
        edge: await w.api("GET", "/integrations/settings", { cookie: edge.owner }),
      };
      const writes = {};
      for (const who of ["manager", "lead", "developer", "viewer"])
        writes[who] = await setting(S(who)(w), false);
      const viewOnly = await withRole(
        { userId: await meId(S("manager")(w)), roleId: await viewOnlyRoleId() },
        async () => ({
          read: await w.api("GET", "/integrations/settings", { cookie: S("manager")(w) }),
          write: await setting(S("manager")(w), false),
        }),
      );
      // another tenant changing its own setting must not touch this tenant's
      const edgeOff = await setting(edge.owner, false);
      const adminAfterEdge = await w.api("GET", "/integrations/settings", { cookie: asA() });
      const edgeOn = await setting(edge.owner, true);
      const readAfter = await w.api("GET", "/integrations/settings", { cookie: asA() });
      return { read, writes, viewOnly, edgeOff, adminAfterEdge, edgeOn, readAfter };
    });
  add(
    "SCM-034",
    "the tenant linking setting is on by default; only integration.manage changes it (view-only and every other role get 403); another tenant's change does not touch it",
    FORBIDDEN,
    async () => (await defaultScenario()).writes.manager,
    async () => {
      const x = await defaultScenario();
      const problems = [];
      if (x.read.admin.status !== 200 || x.read.admin.json.data.allowWorkspaceLinking !== true)
        problems.push("the default is not on");
      for (const [who, res] of Object.entries(x.writes))
        if (res.status !== 403) problems.push(`${who} write answered ${res.status}`);
      if (x.viewOnly.read.status !== 200) problems.push(`view-only read ${x.viewOnly.read.status}`);
      if (x.viewOnly.write.status !== 403)
        problems.push(`view-only write ${x.viewOnly.write.status}`);
      if (x.edgeOff.status !== 200 || x.edgeOff.json.data.allowWorkspaceLinking !== false)
        problems.push("the other tenant could not change its own setting");
      if (x.adminAfterEdge.json.data.allowWorkspaceLinking !== true)
        problems.push("another tenant's change reached this tenant");
      if (x.readAfter.json.data.allowWorkspaceLinking !== true)
        problems.push("the setting changed without integration.manage");
      return problems;
    },
  );
  const offScenario = () =>
    once("scm-setting-off", async () => {
      const admin = asA();
      const manager = S("manager")(w);
      const user = ghUser();
      const account = orgAccount("off");
      // an existing link in two workspaces, and a state minted while linking is still allowed
      const linkedP = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user,
        orgRole: "admin",
        repos: [stubRepo(9100001), stubRepo(9100002)],
      });
      const linkedI = await linkFlow(admin, {
        workspaceId: IDN(),
        installationId: linkedP.installationId,
        account,
        user,
        orgRole: "admin",
      });
      const minted = await mintState(manager, {
        workspaceId: PAY(),
        account: orgAccount("off2"),
        user: ghUser(),
        orgRole: "admin",
      });
      const before = await w.api("POST", `${ghPath(PAY())}/start`, { cookie: manager });
      const off = await setting(admin, false);
      const out = {};
      try {
        out.start = await w.api("POST", `${ghPath(PAY())}/start`, { cookie: manager });
        out.authorize = await w.api("POST", `${ghPath(PAY())}/authorize`, {
          cookie: manager,
          body: { installationId: String(linkedP.installationId) },
        });
        out.consume = await consumeState(manager, minted);
        out.overview = await w.api("GET", ghPath(PAY()), { cookie: manager });
        // existing links keep working: test connection, allow-list edit and unlink are not blocked
        const wlP = linkedP.link.json.data.id;
        const wlI = linkedI.link.json.data.id;
        out.refresh = await w.api("POST", `${ghPath(PAY())}/links/${wlP}/refresh`, {
          cookie: manager,
        });
        out.allowList = await putAllowList(manager, PAY(), wlP, [9100001]);
        out.unlink = await w.api("DELETE", `${ghPath(IDN())}/links/${wlI}`, {
          cookie: admin,
          body: { confirm: account.login },
        });
      } finally {
        out.on = await setting(admin, true);
      }
      out.afterOn = await w.api("POST", `${ghPath(PAY())}/start`, { cookie: manager });
      const rows = await suiteDb().auditLog.findMany({
        where: {
          tenantId: await tenantIdA(),
          action: "scm_settings.workspace_linking_updated",
          actorUserId: await meId(admin),
        },
        orderBy: { createdAt: "desc" },
        take: 2,
      });
      return { before, off, out, rows };
    });
  add(
    "SCM-035",
    "with the setting off, starting, authorizing and consuming a linking state answer 403 workspace_linking_disabled with the documented message, while test connection, allow-list edits and unlink still work; both changes are audited",
    FORBIDDEN,
    async () => {
      const x = await offScenario();
      return x.out.start;
    },
    async () => {
      const x = await offScenario();
      const problems = [];
      if (x.before.status !== 200)
        problems.push(`start before turning it off answered ${x.before.status}`);
      if (x.off.status !== 200) problems.push(`turning it off answered ${x.off.status}`);
      for (const op of ["start", "authorize", "consume"]) {
        const res = x.out[op];
        if (res.status !== 403) problems.push(`${op} answered ${res.status}`);
        else {
          if (res.json.error.details?.reason !== "workspace_linking_disabled")
            problems.push(`${op} reason ${res.json.error.details?.reason}`);
          if (
            res.json.error.message !==
            "Your organization administrator has turned off linking source control from workspaces."
          )
            problems.push(`${op} message ${res.json.error.message}`);
        }
      }
      if (x.out.overview.json?.data?.linkingEnabled !== false)
        problems.push("the workspace overview still says linking is enabled");
      for (const op of ["refresh", "allowList"])
        if (x.out[op].status !== 200) problems.push(`${op} answered ${x.out[op].status}`);
      if (x.out.unlink.status !== 200) problems.push(`unlink answered ${x.out.unlink.status}`);
      if (x.out.on.status !== 200) problems.push("the setting could not be turned back on");
      if (x.out.afterOn.status !== 200)
        problems.push(`start after turning it on answered ${x.out.afterOn.status}`);
      const after = x.rows.map((r) => r.changes?.after?.allowWorkspaceLinking);
      const beforeValues = x.rows.map((r) => r.changes?.before?.allowWorkspaceLinking);
      if (x.rows.length < 2) problems.push(`${x.rows.length} audit entries`);
      else if (
        after[0] !== true ||
        beforeValues[0] !== false ||
        after[1] !== false ||
        beforeValues[1] !== true ||
        x.rows.some((r) => r.targetType !== "tenant_integration_settings")
      )
        problems.push(`audit entries ${JSON.stringify(x.rows.map((r) => r.changes))}`);
      return problems;
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 11. GitHub integration: webhook (SCM). The signature authenticates GitHub; the tenant comes only from the stored link.
// ---------------------------------------------------------------------------------------------------------------------
const WEBHOOK_SECRET = env("SECURITY_GITHUB_WEBHOOK_SECRET");
const signBody = (body, secret = WEBHOOK_SECRET) =>
  `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
/** POSTs a delivery to the webhook. `signature: null` omits the header; `secret` signs with another key. */
async function deliver({
  event = "installation",
  payload,
  rawBody,
  secret,
  signature,
  deliveryId = randomUUID(),
  cookie,
  contentType = "application/json",
}) {
  const body = rawBody ?? JSON.stringify(payload);
  const headers = {
    "content-type": contentType,
    "x-github-delivery": deliveryId,
    "x-github-event": event,
  };
  if (signature !== null) headers["x-hub-signature-256"] = signature ?? signBody(body, secret);
  if (cookie) headers.cookie = cookie;
  const response = await fetch(`${env("SECURITY_API_URL")}/api/v1/webhooks/github`, {
    method: "POST",
    headers,
    body,
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: response.status, json, deliveryId };
}
const noCorrelation = (json) => JSON.stringify({ ...json, meta: undefined });
const rowsFor = async (deliveryId) => {
  const db = suiteDb();
  return {
    delivery: await db.scmWebhookDelivery.findUnique({
      where: { provider_deliveryId: { provider: "github", deliveryId } },
    }),
    events: await db.scmEvent.findMany({ where: { deliveryId } }),
    outbox: await db.outboxMessage.findMany({ where: { messageId: `scm-github-${deliveryId}` } }),
  };
};
{
  const add = group("GitHub integration: webhook");
  const linked = () =>
    once("scm-webhook-link", async () => {
      const account = orgAccount("w");
      const flow = await linkFlow(S("admin")(w), {
        workspaceId: w.A.paymentsWs,
        account,
        user: ghUser(),
        orgRole: "admin",
      });
      if (flow.link.status !== 201) throw new Error(`link answered ${flow.link.status}`);
      return {
        installationId: flow.installationId,
        linkId: flow.link.json.data.installationLinkId,
        tenantId: (await w.api("GET", "/me", { cookie: S("admin")(w) })).json.data.tenant.id,
      };
    });
  const installationPayload = (installationId, action = "suspend") => ({
    action,
    installation: { id: Number(installationId), account: { login: "x" } },
  });
  add(
    "SCM-001",
    "a delivery with a forged signature is rejected with 401 and nothing is stored",
    { status: 401, code: "UNAUTHENTICATED" },
    async () => {
      const l = await linked();
      const r = await deliver({
        payload: installationPayload(l.installationId),
        secret: "not-the-webhook-secret",
      });
      return Object.assign(r, { rows: await rowsFor(r.deliveryId) });
    },
    (r) =>
      r.rows.delivery || r.rows.events.length || r.rows.outbox.length
        ? ["a forged delivery left rows behind"]
        : [],
  );
  add(
    "SCM-002",
    "missing, malformed and mismatched signatures are all rejected with 401",
    { status: 401, code: "UNAUTHENTICATED" },
    async () => {
      const l = await linked();
      const payload = installationPayload(l.installationId);
      const missing = await deliver({ payload, signature: null });
      const malformed = await deliver({ payload, signature: "sha256=zz" });
      const wrongPrefix = await deliver({ payload, signature: `sha1=${"a".repeat(64)}` });
      const otherBody = await deliver({
        payload,
        signature: signBody(JSON.stringify({ different: true })),
      });
      return Object.assign(missing, { others: [malformed, wrongPrefix, otherBody] });
    },
    (r) => r.others.filter((o) => o.status !== 401).map((o) => `answered ${o.status}`),
  );
  add(
    "SCM-006",
    "a signed delivery for an unknown installation is answered exactly like an accepted one and stores nothing tenant-scoped",
    { status: 202 },
    async () => {
      const l = await linked();
      const known = await deliver({ payload: installationPayload(l.installationId, "unsuspend") });
      const unknown = await deliver({
        payload: installationPayload(nextInstallationId(), "unsuspend"),
      });
      return Object.assign(unknown, { known, rows: await rowsFor(unknown.deliveryId) });
    },
    (r) => {
      const problems = [];
      if (r.known.status !== 202)
        problems.push(`the known installation answered ${r.known.status}`);
      if (noCorrelation(r.json) !== noCorrelation(r.known.json))
        problems.push("the unknown installation's answer differs from an accepted one");
      if (r.rows.delivery?.outcome !== "unknown_installation" || r.rows.delivery?.tenantId)
        problems.push(`delivery row ${JSON.stringify(r.rows.delivery)}`);
      if (r.rows.events.length || r.rows.outbox.length)
        problems.push("an unknown installation produced events");
      return problems;
    },
  );
  add(
    "SCM-011",
    "a signed-in tenant session grants nothing on the webhook: without a valid signature it is 401",
    { status: 401, code: "UNAUTHENTICATED" },
    async () => {
      const l = await linked();
      return deliver({
        payload: installationPayload(l.installationId),
        signature: "sha256=" + "0".repeat(64),
        cookie: S("admin")(w),
      });
    },
  );
  add(
    "SCM-015",
    "a signed payload without installation.id is not processed, yet is answered like an accepted delivery",
    { status: 202 },
    async () => {
      await linked();
      const r = await deliver({
        event: "push",
        payload: { ref: "refs/heads/main", repository: { id: 1 } },
      });
      return Object.assign(r, { rows: await rowsFor(r.deliveryId) });
    },
    (r) => {
      const problems = [];
      if (r.rows.delivery?.outcome !== "rejected_payload")
        problems.push(`outcome ${r.rows.delivery?.outcome}`);
      if (r.rows.events.length || r.rows.outbox.length)
        problems.push("a payload without installation.id produced events");
      return problems;
    },
  );
  add(
    "SCM-045",
    "GitHub identifiers above 2^53 stay exact end to end: link, allow-list, connect, a signed push with raw 64-bit integers, and the redelivery id",
    { status: 202 },
    async () => {
      const admin = S("admin")(w);
      // 2^53 + 1, + 3, + 5: none of them can be held exactly by a JavaScript Number
      const bigInstallation = "9007199254740993";
      const bigRepo = "9007199254740995";
      const bigAccount = "9007199254740997";
      const account = {
        id: bigAccount,
        login: `big-${randomBytes(3).toString("hex")}`,
        type: "Organization",
      };
      const flow = await linkFlow(admin, {
        workspaceId: w.A.paymentsWs,
        installationId: bigInstallation,
        account,
        user: ghUser(),
        orgRole: "admin",
        repos: [stubRepo(bigRepo)],
      });
      const workspaceLinkId = flow.link.json.data.id;
      const allow = await putAllowList(admin, w.A.paymentsWs, workspaceLinkId, [bigRepo]);
      const connected = await connectRepo(admin, w.A.paymentsWs, workspaceLinkId, bigRepo);
      const installations = await w.api("GET", "/integrations/github/installations", {
        cookie: admin,
      });
      const rawBody =
        '{"ref":"refs/heads/main","before":"' +
        "a".repeat(40) +
        '","after":"' +
        "b".repeat(40) +
        '","created":false,"deleted":false,"forced":false,"commits":[{"id":"' +
        "b".repeat(40) +
        '"}],"head_commit":{"id":"' +
        "b".repeat(40) +
        '"},"pusher":{"name":"dev"},"repository":{"id":' +
        bigRepo +
        '},"installation":{"id":' +
        bigInstallation +
        "}}";
      const delivery = await deliver({ event: "push", rawBody });
      return {
        ...delivery,
        flow,
        allow,
        connected,
        installations,
        rows: await rowsFor(delivery.deliveryId),
        bigRepo,
        bigInstallation,
        bigAccount,
      };
    },
    (r) => {
      const problems = [];
      if (r.flow.link?.status !== 201) problems.push(`linking answered ${r.flow.link?.status}`);
      if (r.allow.status !== 200) problems.push(`allow-list answered ${r.allow.status}`);
      if (r.connected.status !== 201) problems.push(`connect answered ${r.connected.status}`);
      else if (r.connected.json.data.externalRepoId !== r.bigRepo)
        problems.push("the repository id was altered");
      const installation = r.installations.json?.data?.items?.find(
        (i) => i.externalInstallationId === r.bigInstallation,
      );
      if (!installation) problems.push("the installation id was altered or missing");
      if (r.rows.delivery?.outcome !== "accepted")
        problems.push(`the push was ${r.rows.delivery?.outcome ?? "not recorded"}, not accepted`);
      if (r.rows.events.length !== 1)
        problems.push(`${r.rows.events.length} events for the push (a rounded id matches nothing)`);
      if (r.rows.delivery && r.rows.delivery.externalInstallationId !== r.bigInstallation)
        problems.push("the delivery row holds a different installation id");
      return problems;
    },
  );
  add(
    "SCM-021",
    "an installation event of a linked installation creates one normalized event and one outbox message in that tenant, and a duplicate delivery id creates no second",
    { status: 202 },
    async () => {
      const l = await linked();
      const deliveryId = randomUUID();
      const first = await deliver({
        payload: installationPayload(l.installationId, "new_permissions_accepted"),
        deliveryId,
      });
      const duplicate = await deliver({
        payload: installationPayload(l.installationId, "new_permissions_accepted"),
        deliveryId,
      });
      return Object.assign(first, {
        duplicate,
        rows: await rowsFor(deliveryId),
        tenantId: l.tenantId,
        linkId: l.linkId,
      });
    },
    (r) => {
      const problems = [];
      if (r.duplicate.status !== 202) problems.push(`the duplicate answered ${r.duplicate.status}`);
      if (r.rows.events.length !== 1 || r.rows.events[0].tenantId !== r.tenantId)
        problems.push(`events ${JSON.stringify(r.rows.events.map((e) => e.tenantId))}`);
      if (r.rows.outbox.length !== 1) problems.push(`${r.rows.outbox.length} outbox rows`);
      else {
        const o = r.rows.outbox[0];
        if (
          o.tenantId !== r.tenantId ||
          o.exchange !== "qmentis.scm.events" ||
          o.routingKey !== "scm.github.installation"
        )
          problems.push(`outbox ${o.tenantId} ${o.exchange} ${o.routingKey}`);
        if (JSON.stringify(o.payload).includes("secret"))
          problems.push("secret-like content in the message");
      }
      if (r.rows.delivery?.outcome !== "accepted")
        problems.push(`outcome ${r.rows.delivery?.outcome}`);
      return problems;
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 11b. GitHub integration: workspace permissions (SCM-022..026). workspace_integration.view / .manage are evaluated in the
//      workspace of the URL; a link id is bound to its workspace; tenant-level actions need tenant keys.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("GitHub integration: workspace permissions");
  const base = 5000000 + (Date.now() % 100000) * 10;
  const PAY = () => w.A.paymentsWs;
  const IDN = () => w.A.identityWs;
  const world = () =>
    once("scm-routing", async () => {
      const edge = await edgeTenant();
      const edgeWs = await edgeWorkspace();
      const admin = S("admin")(w);
      const manager = S("manager")(w);
      const lead = S("lead")(w);
      const developer = S("developer")(w);
      const account = orgAccount("w");
      const user = ghUser();
      const flowP = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user,
        orgRole: "admin",
        repos: [base + 1, base + 2, base + 3, base + 4].map(stubRepo),
      });
      const flowI = await linkFlow(admin, {
        workspaceId: IDN(),
        installationId: flowP.installationId,
        account,
        user,
        orgRole: "admin",
      });
      const wlP = flowP.link.json.data.id;
      const wlI = flowI.link.json.data.id;
      const read = {
        manager: await w.api("GET", ghPath(PAY()), { cookie: manager }),
        lead: await w.api("GET", ghPath(PAY()), { cookie: lead }),
        developer: await w.api("GET", ghPath(PAY()), { cookie: developer }),
        viewer: await w.api("GET", ghPath(PAY()), { cookie: S("viewer")(w) }),
        edgeOnA: await w.api("GET", ghPath(PAY()), { cookie: edge.owner }),
      };
      const leadWrite = await putAllowList(lead, PAY(), wlP, [base + 1]);
      const developerWrite = await putAllowList(developer, PAY(), wlP, [base + 1]);
      const leadStart = await w.api("POST", `${ghPath(PAY())}/start`, { cookie: lead });
      const leadRefresh = await w.api("POST", `${ghPath(PAY())}/links/${wlP}/refresh`, {
        cookie: lead,
      });
      const managerWrite = await putAllowList(manager, PAY(), wlP, [base + 1, base + 2]);
      const idAllow = await putAllowList(admin, IDN(), wlI, [base + 3]);
      // SCM-023: a workspace that is no longer linked cannot list or connect repositories through the connection
      const unlink = await w.api("DELETE", `${ghPath(IDN())}/links/${wlI}`, {
        cookie: admin,
        body: { confirm: account.login },
      });
      const unlinked = {
        picker: await w.api("GET", `${ghPath(IDN())}/links/${wlI}/repositories`, { cookie: admin }),
        available: await w.api(
          "GET",
          `/workspaces/${IDN()}/repositories/available?workspaceLinkId=${wlI}`,
          { cookie: admin },
        ),
        connect: await connectRepo(admin, IDN(), wlI, base + 3),
        overview: await w.api("GET", ghPath(IDN()), { cookie: admin }),
      };
      const otherWorkspaceConnect = await connectRepo(manager, PAY(), wlP, base + 1);
      const otherWorkspaceAvailable = await w.api(
        "GET",
        `/workspaces/${PAY()}/repositories/available?workspaceLinkId=${wlP}`,
        { cookie: manager },
      );
      const relinked = await linkFlow(admin, {
        workspaceId: IDN(),
        installationId: flowP.installationId,
        account,
        user,
        orgRole: "admin",
      });
      const relinkAllow = await putAllowList(admin, IDN(), wlI, [base + 3]);
      const relinkConnect = await connectRepo(admin, IDN(), wlI, base + 3);
      // SCM-024: link ids are bound to their workspace
      const under = (op, path, options) =>
        w.api(op, `${ghPath(PAY())}/links/${wlI}${path}`, { cookie: manager, ...options });
      const crossPair = {
        picker: await under("GET", "/repositories"),
        allowList: await under("PUT", "/repositories", { body: { add: [String(base + 4)] } }),
        refresh: await under("POST", "/refresh"),
        unlink: await w.api("DELETE", `${ghPath(PAY())}/links/${wlI}`, {
          cookie: manager,
          body: { confirm: account.login },
        }),
        connect: await connectRepo(manager, PAY(), wlI, base + 3),
        available: await w.api(
          "GET",
          `/workspaces/${PAY()}/repositories/available?workspaceLinkId=${wlI}`,
          { cookie: manager },
        ),
        overview: await w.api("GET", ghPath(PAY()), { cookie: manager }),
      };
      // SCM-025: tenant-level reads and the tenant setting need tenant keys; a workspace Manager has none
      const tenantLevel = {
        list: await w.api("GET", "/integrations/github/installations", { cookie: manager }),
        deliveries: await w.api(
          "GET",
          `/integrations/github/installations/${flowP.link.json.data.installationLinkId}/deliveries`,
          { cookie: manager },
        ),
        settingsRead: await w.api("GET", "/integrations/settings", { cookie: manager }),
        settingsWrite: await w.api("PUT", "/integrations/settings", {
          cookie: manager,
          body: { allowWorkspaceLinking: false },
        }),
        overview: await w.api("GET", "/integrations/github", { cookie: manager }),
        control: await w.api("GET", "/integrations/github/installations", { cookie: admin }),
      };
      // SCM-026: another tenant can neither reach this tenant's workspace nor use this tenant's link ids
      const edgeOwn = await w.api("POST", `${ghPath(edgeWs)}/links/${wlP}/refresh`, {
        cookie: edge.owner,
      });
      const edgeOwnPut = await putAllowList(edge.owner, edgeWs, wlP, [base + 1]);
      const edgeInA = await w.api("POST", `${ghPath(PAY())}/links/${wlP}/refresh`, {
        cookie: edge.owner,
      });
      const edgeInAStart = await w.api("POST", `${ghPath(PAY())}/start`, { cookie: edge.owner });
      return {
        wlP,
        wlI,
        read,
        leadWrite,
        developerWrite,
        leadStart,
        leadRefresh,
        managerWrite,
        idAllow,
        unlink,
        unlinked,
        otherWorkspaceConnect,
        otherWorkspaceAvailable,
        relinked,
        relinkAllow,
        relinkConnect,
        crossPair,
        tenantLevel,
        edgeOwn,
        edgeOwnPut,
        edgeInA,
        edgeInAStart,
      };
    });
  add(
    "SCM-022",
    "reading a workspace's GitHub connections needs workspace_integration.view (manager and lead can, developer and viewer cannot, another tenant sees a 404); changing needs .manage (lead cannot)",
    FORBIDDEN,
    async () => {
      const x = await world();
      return Object.assign({}, x.developerWrite, x);
    },
    (r) => {
      const problems = [];
      if (r.read.manager.status !== 200) problems.push(`manager read ${r.read.manager.status}`);
      if (r.read.lead.status !== 200) problems.push(`lead read ${r.read.lead.status}`);
      for (const who of ["developer", "viewer"])
        if (r.read[who].status !== 403) problems.push(`${who} read ${r.read[who].status}`);
      if (r.read.edgeOnA.status !== 404)
        problems.push(`other tenant read ${r.read.edgeOnA.status}`);
      if (r.leadWrite.status !== 403) problems.push(`lead allow-list edit ${r.leadWrite.status}`);
      if (r.leadStart.status !== 403) problems.push(`lead start ${r.leadStart.status}`);
      if (r.leadRefresh.status !== 403) problems.push(`lead refresh ${r.leadRefresh.status}`);
      if (r.developerWrite.status !== 403)
        problems.push(`developer allow-list edit ${r.developerWrite.status}`);
      if (r.managerWrite.status !== 200)
        problems.push(`manager allow-list edit ${r.managerWrite.status}`);
      return problems;
    },
  );
  add(
    "SCM-023",
    "a workspace that unlinked a connection cannot list or connect repositories through it, another workspace on the same installation still can, and linking again restores it",
    FORBIDDEN,
    async () => {
      const x = await world();
      return Object.assign({}, x.unlinked.connect, x);
    },
    (r) => {
      const problems = [];
      if (r.unlink.status !== 200 || r.unlink.json.data.unlinked !== true)
        problems.push("unlink failed");
      if (r.unlinked.picker.status !== 409)
        problems.push(`picker after unlink ${r.unlinked.picker.status}`);
      if (r.unlinked.available.status !== 403)
        problems.push(`available after unlink ${r.unlinked.available.status}`);
      if (r.unlinked.connect.json.error?.details?.reason !== "workspace_link_not_linked")
        problems.push(`connect reason ${r.unlinked.connect.json.error?.details?.reason}`);
      if (r.unlinked.overview.json.data.items.some((l) => l.id === r.wlI))
        problems.push("the unlinked connection is still listed");
      if (r.otherWorkspaceConnect.status !== 201)
        problems.push(`the other workspace could not connect (${r.otherWorkspaceConnect.status})`);
      if (r.otherWorkspaceAvailable.status !== 200)
        problems.push(`the other workspace's list answered ${r.otherWorkspaceAvailable.status}`);
      if (r.relinked.link?.status !== 201 || r.relinked.link.json.data.id !== r.wlI)
        problems.push(`linking again answered ${r.relinked.link?.status}`);
      if (r.relinkAllow.status !== 200 || r.relinkConnect.status !== 201)
        problems.push(
          `after linking again: allow-list ${r.relinkAllow.status}, connect ${r.relinkConnect.status}`,
        );
      return problems;
    },
  );
  add(
    "SCM-024",
    "a workspace link id is bound to its workspace: another workspace's connection under this workspace's URL is a 404 for list, edit, test, unlink, connect and available, and is not in this workspace's own list",
    NOT_FOUND,
    async () => {
      const x = await world();
      return Object.assign(
        { status: x.crossPair.allowList.status, json: x.crossPair.allowList.json },
        x,
      );
    },
    (r) => {
      const problems = [];
      for (const [name, res] of Object.entries(r.crossPair))
        if (name !== "overview" && res.status !== 404)
          problems.push(`${name} answered ${res.status}`);
      if (
        r.crossPair.overview.status !== 200 ||
        r.crossPair.overview.json.data.items.some((l) => l.id === r.wlI)
      )
        problems.push("the workspace lists another workspace's connection");
      if (!r.crossPair.overview.json.data.items.some((l) => l.id === r.wlP))
        problems.push("the workspace does not list its own connection");
      if (JSON.stringify(r.crossPair).includes(r.wlI))
        problems.push("a body repeats the foreign link id");
      return problems;
    },
  );
  add(
    "SCM-025",
    "tenant-level GitHub reads and the tenant setting need tenant keys: a workspace Manager gets 403 on the installation list, its deliveries, the setting (read and write) and the overview",
    FORBIDDEN,
    async () => {
      const x = await world();
      return Object.assign(
        { status: x.tenantLevel.settingsWrite.status, json: x.tenantLevel.settingsWrite.json },
        x,
      );
    },
    (r) => {
      const problems = Object.entries(r.tenantLevel)
        .filter(([name, res]) => name !== "control" && res.status !== 403)
        .map(([name, res]) => `${name} answered ${res.status}`);
      if (r.tenantLevel.control.status !== 200)
        problems.push(`the tenant administrator's list answered ${r.tenantLevel.control.status}`);
      return problems;
    },
  );
  add(
    "SCM-026",
    "another tenant cannot use this tenant's workspace connections, from its own workspace or from ours (404), and the workspace overview exposes no organization-level fields",
    NOT_FOUND,
    async () => {
      const x = await world();
      return Object.assign({ status: x.edgeOwn.status, json: x.edgeOwn.json }, x);
    },
    (r) => {
      const problems = [];
      if (r.edgeOwnPut.status !== 404) problems.push(`edge allow-list edit ${r.edgeOwnPut.status}`);
      if (r.edgeInA.status !== 404) problems.push(`edge in A's workspace ${r.edgeInA.status}`);
      if (r.edgeInAStart.status !== 404)
        problems.push(`edge start in A's workspace ${r.edgeInAStart.status}`);
      if (
        /externalInstallationId|permissions|workspaceScope/.test(
          JSON.stringify(r.read.manager.json),
        )
      )
        problems.push("the workspace overview exposes organization-level fields");
      return problems;
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 12. GitHub integration: repositories and webhook events (SCM). The scm worker's handlers run in-process against the stub
//     (no broker): the reconciler and the unavailable -> disconnected path.
// ---------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------------------------------------------------------------------------------
const stubRepo = (id) => ({
  id,
  node_id: `R_${id}`,
  name: `repo${id}`,
  full_name: `org/repo${id}`,
  owner: { login: "org" },
  private: true,
  default_branch: "main",
  html_url: `https://example.test/org/repo${id}`,
  archived: false,
  fork: false,
});
const quietLog = {
  info() {},
  warn() {},
  error() {},
  debug() {},
  child() {
    return quietLog;
  },
};
const TOKEN_MATERIAL = /ghs_stub_|ghu_stub_|BEGIN (RSA )?PRIVATE KEY/;
{
  const add = group("GitHub integration: repositories and events");
  const base = 4000000 + (Date.now() % 100000) * 10;
  const common = base + 9;
  const scmWorld = () =>
    once("scm-world", async () => {
      const edge = await edgeTenant();
      const edgeWorkspaceId = await edgeWorkspace();
      const admin = S("admin")(w);
      const user = ghUser();
      const accountA = orgAccount("r");
      const PAY = w.A.paymentsWs;
      const IDN = w.A.identityWs;
      const flowA = await linkFlow(admin, {
        workspaceId: PAY,
        account: accountA,
        user,
        orgRole: "admin",
        repos: [base + 1, base + 2, base + 3, base + 4, base + 5, base + 6, common].map(stubRepo),
      });
      // the second workspace of the same tenant uses the same installation (SPEC §18 A2)
      const flowAI = await linkFlow(admin, {
        workspaceId: IDN,
        installationId: flowA.installationId,
        account: accountA,
        user,
        orgRole: "admin",
      });
      const accountE = orgAccount("re");
      const userE = ghUser();
      const flowE = await linkFlow(edge.owner, {
        workspaceId: edgeWorkspaceId,
        account: accountE,
        user: userE,
        orgRole: "admin",
        repos: [common, base + 20].map(stubRepo),
      });
      const wlP = flowA.link.json.data.id;
      const wlI = flowAI.link.json.data.id;
      const wlE = flowE.link.json.data.id;
      const linkA = flowA.link.json.data.installationLinkId;
      // a repository is on ONE workspace's allow-list: payments gets 1, 3, 5 and the shared one; identity gets 2
      const allowP = await putAllowList(admin, PAY, wlP, [base + 1, base + 3, base + 5, common]);
      const allowI = await putAllowList(admin, IDN, wlI, [base + 2]);
      const allowE = await putAllowList(edge.owner, edgeWorkspaceId, wlE, [common]);
      const connect = (cookie, workspaceId, workspaceLinkId, externalRepoId, key) =>
        connectRepo(cookie, workspaceId, workspaceLinkId, externalRepoId, key);
      const payRepo = await connect(admin, PAY, wlP, base + 1);
      const idRepo = await connect(admin, IDN, wlI, base + 2);
      const managerRepo = await connect(S("manager")(w), PAY, wlP, base + 3);
      const duplicate = await connect(admin, PAY, wlP, base + 1);
      const commonA = await connect(admin, PAY, wlP, common);
      const commonE = await connect(edge.owner, edgeWorkspaceId, wlE, common);
      const syncRepoRes = await connect(admin, PAY, wlP, base + 5);
      const notOnList = await connect(admin, PAY, wlP, base + 4);
      const tenantId = (await w.api("GET", "/me", { cookie: admin })).json.data.tenant.id;
      return {
        edge,
        admin,
        flowA,
        flowAI,
        flowE,
        wlP,
        wlI,
        wlE,
        linkA,
        allowP,
        allowI,
        allowE,
        payRepo,
        idRepo,
        managerRepo,
        duplicate,
        commonA,
        commonE,
        syncRepoRes,
        notOnList,
        tenantId,
        edgeTenantId: edge.id,
        edgeWorkspace: edgeWorkspaceId,
        account: accountA,
      };
    });
  const push = (installationId, externalRepoId, extra = {}) => ({
    ref: "refs/heads/main",
    before: "a".repeat(40),
    after: "b".repeat(40),
    created: false,
    deleted: false,
    forced: false,
    commits: [{ id: "b".repeat(40) }],
    head_commit: { id: "b".repeat(40) },
    pusher: { name: "dev" },
    repository: { id: Number(externalRepoId) },
    installation: { id: Number(installationId) },
    ...extra,
  });
  add(
    "SCM-003",
    "a signed push for a connected repository creates exactly one normalized event and one outbox message in that tenant only",
    { status: 202 },
    async () => {
      const x = await scmWorld();
      const deliveryId = randomUUID();
      const r = await deliver({
        event: "push",
        payload: push(x.flowA.installationId, base + 1),
        deliveryId,
      });
      return Object.assign(r, { rows: await rowsFor(deliveryId), x });
    },
    (r) => {
      const problems = [];
      if (r.x.payRepo.status !== 201) problems.push(`connect answered ${r.x.payRepo.status}`);
      if (
        r.rows.events.length !== 1 ||
        r.rows.events[0].tenantId !== r.x.tenantId ||
        r.rows.events[0].repositoryId !== r.x.payRepo.json.data.id
      )
        problems.push(
          `events ${JSON.stringify(r.rows.events.map((e) => [e.tenantId, e.repositoryId]))}`,
        );
      if (r.rows.outbox.length !== 1) problems.push(`${r.rows.outbox.length} outbox rows`);
      else if (
        r.rows.outbox[0].type !== "scm.push.received" ||
        r.rows.outbox[0].routingKey !== "scm.github.push" ||
        r.rows.outbox[0].tenantId !== r.x.tenantId
      )
        problems.push(
          `outbox ${JSON.stringify([r.rows.outbox[0].type, r.rows.outbox[0].routingKey])}`,
        );
      return problems;
    },
  );
  add(
    "SCM-004",
    "a payload naming a repository id that another tenant also connected only ever affects the installation's own tenant",
    { status: 202 },
    async () => {
      const x = await scmWorld();
      const deliveryId = randomUUID();
      const r = await deliver({
        event: "push",
        payload: push(x.flowA.installationId, common),
        deliveryId,
      });
      return Object.assign(r, { rows: await rowsFor(deliveryId), x });
    },
    async (r) => {
      const problems = [];
      if (r.x.commonA.status !== 201 || r.x.commonE.status !== 201)
        problems.push(
          `both tenants should connect the same GitHub repository (${r.x.commonA.status}, ${r.x.commonE.status})`,
        );
      if (r.rows.events.length !== 1 || r.rows.events[0].tenantId !== r.x.tenantId)
        problems.push("the event is not in the installation's tenant");
      const other = await suiteDb().scmEvent.count({
        where: { tenantId: r.x.edgeTenantId, deliveryId: r.deliveryId },
      });
      if (other !== 0) problems.push("the other tenant received an event");
      const untouched = await suiteDb().repository.findUnique({
        where: { id: r.x.commonE.json.data.id },
      });
      if (untouched.lastEventAt !== null)
        problems.push("the other tenant's repository was touched");
      return problems;
    },
  );
  add(
    "SCM-007",
    "a duplicate X-GitHub-Delivery produces no second event or message",
    { status: 202 },
    async () => {
      const x = await scmWorld();
      const deliveryId = randomUUID();
      const first = await deliver({
        event: "push",
        payload: push(x.flowA.installationId, base + 1),
        deliveryId,
      });
      const second = await deliver({
        event: "push",
        payload: push(x.flowA.installationId, base + 1),
        deliveryId,
      });
      return Object.assign(second, { first, rows: await rowsFor(deliveryId) });
    },
    (r) =>
      r.first.status === 202 && r.rows.events.length === 1 && r.rows.outbox.length === 1
        ? []
        : [`events ${r.rows.events.length}, outbox ${r.rows.outbox.length}`],
  );
  add(
    "SCM-008",
    "another tenant's repository id answers 404 for read, edit, sync, disable and disconnect",
    NOT_FOUND,
    async () => {
      const x = await scmWorld();
      const id = x.payRepo.json.data.id;
      const cookie = x.edge.owner;
      const results = [
        await w.api("GET", `/repositories/${id}`, { cookie }),
        await w.api("PATCH", `/repositories/${id}`, { cookie, body: { displayName: "x" } }),
        await w.api("POST", `/repositories/${id}/sync`, { cookie }),
        await w.api("POST", `/repositories/${id}/disable`, { cookie }),
        await w.api("DELETE", `/repositories/${id}`, { cookie, body: { confirm: "org/x" } }),
      ];
      return Object.assign(results[0], { others: results.slice(1), id });
    },
    (r) =>
      r.others
        .filter((o) => o.status !== 404)
        .map((o) => `answered ${o.status}`)
        .concat(JSON.stringify(r.json).includes(r.id) ? ["the body leaks the id"] : []),
  );
  add(
    "SCM-009",
    "a repository in a workspace the caller cannot see answers 404 like a missing one; one they can see without the permission answers 403",
    NOT_FOUND,
    async () => {
      const x = await scmWorld();
      const hidden = await w.api("GET", `/repositories/${x.idRepo.json.data.id}`, {
        cookie: S("manager")(w),
      });
      const missing = await w.api("GET", `/repositories/${w.UNKNOWN}`, { cookie: S("manager")(w) });
      const forbidden = await w.api("PATCH", `/repositories/${x.payRepo.json.data.id}`, {
        cookie: S("developer")(w),
        body: { displayName: "x" },
      });
      const listed = await w.api("GET", "/repositories?pageSize=100", { cookie: S("manager")(w) });
      return Object.assign(hidden, { missing, forbidden, listed, x });
    },
    (r) => {
      const problems = [];
      if (JSON.stringify(r.json.error) !== JSON.stringify(r.missing.json.error))
        problems.push("hidden and missing differ");
      if (r.forbidden.status !== 403)
        problems.push(`the developer's edit answered ${r.forbidden.status}`);
      if (r.listed.json.data.some((repo) => repo.id === r.x.idRepo.json.data.id))
        problems.push("the list shows a repository of a hidden workspace");
      return problems;
    },
  );
  add(
    "SCM-010",
    "a repository can be connected once per tenant, but the same GitHub repository may be connected by two tenants",
    { status: 409, code: "CONFLICT" },
    async () => (await scmWorld()).duplicate,
    async () => {
      const x = await scmWorld();
      const problems = [];
      if (x.duplicate.json.error.details?.reason !== "repository_already_connected")
        problems.push(`reason ${x.duplicate.json.error.details?.reason}`);
      if (x.commonA.status !== 201 || x.commonE.status !== 201)
        problems.push("the shared repository could not be connected by both tenants");
      if (x.managerRepo.status !== 201)
        problems.push(`a manager could not connect (${x.managerRepo.status})`);
      return problems;
    },
  );
  add(
    "SCM-012",
    "no token or key material appears in any response, outbox message or audit entry",
    { status: 200 },
    async () => {
      const x = await scmWorld();
      const db = suiteDb();
      const texts = [
        JSON.stringify([
          x.flowA.link.json,
          x.flowE.link.json,
          x.payRepo.json,
          x.idRepo.json,
          x.managerRepo.json,
          x.commonA.json,
        ]),
        JSON.stringify(
          (await w.api("GET", `/repositories/${x.payRepo.json.data.id}`, { cookie: x.admin })).json,
        ),
        JSON.stringify(
          (await w.api("GET", "/integrations/github/installations", { cookie: x.admin })).json,
        ),
        JSON.stringify(
          (
            await w.api("GET", `/repositories/${x.payRepo.json.data.id}/branches`, {
              cookie: x.admin,
            })
          ).json,
        ),
        JSON.stringify(await db.outboxMessage.findMany({ where: { tenantId: x.tenantId } })),
        JSON.stringify(await db.auditLog.findMany({ where: { tenantId: x.tenantId } })),
      ];
      return {
        status: 200,
        json: null,
        problems: texts.some((text) => TOKEN_MATERIAL.test(text))
          ? ["token or key material found"]
          : [],
      };
    },
    (r) => r.problems,
  );
  add(
    "SCM-047",
    "a signed repository.renamed delivery changes the repository's display fields (full name, name, owner, URL) and never its identity (external id, node id, workspace, links, status)",
    { status: 202 },
    async () => {
      const x = await scmWorld();
      const db = suiteDb();
      const id = x.payRepo.json.data.id;
      const before = await db.repository.findUnique({ where: { id } });
      const newName = `renamed-${randomBytes(3).toString("hex")}`;
      const deliveryId = randomUUID();
      const delivered = await deliver({
        event: "repository",
        deliveryId,
        payload: {
          action: "renamed",
          changes: { repository: { name: { from: before.name } } },
          repository: {
            id: Number(before.externalRepoId),
            node_id: before.nodeId,
            name: newName,
            full_name: `org/${newName}`,
            html_url: `https://example.test/org/${newName}`,
            private: true,
            default_branch: "main",
            archived: false,
            owner: { login: "org" },
          },
          installation: { id: Number(x.flowA.installationId) },
        },
      });
      const rows = await rowsFor(deliveryId);
      await createScmEventHandler({
        db,
        config: { scm: { syncFailuresBeforeDisconnect: 3 } },
        logger: quietLog,
      })(rows.outbox[0].payload, { log: quietLog });
      const after = await db.repository.findUnique({ where: { id } });
      return { ...delivered, before, after, rows, newName };
    },
    (r) => {
      const problems = [];
      if (r.rows.delivery?.outcome !== "accepted") problems.push("the rename was not accepted");
      if (r.after.fullName !== `org/${r.newName}` || r.after.name !== r.newName)
        problems.push("the display name was not updated");
      if (r.after.htmlUrl !== `https://example.test/org/${r.newName}`)
        problems.push("the repository URL still points at the old name");
      for (const field of [
        "externalRepoId",
        "nodeId",
        "workspaceId",
        "linkId",
        "workspaceLinkId",
        "status",
        "tenantId",
      ])
        if (r.after[field] !== r.before[field]) problems.push(`${field} changed on a rename`);
      return problems;
    },
  );
  add(
    "SCM-016",
    "the delivery reconciler redelivers a failed delivery once; repeating it does not redeliver again, and the redelivery is processed once",
    { status: 200 },
    async () => {
      const x = await scmWorld();
      const guid = randomUUID();
      const payload = {
        action: "new_permissions_accepted",
        installation: { id: Number(x.flowA.installationId) },
      };
      // GitHub delivery ids are 64-bit integers: this one is above 2^53 and NOT exactly representable as a JS number, so a
      // client that parses it as a Number addresses the wrong id (the live-test defect of 2026-11-12).
      const bigDeliveryId = String(3853579981959463001n + BigInt(Date.now() % 1000) * 2n);
      await stubCtl("/__control/delivery", {
        id: bigDeliveryId,
        guid,
        status_code: 500,
        event: "installation",
        action: payload.action,
        installation_id: Number(x.flowA.installationId),
        payload,
        webhookUrl: `${env("SECURITY_API_URL")}/api/v1/webhooks/github`,
        secret: WEBHOOK_SECRET,
      });
      const github = createGitHubClient({
        apiBaseUrl: STUB,
        webBaseUrl: STUB,
        apiVersion: "2026-03-10",
        clientId: env("SECURITY_GITHUB_CLIENT_ID"),
        getPrivateKey: () => env("SECURITY_GITHUB_PRIVATE_KEY"),
        getClientSecret: () => env("SECURITY_GITHUB_CLIENT_SECRET"),
      });
      const handle = createScmJobHandler({
        db: suiteDb(),
        config: { scm: { syncFailuresBeforeDisconnect: 3, redeliverPauseMs: 0 } },
        logger: quietLog,
        github,
      });
      const message = {
        type: "scm.deliveries.reconcile_requested",
        payload: { windowHours: 70, maxRedeliveries: 10 },
      };
      await handle(message, { log: quietLog });
      for (let i = 0; i < 40; i += 1) {
        const seen = (await stubCtl("/__control/deliveries", {})).deliveries.some(
          (d) => d.guid === guid && d.redelivery,
        );
        if (seen) break;
        await sleep(100);
      }
      await handle(message, { log: quietLog });
      await sleep(300);
      const redeliveries = (await stubCtl("/__control/redeliveries", {})).redeliveries;
      return { status: 200, json: null, rows: await rowsFor(guid), redeliveries, bigDeliveryId };
    },
    (r) => {
      const problems = [];
      if (r.redeliveries.length !== 1)
        problems.push(`${r.redeliveries.length} redelivery requests`);
      if (r.redeliveries[0] !== r.bigDeliveryId)
        problems.push("the redelivery addressed a different (rounded) delivery id");
      if (r.rows.events.length !== 1 || r.rows.outbox.length !== 1)
        problems.push(`events ${r.rows.events.length}, outbox ${r.rows.outbox.length}`);
      if (r.rows.delivery?.outcome !== "accepted")
        problems.push(`outcome ${r.rows.delivery?.outcome}`);
      return problems;
    },
  );
  add(
    "SCM-017",
    "a repository that stops being listed becomes unavailable, then disconnected after N failures; nothing is deleted and both transitions are audited",
    { status: 200 },
    async () => {
      const x = await scmWorld();
      const repoId = x.syncRepoRes.json.data.id;
      const db = suiteDb();
      const github = createGitHubClient({
        apiBaseUrl: STUB,
        webBaseUrl: STUB,
        apiVersion: "2026-03-10",
        clientId: env("SECURITY_GITHUB_CLIENT_ID"),
        getPrivateKey: () => env("SECURITY_GITHUB_PRIVATE_KEY"),
        getClientSecret: () => env("SECURITY_GITHUB_CLIENT_SECRET"),
      });
      const handle = createScmJobHandler({
        db,
        config: { scm: { syncFailuresBeforeDisconnect: 3, redeliverPauseMs: 0 } },
        logger: quietLog,
        github,
      });
      const sync = () =>
        handle(
          {
            type: "scm.repository.sync_requested",
            tenantId: x.tenantId,
            payload: { repositoryId: repoId },
          },
          { log: quietLog },
        );
      const statuses = [];
      await sync(); // still listed: healthy
      statuses.push((await db.repository.findUnique({ where: { id: repoId } })).status);
      await stubCtl("/__control/repos", {
        installationId: x.flowA.installationId,
        repos: [base + 1, base + 2, base + 3, base + 4, base + 6, common].map(stubRepo),
      });
      for (let i = 0; i < 3; i += 1) {
        await sync();
        const row = await db.repository.findUnique({ where: { id: repoId } });
        statuses.push(`${row.status}:${row.consecutiveSyncFailures}`);
      }
      const audits = (
        await db.auditLog.findMany({
          where: { tenantId: x.tenantId, targetId: repoId, actorType: "system" },
        })
      ).map((a) => a.action);
      const events = await db.outboxMessage.count({
        where: {
          tenantId: x.tenantId,
          type: "repository.disconnected",
          messageId: { not: "" },
          payload: { path: ["payload", "repositoryId"], equals: repoId },
        },
      });
      return {
        status: 200,
        json: null,
        statuses,
        audits,
        events,
        exists: Boolean(await db.repository.findUnique({ where: { id: repoId } })),
      };
    },
    (r) => {
      const problems = [];
      if (
        JSON.stringify(r.statuses) !==
        JSON.stringify(["active", "unavailable:1", "unavailable:2", "disconnected:3"])
      )
        problems.push(`transitions ${JSON.stringify(r.statuses)}`);
      if (
        !r.audits.includes("repository.unavailable") ||
        !r.audits.includes("repository.disconnected")
      )
        problems.push(`audit ${JSON.stringify(r.audits)}`);
      if (r.events !== 1) problems.push(`${r.events} disconnect events`);
      if (!r.exists) problems.push("the row was deleted");
      return problems;
    },
  );

  // ---- workspace isolation under one installation (SPEC §18.3 items 1, 5 and 6). Workspace A and workspace B use the SAME
  //      installation; neither may list, connect or see the other's repositories, allow-list or link records.
  const PAYW = () => w.A.paymentsWs;
  const IDNW = () => w.A.identityWs;
  /** Every operation a workspace connection offers, aimed at (workspace, workspace link, repository). */
  const probe = async (cookie, workspaceId, workspaceLinkId, externalRepoId) => ({
    overview: await w.api("GET", ghPath(workspaceId), { cookie }),
    picker: await w.api("GET", `${ghPath(workspaceId)}/links/${workspaceLinkId}/repositories`, {
      cookie,
    }),
    allowList: await w.api("PUT", `${ghPath(workspaceId)}/links/${workspaceLinkId}/repositories`, {
      cookie,
      body: { add: [String(externalRepoId)] },
    }),
    refresh: await w.api("POST", `${ghPath(workspaceId)}/links/${workspaceLinkId}/refresh`, {
      cookie,
    }),
    unlink: await w.api("DELETE", `${ghPath(workspaceId)}/links/${workspaceLinkId}`, {
      cookie,
      body: { confirm: "not-the-account" },
    }),
    available: await w.api(
      "GET",
      `/workspaces/${workspaceId}/repositories/available?workspaceLinkId=${workspaceLinkId}`,
      { cookie },
    ),
    connect: await connectRepo(cookie, workspaceId, workspaceLinkId, externalRepoId),
  });
  const isoWorld = () =>
    once("scm-iso", async () => {
      const x = await scmWorld();
      const manager = S("manager")(w);
      const developer = S("developer")(w);
      const lead = S("lead")(w);
      const missingWorkspace = await w.api("GET", ghPath(w.UNKNOWN), { cookie: manager });
      return {
        x,
        hidden: await probe(manager, IDNW(), x.wlI, base + 2),
        missingWorkspace,
        crossPair: await probe(manager, PAYW(), x.wlI, base + 2),
        visibleNoKey: await probe(developer, IDNW(), x.wlI, base + 2),
        leadOwn: {
          overview: await w.api("GET", ghPath(PAYW()), { cookie: lead }),
          picker: await w.api("GET", `${ghPath(PAYW())}/links/${x.wlP}/repositories`, {
            cookie: lead,
          }),
          allowList: await w.api("PUT", `${ghPath(PAYW())}/links/${x.wlP}/repositories`, {
            cookie: lead,
            body: { add: [String(base + 4)] },
          }),
        },
        ownOverview: await w.api("GET", ghPath(PAYW()), { cookie: manager }),
        ownAvailable: await w.api(
          "GET",
          `/workspaces/${PAYW()}/repositories/available?workspaceLinkId=${x.wlP}`,
          { cookie: manager },
        ),
        identityOverview: await w.api("GET", ghPath(IDNW()), { cookie: x.admin }),
        managerRepos: await w.api("GET", "/repositories?pageSize=100", { cookie: manager }),
        identityRepoById: await w.api("GET", `/repositories/${x.idRepo.json.data.id}`, {
          cookie: manager,
        }),
      };
    });
  add(
    "SCM-036",
    "workspace A cannot list, connect or see workspace B's repositories, allow-list or link records under the same installation: a workspace the caller cannot see is a 404 identical to a missing one, also through A's own URL with B's link id",
    NOT_FOUND,
    async () => {
      const x = await isoWorld();
      return Object.assign({}, x.hidden.picker, x);
    },
    (r) => {
      const problems = [];
      for (const [group, results] of [
        ["hidden workspace", r.hidden],
        ["foreign link id", r.crossPair],
      ])
        for (const [name, res] of Object.entries(results)) {
          if (group === "foreign link id" && name === "overview") continue;
          if (res.status !== 404) problems.push(`${group}: ${name} answered ${res.status}`);
        }
      if (
        JSON.stringify(r.hidden.overview.json.error) !==
        JSON.stringify(r.missingWorkspace.json.error)
      )
        problems.push("a hidden workspace differs from a missing one");
      const text = JSON.stringify([r.hidden, r.crossPair]);
      if (
        text.includes(r.x.wlI) ||
        text.includes(`repo${base + 2}`) ||
        text.includes(r.x.idRepo.json.data.id)
      )
        problems.push("a refusal repeats an identifier or name of the other workspace");
      // controls: the legitimate requests work, and the foreign data is not in the caller's own views
      if (
        r.ownOverview.status !== 200 ||
        !r.ownOverview.json.data.items.some((l) => l.id === r.x.wlP)
      )
        problems.push("the Manager cannot read their own workspace's connection");
      if (r.ownOverview.json.data.items.some((l) => l.id === r.x.wlI))
        problems.push("the Manager's list shows the other workspace's connection");
      if (r.ownAvailable.status !== 200)
        problems.push(`own available answered ${r.ownAvailable.status}`);
      else if (r.ownAvailable.json.data.some((i) => i.externalRepoId === String(base + 2)))
        problems.push("the available list shows the other workspace's repository");
      if (
        r.identityOverview.status !== 200 ||
        !r.identityOverview.json.data.items.some((l) => l.id === r.x.wlI)
      )
        problems.push("the administrator cannot read the other workspace's connection");
      if (r.managerRepos.json.data.some((repo) => repo.id === r.x.idRepo.json.data.id))
        problems.push("the repository list shows the other workspace's repository");
      if (r.identityRepoById.status !== 404)
        problems.push(`repository by id answered ${r.identityRepoById.status}`);
      return problems;
    },
  );
  add(
    "SCM-037",
    "a workspace the caller can see but holds no workspace_integration key in answers 403 for the connection overview, list, allow-list edit, test, unlink, available and connect, while a Lead can read but not edit",
    FORBIDDEN,
    async () => {
      const x = await isoWorld();
      return Object.assign({}, x.visibleNoKey.picker, x);
    },
    (r) => {
      const problems = [];
      for (const [name, res] of Object.entries(r.visibleNoKey))
        if (res.status !== 403) problems.push(`developer ${name} answered ${res.status}`);
      if (r.leadOwn.overview.status !== 200)
        problems.push(`lead overview ${r.leadOwn.overview.status}`);
      if (r.leadOwn.picker.status !== 200) problems.push(`lead picker ${r.leadOwn.picker.status}`);
      if (r.leadOwn.allowList.status !== 403)
        problems.push(`lead allow-list edit ${r.leadOwn.allowList.status}`);
      if (JSON.stringify(r.visibleNoKey).includes(`repo${base + 2}`))
        problems.push("a refusal repeats a repository name");
      return problems;
    },
  );
  add(
    "SCM-038",
    "a repository that is not on the workspace's allow-list cannot be connected (403 repository_not_allowed) and is not offered; only workspace_integration.manage edits the list; adding it makes it connectable and a connected one cannot be removed",
    FORBIDDEN,
    async () => (await scmWorld()).notOnList,
    async (r) => {
      const x = await scmWorld();
      const problems = [];
      if (r.json.error.details?.reason !== "repository_not_allowed")
        problems.push(`reason ${r.json.error.details?.reason}`);
      const manager = S("manager")(w);
      const available = await w.api(
        "GET",
        `/workspaces/${PAYW()}/repositories/available?workspaceLinkId=${x.wlP}&pageSize=100`,
        { cookie: manager },
      );
      const offered = (available.json?.data ?? []).map((i) => i.externalRepoId).sort();
      // base + 5 is on the list but no longer listed by GitHub (SCM-017 removes it from the stub), so it is not offered
      const expected = [base + 1, base + 3, common].map(String).sort();
      if (JSON.stringify(offered) !== JSON.stringify(expected))
        problems.push(`offered ${offered.join(",")}`);
      const picker = await w.api(
        "GET",
        `${ghPath(PAYW())}/links/${x.wlP}/repositories?pageSize=100`,
        { cookie: manager },
      );
      const flag = (id) => picker.json?.data?.find((i) => i.externalRepoId === String(id));
      if (flag(base + 1)?.allowed !== true || flag(base + 1)?.connected !== true)
        problems.push("the picker does not show an allowed, connected repository");
      if (flag(base + 2)?.allowed !== false || flag(base + 2)?.allowedElsewhere !== true)
        problems.push(
          "the picker does not mark the other workspace's repository as allowed elsewhere",
        );
      if (flag(base + 4)?.allowed !== false || flag(base + 4)?.allowedElsewhere !== false)
        problems.push("the picker marks an unlisted repository");
      // control: the editor adds it, then it connects; and a connected repository cannot be removed
      const added = await w.api("PUT", `${ghPath(PAYW())}/links/${x.wlP}/repositories`, {
        cookie: manager,
        body: { add: [String(base + 4)] },
      });
      if (added.status !== 200 || added.json.data.added !== 1)
        problems.push(`adding answered ${added.status}`);
      const connected = await connectRepo(manager, PAYW(), x.wlP, base + 4);
      if (connected.status !== 201)
        problems.push(`connecting after adding answered ${connected.status}`);
      const removeConnected = await w.api("PUT", `${ghPath(PAYW())}/links/${x.wlP}/repositories`, {
        cookie: manager,
        body: { remove: [String(base + 4)] },
      });
      if (
        removeConnected.status !== 409 ||
        removeConnected.json.error.details?.reason !== "repository_connected"
      )
        problems.push(`removing a connected repository answered ${removeConnected.status}`);
      return problems;
    },
  );
  add(
    "SCM-039",
    "a repository on one workspace's allow-list cannot be added to another's (generic 409 that names no workspace), by patch or replace, and the other list is unchanged; the same GitHub repository may be listed by another tenant",
    { status: 409, code: "CONFLICT" },
    async () => {
      const x = await scmWorld();
      return w.api("PUT", `${ghPath(IDNW())}/links/${x.wlI}/repositories`, {
        cookie: x.admin,
        body: { add: [String(base + 1)] },
      });
    },
    async (r) => {
      const x = await scmWorld();
      const problems = [];
      if (r.json.error.details?.reason !== "allow_list_conflict")
        problems.push(`reason ${r.json.error.details?.reason}`);
      const replace = await putAllowList(x.admin, IDNW(), x.wlI, [base + 2, base + 1]);
      if (replace.status !== 409) problems.push(`replace answered ${replace.status}`);
      const text = JSON.stringify([r.json, replace.json]);
      if (text.includes("Payments") || text.includes(x.wlP))
        problems.push("the refusal names the other workspace");
      const picker = await w.api(
        "GET",
        `${ghPath(IDNW())}/links/${x.wlI}/repositories?pageSize=100`,
        {
          cookie: x.admin,
        },
      );
      const mine = (picker.json?.data ?? []).filter((i) => i.allowed).map((i) => i.externalRepoId);
      if (JSON.stringify(mine) !== JSON.stringify([String(base + 2)]))
        problems.push(`the list changed: ${mine.join(",")}`);
      if (x.allowE.status !== 200 || x.commonE.status !== 201)
        problems.push("the other tenant could not list and connect the same GitHub repository");
      const control = await w.api("PUT", `${ghPath(IDNW())}/links/${x.wlI}/repositories`, {
        cookie: x.admin,
        body: { add: [String(base + 6)] },
      });
      if (control.status !== 200)
        problems.push(`adding an unlisted repository answered ${control.status}`);
      return problems;
    },
  );
  add(
    "SCM-040",
    "unlinking a workspace disconnects only its own repositories (the other workspace's stay active), keeps the installation record, needs the typed account name, and linking again restores them",
    { status: 200 },
    async () => {
      const x = await scmWorld();
      const admin = x.admin;
      const status = async (id) =>
        (await w.api("GET", `/repositories/${id}`, { cookie: admin })).json.data;
      const wrong = await w.api("DELETE", `${ghPath(IDNW())}/links/${x.wlI}`, {
        cookie: admin,
        body: { confirm: "not-the-account" },
      });
      const before = {
        identity: (await status(x.idRepo.json.data.id)).status,
        payments: (await status(x.payRepo.json.data.id)).status,
      };
      const unlink = await w.api("DELETE", `${ghPath(IDNW())}/links/${x.wlI}`, {
        cookie: admin,
        body: { confirm: x.account.login },
      });
      const after = {
        identity: await status(x.idRepo.json.data.id),
        payments: await status(x.payRepo.json.data.id),
        manager: await status(x.managerRepo.json.data.id),
      };
      const list = await w.api("GET", "/integrations/github/installations", { cookie: admin });
      const paymentsOverview = await w.api("GET", ghPath(PAYW()), { cookie: admin });
      const relink = await linkFlow(admin, {
        workspaceId: IDNW(),
        installationId: x.flowA.installationId,
        account: x.account,
        user: ghUser(),
        orgRole: "admin",
      });
      const restored = await status(x.idRepo.json.data.id);
      return { ...unlink, wrong, before, after, list, paymentsOverview, relink, restored, x };
    },
    (r) => {
      const problems = [];
      if (r.wrong.status !== 400) problems.push(`a wrong confirmation answered ${r.wrong.status}`);
      if (r.before.identity !== "active" || r.before.payments !== "active")
        problems.push(`before: ${JSON.stringify(r.before)}`);
      if (r.json.data.unlinked !== true || r.json.data.repositoriesDisconnected !== 1)
        problems.push(`unlink result ${JSON.stringify(r.json.data)}`);
      if (
        r.after.identity.status !== "disconnected" ||
        r.after.identity.disconnectReason !== "workspace_unlinked"
      )
        problems.push(`the unlinked workspace's repository is ${r.after.identity.status}`);
      for (const k of ["payments", "manager"])
        if (r.after[k].status !== "active")
          problems.push(`the other workspace's repository is ${r.after[k].status}`);
      const link = r.list.json.data.items.find((l) => l.id === r.x.linkA);
      if (!link || link.status !== "linked" || link.workspaceCount !== 1)
        problems.push(
          `the installation record is ${JSON.stringify(link && [link.status, link.workspaceCount])}`,
        );
      if (!r.paymentsOverview.json.data.items.some((l) => l.id === r.x.wlP))
        problems.push("the other workspace lost its connection");
      if (r.relink.link?.status !== 201)
        problems.push(`linking again answered ${r.relink.link?.status}`);
      else if (r.restored.status !== "active")
        problems.push(`after linking again: ${r.restored.status}`);
      return problems;
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 12b. GitHub integration: the tenant view is read-only (SPEC §18.2, A7), and the removed tenant-level endpoints stay removed.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("GitHub integration: tenant read-only view");
  const PAY = () => w.A.paymentsWs;
  const IDN = () => w.A.identityWs;
  const twoWorkspaces = () =>
    once("scm-readonly", async () => {
      const admin = S("admin")(w);
      const account = orgAccount("ro");
      const user = ghUser();
      const first = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user,
        orgRole: "admin",
        repos: [],
      });
      const second = await linkFlow(admin, {
        workspaceId: IDN(),
        installationId: first.installationId,
        account,
        user,
        orgRole: "admin",
      });
      const edge = await edgeTenant();
      const names = await w.api("GET", "/workspaces?pageSize=100", { cookie: admin });
      return {
        account,
        first,
        second,
        adminList: await w.api("GET", "/integrations/github/installations", { cookie: admin }),
        edgeList: await w.api("GET", "/integrations/github/installations", { cookie: edge.owner }),
        paymentsName: names.json.data.find((n) => n.id === PAY()).name,
        identityName: names.json.data.find((n) => n.id === IDN()).name,
      };
    });
  add(
    "SCM-041",
    "the tenant installation list (integration.view) is read-only and names only the workspaces the caller can see, counting the rest; a holder of integration.view with no sight of a workspace never learns its name; callers without integration.view get 403; another tenant sees none of it",
    FORBIDDEN,
    async () => {
      await twoWorkspaces();
      return w.api("GET", "/integrations/github/installations", { cookie: S("viewer")(w) });
    },
    async () => {
      const x = await twoWorkspaces();
      const problems = [];
      const forAdmin = x.adminList.json.data.items.find((l) => l.account.login === x.account.login);
      if (!forAdmin || forAdmin.workspaceCount !== 2 || forAdmin.hiddenWorkspaceCount !== 0)
        problems.push(`administrator view ${JSON.stringify(forAdmin?.workspaces)}`);
      else if (
        !forAdmin.workspaces.some((n) => n.name === x.paymentsName) ||
        !forAdmin.workspaces.some((n) => n.name === x.identityName)
      )
        problems.push("the administrator does not see both workspace names");
      // a Manager of the first workspace only, holding the tenant key integration.view through a custom role
      const manager = S("manager")(w);
      const restricted = await withRole(
        { userId: await meId(manager), roleId: await viewOnlyRoleId() },
        async () => ({
          list: await w.api("GET", "/integrations/github/installations", { cookie: manager }),
          write: await w.api("PUT", "/integrations/settings", {
            cookie: manager,
            body: { allowWorkspaceLinking: true },
          }),
        }),
      );
      const seen = restricted.list.json?.data?.items?.find(
        (l) => l.account.login === x.account.login,
      );
      if (restricted.list.status !== 200 || !seen)
        problems.push(`restricted list ${restricted.list.status}`);
      else {
        if (seen.workspaceCount !== 2 || seen.hiddenWorkspaceCount !== 1)
          problems.push(`restricted counts ${seen.workspaceCount}/${seen.hiddenWorkspaceCount}`);
        if (JSON.stringify(seen.workspaces.map((n) => n.name)) !== JSON.stringify([x.paymentsName]))
          problems.push("the restricted view does not name exactly the visible workspace");
        if (JSON.stringify(restricted.list.json).includes(x.identityName))
          problems.push("a hidden workspace's name is in the response");
        if (JSON.stringify(restricted.list.json).includes(IDN()))
          problems.push("a hidden workspace's id is in the response");
      }
      if (restricted.write.status !== 403)
        problems.push(`view-only write answered ${restricted.write.status}`);
      for (const who of ["manager", "lead", "developer"]) {
        const res = await w.api("GET", "/integrations/github/installations", { cookie: S(who)(w) });
        if (res.status !== 403) problems.push(`${who} list answered ${res.status}`);
      }
      if (
        JSON.stringify(x.edgeList.json).includes(x.account.login) ||
        JSON.stringify(x.edgeList.json).includes(x.paymentsName)
      )
        problems.push("another tenant sees this tenant's installation");
      return problems;
    },
  );
  add(
    "SCM-042",
    "no tenant-level GitHub write endpoint exists: the removed link, scope, refresh and unlink endpoints and the workspace routing endpoints answer 404 even for the administrator, who can still do the same through the workspace endpoints",
    { status: 404 },
    async () => {
      await twoWorkspaces();
      return w.api("POST", "/integrations/github/installations/start", { cookie: S("admin")(w) });
    },
    async () => {
      const x = await twoWorkspaces();
      const admin = S("admin")(w);
      const linkId = x.first.link.json.data.installationLinkId;
      const wl = x.first.link.json.data.id;
      const removed = {
        authorize: await w.api("POST", "/integrations/github/installations/authorize", {
          cookie: admin,
          body: { installationId: "1" },
        }),
        link: await w.api("POST", "/integrations/github/installations", {
          cookie: admin,
          body: { code: "x", state: "y".repeat(30) },
        }),
        refresh: await w.api("POST", `/integrations/github/installations/${linkId}/refresh`, {
          cookie: admin,
        }),
        scope: await w.api("PUT", `/integrations/github/installations/${linkId}/workspaces`, {
          cookie: admin,
          body: { workspaceIds: [] },
        }),
        unlink: await w.api("DELETE", `/integrations/github/installations/${linkId}`, {
          cookie: admin,
          body: { confirm: x.account.login },
        }),
        routingList: await w.api("GET", `/workspaces/${PAY()}/integrations`, { cookie: admin }),
        routingSet: await w.api("PUT", `/workspaces/${PAY()}/integrations/${wl}`, {
          cookie: admin,
          body: { enabled: false },
        }),
      };
      const problems = Object.entries(removed)
        .filter(([, res]) => res.status !== 404)
        .map(([name, res]) => `${name} answered ${res.status}`);
      // controls: the connection is intact, and the workspace endpoints do the work
      const overview = await w.api("GET", ghPath(PAY()), { cookie: admin });
      if (!overview.json.data.items.some((l) => l.id === wl && l.status === "linked"))
        problems.push("a removed endpoint changed the connection");
      const refresh = await w.api("POST", `${ghPath(PAY())}/links/${wl}/refresh`, {
        cookie: admin,
      });
      if (refresh.status !== 200) problems.push(`the workspace refresh answered ${refresh.status}`);
      return problems;
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 12c. GitHub integration: uninstall on GitHub (installation.deleted) affects every linked workspace (SPEC §18 A6, §18.6).
//      The signed webhook runs through the API; the scm event consumer and the notification handler run in-process.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("GitHub integration: uninstall and notification");
  const base = 6000000 + (Date.now() % 100000) * 10;
  const PAY = () => w.A.paymentsWs;
  const IDN = () => w.A.identityWs;
  const world = () =>
    once("scm-uninstall", async () => {
      const edge = await edgeTenant();
      const admin = S("admin")(w);
      const manager = S("manager")(w);
      const tenantId = await tenantIdA();
      const account = orgAccount("un");
      const user = ghUser();
      const flowP = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user,
        orgRole: "admin",
        repos: [base + 1, base + 2, base + 3].map(stubRepo),
      });
      const flowI = await linkFlow(admin, {
        workspaceId: IDN(),
        installationId: flowP.installationId,
        account,
        user,
        orgRole: "admin",
      });
      const wlP = flowP.link.json.data.id;
      const wlI = flowI.link.json.data.id;
      const linkId = flowP.link.json.data.installationLinkId;
      await putAllowList(admin, PAY(), wlP, [base + 1, base + 2]);
      await putAllowList(admin, IDN(), wlI, [base + 3]);
      const repoP1 = await connectRepo(manager, PAY(), wlP, base + 1);
      const repoP2 = await connectRepo(admin, PAY(), wlP, base + 2);
      const repoI = await connectRepo(admin, IDN(), wlI, base + 3);
      const repoIds = [repoP1, repoP2, repoI].map((r) => r.json.data.id);
      const db = suiteDb();
      const statusOf = async () =>
        (await db.repository.findMany({ where: { id: { in: repoIds } } })).map((r) => [
          r.status,
          r.disconnectReason,
        ]);
      const before = await statusOf();
      // people: the Manager of Payments, a Security Analyst made workspace Manager of Identity (removed again below)
      const people = {
        admin: await meId(admin),
        manager: await meId(manager),
        analyst: w.A.user,
        viewer: await meId(S("viewer")(w)),
        lead: await meId(S("lead")(w)),
        developer: await meId(S("developer")(w)),
        bOwner: w.B.userId,
        edgeOwner: await meId(edge.owner),
      };
      const managerRole = await integrationManagerRoleId();
      const edgeBefore = await w.api("GET", "/integrations/github/installations", {
        cookie: edge.owner,
      });
      const handleEvent = (message) =>
        createScmEventHandler({
          db,
          config: { scm: { syncFailuresBeforeDisconnect: 3 } },
          logger: quietLog,
        })(message, { log: quietLog });
      // SPEC §16.2: what every endpoint reports for the link, before and after the uninstall
      const statusViews = async () => ({
        tenantList: await w.api("GET", "/integrations/github/installations", { cookie: admin }),
        payAdmin: await w.api("GET", ghPath(PAY()), { cookie: admin }),
        payManager: await w.api("GET", ghPath(PAY()), { cookie: manager }),
        idnAdmin: await w.api("GET", ghPath(IDN()), { cookie: admin }),
        available: await w.api(
          "GET",
          `/workspaces/${PAY()}/repositories/available?workspaceLinkId=${wlP}`,
          { cookie: manager },
        ),
        connect: await connectRepo(admin, IDN(), wlI, base + 3),
        edgeList: await w.api("GET", "/integrations/github/installations", { cookie: edge.owner }),
      });
      const apiBefore = await statusViews();
      let deleted;
      let envelope;
      const fetchAudits = () =>
        db.auditLog.findMany({
          where: {
            tenantId,
            OR: [
              { action: "scm_workspace_link.status_changed", targetId: { in: [wlP, wlI] } },
              { action: "scm_installation.status_changed", targetId: linkId },
              { action: "repository.disconnected", targetId: { in: repoIds } },
            ],
          },
        });
      let audits = [];

      let revokedMessages = [];
      const warnings = [];
      await withRole(
        { userId: people.analyst, roleId: managerRole, workspaceId: IDN() },
        async () => {
          const deliveryId = randomUUID();
          deleted = await deliver({
            payload: {
              action: "deleted",
              installation: { id: Number(flowP.installationId), account: { login: account.login } },
            },
            deliveryId,
          });
          const rows = await rowsFor(deliveryId);
          envelope = rows.outbox[0]?.payload;
          await handleEvent(envelope);
          audits = await fetchAudits(); // what the first delivery wrote
          // the same event again and a later "unsuspend": revoked is terminal and notifies nobody a second time
          await handleEvent(envelope);
          const later = await deliver({
            payload: {
              action: "unsuspend",
              installation: { id: Number(flowP.installationId), account: { login: account.login } },
            },
          });
          const laterRows = await rowsFor(later.deliveryId);
          if (laterRows.outbox[0]) await handleEvent(laterRows.outbox[0].payload);
          revokedMessages = (
            await db.outboxMessage.findMany({
              where: { tenantId, type: "scm.installation.revoked" },
            })
          ).filter((m) => m.payload?.payload?.linkId === linkId);
          // notification: the handler turns the stored message into recipients (it needs no broker). It runs while the
          // analyst still holds the Identity Manager role, because recipients are looked up when the message is handled.
          const log = {
            warn: (fields) => warnings.push(fields),
            info() {},
            error() {},
            debug() {},
          };
          if (revokedMessages[0])
            await createNotificationHandler({ db })(revokedMessages[0].payload, {
              log,
              attempt: 1,
            });
        },
      );
      const afterPush = await deliver({
        event: "push",
        payload: {
          ref: "refs/heads/main",
          before: "a".repeat(40),
          after: "b".repeat(40),
          commits: [{ id: "b".repeat(40) }],
          head_commit: { id: "b".repeat(40) },
          pusher: { name: "dev" },
          repository: { id: base + 1 },
          installation: { id: Number(flowP.installationId) },
        },
      });
      const pushRows = await rowsFor(afterPush.deliveryId);
      const installation = await db.scmInstallation.findFirst({
        where: { externalInstallationId: String(flowP.installationId) },
      });
      const apiAfter = await statusViews();
      return {
        apiBefore,
        apiAfter,
        flowP,
        account,
        people,
        deleted,
        before,
        after: await statusOf(),
        installation,
        audits,
        revokedMessages,
        wlP,
        wlI,
        linkId,
        repoIds,
        afterPush,
        pushRows,
        edgeBefore,
        warnings,
        edgeAfter: await w.api("GET", "/integrations/github/installations", { cookie: edge.owner }),
        statusAfterAll: await statusOf(),
      };
    });
  add(
    "SCM-043",
    "a signed installation.deleted disconnects the repositories of every linked workspace (reason installation_revoked), audits each workspace and the tenant once, queues exactly one admin notification, and later events and webhooks for the installation change nothing",
    { status: 202 },
    async () => (await world()).deleted,
    async () => {
      const x = await world();
      const problems = [];
      if (
        JSON.stringify(x.before.map((s) => s[0])) !== JSON.stringify(["active", "active", "active"])
      )
        problems.push(`before: ${JSON.stringify(x.before)}`);
      if (x.installation?.status !== "revoked")
        problems.push(`installation is ${x.installation?.status}`);
      for (const [status, reason] of x.statusAfterAll)
        if (status !== "disconnected" || reason !== "installation_revoked")
          problems.push(`a repository is ${status}/${reason}`);
      const count = (action) => x.audits.filter((a) => a.action === action);
      const perWorkspace = count("scm_workspace_link.status_changed");
      if (
        perWorkspace.length !== 2 ||
        new Set(perWorkspace.map((a) => a.workspaceId)).size !== 2 ||
        !perWorkspace.some((a) => a.workspaceId === w.A.paymentsWs) ||
        !perWorkspace.some((a) => a.workspaceId === w.A.identityWs)
      )
        problems.push(`${perWorkspace.length} per-workspace audit entries`);
      const tenantLevel = count("scm_installation.status_changed");
      if (tenantLevel.length !== 1 || tenantLevel[0].workspaceId !== null)
        problems.push(`${tenantLevel.length} tenant-level audit entries`);
      if (count("repository.disconnected").length !== 3)
        problems.push(`${count("repository.disconnected").length} repository audit entries`);
      if (x.revokedMessages.length !== 1)
        problems.push(`${x.revokedMessages.length} notification messages`);
      else {
        const m = x.revokedMessages[0].payload;
        const text = JSON.stringify(m);
        if (m.payload.cause !== "deleted" || m.payload.repositoriesAffected !== 3)
          problems.push(`message ${m.payload.cause}/${m.payload.repositoriesAffected}`);
        if (m.payload.workspaces.length !== 2)
          problems.push("the message does not list both workspaces");
        if (text.includes(x.account.login) || /secret|token|ghs_/i.test(text))
          problems.push("the message carries a name or secret");
      }
      if (x.pushRows.events.length || x.pushRows.outbox.length || x.afterPush.status !== 202)
        problems.push("a push for a repository of the revoked installation was processed");
      if (x.pushRows.delivery?.outcome !== "ignored")
        problems.push(`push outcome ${x.pushRows.delivery?.outcome}`);
      if (
        JSON.stringify(x.edgeBefore.json.data.items) !== JSON.stringify(x.edgeAfter.json.data.items)
      )
        problems.push("another tenant's installations changed");
      return problems;
    },
  );
  add(
    "SCM-044",
    "the uninstall notification reaches the active holders of tenant integration.manage and each affected workspace's workspace_integration.manage holders once each, never a Viewer or anyone of another tenant",
    { status: 200 },
    async () => ({ status: 200, json: null, x: await world() }),
    (r) => {
      const { people, warnings, wlP } = r.x;
      const problems = [];
      const byUser = new Map();
      for (const w1 of warnings) {
        if (byUser.has(w1.recipientUserId)) problems.push("a person was notified twice");
        byUser.set(w1.recipientUserId, w1);
      }
      const get = (name) => byUser.get(people[name]);
      if (!get("admin")?.tenantLevel || get("admin").workspaceIds.length !== 2)
        problems.push(`administrator: ${JSON.stringify(get("admin"))}`);
      if (
        !get("manager") ||
        get("manager").tenantLevel ||
        JSON.stringify(get("manager").workspaceIds) !== JSON.stringify([w.A.paymentsWs])
      )
        problems.push(`payments manager: ${JSON.stringify(get("manager"))}`);
      if (
        !get("analyst") ||
        JSON.stringify(get("analyst").workspaceIds) !== JSON.stringify([w.A.identityWs])
      )
        problems.push(`identity manager: ${JSON.stringify(get("analyst"))}`);
      for (const name of ["viewer", "lead", "developer", "bOwner", "edgeOwner"])
        if (get(name)) problems.push(`${name} was notified`);
      if (warnings.length === 0) problems.push("nobody was notified");
      if (wlP === undefined) problems.push("no world");
      return problems;
    },
  );
  // ---- SPEC §16.2: revoked and suspended installations read revoked / suspended everywhere (SCM-059..062)
  const itemsOf = (res) => res.json?.data?.items ?? [];
  const mineIn = (res, id) => itemsOf(res).find((i) => i.id === id);
  add(
    "SCM-059",
    "after a signed installation.deleted, the tenant installation list and the workspace link of every workspace report revoked with statusChangedAt set and statusReason uninstalled (health revoked too), no endpoint reports linked for it, and the wizard's available list and connect refuse with 409 installation_revoked",
    { status: 200 },
    async () => ({ status: 200, json: null, x: await world() }),
    (r) => {
      const x = r.x;
      const linkId = x.flowP.link.json.data.installationLinkId;
      const wlP = x.flowP.link.json.data.id;
      const wlI = x.wlI;
      const problems = [];
      // control: before the uninstall everything reads linked with the fields empty
      for (const [name, res, id] of [
        ["tenant list", x.apiBefore.tenantList, linkId],
        ["payments link", x.apiBefore.payAdmin, wlP],
        ["identity link", x.apiBefore.idnAdmin, wlI],
      ]) {
        const row = mineIn(res, id);
        if (row?.status !== "linked" || row.statusChangedAt !== null || row.statusReason !== null)
          problems.push(`control: ${name} before is ${row?.status}/${row?.statusReason}`);
      }
      if (x.apiBefore.available.status !== 200)
        problems.push("control: available before is not 200");
      const expect = (name, res, id) => {
        const row = mineIn(res, id);
        if (res.status !== 200 || !row) return problems.push(`${name}: ${res.status}, no row`);
        if (row.status !== "revoked") problems.push(`${name} status is ${row.status}`);
        if (row.health !== "revoked") problems.push(`${name} health is ${row.health}`);
        if (row.statusReason !== "uninstalled") problems.push(`${name} reason ${row.statusReason}`);
        if (!row.statusChangedAt || Number.isNaN(Date.parse(row.statusChangedAt)))
          problems.push(`${name} has no date`);
      };
      expect("tenant list", x.apiAfter.tenantList, linkId);
      expect("payments link (admin)", x.apiAfter.payAdmin, wlP);
      expect("payments link (manager)", x.apiAfter.payManager, wlP);
      expect("identity link (admin)", x.apiAfter.idnAdmin, wlI);
      for (const [name, res] of Object.entries(x.apiAfter))
        if (itemsOf(res).some((i) => i.account?.login === x.account.login && i.status === "linked"))
          problems.push(`${name} still reports it as linked`);
      for (const name of ["available", "connect"])
        if (
          x.apiAfter[name].status !== 409 ||
          x.apiAfter[name].json?.error?.details?.reason !== "installation_revoked"
        )
          problems.push(`${name} answered ${x.apiAfter[name].status}`);
      const dates = new Set(
        [x.apiAfter.tenantList, x.apiAfter.payAdmin, x.apiAfter.idnAdmin].map(
          (res) => itemsOf(res).find((i) => i.statusReason)?.statusChangedAt,
        ),
      );
      if (dates.size !== 1) problems.push("the date differs between endpoints");
      if (x.installation?.statusReason !== "uninstalled" || !x.installation?.statusChangedAt)
        problems.push("the installation row has no date or reason");
      return problems;
    },
  );
  add(
    "SCM-060",
    "tenant isolation of the status fields: another tenant's installations keep reading linked with empty statusChangedAt and statusReason across the uninstall, its answer is identical before and after, and the revoked account never appears in it",
    { status: 200 },
    async () => ({ status: 200, json: null, x: await world() }),
    (r) => {
      const x = r.x;
      const problems = [];
      const before = itemsOf(x.apiBefore.edgeList);
      const after = itemsOf(x.apiAfter.edgeList);
      if (JSON.stringify(before) !== JSON.stringify(after))
        problems.push("another tenant's installations changed");
      for (const i of after)
        if (i.status !== "linked" || i.statusChangedAt !== null || i.statusReason !== null)
          problems.push(`another tenant's installation reads ${i.status}/${i.statusReason}`);
      if (JSON.stringify(x.apiAfter.edgeList.json).includes(x.account.login))
        problems.push("the revoked account leaks to another tenant");
      // control: tenant A's own list does carry the revoked row with the fields
      if (!itemsOf(x.apiAfter.tenantList).some((i) => i.status === "revoked" && i.statusReason))
        problems.push("control: tenant A's list has no revoked row");
      return problems;
    },
  );
  const suspendWorld = () =>
    once("scm-status-roundtrip", async () => {
      const db = suiteDb();
      const admin = S("admin")(w);
      const account = orgAccount("sp");
      const flow = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user: ghUser(),
        orgRole: "admin",
        repos: [stubRepo(base + 21)],
      });
      const wl = flow.link.json.data.id;
      const linkId = flow.link.json.data.installationLinkId;
      const handle = (message) =>
        createScmEventHandler({
          db,
          config: { scm: { syncFailuresBeforeDisconnect: 3 } },
          logger: quietLog,
        })(message, { log: quietLog });
      const send = async (action) => {
        const deliveryId = randomUUID();
        const res = await deliver({
          payload: {
            action,
            installation: { id: Number(flow.installationId), account: { login: account.login } },
          },
          deliveryId,
        });
        const rows = await rowsFor(deliveryId);
        if (rows.outbox[0]) await handle(rows.outbox[0].payload);
        return res;
      };
      const view = async () => ({
        list: mineIn(
          await w.api("GET", "/integrations/github/installations", { cookie: admin }),
          linkId,
        ),
        link: mineIn(await w.api("GET", ghPath(PAY()), { cookie: admin }), wl),
        row: await db.scmInstallation.findFirst({
          where: { externalInstallationId: String(flow.installationId) },
        }),
      });
      const initial = await view();
      const suspendRes = await send("suspend");
      const suspended = await view();
      const suspendAgain = await send("suspend");
      const stillSuspended = await view();
      const unsuspendRes = await send("unsuspend");
      const active = await view();
      return { initial, suspendRes, suspended, suspendAgain, stillSuspended, unsuspendRes, active };
    });
  add(
    "SCM-061",
    "a suspension reports suspended (with statusChangedAt and statusReason suspended) in the tenant list and the workspace link, repeating it keeps the first date, and unsuspending returns both to linked with the fields cleared in the API and the row",
    { status: 200 },
    async () => ({ status: 200, json: null, x: await suspendWorld() }),
    (r) => {
      const x = r.x;
      const problems = [];
      const clear = (v) => v?.statusChangedAt === null && v?.statusReason === null;
      if (x.initial.list?.status !== "linked" || !clear(x.initial.list) || !clear(x.initial.link))
        problems.push("control: the fresh link does not read linked with empty fields");
      if (x.suspendRes.status !== 202 || x.unsuspendRes.status !== 202)
        problems.push("a signed event was not accepted");
      for (const [name, v] of [
        ["list", x.suspended.list],
        ["link", x.suspended.link],
      ]) {
        if (v?.status !== "suspended" || v.health !== "suspended")
          problems.push(`${name} while suspended: ${v?.status}/${v?.health}`);
        if (v?.statusReason !== "suspended" || !v.statusChangedAt)
          problems.push(`${name} while suspended has ${v?.statusReason}/${v?.statusChangedAt}`);
      }
      if (
        x.stillSuspended.row?.statusChangedAt?.getTime() !==
        x.suspended.row?.statusChangedAt?.getTime()
      )
        problems.push("a repeated suspension moved the date");
      for (const [name, v] of [
        ["list", x.active.list],
        ["link", x.active.link],
      ]) {
        if (v?.status !== "linked" || !clear(v))
          problems.push(`${name} after unsuspend: ${v?.status}`);
      }
      if (
        x.active.row?.status !== "active" ||
        x.active.row.statusChangedAt ||
        x.active.row.statusReason
      )
        problems.push("the row kept the suspension fields");
      return problems;
    },
  );
  const goneWorld = () =>
    once("scm-status-gone", async () => {
      const db = suiteDb();
      const admin = S("admin")(w);
      const account = orgAccount("gn");
      const flow = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user: ghUser(),
        orgRole: "admin",
      });
      const wl = flow.link.json.data.id;
      const linkId = flow.link.json.data.installationLinkId;
      const before = mineIn(await w.api("GET", ghPath(PAY()), { cookie: admin }), wl);
      await stubCtl("/__control/remove-installation", { id: flow.installationId });
      const refresh = await w.api("POST", `${ghPath(PAY())}/links/${wl}/refresh`, {
        cookie: admin,
      });
      const list = await w.api("GET", "/integrations/github/installations", { cookie: admin });
      const links = await w.api("GET", ghPath(PAY()), { cookie: admin });
      const row = await db.scmInstallation.findFirst({
        where: { externalInstallationId: String(flow.installationId) },
      });
      const edge = await edgeTenant();
      const edgeList = await w.api("GET", "/integrations/github/installations", {
        cookie: edge.owner,
      });
      return {
        before,
        refresh,
        list: mineIn(list, linkId),
        link: mineIn(links, wl),
        row,
        edgeList,
      };
    });
  add(
    "SCM-062",
    "a refresh that finds the installation gone on GitHub marks it revoked with statusReason not_found_on_github and a date, in the refresh answer, the tenant list, the workspace link and the row, and no other tenant sees it",
    { status: 200 },
    async () => ({ status: 200, json: null, x: await goneWorld() }),
    (r) => {
      const x = r.x;
      const problems = [];
      if (x.before?.status !== "linked")
        problems.push("control: the link did not read linked first");
      if (x.refresh.status !== 200) problems.push(`refresh answered ${x.refresh.status}`);
      for (const [name, v] of [
        ["refresh answer", x.refresh.json?.data],
        ["tenant list", x.list],
        ["workspace link", x.link],
      ]) {
        if (v?.status !== "revoked" || v.health !== "revoked")
          problems.push(`${name} reads ${v?.status}/${v?.health}`);
        if (v?.statusReason !== "not_found_on_github" || !v.statusChangedAt)
          problems.push(`${name} has ${v?.statusReason}/${v?.statusChangedAt}`);
      }
      if (
        x.row?.status !== "revoked" ||
        x.row.statusReason !== "not_found_on_github" ||
        !x.row.statusChangedAt
      )
        problems.push("the row has no reason or date");
      if (itemsOf(x.edgeList).some((i) => i.status !== "linked" || i.statusReason !== null))
        problems.push("another tenant sees a status");
      return problems;
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 12d. GitHub integration: restoring repositories when a workspace links an installation (SPEC §18.7). The signed webhook runs
//      through the API; the scm event consumer runs in-process (as in 12c). Tenant A uninstalls installation X, then links a
//      NEW installation Y; another tenant holds disconnected repositories with the same GitHub repository ids.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("GitHub integration: restoring repositories");
  const base = 8000000 + (Date.now() % 100000) * 10;
  const [R1, R2, R3, R4, R5] = [1, 2, 3, 4, 5].map((n) => base + n);
  const PAY = () => w.A.paymentsWs;
  const IDN = () => w.A.identityWs;
  const world = () =>
    once("scm-restore", async () => {
      const db = suiteDb();
      const admin = S("admin")(w);
      const edge = await edgeTenant();
      const edgeWs = await edgeWorkspace();
      const tenantId = await tenantIdA();
      const edgeTenantId = (await w.api("GET", "/me", { cookie: edge.owner })).json.data.tenant.id;
      const user = ghUser();
      const account = orgAccount("rs");
      const handleEvent = (message) =>
        createScmEventHandler({
          db,
          config: { scm: { syncFailuresBeforeDisconnect: 3 } },
          logger: quietLog,
        })(message, { log: quietLog });
      const uninstall = async (installationId, accountLogin) => {
        const deliveryId = randomUUID();
        const res = await deliver({
          payload: {
            action: "deleted",
            installation: { id: Number(installationId), account: { login: accountLogin } },
          },
          deliveryId,
        });
        const rows = await rowsFor(deliveryId);
        await handleEvent(rows.outbox[0].payload);
        return res;
      };
      const rowOf = (id) => db.repository.findUnique({ where: { id } });
      const rowsOf = async (tid, ids) =>
        (
          await db.repository.findMany({
            where: { tenantId: tid, externalRepoId: { in: ids.map(String) } },
          })
        ).sort((a, b) => a.externalRepoId.localeCompare(b.externalRepoId));
      const view = (r) =>
        r && {
          id: r.id,
          status: r.status,
          reason: r.disconnectReason,
          linkId: r.linkId,
          workspaceLinkId: r.workspaceLinkId,
          workspaceId: r.workspaceId,
          nodeId: r.nodeId,
          externalRepoId: r.externalRepoId,
          failures: r.consecutiveSyncFailures,
        };
      const allowRows = (tid) =>
        db.scmWorkspaceLinkRepository.findMany({
          where: { tenantId: tid },
          orderBy: { externalRepoId: "asc" },
        });

      // --- tenant A: installation X in Payments (r1..r5 listed; r1, r2, r3, r5 allow-listed) and Identity (r4)
      const flowX = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user,
        orgRole: "admin",
        repos: [R1, R2, R3, R4, R5].map(stubRepo),
      });
      const flowXI = await linkFlow(admin, {
        workspaceId: IDN(),
        installationId: flowX.installationId,
        account,
        user,
        orgRole: "admin",
      });
      const wlX = flowX.link.json.data.id;
      const wlXI = flowXI.link.json.data.id;
      await putAllowList(admin, PAY(), wlX, [R1, R2, R3, R5]);
      await putAllowList(admin, IDN(), wlXI, [R4]);
      const c1 = await connectRepo(admin, PAY(), wlX, R1);
      const c2 = await connectRepo(admin, PAY(), wlX, R2);
      const c3 = await connectRepo(admin, PAY(), wlX, R3);
      const c4 = await connectRepo(admin, IDN(), wlXI, R4);
      const ids = {
        r1: c1.json.data.id,
        r2: c2.json.data.id,
        r3: c3.json.data.id,
        r4: c4.json.data.id,
      };
      // r3 was disconnected earlier for another reason (a direct, tenant-scoped update)
      await db.repository.updateMany({
        where: { id: ids.r3, tenantId },
        data: {
          status: "disconnected",
          disconnectReason: "repo_inaccessible",
          disconnectedAt: new Date(),
        },
      });

      // --- the other tenant: installation E with the same GitHub repository ids r1 and r2, connected, then uninstalled
      const edgeAccount = orgAccount("re");
      const edgeUser = ghUser();
      const flowE = await linkFlow(edge.owner, {
        workspaceId: edgeWs,
        account: edgeAccount,
        user: edgeUser,
        orgRole: "admin",
        repos: [R1, R2].map(stubRepo),
      });
      const wlE = flowE.link.json.data.id;
      await putAllowList(edge.owner, edgeWs, wlE, [R1, R2]);
      const e1 = await connectRepo(edge.owner, edgeWs, wlE, R1);
      const e2 = await connectRepo(edge.owner, edgeWs, wlE, R2);
      const edgeIds = [e1.json.data.id, e2.json.data.id];

      const beforeRevoke = (await rowsOf(tenantId, [R1, R2, R3, R4])).map(view);
      await uninstall(flowX.installationId, account.login);
      await uninstall(flowE.installationId, edgeAccount.login);
      const afterRevoke = (await rowsOf(tenantId, [R1, R2, R3, R4])).map(view);
      const edgeAfterRevoke = (await rowsOf(edgeTenantId, [R1, R2])).map(view);
      const allowAfterRevoke = await allowRows(tenantId);

      // --- tenant A links a NEW installation Y in Payments: r1, r3, r4, r5 are listed, r2 is not
      const outboxBefore = await db.outboxMessage.count({
        where: { tenantId, type: "repository.connected" },
      });
      const flowY = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user,
        orgRole: "admin",
        repos: [R1, R3, R4, R5].map(stubRepo),
      });
      const wlY = flowY.link.json.data.id;
      const afterPay = (await rowsOf(tenantId, [R1, R2, R3, R4])).map(view);
      const edgeAfterPay = (await rowsOf(edgeTenantId, [R1, R2])).map(view);
      const allowAfterPay = await allowRows(tenantId);
      const restoredAudits = await db.auditLog.findMany({
        where: { tenantId, action: "repository.restored", targetId: { in: Object.values(ids) } },
      });
      const outboxAfter = await db.outboxMessage.findMany({
        where: { tenantId, type: "repository.connected" },
      });
      const allRowsA = await db.repository.count({
        where: { tenantId, externalRepoId: { in: [R1, R2, R3, R4].map(String) } },
      });

      // --- allow-list after the re-install: another workspace's repository (r4) is refused, an earlier link's (r5) is not
      const withOther = await putAllowList(admin, PAY(), wlY, [R1, R5, R4]);
      const withEarlier = await putAllowList(admin, PAY(), wlY, [R1, R5]);
      const allowAfterEdit = (await allowRows(tenantId)).filter((r) =>
        [R1, R4, R5].map(String).includes(r.externalRepoId),
      );

      // --- Identity links Y itself: r4 comes back only now
      const flowYI = await linkFlow(admin, {
        workspaceId: IDN(),
        installationId: flowY.installationId,
        account,
        user,
        orgRole: "admin",
      });
      const afterIdn = (await rowsOf(tenantId, [R1, R2, R3, R4])).map(view);

      // --- the other tenant links its new installation (r1 and r2 listed): its rows come back, tenant A's do not change
      const edgeBeforeRelink = (await rowsOf(edgeTenantId, [R1, R2])).map(view);
      const flowE2 = await linkFlow(edge.owner, {
        workspaceId: edgeWs,
        account: edgeAccount,
        user: edgeUser,
        orgRole: "admin",
        repos: [R1, R2].map(stubRepo),
      });
      const edgeAfterRelink = (await rowsOf(edgeTenantId, [R1, R2])).map(view);
      const afterEdge = (await rowsOf(tenantId, [R1, R2, R3, R4])).map(view);
      const rowAtEnd = await rowOf(ids.r1);
      return {
        ids,
        edgeIds,
        beforeRevoke,
        afterRevoke,
        edgeAfterRevoke,
        afterPay,
        edgeAfterPay,
        afterIdn,
        edgeBeforeRelink,
        edgeAfterRelink,
        afterEdge,
        flowY,
        flowYI,
        flowE2,
        wlX,
        wlY,
        wlE,
        withOther,
        withEarlier,
        allowAfterRevoke,
        allowAfterPay,
        allowAfterEdit,
        restoredAudits,
        outboxBefore,
        outboxAfter,
        allRowsA,
        rowAtEnd,
        ext: { R1, R2, R3, R4, R5 },
        tenantId,
        edgeTenantId,
      };
    });
  const byExt = (rows, ext) => rows.find((r) => r.externalRepoId === String(ext));
  add(
    "SCM-048",
    "linking a new installation restores to active, in the same row, only the workspace's repositories that were disconnected as installation_revoked / workspace_unlinked / installation_unlinked, are accessible to the new installation and (for installation_revoked) still on the allow-list; repo_inaccessible and inaccessible repositories stay disconnected, and another workspace's repositories wait until it links itself",
    { status: 200 },
    async () => ({ status: 200, json: null, x: await world() }),
    (r) => {
      const x = r.x;
      const E = x.ext;
      const problems = [];
      if (x.flowY.link?.status !== 201) problems.push(`linking Y answered ${x.flowY.link?.status}`);
      if (x.beforeRevoke.filter((v) => v.status === "active").length !== 3)
        problems.push("fixture: r1, r2 and r4 should be active before the uninstall");
      // fixture sanity (controls): the revoke produced the starting state
      for (const n of [E.R1, E.R2, E.R4])
        if (byExt(x.afterRevoke, n).reason !== "installation_revoked")
          problems.push(`r${n - E.R1 + 1} after the uninstall: ${byExt(x.afterRevoke, n).reason}`);
      if (byExt(x.afterRevoke, E.R3).reason !== "repo_inaccessible")
        problems.push(`r3 after the uninstall: ${byExt(x.afterRevoke, E.R3).reason}`);
      const r1 = byExt(x.afterPay, E.R1);
      const r1Before = byExt(x.beforeRevoke, E.R1);
      if (r1.status !== "active" || r1.reason !== null)
        problems.push(`r1 is ${r1.status}/${r1.reason}`);
      if (
        r1.id !== x.ids.r1 ||
        r1.externalRepoId !== r1Before.externalRepoId ||
        r1.nodeId !== r1Before.nodeId
      )
        problems.push("r1 is not the same row (id, external id, node id)");
      if (r1.failures !== 0) problems.push(`r1 failures ${r1.failures}`);
      if (r1.linkId === r1Before.linkId || r1.workspaceLinkId === r1Before.workspaceLinkId)
        problems.push("r1 still points at the old links");
      if (
        r1.workspaceLinkId !== x.wlY ||
        r1.linkId !== x.flowY.link?.json?.data?.installationLinkId
      )
        problems.push("r1 does not point at the new links");
      const r2 = byExt(x.afterPay, E.R2);
      if (r2.status !== "disconnected" || r2.reason !== "installation_revoked")
        problems.push(`r2 (not accessible) is ${r2.status}/${r2.reason}`);
      if (JSON.stringify(r2) !== JSON.stringify(byExt(x.afterRevoke, E.R2)))
        problems.push("r2 changed");
      const r3 = byExt(x.afterPay, E.R3);
      if (r3.status !== "disconnected" || r3.reason !== "repo_inaccessible")
        problems.push(`r3 (repo_inaccessible, accessible) is ${r3.status}/${r3.reason}`);
      const r4 = byExt(x.afterPay, E.R4);
      if (JSON.stringify(r4) !== JSON.stringify(byExt(x.afterRevoke, E.R4)))
        problems.push("another workspace's repository changed when Payments linked");
      if (x.allRowsA !== 4) problems.push(`${x.allRowsA} repository rows for 4 repositories`);
      const audit = x.restoredAudits.filter((a) => a.targetId === x.ids.r1);
      if (x.restoredAudits.length !== 1 || audit.length !== 1)
        problems.push(
          `${x.restoredAudits.length} repository.restored entries after the first link`,
        );
      else if (audit[0].metadata?.previousReason !== "installation_revoked")
        problems.push(`previousReason ${audit[0].metadata?.previousReason}`);
      if (x.outboxAfter.length !== x.outboxBefore + 1)
        problems.push(`${x.outboxAfter.length - x.outboxBefore} repository.connected messages`);
      // the allow-list entry of r1 moved to the new workspace link; exactly one row
      const entries = x.allowAfterPay.filter((a) => a.externalRepoId === String(E.R1));
      if (entries.length !== 1 || entries[0].workspaceLinkId !== x.wlY)
        problems.push(`r1 allow-list: ${entries.length} rows`);
      // r2 and r3 stay on the old list (not touched)
      if (x.allowAfterPay.filter((a) => a.externalRepoId === String(E.R2)).length !== 1)
        problems.push("r2's allow-list entry changed");
      // Identity links Y itself: now r4 returns
      const r4End = byExt(x.afterIdn, E.R4);
      if (
        r4End.status !== "active" ||
        r4End.id !== x.ids.r4 ||
        r4End.workspaceLinkId === r4.workspaceLinkId
      )
        problems.push(`r4 after Identity linked: ${r4End.status}`);
      if (
        byExt(x.afterIdn, E.R2).status !== "disconnected" ||
        byExt(x.afterIdn, E.R3).reason !== "repo_inaccessible"
      )
        problems.push("r2 or r3 changed when Identity linked");
      return problems;
    },
  );
  add(
    "SCM-049",
    "restoring repositories never crosses tenants: another tenant's disconnected repository with the same GitHub repository id is left untouched when tenant A links a new installation, and tenant A's rows are left untouched when the other tenant links its own",
    { status: 200 },
    async () => ({ status: 200, json: null, x: await world() }),
    (r) => {
      const x = r.x;
      const E = x.ext;
      const problems = [];
      const gone = x.edgeAfterRevoke;
      for (const row of gone)
        if (row.status !== "disconnected" || row.reason !== "installation_revoked")
          problems.push(`fixture: the other tenant's row is ${row.status}/${row.reason}`);
      if (gone.length !== 2) problems.push(`fixture: ${gone.length} rows for the other tenant`);
      if (x.flowE2.link?.status !== 201)
        problems.push(`the other tenant's link answered ${x.flowE2.link?.status}`);
      // tenant A linked a new installation that lists r1: only A's row came back (control: A's r1 is active)
      if (byExt(x.afterPay, E.R1).status !== "active")
        problems.push("control: tenant A's r1 was not restored");
      if (JSON.stringify(x.edgeAfterPay) !== JSON.stringify(x.edgeAfterRevoke))
        problems.push("the other tenant's rows changed when tenant A linked");
      if (JSON.stringify(x.edgeBeforeRelink) !== JSON.stringify(x.edgeAfterPay))
        problems.push("the other tenant's rows changed before it linked");
      // the other tenant links: its rows are restored (control), tenant A's are unchanged
      for (const row of x.edgeAfterRelink)
        if (row.status !== "active" || row.reason !== null)
          problems.push(`control: the other tenant's row r${row.externalRepoId} is ${row.status}`);
      if (
        JSON.stringify(x.edgeAfterRelink.map((v) => v.id).sort()) !==
        JSON.stringify([...x.edgeIds].sort())
      )
        problems.push("the other tenant's rows are not the same rows");
      if (JSON.stringify(x.afterEdge) !== JSON.stringify(x.afterIdn))
        problems.push("tenant A's rows changed when the other tenant linked");
      if (x.edgeAfterRelink.some((v) => [x.ids.r1, x.ids.r2].includes(v.id)))
        problems.push("a row was shared between tenants");
      if (!x.rowAtEnd || x.rowAtEnd.tenantId !== x.tenantId)
        problems.push("tenant A's r1 row moved");
      return problems;
    },
  );
  add(
    "SCM-050",
    "after the re-install the workspace can add a repository that was on an earlier (revoked) link of its own allow-list to the new link, while a repository on another workspace's list still gives the generic 409",
    { status: 409, code: "CONFLICT" },
    async () => (await world()).withOther,
    async () => {
      const x = await world();
      const problems = [];
      if (x.withOther.json.error.details?.reason !== "allow_list_conflict")
        problems.push(`reason ${x.withOther.json.error.details?.reason}`);
      const text = JSON.stringify(x.withOther.json);
      if (text.includes("Identity") || text.includes(x.wlY))
        problems.push("the refusal names the other workspace");
      if (x.withEarlier.status !== 200)
        problems.push(`the earlier link's repository answered ${x.withEarlier.status}`);
      const mine = (id) => x.allowAfterEdit.filter((a) => a.externalRepoId === String(id));
      if (mine(x.ext.R5).length !== 1 || mine(x.ext.R5)[0].workspaceLinkId !== x.wlY)
        problems.push(`r5 allow-list rows: ${mine(x.ext.R5).length}`);
      if (mine(x.ext.R1).length !== 1)
        problems.push(`r1 allow-list rows: ${mine(x.ext.R1).length}`);
      if (mine(x.ext.R4).length !== 1 || mine(x.ext.R4)[0].workspaceLinkId === x.wlY)
        problems.push("the other workspace's entry moved or was copied");
      return problems;
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 12e. GitHub integration: "Use an existing installation" (SPEC §16.2): two-step discovery, then the normal flow with D5 on
//      consume; and restoring repositories when an installation gains access (installation_repositories.added, SPEC §18.7).
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("GitHub integration: discovery and restore on gaining access");
  const asA = () => S("admin")(w);
  const PAY = () => w.A.paymentsWs;
  const IDN = () => w.A.identityWs;
  const setting = (cookie, value) =>
    w.api("PUT", "/integrations/settings", { cookie, body: { allowWorkspaceLinking: value } });
  const stateOf = (response) =>
    response.status === 200
      ? new URL(response.json.data.authorizeUrl).searchParams.get("state")
      : null;
  /** Sets up GitHub's side for a user who can see `installs` and asks for a discovery state in the workspace. */
  async function discoverFlow(cookie, { workspaceId, user, installs, visible, orgRoles = {} }) {
    for (const i of installs)
      await stubCtl("/__control/installation", {
        id: i.id,
        account: i.account,
        suspended_at: i.suspended ? "2026-01-01T00:00:00Z" : null,
        ...(i.repos ? { repos: i.repos } : { repos: [] }),
      });
    const code = `code-${randomBytes(6).toString("hex")}`;
    await stubCtl("/__control/code", {
      code,
      user,
      installationIds: (visible ?? installs.map((i) => i.id)).map(String),
      orgRoles,
    });
    const disc = await w.api("POST", `${ghPath(workspaceId)}/discover`, { cookie });
    return { disc, code, state: stateOf(disc), workspaceId };
  }
  const role = (login, r) => ({ [login]: { role: r, state: "active" } });
  const counts = async () => {
    const db = suiteDb();
    const tenantId = await tenantIdA();
    return {
      installations: await db.scmInstallation.count(),
      links: await db.scmInstallationLink.count({ where: { tenantId } }),
      workspaceLinks: await db.scmWorkspaceLink.count({ where: { tenantId } }),
    };
  };

  // ---- who may discover (SCM-051)
  const permScenario = () =>
    once("scm-discover-perm", async () => {
      const devLead = await loginAs("demo.devlead@demo.example");
      const analyst = await loginAs("demo.analyst@demo.example");
      const who = {
        viewer: S("viewer")(w),
        developer: S("developer")(w),
        lead: S("lead")(w),
        devLead,
        analyst,
      };
      const denied = {};
      for (const [name, cookie] of Object.entries(who))
        denied[name] = await w.api("POST", `${ghPath(PAY())}/discover`, { cookie });
      return {
        denied,
        unauthenticated: await w.api("POST", `${ghPath(PAY())}/discover`),
        hidden: await w.api("POST", `${ghPath(IDN())}/discover`, { cookie: S("manager")(w) }),
        missing: await w.api("POST", `${ghPath("00000000-0000-4000-8000-000000000000")}/discover`, {
          cookie: S("manager")(w),
        }),
        control: await w.api("POST", `${ghPath(PAY())}/discover`, { cookie: S("manager")(w) }),
        adminControl: await w.api("POST", `${ghPath(IDN())}/discover`, { cookie: asA() }),
      };
    });
  add(
    "SCM-051",
    "discovering existing installations needs workspace_integration.manage in the workspace: Viewer, Developer, Lead, Dev Lead and Security Analyst get 403, no session 401, a workspace the caller cannot see 404 (same as a missing one); the Manager and the Administrator get the authorize URL",
    FORBIDDEN,
    async () => (await permScenario()).denied.developer,
    async () => {
      const x = await permScenario();
      const problems = [];
      for (const [name, res] of Object.entries(x.denied))
        if (res.status !== 403) problems.push(`${name} answered ${res.status}`);
      if (x.unauthenticated.status !== 401)
        problems.push(`no session answered ${x.unauthenticated.status}`);
      if (x.hidden.status !== 404) problems.push(`a hidden workspace answered ${x.hidden.status}`);
      if (JSON.stringify(x.hidden.json.error) !== JSON.stringify(x.missing.json?.error))
        problems.push("a hidden workspace differs from a missing one");
      for (const [name, res] of [
        ["manager", x.control],
        ["admin", x.adminControl],
      ]) {
        if (res.status !== 200) problems.push(`${name} control answered ${res.status}`);
        else {
          const url = new URL(res.json.data.authorizeUrl);
          if (!url.searchParams.get("state")) problems.push(`${name}: the URL has no state`);
          if (url.searchParams.has("installation_id"))
            problems.push(`${name}: the URL names an installation`);
        }
      }
      return problems;
    },
  );

  // ---- the tenant setting (SCM-052)
  const offScenario = () =>
    once("scm-discover-off", async () => {
      const admin = asA();
      const manager = S("manager")(w);
      const user = ghUser();
      const account = orgAccount("dof");
      const id = nextInstallationId();
      const installs = [{ id, account }];
      const minted = await discoverFlow(manager, {
        workspaceId: PAY(),
        user,
        installs,
        orgRoles: role(account.login, "admin"),
      });
      const before = await counts();
      const out = {};
      const off = await setting(admin, false);
      try {
        out.discover = await w.api("POST", `${ghPath(PAY())}/discover`, { cookie: manager });
        out.consume = await consumeState(manager, minted);
      } finally {
        out.on = await setting(admin, true);
      }
      out.after = await counts();
      out.afterOn = await w.api("POST", `${ghPath(PAY())}/discover`, { cookie: manager });
      out.minted = minted;
      out.before = before;
      out.off = off;
      return out;
    });
  add(
    "SCM-052",
    "with the tenant setting off, starting a discovery and consuming a discovery state minted earlier both answer 403 workspace_linking_disabled and create nothing; turning it back on lets the Manager discover again",
    FORBIDDEN,
    async () => (await offScenario()).discover,
    async () => {
      const x = await offScenario();
      const problems = [];
      if (x.minted.disc.status !== 200)
        problems.push(`minting before the change answered ${x.minted.disc.status}`);
      if (x.off.status !== 200) problems.push(`turning the setting off answered ${x.off.status}`);
      for (const op of ["discover", "consume"]) {
        if (x[op].status !== 403) problems.push(`${op} answered ${x[op].status}`);
        else if (x[op].json.error.details?.reason !== "workspace_linking_disabled")
          problems.push(`${op} reason ${x[op].json.error.details?.reason}`);
      }
      if (JSON.stringify(x.before) !== JSON.stringify(x.after))
        problems.push("rows were created while off");
      if (x.on.status !== 200) problems.push("the setting could not be turned back on");
      if (x.afterOn.status !== 200)
        problems.push(`discover after turning it on answered ${x.afterOn.status}`);
      return problems;
    },
  );

  // ---- the discovery state (SCM-053)
  const stateScenario = () =>
    once("scm-discover-state", async () => {
      const admin = asA();
      const manager = S("manager")(w);
      const user = ghUser();
      const account = orgAccount("dst");
      const id = nextInstallationId();
      const mint = (cookie = admin) =>
        discoverFlow(cookie, {
          workspaceId: PAY(),
          user,
          installs: [{ id, account }],
          orgRoles: role(account.login, "admin"),
        });
      const a = await mint();
      const flipped = a.state.slice(0, -1) + (a.state.at(-1) === "A" ? "B" : "A");
      const tampered = await consumeState(admin, { code: a.code, state: flipped });
      const truncated = await consumeState(admin, { code: a.code, state: a.state.slice(0, 30) });
      const garbage = await consumeState(admin, { code: a.code, state: "x".repeat(40) });
      const byOtherUser = await consumeState(manager, await mint());
      const byOtherSession = await consumeState(
        await loginAs("demo.admin@demo.example"),
        await mint(),
      );
      // single use: the second presentation of a state the owner already consumed is refused
      const b = await mint();
      const first = await consumeState(admin, b);
      const reused = await consumeState(admin, b);
      const edge = await edgeTenant();
      const foreignTenant = await consumeState(edge.owner, await mint());
      const stale = await mint();
      await sleep(3600); // SCM_LINK_STATE_TTL_SECONDS is 3 in this run
      const expired = await consumeState(admin, stale);
      // a discovery state cannot be used to link: it carries no installation (the response is a list, never a link)
      const links = await counts();
      return {
        tampered,
        truncated,
        garbage,
        byOtherUser,
        byOtherSession,
        first,
        reused,
        foreignTenant,
        expired,
        links,
        id,
      };
    });
  add(
    "SCM-053",
    "a discovery state is single use and bound to tenant, user and session: tampered, truncated, garbage, foreign-user, other-session, other-tenant, reused and expired variants all answer 400, and the genuine one lists candidates (200, mode discover) without linking",
    { status: 400, code: "BAD_REQUEST" },
    async () => (await stateScenario()).reused,
    async () => {
      const x = await stateScenario();
      const problems = [];
      for (const name of [
        "tampered",
        "truncated",
        "garbage",
        "byOtherUser",
        "byOtherSession",
        "foreignTenant",
        "expired",
      ])
        if (x[name].status !== 400) problems.push(`${name} answered ${x[name].status}`);
      if (x.first.status !== 200 || x.first.json.data.mode !== "discover")
        problems.push(`the genuine state answered ${x.first.status}`);
      if (x.first.json?.data?.candidates?.length !== 1)
        problems.push("the genuine state did not list the installation");
      if (x.first.status === 201) problems.push("a discovery state created a link");
      return problems;
    },
  );

  // ---- what discovery returns (SCM-054)
  const listScenario = () =>
    once("scm-discover-list", async () => {
      const admin = asA();
      const user = ghUser();
      const orgAdmin = { id: nextInstallationId(), account: orgAccount("da") };
      const orgMember = { id: nextInstallationId(), account: orgAccount("dm") };
      const ownPersonal = {
        id: nextInstallationId(),
        account: { id: user.id, login: user.login, type: "User" },
      };
      const otherPersonal = {
        id: nextInstallationId(),
        account: {
          id: user.id + 1000,
          login: `other-${randomBytes(3).toString("hex")}`,
          type: "User",
        },
      };
      const suspended = { id: nextInstallationId(), account: orgAccount("ds"), suspended: true };
      const invisible = { id: nextInstallationId(), account: orgAccount("di") };
      const linked = { id: nextInstallationId(), account: orgAccount("dl") };
      const flowLinked = await linkFlow(admin, {
        workspaceId: PAY(),
        installationId: undefined,
        account: linked.account,
        user,
        orgRole: "admin",
      });
      linked.id = flowLinked.installationId;
      const installs = [
        orgAdmin,
        orgMember,
        ownPersonal,
        otherPersonal,
        suspended,
        invisible,
        linked,
      ];
      const orgRoles = {
        ...role(orgAdmin.account.login, "admin"),
        ...role(orgMember.account.login, "member"),
        ...role(suspended.account.login, "admin"),
        ...role(linked.account.login, "admin"),
      };
      const before = await counts();
      const flow = await discoverFlow(admin, {
        workspaceId: PAY(),
        user,
        installs,
        visible: installs.filter((i) => i !== invisible).map((i) => i.id),
        orgRoles,
      });
      const res = await consumeState(admin, flow);
      const after = await counts();
      const db = suiteDb();
      const created = await db.scmInstallation.count({
        where: {
          externalInstallationId: {
            in: [orgAdmin, orgMember, ownPersonal, otherPersonal, suspended, invisible].map((i) =>
              String(i.id),
            ),
          },
        },
      });
      const other = await w.api("GET", ghPath(IDN()), { cookie: admin });
      return {
        res,
        before,
        after,
        created,
        ids: { orgAdmin, orgMember, ownPersonal, otherPersonal, suspended, invisible, linked },
        other,
      };
    });
  add(
    "SCM-054",
    "discovery answers 200 and lists only the installations the signed-in GitHub user can see, with eligible computed by D5 (organization admin yes, member no, own personal account yes, another personal account no), suspended and alreadyLinkedHere flagged, and creates no installation, link or workspace link",
    { status: 200 },
    async () => (await listScenario()).res,
    async () => {
      const x = await listScenario();
      const problems = [];
      const data = x.res.json?.data;
      if (data?.mode !== "discover") problems.push(`mode ${data?.mode}`);
      if (data?.truncated !== false) problems.push("truncated is not false");
      const by = (i) => data?.candidates?.find((c) => c.externalInstallationId === String(i.id));
      const expect = (name, i, eligible, extra = {}) => {
        const c = by(i);
        if (!c) return problems.push(`${name} is not listed`);
        if (c.eligible !== eligible) problems.push(`${name} eligible ${c.eligible}`);
        if (c.reason !== (eligible ? null : "not_owner"))
          problems.push(`${name} reason ${c.reason}`);
        if (c.account.login !== i.account.login) problems.push(`${name} account`);
        for (const [k, v] of Object.entries(extra))
          if (c[k] !== v) problems.push(`${name} ${k} ${c[k]}`);
      };
      const I = x.ids;
      expect("org admin", I.orgAdmin, true, { suspended: false, alreadyLinkedHere: false });
      expect("org member", I.orgMember, false);
      expect("own personal", I.ownPersonal, true);
      expect("other personal", I.otherPersonal, false);
      expect("suspended", I.suspended, true, { suspended: true });
      expect("already linked", I.linked, true, { alreadyLinkedHere: true });
      expect("other personal type", I.otherPersonal, false, { repositorySelection: "all" });
      if (by(I.invisible)) problems.push("an installation the user cannot see is listed");
      if (data?.candidates?.length !== 6) problems.push(`${data?.candidates?.length} candidates`);
      if (x.created !== 0) problems.push(`${x.created} installation rows were created`);
      if (JSON.stringify(x.before) !== JSON.stringify(x.after)) problems.push("rows were created");
      if (x.other.json.data.items.some((l) => l.account.login === I.orgAdmin.account.login))
        problems.push("a link appeared in another workspace");
      if (/ghu_stub|ghs_stub|access_token/.test(JSON.stringify(x.res.json)))
        problems.push("a token leaked");
      return problems;
    },
  );

  // ---- choosing a candidate (SCM-055)
  const pickScenario = () =>
    once("scm-discover-pick", async () => {
      const admin = asA();
      const edge = await edgeTenant();
      const edgeWs = await edgeWorkspace();
      const user = ghUser();
      const edgeAccount = orgAccount("dpe");
      const edgeFlow = await linkFlow(edge.owner, {
        workspaceId: edgeWs,
        account: edgeAccount,
        user,
        orgRole: "admin",
      });
      const edgeId = edgeFlow.installationId;
      const member = { id: nextInstallationId(), account: orgAccount("dpm") };
      const ok = { id: nextInstallationId(), account: orgAccount("dpo") };
      const unseen = { id: nextInstallationId(), account: orgAccount("dpu") };
      const installs = [{ id: edgeId, account: edgeAccount }, member, ok];
      const orgRoles = {
        ...role(edgeAccount.login, "admin"),
        ...role(member.account.login, "member"),
        ...role(ok.account.login, "admin"),
      };
      const flow = await discoverFlow(admin, { workspaceId: PAY(), user, installs, orgRoles });
      const listed = await consumeState(admin, flow);
      const before = await counts();
      const pick = (i, listedFor = true, roles = orgRoles) =>
        mintState(admin, {
          workspaceId: PAY(),
          installationId: i.id,
          account: i.account,
          user,
          orgRole: roles[i.account.login]?.role,
          listed: listedFor,
        });
      const toEdge = await (async () =>
        consumeState(admin, await pick({ id: edgeId, account: edgeAccount })))();
      const toMember = await (async () => consumeState(admin, await pick(member)))();
      await stubCtl("/__control/installation", {
        id: unseen.id,
        account: unseen.account,
        repos: [],
      });
      const toUnseen = await (async () => consumeState(admin, await pick(unseen, false)))();
      const toOk = await (async () => consumeState(admin, await pick(ok)))();
      return {
        listed,
        before,
        toEdge,
        toMember,
        toUnseen,
        toOk,
        edgeId,
        edgeAccount,
        member,
        unseen,
        ok,
      };
    });
  add(
    "SCM-055",
    "choosing a candidate runs the normal flow with D5 on consume: an organization installation the user is only a member of answers 403, one the user cannot see answers 403, one linked to another tenant is listed like any other and gives the generic 409 when linked, and an eligible one links (201)",
    { status: 409, code: "CONFLICT" },
    async () => (await pickScenario()).toEdge,
    async () => {
      const x = await pickScenario();
      const problems = [];
      const row = (i) =>
        x.listed.json?.data?.candidates?.find((c) => c.externalInstallationId === String(i));
      const edgeRow = row(x.edgeId);
      const okRow = row(x.ok.id);
      if (!edgeRow)
        problems.push("the installation of another tenant is not listed like any other");
      else if (
        JSON.stringify(Object.keys(edgeRow).sort()) !== JSON.stringify(Object.keys(okRow).sort()) ||
        edgeRow.alreadyLinkedHere !== false ||
        edgeRow.eligible !== true
      )
        problems.push(
          `the other tenant's installation reads differently: ${JSON.stringify(edgeRow)}`,
        );
      if (x.toEdge.json.error.details?.reason !== "installation_unavailable")
        problems.push(`reason ${x.toEdge.json.error.details?.reason}`);
      const text = JSON.stringify(x.toEdge.json);
      if (text.includes(x.edgeAccount.login) || /tenant/i.test(x.toEdge.json.error.message))
        problems.push("the refusal names the owner");
      if (x.toMember.status !== 403) problems.push(`member pick answered ${x.toMember.status}`);
      if (x.toUnseen.status !== 403) problems.push(`unseen pick answered ${x.toUnseen.status}`);
      if (x.toOk.status !== 201) problems.push(`control pick answered ${x.toOk.status}`);
      else if (
        x.toOk.json.data.workspaceId !== PAY() ||
        x.toOk.json.data.account.login !== x.ok.account.login
      )
        problems.push("the link is wrong");
      return problems;
    },
  );

  // ---- the permission is re-checked when a discovery state is consumed (SCM-056)
  add(
    "SCM-056",
    "consuming a discovery state re-checks workspace_integration.manage in the state's workspace: a person who lost the key after minting is refused (403) and nothing is listed or created",
    FORBIDDEN,
    async () => (await lostScenario()).lost,
    async () => {
      const x = await lostScenario();
      const problems = [];
      if (x.mintedWith.disc.status !== 200) problems.push("the state could not be minted");
      if (x.withKey.status !== 200)
        problems.push(`with the key the listing answered ${x.withKey.status}`);
      if (JSON.stringify(x.before) !== JSON.stringify(x.after)) problems.push("rows were created");
      return problems;
    },
  );
  const lostScenario = () =>
    once("scm-discover-lost", async () => {
      const analystId = w.A.user;
      const managerRole = await integrationManagerRoleId();
      const analyst = await loginAs("demo.analyst@demo.example");
      const user = ghUser();
      const account = orgAccount("dlk");
      const installs = [{ id: nextInstallationId(), account }];
      const orgRoles = role(account.login, "admin");
      const withKey = await withRole(
        { userId: analystId, roleId: managerRole, workspaceId: IDN() },
        async () =>
          consumeState(
            analyst,
            await discoverFlow(analyst, { workspaceId: IDN(), user, installs, orgRoles }),
          ),
      );
      let mintedWith;
      await withRole({ userId: analystId, roleId: managerRole, workspaceId: IDN() }, async () => {
        mintedWith = await discoverFlow(analyst, { workspaceId: IDN(), user, installs, orgRoles });
      });
      const before = await counts();
      const lost = await consumeState(analyst, mintedWith);
      return { withKey, mintedWith, lost, before, after: await counts() };
    });

  // ---- restore on gaining access (SCM-057, SCM-058)
  const base = 9000000 + (Date.now() % 100000) * 10;
  const [R1, R2, R3, R4, R5, R6, R7, R9] = [1, 2, 3, 4, 5, 6, 7, 9].map((n) => base + n);
  const restoreWorld = () =>
    once("scm-restore-added", async () => {
      const db = suiteDb();
      const admin = asA();
      const edge = await edgeTenant();
      const edgeWs = await edgeWorkspace();
      const tenantId = await tenantIdA();
      const edgeTenantId = (await w.api("GET", "/me", { cookie: edge.owner })).json.data.tenant.id;
      const third = await w.api("POST", "/workspaces", {
        cookie: admin,
        body: { name: `Restore third ${w.suffix}` },
      });
      assert.equal(third.status, 201, `fixture: third workspace answered ${third.status}`);
      const THIRD = third.json.data.id;
      const user = ghUser();
      const account = orgAccount("ra");
      const handle = (message) =>
        createScmEventHandler({
          db,
          config: { scm: { syncFailuresBeforeDisconnect: 3 } },
          logger: quietLog,
        })(message, { log: quietLog });
      const deliverAndHandle = async (event, payload) => {
        const deliveryId = randomUUID();
        const res = await deliver({ event, payload, deliveryId });
        const rows = await rowsFor(deliveryId);
        if (rows.outbox[0]) await handle(rows.outbox[0].payload);
        return { res, rows, deliveryId };
      };
      // installation X: Payments (R1, R2, R3, R5), Third (R6), Identity (R4)
      const flowX = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user,
        orgRole: "admin",
        repos: [R1, R2, R3, R4, R5, R6, R7].map(stubRepo),
      });
      const link = (workspaceId) =>
        linkFlow(admin, {
          workspaceId,
          installationId: flowX.installationId,
          account,
          user,
          orgRole: "admin",
        });
      const flowXT = await link(THIRD);
      const flowXI = await link(IDN());
      const wl = {
        pay: flowX.link.json.data.id,
        third: flowXT.link.json.data.id,
        idn: flowXI.link.json.data.id,
      };
      await putAllowList(admin, PAY(), wl.pay, [R1, R2, R3, R5, R7]);
      await putAllowList(admin, THIRD, wl.third, [R6]);
      await putAllowList(admin, IDN(), wl.idn, [R4]);
      const ids = {};
      for (const [key, workspaceId, link, ext] of [
        ["r1", PAY(), wl.pay, R1],
        ["r2", PAY(), wl.pay, R2],
        ["r3", PAY(), wl.pay, R3],
        ["r5", PAY(), wl.pay, R5],
        ["r7", PAY(), wl.pay, R7],
        ["r6", THIRD, wl.third, R6],
        ["r4", IDN(), wl.idn, R4],
      ])
        ids[key] = (await connectRepo(admin, workspaceId, link, ext)).json.data.id;
      // the other tenant: the same GitHub repository ids, connected through its own installation
      const edgeAccount = orgAccount("re2");
      const flowE = await linkFlow(edge.owner, {
        workspaceId: edgeWs,
        account: edgeAccount,
        user: ghUser(),
        orgRole: "admin",
        repos: [R1, R2].map(stubRepo),
      });
      const wlE = flowE.link.json.data.id;
      await putAllowList(edge.owner, edgeWs, wlE, [R1, R2]);
      const e1 = await connectRepo(edge.owner, edgeWs, wlE, R1);
      const e2 = await connectRepo(edge.owner, edgeWs, wlE, R2);
      const edgeIds = [e1.json.data.id, e2.json.data.id];
      await db.repository.updateMany({
        where: { id: ids.r3, tenantId },
        data: {
          status: "disconnected",
          disconnectReason: "repo_inaccessible",
          disconnectedAt: new Date(),
        },
      });
      // uninstall both
      const uninstall = (installationId, login) =>
        deliverAndHandle("installation", {
          action: "deleted",
          installation: { id: Number(installationId), account: { login } },
        });
      await uninstall(flowX.installationId, account.login);
      await uninstall(flowE.installationId, edgeAccount.login);
      // r5 leaves the Payments allow-list while disconnected (tenant-scoped delete)
      await db.scmWorkspaceLinkRepository.deleteMany({
        where: { tenantId, workspaceLinkId: wl.pay, externalRepoId: String(R5) },
      });
      // r7 was disconnected by an unlink (no allow-list needed to return) but another workspace (Identity) has since put it
      // on ITS allow-list: one repository serves one workspace, so Payments must not get it back
      await db.scmWorkspaceLinkRepository.deleteMany({
        where: { tenantId, workspaceLinkId: wl.pay, externalRepoId: String(R7) },
      });
      await db.scmWorkspaceLinkRepository.create({
        data: {
          tenantId,
          workspaceLinkId: wl.idn,
          provider: "github",
          externalRepoId: String(R7),
          fullName: `org/repo${R7}`,
          addedByUserId: await meId(admin),
        },
      });
      await db.repository.updateMany({
        where: { id: ids.r7, tenantId },
        data: { disconnectReason: "workspace_unlinked" },
      });
      // the new installation Y is linked in Payments and Third while it lists only R9: nothing is restored by linking
      const flowY = await linkFlow(admin, {
        workspaceId: PAY(),
        account,
        user,
        orgRole: "admin",
        repos: [R9].map(stubRepo),
      });
      const flowYT = await linkFlow(admin, {
        workspaceId: THIRD,
        installationId: flowY.installationId,
        account,
        user,
        orgRole: "admin",
      });
      const wlY = { pay: flowY.link.json.data.id, third: flowYT.link.json.data.id };
      const rowsOf = async (tid, list) =>
        (
          await db.repository.findMany({
            where: { tenantId: tid, externalRepoId: { in: list.map(String) } },
            orderBy: { externalRepoId: "asc" },
          })
        ).map((r) => ({
          id: r.id,
          ext: r.externalRepoId,
          status: r.status,
          reason: r.disconnectReason,
          linkId: r.linkId,
          workspaceLinkId: r.workspaceLinkId,
          workspaceId: r.workspaceId,
          nodeId: r.nodeId,
          failures: r.consecutiveSyncFailures,
        }));
      const all = [R1, R2, R3, R4, R5, R6, R7];
      const beforeAdded = await rowsOf(tenantId, all);
      const edgeBefore = await rowsOf(edgeTenantId, [R1, R2]);
      const outboxBefore = await db.outboxMessage.count({
        where: { tenantId, type: "repository.connected" },
      });
      // GitHub now lets Y see every repository, and announces r1, r3, r4, r5, r6 (not r2) as added
      await stubCtl("/__control/repos", {
        installationId: flowY.installationId,
        repos: [R1, R2, R3, R4, R5, R6, R7, R9].map(stubRepo),
      });
      // an event that is not `added` restores nothing, whatever lists it carries
      await deliverAndHandle("installation_repositories", {
        action: "removed",
        installation: { id: Number(flowY.installationId), account: { login: account.login } },
        repositories_added: [R1, R3, R4, R5, R6, R7].map((id) => ({ id })),
        repositories_removed: [],
      });
      const afterNotAdded = await rowsOf(tenantId, all);
      const added = await deliverAndHandle("installation_repositories", {
        action: "added",
        installation: { id: Number(flowY.installationId), account: { login: account.login } },
        repositories_added: [R1, R3, R4, R5, R6, R7].map((id) => ({ id })),
        repositories_removed: [],
      });
      const afterAdded = await rowsOf(tenantId, all);
      const edgeAfter = await rowsOf(edgeTenantId, [R1, R2]);
      const restoredAudits = await db.auditLog.findMany({
        where: { tenantId, action: "repository.restored", targetId: { in: Object.values(ids) } },
      });
      const outboxAfter = await db.outboxMessage.count({
        where: { tenantId, type: "repository.connected" },
      });
      const allow = await db.scmWorkspaceLinkRepository.findMany({
        where: { tenantId, externalRepoId: { in: all.map(String) } },
        orderBy: { externalRepoId: "asc" },
      });
      // the same event again changes nothing more; a `removed`-shaped replay with another action restores nothing either
      const replay = await deliverAndHandle("installation_repositories", {
        action: "added",
        installation: { id: Number(flowY.installationId), account: { login: account.login } },
        repositories_added: [R1, R3, R4, R5, R6, R7].map((id) => ({ id })),
        repositories_removed: [],
      });
      const afterReplay = await rowsOf(tenantId, all);
      const auditsAfterReplay = await db.auditLog.count({
        where: { tenantId, action: "repository.restored", targetId: { in: Object.values(ids) } },
      });
      return {
        ids,
        edgeIds,
        beforeAdded,
        afterAdded,
        afterNotAdded,
        afterReplay,
        edgeBefore,
        edgeAfter,
        restoredAudits,
        outboxBefore,
        outboxAfter,
        allow,
        wlY,
        flowY,
        flowYT,
        added,
        replay,
        auditsAfterReplay,
        ext: { R1, R2, R3, R4, R5, R6, R7 },
        tenantId,
        THIRD,
      };
    });
  const row = (rows, ext) => rows.find((r) => r.ext === String(ext));
  add(
    "SCM-057",
    "when an installation gains access (installation_repositories.added), every linked workspace's repositories that were disconnected by an uninstall return to active in the same row if they are listed in the event and still on that workspace's allow-list, move to the new links, are audited as repository.restored by the system actor and announced; repo_inaccessible, not-listed and off-the-allow-list repositories stay disconnected, and replaying the event changes nothing",
    { status: 200 },
    async () => ({ status: 200, json: null, x: await restoreWorld() }),
    (r) => {
      const x = r.x;
      const E = x.ext;
      const problems = [];
      if (x.added.res.status !== 202)
        problems.push(`the signed event answered ${x.added.res.status}`);
      if (x.flowY.link?.status !== 201 || x.flowYT.link?.status !== 201)
        problems.push("fixture: Y was not linked in both workspaces");
      for (const n of [E.R1, E.R2, E.R4, E.R5, E.R6])
        if (
          row(x.beforeAdded, n).status !== "disconnected" ||
          row(x.beforeAdded, n).reason !== "installation_revoked"
        )
          problems.push(
            `fixture: r${n - E.R1 + 1} before the event is ${row(x.beforeAdded, n).status}/${row(x.beforeAdded, n).reason}`,
          );
      for (const [key, n, wlKey] of [
        ["r1", E.R1, "pay"],
        ["r6", E.R6, "third"],
      ]) {
        const a = row(x.afterAdded, n);
        const b = row(x.beforeAdded, n);
        if (a.status !== "active" || a.reason !== null)
          problems.push(`${key} is ${a.status}/${a.reason}`);
        if (a.id !== x.ids[key] || a.nodeId !== b.nodeId)
          problems.push(`${key} is not the same row`);
        if (a.workspaceLinkId !== x.wlY[wlKey] || a.linkId === b.linkId || a.failures !== 0)
          problems.push(`${key} does not point at the new links`);
        if (
          x.allow.filter((e) => e.externalRepoId === String(n)).length !== 1 ||
          x.allow.find((e) => e.externalRepoId === String(n)).workspaceLinkId !== x.wlY[wlKey]
        )
          problems.push(`${key}'s allow-list entry did not move`);
        const audit = x.restoredAudits.filter((e) => e.targetId === x.ids[key]);
        if (
          audit.length !== 1 ||
          audit[0].actorType !== "system" ||
          audit[0].metadata?.previousReason !== "installation_revoked" ||
          audit[0].workspaceId !== a.workspaceId
        )
          problems.push(`${key} audit: ${audit.length} entries`);
      }
      if (x.outboxAfter !== x.outboxBefore + 2)
        problems.push(`${x.outboxAfter - x.outboxBefore} repository.connected messages`);
      if (JSON.stringify(row(x.afterAdded, E.R2)) !== JSON.stringify(row(x.beforeAdded, E.R2)))
        problems.push("r2 (not in the event) changed");
      if (JSON.stringify(x.afterNotAdded) !== JSON.stringify(x.beforeAdded))
        problems.push("an event whose action is not `added` restored repositories");
      const r7 = row(x.afterAdded, E.R7);
      if (
        r7.status !== "disconnected" ||
        r7.reason !== "workspace_unlinked" ||
        JSON.stringify(r7) !== JSON.stringify(row(x.beforeAdded, E.R7))
      )
        problems.push(`r7 (on another workspace's allow-list) is ${r7.status}/${r7.reason}`);
      const r3 = row(x.afterAdded, E.R3);
      if (r3.status !== "disconnected" || r3.reason !== "repo_inaccessible")
        problems.push(`r3 is ${r3.status}/${r3.reason}`);
      if (JSON.stringify(row(x.afterAdded, E.R5)) !== JSON.stringify(row(x.beforeAdded, E.R5)))
        problems.push("r5 (off the allow-list) changed");
      if (JSON.stringify(x.afterReplay) !== JSON.stringify(x.afterAdded))
        problems.push("replaying the event changed rows");
      if (x.auditsAfterReplay !== 2)
        problems.push(`${x.auditsAfterReplay} restore audit entries after the replay`);
      return problems;
    },
  );
  add(
    "SCM-058",
    "restoring on gaining access never crosses workspaces or tenants: a workspace that has not linked the installation keeps its disconnected repository, and another tenant's disconnected repositories with the same GitHub repository ids are untouched",
    { status: 200 },
    async () => ({ status: 200, json: null, x: await restoreWorld() }),
    (r) => {
      const x = r.x;
      const E = x.ext;
      const problems = [];
      const r4 = row(x.afterAdded, E.R4);
      if (
        r4.status !== "disconnected" ||
        r4.reason !== "installation_revoked" ||
        JSON.stringify(r4) !== JSON.stringify(row(x.beforeAdded, E.R4))
      )
        problems.push(`the unlinked workspace's r4 is ${r4.status}/${r4.reason}`);
      if (row(x.afterAdded, E.R1).status !== "active")
        problems.push("control: tenant A's r1 was not restored");
      if (
        x.edgeBefore.length !== 2 ||
        x.edgeBefore.some((e) => e.status !== "disconnected" || e.reason !== "installation_revoked")
      )
        problems.push("fixture: the other tenant's rows are not revoked");
      if (JSON.stringify(x.edgeBefore) !== JSON.stringify(x.edgeAfter))
        problems.push("the other tenant's rows changed");
      if (x.edgeAfter.some((e) => Object.values(x.ids).includes(e.id)))
        problems.push("a row is shared between tenants");
      return problems;
    },
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 12e. Idempotent repository and installation state transitions (SPEC repositories-github §16.3 item 7, SCM-063..068): the scm
//      worker's event consumer, sync job and state functions race each other in process against the disposable database;
//      the world is built directly in the database (helpers/repo-state.js).
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("GitHub integration: idempotent state transitions");
  const stateWorld = () => once("repo-state", () => buildStateWorld(suiteDb()));
  for (const { id, name, run } of STATE_CHECKS)
    add(
      id,
      name,
      { status: 200 },
      async () => ({
        status: 200,
        json: null,
        problems: await run(await stateWorld(), { deliver }),
      }),
      (r) => r.problems,
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// 12f. Broker topology and publish safety (SPEC repositories-github §16.3 item 6, BRK-001..004): the shared topology
//      definition and the mandatory-publish rule. The real publisher, relay, consumer and outbox repository run in process
//      against a channel double (helpers/broker-topology.js); no real broker is used.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Broker topology and publish safety");
  const brokerWorld = () => once("broker", () => buildBrokerWorld(suiteDb()));
  for (const { id, name, run } of BROKER_CHECKS)
    add(
      id,
      name,
      { status: 200 },
      async () => ({ status: 200, json: null, problems: await run(await brokerWorld()) }),
      (r) => r.problems,
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// 11. Data-access isolation (ADR-008 area 10): every tenant-scoped repository function is called IN PROCESS with another
//     tenant's id and must answer nothing / refuse / leave the owner's rows unchanged. One check per function; the entries
//     live in helpers/direct-repos.js. Runs against the disposable database like the SEC and SCM-016/017 checks.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Data-access isolation (in-process)");
  const dalWorld = () => once("dal", () => buildDalWorld(suiteDb()));
  for (const { id, name, entry } of buildDalEntries())
    add(
      id,
      name,
      { status: 200 },
      async () => ({
        status: 200,
        json: null,
        problems: await runDalEntry(entry, await dalWorld()),
      }),
      (r) => r.problems,
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// 12. Pipelines: database integrity (ADR-008 area 10, SPEC pipelines-triggers §7, part B): composite tenant-safe foreign keys,
//     unique identities, immutability triggers and CHECK constraints of the pipeline tables, in process against the
//     disposable database. Each check pairs its denials with a control; the fixtures live in helpers/pipeline-db.js.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Pipelines: database integrity");
  const pipdbWorld = () => once("pipdb", () => buildPipelineDbWorld(suiteDb()));
  for (const { id, name, run } of PIPDB_CHECKS)
    add(
      id,
      name,
      { status: 200 },
      async () => ({ status: 200, json: null, problems: await run(await pipdbWorld()) }),
      (r) => r.problems,
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// 12b. Executions: database integrity and the state-machine helpers (ADR-008 area 10, SPEC executions §7.3, §14.1 part B):
//     the transition trigger, immutability and insert-only guards, lease and attempt fences, composite tenant-safe foreign
//     keys, the orchestrator marker, and the real claim / lease / quota-release helpers of @qmentisai/db called concurrently,
//     in process against the disposable database. Fixtures and checks live in helpers/execution-db.js.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Executions: database integrity and state-machine helpers");
  const execdbWorld = () => once("execdb", () => buildExecutionDbWorld(suiteDb()));
  for (const { id, name, run } of [...EXECDB_CHECKS, ...LOGDB_CHECKS])
    add(
      id,
      name,
      { status: 200 },
      async () => ({ status: 200, json: null, problems: await run(await execdbWorld()) }),
      (r) => r.problems,
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// 13. Pipelines API (SPEC pipelines-triggers §14.1, part C): tenant isolation, 404/403, the fork-policy permission, the manual
//     run, quota and entitlement blocks, immutable versions and the "no code execution" configuration. HTTP checks run against
//     the real API; the world is built through the public API (GitHub stub, linking, connecting) and read back from the
//     disposable database. The router, scheduler and producer checks belong to later parts.
// ---------------------------------------------------------------------------------------------------------------------
const pipCfg = (over = {}) => ({
  schemaVersion: 1,
  triggers: [
    { key: "push", type: "push" },
    { key: "manual", type: "manual" },
  ],
  scans: { sca: { enabled: true } },
  ...over,
});
const pipCfgFork = (forkPolicy) =>
  pipCfg({
    triggers: [
      { key: "push", type: "push" },
      { key: "pr", type: "pull_request", forkPolicy },
      { key: "manual", type: "manual" },
    ],
  });
const pipName = (label) => `${label} ${randomBytes(3).toString("hex")}`;
const pipCreate = (cookie, repositoryId, body, key) =>
  w.api("POST", `/repositories/${repositoryId}/pipelines`, {
    cookie,
    body: { name: pipName("pipe"), enabled: true, config: pipCfg(), ...body },
    ...(key ? { headers: { "idempotency-key": key } } : {}),
  });
const pipRun = (cookie, pipelineId, body = {}, key = KEY("run")) =>
  w.api("POST", `/pipelines/${pipelineId}/runs`, {
    cookie,
    body,
    headers: { "idempotency-key": key },
  });
const pipPublish = (cookie, pipelineId, expectedVersion, config) =>
  w.api("PUT", `/pipelines/${pipelineId}/config`, { cookie, body: { expectedVersion, config } });
const strip = (json) => JSON.stringify({ ...json, meta: undefined });

const pipWorld = () =>
  once("pip-world", async () => {
    const admin = S("admin")(w);
    const PAY = w.A.paymentsWs;
    const IDN = w.A.identityWs;
    const base = 6000000 + (Date.now() % 100000) * 10;
    const account = orgAccount("pip");
    const user = ghUser();
    const flowP = await linkFlow(admin, {
      workspaceId: PAY,
      account,
      user,
      orgRole: "admin",
      repos: [base + 1, base + 2, base + 3].map(stubRepo),
    });
    const flowI = await linkFlow(admin, {
      workspaceId: IDN,
      installationId: flowP.installationId,
      account,
      user,
      orgRole: "admin",
    });
    const wlP = flowP.link.json.data.id;
    const wlI = flowI.link.json.data.id;
    await putAllowList(admin, PAY, wlP, [base + 1, base + 3]);
    await putAllowList(admin, IDN, wlI, [base + 2]);
    const payRepo = (await connectRepo(admin, PAY, wlP, base + 1)).json.data.id;
    const payRepo2 = (await connectRepo(admin, PAY, wlP, base + 3)).json.data.id;
    const idRepo = (await connectRepo(admin, IDN, wlI, base + 2)).json.data.id;
    const edge = await edgeTenant();
    // a workspace of its own: the SCM checks assume the shared edge workspace has no link
    const edgeWs = (
      await w.api("POST", "/workspaces", {
        cookie: edge.owner,
        body: { name: `Edge pipelines ${w.suffix}` },
      })
    ).json.data.id;
    const edgeAccount = orgAccount("pipe");
    const edgeFlow = await linkFlow(edge.owner, {
      workspaceId: edgeWs,
      account: edgeAccount,
      user: ghUser(),
      orgRole: "admin",
      repos: [base + 21].map(stubRepo),
    });
    await putAllowList(edge.owner, edgeWs, edgeFlow.link.json.data.id, [base + 21]);
    const edgeRepo = (await connectRepo(edge.owner, edgeWs, edgeFlow.link.json.data.id, base + 21))
      .json.data.id;
    const sessions = {
      admin,
      manager: S("manager")(w),
      lead: S("lead")(w),
      developer: S("developer")(w),
      viewer: S("viewer")(w),
      analyst: await loginAs("demo.analyst@demo.example"),
      devlead: await loginAs("demo.devlead@demo.example"),
      edge: edge.owner,
    };
    const made = async (cookie, repositoryId, body) => {
      const r = await pipCreate(cookie, repositoryId, body);
      assert.equal(
        r.status,
        201,
        `fixture: pipeline create answered ${r.status} ${JSON.stringify(r.json?.error)}`,
      );
      return r.json.data;
    };
    const pPay = await made(admin, payRepo, { name: pipName("pay") });
    const pId = await made(admin, idRepo, { name: pipName("idn") });
    const pEdge = await made(edge.owner, edgeRepo, { name: pipName("edge") });
    const tenantId = await tenantIdA();
    return {
      PAY,
      IDN,
      payRepo,
      payRepo2,
      idRepo,
      edge,
      edgeWs,
      edgeRepo,
      sessions,
      pPay,
      pId,
      pEdge,
      tenantId,
      edgeTenantId: edge.id,
      account,
      user,
    };
  });
const missingId = () => randomUUID();

/** Runs requests in order; the response carries the first unexpected status, or `expected` when all matched. */
async function sweep(calls, expected) {
  const results = [];
  for (const call of calls) results.push({ call, response: await call.run() });
  const wrong = results.filter((r) => r.response.status !== expected);
  return {
    status: wrong.length ? wrong[0].response.status : expected,
    json: (wrong[0] ?? results[results.length - 1])?.response.json ?? null,
    results,
    problems: wrong.map(
      (r) => `${r.call.label} answered ${r.response.status}, expected ${expected}`,
    ),
  };
}

{
  const add = group("Pipelines: isolation (404) and permissions (403)");
  const pipelineCalls = (cookie, id, repositoryId) => [
    { label: "GET", run: () => w.api("GET", `/pipelines/${id}`, { cookie }) },
    {
      label: "PATCH",
      run: () => w.api("PATCH", `/pipelines/${id}`, { cookie, body: { description: "x" } }),
    },
    { label: "PUT config", run: () => pipPublish(cookie, id, 1, pipCfg()) },
    { label: "enable", run: () => w.api("POST", `/pipelines/${id}/enable`, { cookie }) },
    { label: "disable", run: () => w.api("POST", `/pipelines/${id}/disable`, { cookie }) },
    {
      label: "DELETE",
      run: () => w.api("DELETE", `/pipelines/${id}`, { cookie, body: { confirm: "x" } }),
    },
    { label: "run", run: () => pipRun(cookie, id) },
    { label: "versions", run: () => w.api("GET", `/pipelines/${id}/versions`, { cookie }) },
    { label: "version 1", run: () => w.api("GET", `/pipelines/${id}/versions/1`, { cookie }) },
    { label: "executions", run: () => w.api("GET", `/pipelines/${id}/executions`, { cookie }) },
    {
      label: "trigger decisions",
      run: () => w.api("GET", `/pipelines/${id}/trigger-decisions`, { cookie }),
    },
    ...(repositoryId
      ? [
          {
            label: "dry-run",
            run: () =>
              w.api("POST", `/repositories/${repositoryId}/pipelines/test-triggers`, {
                cookie,
                body: { event: "push", branch: "main" },
              }),
          },
        ]
      : []),
  ];
  add(
    "PIP-001",
    "pipeline by id across tenants: tenant A administrator on tenant B's pipeline (get, edit, publish, enable, disable, delete, run, versions, executions, decisions) answers 404, and the other tenant's administrator the same on A's",
    NOT_FOUND,
    async () => {
      const x = await pipWorld();
      const out = await sweep(pipelineCalls(x.sessions.admin, x.pEdge.id), 404);
      const back = await sweep(pipelineCalls(x.sessions.edge, x.pPay.id), 404);
      const missing = await w.api("GET", `/pipelines/${missingId()}`, { cookie: x.sessions.admin });
      out.problems.push(...back.problems);
      const foreign = out.results[0].response;
      if (strip(foreign.json) !== strip(missing.json))
        out.problems.push("the foreign pipeline's 404 body differs from a missing id's");
      return out;
    },
    (r) => r.problems,
  );
  add(
    "PIP-002",
    "a pipeline in a workspace the caller cannot see answers the same 404 as a missing id; a visible workspace without the key answers 403 (Developer, Viewer, Security Analyst, Lead on delete)",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const problems = [];
      const hidden = await sweep(pipelineCalls(x.sessions.manager, x.pId.id), 404);
      problems.push(...hidden.problems);
      const missing = await w.api("GET", `/pipelines/${missingId()}`, {
        cookie: x.sessions.manager,
      });
      if (strip(hidden.results[0].response.json) !== strip(missing.json))
        problems.push("a hidden pipeline's 404 body differs from a missing id's");
      const manage = (cookie) => [
        {
          label: "PATCH",
          run: () =>
            w.api("PATCH", `/pipelines/${x.pPay.id}`, { cookie, body: { description: "x" } }),
        },
        { label: "PUT config", run: () => pipPublish(cookie, x.pPay.id, 1, pipCfg()) },
        { label: "enable", run: () => w.api("POST", `/pipelines/${x.pPay.id}/enable`, { cookie }) },
        {
          label: "disable",
          run: () => w.api("POST", `/pipelines/${x.pPay.id}/disable`, { cookie }),
        },
        { label: "run", run: () => pipRun(cookie, x.pPay.id) },
        {
          label: "DELETE",
          run: () =>
            w.api("DELETE", `/pipelines/${x.pPay.id}`, { cookie, body: { confirm: x.pPay.name } }),
        },
      ];
      for (const who of ["developer", "viewer", "analyst"]) {
        const r = await sweep(manage(x.sessions[who]), 403);
        problems.push(...r.problems.map((p) => `${who}: ${p}`));
        const reads = await w.api("GET", `/pipelines/${x.pPay.id}`, { cookie: x.sessions[who] });
        if (reads.status !== 200)
          problems.push(`${who} could not read a visible pipeline (${reads.status})`);
      }
      const lead = await w.api("DELETE", `/pipelines/${x.pPay.id}`, {
        cookie: x.sessions.lead,
        body: { confirm: x.pPay.name },
      });
      if (lead.status !== 403) problems.push(`lead delete answered ${lead.status}`);
      const still = await w.api("GET", `/pipelines/${x.pPay.id}`, { cookie: x.sessions.admin });
      if (still.status !== 200 || still.json.data.deletedAt)
        problems.push("a refused delete changed the pipeline");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-003",
    "creating under a repository of another tenant or of a hidden workspace answers 404; a body naming tenantId or workspaceId is rejected",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const problems = [];
      const cross = await pipCreate(x.sessions.admin, x.edgeRepo, { name: pipName("x") });
      if (cross.status !== 404) problems.push(`other tenant's repository answered ${cross.status}`);
      const hidden = await pipCreate(x.sessions.manager, x.idRepo, { name: pipName("x") });
      if (hidden.status !== 404) problems.push(`hidden workspace answered ${hidden.status}`);
      for (const smuggled of [{ tenantId: x.edgeTenantId }, { workspaceId: x.IDN }]) {
        const r = await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("x"), ...smuggled });
        if (r.status !== 400)
          problems.push(`${Object.keys(smuggled)[0]} in the body answered ${r.status}`);
      }
      const rows = await suiteDb().pipeline.count({ where: { name: { startsWith: "x " } } });
      if (rows) problems.push("a refused create left a pipeline behind");
      const control = await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("ctl") });
      if (control.status !== 201) problems.push(`control create answered ${control.status}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-004",
    "the pipeline list shows only pipelines of workspaces the caller can see; a hidden or unknown ?workspaceId= gives the same empty result; nothing of another tenant appears",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const problems = [];
      const asManager = await w.api("GET", "/pipelines?pageSize=100", {
        cookie: x.sessions.manager,
      });
      const asAdmin = await w.api("GET", "/pipelines?pageSize=100", { cookie: x.sessions.admin });
      const ids = (r) => r.json.data.map((p) => p.id);
      if (ids(asManager).includes(x.pId.id))
        problems.push("the manager sees a pipeline of a hidden workspace");
      if (!ids(asManager).includes(x.pPay.id))
        problems.push("the manager does not see a visible pipeline");
      if (!ids(asAdmin).includes(x.pId.id) || !ids(asAdmin).includes(x.pPay.id))
        problems.push("the administrator misses pipelines");
      if (ids(asAdmin).includes(x.pEdge.id) || ids(asManager).includes(x.pEdge.id))
        problems.push("another tenant's pipeline is listed");
      const hidden = await w.api("GET", `/pipelines?workspaceId=${x.IDN}`, {
        cookie: x.sessions.manager,
      });
      const unknown = await w.api("GET", `/pipelines?workspaceId=${missingId()}`, {
        cookie: x.sessions.manager,
      });
      if (hidden.status !== 200 || hidden.json.data.length !== 0)
        problems.push("a hidden workspace filter returned data or an error");
      if (
        JSON.stringify(hidden.json.data) !== JSON.stringify(unknown.json.data) ||
        hidden.json.meta.pagination.totalItems !== unknown.json.meta.pagination.totalItems
      )
        problems.push("a hidden workspace is distinguishable from an unknown one");
      // filters and sorts stay inside the caller's workspaces
      for (const query of [
        "sort=lastRequestedAt:desc",
        "sort=createdAt:asc",
        "effectiveState=running_normally",
        "triggerType=manual",
        "enabled=true",
        `q=${encodeURIComponent(x.pPay.name.slice(0, 3))}`,
      ]) {
        const filtered = await w.api("GET", `/pipelines?pageSize=100&${query}`, {
          cookie: x.sessions.manager,
        });
        if (filtered.status !== 200) problems.push(`${query} answered ${filtered.status}`);
        else if (filtered.json.data.some((p) => p.id === x.pId.id || p.id === x.pEdge.id))
          problems.push(`${query} listed a pipeline outside the caller's workspaces`);
        else if (
          query.startsWith("sort=lastRequestedAt") &&
          !filtered.json.data.some((p) => p.id === x.pPay.id)
        )
          problems.push("the lastRequestedAt sort lost a visible pipeline");
      }
      const repoList = await w.api("GET", `/repositories/${x.idRepo}/pipelines`, {
        cookie: x.sessions.manager,
      });
      if (repoList.status !== 404)
        problems.push(`repository-nested list of a hidden repository answered ${repoList.status}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

{
  const add = group("Pipelines: configuration (R-8), versions and fork policy");
  const FORBIDDEN_KEYS = [
    "command",
    "commands",
    "script",
    "scripts",
    "run",
    "install",
    "build",
    "postinstall",
    "hooks",
    "preScan",
    "env",
    "image",
    "shell",
  ];
  const withKey = (path, key) => {
    const cfg = pipCfg({ scans: { sca: { enabled: true } } });
    if (path === "root") cfg[key] = "echo pwned";
    else if (path === "scan") cfg.scans.sca[key] = "echo pwned";
    else if (path === "engine") cfg.scans.sca.engine = { id: "default", [key]: "echo pwned" };
    else if (path === "execution") cfg.execution = { [key]: "echo pwned" };
    else if (path === "trigger") cfg.triggers[0][key] = "echo pwned";
    else if (path === "exclusions") cfg.exclusions = { paths: [], [key]: "echo pwned" };
    return cfg;
  };
  add(
    "PIP-009",
    "the configuration schema rejects run_with_credentials, dast, assetDiscovery and unknown keys with 400 (the router half of this check belongs to part D)",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const problems = [];
      const bad = {
        "run_with_credentials fork policy": pipCfgFork("run_with_credentials"),
        "dast scan": pipCfg({ scans: { sca: { enabled: true }, dast: { enabled: true } } }),
        "assetDiscovery scan": pipCfg({ assetDiscovery: { enabled: true } }),
        "unknown top-level key": pipCfg({ somethingElse: 1 }),
        "unknown trigger type": pipCfg({ triggers: [{ key: "x", type: "webhook" }] }),
        "engine not in the catalog": pipCfg({
          scans: { sca: { enabled: true, engine: { id: "my-own-engine" } } },
        }),
        "schemaVersion 2": pipCfg({ schemaVersion: 2 }),
      };
      for (const [label, config] of Object.entries(bad)) {
        const r = await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("bad"), config });
        if (r.status !== 400 || r.json?.error?.code !== "VALIDATION_FAILED")
          problems.push(`${label} answered ${r.status}`);
      }
      const control = await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("ok") });
      if (control.status !== 201) problems.push(`control answered ${control.status}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-027",
    "no code execution (R-8): any command-, script-, install-, build- or hook-like key at any level of the configuration answers 400 and the published OpenAPI schema of the configuration has no such property and additionalProperties false on every object",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const problems = [];
      for (const path of ["root", "scan", "engine", "execution", "trigger", "exclusions"])
        for (const key of FORBIDDEN_KEYS) {
          const r = await pipPublish(
            x.sessions.admin,
            x.pPay.id,
            x.pPay.currentVersion.version,
            withKey(path, key),
          );
          if (r.status !== 400) problems.push(`${key} at ${path} answered ${r.status}`);
        }
      const doc = await w.api("GET", "/openapi.json");
      const op = doc.json?.paths?.["/api/v1/pipelines/{pipelineId}/config"]?.put;
      const root = op?.requestBody?.content?.["application/json"]?.schema?.properties?.config;
      if (!root) problems.push("the OpenAPI document has no configuration schema for PUT config");
      else {
        const banned = new RegExp(
          `^(${FORBIDDEN_KEYS.join("|")}|cmd|exec|entrypoint|args|plugins?|steps)$`,
          "i",
        );
        const walk = (node, where) => {
          if (!node || typeof node !== "object") return;
          if (Array.isArray(node)) return node.forEach((n, i) => walk(n, `${where}[${i}]`));
          if (node.type === "object" || node.properties) {
            if (node.additionalProperties !== false)
              problems.push(`${where}: additionalProperties is not false`);
            for (const key of Object.keys(node.properties ?? {}))
              if (banned.test(key)) problems.push(`${where}: property ${key}`);
          }
          for (const [k, v] of Object.entries(node)) walk(v, `${where}.${k}`);
        };
        walk(root, "config");
      }
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-026",
    "fork-policy permission: pipeline.manage alone (Manager, Dev Lead) cannot create or publish run_without_credentials (403 fork_policy_requires_permission, nothing written); Admin and Lead can; setting back to skip and leaving an existing value need only pipeline.manage; every change is audited with old and new value; a hidden workspace answers 404",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const deniedCreate = [];
      for (const who of ["manager", "devlead"]) {
        const r = await pipCreate(x.sessions[who], x.payRepo, {
          name: pipName(`deny-${who}`),
          config: pipCfgFork("run_without_credentials"),
        });
        deniedCreate.push(r);
        if (
          r.status !== 403 ||
          r.json?.error?.details?.reason !== "fork_policy_requires_permission"
        )
          problems.push(
            `${who} create answered ${r.status} ${JSON.stringify(r.json?.error?.details)}`,
          );
      }
      if (await db.pipeline.count({ where: { name: { startsWith: "deny-" } } }))
        problems.push("a refused create left a pipeline behind");
      const target = (await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("fork") })).json
        .data;
      const versionsBefore = await db.pipelineConfigVersion.count({
        where: { pipelineId: target.id },
      });
      for (const who of ["manager", "devlead"]) {
        const r = await pipPublish(
          x.sessions[who],
          target.id,
          1,
          pipCfgFork("run_without_credentials"),
        );
        if (
          r.status !== 403 ||
          r.json?.error?.details?.reason !== "fork_policy_requires_permission"
        )
          problems.push(`${who} publish answered ${r.status}`);
      }
      if (
        (await db.pipelineConfigVersion.count({ where: { pipelineId: target.id } })) !==
        versionsBefore
      )
        problems.push("a refused publish wrote a version");
      const lead = await pipPublish(
        x.sessions.lead,
        target.id,
        1,
        pipCfgFork("run_without_credentials"),
      );
      if (lead.status !== 200) problems.push(`lead publish answered ${lead.status}`);
      // unchanged non-skip value: the manager may edit other configuration
      const unchanged = pipCfgFork("run_without_credentials");
      unchanged.scans.sast = { enabled: true };
      const keep = await pipPublish(x.sessions.manager, target.id, 2, unchanged);
      if (keep.status !== 200)
        problems.push(`manager edit leaving the policy unchanged answered ${keep.status}`);
      const back = await pipPublish(x.sessions.manager, target.id, 3, pipCfgFork("skip"));
      if (back.status !== 200) problems.push(`manager setting skip answered ${back.status}`);
      const admin = await pipPublish(
        x.sessions.admin,
        target.id,
        4,
        pipCfgFork("run_without_credentials"),
      );
      if (admin.status !== 200) problems.push(`admin publish answered ${admin.status}`);
      const created = await pipCreate(x.sessions.admin, x.payRepo, {
        name: pipName("adminfork"),
        config: pipCfgFork("run_without_credentials"),
      });
      if (created.status !== 201) problems.push(`admin create answered ${created.status}`);
      const hidden = await pipPublish(
        x.sessions.manager,
        x.pId.id,
        1,
        pipCfgFork("run_without_credentials"),
      );
      if (hidden.status !== 404) problems.push(`hidden workspace answered ${hidden.status}`);
      const audits = await db.auditLog.findMany({
        where: {
          tenantId: x.tenantId,
          action: "pipeline.fork_policy_changed",
          targetId: target.id,
        },
        orderBy: { createdAt: "asc" },
      });
      const pairs = audits.map(
        (a) => `${a.changes?.before?.forkPolicy}>${a.changes?.after?.forkPolicy}`,
      );
      if (
        JSON.stringify(pairs) !==
        JSON.stringify([
          "skip>run_without_credentials",
          "run_without_credentials>skip",
          "skip>run_without_credentials",
        ])
      )
        problems.push(`fork-policy audit entries: ${JSON.stringify(pairs)}`);
      const foreign = await db.auditLog.count({
        where: { tenantId: x.edgeTenantId, action: "pipeline.fork_policy_changed" },
      });
      if (foreign) problems.push("a fork-policy audit entry was written in another tenant");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-018",
    "versions are immutable: there is no route to update or delete one, an edit creates a new version, and an earlier execution's snapshot (version, hash) is unchanged",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const p = (await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("snap") })).json.data;
      const run = await pipRun(x.sessions.lead, p.id);
      if (run.status !== 202) problems.push(`run answered ${run.status}`);
      const execId = run.json.data.execution.id;
      const before = await db.execution.findFirst({ where: { id: execId } });
      const v1 = await w.api("GET", `/pipelines/${p.id}/versions/1`, { cookie: x.sessions.admin });
      const next = pipCfg({ failOn: { severity: "critical" } });
      const published = await pipPublish(x.sessions.admin, p.id, 1, next);
      if (published.status !== 200 || published.json.data.version !== 2)
        problems.push(`publish answered ${published.status}`);
      const after = await db.execution.findFirst({ where: { id: execId } });
      if (
        after.configVersion !== 1 ||
        after.configHash !== before.configHash ||
        after.configVersionId !== before.configVersionId
      )
        problems.push("the execution's snapshot changed after a new version");
      const v1again = await w.api("GET", `/pipelines/${p.id}/versions/1`, {
        cookie: x.sessions.admin,
      });
      if (JSON.stringify(v1.json.data) !== JSON.stringify(v1again.json.data))
        problems.push("version 1 changed");
      for (const method of ["PUT", "PATCH", "DELETE", "POST"]) {
        const r = await w.api(method, `/pipelines/${p.id}/versions/1`, {
          cookie: x.sessions.admin,
          body: {},
        });
        if (r.status !== 404) problems.push(`${method} on a version answered ${r.status}`);
      }
      const direct = await db.pipelineConfigVersion
        .updateMany({ where: { pipelineId: p.id, version: 1 }, data: { changeNote: "tamper" } })
        .then(
          () => "accepted",
          () => "rejected",
        );
      if (direct !== "rejected") problems.push("the database accepted an update of a version");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-019",
    "concurrent configuration publishes with the same expectedVersion: exactly one succeeds, the other answers 409 version_conflict",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const p = (await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("race") })).json.data;
      const results = await Promise.all(
        [1, 2, 3, 4].map((n) =>
          pipPublish(
            x.sessions.admin,
            p.id,
            1,
            pipCfg({ failOn: { severity: n % 2 ? "low" : "medium" } }),
          ),
        ),
      );
      const ok = results.filter((r) => r.status === 200).length;
      const conflicts = results.filter(
        (r) => r.status === 409 && r.json?.error?.details?.reason === "version_conflict",
      ).length;
      const versions = await suiteDb().pipelineConfigVersion.count({ where: { pipelineId: p.id } });
      const problems = [];
      if (ok !== 1 || conflicts !== 3) problems.push(`results ${results.map((r) => r.status)}`);
      if (versions !== 2) problems.push(`${versions} versions stored`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

{
  const add = group("Pipelines: manual run, quota, entitlement and audit");
  const outboxFor = (executionId) =>
    suiteDb().outboxMessage.findMany({
      where: { messageId: `execution-requested-${executionId}` },
    });
  add(
    "PIP-010",
    "manual run: Viewer, Developer and Security Analyst get 403, a hidden workspace 404, Lead, Dev Lead, Manager and Admin get 202 with one queued execution and one message",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const problems = [];
      const p = (await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("manual") })).json
        .data;
      const before = await suiteDb().execution.count({ where: { pipelineId: p.id } });
      for (const who of ["viewer", "developer", "analyst"]) {
        const r = await pipRun(x.sessions[who], p.id);
        if (r.status !== 403) problems.push(`${who} answered ${r.status}`);
      }
      const hidden = await pipRun(x.sessions.manager, x.pId.id);
      if (hidden.status !== 404) problems.push(`hidden workspace answered ${hidden.status}`);
      if ((await suiteDb().execution.count({ where: { pipelineId: p.id } })) !== before)
        problems.push("a refused run created an execution");
      for (const who of ["lead", "devlead", "manager", "admin"]) {
        const r = await pipRun(x.sessions[who], p.id);
        if (r.status !== 202 || r.json?.data?.execution?.status !== "queued")
          problems.push(`${who} answered ${r.status}`);
        else if ((await outboxFor(r.json.data.execution.id)).length !== 1)
          problems.push(`${who}: no single outbox message`);
      }
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-030",
    "manual run is idempotent: the same Idempotency-Key creates one execution, one message and one quota unit; the key is required; a different key is a different run",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const p = (await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("idem") })).json.data;
      const key = KEY("idem");
      const first = await pipRun(
        x.sessions.lead,
        p.id,
        { ref: { type: "branch", name: "main" } },
        key,
      );
      const second = await pipRun(
        x.sessions.lead,
        p.id,
        { ref: { type: "branch", name: "main" } },
        key,
      );
      if (first.status !== 202 || second.status !== 202)
        problems.push(`statuses ${first.status}, ${second.status}`);
      else if (first.json.data.execution.id !== second.json.data.execution.id)
        problems.push("the replay returned another execution");
      const count = await db.execution.count({ where: { pipelineId: p.id } });
      if (count !== 1) problems.push(`${count} executions for one key`);
      const usage = await db.execution.findFirst({ where: { pipelineId: p.id } });
      if (usage?.quotaConsumed !== 1)
        problems.push("the run did not record exactly one quota unit");
      const other = await pipRun(
        x.sessions.lead,
        p.id,
        { ref: { type: "branch", name: "main" } },
        KEY("other"),
      );
      if (other.status !== 202 || other.json.data.execution.id === first.json.data.execution.id)
        problems.push("a different key did not create a different run");
      const noKey = await w.api("POST", `/pipelines/${p.id}/runs`, {
        cookie: x.sessions.lead,
        body: {},
      });
      if (noKey.status !== 400)
        problems.push(`a run without Idempotency-Key answered ${noKey.status}`);
      // the database key also survives the HTTP replay window: the same key by the same user after the cache is gone
      const direct = await db.execution.findFirst({
        where: { pipelineId: p.id, idempotencyKey: { startsWith: "manual:" } },
      });
      if (!direct) problems.push("no stored idempotency key");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-011",
    "manual run on a disabled pipeline, a disabled, unavailable or disconnected repository, or an archived workspace answers 409 with no row, no message and no quota used; the denials are audited",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const p = (await pipCreate(x.sessions.admin, x.payRepo2, { name: pipName("gate") })).json
        .data;
      const state = async () => ({
        executions: await db.execution.count({ where: { pipelineId: p.id } }),
        outbox: await db.outboxMessage.count({
          where: {
            type: "pipeline.execution.requested",
            payload: { path: ["pipelineId"], equals: p.id },
          },
        }),
        usage: JSON.stringify(
          await db.tenantQuotaUsage
            .findMany({ where: { tenantId: x.tenantId } })
            .then((rows) => rows.map((r) => [r.periodKey, String(r.used)])),
        ),
      });
      const before = await state();
      const expect409 = async (label, reason) => {
        const r = await pipRun(x.sessions.admin, p.id);
        if (r.status !== 409 || r.json?.error?.details?.reason !== reason)
          problems.push(`${label} answered ${r.status} ${JSON.stringify(r.json?.error?.details)}`);
      };
      await w.api("POST", `/pipelines/${p.id}/disable`, { cookie: x.sessions.admin });
      await expect409("disabled pipeline", "pipeline_disabled");
      await w.api("POST", `/pipelines/${p.id}/enable`, { cookie: x.sessions.admin });
      await w.api("POST", `/repositories/${x.payRepo2}/disable`, { cookie: x.sessions.admin });
      await expect409("disabled repository", "repository_not_active");
      await w.api("POST", `/repositories/${x.payRepo2}/enable`, { cookie: x.sessions.admin });
      for (const status of ["unavailable", "disconnected"]) {
        await db.repository.updateMany({
          where: { id: x.payRepo2, tenantId: x.tenantId },
          data: { status },
        });
        await expect409(`${status} repository`, "repository_not_active");
      }
      await db.repository.updateMany({
        where: { id: x.payRepo2, tenantId: x.tenantId },
        data: { status: "active" },
      });
      const edgePipe = (await pipCreate(x.sessions.edge, x.edgeRepo, { name: pipName("arch") }))
        .json.data;
      const archived = await w.api("POST", `/workspaces/${x.edgeWs}/archive`, {
        cookie: x.sessions.edge,
      });
      if (archived.status !== 200) problems.push(`fixture: archive answered ${archived.status}`);
      else {
        const r = await pipRun(x.sessions.edge, edgePipe.id);
        if (r.status !== 409 || r.json?.error?.details?.reason !== "workspace_archived")
          problems.push(
            `archived workspace answered ${r.status} ${JSON.stringify(r.json?.error?.details)}`,
          );
        const noCreate = await pipCreate(x.sessions.edge, x.edgeRepo, { name: pipName("arch2") });
        if (noCreate.status !== 409)
          problems.push(`create in an archived workspace answered ${noCreate.status}`);
        await w.api("POST", `/workspaces/${x.edgeWs}/restore`, { cookie: x.sessions.edge });
      }
      const after = await state();
      if (JSON.stringify(before) !== JSON.stringify(after))
        problems.push(`state changed: ${JSON.stringify(before)} -> ${JSON.stringify(after)}`);
      const denied = await db.auditLog.findMany({
        where: { tenantId: x.tenantId, action: "execution.manual_denied", targetId: p.id },
      });
      const reasons = denied.map((d) => d.metadata?.reason).sort();
      if (
        JSON.stringify(reasons) !==
        JSON.stringify([
          "pipeline_disabled",
          "repository_not_active",
          "repository_not_active",
          "repository_not_active",
        ])
      )
        problems.push(`denial audit reasons ${JSON.stringify(reasons)}`);
      const control = await pipRun(x.sessions.admin, p.id);
      if (control.status !== 202) problems.push(`control run answered ${control.status}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

/** A fresh tenant with one workspace, one connected repository and plan overrides, for the limit and suspension checks. */
const capWorld = () =>
  once("pip-cap", async () => {
    const t = await w.provisionTenant("pipcap");
    const ws = (
      await w.api("POST", "/workspaces", { cookie: t.owner, body: { name: `Cap WS ${w.suffix}` } })
    ).json.data.id;
    const base = 6500000 + (Date.now() % 100000) * 10;
    const flow = await linkFlow(t.owner, {
      workspaceId: ws,
      account: orgAccount("cap"),
      user: ghUser(),
      orgRole: "admin",
      repos: [stubRepo(base + 1)],
    });
    const wl = flow.link.json.data.id;
    await putAllowList(t.owner, ws, wl, [base + 1]);
    const repo = (await connectRepo(t.owner, ws, wl, base + 1)).json.data.id;
    const db = suiteDb();
    const limit = await db.entitlementCatalog.findUnique({ where: { key: "pipelines.max" } });
    await db.tenantEntitlement.create({
      data: {
        tenantId: t.id,
        entitlementId: limit.id,
        enabled: true,
        limitValue: 2n,
        source: "security-suite",
      },
    });
    const quota = await db.quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
    await db.tenantQuota.create({
      data: { tenantId: t.id, quotaDefinitionId: quota.id, limitValue: 1n },
    });
    return { t, ws, repo, quota };
  });

{
  const add = group("Pipelines: limits, audit, messages and soft delete");
  add(
    "PIP-025",
    "pipelines.max: the (max+1)th pipeline answers 403 QUOTA_EXCEEDED for that tenant only, and concurrent creates cannot exceed the limit",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const cap = await capWorld();
      const problems = [];
      const first = await pipCreate(cap.t.owner, cap.repo, { name: pipName("first") });
      if (first.status !== 201) problems.push(`first create answered ${first.status}`);
      const racers = await Promise.all(
        Array.from({ length: 4 }, (_, i) =>
          pipCreate(cap.t.owner, cap.repo, { name: pipName(`race${i}`) }),
        ),
      );
      const created = racers.filter((r) => r.status === 201).length;
      const blocked = racers.filter(
        (r) => r.status === 403 && r.json?.error?.code === "QUOTA_EXCEEDED",
      ).length;
      if (created !== 1 || blocked !== 3)
        problems.push(`concurrent creates: ${racers.map((r) => r.status)}`);
      const stored = await suiteDb().pipeline.count({ where: { tenantId: cap.t.id } });
      if (stored !== 2) problems.push(`${stored} pipelines stored, limit 2`);
      const other = await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("unaffected") });
      if (other.status !== 201) problems.push(`another tenant's create answered ${other.status}`);
      const options = await w.api("GET", `/workspaces/${cap.ws}/pipelines/options`, {
        cookie: cap.t.owner,
      });
      if (options.json?.data?.pipelines?.limit !== 2 || options.json.data.pipelines.used !== 2)
        problems.push(`options ${JSON.stringify(options.json?.data?.pipelines)}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-014",
    "scans.monthly at its limit: a manual run answers 403 QUOTA_EXCEEDED and creates no row and no message, uses no unit and leaves a denial audit entry; a disabled scans entitlement answers 403 ENTITLEMENT_REQUIRED the same way; another tenant's runs are unaffected",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const cap = await capWorld();
      const db = suiteDb();
      const problems = [];
      const pipe = await db.pipeline.findFirst({
        where: { tenantId: cap.t.id, deletedAt: null },
        orderBy: { createdAt: "asc" },
      });
      const first = await pipRun(cap.t.owner, pipe.id);
      if (first.status !== 202) problems.push(`the run inside the limit answered ${first.status}`);
      const usage = () =>
        db.tenantQuotaUsage
          .findFirst({ where: { tenantId: cap.t.id, quotaDefinitionId: cap.quota.id } })
          .then((u) => u?.used);
      const used = await usage();
      // another ref, so the default `supersede` policy does not release the first request's unit
      const blocked = await pipRun(cap.t.owner, pipe.id, { ref: { type: "tag", name: "q1" } });
      if (blocked.status !== 403 || blocked.json?.error?.code !== "QUOTA_EXCEEDED")
        problems.push(`quota block answered ${blocked.status} ${blocked.json?.error?.code}`);
      if ((await db.execution.count({ where: { pipelineId: pipe.id } })) !== 1)
        problems.push("a blocked run left an execution row");
      if (
        (await db.outboxMessage.count({
          where: { tenantId: cap.t.id, type: "pipeline.execution.requested" },
        })) !== 1
      )
        problems.push("a blocked run left a message");
      if ((await usage()) !== used) problems.push("a blocked run consumed quota");
      const entitlement = await db.entitlementCatalog.findUnique({
        where: { key: "scans.monthly" },
      });
      await db.tenantEntitlement.create({
        data: {
          tenantId: cap.t.id,
          entitlementId: entitlement.id,
          enabled: false,
          source: "security-suite",
        },
      });
      const notIncluded = await pipRun(cap.t.owner, pipe.id, { ref: { type: "tag", name: "q2" } });
      if (notIncluded.status !== 403 || notIncluded.json?.error?.code !== "ENTITLEMENT_REQUIRED")
        problems.push(
          `entitlement block answered ${notIncluded.status} ${notIncluded.json?.error?.code}`,
        );
      const audits = await db.auditLog.findMany({
        where: { tenantId: cap.t.id, action: "execution.manual_denied", targetId: pipe.id },
      });
      if (
        JSON.stringify(audits.map((a) => a.metadata?.reason).sort()) !==
        JSON.stringify(["entitlement_required", "quota_exceeded"])
      )
        problems.push(`denial audit ${JSON.stringify(audits.map((a) => a.metadata))}`);
      const pay = await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("quota-other") });
      const run = await pipRun(x.sessions.admin, pay.json.data.id);
      if (run.status !== 202) problems.push(`another tenant's run answered ${run.status}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-029",
    "denied manual runs (disabled pipeline, 403 on a visible pipeline) leave an execution.manual_denied audit entry in the caller's tenant only, no execution row and no secret; a hidden or absent pipeline leaves no entry",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const p = (await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("deny") })).json.data;
      const hiddenBefore = await db.auditLog.count({
        where: { action: "execution.manual_denied", targetId: x.pId.id },
      });
      await pipRun(x.sessions.viewer, p.id);
      await w.api("POST", `/pipelines/${p.id}/disable`, { cookie: x.sessions.admin });
      await pipRun(x.sessions.lead, p.id);
      await pipRun(x.sessions.manager, x.pId.id);
      await pipRun(x.sessions.admin, missingId());
      const audits = await db.auditLog.findMany({
        where: { action: "execution.manual_denied", targetId: p.id },
        orderBy: { createdAt: "asc" },
      });
      if (
        JSON.stringify(audits.map((a) => a.metadata?.reason)) !==
        JSON.stringify(["permission_denied", "pipeline_disabled"])
      )
        problems.push(`audit reasons ${JSON.stringify(audits.map((a) => a.metadata))}`);
      if (audits.some((a) => a.tenantId !== x.tenantId || a.result === "x"))
        problems.push("an audit entry is in the wrong tenant");
      if (new Set(audits.map((a) => a.actorUserId)).size !== 2)
        problems.push("the denial entries do not name the two different actors");
      if (
        (await db.auditLog.count({
          where: { action: "execution.manual_denied", targetId: x.pId.id },
        })) !== hiddenBefore
      )
        problems.push("a hidden pipeline was audited");
      if (await db.execution.count({ where: { pipelineId: p.id } }))
        problems.push("a denied run left an execution row");
      if (TOKEN_MATERIAL.test(JSON.stringify(audits)))
        problems.push("token material in the audit entries");
      if (
        await db.auditLog.count({
          where: { tenantId: x.edgeTenantId, action: "execution.manual_denied", targetId: p.id },
        })
      )
        problems.push("another tenant has denial entries");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-022",
    "audit: create, publish (with version numbers and a diff summary), enable, disable, delete and a manual run each write an entry in the caller's tenant only, in the same transaction as the change, with paths and ids but no values, commit text or secret",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const p = (await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("audited") })).json
        .data;
      await pipPublish(x.sessions.admin, p.id, 1, pipCfg({ failOn: { severity: "critical" } }));
      await w.api("POST", `/pipelines/${p.id}/disable`, { cookie: x.sessions.admin });
      await w.api("POST", `/pipelines/${p.id}/enable`, { cookie: x.sessions.admin });
      const run = await pipRun(x.sessions.admin, p.id);
      await w.api("PATCH", `/pipelines/${p.id}`, {
        cookie: x.sessions.admin,
        body: { description: "renamed" },
      });
      const del = await w.api("DELETE", `/pipelines/${p.id}`, {
        cookie: x.sessions.admin,
        body: { confirm: p.name },
      });
      if (del.status !== 200)
        problems.push(`delete answered ${del.status} ${JSON.stringify(del.json?.error)}`);
      const rows = await db.auditLog.findMany({
        where: { targetId: p.id },
        orderBy: { createdAt: "asc" },
      });
      const actions = rows.map((r) => r.action);
      const expected = [
        "pipeline.created",
        "pipeline.config_published",
        "pipeline.disabled",
        "pipeline.enabled",
        "execution.manual_requested",
        "pipeline.updated",
        "pipeline.deleted",
      ];
      if (JSON.stringify(actions) !== JSON.stringify(expected))
        problems.push(`actions ${JSON.stringify(actions)}`);
      const published = rows.find((r) => r.action === "pipeline.config_published");
      if (
        published?.metadata?.fromVersion !== 1 ||
        published?.metadata?.toVersion !== 2 ||
        !published?.metadata?.configHash ||
        !published?.metadata?.diff?.changed?.includes("failOn.severity")
      )
        problems.push(`publish entry ${JSON.stringify(published?.metadata)}`);
      const manual = rows.find((r) => r.action === "execution.manual_requested");
      if (manual?.metadata?.executionId !== run.json?.data?.execution?.id)
        problems.push("the manual-run entry does not name the execution");
      if (rows.some((r) => r.tenantId !== x.tenantId))
        problems.push("an entry is in the wrong tenant");
      if (rows.some((r) => !r.actorUserId)) problems.push("an entry has no actor");
      const text = JSON.stringify(rows.map((r) => [r.metadata, r.changes]));
      if (TOKEN_MATERIAL.test(text) || /commit|password|secret/i.test(text))
        problems.push("secret-like or commit text in the entries");
      if (await db.auditLog.count({ where: { tenantId: x.edgeTenantId, targetId: p.id } }))
        problems.push("another tenant has entries about this pipeline");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-023",
    "the pipeline.execution.requested message carries only the allowed ids, enums and short strings, the caller's tenant, and its ownership check rejects a pipeline or execution of another tenant",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const p = (await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("message") })).json
        .data;
      const run = await pipRun(x.sessions.lead, p.id, { ref: { type: "branch", name: "main" } });
      const id = run.json.data.execution.id;
      const row = await db.outboxMessage.findFirst({
        where: { messageId: `execution-requested-${id}` },
      });
      const message = row?.payload;
      const allowed = [
        "executionId",
        "pipelineId",
        "repositoryId",
        "workspaceId",
        "configVersion",
        "configHash",
        "triggerType",
        "triggerKey",
        "refType",
        "refName",
        "commitSha",
        "pullRequestNumber",
        "scanKind",
        "scanKindReason",
        "trust",
      ].sort();
      if (JSON.stringify(Object.keys(message?.payload ?? {}).sort()) !== JSON.stringify(allowed))
        problems.push(`payload keys ${Object.keys(message?.payload ?? {})}`);
      if (
        message?.tenantId !== x.tenantId ||
        row?.tenantId !== x.tenantId ||
        row?.queue !== "pipeline"
      )
        problems.push("wrong tenant or queue");
      if (message?.subject?.id !== id || message?.initiator?.type !== "user")
        problems.push("subject or initiator is wrong");
      if (TOKEN_MATERIAL.test(JSON.stringify(message)) || JSON.stringify(message).includes(p.name))
        problems.push("token material or free text in the message");
      const { createOwnershipVerifier } = await import("../../../workers/src/ownership/index.js");
      const verify = createOwnershipVerifier({ db });
      const reject = async (msg, label) => {
        try {
          await verify(msg);
          problems.push(`${label} was accepted`);
        } catch (error) {
          if (error?.reason !== "resource-not-in-tenant")
            problems.push(`${label} rejected with ${error?.reason ?? error?.message}`);
        }
      };
      await verify(message).catch((e) =>
        problems.push(`the legitimate message was rejected: ${e.message}`),
      );
      await reject(
        { ...message, tenantId: x.edgeTenantId, workspaceId: undefined },
        "a message of another tenant naming this pipeline",
      );
      const edgeRun = await pipRun(x.sessions.edge, x.pEdge.id);
      const edgeMessage = (
        await db.outboxMessage.findFirst({
          where: { messageId: `execution-requested-${edgeRun.json.data.execution.id}` },
        })
      )?.payload;
      await reject(
        { ...message, payload: { ...message.payload, pipelineId: x.pEdge.id } },
        "a pipeline of another tenant",
      );
      await reject(
        {
          ...message,
          payload: { ...message.payload, executionId: edgeMessage.payload.executionId },
        },
        "an execution of another tenant",
      );
      await reject(
        { ...message, payload: { ...message.payload, repositoryId: x.idRepo } },
        "a repository that is not the pipeline's",
      );
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-024",
    "dry-run: another tenant's or a hidden repository answers 404 (identical to a missing id), only the repository's own pipelines are described, a pipelineId of another repository is 404, no row of any kind is created, and fork, disabled and match outcomes are reported with stable reasons",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const dry = (cookie, repoId, body) =>
        w.api("POST", `/repositories/${repoId}/pipelines/test-triggers`, { cookie, body });
      const cross = await dry(x.sessions.admin, x.edgeRepo, { event: "push", branch: "main" });
      const hidden = await dry(x.sessions.manager, x.idRepo, { event: "push", branch: "main" });
      const missing = await dry(x.sessions.manager, missingId(), { event: "push", branch: "main" });
      if (cross.status !== 404 || hidden.status !== 404)
        problems.push(`statuses ${cross.status}, ${hidden.status}`);
      if (strip(hidden.json) !== strip(missing.json) || strip(cross.json) !== strip(missing.json))
        problems.push("404 bodies differ from a missing id");
      const forkPipe = (
        await pipCreate(x.sessions.admin, x.payRepo, {
          name: pipName("dry"),
          config: pipCfgFork("skip"),
        })
      ).json.data;
      const offPipe = (
        await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("dryoff"), enabled: false })
      ).json.data;
      const counts = async () =>
        JSON.stringify([
          await db.execution.count(),
          await db.pipelineTriggerDecision.count(),
          await db.auditLog.count(),
          await db.outboxMessage.count(),
        ]);
      const before = await counts();
      const push = await dry(x.sessions.manager, x.payRepo, { event: "push", branch: "main" });
      const pr = await dry(x.sessions.manager, x.payRepo, {
        event: "pull_request",
        action: "opened",
        baseRef: "main",
        isFork: true,
        draft: false,
      });
      const feature = await dry(x.sessions.manager, x.payRepo, {
        event: "push",
        branch: "feature/x",
      });
      const foreignPipeline = await dry(x.sessions.manager, x.payRepo, {
        event: "push",
        branch: "main",
        pipelineId: x.pEdge.id,
      });
      const otherRepoPipeline = await dry(x.sessions.manager, x.payRepo, {
        event: "push",
        branch: "main",
        pipelineId:
          (
            await db.pipeline.findFirst({
              where: { tenantId: x.tenantId, repositoryId: x.payRepo2 },
            })
          )?.id ?? missingId(),
      });
      if ((await counts()) !== before) problems.push("a dry-run changed rows");
      if (push.status !== 200) problems.push(`push dry-run answered ${push.status}`);
      else {
        const names = push.json.data.items.map((i) => i.pipelineId);
        if (names.includes(x.pId.id) || names.includes(x.pEdge.id))
          problems.push("the dry-run describes pipelines of another repository or tenant");
        const mine = push.json.data.items.find((i) => i.pipelineId === forkPipe.id);
        if (mine?.triggers.find((t) => t.triggerKey === "push")?.decision !== "would_run")
          problems.push(`push to the default branch: ${JSON.stringify(mine)}`);
        const off = push.json.data.items.find((i) => i.pipelineId === offPipe.id);
        if (
          off?.triggers.find((t) => t.triggerKey === "push")?.decision !== "not_effective" ||
          off?.effectiveState !== "disabled"
        )
          problems.push(`disabled pipeline: ${JSON.stringify(off)}`);
        if (push.json.data.quota !== "unknown")
          problems.push("the dry-run claimed to know the quota");
      }
      const prItem = pr.json?.data?.items
        ?.find((i) => i.pipelineId === forkPipe.id)
        ?.triggers?.find((t) => t.triggerType === "pull_request");
      if (prItem?.decision !== "blocked_by_policy" || !prItem.reasons.includes("fork_policy_skip"))
        problems.push(`fork PR: ${JSON.stringify(prItem)}`);
      const featureItem = feature.json?.data?.items
        ?.find((i) => i.pipelineId === forkPipe.id)
        ?.triggers?.find((t) => t.triggerKey === "push");
      if (featureItem?.decision !== "no_match" || featureItem.reasons[0] !== "branch_not_included")
        problems.push(`non-matching branch: ${JSON.stringify(featureItem)}`);
      if (foreignPipeline.status !== 404 || otherRepoPipeline.status !== 404)
        problems.push(
          `pipelineId of another repository answered ${foreignPipeline.status}, ${otherRepoPipeline.status}`,
        );
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-020",
    "delete is soft: versions and executions remain readable, queued requests are cancelled with their quota returned, the name is released, a running execution refuses the delete (409), and a deleted pipeline is gone for mutations and for the default list",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const p = (await pipCreate(x.sessions.admin, x.payRepo, { name: pipName("soft") })).json.data;
      await pipPublish(x.sessions.admin, p.id, 1, pipCfg({ failOn: { severity: "medium" } }));
      const a = (await pipRun(x.sessions.admin, p.id, { ref: { type: "branch", name: "main" } }))
        .json.data.execution.id;
      const b = (await pipRun(x.sessions.admin, p.id, { ref: { type: "tag", name: "v1" } })).json
        .data.execution.id;
      const quota = await db.quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
      const used = () =>
        db.tenantQuotaUsage
          .findFirst({ where: { tenantId: x.tenantId, quotaDefinitionId: quota.id } })
          .then((u) => Number(u?.used ?? 0));
      await driveExecution(db, a, "running");
      const usedBefore = await used();
      const refused = await w.api("DELETE", `/pipelines/${p.id}`, {
        cookie: x.sessions.admin,
        body: { confirm: p.name },
      });
      if (
        refused.status !== 409 ||
        refused.json?.error?.details?.reason !== "has_active_executions"
      )
        problems.push(`delete with a running execution answered ${refused.status}`);
      if ((await db.pipeline.findFirst({ where: { id: p.id } })).deletedAt)
        problems.push("a refused delete changed the pipeline");
      await driveExecution(db, a, "succeeded");
      const wrong = await w.api("DELETE", `/pipelines/${p.id}`, {
        cookie: x.sessions.admin,
        body: { confirm: "nope" },
      });
      if (wrong.status !== 400) problems.push(`a wrong confirmation answered ${wrong.status}`);
      const noRole = await w.api("DELETE", `/pipelines/${p.id}`, {
        cookie: x.sessions.edge,
        body: { confirm: p.name },
      });
      if (noRole.status !== 404) problems.push(`another tenant's delete answered ${noRole.status}`);
      const del = await w.api("DELETE", `/pipelines/${p.id}`, {
        cookie: x.sessions.manager,
        body: { confirm: p.name },
      });
      if (del.status !== 200 || del.json?.data?.deleted !== true)
        problems.push(`delete answered ${del.status}`);
      const queued = await db.execution.findFirst({ where: { id: b } });
      if (queued.status !== "cancelled" || queued.statusReason !== "pipeline_deleted")
        problems.push(`the queued request is ${queued.status}/${queued.statusReason}`);
      if ((await used()) !== usedBefore - 1)
        problems.push("the queued request's quota unit was not returned");
      if ((await db.pipelineConfigVersion.count({ where: { pipelineId: p.id } })) !== 2)
        problems.push("versions were removed");
      if ((await db.pipelineTrigger.count({ where: { pipelineId: p.id } })) !== 0)
        problems.push("triggers stay in the projection");
      const versions = await w.api("GET", `/pipelines/${p.id}/versions`, {
        cookie: x.sessions.admin,
      });
      const executions = await w.api("GET", `/pipelines/${p.id}/executions`, {
        cookie: x.sessions.admin,
      });
      if (versions.json?.data?.length !== 2 || executions.json?.data?.length !== 2)
        problems.push("history is not readable after the delete");
      const got = await w.api("GET", `/pipelines/${p.id}`, { cookie: x.sessions.admin });
      if (got.json?.data?.deletedAt === null || got.json.data.effectiveState !== "deleted")
        problems.push("a deleted pipeline is not marked");
      const list = await w.api("GET", "/pipelines?pageSize=100", { cookie: x.sessions.admin });
      const listAll = await w.api("GET", "/pipelines?pageSize=100&includeDeleted=true", {
        cookie: x.sessions.admin,
      });
      if (
        list.json.data.some((r) => r.id === p.id) ||
        !listAll.json.data.some((r) => r.id === p.id)
      )
        problems.push("includeDeleted does not behave");
      for (const [label, r] of [
        [
          "patch",
          await w.api("PATCH", `/pipelines/${p.id}`, {
            cookie: x.sessions.admin,
            body: { description: "x" },
          }),
        ],
        ["run", await pipRun(x.sessions.admin, p.id)],
        ["enable", await w.api("POST", `/pipelines/${p.id}/enable`, { cookie: x.sessions.admin })],
      ])
        if (r.status !== 404) problems.push(`${label} on a deleted pipeline answered ${r.status}`);
      const again = await pipCreate(x.sessions.admin, x.payRepo, { name: p.name });
      if (again.status !== 201 || again.json.data.id === p.id)
        problems.push(`re-creating the name answered ${again.status}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-021",
    "platform session on any pipeline route answers 401, no pipeline route exists under /api/v1/platform, and a tenant session cannot reach one",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const sa = S("sa")(w);
      const problems = [];
      const id = x.pPay.id;
      const calls = [
        ["GET", "/pipelines"],
        ["GET", `/pipelines/${id}`],
        ["POST", `/pipelines/${id}/runs`],
        ["PUT", `/pipelines/${id}/config`],
        ["POST", `/repositories/${x.payRepo}/pipelines`],
        ["POST", `/repositories/${x.payRepo}/pipelines/test-triggers`],
        ["GET", `/pipelines/${id}/executions`],
        ["GET", `/pipelines/${id}/trigger-decisions`],
        ["GET", `/workspaces/${x.PAY}/pipelines/options`],
      ];
      for (const [method, path] of calls) {
        const r = await w.api(method, path, {
          cookie: sa,
          body: method === "GET" ? undefined : {},
        });
        if (r.status !== 401)
          problems.push(`platform session on ${method} ${path} answered ${r.status}`);
      }
      for (const path of [
        "/platform/pipelines",
        `/platform/pipelines/${id}`,
        `/platform/tenants/${x.tenantId}/pipelines`,
      ]) {
        const asPlatform = await w.api("GET", path, { cookie: sa });
        const asTenant = await w.api("GET", path, { cookie: x.sessions.admin });
        if (asPlatform.status !== 404)
          problems.push(
            `platform route ${path} with a platform session answered ${asPlatform.status}`,
          );
        if (asTenant.status !== 404)
          problems.push(`platform route ${path} with a tenant session answered ${asTenant.status}`);
      }
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-033",
    "the repository's pipelineCount is the real number of non-deleted pipelines of that repository, counted within the caller's tenant",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const check = async (cookie, repoId, tenantId) => {
        const expected = await db.pipeline.count({
          where: { tenantId, repositoryId: repoId, deletedAt: null },
        });
        const one = await w.api("GET", `/repositories/${repoId}`, { cookie });
        const list = await w.api("GET", "/repositories?pageSize=100", { cookie });
        const inList = list.json?.data?.find((r) => r.id === repoId);
        if (
          one.json?.data?.pipelineCount !== expected ||
          inList?.pipelineCount !== expected ||
          expected < 1
        )
          problems.push(
            `repository ${repoId}: ${one.json?.data?.pipelineCount}/${inList?.pipelineCount}, expected ${expected}`,
          );
      };
      await check(x.sessions.admin, x.payRepo, x.tenantId);
      await check(x.sessions.edge, x.edgeRepo, x.edgeTenantId);
      // a member who may see the repository but does NOT hold pipeline.view gets null, not a count (control: the owner gets it)
      const t = x.edge;
      const email = `nopipe.${w.suffix}@iso.example`;
      const invited = await w.api("POST", "/users", {
        cookie: t.owner,
        body: { email, name: "No Pipelines" },
      });
      if (invited.status !== 201) problems.push(`invite answered ${invited.status}`);
      const login = await w.api("POST", "/auth/login", {
        body: { email, password: w.secrets.tenantPassword },
      });
      await w.api("POST", `/me/invitations/${t.id}/accept`, { cookie: login.cookie });
      await w.api("PUT", "/me/active-tenant", { cookie: login.cookie, body: { tenantId: t.id } });
      const me = await w.api("GET", "/me", { cookie: login.cookie });
      const role = await w.api("POST", "/roles", {
        cookie: t.owner,
        body: {
          name: `No pipeline view ${w.suffix}`,
          description: "repository.view without pipeline.view",
          permissions: ["workspace.view", "repository.view"],
        },
      });
      if (role.status !== 201) problems.push(`role answered ${role.status}`);
      const assigned = await w.api("POST", `/workspaces/${x.edgeWs}/role-assignments`, {
        cookie: t.owner,
        body: { subjectType: "user", subjectId: me.json.data.user.id, roleId: role.json.data.id },
      });
      if (assigned.status !== 201) problems.push(`assignment answered ${assigned.status}`);
      const restrictedOne = await w.api("GET", `/repositories/${x.edgeRepo}`, {
        cookie: login.cookie,
      });
      const restrictedList = await w.api("GET", "/repositories?pageSize=100", {
        cookie: login.cookie,
      });
      if (restrictedOne.status !== 200)
        problems.push(`restricted GET answered ${restrictedOne.status}`);
      if (restrictedOne.json?.data?.pipelineCount !== null)
        problems.push(
          "the single repository leaks a pipeline count to a caller without pipeline.view",
        );
      const listed = restrictedList.json?.data?.find((r) => r.id === x.edgeRepo);
      if (!listed) problems.push("the repository is not listed for the restricted caller");
      else if (listed.pipelineCount !== null)
        problems.push(
          "the repository list leaks a pipeline count to a caller without pipeline.view",
        );
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-034",
    "a suspended tenant cannot run a pipeline (TENANT_SUSPENDED) and nothing is created; another tenant is unaffected",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const cap = await capWorld();
      const db = suiteDb();
      const problems = [];
      const pipe = await db.pipeline.findFirst({ where: { tenantId: cap.t.id, deletedAt: null } });
      const before = await db.execution.count({ where: { tenantId: cap.t.id } });
      const suspended = await w.api("POST", `/platform/tenants/${cap.t.id}/suspend`, {
        cookie: S("sa")(w),
        body: { reason: "security regression suite", confirm: cap.t.name },
      });
      if (suspended.status !== 200) problems.push(`fixture: suspend answered ${suspended.status}`);
      const r = await pipRun(cap.t.owner, pipe.id);
      if (r.status !== 403 || r.json?.error?.code !== "TENANT_SUSPENDED")
        problems.push(`run answered ${r.status} ${r.json?.error?.code}`);
      if ((await db.execution.count({ where: { tenantId: cap.t.id } })) !== before)
        problems.push("a suspended tenant's run created an execution");
      const other = await pipRun(x.sessions.admin, x.pPay.id);
      if (other.status !== 202) problems.push(`another tenant's run answered ${other.status}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 14. Pipeline trigger router (SPEC pipelines-triggers §6.2, §14.1, part D). Signed webhook deliveries go through the running
//     API (webhook -> scm_events + outbox), the stored `scm.*.received` envelope is then handed to the router IN PROCESS exactly
//     as the `pipeline-triggers` consumer does (parse, ownership verification, handler), against the disposable database.
//     Tenants: R (all scenarios, two workspaces), X (the same GitHub repository id connected by another tenant) and Q (quota).
// ---------------------------------------------------------------------------------------------------------------------
const rtSha = (c) => c.repeat(40);
const rtPush = ({
  inst,
  repo,
  branch = "main",
  tag,
  before = rtSha("a"),
  after = rtSha("b"),
  created = false,
  deleted = false,
  forced = false,
}) => ({
  ref: tag ? `refs/tags/${tag}` : `refs/heads/${branch}`,
  before,
  after,
  created,
  deleted,
  forced,
  commits: deleted ? [] : [{ id: after }],
  head_commit: deleted ? null : { id: after },
  pusher: { name: "dev" },
  repository: { id: Number(repo) },
  installation: { id: Number(inst) },
});
/** `fork`: false (same repository), true (a fork) or "unknown" (GitHub sends no head repository). */
const rtPr = ({
  inst,
  repo,
  action = "opened",
  number = 7,
  base = "main",
  head = "feature",
  fork = false,
  draft = false,
  merged = false,
  sha = rtSha("c"),
}) => ({
  action,
  number,
  repository: { id: Number(repo) },
  installation: { id: Number(inst) },
  pull_request: {
    number,
    draft,
    merged,
    user: { login: "dev" },
    base: { ref: base, sha: rtSha("d") },
    head: {
      ref: head,
      sha,
      ...(fork === "unknown"
        ? {}
        : { repo: { id: fork ? Number(repo) + 1 : Number(repo), fork: fork === true } }),
    },
  },
});
const rtHandler = (db = suiteDb()) =>
  createPipelineTriggerHandler({
    db,
    config: { pipelines: { maxPerRepository: 20 } },
    logger: quietLog,
  });
/** What the consumer does with a message: parse, verify ownership against the database, run the handler. */
async function rtConsume(envelope, { handler } = {}) {
  const message = parseMessage(envelope);
  try {
    await createOwnershipVerifier({ db: suiteDb() })(message);
    await (handler ?? rtHandler())(message, { log: quietLog });
    return { ok: true, reason: null };
  } catch (error) {
    return { ok: false, reason: error?.reason ?? null, name: error?.name, error };
  }
}
/** Delivers a signed event, reads the stored message, and (unless `route` is false) routes it. */
async function rtEvent(kind, opts, { route = true } = {}) {
  const payload = kind === "push" ? rtPush(opts) : rtPr(opts);
  const delivery = await deliver({ event: kind, payload });
  const rows = await rowsFor(delivery.deliveryId);
  const envelope = rows.outbox[0]?.payload ?? null;
  const consumed = envelope && route ? await rtConsume(envelope) : null;
  return { ...delivery, rows, envelope, consumed };
}
const rtExecs = (pipelineId, where = {}) =>
  suiteDb().execution.findMany({
    where: { pipelineId, ...where },
    orderBy: { requestedAt: "asc" },
  });
const rtDecisions = (pipelineId, where = {}) =>
  suiteDb().pipelineTriggerDecision.findMany({ where: { pipelineId, ...where } });
const rtAudits = (pipelineId, tenantId) =>
  suiteDb().auditLog.findMany({
    where: { tenantId, targetId: pipelineId, action: { startsWith: "execution." } },
  });
const rtMessages = (executionIds) =>
  suiteDb().outboxMessage.findMany({
    where: {
      type: "pipeline.execution.requested",
      messageId: { in: executionIds.map((id) => `execution-requested-${id}`) },
    },
  });
const rtSetRepo = (id, data) => suiteDb().repository.update({ where: { id }, data });
const rtActive = { status: "active", enabled: true, disconnectedAt: null, disconnectReason: null };
const rtUsed = async (tenantId) => {
  const def = await suiteDb().quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
  const row = await suiteDb().tenantQuotaUsage.findFirst({
    where: {
      tenantId,
      quotaDefinitionId: def.id,
      periodKey: new Date().toISOString().slice(0, 7),
    },
  });
  return Number(row?.used ?? 0);
};

const rtWorld = () =>
  once("rt-world", async () => {
    const db = suiteDb();
    const base = 7100000 + (Date.now() % 100000) * 20;
    const ext = {
      fan: base + 1,
      common: base + 2,
      fork: base + 3,
      bt: base + 4,
      st: base + 5,
      conc: base + 6,
      lc: base + 7,
      wk: base + 8,
      oth: base + 9,
      q: base + 10,
      prc: base + 11,
      prd: base + 12,
      prw: base + 13,
    };
    const mk = async (cookie, repositoryId, label, config, enabled = true) => {
      const r = await pipCreate(cookie, repositoryId, { name: pipName(label), enabled, config });
      assert.equal(
        r.status,
        201,
        `fixture: pipeline ${label} answered ${r.status} ${JSON.stringify(r.json?.error)}`,
      );
      return r.json.data;
    };
    const connectAll = async (cookie, workspaceId, flow, ids) => {
      const wl = flow.link.json.data.id;
      await putAllowList(cookie, workspaceId, wl, ids);
      const out = {};
      for (const id of ids) {
        const res = await connectRepo(cookie, workspaceId, wl, id);
        assert.equal(res.status, 201, `fixture: connect ${id} answered ${res.status}`);
        out[id] = res.json.data.id;
      }
      return out;
    };
    const workspace = async (cookie, name) => {
      const r = await w.api("POST", "/workspaces", {
        cookie,
        body: { name: `${name} ${w.suffix}` },
      });
      assert.equal(r.status, 201, `fixture: workspace answered ${r.status}`);
      return r.json.data.id;
    };

    // tenant R: workspace 1 (most repositories) and workspace 2 (one repository)
    const R = await w.provisionTenant("rtr");
    const ws1 = await workspace(R.owner, "Router one");
    const ws2 = await workspace(R.owner, "Router two");
    const account = orgAccount("rt");
    const user = ghUser();
    const inWs1 = [
      ext.fan,
      ext.common,
      ext.fork,
      ext.bt,
      ext.st,
      ext.conc,
      ext.lc,
      ext.wk,
      ext.prc,
      ext.prd,
    ];
    const flow1 = await linkFlow(R.owner, {
      workspaceId: ws1,
      account,
      user,
      orgRole: "admin",
      repos: [...inWs1, ext.oth, ext.prw].map(stubRepo),
    });
    assert.equal(flow1.link?.status, 201, "fixture: link R workspace 1");
    const flow2 = await linkFlow(R.owner, {
      workspaceId: ws2,
      installationId: flow1.installationId,
      account,
      user,
      orgRole: "admin",
    });
    assert.equal(flow2.link?.status, 201, "fixture: link R workspace 2");
    const repoIds = { ...(await connectAll(R.owner, ws1, flow1, inWs1)) };
    Object.assign(repoIds, await connectAll(R.owner, ws2, flow2, [ext.oth, ext.prw]));
    R.inst = flow1.installationId;

    // tenant X connects the SAME GitHub repository id (`common`) through its own installation
    const X = await w.provisionTenant("rtx");
    const wsX = await workspace(X.owner, "Router X");
    const flowX = await linkFlow(X.owner, {
      workspaceId: wsX,
      account: orgAccount("rtx"),
      user: ghUser(),
      orgRole: "admin",
      repos: [stubRepo(ext.common), stubRepo(ext.prc)],
    });
    assert.equal(flowX.link?.status, 201, "fixture: link X");
    const repoXs = await connectAll(X.owner, wsX, flowX, [ext.common, ext.prc]);
    const repoX = repoXs[ext.common];
    X.inst = flowX.installationId;

    // tenant Q: one scan per month
    const Q = await w.provisionTenant("rtq");
    const wsQ = await workspace(Q.owner, "Router Q");
    const flowQ = await linkFlow(Q.owner, {
      workspaceId: wsQ,
      account: orgAccount("rtq"),
      user: ghUser(),
      orgRole: "admin",
      repos: [stubRepo(ext.q)],
    });
    assert.equal(flowQ.link?.status, 201, "fixture: link Q");
    const repoQ = (await connectAll(Q.owner, wsQ, flowQ, [ext.q]))[ext.q];
    Q.inst = flowQ.installationId;
    const quota = await db.quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
    await db.tenantQuota.create({
      data: { tenantId: Q.id, quotaDefinitionId: quota.id, limitValue: 1n },
    });

    const own = R.owner;
    const fan = await Promise.all(
      ["a", "b", "c"].map((n) => mk(own, repoIds[ext.fan], `fan-${n}`, pipCfg())),
    );
    const common = {
      pa: await mk(own, repoIds[ext.common], "common-a", pipCfg()),
      pb: await mk(X.owner, repoX, "common-b", pipCfg()),
    };
    const fork = {
      skip: await mk(own, repoIds[ext.fork], "fork-skip", pipCfgFork("skip")),
      run: await mk(own, repoIds[ext.fork], "fork-run", pipCfgFork("run_without_credentials")),
    };
    const bt = await mk(
      own,
      repoIds[ext.bt],
      "rules",
      pipCfg({
        triggers: [
          {
            key: "push",
            type: "push",
            branches: { include: ["main", "release/*"], exclude: ["release/old"] },
            tags: { enabled: true, include: ["v*"], exclude: ["v0*"] },
          },
          { key: "manual", type: "manual" },
        ],
      }),
    );
    const st = {
      on: await mk(own, repoIds[ext.st], "state-on", pipCfg()),
      off: await mk(own, repoIds[ext.st], "state-off", pipCfg(), false),
      trigOff: await mk(
        own,
        repoIds[ext.st],
        "state-trigger-off",
        pipCfg({
          triggers: [
            { key: "push", type: "push", enabled: false },
            { key: "manual", type: "manual" },
          ],
        }),
      ),
      del: await mk(own, repoIds[ext.st], "state-deleted", pipCfg()),
    };
    const delRes = await w.api("DELETE", `/pipelines/${st.del.id}`, {
      cookie: own,
      body: { confirm: st.del.name },
    });
    assert.equal(delRes.status, 200, `fixture: delete answered ${delRes.status}`);
    const conc = {
      supersede: await mk(own, repoIds[ext.conc], "conc-supersede", pipCfg()),
      queue: await mk(
        own,
        repoIds[ext.conc],
        "conc-queue",
        pipCfg({ execution: { concurrency: { policy: "queue", maxQueued: 1 } } }),
      ),
      skip: await mk(
        own,
        repoIds[ext.conc],
        "conc-skip",
        pipCfg({ execution: { concurrency: { policy: "skip" } } }),
      ),
    };
    const lc = await mk(own, repoIds[ext.lc], "lifecycle", pipCfg());
    const wk = await mk(own, repoIds[ext.wk], "webhook-states", pipCfg());
    const oth = await mk(own, repoIds[ext.oth], "workspace-two", pipCfg());
    // closed pull request housekeeping (PIP-056..059): R has two pipelines with a pull_request trigger on `prc` (supersede and
    // queue policy) and one without, a pipeline on another repository of the same workspace (`prd`) and one in the other
    // workspace (`prw`); tenant X connects the same GitHub repository id as `prc`
    const prTriggers = [
      { key: "push", type: "push" },
      { key: "pr", type: "pull_request" },
      { key: "manual", type: "manual" },
    ];
    const pr = {
      a: await mk(own, repoIds[ext.prc], "pr-supersede", pipCfg({ triggers: prTriggers })),
      b: await mk(
        own,
        repoIds[ext.prc],
        "pr-queue",
        pipCfg({
          triggers: prTriggers,
          execution: { concurrency: { policy: "queue", maxQueued: 10 } },
        }),
      ),
      c: await mk(own, repoIds[ext.prc], "pr-no-trigger", pipCfg()),
      d: await mk(own, repoIds[ext.prd], "pr-other-repo", pipCfg({ triggers: prTriggers })),
      w: await mk(own, repoIds[ext.prw], "pr-other-workspace", pipCfg({ triggers: prTriggers })),
      x: await mk(X.owner, repoXs[ext.prc], "pr-other-tenant", pipCfg({ triggers: prTriggers })),
    };
    const q = await mk(
      Q.owner,
      repoQ,
      "quota",
      pipCfg({
        triggers: [
          { key: "push", type: "push", branches: { include: ["main", "dev", "qa", "ops"] } },
          { key: "manual", type: "manual" },
        ],
      }),
    );
    return {
      ext,
      R,
      X,
      Q,
      ws1,
      ws2,
      repoIds,
      repoX,
      repoQ,
      fan,
      common,
      fork,
      bt,
      st,
      conc,
      lc,
      wk,
      oth,
      pr,
      q,
    };
  });
const rtId = (x, name) => x.repoIds[x.ext[name]];

{
  const add = group("Pipeline trigger router: isolation and fan-out");
  add(
    "PIP-005",
    "trigger matching never crosses tenants: the same GitHub repository id connected by two tenants only creates executions for the owning tenant's pipelines, in both directions",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const db = suiteDb();
      const problems = [];
      const r1 = await rtEvent("push", { inst: x.R.inst, repo: x.ext.common });
      if (!r1.consumed?.ok) problems.push(`R's push was not routed: ${r1.consumed?.reason}`);
      const forA = await rtExecs(x.common.pa.id, { scmDeliveryId: r1.deliveryId });
      if (forA.length !== 1) problems.push(`the owner's pipeline got ${forA.length} executions`);
      if (
        (await db.execution.count({
          where: { tenantId: x.X.id, scmDeliveryId: r1.deliveryId },
        })) !== 0 ||
        (await rtExecs(x.common.pb.id)).length !== 0 ||
        (await rtDecisions(x.common.pb.id)).length !== 0
      )
        problems.push("the other tenant's pipeline was touched by R's event");
      const r2 = await rtEvent("push", { inst: x.X.inst, repo: x.ext.common, after: rtSha("e") });
      if (!r2.consumed?.ok) problems.push(`X's push was not routed: ${r2.consumed?.reason}`);
      const forB = await rtExecs(x.common.pb.id, { scmDeliveryId: r2.deliveryId });
      if (forB.length !== 1) problems.push(`X's pipeline got ${forB.length} executions`);
      if (
        (await db.execution.count({
          where: { tenantId: x.R.id, scmDeliveryId: r2.deliveryId },
        })) !== 0
      )
        problems.push("R's pipelines were touched by X's event");
      if ((await rtExecs(x.common.pa.id)).length !== 1)
        problems.push("R's pipeline has executions it should not have");
      const messages = await rtMessages([...forA, ...forB].map((e) => e.id));
      if (
        messages.length !== 2 ||
        messages.some(
          (m) =>
            m.tenantId !== (m.messageId.endsWith(forA[0]?.id) ? x.R.id : x.X.id) ||
            m.payload.tenantId !== m.tenantId,
        )
      )
        problems.push("the execution messages do not carry their own tenant");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-006",
    "trigger matching never crosses workspaces or repositories: an event for one repository creates nothing for the other pipelines of the same tenant, in the same or another workspace",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const db = suiteDb();
      const problems = [];
      const others = [...x.fan, x.bt, x.st.on, x.conc.supersede, x.lc, x.wk, x.oth];
      const snapshot = async () =>
        JSON.stringify(
          await Promise.all(
            others.map(async (p) => [
              (await rtExecs(p.id)).length,
              (await rtDecisions(p.id)).length,
            ]),
          ),
        );
      const before = await snapshot();
      const pa = (await rtExecs(x.common.pa.id)).length;
      const r = await rtEvent("push", { inst: x.R.inst, repo: x.ext.common, after: rtSha("f") });
      if (!r.consumed?.ok) problems.push(`not routed: ${r.consumed?.reason}`);
      if ((await rtExecs(x.common.pa.id)).length !== pa + 1)
        problems.push("the repository's own pipeline did not run (control)");
      if ((await snapshot()) !== before)
        problems.push("pipelines of other repositories or of the other workspace were touched");
      const stray = await db.execution.count({
        where: { scmDeliveryId: r.deliveryId, pipelineId: { not: x.common.pa.id } },
      });
      if (stray !== 0) problems.push(`${stray} stray executions for the delivery`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-007",
    "a forged message (tenantId of one tenant with the repository, or the workspace, of another) is dead-lettered with resource-not-in-tenant by the consumer's ownership check, and the router itself refuses it: no execution in either tenant",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const db = suiteDb();
      const problems = [];
      const real = await rtEvent("push", { inst: x.R.inst, repo: x.ext.fan }, { route: false });
      const env = real.envelope;
      if (!env) return { status: 200, json: null, problems: ["fixture: no stored message"] };
      const forged = {
        tenantOnly: { ...env, tenantId: x.X.id },
        tenantNoWorkspace: (({ workspaceId: _omitted, ...rest }) => ({
          ...rest,
          tenantId: x.X.id,
        }))(env),
        repositoryOfX: {
          ...env,
          payload: { ...env.payload, repositoryId: x.repoX },
          subject: { type: "repository", id: x.repoX },
        },
        otherWorkspace: { ...env, workspaceId: x.ws2 },
      };
      for (const [name, envelope] of Object.entries(forged)) {
        const viaConsumer = await rtConsume(envelope);
        if (viaConsumer.ok || viaConsumer.reason !== "resource-not-in-tenant")
          problems.push(`${name}: the consumer answered ${viaConsumer.reason ?? "accepted"}`);
        // the handler alone (no ownership verification before it) must refuse as well
        const alone = await (async () => {
          try {
            await rtHandler()(parseMessage(envelope), { log: quietLog });
            return null;
          } catch (error) {
            return error?.reason ?? error?.message;
          }
        })();
        if (alone !== "resource-not-in-tenant" && alone !== "scm-event-missing")
          problems.push(`${name}: the router alone answered ${alone ?? "accepted"}`);
        const created = await db.execution.count({ where: { scmDeliveryId: real.deliveryId } });
        if (created !== 0) {
          problems.push(`${name}: ${created} executions were created`);
          break;
        }
      }
      const stray = await db.execution.count({ where: { scmDeliveryId: real.deliveryId } });
      if (stray !== 0) problems.push(`${stray} executions were created by forged messages`);
      const control = await rtConsume(env);
      if (!control.ok)
        problems.push(`control: the genuine message was refused (${control.reason})`);
      if ((await db.execution.count({ where: { scmDeliveryId: real.deliveryId } })) !== 3)
        problems.push("control: the genuine message did not create its executions");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-016",
    "one event with N matching pipelines creates N executions and N messages (N = 3), exactly one per pipeline on a duplicate delivery, when the consumer handles the same message twice, and after a crash between two pipelines",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const db = suiteDb();
      const problems = [];
      const ids = x.fan.map((p) => p.id);
      const byDelivery = (d) => db.execution.findMany({ where: { scmDeliveryId: d } });
      const first = await rtEvent("push", { inst: x.R.inst, repo: x.ext.fan, after: rtSha("1") });
      const rows = await byDelivery(first.deliveryId);
      if (rows.length !== 3 || new Set(rows.map((r) => r.pipelineId)).size !== 3)
        problems.push(`${rows.length} executions for 3 matching pipelines`);
      if (rows.some((r) => r.status !== "queued" || !ids.includes(r.pipelineId)))
        problems.push("an execution is not a queued request of one of the three pipelines");
      if ((await rtMessages(rows.map((r) => r.id))).length !== 3)
        problems.push("not one message per execution");
      // the same delivery again (GitHub retries) and the same message again (the broker redelivers)
      const dup = await deliver({
        event: "push",
        payload: rtPush({ inst: x.R.inst, repo: x.ext.fan, after: rtSha("1") }),
        deliveryId: first.deliveryId,
      });
      if (dup.status !== 202) problems.push(`the duplicate delivery answered ${dup.status}`);
      const again = await rtConsume(first.envelope);
      const third = await rtConsume(first.envelope);
      if (!again.ok || !third.ok) problems.push("a redelivered message was refused");
      if (
        (await byDelivery(first.deliveryId)).length !== 3 ||
        (await rtMessages(rows.map((r) => r.id))).length !== 3 ||
        (await db.outboxMessage.count({
          where: { messageId: `scm-github-${first.deliveryId}` },
        })) !== 1
      )
        problems.push("a duplicate created a second execution or message");
      // a crash in the middle: the second pipeline's transaction fails
      const crashing = (() => {
        let calls = 0;
        return new Proxy(db, {
          get(target, prop) {
            const value = target[prop];
            if (prop === "$transaction")
              return (fn, options) => {
                calls += 1;
                if (calls === 2) throw new Error("simulated crash");
                return target.$transaction(fn, options);
              };
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
      })();
      const second = await rtEvent(
        "push",
        { inst: x.R.inst, repo: x.ext.fan, after: rtSha("2") },
        { route: false },
      );
      const crashed = await rtConsume(second.envelope, { handler: rtHandler(crashing) });
      if (crashed.ok || crashed.name !== "TransientError")
        problems.push(`the crash was not a transient failure (${crashed.name})`);
      const partial = (await byDelivery(second.deliveryId)).length;
      if (partial !== 2) problems.push(`${partial} executions after the crash, expected 2`);
      const retried = await rtConsume(second.envelope);
      if (!retried.ok) problems.push(`the retry failed (${retried.reason})`);
      const final = await byDelivery(second.deliveryId);
      if (final.length !== 3 || new Set(final.map((r) => r.pipelineId)).size !== 3)
        problems.push(`${final.length} executions after the retry, one per pipeline expected`);
      if ((await rtMessages(final.map((r) => r.id))).length !== 3)
        problems.push("the retry did not leave exactly one message per execution");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

{
  const add = group("Pipeline trigger router: fork rule, branch and tag rules, decisions");
  const forkEvent = (x, opts) =>
    rtEvent("pull_request", { inst: x.R.inst, repo: x.ext.fork, ...opts });
  add(
    "PIP-008",
    "fork rule: with the default policy a fork pull request, and one whose head repository is unknown, create no execution and leave a fork_policy_skip decision row; a same-repository pull request runs; run_without_credentials creates an untrusted_fork execution; a draft is skipped by the draft policy",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const problems = [];
      const outcome = async (opts) => {
        const r = await forkEvent(x, opts);
        return {
          r,
          skip: await rtExecs(x.fork.skip.id, { scmDeliveryId: r.deliveryId }),
          run: await rtExecs(x.fork.run.id, { scmDeliveryId: r.deliveryId }),
          skipDec: await rtDecisions(x.fork.skip.id, { scmDeliveryId: r.deliveryId }),
          runDec: await rtDecisions(x.fork.run.id, { scmDeliveryId: r.deliveryId }),
        };
      };
      for (const [label, opts] of [
        ["a fork", { fork: true, number: 11 }],
        ["an unknown head repository", { fork: "unknown", number: 12 }],
      ]) {
        const o = await outcome(opts);
        if (!o.r.consumed?.ok) problems.push(`${label}: not routed (${o.r.consumed?.reason})`);
        if (o.skip.length !== 0) problems.push(`${label}: the default policy created an execution`);
        if (o.skipDec.length !== 1 || o.skipDec[0].reason !== "fork_policy_skip")
          problems.push(`${label}: no fork_policy_skip decision row`);
        if (o.run.length !== 1 || o.run[0].trust !== "untrusted_fork" || o.runDec.length !== 0)
          problems.push(`${label}: run_without_credentials did not create one untrusted_fork run`);
      }
      const same = await outcome({ fork: false, number: 13 });
      if (same.skip.length !== 1 || same.skip[0].trust !== "trusted" || same.skipDec.length !== 0)
        problems.push("a same-repository pull request did not run (control)");
      if (same.run.length !== 1 || same.run[0].trust !== "trusted")
        problems.push("a same-repository pull request did not run trusted under the fork policy");
      const draft = await outcome({ fork: false, draft: true, number: 14 });
      if (draft.skip.length || draft.run.length)
        problems.push("a draft pull request ran under the default draft policy");
      if (
        draft.skipDec[0]?.reason !== "draft_policy_skip" ||
        draft.runDec[0]?.reason !== "draft_policy_skip"
      )
        problems.push("a skipped draft left no draft_policy_skip decision row");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-035",
    "a run_without_credentials execution carries trust untrusted_fork in its row and in its request message, whose payload holds only the allowed ids, enums and short strings (no token, credential or free text)",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const problems = [];
      const r = await forkEvent(x, { fork: true, number: 21, sha: rtSha("9") });
      const rows = await rtExecs(x.fork.run.id, { scmDeliveryId: r.deliveryId });
      if (rows.length !== 1 || rows[0].trust !== "untrusted_fork")
        return { status: 200, json: null, problems: ["fixture: no untrusted_fork execution"] };
      const [message] = await rtMessages([rows[0].id]);
      const allowed = new Set([
        "executionId",
        "pipelineId",
        "repositoryId",
        "workspaceId",
        "configVersion",
        "configHash",
        "triggerType",
        "triggerKey",
        "refType",
        "refName",
        "commitSha",
        "pullRequestNumber",
        "scanKind",
        "scanKindReason",
        "trust",
      ]);
      if (!message) problems.push("no request message");
      else {
        const extra = Object.keys(message.payload.payload).filter((k) => !allowed.has(k));
        if (extra.length) problems.push(`unexpected payload fields ${extra}`);
        if (message.payload.payload.trust !== "untrusted_fork")
          problems.push("the message does not carry the trust marker");
        if (
          message.payload.payload.pullRequestNumber !== 21 ||
          message.payload.payload.refType !== "pull_request"
        )
          problems.push("the message lacks the pull request context");
        const text = JSON.stringify(message.payload);
        if (TOKEN_MATERIAL.test(text) || /token|secret|password|credential/i.test(text))
          problems.push("credential-like content in the message");
        if (text.includes("authorLogin") || text.includes('"dev"'))
          problems.push("an author or commit text reached the message");
        if (
          message.payload.initiator?.type !== "scm" ||
          message.payload.causationId !== r.envelope.messageId
        )
          problems.push("the message does not name its cause");
      }
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-036",
    "branch include/exclude and tag rules: matching branches and tags create one execution (full for a created branch, a force push and a tag), excluded or unlisted branches, excluded tags and deleted refs create nothing and leave no decision row and no audit entry",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const problems = [];
      const run = async (label, opts, expected) => {
        const r = await rtEvent("push", { inst: x.R.inst, repo: x.ext.bt, ...opts });
        const rows = await rtExecs(x.bt.id, { scmDeliveryId: r.deliveryId });
        if (!r.consumed?.ok) problems.push(`${label}: not routed (${r.consumed?.reason})`);
        if (!expected) {
          if (rows.length) problems.push(`${label}: created an execution`);
        } else if (rows.length !== 1) problems.push(`${label}: ${rows.length} executions`);
        else if (expected !== true) {
          const [kind, reason] = expected;
          if (rows[0].scanKind !== kind || rows[0].scanKindReason !== reason)
            problems.push(`${label}: ${rows[0].scanKind}/${rows[0].scanKindReason}`);
        }
        return r;
      };
      const decisionsBefore = (await rtDecisions(x.bt.id)).length;
      await run("main", { branch: "main", after: rtSha("1") }, true);
      await run("release/1.0", { branch: "release/1.0", after: rtSha("2") }, true);
      await run("a created branch", { branch: "main", after: rtSha("3"), created: true }, [
        "full",
        "branch_created",
      ]);
      await run("a force push", { branch: "main", after: rtSha("4"), forced: true }, [
        "full",
        "force_push",
      ]);
      await run("tag v1.0", { tag: "v1.0", after: rtSha("5") }, ["full", "tag"]);
      const stateAfterMatches = {
        decisions: (await rtDecisions(x.bt.id)).length,
        audits: (await rtAudits(x.bt.id, x.R.id)).length,
      };
      await run("an excluded branch", { branch: "release/old", after: rtSha("6") }, false);
      await run("an unlisted branch", { branch: "feature/x", after: rtSha("7") }, false);
      await run("an excluded tag", { tag: "v0.9", after: rtSha("8") }, false);
      await run("an unlisted tag", { tag: "nightly", after: rtSha("9") }, false);
      await run(
        "a deleted branch",
        { branch: "main", after: "0".repeat(40), deleted: true },
        false,
      );
      const decisionsAfter = (await rtDecisions(x.bt.id)).length;
      if (decisionsBefore !== 0 || decisionsAfter !== stateAfterMatches.decisions)
        problems.push("a non-matching event left a decision row");
      const auditsAfter = (await rtAudits(x.bt.id, x.R.id)).length;
      if (auditsAfter !== stateAfterMatches.audits)
        problems.push("a non-matching event left an audit entry");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-038",
    "decision recording: a policy skip leaves exactly one decision row per pipeline and delivery (a redelivered message adds none), no execution, no quota and no audit entry; a pull request to a branch no trigger targets leaves no row at all",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const problems = [];
      const usedBefore = await rtUsed(x.R.id);
      const auditsBefore = (await rtAudits(x.fork.skip.id, x.R.id)).length;
      const r = await forkEvent(x, { fork: true, number: 31 });
      await rtConsume(r.envelope);
      await rtConsume(r.envelope);
      const dec = await rtDecisions(x.fork.skip.id, { scmDeliveryId: r.deliveryId });
      if (dec.length !== 1)
        problems.push(`${dec.length} decision rows for one pipeline and delivery`);
      else if (
        dec[0].decision !== "skipped_by_policy" ||
        dec[0].triggerKey !== "pr" ||
        dec[0].refName !== "pull/31" ||
        dec[0].pullRequestNumber !== 31
      )
        problems.push("the decision row does not describe the event");
      if ((await rtExecs(x.fork.skip.id, { scmDeliveryId: r.deliveryId })).length !== 0)
        problems.push("a policy skip created an execution");
      if ((await rtAudits(x.fork.skip.id, x.R.id)).length !== auditsBefore)
        problems.push("a policy skip was audited");
      // the run_without_credentials pipeline ran once (one unit); the skipping one used nothing
      if ((await rtUsed(x.R.id)) !== usedBefore + 1)
        problems.push("the quota use is not exactly one unit");
      const nonMatch = await forkEvent(x, { fork: true, base: "feature/none", number: 32 });
      const rows = await Promise.all(
        [x.fork.skip, x.fork.run].map(async (p) => [
          (await rtDecisions(p.id, { scmDeliveryId: nonMatch.deliveryId })).length,
          (await rtExecs(p.id, { scmDeliveryId: nonMatch.deliveryId })).length,
        ]),
      );
      if (
        JSON.stringify(rows) !==
        JSON.stringify([
          [0, 0],
          [0, 0],
        ])
      )
        problems.push("a non-matching target branch left rows");
      const stored = await suiteDb().pipelineTriggerDecision.findFirst({
        where: { scmDeliveryId: r.deliveryId },
      });
      if (stored && Object.values(stored).some((v) => v === "dev" || String(v).includes("@")))
        problems.push("an author or title reached the decision row");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

{
  const add = group("Pipeline trigger router: state, lifecycle and the SCM producer");
  add(
    "PIP-015",
    "disconnected, unavailable and disabled repositories, disabled and deleted pipelines and disabled triggers create no execution for a valid event; the policy-skip cases leave a decision row with the right reason and a non-matching branch leaves none",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const problems = [];
      const repoId = rtId(x, "st");
      const all = [x.st.on, x.st.off, x.st.trigOff, x.st.del];
      const counts = async (d) =>
        Object.fromEntries(
          await Promise.all(
            all.map(async (p) => [
              p.name,
              {
                execs: (await rtExecs(p.id, { scmDeliveryId: d })).length,
                decisions: (await rtDecisions(p.id, { scmDeliveryId: d })).map((r) => r.reason),
              },
            ]),
          ),
        );
      const control = await rtEvent("push", { inst: x.R.inst, repo: x.ext.st, after: rtSha("1") });
      const c = await counts(control.deliveryId);
      if (c[x.st.on.name].execs !== 1) problems.push("control: the active pipeline did not run");
      if (c[x.st.off.name].decisions[0] !== "pipeline_disabled" || c[x.st.off.name].execs)
        problems.push("a disabled pipeline did not leave pipeline_disabled");
      if (c[x.st.trigOff.name].decisions[0] !== "trigger_disabled" || c[x.st.trigOff.name].execs)
        problems.push("a disabled trigger did not leave trigger_disabled");
      if (c[x.st.del.name].execs || c[x.st.del.name].decisions.length)
        problems.push("a deleted pipeline was evaluated");
      const states = [
        [
          "disconnected",
          { status: "disconnected", disconnectedAt: new Date(), disconnectReason: "suite" },
          "repository_inactive",
        ],
        ["unavailable", { status: "unavailable" }, "repository_inactive"],
        ["disabled", { enabled: false }, "repository_disabled"],
      ];
      try {
        for (const [label, patch, reason] of states) {
          // published while the repository was usable, consumed after its state changed
          const e = await rtEvent(
            "push",
            {
              inst: x.R.inst,
              repo: x.ext.st,
              after: rtSha(label === "disabled" ? "4" : label === "unavailable" ? "3" : "2"),
            },
            { route: false },
          );
          await rtSetRepo(repoId, patch);
          const consumed = await rtConsume(e.envelope);
          const n = await counts(e.deliveryId);
          if (!consumed.ok) problems.push(`${label}: the message was refused (${consumed.reason})`);
          if (all.some((p) => n[p.name].execs)) problems.push(`${label}: an execution was created`);
          if (
            n[x.st.on.name].decisions[0] !== reason ||
            n[x.st.trigOff.name].decisions[0] !== reason
          )
            problems.push(`${label}: decision rows ${JSON.stringify(n[x.st.on.name].decisions)}`);
          if (n[x.st.off.name].decisions[0] !== "pipeline_disabled")
            problems.push(`${label}: the disabled pipeline's reason changed`);
          await rtSetRepo(repoId, rtActive);
        }
      } finally {
        await rtSetRepo(repoId, rtActive);
      }
      const noMatch = await rtEvent("push", {
        inst: x.R.inst,
        repo: x.ext.st,
        branch: "feature/y",
        after: rtSha("5"),
      });
      const nm = await counts(noMatch.deliveryId);
      if (all.some((p) => nm[p.name].execs || nm[p.name].decisions.length))
        problems.push("a non-matching branch left rows");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-017",
    "suspended and deactivated tenants and an archived workspace create nothing (the consumer dead-letters the message with tenant-not-usable; an archived workspace leaves a workspace_archived decision row); another tenant is unaffected and the legitimate path works once the state is restored",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const db = suiteDb();
      const problems = [];
      const e = await rtEvent(
        "push",
        { inst: x.R.inst, repo: x.ext.lc, after: rtSha("1") },
        { route: false },
      );
      const execs = () => rtExecs(x.lc.id, { scmDeliveryId: e.deliveryId });
      try {
        for (const status of ["suspended", "deactivated"]) {
          await db.tenant.update({ where: { id: x.R.id }, data: { status } });
          const refused = await rtConsume(e.envelope);
          if (refused.ok || refused.reason !== "tenant-not-usable")
            problems.push(`${status}: the consumer answered ${refused.reason ?? "accepted"}`);
          // the router alone refuses too
          const alone = await (async () => {
            try {
              await rtHandler()(parseMessage(e.envelope), { log: quietLog });
              return null;
            } catch (error) {
              return error?.reason;
            }
          })();
          if (alone !== "tenant-not-usable")
            problems.push(`${status}: the router alone answered ${alone ?? "accepted"}`);
          if ((await execs()).length) problems.push(`${status}: an execution was created`);
          if ((await rtDecisions(x.lc.id, { scmDeliveryId: e.deliveryId })).length)
            problems.push(`${status}: a decision row was written`);
          // another tenant keeps working
          const other = await rtEvent("push", {
            inst: x.X.inst,
            repo: x.ext.common,
            after: rtSha(status === "suspended" ? "7" : "8"),
          });
          if ((await rtExecs(x.common.pb.id, { scmDeliveryId: other.deliveryId })).length !== 1)
            problems.push(`${status}: another tenant's event was not routed`);
        }
      } finally {
        await db.tenant.update({ where: { id: x.R.id }, data: { status: "active" } });
      }
      try {
        await db.workspace.update({ where: { id: x.ws1 }, data: { status: "archived" } });
        const archived = await rtConsume(e.envelope);
        if (!archived.ok) problems.push(`archived: the message was refused (${archived.reason})`);
        if ((await execs()).length) problems.push("archived: an execution was created");
        const dec = await rtDecisions(x.lc.id, { scmDeliveryId: e.deliveryId });
        if (dec.length !== 1 || dec[0].reason !== "workspace_archived")
          problems.push("archived: no workspace_archived decision row");
      } finally {
        await db.workspace.update({ where: { id: x.ws1 }, data: { status: "active" } });
      }
      const control = await rtConsume(e.envelope);
      if (!control.ok || (await execs()).length !== 1)
        problems.push("control: the restored workspace did not create its execution");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-028",
    "SCM producer: a signed push and pull-request webhook for a disconnected, unavailable or disabled repository publish no scm.push.received / scm.pull_request.received (delivery ignored, no event row, no outbox row); an active enabled repository publishes both; a repository event for an unavailable repository is still published",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const db = suiteDb();
      const problems = [];
      const repoId = rtId(x, "wk");
      const send = async (kind) => {
        const d = await rtEvent(
          kind,
          { inst: x.R.inst, repo: x.ext.wk, number: 41 },
          { route: false },
        );
        return d;
      };
      const published = (d) => d.rows.outbox.length === 1 && d.rows.events.length === 1;
      const ignored = (d) =>
        d.status === 202 &&
        d.rows.delivery?.outcome === "ignored" &&
        d.rows.events.length === 0 &&
        d.rows.outbox.length === 0;
      for (const kind of ["push", "pull_request"]) {
        const control = await send(kind);
        if (!published(control) || control.rows.delivery?.outcome !== "accepted")
          problems.push(`control: an active repository did not publish ${kind}`);
      }
      const states = [
        [
          "disconnected",
          { status: "disconnected", disconnectedAt: new Date(), disconnectReason: "suite" },
        ],
        ["unavailable", { status: "unavailable" }],
        ["disabled", { enabled: false }],
      ];
      try {
        for (const [label, patch] of states) {
          await rtSetRepo(repoId, patch);
          for (const kind of ["push", "pull_request"]) {
            const d = await send(kind);
            if (!ignored(d)) problems.push(`${label}: ${kind} was published or not ignored`);
          }
          if (label === "unavailable") {
            const repoEvent = await deliver({
              event: "repository",
              payload: {
                action: "edited",
                repository: { id: Number(x.ext.wk), full_name: `org/repo${x.ext.wk}` },
                installation: { id: Number(x.R.inst) },
              },
            });
            const rows = await rowsFor(repoEvent.deliveryId);
            if (rows.outbox.length !== 1 || rows.outbox[0].type !== "scm.repository.changed")
              problems.push("a repository event for an unavailable repository was not published");
          }
          await rtSetRepo(repoId, rtActive);
        }
      } finally {
        await rtSetRepo(repoId, rtActive);
      }
      // a forged / stale message for an inactive repository still creates nothing (the consumer re-checks)
      const e = await send("push");
      await rtSetRepo(repoId, { status: "unavailable" });
      const consumed = await rtConsume(e.envelope);
      await rtSetRepo(repoId, rtActive);
      if (
        !consumed.ok ||
        (await db.execution.count({ where: { scmDeliveryId: e.deliveryId } })) !== 0
      )
        problems.push("the consumer created a request for an unavailable repository");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

{
  const add = group("Pipeline trigger router: quota and concurrency");
  add(
    "PIP-037",
    "quota exhaustion: an unattended trigger creates a blocked row (quota_exceeded, then entitlement_required) with no message and no unit consumed, one audit entry per pipeline, reason and day, and another tenant's events still run",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const db = suiteDb();
      const problems = [];
      const run = (branch, n) =>
        rtEvent("push", { inst: x.Q.inst, repo: x.ext.q, branch, after: rtSha(n) });
      const first = await run("main", "1");
      const ok = await rtExecs(x.q.id, { scmDeliveryId: first.deliveryId });
      if (ok.length !== 1 || ok[0].status !== "queued" || ok[0].quotaConsumed !== 1)
        problems.push("control: the first run inside the limit was not queued with one unit");
      const used = await rtUsed(x.Q.id);
      if (used !== 1) problems.push(`the quota use is ${used}, expected 1`);
      const a = await run("dev", "2");
      const b = await run("qa", "3");
      for (const [label, r] of [
        ["dev", a],
        ["qa", b],
      ]) {
        const rows = await rtExecs(x.q.id, { scmDeliveryId: r.deliveryId });
        if (
          rows.length !== 1 ||
          rows[0].status !== "blocked" ||
          rows[0].statusReason !== "quota_exceeded" ||
          rows[0].quotaConsumed !== 0
        )
          problems.push(`${label}: not a blocked quota_exceeded row`);
        if (rows[0] && (await rtMessages([rows[0].id])).length)
          problems.push(`${label}: a blocked request enqueued a message`);
      }
      if ((await rtUsed(x.Q.id)) !== used) problems.push("a blocked request consumed quota");
      let audits = (await rtAudits(x.q.id, x.Q.id)).filter((e) => e.action === "execution.blocked");
      if (audits.length !== 1 || audits[0].metadata?.reason !== "quota_exceeded")
        problems.push(`${audits.length} blocked audit entries for two blocks on one day`);
      // the redelivered message adds nothing
      await rtConsume(a.envelope);
      if ((await rtExecs(x.q.id, { scmDeliveryId: a.deliveryId })).length !== 1)
        problems.push("a redelivered blocked message created a second row");
      // entitlement removed: a different reason, audited once more
      const entitlement = await db.entitlementCatalog.findUnique({
        where: { key: "scans.monthly" },
      });
      await db.tenantEntitlement.create({
        data: {
          tenantId: x.Q.id,
          entitlementId: entitlement.id,
          enabled: false,
          limitValue: null,
          source: "security-suite",
        },
      });
      const c = await run("ops", "4");
      const rowsC = await rtExecs(x.q.id, { scmDeliveryId: c.deliveryId });
      if (
        rowsC.length !== 1 ||
        rowsC[0].status !== "blocked" ||
        rowsC[0].statusReason !== "entitlement_required"
      )
        problems.push("a disabled entitlement did not block with entitlement_required");
      audits = (await rtAudits(x.q.id, x.Q.id)).filter((e) => e.action === "execution.blocked");
      if (audits.length !== 2) problems.push(`${audits.length} blocked audit entries, expected 2`);
      if (audits.some((e) => /token|secret|password/i.test(JSON.stringify(e.metadata))))
        problems.push("secret-like content in a blocked audit entry");
      // another tenant is unaffected
      const other = await rtEvent("push", {
        inst: x.X.inst,
        repo: x.ext.common,
        after: rtSha("a"),
      });
      if ((await rtExecs(x.common.pb.id, { scmDeliveryId: other.deliveryId })).length !== 1)
        problems.push("another tenant's event was blocked by this tenant's quota");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-039",
    "concurrency policies on the same ref: supersede cancels the older queued request (reason superseded, unit released, audited), queue stops at maxQueued (queue_full), skip refuses while one is queued (concurrency_skip); an event that arrives late is recorded stale_event and never cancels the newer request; skipped requests consume no quota",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const problems = [];
      const push = (before, after) =>
        rtEvent("push", {
          inst: x.R.inst,
          repo: x.ext.conc,
          before: rtSha(before),
          after: rtSha(after),
        });
      const status = async (p) =>
        (await rtExecs(p.id)).map((e) => `${e.status}:${e.statusReason ?? ""}`);
      const used0 = await rtUsed(x.R.id);
      await push("0", "1");
      if ((await rtUsed(x.R.id)) !== used0 + 3)
        problems.push("three first requests did not use three units");
      await push("1", "2");
      const sup = await status(x.conc.supersede);
      if (JSON.stringify(sup) !== JSON.stringify(["cancelled:superseded", "queued:"]))
        problems.push(`supersede: ${sup}`);
      const que = await status(x.conc.queue);
      if (JSON.stringify(que) !== JSON.stringify(["queued:", "skipped:queue_full"]))
        problems.push(`queue: ${que}`);
      const skp = await status(x.conc.skip);
      if (JSON.stringify(skp) !== JSON.stringify(["queued:", "skipped:concurrency_skip"]))
        problems.push(`skip: ${skp}`);
      if ((await rtUsed(x.R.id)) !== used0 + 3)
        problems.push("supersede and skips changed the net quota use");
      const audits = (await rtAudits(x.conc.supersede.id, x.R.id)).map((e) => e.action).sort();
      if (JSON.stringify(audits) !== JSON.stringify(["execution.cancelled_superseded"]))
        problems.push(`supersede audit ${audits}`);
      const skipAudit = (await rtAudits(x.conc.skip.id, x.R.id)).map((e) => e.action);
      if (JSON.stringify(skipAudit) !== JSON.stringify(["execution.skipped"]))
        problems.push(`skip audit ${skipAudit}`);
      // a late event: its commit ("1") is the base of the newer request ("1" -> "2")
      await push("0", "1");
      const late = await rtExecs(x.conc.supersede.id);
      if (
        late.length !== 3 ||
        late[2].status !== "skipped" ||
        late[2].statusReason !== "stale_event"
      )
        problems.push("a late event was not recorded as stale_event");
      if (late[1].status !== "queued") problems.push("a stale event cancelled the newer request");
      if ((await rtUsed(x.R.id)) !== used0 + 3) problems.push("a stale event consumed quota");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  // ---- closed pull request housekeeping (owner decision 2026-11-13, SPEC §5.4, §5.9, §5.9b, §7.8): a closed event never
  //      creates a run; it cancels the still-queued runs of that pull request, per pipeline, and records cancelled_pr_closed
  const prOpen = (x, repo, number, opts = {}) =>
    rtEvent("pull_request", { inst: x.R.inst, repo: x.ext[repo], number, ...opts });
  const prClose = (x, repo, number, opts = {}) =>
    rtEvent(
      "pull_request",
      { inst: x.R.inst, repo: x.ext[repo], number, action: "closed", ...opts },
      { route: opts.route },
    );
  const prRows = async (pipelines) =>
    JSON.stringify(
      await Promise.all(
        pipelines.map(async (p) =>
          (await rtExecs(p.id)).map((e) => [e.id, e.status, e.statusReason, e.quotaConsumed]),
        ),
      ),
    );
  const prCloseDecisions = (pipelineId, where = {}) =>
    rtDecisions(pipelineId, { reason: "cancelled_pr_closed", ...where });
  const prCloseAudits = (tenantId, where = {}) =>
    suiteDb().auditLog.findMany({
      where: { tenantId, action: "execution.cancelled_pr_closed", ...where },
    });
  /** Opens PR `n` twice on the `prc` pipelines, then makes one run of each pipeline running / succeeded. */
  async function prSetup(x, n) {
    const db = suiteDb();
    await prOpen(x, "prc", n, { sha: rtSha("1") });
    const first = {
      a: (await rtExecs(x.pr.a.id, { pullRequestNumber: n }))[0],
      b: (await rtExecs(x.pr.b.id, { pullRequestNumber: n }))[0],
    };
    await driveExecution(db, first.a.id, "running");
    await driveExecution(db, first.b.id, "succeeded");
    await prOpen(x, "prc", n, { action: "synchronize", sha: rtSha("2") });
    await prOpen(x, "prc", n, { action: "synchronize", sha: rtSha("3") });
    return first;
  }
  add(
    "PIP-056",
    "a closed pull request (merged or not) cancels exactly the still-queued runs of that pull request in each pipeline of that repository (reason cancelled_pr_closed, quota unit given back once, audited, one decision row per pipeline keyed by the delivery) and never a running or finished run, another pull request, a push run, a pipeline without the pull request, a run superseded earlier, or a new run; the closed event creates no execution",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const problems = [];
      const mine = [x.pr.a, x.pr.b, x.pr.c];
      await prSetup(x, 51);
      await prOpen(x, "prc", 52);
      await rtEvent("push", { inst: x.R.inst, repo: x.ext.prc, after: rtSha("4") });
      const before = await Promise.all(mine.map((p) => rtExecs(p.id)));
      const queued51 = (list) =>
        list.filter((e) => e.pullRequestNumber === 51 && e.status === "queued");
      const expectCancelled = [...queued51(before[0]), ...queued51(before[1])];
      if (queued51(before[0]).length !== 1 || queued51(before[1]).length !== 2)
        problems.push("fixture: expected 1 + 2 queued runs of PR 51");
      const superseded = before[0].filter((e) => e.statusReason === "superseded");
      if (superseded.length !== 1)
        problems.push("fixture: the supersede pipeline did not supersede");
      const used0 = await rtUsed(x.R.id);
      const auditsBefore = (await prCloseAudits(x.R.id)).length;
      const closed = await prClose(x, "prc", 51);
      if (!closed.consumed?.ok) problems.push(`not routed: ${closed.consumed?.reason}`);
      const after = await Promise.all(mine.map((p) => rtExecs(p.id)));
      if (after.map((l) => l.length).join() !== before.map((l) => l.length).join())
        problems.push("the closed event created or removed execution rows");
      const byId = new Map(after.flat().map((e) => [e.id, e]));
      for (const e of expectCancelled) {
        const now = byId.get(e.id);
        if (now?.status !== "cancelled" || now.statusReason !== "cancelled_pr_closed")
          problems.push(`queued run ${e.id} of PR 51 was not cancelled with cancelled_pr_closed`);
      }
      for (const e of before.flat()) {
        if (expectCancelled.some((c) => c.id === e.id)) continue;
        const now = byId.get(e.id);
        if (now.status !== e.status || now.statusReason !== e.statusReason)
          problems.push(
            `${e.status} run of ${e.pullRequestNumber ?? e.triggerType} changed to ${now.status} (it must not)`,
          );
      }
      if (!after[0].some((e) => e.status === "running")) problems.push("the running run vanished");
      if (!after[1].some((e) => e.status === "succeeded"))
        problems.push("the finished run vanished");
      if (!after.flat().some((e) => e.pullRequestNumber === 52 && e.status === "queued"))
        problems.push("control: PR 52 lost its queued run");
      if (!after.flat().some((e) => e.triggerType === "push" && e.status === "queued"))
        problems.push("control: the push run was cancelled");
      if ((await rtUsed(x.R.id)) !== used0 - expectCancelled.length)
        problems.push(`the quota was not given back exactly once per cancelled run`);
      for (const e of expectCancelled) if (e.quotaConsumed !== 1) problems.push("fixture: quota");
      const decA = await prCloseDecisions(x.pr.a.id, { scmDeliveryId: closed.deliveryId });
      const decB = await prCloseDecisions(x.pr.b.id, { scmDeliveryId: closed.deliveryId });
      for (const d of [...decA, ...decB])
        if (
          d.sourceType !== "scm_event" ||
          d.triggerType !== "pull_request" ||
          d.triggerKey !== "pr" ||
          d.pullRequestNumber !== 51 ||
          d.refName !== "pull/51" ||
          d.decision !== "skipped_by_policy" ||
          d.tenantId !== x.R.id
        )
          problems.push("a cancelled_pr_closed decision row has the wrong shape");
      if (decA.length !== 1 || decB.length !== 1)
        problems.push(`decision rows: ${decA.length} and ${decB.length}, expected one each`);
      if ((await prCloseDecisions(x.pr.c.id)).length)
        problems.push("a pipeline without a PR run got a decision row");
      const audits = await prCloseAudits(x.R.id);
      if (audits.length - auditsBefore !== expectCancelled.length)
        problems.push("one audit entry per cancelled run was not written");
      // a merged pull request cancels too, and a closed event for a number nobody queued writes nothing
      await prOpen(x, "prc", 53);
      const q53 = (await rtExecs(x.pr.a.id, { pullRequestNumber: 53, status: "queued" })).length;
      const merged = await prClose(x, "prc", 53, { merged: true });
      const left = await rtExecs(x.pr.a.id, { pullRequestNumber: 53, status: "queued" });
      if (q53 !== 1 || !merged.consumed?.ok || left.length)
        problems.push("a merged pull request did not cancel its queued run");
      const nothing = await prClose(x, "prc", 9999);
      if (
        !nothing.consumed?.ok ||
        (await rtDecisions(x.pr.a.id, { scmDeliveryId: nothing.deliveryId })).length
      )
        problems.push("a closed event with nothing queued wrote a decision row");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-057",
    "closed pull request housekeeping is idempotent: handing the same closed message to the router again, or twice at the same time, changes nothing (no second decision row, audit entry, quota release or status change), and a run requested after the close for the same number is a new run that the old closed event does not cancel on replay",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const problems = [];
      const mine = [x.pr.a, x.pr.b];
      await prSetup(x, 61);
      const closed = await prClose(x, "prc", 61);
      if (!closed.consumed?.ok) problems.push(`not routed: ${closed.consumed?.reason}`);
      const snap = async () =>
        JSON.stringify([
          await prRows(mine),
          await rtUsed(x.R.id),
          (await prCloseDecisions(x.pr.a.id, { pullRequestNumber: 61 })).length,
          (await prCloseDecisions(x.pr.b.id, { pullRequestNumber: 61 })).length,
          (await prCloseAudits(x.R.id)).length,
        ]);
      const once = await snap();
      for (let i = 0; i < 2; i += 1) {
        const again = await rtConsume(closed.envelope);
        if (!again.ok) problems.push(`replay ${i} was refused: ${again.reason}`);
      }
      const race = await Promise.all([rtConsume(closed.envelope), rtConsume(closed.envelope)]);
      if (race.some((r) => !r.ok)) problems.push("a concurrent replay failed");
      if ((await snap()) !== once) problems.push("a replay of the closed message changed state");
      // control: the first handling really did the work
      if (JSON.parse(once)[2] !== 1 || JSON.parse(once)[3] !== 1)
        problems.push("control: the first handling wrote no decision rows");
      // a later run of the same pull request (reopened) is new work, the replay must not cancel it
      await prOpen(x, "prc", 61, { action: "reopened", sha: rtSha("5") });
      const reopened = (await rtExecs(x.pr.a.id, { pullRequestNumber: 61, status: "queued" }))
        .length;
      await rtConsume(closed.envelope);
      const still = (await rtExecs(x.pr.a.id, { pullRequestNumber: 61, status: "queued" })).length;
      if (reopened !== 1 || still !== 1)
        problems.push("a replay of an old closed event cancelled a run requested after it");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-058",
    "closed pull request housekeeping never crosses tenants, workspaces or repositories: the same pull request number queued on another repository of the same workspace, on a repository of another workspace and on the same GitHub repository id of another tenant is untouched (runs, quota, decision rows, audit) by a closed event, in both directions, and a message that names another tenant's repository is refused",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const db = suiteDb();
      const problems = [];
      const n = 71;
      await prOpen(x, "prc", n);
      await prOpen(x, "prd", n);
      await prOpen(x, "prw", n);
      const opened = await rtEvent("pull_request", { inst: x.X.inst, repo: x.ext.prc, number: n });
      const foreign = [x.pr.d, x.pr.w, x.pr.x];
      const queuedOf = async (p) =>
        (await rtExecs(p.id, { pullRequestNumber: n, status: "queued" })).length;
      for (const p of [x.pr.a, x.pr.d, x.pr.w, x.pr.x])
        if ((await queuedOf(p)) !== 1) problems.push("fixture: a queued run of the PR is missing");
      const foreignBefore = await prRows(foreign);
      const usedX = await rtUsed(x.X.id);
      const auditX = (await prCloseAudits(x.X.id)).length;
      // R closes PR n of prc
      const usedR = await rtUsed(x.R.id);
      const r1 = await prClose(x, "prc", n);
      if (!r1.consumed?.ok) problems.push(`not routed: ${r1.consumed?.reason}`);
      if ((await queuedOf(x.pr.a)) !== 0 || (await queuedOf(x.pr.b)) !== 0)
        problems.push("control: the repository's own queued runs were not cancelled");
      if ((await rtUsed(x.R.id)) >= usedR) problems.push("control: R's quota was not released");
      if ((await prRows(foreign)) !== foreignBefore)
        problems.push("a closed event touched a run of another repository, workspace or tenant");
      if ((await rtUsed(x.X.id)) !== usedX) problems.push("another tenant's quota changed");
      if ((await prCloseAudits(x.X.id)).length !== auditX)
        problems.push("an audit entry appeared for another tenant");
      for (const p of foreign)
        if ((await prCloseDecisions(p.id)).length)
          problems.push("a decision row appeared on a foreign pipeline");
      // the other direction: tenant X closes the same number on the same GitHub repository id
      await prOpen(x, "prc", n, { action: "reopened", sha: rtSha("6") });
      const rBefore = await prRows([x.pr.a, x.pr.b, x.pr.d, x.pr.w]);
      const closedX = await rtEvent("pull_request", {
        inst: x.X.inst,
        repo: x.ext.prc,
        number: n,
        action: "closed",
      });
      if (!closedX.consumed?.ok)
        problems.push(`X's close was not routed: ${closedX.consumed?.reason}`);
      if ((await queuedOf(x.pr.x)) !== 0) problems.push("control: X's own run was not cancelled");
      if ((await prRows([x.pr.a, x.pr.b, x.pr.d, x.pr.w])) !== rBefore)
        problems.push("X's closed event touched tenant R's runs");
      if (opened.deliveryId === closedX.deliveryId) problems.push("fixture: same delivery");
      // forged messages: a repository of another tenant, and a tenant id that does not own the repository
      const forgedRepo = structuredClone(r1.envelope);
      forgedRepo.payload.repositoryId = x.repoX;
      const forgedTenant = structuredClone(r1.envelope);
      forgedTenant.tenantId = x.X.id;
      for (const [label, envelope] of [
        ["another tenant's repository", forgedRepo],
        ["another tenant's id", forgedTenant],
      ]) {
        const refused = await rtConsume(envelope);
        if (refused.ok) problems.push(`a message with ${label} was accepted`);
      }
      if ((await prRows([x.pr.a, x.pr.b, x.pr.d, x.pr.w])) !== rBefore)
        problems.push("a forged message changed tenant R's runs");
      if (
        (await db.pipelineTriggerDecision.count({
          where: {
            reason: "cancelled_pr_closed",
            scmDeliveryId: closedX.deliveryId,
            tenantId: x.R.id,
          },
        })) !== 0
      )
        problems.push("X's delivery left a decision row in tenant R");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-059",
    "closed pull request housekeeping respects the lifecycle gates: a suspended tenant is refused (nothing cancelled, no row), a disabled pipeline's queued run of the closed pull request is still cancelled, the closed event itself never consumes quota or creates a run, and the legitimate path works once the tenant is active again",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const db = suiteDb();
      const problems = [];
      const n = 81;
      await prOpen(x, "prc", n);
      const closed = await prClose(x, "prc", n, { route: false });
      const queued = () => rtExecs(x.pr.a.id, { pullRequestNumber: n, status: "queued" });
      if ((await queued()).length !== 1) problems.push("fixture: no queued run");
      const used0 = await rtUsed(x.R.id);
      try {
        await db.tenant.update({ where: { id: x.R.id }, data: { status: "suspended" } });
        const refused = await rtConsume(closed.envelope);
        if (refused.ok || refused.reason !== "tenant-not-usable")
          problems.push(`suspended: the consumer answered ${refused.reason ?? "accepted"}`);
        if ((await queued()).length !== 1) problems.push("suspended: the run was cancelled");
        if ((await prCloseDecisions(x.pr.a.id, { scmDeliveryId: closed.deliveryId })).length)
          problems.push("suspended: a decision row was written");
      } finally {
        await db.tenant.update({ where: { id: x.R.id }, data: { status: "active" } });
      }
      if ((await rtUsed(x.R.id)) !== used0) problems.push("suspended: quota changed");
      await db.pipeline.update({ where: { id: x.pr.a.id }, data: { enabled: false } });
      try {
        const ok = await rtConsume(closed.envelope);
        if (!ok.ok) problems.push(`control: the active tenant was refused (${ok.reason})`);
        if ((await queued()).length !== 0)
          problems.push("a disabled pipeline kept the run of a closed pull request queued");
        if ((await rtUsed(x.R.id)) !== used0 - 2)
          problems.push("the quota units of the two cancelled runs were not given back once each");
        const created = await rtExecs(x.pr.a.id, { scmDeliveryId: closed.deliveryId });
        if (created.length) problems.push("the closed event created an execution");
      } finally {
        await db.pipeline.update({ where: { id: x.pr.a.id }, data: { enabled: true } });
      }
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 15. Pipeline schedules (SPEC pipelines-triggers §5.6, §6.4, §14.1, part E). The scheduler's due-schedule handler runs IN
//     PROCESS against the disposable database with a FIXED clock (instants in 2026, all before the real date, so the planned
//     times the API computes from the real clock are never due and no other fixture is touched). Pipelines and schedules are
//     created through the public API; the due state is set directly in the database. Tenants: S (all scenarios, two
//     workspaces), X (the same GitHub repository id and the same cron) and Q (one scan per month).
// ---------------------------------------------------------------------------------------------------------------------
const SCH_SLOT = "2026-06-10T12:00:00.000Z";
const SCH_SLOT2 = "2026-06-10T13:00:00.000Z";
const SCH_HOUR = 3600000;
const SCH_JITTER_WINDOW = 300;
/** The jitter of one slot of a trigger in milliseconds: `hash(triggerId + slot) mod window` (the function the API and the handler use). */
const schJit = (trigger, slotIso) =>
  jitterOffsetSeconds(trigger.id, new Date(slotIso), SCH_JITTER_WINDOW) * 1000;
const schHourly = (over = {}) => ({
  key: "nightly",
  type: "schedule",
  cron: "0 * * * *",
  timezone: "UTC",
  ...over,
});
const schCfg = (trigger = {}, extra = {}) =>
  pipCfg({
    triggers: [
      { key: "push", type: "push" },
      schHourly(trigger),
      { key: "manual", type: "manual" },
    ],
    ...extra,
  });
const schTrigger = (pipelineId) =>
  suiteDb().pipelineTrigger.findFirst({ where: { pipelineId, type: "schedule" } });
/** Makes the schedule of a pipeline due at `slotIso` (planned time = slot + the jitter of that slot) and returns the trigger row. */
async function schSetDue(pipelineId, slotIso, extra = {}) {
  const t = await schTrigger(pipelineId);
  const nextFireAt = new Date(new Date(slotIso).getTime() + schJit(t, slotIso));
  await suiteDb().pipelineTrigger.update({
    where: { id: t.id },
    data: { nextFireAt, enabled: true, ...extra },
  });
  return { ...t, nextFireAt };
}
/** The clock of a run: five seconds after the planned fire time of the trigger. */
const schAfter =
  (trigger, seconds = 5) =>
  () =>
    new Date(trigger.nextFireAt.getTime() + seconds * 1000);
const schAt = (iso) => () => new Date(iso);
const schJob = () =>
  parseMessage(
    createJobEnvelope({
      messageId: `pipeline-schedules-due-suite-${randomBytes(4).toString("hex")}`,
      type: "pipeline.schedules.due_requested",
      schemaVersion: 1,
      initiator: { type: "system", id: "scheduler" },
      payload: { bucket: 1 },
    }),
  );
/** One handler run of the scheduler worker; resolves with the outcome counters. */
const schRun = (clock, { db = suiteDb(), limits = {} } = {}) =>
  createScheduleHandler({
    db,
    config: { pipelines: { schedule: limits } },
    logger: quietLog,
    clock,
  })(schJob(), { log: quietLog });
const schExecs = (pipelineId, where = {}) =>
  suiteDb().execution.findMany({
    where: { pipelineId, triggerType: "schedule", ...where },
    orderBy: [{ scheduleSlot: "asc" }, { requestedAt: "asc" }],
  });
const schSlots = async (pipelineId) =>
  (await schExecs(pipelineId)).map((e) => e.scheduleSlot.toISOString());
const schMsgCount = (tenantId) =>
  suiteDb().outboxMessage.count({ where: { tenantId, type: "pipeline.execution.requested" } });
const schUsed = async (tenantId, period) => {
  const def = await suiteDb().quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
  const row = await suiteDb().tenantQuotaUsage.findFirst({
    where: { tenantId, quotaDefinitionId: def.id, periodKey: period },
  });
  return Number(row?.used ?? 0);
};
/** A database whose transactions fail when the handler tries to advance a trigger: the crash between the request and the advance. */
const schCrashOnAdvance = (db) =>
  new Proxy(db, {
    get(target, prop) {
      const value = target[prop];
      if (prop === "$transaction")
        return (fn, options) =>
          target.$transaction(
            (tx) =>
              fn(
                new Proxy(tx, {
                  get(t, p) {
                    if (p === "pipelineTrigger")
                      return new Proxy(t.pipelineTrigger, {
                        get(model, q) {
                          if (q === "updateMany")
                            return () => {
                              throw new Error("simulated crash before the commit");
                            };
                          const v = model[q];
                          return typeof v === "function" ? v.bind(model) : v;
                        },
                      });
                    const v = t[p];
                    return typeof v === "function" ? v.bind(t) : v;
                  },
                }),
              ),
            options,
          );
      return typeof value === "function" ? value.bind(target) : value;
    },
  });

/** Parks every schedule of the fixture tenants, so a run of the handler only meets the schedules a check sets due itself. */
const schQuiet = (x) =>
  suiteDb().pipelineTrigger.updateMany({
    where: { tenantId: { in: [x.S.id, x.X.id, x.Q.id] }, type: "schedule" },
    data: { enabled: false, nextFireAt: null },
  });

const schWorld = () =>
  once("sch-world", async () => {
    const db = suiteDb();
    const base = 7700000 + (Date.now() % 100000) * 20;
    const ext = { m: base + 1, common: base + 2, o: base + 3, q: base + 4 };
    const mk = async (cookie, repositoryId, label, config, enabled = true) => {
      const r = await pipCreate(cookie, repositoryId, { name: pipName(label), enabled, config });
      assert.equal(
        r.status,
        201,
        `fixture: pipeline ${label} answered ${r.status} ${JSON.stringify(r.json?.error)}`,
      );
      return r.json.data;
    };
    const connectAll = async (cookie, workspaceId, flow, ids) => {
      const wl = flow.link.json.data.id;
      await putAllowList(cookie, workspaceId, wl, ids);
      const out = {};
      for (const id of ids) {
        const res = await connectRepo(cookie, workspaceId, wl, id);
        assert.equal(res.status, 201, `fixture: connect ${id} answered ${res.status}`);
        out[id] = res.json.data.id;
      }
      return out;
    };
    const workspace = async (cookie, name) => {
      const r = await w.api("POST", "/workspaces", {
        cookie,
        body: { name: `${name} ${w.suffix}` },
      });
      assert.equal(r.status, 201, `fixture: workspace answered ${r.status}`);
      return r.json.data.id;
    };
    const S = await w.provisionTenant("scs");
    const ws1 = await workspace(S.owner, "Schedules one");
    const ws2 = await workspace(S.owner, "Schedules two");
    const account = orgAccount("sc");
    const user = ghUser();
    const flow1 = await linkFlow(S.owner, {
      workspaceId: ws1,
      account,
      user,
      orgRole: "admin",
      repos: [ext.m, ext.common, ext.o].map(stubRepo),
    });
    assert.equal(flow1.link?.status, 201, "fixture: link S workspace 1");
    const flow2 = await linkFlow(S.owner, {
      workspaceId: ws2,
      installationId: flow1.installationId,
      account,
      user,
      orgRole: "admin",
    });
    assert.equal(flow2.link?.status, 201, "fixture: link S workspace 2");
    const repoIds = await connectAll(S.owner, ws1, flow1, [ext.m, ext.common]);
    Object.assign(repoIds, await connectAll(S.owner, ws2, flow2, [ext.o]));

    // tenant X connects the SAME GitHub repository id (`common`) through its own installation
    const X = await w.provisionTenant("scx");
    const wsX = await workspace(X.owner, "Schedules X");
    const flowX = await linkFlow(X.owner, {
      workspaceId: wsX,
      account: orgAccount("scx"),
      user: ghUser(),
      orgRole: "admin",
      repos: [stubRepo(ext.common)],
    });
    assert.equal(flowX.link?.status, 201, "fixture: link X");
    const repoX = (await connectAll(X.owner, wsX, flowX, [ext.common]))[ext.common];

    // tenant Q: one scan per month
    const Q = await w.provisionTenant("scq");
    const wsQ = await workspace(Q.owner, "Schedules Q");
    const flowQ = await linkFlow(Q.owner, {
      workspaceId: wsQ,
      account: orgAccount("scq"),
      user: ghUser(),
      orgRole: "admin",
      repos: [stubRepo(ext.q)],
    });
    assert.equal(flowQ.link?.status, 201, "fixture: link Q");
    const repoQ = (await connectAll(Q.owner, wsQ, flowQ, [ext.q]))[ext.q];
    const quota = await db.quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
    await db.tenantQuota.create({
      data: { tenantId: Q.id, quotaDefinitionId: quota.id, limitValue: 1n },
    });

    const own = S.owner;
    const repoM = repoIds[ext.m];
    const p = {};
    for (const name of ["pv", "pDis", "pDel", "pRem", "pEx", "pRef", "pExplicit", "mRun", "mSkip"])
      p[name] = await mk(
        own,
        repoM,
        name,
        schCfg(name === "mSkip" ? { missedPolicy: "skip" } : {}),
      );
    p.pExplicit = await mk(
      own,
      repoM,
      "explicit",
      schCfg({ ref: "release/1", scanKind: "incremental" }),
    );
    p.mDaily = await mk(own, repoM, "daily", schCfg({ cron: "0 2 * * *" }));
    // daylight-saving fixtures: the first four rows of the evaluation table, one pipeline each
    p.dst = [];
    for (const row of NEXT_FIRES.slice(0, 4))
      p.dst.push(
        await mk(
          own,
          repoM,
          `dst-${row.timeZone.split("/")[0]}`,
          schCfg({ cron: row.expression, timezone: row.timeZone }),
        ),
      );
    // fall-back days through the handler (wildcard-hour expressions, both overlap occurrences; step and named hours once) and the jitter check
    p.wild = [];
    for (const row of DAY_FIRES.slice(0, 2))
      p.wild.push(
        await mk(
          own,
          repoIds[ext.o],
          `wild-${row.timeZone.split("/")[0]}`,
          schCfg({ cron: row.expression, timezone: row.timeZone }),
        ),
      );
    p.jit = await mk(own, repoIds[ext.o], "jitter", schCfg());
    p.common = await mk(own, repoIds[ext.common], "common-s", schCfg());
    p.common2 = await mk(own, repoIds[ext.common], "common-s2", schCfg());
    p.other = await mk(own, repoIds[ext.o], "workspace-two", schCfg());
    p.xCommon = await mk(X.owner, repoX, "common-x", schCfg());
    p.q = await mk(
      Q.owner,
      repoQ,
      "quota",
      schCfg({}, { execution: { concurrency: { policy: "queue", maxQueued: 10 } } }),
    );
    return { ext, S, X, Q, ws1, ws2, wsX, repoM, repoIds, repoX, repoQ, p };
  });

{
  const add = group(
    "Pipeline schedules: fire-time re-validation, exactly once, quota and isolation",
  );
  add(
    "PIP-012",
    "a due schedule re-validates at fire time: a repository that became disconnected, unavailable or disabled, an archived workspace, a suspended tenant, a disabled or deleted pipeline and a trigger removed or disabled by a later configuration version create no execution and no message; the schedule advances to the next slot (or is parked when its pipeline or trigger is gone); the legitimate path fires once restored",
    { status: 200 },
    async () => {
      const x = await schWorld();
      const p = x.p;
      await schQuiet(x);
      const db = suiteDb();
      const problems = [];
      const variants = [
        {
          label: "repository disconnected",
          pipeline: p.pv,
          apply: () =>
            rtSetRepo(x.repoM, {
              status: "disconnected",
              disconnectedAt: new Date(),
              disconnectReason: "suite",
            }),
          restore: () => rtSetRepo(x.repoM, rtActive),
          expect: "advanced",
        },
        {
          label: "repository unavailable",
          pipeline: p.pv,
          apply: () => rtSetRepo(x.repoM, { status: "unavailable" }),
          restore: () => rtSetRepo(x.repoM, rtActive),
          expect: "advanced",
        },
        {
          label: "repository disabled",
          pipeline: p.pv,
          apply: () => rtSetRepo(x.repoM, { enabled: false }),
          restore: () => rtSetRepo(x.repoM, rtActive),
          expect: "advanced",
        },
        {
          label: "workspace archived",
          pipeline: p.pv,
          apply: () => db.workspace.update({ where: { id: x.ws1 }, data: { status: "archived" } }),
          restore: () => db.workspace.update({ where: { id: x.ws1 }, data: { status: "active" } }),
          expect: "advanced",
        },
        {
          label: "tenant suspended",
          pipeline: p.pv,
          apply: () => db.tenant.update({ where: { id: x.S.id }, data: { status: "suspended" } }),
          restore: () => db.tenant.update({ where: { id: x.S.id }, data: { status: "active" } }),
          expect: "advanced",
        },
        {
          label: "pipeline disabled",
          pipeline: p.pDis,
          apply: () => db.pipeline.update({ where: { id: p.pDis.id }, data: { enabled: false } }),
          restore: () => db.pipeline.update({ where: { id: p.pDis.id }, data: { enabled: true } }),
          expect: "advanced",
        },
        {
          label: "pipeline deleted",
          pipeline: p.pDel,
          apply: () =>
            db.pipeline.update({ where: { id: p.pDel.id }, data: { deletedAt: new Date() } }),
          restore: () =>
            db.pipeline.update({ where: { id: p.pDel.id }, data: { deletedAt: null } }),
          expect: "parked",
        },
      ];
      for (const v of variants) {
        await v.apply();
        try {
          const before = [(await schExecs(v.pipeline.id)).length, await schMsgCount(x.S.id)];
          const trigger = await schSetDue(v.pipeline.id, SCH_SLOT);
          const counts = await schRun(schAfter(trigger));
          const after = [(await schExecs(v.pipeline.id)).length, await schMsgCount(x.S.id)];
          if (JSON.stringify(before) !== JSON.stringify(after))
            problems.push(`${v.label}: an execution or a message was created`);
          const row = await schTrigger(v.pipeline.id);
          const wanted =
            v.expect === "parked"
              ? null
              : new Date(new Date(SCH_SLOT).getTime() + SCH_HOUR + schJit(row, SCH_SLOT2));
          if ((row.nextFireAt?.getTime() ?? null) !== (wanted?.getTime() ?? null))
            problems.push(
              `${v.label}: next_fire_at is ${row.nextFireAt?.toISOString() ?? "null"}, expected ${wanted?.toISOString() ?? "null"}`,
            );
          if (!counts[v.expect === "parked" ? "parked" : "skipped_ineligible"])
            problems.push(`${v.label}: outcomes ${JSON.stringify(counts)}`);
        } finally {
          await v.restore();
        }
      }
      // a trigger removed, then one disabled, by later configuration versions: the stale projection row is re-created due
      let version = 1;
      for (const [label, trigger] of [
        ["removed", null],
        ["disabled", schHourly({ enabled: false })],
      ]) {
        const cfg = pipCfg({
          triggers: [
            { key: "push", type: "push" },
            ...(trigger ? [trigger] : []),
            { key: "manual", type: "manual" },
          ],
        });
        const publish = await pipPublish(x.S.owner, p.pRem.id, version, cfg);
        if (publish.status !== 200) {
          problems.push(`${label}: the later version was refused (${publish.status})`);
          continue;
        }
        version += 1;
        const live = await db.pipeline.findFirst({ where: { id: p.pRem.id } });
        await db.pipelineTrigger.deleteMany({ where: { pipelineId: p.pRem.id, type: "schedule" } });
        await db.pipelineTrigger.create({
          data: {
            tenantId: x.S.id,
            workspaceId: x.ws1,
            repositoryId: x.repoM,
            pipelineId: p.pRem.id,
            triggerKey: "nightly",
            type: "schedule",
            versionId: live.currentVersionId,
            cron: "0 * * * *",
            timezone: "UTC",
            missedPolicy: "run_once",
            jitterOffsetSeconds: 0,
            nextFireAt: new Date(SCH_SLOT),
          },
        });
        const t = await schTrigger(p.pRem.id);
        await schRun(schAfter({ nextFireAt: t.nextFireAt }));
        const row = await schTrigger(p.pRem.id);
        if ((await schExecs(p.pRem.id)).length)
          problems.push(`${label} by a later version: an execution was created`);
        if (row.nextFireAt !== null || row.enabled !== false)
          problems.push(`${label} by a later version: the schedule was not parked`);
      }
      // control: with everything restored the same schedule fires once
      const trigger = await schSetDue(p.pv.id, SCH_SLOT);
      const counts = await schRun(schAfter(trigger));
      const rows = await schExecs(p.pv.id);
      if (rows.length !== 1 || rows[0].status !== "queued" || counts.created !== 1)
        problems.push(
          `control: the restored schedule did not fire once (${JSON.stringify(counts)})`,
        );
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-013",
    "a schedule fires exactly once per slot: two handlers racing on the same due trigger, the same slot handled again (the state after a crash that kept the request but not the advance) and a crash before the commit (request and advance are one transaction) each leave one execution and one message for the slot",
    { status: 200 },
    async () => {
      const x = await schWorld();
      await schQuiet(x);
      const problems = [];
      const p = x.p.pEx;
      const t1 = await schSetDue(p.id, SCH_SLOT);
      const clock = schAfter(t1);
      const [a, b] = await Promise.all([schRun(clock), schRun(clock)]);
      const created = (a.created ?? 0) + (b.created ?? 0);
      if (created !== 1) problems.push(`two racing handlers created ${created} executions`);
      if ((await schSlots(p.id)).join() !== SCH_SLOT)
        problems.push(`slots after the race: ${(await schSlots(p.id)).join()}`);
      const first = await schExecs(p.id);
      const executionIds = first.map((e) => e.id);
      const messageCount = async () =>
        (await rtMessages((await schExecs(p.id)).map((e) => e.id))).length;
      if ((await messageCount()) !== 1) problems.push("the race did not leave exactly one message");
      const advanced = (await schTrigger(p.id)).nextFireAt.getTime();
      if (advanced !== new Date(SCH_SLOT2).getTime() + schJit(t1, SCH_SLOT2))
        problems.push("the trigger was not advanced to the next slot");
      // the same slot again: the request exists, the advance is missing
      await schSetDue(p.id, SCH_SLOT);
      const again = await schRun(clock);
      if ((await schExecs(p.id)).length !== 1 || again.duplicate !== 1)
        problems.push(`the same slot created a second execution (${JSON.stringify(again)})`);
      if ((await schTrigger(p.id)).nextFireAt.getTime() !== advanced)
        problems.push("the duplicate slot was not advanced");
      // a crash before the commit: nothing of the second slot survives, the trigger stays due, the retry fires it once
      const t2 = await schSetDue(p.id, SCH_SLOT2);
      const used = await schUsed(x.S.id, "2026-06");
      const crashed = await schRun(schAfter(t2), { db: schCrashOnAdvance(suiteDb()) });
      if (!crashed.failed) problems.push("the simulated crash was not seen");
      if (
        (await schExecs(p.id)).length !== 1 ||
        (await rtMessages(executionIds)).length !== 1 ||
        (await schUsed(x.S.id, "2026-06")) !== used
      )
        problems.push("a crashed run left an execution, a message or a quota unit behind");
      if ((await schTrigger(p.id)).nextFireAt.getTime() !== t2.nextFireAt.getTime())
        problems.push("a crashed run advanced the trigger");
      const retried = await schRun(schAfter(t2));
      if ((await schExecs(p.id)).length !== 2 || retried.created !== 1)
        problems.push("the retry after the crash did not create exactly the second slot");
      const slots = await schSlots(p.id);
      if (slots.join() !== [SCH_SLOT, SCH_SLOT2].join())
        problems.push(`slots after the retry: ${slots.join()}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-040",
    "quota exhaustion at fire time: the first slot of a tenant with one scan per month runs, later slots create blocked rows (quota_exceeded) with no message and no unit consumed and ONE audit entry per pipeline, reason and day; another tenant's schedule is unaffected",
    { status: 200 },
    async () => {
      const x = await schWorld();
      const p = x.p;
      await schQuiet(x);
      const problems = [];
      const q = x.p.q;
      const slots = [
        "2026-07-10T12:00:00.000Z",
        "2026-07-10T13:00:00.000Z",
        "2026-07-10T14:00:00.000Z",
      ];
      const period = "2026-07";
      for (const slot of slots) {
        const t = await schSetDue(q.id, slot);
        await schRun(schAfter(t));
      }
      const rows = await schExecs(q.id);
      const statuses = rows.map((r) => `${r.status}:${r.statusReason ?? ""}`).join();
      if (statuses !== "queued:,blocked:quota_exceeded,blocked:quota_exceeded")
        problems.push(`statuses ${statuses}`);
      if ((await rtMessages(rows.map((r) => r.id))).length !== 1)
        problems.push("a blocked slot left a message");
      if ((await schUsed(x.Q.id, period)) !== 1) problems.push("a blocked slot consumed quota");
      if (rows.some((r) => r.status === "blocked" && r.quotaConsumed !== 0))
        problems.push("a blocked row records consumed quota");
      const audits = await rtAudits(q.id, x.Q.id);
      if (audits.filter((a) => a.action === "execution.blocked").length !== 1)
        problems.push(`${audits.length} audit entries for two blocked slots in one day`);
      const entry = audits.find((a) => a.action === "execution.blocked");
      if (entry?.metadata?.triggerType !== "schedule")
        problems.push("the audit entry does not name the schedule trigger");
      // another tenant is not affected by this tenant's quota
      const other = await schSetDue(x.p.xCommon.id, "2026-07-10T12:00:00.000Z");
      await schRun(schAfter(other));
      if ((await schExecs(x.p.xCommon.id)).length !== 1)
        problems.push("another tenant's schedule was blocked by this tenant's quota");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-041",
    "a due schedule never creates executions in another tenant or workspace: two tenants with the same GitHub repository id and the same cron, and a second workspace of the same tenant, each get their own execution only, with their own tenant, workspace and repository ids on the row and the message; the per-tenant share of a tick is honored",
    { status: 200 },
    async () => {
      const x = await schWorld();
      const p = x.p;
      await schQuiet(x);
      const db = suiteDb();
      const problems = [];
      const slot = "2026-08-10T12:00:00.000Z";
      // only tenant S's pipeline is due: tenant X's pipeline (same repository id, same cron) gets nothing
      const tS = await schSetDue(x.p.common.id, slot);
      await schRun(schAfter(tS));
      if ((await schExecs(x.p.common.id)).length !== 1)
        problems.push("the due pipeline did not run");
      if ((await schExecs(x.p.xCommon.id, { scheduleSlot: new Date(slot) })).length)
        problems.push("a due schedule of tenant S created an execution for tenant X");
      // all four due at once: each runs in its own tenant, workspace and repository
      const due = [x.p.common, x.p.common2, x.p.other, x.p.xCommon];
      const slot13 = new Date("2026-08-10T13:00:00.000Z");
      const triggers = [];
      for (const pipeline of due) triggers.push(await schSetDue(pipeline.id, slot13.toISOString()));
      await schRun(schAfter(triggers[0], 600));
      const own = [
        [x.p.common, x.S.id, x.ws1, x.repoIds[x.ext.common]],
        [x.p.common2, x.S.id, x.ws1, x.repoIds[x.ext.common]],
        [x.p.other, x.S.id, x.ws2, x.repoIds[x.ext.o]],
        [x.p.xCommon, x.X.id, x.wsX, x.repoX],
      ];
      for (const [pipeline, tenantId, workspaceId, repositoryId] of own) {
        const rows = await schExecs(pipeline.id, { scheduleSlot: slot13 });
        if (rows.length !== 1) {
          problems.push(`${pipeline.name} got ${rows.length} executions`);
          continue;
        }
        const [row] = rows;
        if (
          row.tenantId !== tenantId ||
          row.workspaceId !== workspaceId ||
          row.repositoryId !== repositoryId
        )
          problems.push(
            `${pipeline.name}: the execution carries another tenant, workspace or repository`,
          );
        const messages = await rtMessages([row.id]);
        if (
          messages.length !== 1 ||
          messages[0].tenantId !== tenantId ||
          messages[0].payload.tenantId !== tenantId
        )
          problems.push(`${pipeline.name}: the message does not carry its own tenant`);
      }
      const stray = await db.execution.count({
        where: {
          triggerType: "schedule",
          scheduleSlot: slot13,
          pipelineId: { notIn: due.map((d) => d.id) },
        },
      });
      if (stray) problems.push(`${stray} stray scheduled executions`);
      // fairness: with a share of one execution per tenant and tick, tenant S needs three ticks for its three due pipelines
      const slot14 = new Date("2026-08-10T14:00:00.000Z");
      const ft = [];
      for (const pipeline of due) ft.push(await schSetDue(pipeline.id, slot14.toISOString()));
      const fired = () =>
        db.execution.count({
          where: { pipelineId: { in: due.map((d) => d.id) }, scheduleSlot: slot14 },
        });
      const limits = { maxPerTenantPerTick: 1 };
      const run1 = await schRun(schAfter(ft[0], 600), { limits });
      if ((await fired()) !== 2 || run1.created !== 2)
        problems.push(
          `a share of one per tenant fired ${await fired()}, expected 2 (one for S, one for X)`,
        );
      await schRun(schAfter(ft[0], 600), { limits });
      if ((await fired()) !== 3)
        problems.push("the second tick did not fire another pipeline of S");
      await schRun(schAfter(ft[0], 600), { limits });
      if ((await fired()) !== 4)
        problems.push("the third tick did not fire the last pipeline of S");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

{
  const add = group("Pipeline schedules: validation, daylight saving and missed runs");
  add(
    "PIP-042",
    "schedule validation over the API: a cron that fires more often than the platform minimum (also once a daylight-saving change is counted), an unknown time zone, seconds, @reboot, L, W and # are 400 and write nothing; next_fire_at is stored in UTC when a schedule is created, edited or its pipeline is enabled, and cleared when the pipeline or the trigger is disabled or removed",
    { status: 200 },
    async () => {
      const x = await schWorld();
      const problems = [];
      const own = x.S.owner;
      const repo = x.repoM;
      const refused = [
        ["every 30 minutes", { cron: "*/30 * * * *" }],
        [
          "two fires 30 minutes apart on a daylight-saving day",
          { cron: "30 1,2 * * *", timezone: "Europe/Berlin" },
        ],
        ["an unknown time zone", { timezone: "Mars/Olympus" }],
        ["seconds (6 fields)", { cron: "0 0 * * * *" }],
        ["@reboot", { cron: "@reboot" }],
        ["L", { cron: "0 0 L * *" }],
        ["W", { cron: "0 0 15W * *" }],
        ["#", { cron: "0 0 * * 5#2" }],
        ["a schedule that never fires", { cron: "0 0 31 2 *" }],
      ];
      for (const [label, trigger] of refused) {
        const name = pipName(`bad-${label.replace(/\W+/g, "")}`);
        const r = await pipCreate(own, repo, { name, config: schCfg(trigger) });
        if (r.status !== 400 || r.json?.error?.code !== "VALIDATION_FAILED")
          problems.push(`${label}: answered ${r.status}`);
        else if (await suiteDb().pipeline.findFirst({ where: { tenantId: x.S.id, name } }))
          problems.push(`${label}: a pipeline was written`);
      }
      // next_fire_at: stored in UTC, derived from the expression, never in the past
      const made = await pipCreate(own, repo, {
        name: pipName("planned"),
        config: schCfg({ cron: "0 6 * * *", timezone: "Europe/Berlin" }),
      });
      if (made.status !== 201)
        return { status: 200, json: null, problems: [`create answered ${made.status}`] };
      const id = made.json.data.id;
      const row = () => schTrigger(id);
      let t = await row();
      // the slot of a planned time: the latest slot of the schedule at or before it (the jitter is below the window)
      const slotOf = (r, expression = "0 6 * * *", timeZone = "Europe/Berlin") =>
        previousFireBefore(expression, timeZone, r.nextFireAt, { inclusive: true });
      const berlinSix = (d) => {
        const local = new Intl.DateTimeFormat("en-GB", {
          timeZone: "Europe/Berlin",
          hour: "2-digit",
          minute: "2-digit",
          hourCycle: "h23",
        }).format(d);
        return local === "06:00";
      };
      if (!t.nextFireAt || t.nextFireAt.getTime() <= Date.now())
        problems.push("a created schedule has no future next_fire_at");
      else if (!berlinSix(slotOf(t)))
        problems.push("next_fire_at is not 06:00 in the trigger's zone");
      else if (
        t.nextFireAt.getTime() - slotOf(t).getTime() !== schJit(t, slotOf(t).toISOString()) ||
        schJit(t, slotOf(t).toISOString()) >= SCH_JITTER_WINDOW * 1000
      )
        problems.push("next_fire_at is not the slot plus the jitter of that slot");
      const off = await w.api("POST", `/pipelines/${id}/disable`, { cookie: own });
      t = await row();
      if (off.status !== 200 || t.nextFireAt !== null)
        problems.push("disabling did not clear next_fire_at");
      const on = await w.api("POST", `/pipelines/${id}/enable`, { cookie: own });
      t = await row();
      if (on.status !== 200 || !t.nextFireAt || t.nextFireAt.getTime() <= Date.now())
        problems.push("enabling did not recompute next_fire_at from now");
      const edit = await pipPublish(own, id, 1, schCfg({ cron: "0 18 * * *", timezone: "UTC" }));
      t = await row();
      if (
        edit.status !== 200 ||
        !t.nextFireAt ||
        slotOf(t, "0 18 * * *", "UTC")?.getUTCHours() !== 18
      )
        problems.push("editing the schedule did not recompute next_fire_at");
      const disabledTrigger = await pipPublish(own, id, 2, schCfg({ enabled: false }));
      t = await row();
      if (disabledTrigger.status !== 200 || t.nextFireAt !== null)
        problems.push("a disabled trigger keeps a next_fire_at");
      const removed = await pipPublish(own, id, 3, pipCfg());
      if (removed.status !== 200 || (await row()) !== null)
        problems.push("a removed trigger keeps its projection row");
      // a pipeline created disabled has no planned time
      const idle = await pipCreate(own, repo, {
        name: pipName("idle"),
        enabled: false,
        config: schCfg(),
      });
      const idleRow = idle.status === 201 ? await schTrigger(idle.json.data.id) : null;
      if (!idleRow || idleRow.nextFireAt !== null)
        problems.push("a disabled pipeline has a next_fire_at");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-043",
    "daylight saving and slots (fixed instants, Europe/Berlin and America/New_York, both transitions of 2026): a local time inside the spring-forward gap fires once at the gap end (a named-hour expression) or is skipped (a wildcard or step-hour expression), a repeated local time fires once at its first occurrence (named hours and step hours N > 1) or at every real occurrence, 25 fires on a fall-back day and 23 on a spring-forward day (wildcard hour `*` or `*/1` only), no slot twice, the slot is the UTC instant, the real minimum gap counts the transitions, the missed-run plan fires only the latest pending slot within the lateness limit and records one missed run beyond it",
    { status: 200 },
    async () => ({
      status: 200,
      json: null,
      problems: [...runEvaluationFixtures(), ...runPlanFixtures()],
    }),
    (r) => r.problems,
  );
  add(
    "PIP-044",
    "daylight saving through the scheduler: walking a schedule across the Berlin and New York transitions from fixed instants creates exactly one execution per slot (gap at the gap end, overlap at the first occurrence, never at the repeated one), the slot is stored as the UTC instant and next_fire_at follows",
    { status: 200 },
    async () => {
      const x = await schWorld();
      const p = x.p;
      await schQuiet(
        x,
        p.dst.map((d) => d.id),
      );
      const problems = [];
      for (const [i, row] of NEXT_FIRES.slice(0, 4).entries()) {
        const pipeline = x.p.dst[i];
        await schSetDue(pipeline.id, row.expected[0]);
        for (let n = 0; n < row.expected.length; n += 1) {
          const t = await schTrigger(pipeline.id);
          await schRun(schAfter(t));
        }
        const slots = await schSlots(pipeline.id);
        if (slots.join() !== row.expected.join())
          problems.push(`${row.name}: slots ${slots.join()}`);
        // the last slot handled again, and the repeated or nonexistent local time: nothing more
        await schSetDue(pipeline.id, row.expected[row.expected.length - 1]);
        const t = await schTrigger(pipeline.id);
        const again = await schRun(schAfter(t));
        if ((await schExecs(pipeline.id)).length !== row.expected.length || again.created)
          problems.push(`${row.name}: a slot fired twice`);
        const stored = await schTrigger(pipeline.id);
        if (stored.timezone !== row.timeZone) problems.push(`${row.name}: the zone was not stored`);
      }
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-045",
    "missed runs: after a pause the latest pending slot fires once (run_once) and older ones are not replayed; a slot older than the lateness limit becomes ONE skipped request (missed_run, audited) that consumes no quota and sends no message; the skip policy fires only on time; a pipeline that was disabled does not accumulate misses",
    { status: 200 },
    async () => {
      const x = await schWorld();
      const p = x.p;
      await schQuiet(x);
      const problems = [];
      const used0 = await schUsed(x.S.id, "2026-09");
      // run_once: slots 12:00, 13:00, 14:00 pending at 14:30 -> only the 14:00 slot runs
      const t = await schSetDue(x.p.mRun.id, "2026-09-10T12:00:00.000Z");
      await schRun(schAt("2026-09-10T14:30:00.000Z"));
      const run = await schExecs(x.p.mRun.id);
      if (
        run.length !== 1 ||
        run[0].scheduleSlot.toISOString() !== "2026-09-10T14:00:00.000Z" ||
        run[0].status !== "queued"
      )
        problems.push(
          `run_once: ${run.map((r) => `${r.scheduleSlot.toISOString()} ${r.status}`).join()}`,
        );
      const next = (await schTrigger(x.p.mRun.id)).nextFireAt;
      if (
        next.getTime() !==
        new Date("2026-09-10T15:00:00.000Z").getTime() + schJit(t, "2026-09-10T15:00:00.000Z")
      )
        problems.push("run_once: next_fire_at is not the slot after the handled one");
      // older than the lateness limit (6 h): a daily schedule down for a day
      const d = await schSetDue(x.p.mDaily.id, "2026-09-08T02:00:00.000Z");
      const msgBefore = await schMsgCount(x.S.id);
      await schRun(schAt("2026-09-10T09:00:00.000Z"));
      const daily = await schExecs(x.p.mDaily.id);
      if (
        daily.length !== 1 ||
        daily[0].status !== "skipped" ||
        daily[0].statusReason !== "missed_run"
      )
        problems.push(
          `beyond the lateness limit: ${daily.map((r) => `${r.status}:${r.statusReason}`).join()}`,
        );
      if (daily[0]?.quotaConsumed) problems.push("a missed run consumed quota");
      if ((await schMsgCount(x.S.id)) !== msgBefore) problems.push("a missed run sent a message");
      const audit = (await rtAudits(x.p.mDaily.id, x.S.id)).filter(
        (a) => a.action === "execution.skipped",
      );
      if (audit.length !== 1) problems.push("a missed run was not audited once");
      if ((await schTrigger(x.p.mDaily.id)).nextFireAt.getTime() <= d.nextFireAt.getTime())
        problems.push("the daily schedule was not advanced");
      // skip policy: fires only when on time
      const s = await schSetDue(x.p.mSkip.id, "2026-09-10T12:00:00.000Z");
      await schRun(schAt(new Date(s.nextFireAt.getTime() + 20 * 60000).toISOString()));
      const skipped = await schExecs(x.p.mSkip.id);
      if (
        skipped.length !== 1 ||
        skipped[0].status !== "skipped" ||
        skipped[0].statusReason !== "missed_run"
      )
        problems.push(
          `skip policy, late: ${skipped.map((r) => `${r.status}:${r.statusReason}`).join()}`,
        );
      if ((await schUsed(x.S.id, "2026-09")) !== used0 + 1)
        problems.push("only the one run_once slot should have used a unit");
      // a pipeline that was disabled accumulates no misses: enabling plans from now, nothing is due
      const own = x.S.owner;
      const idle = x.p.pDel;
      await schQuiet(x);
      await suiteDb().pipelineTrigger.updateMany({
        where: { pipelineId: idle.id, type: "schedule" },
        data: { enabled: true, nextFireAt: new Date("2026-09-01T00:00:00.000Z") },
      });
      const off = await w.api("POST", `/pipelines/${idle.id}/disable`, { cookie: own });
      if (off.status !== 200 || (await schTrigger(idle.id)).nextFireAt !== null)
        problems.push("disabling kept a planned time");
      const before = (await schExecs(idle.id)).length;
      const on = await w.api("POST", `/pipelines/${idle.id}/enable`, { cookie: own });
      const planned = await schTrigger(idle.id);
      await schRun(() => new Date());
      if (on.status !== 200 || !planned.nextFireAt || planned.nextFireAt.getTime() <= Date.now())
        problems.push("enabling did not plan a time from now");
      if ((await schExecs(idle.id)).length !== before) problems.push("enabling back-filled a run");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-046",
    "a scheduled run has the same shape as every other request: a queued execution (trigger schedule, the slot, no commit, trusted, the configuration snapshot, concurrency group and idempotency key of the slot) and a pipeline.execution.requested message with the router's payload and a schedule initiator; the ref scanned is the trigger's branch or the repository default branch, resolved at fire time",
    { status: 200 },
    async () => {
      const x = await schWorld();
      await schQuiet(x);
      const db = suiteDb();
      const problems = [];
      const p = x.p.pRef;
      const t1 = await schSetDue(p.id, "2026-10-10T12:00:00.000Z");
      await schRun(schAfter(t1));
      await rtSetRepo(x.repoM, { defaultBranch: "trunk" });
      try {
        const t2 = await schSetDue(p.id, "2026-10-10T13:00:00.000Z");
        await schRun(schAfter(t2));
      } finally {
        await rtSetRepo(x.repoM, { defaultBranch: "main" });
      }
      const rows = await schExecs(p.id);
      if (rows.map((r) => r.refName).join() !== "main,trunk")
        problems.push(
          `the default branch was not resolved at fire time (${rows.map((r) => r.refName)})`,
        );
      const [row] = rows;
      const version = await db.pipelineConfigVersion.findFirst({ where: { pipelineId: p.id } });
      const checks = {
        triggerType: "schedule",
        triggerKey: "nightly",
        refType: "branch",
        commitSha: null,
        baseSha: null,
        trust: "trusted",
        quotaConsumed: 1,
        scmEventId: null,
        scmDeliveryId: null,
        requestedByUserId: null,
        concurrencyGroup: "schedule:nightly",
        idempotencyKey: `schedule:nightly:2026-10-10T12:00:00.000Z`,
        configVersionId: version.id,
        configHash: version.configHash,
        tenantId: x.S.id,
        scanKindReason: "first_run",
      };
      for (const [key, want] of Object.entries(checks))
        if (row[key] !== want) problems.push(`execution.${key} is ${row[key]}, expected ${want}`);
      // the default concurrency policy (supersede) cancels the older queued slot when the next one is requested
      if (
        row.status !== "cancelled" ||
        row.statusReason !== "superseded" ||
        rows[1].status !== "queued"
      )
        problems.push(`statuses ${rows.map((r) => `${r.status}:${r.statusReason ?? ""}`)}`);
      const [message] = await rtMessages([row.id]);
      const keys = [
        "executionId",
        "pipelineId",
        "repositoryId",
        "workspaceId",
        "configVersion",
        "configHash",
        "triggerType",
        "triggerKey",
        "refType",
        "refName",
        "commitSha",
        "pullRequestNumber",
        "scanKind",
        "scanKindReason",
        "trust",
      ].sort();
      if (!message) problems.push("no message");
      else {
        if (Object.keys(message.payload.payload).sort().join() !== keys.join())
          problems.push("the message payload does not have exactly the router's fields");
        const trigger = await schTrigger(p.id);
        if (
          message.payload.initiator?.type !== "schedule" ||
          message.payload.initiator?.id !== trigger.id
        )
          problems.push("the message initiator is not the schedule trigger");
        if (message.tenantId !== x.S.id || message.payload.payload.commitSha !== null)
          problems.push("the message tenant or commit is wrong");
        if (TOKEN_MATERIAL.test(JSON.stringify(message.payload)))
          problems.push("the message carries credential material");
      }
      // an explicit branch and the requested scan kind (after the first full run, the trigger's `incremental` applies)
      const e = x.p.pExplicit;
      for (const slot of ["2026-10-11T12:00:00.000Z", "2026-10-11T13:00:00.000Z"]) {
        const t = await schSetDue(e.id, slot);
        await schRun(schAfter(t));
      }
      const explicit = await schExecs(e.id);
      if (explicit.map((r) => r.refName).join() !== "release/1,release/1")
        problems.push("an explicit branch was not scanned as configured");
      if (
        explicit.map((r) => `${r.scanKind}:${r.scanKindReason}`).join() !==
        "full:first_run,incremental:scheduled"
      )
        problems.push(`scan kinds ${explicit.map((r) => `${r.scanKind}:${r.scanKindReason}`)}`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-047",
    "the tick: the platform job pipeline.schedules.due_requested is enqueued once per time bucket however many schedulers tick (no tenant on the job), validates against the catalog, and a handler run with nothing due is a no-op that repeats safely; a message of another type is refused as non-retryable",
    { status: 200 },
    async () => {
      const x = await schWorld();
      await schQuiet(x);
      const db = suiteDb();
      const problems = [];
      const bucketAt = new Date("2026-05-01T00:00:30.000Z");
      const enqueue = () =>
        enqueuePlatformJob({
          db,
          queue: "scheduler",
          type: "pipeline.schedules.due_requested",
          prefix: "pipeline-schedules-due",
          intervalSeconds: 60,
          payload: (bucket) => ({ bucket }),
          now: bucketAt,
        });
      await Promise.allSettled([enqueue(), enqueue()]);
      await enqueue().catch(() => null);
      const rows = await db.outboxMessage.findMany({
        where: {
          type: "pipeline.schedules.due_requested",
          messageId: { startsWith: "pipeline-schedules-due-" },
        },
      });
      const mine = rows.filter(
        (r) => r.payload?.payload?.bucket === Math.floor(bucketAt.getTime() / 60000),
      );
      if (mine.length !== 1) problems.push(`${mine.length} jobs for one bucket`);
      else {
        const parsed = parseMessage(mine[0].payload);
        if (parsed.tenantId) problems.push("the platform job carries a tenant");
        if (mine[0].queue !== "scheduler") problems.push("the job is not for the scheduler queue");
      }
      const idle = await schRun(schAt("2026-01-01T00:00:00.000Z"));
      const idle2 = await schRun(schAt("2026-01-01T00:00:00.000Z"));
      // the first run may plan schedules that had no planned time yet (fixtures of other checks); nothing is ever created
      if (Object.keys(idle).some((k) => k !== "planned") || Object.keys(idle2).length)
        problems.push(`a run with nothing due did something (${JSON.stringify([idle, idle2])})`);
      let refused = null;
      try {
        await createScheduleHandler({ db, logger: quietLog })(
          parseMessage(
            createJobEnvelope({
              messageId: `other-${randomBytes(3).toString("hex")}`,
              type: "maintenance.sessions.purge_requested",
              schemaVersion: 1,
              initiator: { type: "system", id: "scheduler" },
              payload: { retentionSeconds: 60 },
            }),
          ),
        );
      } catch (error) {
        refused = error;
      }
      if (refused?.name !== "NonRetryableError")
        problems.push("another message type was not refused");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-048",
    "a schedule that is skipped by policy at its slot (repository disconnected, unavailable or disabled, workspace archived, pipeline disabled) writes exactly ONE decision row of source type schedule_slot per (trigger, slot) with the reason and the nominal slot, again idempotently when the run repeats, in its own tenant, workspace and repository only; it creates no execution and no message, the counter outcome stays, a suspended tenant (no decision reason) and a missing pipeline write no row, and the rows are readable through GET /pipelines/{id}/trigger-decisions (404 for another tenant)",
    { status: 200 },
    async () => {
      const x = await schWorld();
      const p = x.p;
      await schQuiet(x);
      const db = suiteDb();
      const problems = [];
      const decisions = (pipelineId) =>
        db.pipelineTriggerDecision.findMany({
          where: { pipelineId, sourceType: "schedule_slot" },
          orderBy: { scheduleSlot: "asc" },
        });
      const variants = [
        [
          "repository disconnected",
          () =>
            rtSetRepo(x.repoM, {
              status: "disconnected",
              disconnectedAt: new Date(),
              disconnectReason: "suite",
            }),
          "repository_inactive",
        ],
        [
          "repository unavailable",
          () => rtSetRepo(x.repoM, { status: "unavailable" }),
          "repository_inactive",
        ],
        [
          "repository disabled",
          () => rtSetRepo(x.repoM, { enabled: false }),
          "repository_disabled",
        ],
        [
          "workspace archived",
          () => db.workspace.update({ where: { id: x.ws1 }, data: { status: "archived" } }),
          "workspace_archived",
        ],
      ];
      const restore = async () => {
        await rtSetRepo(x.repoM, rtActive);
        await db.workspace.update({ where: { id: x.ws1 }, data: { status: "active" } });
      };
      const pipeline = p.pv;
      const before = [(await schExecs(pipeline.id)).length, await schMsgCount(x.S.id)];
      const slots = [];
      for (const [i, [label, apply, reason]] of variants.entries()) {
        const slotIso = `2026-06-10T${String(12 + i).padStart(2, "0")}:00:00.000Z`;
        slots.push(slotIso);
        await apply();
        try {
          const trigger = await schSetDue(pipeline.id, slotIso);
          const counts = await schRun(schAfter(trigger));
          if (!counts.skipped_ineligible)
            problems.push(`${label}: the counter outcome is ${JSON.stringify(counts)}`);
          const rows = (await decisions(pipeline.id)).filter(
            (d) => d.scheduleSlot.toISOString() === slotIso,
          );
          if (rows.length !== 1) {
            problems.push(`${label}: ${rows.length} decision rows for the slot`);
            continue;
          }
          const d = rows[0];
          if (
            d.reason !== reason ||
            d.triggerType !== "schedule" ||
            d.triggerKey !== "nightly" ||
            d.decision !== "skipped_by_policy" ||
            d.scmDeliveryId !== null ||
            d.scmEventKind !== null ||
            d.manualKey !== null ||
            d.tenantId !== x.S.id ||
            d.workspaceId !== x.ws1 ||
            d.repositoryId !== x.repoM ||
            d.pipelineId !== pipeline.id ||
            d.refType !== "branch"
          )
            problems.push(
              `${label}: the decision row is ${JSON.stringify({ reason: d.reason, type: d.triggerType, key: d.triggerKey })}`,
            );
          // the run repeated for the same slot (the state after a crash or a second instance): nothing more
          await schSetDue(pipeline.id, slotIso);
          await schRun(schAfter(trigger));
          const again = (await decisions(pipeline.id)).filter(
            (r) => r.scheduleSlot.toISOString() === slotIso,
          );
          if (again.length !== 1)
            problems.push(`${label}: the repeated run wrote ${again.length} rows`);
        } finally {
          await restore();
        }
      }
      // a pipeline disabled by hand while its schedule is due
      await db.pipeline.update({ where: { id: p.pDis.id }, data: { enabled: false } });
      try {
        const slotIso = "2026-06-10T12:00:00.000Z";
        const trigger = await schSetDue(p.pDis.id, slotIso);
        await schRun(schAfter(trigger));
        const rows = await decisions(p.pDis.id);
        if (rows.length !== 1 || rows[0].reason !== "pipeline_disabled")
          problems.push(`pipeline disabled: ${rows.map((r) => r.reason).join()}`);
      } finally {
        await db.pipeline.update({ where: { id: p.pDis.id }, data: { enabled: true } });
      }
      // a suspended tenant has no decision reason: counter only
      const suspendedBefore = (await decisions(p.pRef.id)).length;
      await db.tenant.update({ where: { id: x.S.id }, data: { status: "suspended" } });
      try {
        const trigger = await schSetDue(p.pRef.id, "2026-06-10T12:00:00.000Z");
        const counts = await schRun(schAfter(trigger));
        if (!counts.skipped_ineligible) problems.push("suspended tenant: no counter outcome");
      } finally {
        await db.tenant.update({ where: { id: x.S.id }, data: { status: "active" } });
      }
      if ((await decisions(p.pRef.id)).length !== suspendedBefore)
        problems.push("a suspended tenant wrote a decision row");
      // a deleted pipeline is parked: no row
      await db.pipeline.update({ where: { id: p.pDel.id }, data: { deletedAt: new Date() } });
      try {
        const trigger = await schSetDue(p.pDel.id, "2026-06-10T12:00:00.000Z");
        await schRun(schAfter(trigger));
      } finally {
        await db.pipeline.update({ where: { id: p.pDel.id }, data: { deletedAt: null } });
      }
      if ((await decisions(p.pDel.id)).length)
        problems.push("a deleted pipeline wrote a decision row");
      // no execution and no message from any skip; the other tenant and workspace saw nothing
      if (
        JSON.stringify(before) !==
        JSON.stringify([(await schExecs(pipeline.id)).length, await schMsgCount(x.S.id)])
      )
        problems.push("a policy skip created an execution or a message");
      for (const other of [p.xCommon, p.other, p.common])
        if ((await decisions(other.id)).length)
          problems.push("a decision row appeared on another pipeline");
      const stray = await db.pipelineTriggerDecision.count({
        where: { sourceType: "schedule_slot", tenantId: { in: [x.X.id, x.Q.id] } },
      });
      if (stray) problems.push("a schedule decision row of another tenant");
      // the read route: source type and the slot, never a delivery id; hidden for another tenant
      const read = await w.api(
        "GET",
        `/pipelines/${pipeline.id}/trigger-decisions?sourceType=schedule_slot&pageSize=100`,
        { cookie: x.S.owner },
      );
      const items = read.json?.data ?? [];
      if (read.status !== 200 || items.length !== slots.length)
        problems.push(`the read route answered ${read.status} with ${items.length} rows`);
      else if (
        items.some(
          (d) =>
            d.sourceType !== "schedule_slot" ||
            !slots.includes(d.scheduleSlot) ||
            d.scmDeliveryId !== null ||
            d.manualKey !== null ||
            d.triggerType !== "schedule" ||
            "tenantId" in d,
        )
      )
        problems.push("the decision DTO has the wrong source fields");
      const foreign = await w.api("GET", `/pipelines/${pipeline.id}/trigger-decisions`, {
        cookie: x.X.owner,
      });
      if (foreign.status !== 404)
        problems.push(`another tenant read the decisions (${foreign.status})`);
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-049",
    "the jitter of a slot is hash(triggerId + slot) mod window: deterministic for the same trigger and slot across handler runs and the API computation, different across slots and triggers for a sample, inside the window, and the nominal slot key never moves (the execution is keyed by the slot, the planned time by slot plus jitter)",
    { status: 200 },
    async () => {
      const x = await schWorld();
      await schQuiet(x);
      const problems = [...runJitterFixtures()];
      const p = x.p.jit;
      const slotIso = "2026-06-10T12:00:00.000Z";
      const t = await schSetDue(p.id, slotIso);
      const planned = t.nextFireAt.getTime();
      const jit = schJit(t, slotIso);
      if (planned !== new Date(slotIso).getTime() + jit)
        problems.push("the planned time is not slot + jitter");
      if (jit < 0 || jit >= SCH_JITTER_WINDOW * 1000)
        problems.push("the jitter is outside the window");
      // not due one second before the planned time (the jitter delays the fire), due at it
      await schRun(() => new Date(planned - 1000));
      if ((await schExecs(p.id)).length)
        problems.push("the schedule fired before its planned time");
      await schRun(() => new Date(planned));
      const rows = await schExecs(p.id);
      if (rows.length !== 1 || rows[0].scheduleSlot.toISOString() !== slotIso)
        problems.push(
          `the slot key is ${rows.map((r) => r.scheduleSlot.toISOString()).join()}, not the nominal slot`,
        );
      if (rows[0]?.idempotencyKey !== `schedule:nightly:${slotIso}`)
        problems.push("the idempotency key is not keyed by the nominal slot");
      const nextSlot = "2026-06-10T13:00:00.000Z";
      const advanced = (await schTrigger(p.id)).nextFireAt.getTime();
      if (advanced !== new Date(nextSlot).getTime() + schJit(t, nextSlot))
        problems.push("the advance is not the next slot plus the jitter of that slot");
      // the same inputs again (a second handler run on the same slot) give the same advance
      await schSetDue(p.id, slotIso);
      await schRun(() => new Date(planned));
      if ((await schTrigger(p.id)).nextFireAt.getTime() !== advanced)
        problems.push("a repeated run advanced to a different planned time");
      // the API computation (create) used the same function: another trigger of the same slot has another offset
      const other = await schTrigger(x.p.common.id);
      const offsets = new Set();
      for (const id of [t.id, other.id])
        for (let h = 0; h < 12; h += 1)
          offsets.add(schJit({ id }, `2026-06-10T${String(h).padStart(2, "0")}:00:00.000Z`));
      if (offsets.size < 10) problems.push("the jitter does not vary across triggers and slots");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-050",
    "daylight saving fall back through the scheduler (Europe/Berlin 25 October and America/New_York 1 November 2026, fixed instants): a wildcard-hour schedule fires once per REAL UTC hour (25 executions on the fall-back day, the repeated hour at both occurrences), no slot twice, each slot handled again creates nothing; step hours N > 1 and named hours fire once in the repeated hour (Berlin 0 */2: 12 fires, none at 01:00Z) and a wildcard hour fires 23 times on a spring-forward day",
    { status: 200 },
    async () => {
      const x = await schWorld();
      await schQuiet(x);
      const problems = [];
      for (const [i, day] of DAY_FIRES.slice(0, 2).entries()) {
        const pipeline = x.p.wild[i];
        const expected = [];
        for (
          let at = nextFireAfter(day.expression, day.timeZone, new Date(day.from));
          at && at.getTime() <= new Date(day.to).getTime();
          at = nextFireAfter(day.expression, day.timeZone, at)
        )
          expected.push(at.toISOString());
        if (expected.length !== 25)
          problems.push(`${day.name}: the fixture has ${expected.length} instants`);
        await schSetDue(pipeline.id, expected[0]);
        for (let n = 0; n < expected.length; n += 1) {
          const t = await schTrigger(pipeline.id);
          await schRun(schAfter(t));
        }
        const slots = await schSlots(pipeline.id);
        if (slots.join() !== expected.join())
          problems.push(`${day.name}: slots ${slots.length} differ from the real hours`);
        if (new Set(slots).size !== slots.length) problems.push(`${day.name}: a slot fired twice`);
        for (const walk of OVERLAP_WALKS.filter((w2) => w2.timeZone === day.timeZone))
          for (const instant of walk.expected)
            if (!slots.includes(instant)) problems.push(`${walk.name}: ${instant} did not fire`);
        // every slot handled again (a duplicate delivery of the tick, a second instance): nothing more
        for (const slot of slots) {
          await schSetDue(pipeline.id, slot);
          await schRun(schAfter(await schTrigger(pipeline.id)));
        }
        if ((await schExecs(pipeline.id)).length !== expected.length)
          problems.push(`${day.name}: a slot created a second execution on repeat`);
      }
      // the other days of the fixture: step hours (N > 1) and named hours once in the repeated hour, 23 on spring forward
      for (const day of DAY_FIRES.slice(2)) {
        const got = [];
        for (
          let at = nextFireAfter(day.expression, day.timeZone, new Date(day.from));
          at && at.getTime() <= new Date(day.to).getTime();
          at = nextFireAfter(day.expression, day.timeZone, at)
        )
          got.push(at.toISOString());
        if (got.length !== day.count || new Set(got).size !== got.length)
          problems.push(`${day.name}: ${got.length} fires`);
        for (const never of day.never ?? [])
          if (got.includes(never)) problems.push(`${day.name}: fired at ${never}`);
      }
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 16. Pipelines and triggers: consolidation (part G, SPEC pipelines-triggers §16 "part G, suite coverage matrix"). Gaps the audit
//     of §14.1 found: audit atomicity under a forced failure, idempotency keys across tenants, soft-deleted pipelines outside the
//     caller's workspaces, and "pipeline.manage cannot grant anything".
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Pipelines: consolidation (part G)");
  add(
    "PIP-051",
    "audit atomicity: when the audit write of a pipeline change or a manual run fails (forced by a database trigger that rejects the entry) the change is rolled back with it, and when the change cannot commit (a deferred constraint trigger raises at COMMIT) no audit entry survives (create, publish, disable, delete and manual run leave no row, no version, no message, no quota unit and no entry); once the fault is removed the same calls succeed and are audited",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const admin = x.sessions.admin;
      const p = (await pipCreate(admin, x.payRepo, { name: pipName("atomic") })).json.data;
      await pipPublish(admin, p.id, 1, pipCfg({ failOn: { severity: "medium" } }));
      const name = pipName("atomic-new");
      const quota = await db.quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
      const used = () =>
        db.tenantQuotaUsage
          .findFirst({ where: { tenantId: x.tenantId, quotaDefinitionId: quota.id } })
          .then((u) => Number(u?.used ?? 0));
      const state = async () => ({
        pipelines: await db.pipeline.count({ where: { tenantId: x.tenantId } }),
        versions: await db.pipelineConfigVersion.count({ where: { pipelineId: p.id } }),
        executions: await db.execution.count({ where: { tenantId: x.tenantId } }),
        messages: await db.outboxMessage.count({
          where: { tenantId: x.tenantId, type: "pipeline.execution.requested" },
        }),
        used: await used(),
        audit: await db.auditLog.count({
          where: {
            tenantId: x.tenantId,
            OR: [{ action: { startsWith: "pipeline." } }, { action: "execution.manual_requested" }],
          },
        }),
        row: JSON.stringify(
          await db.pipeline.findFirst({
            where: { id: p.id },
            select: { enabled: true, deletedAt: true, currentVersionId: true },
          }),
        ),
      });
      const calls = () => [
        ["create", () => pipCreate(admin, x.payRepo, { name })],
        ["publish", () => pipPublish(admin, p.id, 2, pipCfg({ failOn: { severity: "high" } }))],
        ["disable", () => w.api("POST", `/pipelines/${p.id}/disable`, { cookie: admin })],
        [
          "delete",
          () => w.api("DELETE", `/pipelines/${p.id}`, { cookie: admin, body: { confirm: p.name } }),
        ],
        ["run", () => pipRun(admin, p.id, { ref: { type: "branch", name: "main" } })],
      ];
      // two faults: (1) the audit entry cannot be written, (2) the change itself cannot commit (a deferred constraint trigger that
      // raises at COMMIT). Atomic means both leave nothing: no change in (1), and no audit entry for a change that never happened in (2).
      const T = `'${x.tenantId}'::uuid`;
      const fault = async (kind) => {
        if (kind === "audit") {
          await db.$executeRawUnsafe(
            `CREATE OR REPLACE FUNCTION suite_fail_pipeline_audit() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RAISE EXCEPTION 'suite: forced failure'; END $f$`,
          );
          await db.$executeRawUnsafe(
            `CREATE TRIGGER suite_fail_pipeline_audit BEFORE INSERT ON audit_logs FOR EACH ROW WHEN (NEW.tenant_id = ${T} AND (NEW.action LIKE 'pipeline.%' OR NEW.action = 'execution.manual_requested')) EXECUTE FUNCTION suite_fail_pipeline_audit()`,
          );
        } else if (kind === "commit") {
          await db.$executeRawUnsafe(
            `CREATE OR REPLACE FUNCTION suite_fail_pipeline_audit() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RAISE EXCEPTION 'suite: forced failure'; END $f$`,
          );
          for (const table of ["pipelines", "pipeline_config_versions", "executions"])
            await db.$executeRawUnsafe(
              `CREATE CONSTRAINT TRIGGER suite_fail_commit_${table} AFTER INSERT OR UPDATE ON ${table} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.tenant_id = ${T}) EXECUTE FUNCTION suite_fail_pipeline_audit()`,
            );
        } else {
          await db.$executeRawUnsafe(
            `DROP TRIGGER IF EXISTS suite_fail_pipeline_audit ON audit_logs`,
          );
          for (const table of ["pipelines", "pipeline_config_versions", "executions"])
            await db.$executeRawUnsafe(
              `DROP TRIGGER IF EXISTS suite_fail_commit_${table} ON ${table}`,
            );
          await db.$executeRawUnsafe(`DROP FUNCTION IF EXISTS suite_fail_pipeline_audit()`);
        }
      };
      for (const [kind, what] of [
        ["audit", "its audit entry could not be written"],
        ["commit", "the change could not commit"],
      ]) {
        try {
          await fault(kind);
          const before = await state();
          for (const [label, run] of calls()) {
            const r = await run();
            if (r.status >= 200 && r.status < 300)
              problems.push(`${label} succeeded although ${what}`);
            const after = await state();
            if (JSON.stringify(after) !== JSON.stringify(before))
              problems.push(`${label} left a change or an audit entry behind when ${what}`);
          }
        } finally {
          await fault("off");
        }
      }
      // control: without the fault the same calls work, and each leaves its audit entry
      const entriesBefore = await db.auditLog.count({ where: { tenantId: x.tenantId } });
      const okCalls = [
        ["create", () => pipCreate(admin, x.payRepo, { name }), 201],
        [
          "publish",
          () => pipPublish(admin, p.id, 2, pipCfg({ failOn: { severity: "high" } })),
          200,
        ],
        ["disable", () => w.api("POST", `/pipelines/${p.id}/disable`, { cookie: admin }), 200],
        ["enable", () => w.api("POST", `/pipelines/${p.id}/enable`, { cookie: admin }), 200],
        ["run", () => pipRun(admin, p.id, { ref: { type: "branch", name: "main" } }), 202],
      ];
      for (const [label, run, status] of okCalls) {
        const r = await run();
        if (r.status !== status) problems.push(`control: ${label} answered ${r.status}`);
      }
      const entriesAfter = await db.auditLog.count({ where: { tenantId: x.tenantId } });
      if (entriesAfter - entriesBefore < okCalls.length)
        problems.push("control: the legitimate calls did not leave their audit entries");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-055",
    "an unknown fork flag is never a trusted run: a pull-request message whose fork flag is missing, null or not a boolean is refused by the message contract (or, if it ever got through, routed as a fork) and creates no execution under the default policy; an explicit false (control) runs",
    { status: 200 },
    async () => {
      const x = await rtWorld();
      const problems = [];
      const sent = await rtEvent(
        "pull_request",
        { inst: x.R.inst, repo: x.ext.fork, fork: true, number: 31 },
        { route: false },
      );
      if (!sent.envelope) return { status: 200, json: null, problems: ["fixture: no message"] };
      const withFlag = (flag, drop = false) => {
        const e = structuredClone(sent.envelope);
        if (drop) delete e.payload.isFork;
        else e.payload.isFork = flag;
        return e;
      };
      const trustedFor = async (deliveryId) =>
        (await rtExecs(x.fork.skip.id, { scmDeliveryId: deliveryId })).length;
      for (const [label, envelope] of [
        ["missing", withFlag(undefined, true)],
        ["null", withFlag(null)],
        ["the string false", withFlag("false")],
        ["the number 0", withFlag(0)],
      ]) {
        let outcome;
        try {
          outcome = await rtConsume(envelope);
        } catch (error) {
          outcome = { ok: false, refused: true, error };
        }
        if ((await trustedFor(sent.deliveryId)) !== 0)
          problems.push(
            `a fork flag that is ${label} created an execution under the default policy`,
          );
        if (outcome.ok === true) {
          const trust = (await rtExecs(x.fork.run.id, { scmDeliveryId: sent.deliveryId })).map(
            (e) => e.trust,
          );
          if (trust.some((t) => t !== "untrusted_fork"))
            problems.push(`a fork flag that is ${label} ran as trusted`);
        }
      }
      // control: an explicit false is a same-repository pull request and runs trusted; an explicit true is skipped
      const control = await rtConsume(withFlag(false));
      if (!control.ok || (await trustedFor(sent.deliveryId)) !== 1)
        problems.push("control: an explicit false did not run the default-policy pipeline");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-052",
    "idempotency keys never cross tenants or pipelines: the same Idempotency-Key used by two tenants (and on two pipelines of one tenant) for a manual run or a create answers each caller with its own new resource, never a replay of the other's, and the rows carry the caller's own tenant",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const key = KEY("shared-run");
      const a = await pipRun(
        x.sessions.admin,
        x.pPay.id,
        { ref: { type: "branch", name: "main" } },
        key,
      );
      const b = await pipRun(
        x.sessions.edge,
        x.pEdge.id,
        { ref: { type: "branch", name: "main" } },
        key,
      );
      const c2 = await pipRun(
        x.sessions.admin,
        x.pId.id,
        { ref: { type: "branch", name: "main" } },
        key,
      );
      for (const [label, r] of [
        ["tenant A", a],
        ["the other tenant", b],
      ])
        if (r.status !== 202) problems.push(`control: ${label} run answered ${r.status}`);
      if (a.status === 202 && b.status === 202) {
        const ea = a.json.data.execution.id;
        const eb = b.json.data.execution.id;
        if (ea === eb) problems.push("the other tenant received the first tenant's execution");
        if (JSON.stringify(b.json).includes(ea))
          problems.push("a response of the other tenant carries the first tenant's execution id");
        const rowB = await db.execution.findFirst({ where: { id: eb } });
        if (rowB?.tenantId !== x.edgeTenantId || rowB?.pipelineId !== x.pEdge.id)
          problems.push("the other tenant's run is not in its own tenant and pipeline");
        const rowA = await db.execution.findFirst({ where: { id: ea } });
        if (rowA?.tenantId !== x.tenantId) problems.push("the first run is not in its own tenant");
        if (c2.status === 202 && c2.json.data.execution.id === ea)
          problems.push("a second pipeline replayed the first pipeline's run for the same key");
        if (c2.status === 202) {
          const rowC = await db.execution.findFirst({ where: { id: c2.json.data.execution.id } });
          if (rowC?.pipelineId !== x.pId.id) problems.push("the run is not on the pipeline asked");
        }
      }
      // the create route takes a key too
      const createKey = KEY("shared-create");
      const ca = await pipCreate(
        x.sessions.admin,
        x.payRepo2,
        { name: pipName("idem-a") },
        createKey,
      );
      const cb = await pipCreate(
        x.sessions.edge,
        x.edgeRepo,
        { name: pipName("idem-b") },
        createKey,
      );
      if (ca.status !== 201 || cb.status !== 201)
        problems.push(`control: creates answered ${ca.status} and ${cb.status}`);
      else {
        if (ca.json.data.id === cb.json.data.id)
          problems.push("a create was replayed across tenants");
        const row = await db.pipeline.findFirst({ where: { id: cb.json.data.id } });
        if (row?.tenantId !== x.edgeTenantId)
          problems.push("the other tenant's pipeline is not in its own tenant");
      }
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-053",
    "soft-deleted pipelines stay inside their workspace: with includeDeleted or effectiveState=deleted the manager (Payments only) lists the deleted Payments pipeline and nothing of the hidden Identity workspace or of another tenant, and a deleted pipeline of a hidden workspace or another tenant answers the same 404 as a missing id on every read",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const problems = [];
      const admin = x.sessions.admin;
      const del = async (cookie, repo, label) => {
        const p = (await pipCreate(cookie, repo, { name: pipName(label) })).json.data;
        const r = await w.api("DELETE", `/pipelines/${p.id}`, {
          cookie,
          body: { confirm: p.name },
        });
        if (r.status !== 200 && r.status !== 204)
          problems.push(`fixture: delete answered ${r.status}`);
        return p;
      };
      const pay = await del(admin, x.payRepo, "gone-pay");
      const idn = await del(admin, x.idRepo, "gone-idn");
      const foreign = await del(x.sessions.edge, x.edgeRepo, "gone-edge");
      for (const query of ["includeDeleted=true", "effectiveState=deleted"]) {
        const m = await w.api("GET", `/pipelines?pageSize=100&${query}`, {
          cookie: x.sessions.manager,
        });
        const a = await w.api("GET", `/pipelines?pageSize=100&${query}`, { cookie: admin });
        const ids = (r) => (r.json?.data ?? []).map((p) => p.id);
        if (m.status !== 200 || !ids(m).includes(pay.id))
          problems.push(`control: ${query} did not show the manager the deleted Payments pipeline`);
        if (ids(m).includes(idn.id))
          problems.push(`${query} showed a deleted pipeline of a hidden workspace`);
        if (ids(m).includes(foreign.id) || ids(a).includes(foreign.id))
          problems.push(`${query} showed another tenant's deleted pipeline`);
        if (a.status !== 200 || !ids(a).includes(idn.id))
          problems.push(`control: ${query} did not show the administrator the Identity one`);
      }
      const missing = await w.api("GET", `/pipelines/${missingId()}`, {
        cookie: x.sessions.manager,
      });
      for (const [who, cookie, target] of [
        ["manager", x.sessions.manager, idn],
        ["administrator", admin, foreign],
      ]) {
        for (const path of ["", "/versions", "/versions/1", "/executions", "/trigger-decisions"]) {
          const r = await w.api("GET", `/pipelines/${target.id}${path}`, { cookie });
          if (r.status !== 404)
            problems.push(`${who}: deleted ${path || "pipeline"} answered ${r.status}`);
          else if (path === "" && strip(r.json) !== strip(missing.json))
            problems.push(`${who}: a deleted pipeline's 404 differs from a missing id's`);
        }
      }
      const readable = await w.api("GET", `/pipelines/${pay.id}`, { cookie: x.sessions.manager });
      if (readable.status !== 200 || !readable.json?.data?.deletedAt)
        problems.push("control: the manager cannot read the deleted pipeline of its own workspace");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
  add(
    "PIP-054",
    "pipeline.manage cannot grant anything: a manager's create, edit and publish with role, permission, member or assignment fields answer 400 and write nothing, and the tenant's roles, role assignments, group memberships and the caller's own permissions are identical before and after the legitimate calls",
    { status: 200 },
    async () => {
      const x = await pipWorld();
      const db = suiteDb();
      const problems = [];
      const cookie = x.sessions.manager;
      const snapshotOf = async () =>
        JSON.stringify({
          roles: await db.role.count({ where: { tenantId: x.tenantId } }),
          rolePermissions: await db.rolePermission.count({
            where: { role: { tenantId: x.tenantId } },
          }),
          userAssignments: await db.userRoleAssignment.count({ where: { tenantId: x.tenantId } }),
          groupAssignments: await db.groupRoleAssignment.count({ where: { tenantId: x.tenantId } }),
          members: await db.groupMember.count({ where: { tenantId: x.tenantId } }),
          me: (await w.api("GET", "/me", { cookie })).json?.data,
        });
      const before = await snapshotOf();
      const extras = [
        { roleId: randomUUID() },
        { permissions: ["pipeline.manage_fork_policy", "tenant.manage"] },
        { role: "admin" },
        { members: [randomUUID()] },
        { assignments: [{ userId: randomUUID(), roleId: randomUUID() }] },
        { grantTo: "manager" },
      ];
      const p = (await pipCreate(cookie, x.payRepo, { name: pipName("mgr") })).json?.data;
      if (!p?.id) problems.push("control: the manager could not create a pipeline");
      for (const extra of extras) {
        const key = Object.keys(extra)[0];
        const c1 = await pipCreate(cookie, x.payRepo, { name: pipName("mgr-x"), ...extra });
        if (c1.status !== 400) problems.push(`create with ${key} answered ${c1.status}`);
        if (p?.id) {
          const e1 = await w.api("PATCH", `/pipelines/${p.id}`, {
            cookie,
            body: { description: "x", ...extra },
          });
          if (e1.status !== 400) problems.push(`edit with ${key} answered ${e1.status}`);
          const e2 = await w.api("PUT", `/pipelines/${p.id}/config`, {
            cookie,
            body: { expectedVersion: 1, config: pipCfg(), ...extra },
          });
          if (e2.status !== 400) problems.push(`publish with ${key} answered ${e2.status}`);
        }
      }
      if (p?.id) {
        const ok = await pipPublish(cookie, p.id, 1, pipCfg({ failOn: { severity: "low" } }));
        if (ok.status !== 200)
          problems.push(`control: the manager's publish answered ${ok.status}`);
      }
      if (await db.pipeline.count({ where: { name: { startsWith: "mgr-x" } } }))
        problems.push("a refused create left a pipeline behind");
      if ((await snapshotOf()) !== before)
        problems.push("roles, assignments, memberships or the caller's permissions changed");
      return { status: 200, json: null, problems };
    },
    (r) => r.problems,
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// 17. User preferences (docs/modules/user-preferences/SPEC.md §14, PREF-001..013): GET and PUT /me/preferences. The route
//     names no user and no tenant, so isolation is proven by forged identifiers, two users of one tenant, two tenants, the
//     platform session and the suspended tenant, reading the rows back from the disposable database. Fixtures: tenants
//     "prefp" and "prefq" created through the public API (helpers/user-preferences.js).
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("User preferences: own data only");
  for (const { id, name, expected, run, verify } of buildPreferenceChecks({
    S,
    once,
    db: suiteDb,
  }))
    add(id, name, expected, run, verify);
}

// ---------------------------------------------------------------------------------------------------------------------
// 17b. Organization overview is Admin-only (docs/AUTHORIZATION.md decision 30, OVR-001..015): GET /overview needs the
//      tenant-scope dashboard.view, which only the Admin built-in bundle holds. Per-role checks assign each built-in role at
//      TENANT scope to a seeded user (where a tenant-scope key would otherwise become effective); helpers/overview-checks.js.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Organization overview: Admin-only dashboard.view");
  for (const { id, name, expected, run, verify } of buildOverviewChecks({
    S,
    once,
    db: suiteDb,
    withRole,
    loginAs,
  }))
    add(id, name, expected, run, verify);
}

// ---------------------------------------------------------------------------------------------------------------------
// 17c. LLM data-egress consent (docs/modules/scan-decisioning/SPEC.md 7.2a and 14.1, ADR-013, DEC-S10*, DEC-S11*): the gate inside
//      resolveLLMProvider (an external provider is never built or called without the tenant's audited consent) and the route
//      family GET/PUT /settings/ai. Local stub servers count the requests; helpers/llm-consent-checks.js.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("LLM consent gate and tenant AI settings");
  for (const { id, name, expected, run, verify } of buildLlmConsentChecks({
    S,
    once,
    db: suiteDb,
    withRole,
    loginAs,
  }))
    add(id, name, expected, run, verify);
}

// ---------------------------------------------------------------------------------------------------------------------
// 18. Cursor pagination (docs/technical/API_STANDARDS.md "Cursor pagination", PAG-001..015): the Repositories list, the two
//     Pipelines lists and the tenant audit log. Cursor pages must equal the offset result (also under concurrent inserts), and
//     a cursor is only a position: tampered, foreign (sort, filter, endpoint, parent, tenant) cursors answer 400, scope and
//     authorization are re-applied from the session. Fixtures: tenants "pagp" and "pagq" through the public API, rows written
//     to the disposable database (helpers/pagination.js).
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Cursor pagination: position only, never scope");
  for (const { id, name, expected, run, verify } of buildPaginationChecks({
    S,
    once,
    db: suiteDb,
  }))
    add(id, name, expected, run, verify);
}

// ---------------------------------------------------------------------------------------------------------------------
// 19. Executions: the orchestrator against the GitHub stub (ADR-008 area 10, SPEC executions §14.1, part C): the real
//     orchestrator, scan task handler, ownership verifier and outbox run in process against the disposable database, the local
//     GitHub stub (installation tokens, archive by SHA behind a 302) and a deterministic test engine; tenant isolation of the
//     worker (ownership and claim re-validation), credential absence, lease reclaim and fencing, the stale-queue guarantee, the
//     single completed event and resolutionEligible. Fixtures and checks live in helpers/orchestrator*.js. LAST on purpose: the
//     group creates many tenants (the platform tenant list checks walk them) and its first-enable sweep cancels every older
//     queued row of the database.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Executions: orchestrator against the GitHub stub");
  const orchWorld = () =>
    once("orchestrator", () =>
      buildOrchestratorWorld(suiteDb(), {
        stubUrl: STUB,
        clientId: env("SECURITY_GITHUB_CLIENT_ID"),
        privateKey: env("SECURITY_GITHUB_PRIVATE_KEY"),
      }),
    );
  for (const { id, name, run } of [
    ...ORCH_CHECKS,
    ...CANCEL_RETRY_CHECKS,
    ...SBOM_CHECKS,
    ...STORE_CHECKS,
    ...PART_I_CHECKS,
  ])
    add(
      id,
      name,
      { status: 200 },
      async () => ({ status: 200, json: null, problems: await run(await orchWorld()) }),
      (r) => r.problems,
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// Realtime: the Socket.IO server (SPEC executions 9.4 and 17.ad), live API process plus in-process server and consumer.
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Executions: realtime (Socket.IO)");
  const realtimeWorld = () =>
    once("realtime", () =>
      buildRealtimeWorld(w, {
        db: suiteDb(),
        apiUrl: env("SECURITY_API_URL"),
        origin: env("SECURITY_ORIGIN"),
      }),
    );
  for (const { id, name, run } of REALTIME_CHECKS)
    add(
      id,
      name,
      { status: 200 },
      async () => ({ status: 200, json: null, problems: await run(await realtimeWorld()) }),
      (r) => r.problems,
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// Executions API (SPEC executions §8.1, §14.1 EXE-001..010 over HTTP, §17.ae, part G): list, detail, events, logs, cancel and
// retry against the running API, over the Pipelines world (`pipWorld`).
// ---------------------------------------------------------------------------------------------------------------------
{
  const add = group("Executions: API (isolation, permissions, cursors, cancel, retry)");
  for (const { id, name, run } of buildExecHttpChecks({
    w: new Proxy({}, { get: (_t, key) => w[key] }),
    db: suiteDb,
    pipWorld,
    KEY,
  }))
    add(id, name, { status: 200 }, run, (r) => r.problems);
}

// ---------------------------------------------------------------------------------------------------------------------
const allChecks = groups.flatMap((g) => g.checks);

/** @param {{ status: number, json: any }} response @param {Expected} expected @param {string} where */
function assertResponse(response, expected, where) {
  assert.equal(
    response.status,
    expected.status,
    `${where}: expected HTTP ${expected.status}, got ${response.status} (${response.json?.error?.code ?? "no error code"})`,
  );
  if (expected.code)
    assert.equal(
      response.json?.error?.code,
      expected.code,
      `${where}: expected error code ${expected.code}, got ${response.json?.error?.code}`,
    );
  if (expected.status >= 400) {
    assert.equal(
      response.json?.success,
      false,
      `${where}: error responses must use the error envelope`,
    );
    assert.equal(
      typeof response.json?.meta?.correlationId,
      "string",
      `${where}: error responses must carry meta.correlationId`,
    );
  }
}

describe("security regression suite", () => {
  after(async () => {
    (await memo.get("orchestrator")?.catch(() => null))?.cleanup?.();
    await secretDb?.$disconnect();
  });
  before(async () => {
    w = await buildWorld(client, {
      tenantPassword: env("SECURITY_TENANT_PASSWORD"),
      platformPassword: env("SECURITY_PLATFORM_PASSWORD"),
      mfaCode: env("SECURITY_MFA_CODE"),
    });
  });

  describe("suite integrity", () => {
    it(`registers exactly ${EXPECTED_CHECKS} checks with unique ids and names`, () => {
      assert.equal(
        allChecks.length,
        EXPECTED_CHECKS,
        `the suite must keep its ${EXPECTED_CHECKS} checks (found ${allChecks.length}); update ADR-008 if this is intentional`,
      );
      assert.equal(
        new Set(allChecks.map((c) => c.id)).size,
        allChecks.length,
        "check ids must be unique",
      );
      assert.equal(
        new Set(allChecks.map((c) => c.name)).size,
        allChecks.length,
        "check names must be unique",
      );
    });
  });

  // Controls run first and before suspension: they prove the legitimate version of each request WORKS.
  describe("controls (legitimate requests succeed, so denials below are not vacuous)", () => {
    const ok = (name, run, verify) =>
      it(`CONTROL ${name}`, async () => {
        const response = await run(w);
        assertResponse(response, { status: 200 }, `CONTROL ${name}`);
        verify?.(response);
      });
    ok("A admin reads A's workspace", (x) =>
      x.api("GET", `/workspaces/${x.A.paymentsWs}`, { cookie: S("admin")(x) }),
    );
    ok("A admin reads A's user", (x) =>
      x.api("GET", `/users/${x.A.user}`, { cookie: S("admin")(x) }),
    );
    ok("A admin reads A's group and its members", async (x) => {
      const group = await x.api("GET", `/groups/${x.A.group}`, { cookie: S("admin")(x) });
      assert.equal(group.status, 200);
      return x.api("GET", `/groups/${x.A.group}/members`, { cookie: S("admin")(x) });
    });
    ok(
      "A admin lists roles",
      (x) => x.api("GET", "/roles", { cookie: S("admin")(x) }),
      (r) => assert.ok(r.json.data.length >= 7),
    );
    ok("A admin lists workspace role assignments", (x) =>
      x.api("GET", `/workspaces/${x.A.paymentsWs}/role-assignments`, { cookie: S("admin")(x) }),
    );
    ok("A admin can use the member route (idempotent PUT of themselves)", (x) =>
      x.api("PUT", `/workspaces/${x.A.paymentsWs}/members/${x.A.adminUserId}`, {
        cookie: S("admin")(x),
      }),
    );
    ok("A manager reads the workspace they can see", (x) =>
      x.api("GET", `/workspaces/${x.A.paymentsWs}`, { cookie: S("manager")(x) }),
    );
    ok(
      "A viewer lists workspaces",
      (x) => x.api("GET", "/workspaces", { cookie: S("viewer")(x) }),
      (r) => assert.ok(r.json.data.length >= 1),
    );
    ok(
      "A viewer reads and sets their own accent (no special permission)",
      async (x) => {
        const put = await x.api("PUT", "/me/preferences", {
          cookie: S("viewer")(x),
          body: { accent: "blue" },
        });
        assert.equal(put.status, 200);
        return x.api("GET", "/me/preferences", { cookie: S("viewer")(x) });
      },
      (r) => assert.equal(r.json.data.accent, "blue"),
    );
    ok(
      "A admin /me shows tenant A",
      (x) => x.api("GET", "/me", { cookie: S("admin")(x) }),
      (r) => assert.equal(r.json.data.tenant.slug, "demo"),
    );
    ok("B owner reads B's workspace", (x) =>
      x.api("GET", `/workspaces/${x.B.ws}`, { cookie: S("bOwner")(x) }),
    );
    ok("B owner reads B's user", (x) =>
      x.api("GET", `/users/${x.B.userId}`, { cookie: S("bOwner")(x) }),
    );
    ok("B owner reads B's group", (x) =>
      x.api("GET", `/groups/${x.B.group}`, { cookie: S("bOwner")(x) }),
    );
    ok("B owner reads B's custom role", (x) =>
      x.api("GET", `/roles/${x.B.role}`, { cookie: S("bOwner")(x) }),
    );
    ok(
      "B owner reads B's workspace role assignments",
      (x) => x.api("GET", `/workspaces/${x.B.ws}/role-assignments`, { cookie: S("bOwner")(x) }),
      (r) => assert.ok(r.json.data.some((a) => a.id === w.B.assignment)),
    );
    ok(
      "two wrong passwords then the right one still sign in (below the free attempts)",
      async (x) => {
        for (let i = 0; i < 2; i += 1)
          await x.api("POST", "/auth/login", {
            body: { email: "demo.developer@demo.example", password: "definitely-wrong-password" },
          });
        return x.api("POST", "/auth/login", {
          body: { email: "demo.developer@demo.example", password: x.secrets.tenantPassword },
        });
      },
    );
    ok(
      "platform session (after MFA) reads /platform/me",
      (x) => x.api("GET", "/platform/me", { cookie: S("sa")(x) }),
      (r) => assert.equal(r.json.data.session.mfaVerified, true),
    );
    ok(
      "platform session lists tenants (tenant B is among them)",
      (x) => x.api("GET", "/platform/tenants?pageSize=100", { cookie: S("sa")(x) }),
      (r) => assert.ok(r.json.data.some((t) => t.id === w.B.id)),
    );
  });

  for (const g of groups) {
    describe(g.title, () => {
      if (g.setup) before(() => g.setup(w));
      for (const c of g.checks) {
        it(`${c.id} ${c.name}`, async () => {
          const response = await c.run(w);
          assertResponse(response, c.expected, `${c.id} ${c.name}`);
          const problems = (await c.verify?.(response, w)) ?? [];
          assert.deepEqual(problems, [], `${c.id} ${c.name}: ${problems.join("; ")}`);
          if (c.noLeakOf) {
            const body = JSON.stringify(response.json);
            const foreign =
              c.noLeakOf === "B"
                ? ids({
                    id: w.B.id,
                    ws: w.B.ws,
                    group: w.B.group,
                    role: w.B.role,
                    userId: w.B.userId,
                    assignment: w.B.assignment,
                  })
                : ids({
                    ws: w.A.paymentsWs,
                    ws2: w.A.identityWs,
                    group: w.A.group,
                    user: w.A.user,
                  });
            for (const id of foreign)
              assert.ok(
                !body.includes(id),
                `${c.id}: the response leaks an identifier of the other tenant`,
              );
          }
        });
      }
    });
  }
});
