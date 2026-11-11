/**
 * Security regression suite (ADR-008). Scope, deliberately narrow: tenant isolation, 404/403 authorization behavior,
 * platform/tenant session separation, segregation of duties and the progressive sign-in/MFA throttling (ADR-010). Black box over HTTP against a running API: `scripts/security-suite.js` provisions a
 * disposable database, starts the API and sets SECURITY_* variables. Run with `pnpm test:security`.
 *
 * 68 of the 77 checks come from the audit in docs/STATUS_PHASE_1-4.md plus 9 THR (ADR-010) and 6 RST (tenant restore window, AUTHORIZATION Q25) checks added later. Controls (not counted in the 68) prove the legitimate
 * requests SUCCEED, so a transport that stops mounting routes cannot make the "expect 404 / 401" checks pass vacuously.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, describe, it } from "node:test";
import { getDbClient } from "@qmentisai/db";
import { assertSecretFreeMessage, resolveFromMessage, toSecretResponse } from "@qmentisai/infra";
import { createAuditService } from "../../src/audit/audit-service.js";
import { createSecrets } from "../../src/runtime/secrets.js";
import { createClient } from "./helpers/http.js";
import { buildWorld } from "./helpers/world.js";

const EXPECTED_CHECKS = 118;
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
      const { createEntitlementService } = await import("../../src/entitlements/service.js");
      const { createEntitlementRepository } = await import("../../src/entitlements/repository.js");
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
// 10. GitHub integration: installation linking (SCM). The App is a local stub (no network); see helpers/github-stub.js.
// ---------------------------------------------------------------------------------------------------------------------
const STUB = env("SECURITY_GITHUB_STUB_URL");
const stubCtl = (path, body) =>
  fetch(STUB + path, { method: "POST", body: JSON.stringify(body) }).then((r) => r.json());
let installationCounter = 0;
const nextInstallationId = () => 700000000 + (Date.now() % 1000000) * 10 + installationCounter++;
/**
 * The documented linking sequence against the stub: set up GitHub's side, ask for our single-use state, then verify.
 * `orgRole`: the user's role in the organization ("admin", "member"); omit for a personal account.
 */
async function linkFlow(
  cookie,
  { installationId = nextInstallationId(), account, user, orgRole, listed = true, repos = [] },
) {
  await stubCtl("/__control/installation", { id: installationId, account, repos });
  const code = `code-${randomBytes(6).toString("hex")}`;
  await stubCtl("/__control/code", {
    code,
    user,
    installationIds: listed ? [installationId] : [],
    orgRoles: orgRole ? { [account.login]: { role: orgRole, state: "active" } } : {},
  });
  const auth = await w.api("POST", "/integrations/github/installations/authorize", {
    cookie,
    body: { installationId: String(installationId) },
  });
  if (auth.status !== 200) return { auth, installationId };
  const state = new URL(auth.json.data.authorizeUrl).searchParams.get("state");
  const link = await w.api("POST", "/integrations/github/installations", {
    cookie,
    body: { code, state },
  });
  return { auth, state, code, link, installationId };
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
{
  const add = group("GitHub integration: linking");
  const asA = () => S("admin")(w);
  const scenario = () =>
    once("scm-linking", async () => {
      const edge = await edgeTenant();
      const user = ghUser();
      const account = orgAccount("a");
      const adminLink = await linkFlow(asA(), { account, user, orgRole: "admin" });
      // tenant E (a different tenant) tries to link the very same installation with a perfectly valid GitHub user
      const sameInstallation = await (async () => {
        const code = `code-${randomBytes(6).toString("hex")}`;
        await stubCtl("/__control/code", {
          code,
          user,
          installationIds: [adminLink.installationId],
          orgRoles: { [account.login]: { role: "admin", state: "active" } },
        });
        const auth = await w.api("POST", "/integrations/github/installations/authorize", {
          cookie: edge.owner,
          body: { installationId: String(adminLink.installationId) },
        });
        const state = new URL(auth.json.data.authorizeUrl).searchParams.get("state");
        const link = await w.api("POST", "/integrations/github/installations", {
          cookie: edge.owner,
          body: { code, state },
        });
        return { auth, state, link };
      })();
      const memberAccount = orgAccount("m");
      const memberLink = await linkFlow(asA(), {
        account: memberAccount,
        user: ghUser(),
        orgRole: "member",
      });
      const personalUser = ghUser();
      const personalMismatch = await linkFlow(asA(), {
        account: { id: personalUser.id + 1, login: personalUser.login, type: "User" },
        user: personalUser,
      });
      const personalOwn = await linkFlow(asA(), {
        account: { id: personalUser.id, login: personalUser.login, type: "User" },
        user: personalUser,
      });
      const notListed = await linkFlow(asA(), {
        account: orgAccount("n"),
        user: ghUser(),
        orgRole: "admin",
        listed: false,
      });
      // state: single use, and bound to the tenant that asked for it
      const stateUse = await linkFlow(asA(), {
        account: orgAccount("s"),
        user: ghUser(),
        orgRole: "admin",
      });
      const reused = await w.api("POST", "/integrations/github/installations", {
        cookie: asA(),
        body: { code: stateUse.code, state: stateUse.state },
      });
      const foreignState = await (async () => {
        const installationId = nextInstallationId();
        const account = orgAccount("f");
        const u = ghUser();
        await stubCtl("/__control/installation", { id: installationId, account });
        const code = `code-${randomBytes(6).toString("hex")}`;
        await stubCtl("/__control/code", {
          code,
          user: u,
          installationIds: [installationId],
          orgRoles: { [account.login]: { role: "admin", state: "active" } },
        });
        const auth = await w.api("POST", "/integrations/github/installations/authorize", {
          cookie: asA(),
          body: { installationId: String(installationId) },
        });
        const state = new URL(auth.json.data.authorizeUrl).searchParams.get("state");
        return w.api("POST", "/integrations/github/installations", {
          cookie: edge.owner,
          body: { code, state },
        });
      })();
      const viewerStart = await w.api("POST", "/integrations/github/installations/start", {
        cookie: S("viewer")(w),
      });
      const listA = await w.api("GET", "/integrations/github/installations", { cookie: asA() });
      const listEdge = await w.api("GET", "/integrations/github/installations", {
        cookie: edge.owner,
      });
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
      if (text.includes(x.account.login) || text.includes(x.adminLink.link.json.data.id))
        problems.push("the refusal reveals the other tenant's link or account");
      if (
        !x.listA.json.data.items.some(
          (l) => l.id === x.adminLink.link.json.data.id && l.status === "linked",
        )
      )
        problems.push("the first tenant's link changed");
      if (x.listEdge.json.data.items.length !== 0)
        problems.push("the second tenant ended up with a link");
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
      return x.listA.json.data.items.some((l) => l.account.login === x.memberAccount.login)
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
    "only holders of integration.manage can start linking",
    FORBIDDEN,
    async () => (await scenario()).viewerStart,
  );
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
