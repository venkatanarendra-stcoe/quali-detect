/**
 * Security regression suite (ADR-008). Scope, deliberately narrow: tenant isolation, 404/403 authorization behavior,
 * platform/tenant session separation, segregation of duties and the progressive sign-in/MFA throttling (ADR-010). Black box over HTTP against a running API: `scripts/security-suite.js` provisions a
 * disposable database, starts the API and sets SECURITY_* variables. Run with `pnpm test:security`.
 *
 * 68 of the 77 checks come from the audit in docs/STATUS_PHASE_1-4.md plus 9 THR (ADR-010) and 6 RST (tenant restore window, AUTHORIZATION Q25) checks added later. Controls (not counted in the 68) prove the legitimate
 * requests SUCCEED, so a transport that stops mounting routes cannot make the "expect 404 / 401" checks pass vacuously.
 */
import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import { createClient } from "./helpers/http.js";
import { buildWorld } from "./helpers/world.js";

const EXPECTED_CHECKS = 83;
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
