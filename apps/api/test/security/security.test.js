/**
 * Security regression suite (ADR-008). Scope, deliberately narrow: tenant isolation, 404/403 authorization behavior, and
 * platform/tenant session separation. Black box over HTTP against a running API: `scripts/security-suite.js` provisions a
 * disposable database, starts the API and sets SECURITY_* variables. Run with `pnpm test:security`.
 *
 * The 68 checks come from the audit in docs/STATUS_PHASE_1-4.md. Controls (not counted in the 68) prove the legitimate
 * requests SUCCEED, so a transport that stops mounting routes cannot make the "expect 404 / 401" checks pass vacuously.
 */
import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import { createClient } from "./helpers/http.js";
import { buildWorld } from "./helpers/world.js";

const EXPECTED_CHECKS = 68;
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
