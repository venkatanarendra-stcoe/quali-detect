/**
 * Security checks of the Organization overview (`OVR-*`, owner decision 2026-11-17, docs/AUTHORIZATION.md decision 30):
 * the tenant-scope `dashboard.view` belongs to the Admin built-in bundle ONLY. `GET /api/v1/overview` needs it (a visible
 * surface the caller may not use: 403, never 404), and the navigation, evaluated by the shared engine from the caller's
 * real `GET /me` permissions, shows "overview" only to a holder.
 *
 * The seeded demo users hold their roles at WORKSPACE scope, where a tenant-scope key never counts, so a plain login would
 * pass even with the old bundles. The per-role checks therefore assign each built-in role at TENANT scope (the only
 * assignment where a tenant-scope bundle key becomes effective) to one seeded user for the duration of the request, which
 * makes the check fail if a bundle regains the key.
 */
import { ORG_NAV_GROUPS, evaluateNavigation } from "@qmentisai/shared";

const OK = { status: 200 };
const FORBIDDEN = { status: 403, code: "FORBIDDEN" };
const UNAUTHENTICATED = { status: 401, code: "UNAUTHENTICATED" };
const INVALID = { status: 400, code: "VALIDATION_FAILED" };

const navIds = (permissions) =>
  evaluateNavigation(ORG_NAV_GROUPS, { permissions }).flatMap((g) => g.items.map((i) => i.id));

/**
 * @param {{ S: (name: string) => (world: any) => string, once: Function, db: () => any, withRole: Function, loginAs: (email: string) => Promise<string> }} deps
 * @returns {Array<{ id: string, name: string, expected: { status: number, code?: string }, run: (x: any) => Promise<any>, verify?: (r: any, x: any) => string[] | Promise<string[]> }>}
 */
export function buildOverviewChecks({ S, once, db, withRole, loginAs }) {
  const checks = [];
  const add = (id, name, expected, run, verify) => checks.push({ id, name, expected, run, verify });
  const roles = (x) =>
    once("ovr-roles", async () => {
      const r = await x.api("GET", "/roles?pageSize=100", { cookie: S("admin")(x) });
      return r.json.data;
    });
  const analyst = () => once("ovr-analyst", () => loginAs("demo.analyst@demo.example"));
  const envelope = (r) =>
    r.json?.success === true && typeof r.json?.meta?.correlationId === "string"
      ? []
      : ["the success envelope is incomplete"];

  add(
    "OVR-001",
    "tenant Admin: GET /overview answers 200 and the navigation shows the overview item",
    OK,
    async (x) => {
      const r = await x.api("GET", "/overview", { cookie: S("admin")(x) });
      r.me = (await x.api("GET", "/me", { cookie: S("admin")(x) })).json.data;
      return r;
    },
    (r) => [
      ...envelope(r),
      ...(Number.isInteger(r.json.data.accessibleWorkspaces)
        ? []
        : ["accessibleWorkspaces is not an integer"]),
      ...(JSON.stringify(Object.keys(r.json.data)) === '["accessibleWorkspaces"]'
        ? []
        : ["unexpected fields"]),
      ...(navIds(r.me.permissions).includes("overview")
        ? []
        : ["the Admin navigation lacks the overview item"]),
    ],
  );

  const perRole = [
    ["OVR-002", "manager", "Manager"],
    ["OVR-003", "lead", "Lead"],
    ["OVR-004", "security_analyst", "Security Analyst"],
    ["OVR-005", "dev_lead", "Dev Lead"],
    ["OVR-006", "developer", "Developer"],
    ["OVR-007", "viewer", "Guest / Viewer"],
  ];
  for (const [id, key, label] of perRole) {
    add(
      id,
      `built-in ${label} assigned at tenant scope: GET /overview answers 403 and the navigation has no overview item`,
      FORBIDDEN,
      async (x) => {
        const role = (await roles(x)).find((r) => r.key === key && r.kind === "built_in");
        if (!role) throw new Error(`fixture: built-in role ${key} not found`);
        const cookie = await analyst();
        return withRole({ userId: x.A.user, roleId: role.id, workspaceId: null }, async () => {
          const r = await x.api("GET", "/overview", { cookie });
          r.me = (await x.api("GET", "/me", { cookie })).json.data;
          r.role = role;
          return r;
        });
      },
      (r) => [
        ...(r.role.tenantPermissions.includes("dashboard.view")
          ? [`the ${r.role.key} bundle holds dashboard.view`]
          : []),
        ...(r.me.permissions.tenant.includes("dashboard.view")
          ? ["effective permissions include dashboard.view"]
          : []),
        ...(navIds(r.me.permissions).includes("overview")
          ? ["the navigation shows the overview item"]
          : []),
        // control: the tenant-scope assignment IS effective (every workspace visible), so the denial is not vacuous
        ...(r.me.permissions.workspaces.length >= 2
          ? []
          : ["the tenant-scope assignment did not take effect"]),
        ...(navIds(r.me.permissions).includes("workspaces")
          ? []
          : ["Workspaces disappeared from the navigation"]),
      ],
    );
  }

  add(
    "OVR-008",
    "database: only the Admin built-in bundle holds dashboard.view (no other built-in role, no stale row)",
    OK,
    async (x) => {
      const rows = await db().rolePermission.findMany({
        where: { permissionKey: "dashboard.view", role: { kind: "built_in" } },
        select: { role: { select: { key: true } } },
      });
      return { status: 200, json: null, holders: rows.map((r) => r.role.key).sort() };
    },
    (r) => (JSON.stringify(r.holders) === '["admin"]' ? [] : [`built-in holders: ${r.holders}`]),
  );

  add(
    "OVR-009",
    "custom roles: a tenant-scope custom role gains dashboard.view only when granted explicitly",
    OK,
    async (x) => {
      const admin = S("admin")(x);
      const make = async (permissions, label) => {
        const made = await x.api("POST", "/roles", {
          cookie: admin,
          body: { name: `ovr ${label} ${x.suffix}`, description: "overview check", permissions },
        });
        if (made.status !== 201) throw new Error(`fixture: custom role answered ${made.status}`);
        return made.json.data.id;
      };
      const without = await make(["workspace.view", "workspace.create"], "without");
      const withKey = await make(["workspace.view", "dashboard.view"], "with");
      const cookie = await analyst();
      const probe = (roleId) =>
        withRole({ userId: x.A.user, roleId, workspaceId: null }, () =>
          x.api("GET", "/overview", { cookie }),
        );
      const denied = await probe(without);
      const granted = await probe(withKey);
      return { status: granted.status, json: granted.json, denied: denied.status };
    },
    (r) => (r.denied === 403 ? [] : [`a custom role without the key answered ${r.denied}`]),
  );

  add(
    "OVR-010",
    "workspace dashboards are unaffected: the seeded Manager (workspace scope) still opens its workspace and lists it",
    OK,
    async (x) => {
      const manager = S("manager")(x);
      const ws = await x.api("GET", `/workspaces/${x.A.paymentsWs}`, { cookie: manager });
      const list = await x.api("GET", "/workspaces", { cookie: manager });
      const me = (await x.api("GET", "/me", { cookie: manager })).json.data;
      ws.problems = [
        ...(list.status === 200 && list.json.data.some((w) => w.id === x.A.paymentsWs)
          ? []
          : ["the workspace list lost the workspace"]),
        ...(me.permissions.workspaces
          .find((w) => w.id === x.A.paymentsWs)
          ?.permissions.includes("workspace.view")
          ? []
          : ["workspace.view is gone"]),
        ...(navIds(me.permissions).includes("workspaces") &&
        !navIds(me.permissions).includes("overview")
          ? []
          : [`navigation: ${navIds(me.permissions)}`]),
      ];
      return ws;
    },
    (r) => r.problems,
  );

  add(
    "OVR-011",
    "the seeded workspace-scope Manager and Viewer get 403 on /overview",
    FORBIDDEN,
    async (x) => {
      const m = await x.api("GET", "/overview", { cookie: S("manager")(x) });
      const v = await x.api("GET", "/overview", { cookie: S("viewer")(x) });
      m.problems =
        v.status === 403 && v.json?.error?.code === "FORBIDDEN"
          ? []
          : [`viewer answered ${v.status}`];
      return m;
    },
    (r) => r.problems,
  );

  add("OVR-012", "no session: GET /overview answers 401", UNAUTHENTICATED, (x) =>
    x.api("GET", "/overview"),
  );
  add("OVR-013", "a platform session cannot reach GET /overview (401)", UNAUTHENTICATED, (x) =>
    x.api("GET", "/overview", { cookie: S("sa")(x) }),
  );
  add(
    "OVR-014",
    "a forged tenantId or workspaceId in the query is a 400, never a scope",
    INVALID,
    (x) =>
      x.api("GET", `/overview?tenantId=${x.B.ws}&workspaceId=${x.A.paymentsWs}`, {
        cookie: S("admin")(x),
      }),
  );
  add(
    "OVR-015",
    "tenant isolation: a fresh tenant's owner sees only that tenant's one workspace, never tenant A's count",
    OK,
    async (x) => {
      // A fresh tenant (never touched by another check) with exactly one workspace.
      const p = await once("ovr-tenant-p", async () => {
        const t = await x.provisionTenant("ovrp");
        const made = await x.api("POST", "/workspaces", {
          cookie: t.owner,
          body: { name: `Overview ${x.suffix}` },
        });
        if (made.status !== 201) throw new Error(`fixture: workspace answered ${made.status}`);
        return t;
      });
      const mine = await x.api("GET", "/overview", { cookie: p.owner });
      const a = await x.api("GET", "/overview", { cookie: S("admin")(x) });
      mine.problems = [
        ...(mine.status === 200 && mine.json.data.accessibleWorkspaces === 1
          ? []
          : [`tenant P answered ${mine.status} ${JSON.stringify(mine.json?.data)}`]),
        ...(a.status === 200 && a.json.data.accessibleWorkspaces >= 2
          ? []
          : [`tenant A control answered ${a.status} ${JSON.stringify(a.json?.data)}`]),
      ];
      return mine;
    },
    (r) => r.problems,
  );
  return checks;
}
