/**
 * Security checks of the user-preferences module (`PREF-*`, docs/modules/user-preferences/SPEC.md §14): `GET` and `PUT
 * /api/v1/me/preferences`. The route names no user and no tenant, so isolation is proven by forging them (body, query,
 * header) and by reading the rows back from the disposable database. Over HTTP, in the tenant-A demo world and in fresh
 * tenants created through the public API.
 */

const OK = { status: 200 };
const INVALID = { status: 400, code: "VALIDATION_FAILED" };
const UNAUTHENTICATED = { status: 401, code: "UNAUTHENTICATED" };
const SUSPENDED = { status: 403, code: "TENANT_SUSPENDED" };

/**
 * @param {{ S: (name: string) => (world: any) => string, once: <T>(key: string, fn: () => Promise<T>) => Promise<T>, db: () => any }} deps
 * @returns {Array<{ id: string, name: string, expected: { status: number, code?: string }, run: (x: any) => Promise<any>, verify?: (r: any, x: any) => Promise<string[]> | string[] }>}
 */
export function buildPreferenceChecks({ S, once, db, withRole, loginAs }) {
  const get = (x, cookie, options = {}) => x.api("GET", "/me/preferences", { cookie, ...options });
  const put = (x, cookie, body, options = {}) =>
    x.api("PUT", "/me/preferences", { cookie, body, ...options });
  /** A fresh tenant with its owner (never suspended by another check). */
  const tenantP = (x) => once("pref-tenant-p", () => x.provisionTenant("prefp"));
  /** A second fresh tenant that the suspension check suspends. */
  const tenantQ = (x) => once("pref-tenant-q", () => x.provisionTenant("prefq"));
  const meId = async (x, cookie) => (await x.api("GET", "/me", { cookie })).json.data.user.id;
  const rowsOf = (tenantId, userId) =>
    db().userPreference.findMany({ where: { tenantId, ...(userId ? { userId } : {}) } });
  const tenantIdOfA = async (x) =>
    (await x.api("GET", "/me", { cookie: S("admin")(x) })).json.data.tenant.id;
  const envelope = (r) =>
    r.json?.success === true && typeof r.json?.meta?.correlationId === "string"
      ? []
      : ["the success envelope is incomplete"];
  const onlyAccent = (r) =>
    JSON.stringify(Object.keys(r.json?.data ?? {})) === '["accent","defaultWorkspaceId"]'
      ? []
      : [`the DTO has the fields ${Object.keys(r.json?.data ?? {})}`];

  const checks = [];
  const add = (id, name, expected, run, verify) => checks.push({ id, name, expected, run, verify });

  add("PREF-001", "no session: GET /me/preferences", UNAUTHENTICATED, (x) => get(x));
  add(
    "PREF-002",
    "no session: PUT /me/preferences writes nothing",
    UNAUTHENTICATED,
    async (x) => {
      const before = await db().userPreference.count();
      const r = await put(x, undefined, { accent: "rose" });
      r.problems = (await db().userPreference.count()) === before ? [] : ["a row was written"];
      return r;
    },
    (r) => r.problems,
  );
  add(
    "PREF-003",
    "a platform session cannot reach the tenant route: GET and PUT answer 401 and PUT writes nothing",
    UNAUTHENTICATED,
    async (x) => {
      const before = await db().userPreference.count();
      const r = await get(x, S("sa")(x));
      const w = await put(x, S("sa")(x), { accent: "rose" });
      r.problems = [
        ...(w.status === 401 && w.json?.error?.code === "UNAUTHENTICATED"
          ? []
          : [`PUT answered ${w.status}`]),
        ...((await db().userPreference.count()) === before ? [] : ["a row was written"]),
      ];
      return r;
    },
    (r) => r.problems,
  );
  add(
    "PREF-004",
    "a tenant user without any special permission starts with the defaults and no row exists",
    OK,
    async (x) => {
      const p = await tenantP(x);
      const r = await get(x, p.owner);
      r.rows = await rowsOf(p.id);
      return r;
    },
    (r) => [
      ...(r.json.data.accent === "mint" ? [] : [`accent ${r.json.data.accent}`]),
      ...onlyAccent(r),
      ...envelope(r),
      ...(r.rows.length === 0 ? [] : ["reading created a row"]),
    ],
  );
  add(
    "PREF-005",
    "PUT saves the accent under the caller's own tenant and user, and GET reads it back",
    OK,
    async (x) => {
      const p = await tenantP(x);
      const r = await put(x, p.owner, { accent: "teal" });
      r.readBack = await get(x, p.owner);
      r.rows = await rowsOf(p.id);
      r.me = await meId(x, p.owner);
      return r;
    },
    (r) => [
      ...(r.json.data.accent === "teal" ? [] : [`PUT answered ${r.json.data.accent}`]),
      ...(r.readBack.json.data.accent === "teal" ? [] : ["GET did not return the saved accent"]),
      ...onlyAccent(r),
      ...envelope(r),
      ...(r.rows.length === 1 && r.rows[0].userId === r.me && r.rows[0].accent === "teal"
        ? []
        : ["the stored row is not the caller's"]),
    ],
  );
  add(
    "PREF-006",
    "PUT is idempotent: the same request twice gives the same answer and still one row",
    OK,
    async (x) => {
      const p = await tenantP(x);
      const first = await put(x, p.owner, { accent: "amber" });
      const second = await put(x, p.owner, { accent: "amber" });
      second.first = first;
      second.rows = await rowsOf(p.id);
      return second;
    },
    (r) => [
      ...(r.first.status === 200 ? [] : [`first PUT answered ${r.first.status}`]),
      ...(JSON.stringify(r.first.json.data) === JSON.stringify(r.json.data)
        ? []
        : ["the two answers differ"]),
      ...(r.rows.length === 1 && r.rows[0].accent === "amber" ? [] : ["not exactly one row"]),
    ],
  );
  const BAD_ACCENTS = ["indigo", "black", "white", "critical", "success", "MINT", "", null, 7];
  add(
    "PREF-007",
    "accents outside the palette (indigo, black, white, severity and status names, wrong case, empty, null, number) answer 400 and change nothing",
    INVALID,
    async (x) => {
      const p = await tenantP(x);
      await put(x, p.owner, { accent: "blue" });
      const problems = [];
      let last;
      for (const accent of BAD_ACCENTS) {
        last = await put(x, p.owner, { accent });
        if (last.status !== 400 || last.json?.error?.code !== "VALIDATION_FAILED")
          problems.push(`accent ${JSON.stringify(accent)} answered ${last.status}`);
      }
      const rows = await rowsOf(p.id);
      if (rows.length !== 1 || rows[0].accent !== "blue")
        problems.push("the stored accent changed");
      last.problems = problems;
      return last;
    },
    (r) => r.problems,
  );
  add(
    "PREF-008",
    "every palette key is accepted and the stored value is the key",
    OK,
    async (x) => {
      const p = await tenantP(x);
      const problems = [];
      for (const accent of [
        "mint",
        "violet",
        "blue",
        "cyan",
        "teal",
        "emerald",
        "amber",
        "orange",
        "rose",
      ]) {
        const r = await put(x, p.owner, { accent });
        if (r.status !== 200 || r.json.data.accent !== accent)
          problems.push(`${accent} answered ${r.status}`);
      }
      const last = await get(x, p.owner);
      last.problems = problems;
      return last;
    },
    (r) => r.problems,
  );
  add(
    "PREF-009",
    "forged userId, tenantId, extra fields, an empty body and an array body answer 400 and write nothing",
    INVALID,
    async (x) => {
      const p = await tenantP(x);
      const victim = await meId(x, S("admin")(x));
      const aTenant = await tenantIdOfA(x);
      await put(x, S("admin")(x), { accent: "violet" });
      const snapshot = async () => JSON.stringify([await rowsOf(aTenant), await rowsOf(p.id)]);
      const before = await snapshot();
      const bodies = [
        { accent: "rose", userId: victim },
        { accent: "rose", tenantId: aTenant },
        { accent: "rose", tenantId: p.id, userId: victim },
        { accent: "rose", extra: true },
        { userId: victim },
        {},
        [{ accent: "rose" }],
      ];
      const problems = [];
      let last;
      for (const body of bodies) {
        last = await put(x, p.owner, body);
        if (last.status !== 400 || last.json?.error?.code !== "VALIDATION_FAILED")
          problems.push(`${JSON.stringify(body)} answered ${last.status}`);
      }
      if ((await snapshot()) !== before) problems.push("a row changed");
      last.problems = problems;
      return last;
    },
    (r) => r.problems,
  );
  add(
    "PREF-010",
    "a userId or tenantId in the query string is a 400 on GET and PUT; the x-tenant-id header changes nothing",
    INVALID,
    async (x) => {
      const p = await tenantP(x);
      const victim = await meId(x, S("admin")(x));
      const aTenant = await tenantIdOfA(x);
      await put(x, S("admin")(x), { accent: "violet" });
      await put(x, p.owner, { accent: "emerald" });
      const problems = [];
      const q1 = await x.api("GET", `/me/preferences?userId=${victim}`, { cookie: p.owner });
      const q2 = await x.api("GET", `/me/preferences?tenantId=${aTenant}`, { cookie: p.owner });
      const q3 = await x.api("PUT", `/me/preferences?userId=${victim}`, {
        cookie: p.owner,
        body: { accent: "rose" },
      });
      for (const [label, r] of [
        ["GET userId", q1],
        ["GET tenantId", q2],
        ["PUT userId", q3],
      ])
        if (r.status !== 400 || r.json?.error?.code !== "VALIDATION_FAILED")
          problems.push(`${label} answered ${r.status}`);
      const h = await get(x, p.owner, { headers: { "x-tenant-id": aTenant } });
      if (h.status !== 200 || h.json.data.accent !== "emerald")
        problems.push("the x-tenant-id header changed the answer");
      const adminRows = await rowsOf(aTenant, victim);
      if (adminRows.length !== 1 || adminRows[0].accent !== "violet")
        problems.push("the other tenant's row changed");
      q1.problems = problems;
      return q1;
    },
    (r) => r.problems,
  );
  add(
    "PREF-011",
    "two users of one tenant keep separate preferences (admin, viewer and developer of tenant A), each stored under their own user",
    OK,
    async (x) => {
      const aTenant = await tenantIdOfA(x);
      const admin = S("admin")(x);
      const viewer = S("viewer")(x);
      const developer = S("developer")(x);
      const ids = {
        admin: await meId(x, admin),
        viewer: await meId(x, viewer),
        developer: await meId(x, developer),
      };
      await put(x, admin, { accent: "violet" });
      await put(x, viewer, { accent: "amber" });
      const problems = [];
      const seen = {
        admin: (await get(x, admin)).json.data.accent,
        viewer: (await get(x, viewer)).json.data.accent,
      };
      if (seen.admin !== "violet") problems.push(`admin reads ${seen.admin}`);
      if (seen.viewer !== "amber") problems.push(`viewer reads ${seen.viewer}`);
      const dev = await get(x, developer);
      const devRows = await rowsOf(aTenant, ids.developer);
      if (devRows.length === 0 && dev.json.data.accent !== "mint")
        problems.push(`developer (never saved) reads ${dev.json.data.accent}`);
      // the viewer's write did not touch the administrator's row
      await put(x, viewer, { accent: "orange" });
      const adminRow = (await rowsOf(aTenant, ids.admin))[0];
      if (adminRow?.accent !== "violet")
        problems.push("the viewer's write changed the admin's row");
      if ((await rowsOf(aTenant, ids.viewer))[0]?.accent !== "orange")
        problems.push("the viewer's own row was not updated");
      dev.problems = problems;
      return dev;
    },
    (r) => r.problems,
  );
  add(
    "PREF-012",
    "preferences of another tenant are invisible and untouched in both directions",
    OK,
    async (x) => {
      const p = await tenantP(x);
      const aTenant = await tenantIdOfA(x);
      const admin = S("admin")(x);
      const owner = await meId(x, p.owner);
      const adminId = await meId(x, admin);
      await put(x, admin, { accent: "cyan" });
      await put(x, p.owner, { accent: "rose" });
      const problems = [];
      const asP = await get(x, p.owner);
      const asA = await get(x, admin);
      if (asP.json.data.accent !== "rose")
        problems.push(`tenant P owner reads ${asP.json.data.accent}`);
      if (asA.json.data.accent !== "cyan")
        problems.push(`tenant A admin reads ${asA.json.data.accent}`);
      if ((await rowsOf(aTenant)).some((row) => row.userId === owner))
        problems.push("tenant P's owner has a row in tenant A");
      if ((await rowsOf(p.id)).some((row) => row.userId === adminId))
        problems.push("tenant A's admin has a row in tenant P");
      const body = JSON.stringify([asP.json, asA.json]);
      if (
        body.includes(p.id) ||
        body.includes(aTenant) ||
        body.includes(adminId) ||
        body.includes(owner)
      )
        problems.push("a response names a tenant or user identifier");
      asA.problems = problems;
      return asA;
    },
    (r) => r.problems,
  );
  add(
    "PREF-013",
    "a suspended tenant is refused for GET and PUT (403 TENANT_SUSPENDED) and PUT writes nothing; tenant P is unaffected",
    SUSPENDED,
    async (x) => {
      const q = await tenantQ(x);
      await put(x, q.owner, { accent: "orange" });
      const suspend = await x.api("POST", `/platform/tenants/${q.id}/suspend`, {
        cookie: S("sa")(x),
        body: { reason: "security regression suite", confirm: q.name },
      });
      const problems = suspend.status === 200 ? [] : [`suspend answered ${suspend.status}`];
      const r = await get(x, q.owner);
      const w = await put(x, q.owner, { accent: "rose" });
      if (w.status !== 403 || w.json?.error?.code !== "TENANT_SUSPENDED")
        problems.push(`PUT answered ${w.status}`);
      const rows = await rowsOf(q.id);
      if (rows.length !== 1 || rows[0].accent !== "orange")
        problems.push("the stored accent changed");
      const p = await tenantP(x);
      if ((await get(x, p.owner)).status !== 200) problems.push("tenant P was affected");
      r.problems = problems;
      return r;
    },
    (r) => r.problems,
  );

  // ---- default workspace preference and the post-login landing (owner decision 2026-11-17; PREF-014..021, LAND-001..008).
  const NOT_FOUND = { status: 404, code: "RESOURCE_NOT_FOUND" };
  const FORBIDDEN_Q = { status: 400, code: "VALIDATION_FAILED" };
  const landing = (x, cookie, options = {}) => x.api("GET", "/me/landing", { cookie, ...options });
  const strip = (r) =>
    JSON.stringify({ status: r.status, error: r.json?.error, data: r.json?.data });
  /** Tenant P (fresh) with two workspaces created by its owner (an administrator of both). */
  const tenantPWorkspaces = (x) =>
    once("pref-tenant-p-workspaces", async () => {
      const p = await tenantP(x);
      const ids = [];
      for (const label of ["One", "Two"]) {
        const made = await x.api("POST", "/workspaces", {
          cookie: p.owner,
          body: { name: `Pref ${label} ${x.suffix}` },
        });
        if (made.status !== 201) throw new Error(`fixture: workspace answered ${made.status}`);
        ids.push(made.json.data.id);
      }
      return { p, ids };
    });
  const setRow = async (tenantId, userId, defaultWorkspaceId) =>
    db().userPreference.upsert({
      where: { tenantId_userId: { tenantId, userId } },
      create: { tenantId, userId, defaultWorkspaceId },
      update: { defaultWorkspaceId },
    });
  const envelopeOk = (r) =>
    r.json?.success === true && typeof r.json?.meta?.correlationId === "string"
      ? []
      : ["the success envelope is incomplete"];

  add(
    "PREF-014",
    "PUT saves an accessible workspace as the default (own tenant and user), GET reads it back, null clears it, and the accent is untouched",
    OK,
    async (x) => {
      const { p, ids } = await tenantPWorkspaces(x);
      await put(x, p.owner, { accent: "teal" });
      const r = await put(x, p.owner, { defaultWorkspaceId: ids[0] });
      r.readBack = await get(x, p.owner);
      r.rows = await rowsOf(p.id);
      r.me = await meId(x, p.owner);
      r.cleared = await put(x, p.owner, { defaultWorkspaceId: null });
      r.after = await rowsOf(p.id);
      return r;
    },
    (r) => [
      ...(r.readBack.json.data.defaultWorkspaceId === r.json.data.defaultWorkspaceId &&
      typeof r.json.data.defaultWorkspaceId === "string"
        ? []
        : ["GET did not return the saved default"]),
      ...(r.json.data.accent === "teal" ? [] : ["the accent changed"]),
      ...onlyAccent(r),
      ...envelopeOk(r),
      ...(r.rows.length === 1 &&
      r.rows[0].userId === r.me &&
      r.rows[0].defaultWorkspaceId === r.json.data.defaultWorkspaceId
        ? []
        : ["the stored row is not the caller's"]),
      ...(r.cleared.status === 200 &&
      r.cleared.json.data.defaultWorkspaceId === null &&
      r.after[0].defaultWorkspaceId === null &&
      r.after[0].accent === "teal"
        ? []
        : ["null did not clear the default (or touched the accent)"]),
    ],
  );
  add(
    "PREF-015",
    "a default workspace of ANOTHER tenant, of a workspace the caller cannot see and a non-existent id all answer the same 404, and nothing is written",
    NOT_FOUND,
    async (x) => {
      const { ids } = await tenantPWorkspaces(x);
      const manager = S("manager")(x);
      const managerId = await meId(x, manager);
      const aTenant = await tenantIdOfA(x);
      const before = JSON.stringify(await rowsOf(aTenant, managerId));
      const foreign = await put(x, manager, { defaultWorkspaceId: ids[0] });
      const hidden = await put(x, manager, { defaultWorkspaceId: x.A.identityWs });
      const missing = await put(x, manager, { defaultWorkspaceId: x.UNKNOWN });
      const problems = [];
      for (const [label, r] of [
        ["foreign", foreign],
        ["hidden", hidden],
        ["missing", missing],
      ])
        if (r.status !== 404 || r.json?.error?.code !== "RESOURCE_NOT_FOUND")
          problems.push(`${label} answered ${r.status}`);
      const shape = (r) => JSON.stringify(r.json?.error);
      if (shape(foreign) !== shape(hidden) || shape(hidden) !== shape(missing))
        problems.push("the three refusals are distinguishable");
      if (JSON.stringify(await rowsOf(aTenant, managerId)) !== before)
        problems.push("a refused PUT changed a row");
      hidden.problems = problems;
      return hidden;
    },
    (r) => r.problems,
  );
  add(
    "PREF-016",
    "default workspace validation: non-uuid, empty, number, object, array and boolean answer 400, null and a visible workspace are accepted, forged tenantId/userId stay 400",
    FORBIDDEN_Q,
    async (x) => {
      const { p, ids } = await tenantPWorkspaces(x);
      const problems = [];
      let last;
      for (const value of ["not-a-uuid", "", 7, {}, [], true, " "]) {
        last = await put(x, p.owner, { defaultWorkspaceId: value });
        if (last.status !== 400 || last.json?.error?.code !== "VALIDATION_FAILED")
          problems.push(`${JSON.stringify(value)} answered ${last.status}`);
      }
      for (const body of [
        { defaultWorkspaceId: ids[1], tenantId: p.id },
        { defaultWorkspaceId: ids[1], userId: await meId(x, p.owner) },
      ]) {
        const r = await put(x, p.owner, body);
        if (r.status !== 400)
          problems.push(`${JSON.stringify(Object.keys(body))} answered ${r.status}`);
      }
      const ok = await put(x, p.owner, { defaultWorkspaceId: ids[1], accent: "amber" });
      if (
        ok.status !== 200 ||
        ok.json.data.defaultWorkspaceId !== ids[1] ||
        ok.json.data.accent !== "amber"
      )
        problems.push("a valid combined PUT failed");
      last.problems = problems;
      return last;
    },
    (r) => r.problems,
  );
  add(
    "PREF-017",
    "tenant isolation of the row: another tenant's user and the demo tenant never see the saved default; the row is under the caller's own tenant and user",
    OK,
    async (x) => {
      const { p, ids } = await tenantPWorkspaces(x);
      await put(x, p.owner, { defaultWorkspaceId: ids[0] });
      const aTenant = await tenantIdOfA(x);
      const admin = S("admin")(x);
      await put(x, admin, { defaultWorkspaceId: x.A.paymentsWs });
      const asA = await get(x, admin);
      const asP = await get(x, p.owner);
      const problems = [];
      if (asA.json.data.defaultWorkspaceId !== x.A.paymentsWs)
        problems.push("A admin lost the default");
      if (asP.json.data.defaultWorkspaceId !== ids[0]) problems.push("P owner lost the default");
      const body = JSON.stringify([asA.json.data, asP.json.data]);
      if (body.includes(x.A.identityWs)) problems.push("a response names a foreign workspace");
      const rowsP = await rowsOf(p.id);
      const rowsA = await rowsOf(aTenant);
      if (rowsP.some((row) => row.defaultWorkspaceId === x.A.paymentsWs))
        problems.push("tenant P's row points into tenant A");
      if (rowsA.some((row) => row.defaultWorkspaceId === ids[0]))
        problems.push("tenant A's row points into tenant P");
      // the database refuses a pointer into another tenant (composite foreign key), even with direct writes
      let crossRefused = false;
      try {
        await setRow(aTenant, await meId(x, S("viewer")(x)), ids[0]);
      } catch {
        crossRefused = true;
      }
      if (!crossRefused) problems.push("the database accepted a pointer into another tenant");
      await put(x, admin, { defaultWorkspaceId: null });
      asA.problems = problems;
      return asA;
    },
    (r) => r.problems,
  );
  add(
    "PREF-018",
    "the preference never grants access: a pointer written straight into the database at a hidden workspace opens nothing, GET reads null, and the landing ignores it (row untouched)",
    OK,
    async (x) => {
      const manager = S("manager")(x);
      const managerId = await meId(x, manager);
      const aTenant = await tenantIdOfA(x);
      await setRow(aTenant, managerId, x.A.identityWs);
      try {
        const ws = await x.api("GET", `/workspaces/${x.A.identityWs}`, { cookie: manager });
        const prefs = await get(x, manager);
        const land = await landing(x, manager);
        const row = (await rowsOf(aTenant, managerId))[0];
        prefs.problems = [
          ...(ws.status === 404 ? [] : [`the hidden workspace answered ${ws.status}`]),
          ...(prefs.json.data.defaultWorkspaceId === null ? [] : ["GET reveals the stale pointer"]),
          ...(land.json.data.target === "workspace" && land.json.data.workspaceId === x.A.paymentsWs
            ? []
            : [`landing answered ${JSON.stringify(land.json?.data)}`]),
          ...(row.defaultWorkspaceId === x.A.identityWs
            ? []
            : ["the stale pointer was auto-cleared"]),
          ...(JSON.stringify(land.json).includes(x.A.identityWs)
            ? ["the landing names the hidden workspace"]
            : []),
        ];
        return prefs;
      } finally {
        await setRow(aTenant, managerId, null);
      }
    },
    (r) => r.problems,
  );

  add("LAND-001", "no session: GET /me/landing answers 401", UNAUTHENTICATED, (x) => landing(x));
  add(
    "LAND-002",
    "a platform session cannot reach GET /me/landing (401) and a forged tenantId or workspaceId in the query is a 400",
    UNAUTHENTICATED,
    async (x) => {
      const r = await landing(x, S("sa")(x));
      const forged = await x.api("GET", `/me/landing?tenantId=${x.UNKNOWN}`, {
        cookie: S("admin")(x),
      });
      const forged2 = await x.api("GET", `/me/landing?workspaceId=${x.A.identityWs}`, {
        cookie: S("manager")(x),
      });
      r.problems = [forged, forged2].flatMap((f, i) =>
        f.status === 400 ? [] : [`forged ${i} answered ${f.status}`],
      );
      return r;
    },
    (r) => r.problems,
  );
  add(
    "LAND-003",
    "precedence for an administrator (holder of dashboard.view): no default = Overview, a default workspace wins, clearing it returns to Overview",
    OK,
    async (x) => {
      const admin = S("admin")(x);
      await put(x, admin, { defaultWorkspaceId: null });
      const none = await landing(x, admin);
      await put(x, admin, { defaultWorkspaceId: x.A.paymentsWs });
      const pref = await landing(x, admin);
      await put(x, admin, { defaultWorkspaceId: null });
      const again = await landing(x, admin);
      none.problems = [
        ...envelopeOk(none),
        ...(JSON.stringify(Object.keys(none.json.data)) === '["target","workspaceId"]'
          ? []
          : ["unexpected landing fields"]),
        ...(none.json.data.target === "overview" && none.json.data.workspaceId === null
          ? []
          : [`no default: ${JSON.stringify(none.json.data)}`]),
        ...(pref.json.data.target === "workspace" && pref.json.data.workspaceId === x.A.paymentsWs
          ? []
          : [`default: ${JSON.stringify(pref.json.data)}`]),
        ...(again.json.data.target === "overview"
          ? []
          : [`cleared: ${JSON.stringify(again.json.data)}`]),
      ];
      return none;
    },
    (r) => r.problems,
  );
  add(
    "LAND-004",
    "a non-administrator (workspace-scope Manager) never lands on the Overview: no default = its first accessible workspace, a default of an accessible workspace wins",
    OK,
    async (x) => {
      const dev = S("developer")(x); // developer in Payments, viewer in Identity: two accessible workspaces
      await put(x, dev, { defaultWorkspaceId: null });
      const first = await landing(x, dev);
      await put(x, dev, { defaultWorkspaceId: x.A.identityWs });
      const chosen = await landing(x, dev);
      await put(x, dev, { defaultWorkspaceId: null });
      const mgr = await landing(x, S("manager")(x));
      first.problems = [
        ...(first.json.data.target === "workspace" &&
        [x.A.paymentsWs, x.A.identityWs].includes(first.json.data.workspaceId)
          ? []
          : [`no default: ${JSON.stringify(first.json.data)}`]),
        ...(chosen.json.data.target === "workspace" &&
        chosen.json.data.workspaceId === x.A.identityWs
          ? []
          : [`default: ${JSON.stringify(chosen.json.data)}`]),
        ...(mgr.json.data.target === "workspace" && mgr.json.data.workspaceId === x.A.paymentsWs
          ? []
          : [`manager: ${JSON.stringify(mgr.json.data)}`]),
      ];
      return first;
    },
    (r) => r.problems,
  );
  add(
    "LAND-005",
    "stale default: access removed after the default was set falls back to the standard landing, identical to never having set one (no leak), the row is not cleared, and access returning restores it",
    OK,
    async (x) => {
      const manager = S("manager")(x);
      const managerId = await meId(x, manager);
      const aTenant = await tenantIdOfA(x);
      const viewerRole = (
        await x.api("GET", "/roles?pageSize=100", { cookie: S("admin")(x) })
      ).json.data.find((role) => role.key === "viewer" && role.kind === "built_in");
      await put(x, manager, { defaultWorkspaceId: null });
      const baseline = await landing(x, manager);
      const problems = [];
      let during;
      await withRole(
        { userId: managerId, roleId: viewerRole.id, workspaceId: x.A.identityWs },
        async () => {
          const set = await put(x, manager, { defaultWorkspaceId: x.A.identityWs });
          if (set.status !== 200)
            problems.push(`setting a default while accessible answered ${set.status}`);
          during = await landing(x, manager);
        },
      );
      const stale = await landing(x, manager);
      const stalePrefs = await get(x, manager);
      const row = (await rowsOf(aTenant, managerId))[0];
      if (during.json.data.workspaceId !== x.A.identityWs)
        problems.push("the default was not used while accessible");
      if (strip(stale) !== strip(baseline))
        problems.push("the stale landing differs from the baseline");
      if (JSON.stringify(stale.json).includes(x.A.identityWs))
        problems.push("the stale landing names the revoked workspace");
      if (stalePrefs.json.data.defaultWorkspaceId !== null)
        problems.push("GET /me/preferences reveals the stale default");
      if (row?.defaultWorkspaceId !== x.A.identityWs)
        problems.push("the stale default was auto-cleared");
      // access returns: the saved default applies again
      await withRole(
        { userId: managerId, roleId: viewerRole.id, workspaceId: x.A.identityWs },
        async () => {
          const back = await landing(x, manager);
          if (back.json.data.workspaceId !== x.A.identityWs)
            problems.push("returning access did not restore the default");
        },
      );
      await setRow(aTenant, managerId, null);
      stale.problems = problems;
      return stale;
    },
    (r) => r.problems,
  );
  add(
    "LAND-006",
    "a default workspace that is deleted never errors: the database clears the pointer (ON DELETE SET NULL on the pointer only) and the landing falls back",
    OK,
    async (x) => {
      const { p } = await tenantPWorkspaces(x);
      const made = await x.api("POST", "/workspaces", {
        cookie: p.owner,
        body: { name: `Doomed ${x.suffix}` },
      });
      const id = made.json.data.id;
      await put(x, p.owner, { defaultWorkspaceId: id });
      const withDefault = await landing(x, p.owner);
      const problems = [];
      if (withDefault.json.data.workspaceId !== id) problems.push("the default was not used");
      await db().userRoleAssignment.deleteMany({ where: { workspaceId: id } });
      await db().workspaceMember.deleteMany({ where: { workspaceId: id } });
      try {
        await db().workspace.delete({ where: { id } });
      } catch (error) {
        problems.push(`deleting the workspace failed: ${String(error.message).slice(0, 120)}`);
      }
      const row = (await rowsOf(p.id)).find((r) => r.userId !== undefined);
      if (row && row.defaultWorkspaceId === id) problems.push("the pointer survived the delete");
      if (row && !row.tenantId) problems.push("the row lost its tenant");
      const after = await landing(x, p.owner);
      if (after.status !== 200 || after.json.data.target !== "overview")
        problems.push(
          `landing after the delete: ${after.status} ${JSON.stringify(after.json?.data)}`,
        );
      after.problems = problems;
      return after;
    },
    (r) => r.problems,
  );
  add(
    "LAND-007",
    "a member with no accessible workspace and no dashboard.view lands on nothing (target none), never on another workspace or the Overview",
    OK,
    async (x) => {
      const aTenant = await tenantIdOfA(x);
      const email = `landnone.${x.suffix}@iso.example`;
      const user = await db().user.create({
        data: { email, name: "Landing None", status: "active" },
      });
      await db().tenantMembership.create({
        data: { tenantId: aTenant, userId: user.id, status: "active", joinedAt: new Date() },
      });
      const cookie = await loginAs(email);
      const r = await landing(x, cookie);
      const me = (await x.api("GET", "/me", { cookie })).json.data;
      r.problems = [
        ...(r.status === 200 && r.json.data.target === "none" && r.json.data.workspaceId === null
          ? []
          : [`landing: ${r.status} ${JSON.stringify(r.json?.data)}`]),
        ...(me.permissions.workspaces.length === 0
          ? []
          : ["fixture: the user has workspace access"]),
      ];
      return r;
    },
    (r) => r.problems,
  );
  add(
    "LAND-008",
    "the landing never reveals an inaccessible workspace: users with different hidden defaults get answers that contain only workspaces they can see",
    OK,
    async (x) => {
      const aTenant = await tenantIdOfA(x);
      const who = [
        ["manager", S("manager")(x)],
        ["lead", S("lead")(x)],
        ["viewer", S("viewer")(x)],
      ];
      const problems = [];
      for (const [label, cookie] of who) {
        const id = await meId(x, cookie);
        const me = (await x.api("GET", "/me", { cookie })).json.data;
        const visible = new Set(me.permissions.workspaces.map((w) => w.id));
        const hidden = [x.A.paymentsWs, x.A.identityWs].find((w) => !visible.has(w));
        if (!hidden) continue; // viewer sees both: nothing hidden to point at
        await setRow(aTenant, id, hidden);
        try {
          const r = await landing(x, cookie);
          const text = JSON.stringify(r.json);
          if (text.includes(hidden))
            problems.push(`${label}: the answer names the hidden workspace`);
          if (r.json.data.workspaceId && !visible.has(r.json.data.workspaceId))
            problems.push(`${label}: landed on a hidden workspace`);
        } finally {
          await setRow(aTenant, id, null);
        }
      }
      const last = await get(x, S("admin")(x));
      last.problems = problems;
      return last;
    },
    (r) => r.problems,
  );
  return checks;
}
