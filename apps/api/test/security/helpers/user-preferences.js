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
export function buildPreferenceChecks({ S, once, db }) {
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
    JSON.stringify(Object.keys(r.json?.data ?? {})) === '["accent"]'
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
  return checks;
}
