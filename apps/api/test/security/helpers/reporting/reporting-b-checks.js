import { randomUUID } from "node:crypto";
import { createReportingReadRepository } from "@qmentisai/db";
import {
  BUILT_IN_ROLES,
  FORBIDDEN_REPORTING_DTO_KEYS,
  REPORTING_ROUTE_SCHEMAS,
} from "@qmentisai/shared";
import { createHintHandler } from "../../../../src/realtime/consumer.js";
import { createReportingEpochBumper } from "../../../../src/modules/reporting/read-cache.js";
import { attempt, mustAccept, mustReject } from "../pipeline-db.js";
import {
  CANARY_TAG,
  buildReportingData,
  createFakeRedis,
  dayOffset,
  makeUser,
  splitKeys,
  startReadApi,
} from "./reporting-b-fixtures.js";
import { readTx } from "../../../../../../packages/db/src/reporting/read/tx.js";

/**
 * Reporting Part B (read API) checks (ADR-008 area 20, docs/modules/reporting-dashboards/SPEC.md 16.2): `RPT-S01` (isolation, identical 404),
 * `RPT-S02` (permission matrix, 403 vs 404, the overview scope), `RPT-S03` (no-leak DTO, hostile input), `RPT-S04` (the role grants in use),
 * `RPT-S11` (cache scoping, epoch invalidation, Redis down). The REAL routes run behind a stub authentication chain (the permissions of a
 * principal are given by the check) with the real authorization middleware, scope resolvers, route kit validation, services, repository,
 * mappers and error handler; every read statement runs as the `qm_reporting_ro` role. Every denial has a control (the same call made
 * legitimately succeeds) so a check cannot pass vacuously. Metric VALUES are not asserted here (ADR-008 area 20 leaves them out); shapes,
 * scoping, authorization, leaks and the cache are.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const j = (v) => JSON.stringify(v);
const eq = (p, label, got, want) => {
  if (j(got) !== j(want)) p.push(`${label}: got ${j(got)}, want ${j(want)}`);
};
const UNKNOWN = "00000000-0000-4000-8000-0000000000bb";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/** The envelope without its per-request correlation id. */
const bare = (r) =>
  j({ status: r.status, ...r.json, meta: { ...r.json?.meta, correlationId: undefined } });

/** The twelve workspace reads and the overview: route name, the key the route needs, the path of a workspace. */
const WORKSPACE_ENDPOINTS = Object.freeze([
  { name: "posture", key: "finding.view", path: (ws) => `/reporting/posture?workspaceId=${ws}` },
  {
    name: "trends",
    key: "finding.view",
    path: (ws) => `/reporting/trends?workspaceId=${ws}&period=30`,
  },
  {
    name: "remediation",
    key: "finding.view",
    path: (ws) => `/reporting/remediation?workspaceId=${ws}&period=30`,
  },
  { name: "sla", key: "finding.view", path: (ws) => `/reporting/sla?workspaceId=${ws}` },
  { name: "aging", key: "finding.view", path: (ws) => `/reporting/aging?workspaceId=${ws}` },
  {
    name: "scan-activity",
    key: "execution.view",
    path: (ws) => `/reporting/scan-activity?workspaceId=${ws}&period=7`,
  },
  {
    name: "coverage",
    key: "execution.view",
    path: (ws) => `/reporting/coverage?workspaceId=${ws}`,
  },
  {
    name: "sbom",
    key: "execution.view",
    path: (ws) => `/reporting/sbom?workspaceId=${ws}&period=7`,
  },
  {
    name: "quality",
    key: "security_review.view",
    path: (ws) => `/reporting/quality?workspaceId=${ws}&period=30`,
  },
  {
    name: "breakdown",
    key: "finding.view",
    path: (ws) => `/reporting/breakdown?workspaceId=${ws}&by=repository`,
  },
  { name: "top-risk", key: "finding.view", path: (ws) => `/reporting/top-risk?workspaceId=${ws}` },
  {
    name: "workload",
    key: "finding.assign",
    path: (ws) => `/reporting/workload?workspaceId=${ws}`,
  },
]);
const OVERVIEW = Object.freeze({
  name: "overview",
  key: "dashboard.view",
  path: () => "/reporting/overview?period=7",
});

/** What each built-in role holds of the five section keys, written out HERE from SPEC 3 (independent of the bundles under test). */
const HOLDS = Object.freeze({
  admin: [
    "finding.view",
    "execution.view",
    "security_review.view",
    "finding.assign",
    "dashboard.view",
  ],
  manager: ["finding.view", "execution.view", "security_review.view"],
  lead: ["finding.view", "execution.view", "security_review.view"],
  security_analyst: ["finding.view", "execution.view", "security_review.view"],
  dev_lead: ["finding.view", "execution.view", "finding.assign"],
  developer: ["finding.view", "execution.view"],
  viewer: ["finding.view", "execution.view"],
  custom: ["execution.view"],
});

/** Builds (once) the data, the API, the principals and the fake Redis every check of this file shares. */
function bWorld(c) {
  c.__rptB ??= (async () => {
    const { db } = c;
    const w = await buildReportingData(c);
    const redis = createFakeRedis();
    const api = await startReadApi(db, { redis });
    const user = await makeUser(db, c.A, "principal");
    const userB = await makeUser(db, c.B, "principal-b");
    const allWs = [w.wsA0, w.wsA1];
    // the seven built-in roles, from the product's own bundles, assigned at tenant scope (workspace keys in every workspace)
    for (const role of BUILT_IN_ROLES) {
      const { workspace, tenant } = splitKeys(role.permissions);
      api.register(`role:${role.key}`, {
        userId: user.id,
        tenantId: w.tenantA,
        tenant,
        workspaces: allWs.map((id) => ({ id, permissions: workspace })),
      });
    }
    api.register("role:custom", {
      userId: user.id,
      tenantId: w.tenantA,
      workspaces: [{ id: w.wsA0, permissions: ["execution.view"] }],
    });
    // a tenant dashboard holder who sees ONE workspace (finding.view only), one who sees it with execution.view only
    api.register("ws0only", {
      userId: user.id,
      tenantId: w.tenantA,
      tenant: ["dashboard.view"],
      workspaces: [{ id: w.wsA0, permissions: ["finding.view"] }],
    });
    api.register("ws0exec", {
      userId: user.id,
      tenantId: w.tenantA,
      tenant: ["dashboard.view"],
      workspaces: [{ id: w.wsA0, permissions: ["execution.view"] }],
    });
    api.register("adminB", {
      userId: userB.id,
      tenantId: w.tenantB,
      tenant: ["dashboard.view"],
      workspaces: [
        {
          id: w.wsB0,
          permissions: ["finding.view", "execution.view", "security_review.view", "finding.assign"],
        },
      ],
    });
    return { ...w, redis, api, user };
  })();
  return c.__rptB;
}

/** Every key of a JSON value, at every depth. */
function* keysOf(value) {
  if (Array.isArray(value)) for (const v of value) yield* keysOf(v);
  else if (value && typeof value === "object")
    for (const [k, v] of Object.entries(value)) {
      yield k;
      yield* keysOf(v);
    }
}

export const REPORTING_B_CHECKS = [
  {
    id: "RPT-S01",
    name: "Reporting reads: another tenant's workspace, a workspace the caller cannot see and a workspace that does not exist answer the IDENTICAL 404 (status, code, message and body, correlation id aside) on all twelve workspace endpoints, before any data is read; the same call in the caller's own workspace answers 200 (control); a tenant or workspace parameter on the overview is a 400, a tenant parameter on a workspace read is a 400 (tenantId never comes from input); an unauthenticated call is 401",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      const { api } = w;
      for (const e of WORKSPACE_ENDPOINTS) {
        const control = await api.get("role:admin", e.path(w.wsA0));
        ok(
          p,
          control.status === 200,
          `${e.name}: control (own workspace) answered ${control.status}`,
        );
        const other = await api.get("role:admin", e.path(w.wsB0)); // tenant B's workspace
        const hidden = await api.get("ws0only", e.path(w.wsA1)); // a workspace this caller cannot see
        const missing = await api.get("role:admin", e.path(UNKNOWN));
        for (const [what, r] of [
          ["another tenant", other],
          ["a hidden workspace", hidden],
          ["a missing workspace", missing],
        ])
          ok(p, r.status === 404, `${e.name}: ${what} answered ${r.status}, not 404`);
        ok(
          p,
          bare(other) === bare(missing) && bare(hidden) === bare(missing),
          `${e.name}: the three 404 bodies differ`,
        );
        ok(
          p,
          !j(other.json).includes(w.wsB0),
          `${e.name}: the 404 echoes the foreign workspace id`,
        );
        const asB = await api.get("adminB", e.path(w.wsA0)); // tenant A's workspace as tenant B
        eq(p, `${e.name}: B reading A`, [asB.status, bare(asB)], [404, bare(missing)]);
        const own = await api.get("adminB", e.path(w.wsB0));
        ok(
          p,
          own.status === 200,
          `${e.name}: control (tenant B own workspace) answered ${own.status}`,
        );
        const withTenant = await api.get("role:admin", `${e.path(w.wsA0)}&tenantId=${w.tenantB}`);
        ok(
          p,
          withTenant.status === 400,
          `${e.name}: a tenantId parameter answered ${withTenant.status}`,
        );
        const anon = await api.get("nobody", e.path(w.wsA0));
        ok(p, anon.status === 401, `${e.name}: unauthenticated answered ${anon.status}`);
      }
      for (const extra of [
        `&workspaceId=${w.wsA0}`,
        `&tenantId=${w.tenantA}`,
        `&workspaceId=${w.wsB0}`,
      ]) {
        const r = await api.get("role:admin", `/reporting/overview?period=7${extra}`);
        ok(p, r.status === 400, `overview with ${extra.slice(1, 12)}: answered ${r.status}`);
      }
      const ctl = await api.get("role:admin", "/reporting/overview?period=7");
      ok(p, ctl.status === 200, `overview control answered ${ctl.status}`);
      return p;
    },
  },
  {
    id: "RPT-S01b",
    name: "Reporting module OFF (REPORTING_ENABLED not true): all thirteen read routes answer the same 404 as a route that does not exist for an authenticated caller who holds every permission, and the read database is never touched; switched on, the same calls answer 200 (control)",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      const off = await startReadApi(c.db, { redis: createFakeRedis(), enabled: false });
      const before = off.statements.length;
      off.register("admin", {
        userId: w.user.id,
        tenantId: w.tenantA,
        tenant: ["dashboard.view"],
        workspaces: [
          {
            id: w.wsA0,
            permissions: [
              "finding.view",
              "execution.view",
              "security_review.view",
              "finding.assign",
            ],
          },
        ],
      });
      const unknownRoute = await off.get("admin", "/reporting/no-such-metric");
      ok(p, unknownRoute.status === 404, "an unknown route is not a 404");
      for (const e of [...WORKSPACE_ENDPOINTS, OVERVIEW]) {
        const r = await off.get("admin", e.path(w.wsA0));
        ok(p, r.status === 404, `${e.name}: answered ${r.status} while the module is off`);
        ok(
          p,
          bare(r) === bare(unknownRoute),
          `${e.name}: the disabled 404 differs from an unknown route`,
        );
        const on = await w.api.get("role:admin", e.path(w.wsA0));
        ok(p, on.status === 200, `${e.name}: control (module on) answered ${on.status}`);
      }
      ok(p, off.statements.length === before, "the read database was used while the module is off");
      await off.close();
      return p;
    },
  },
  {
    id: "RPT-S02",
    name: "Reporting permission matrix (SPEC 3, docs/AUTHORIZATION.md 404 vs 403): for each of the seven built-in roles and a custom role, each of the thirteen endpoints answers 200 exactly when the role holds the section key (finding.view, execution.view, security_review.view, finding.assign, and tenant-scope dashboard.view for the overview) and 403 otherwise, never 404, in a visible workspace; a viewer of the workspace without the key is refused before any data is read",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      for (const role of [...BUILT_IN_ROLES.map((r) => r.key), "custom"]) {
        const holds = new Set(HOLDS[role]);
        const who = `role:${role}`;
        for (const e of [...WORKSPACE_ENDPOINTS, OVERVIEW]) {
          const r = await w.api.get(who, e.path(w.wsA0));
          const want = holds.has(e.key) ? 200 : 403;
          ok(p, r.status === want, `${role} ${e.name}: answered ${r.status}, want ${want}`);
          if (want === 403)
            ok(
              p,
              r.json?.success === false && !j(r.json).includes('"data"'),
              `${role} ${e.name}: a 403 carries data`,
            );
        }
      }
      // controls: the keys exist and are the ones the frozen map names
      eq(
        p,
        "frozen route permissions",
        [...WORKSPACE_ENDPOINTS, OVERVIEW].map((e) => e.key),
        [
          "finding.view",
          "finding.view",
          "finding.view",
          "finding.view",
          "finding.view",
          "execution.view",
          "execution.view",
          "execution.view",
          "security_review.view",
          "finding.view",
          "finding.view",
          "finding.assign",
          "dashboard.view",
        ],
      );
      return p;
    },
  },
  {
    id: "RPT-S02b",
    name: "Reporting overview scope (SPEC 3, decision 30): GET /reporting/overview needs tenant-scope dashboard.view (Admin only among the built-in roles), aggregates ONLY the workspaces the caller can see (a hidden workspace is ABSENT, never zero, and its counts are not in the totals or the top risk), and per visible workspace only the sections whose key the caller holds there (null otherwise); workload needs finding.assign and names people by display name only",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      const { api } = w;
      const admin = await api.get("role:admin", OVERVIEW.path());
      eq(
        p,
        "admin sees both workspaces",
        (admin.json?.data?.workspaces ?? []).map((x) => x.workspaceId).sort(),
        [w.wsA0, w.wsA1].sort(),
      );
      const wsAdmin = admin.json?.data?.workspaces?.find((x) => x.workspaceId === w.wsA0);
      ok(
        p,
        typeof wsAdmin?.open === "number" && typeof wsAdmin?.executions === "number",
        "admin sections are not numbers",
      );
      const one = await api.get("ws0only", OVERVIEW.path());
      ok(p, one.status === 200, `ws0only overview answered ${one.status}`);
      const list = one.json?.data?.workspaces ?? [];
      eq(
        p,
        "only the visible workspace is listed",
        list.map((x) => x.workspaceId),
        [w.wsA0],
      );
      ok(p, !j(one.json).includes(w.wsA1), "the hidden workspace id appears in the overview");
      ok(
        p,
        list[0]?.executions === null && list[0]?.successRate === null,
        "a section without its key is not null (executions)",
      );
      ok(p, typeof list[0]?.open === "number", "a section with its key is missing (open)");
      ok(
        p,
        one.json?.data?.totals?.open === list[0]?.open,
        "the totals include a workspace the caller cannot see",
      );
      ok(
        p,
        admin.json?.data?.totals?.open > one.json?.data?.totals?.open,
        "control: the admin total is not larger than the one-workspace total",
      );
      const hiddenRepos = new Set((admin.json?.data?.topRisk ?? []).map((x) => x.repositoryId));
      ok(p, hiddenRepos.size > 0, "control: the admin top risk is empty");
      const exec = await api.get("ws0exec", OVERVIEW.path());
      const e0 = exec.json?.data?.workspaces?.[0];
      ok(
        p,
        e0?.open === null && e0?.bySeverity === null && e0?.slaBreached === null,
        "execution.view only: finding counts are not null",
      );
      ok(p, typeof e0?.executions === "number", "execution.view only: executions are missing");
      eq(p, "no finding key, no top risk", exec.json?.data?.topRisk, []);
      eq(p, "no finding key, zero totals", exec.json?.data?.totals?.open, 0);
      const b = await api.get("adminB", OVERVIEW.path());
      eq(
        p,
        "tenant B sees only its own workspace",
        (b.json?.data?.workspaces ?? []).map((x) => x.workspaceId),
        [w.wsB0],
      );
      ok(
        p,
        !j(b.json).includes(w.wsA0) && !j(b.json).includes(w.tenantA),
        "tenant B overview leaks tenant A",
      );
      // workload: finding.assign only, display names only
      const wl = await api.get("role:dev_lead", `/reporting/workload?workspaceId=${w.wsA0}`);
      ok(
        p,
        wl.status === 200 && (wl.json?.data?.assignees?.length ?? 0) >= 1,
        "control: workload for a finding.assign holder",
      );
      ok(p, !/@/.test(j(wl.json?.data)), "the workload carries an e-mail address");
      for (const a of wl.json?.data?.assignees ?? [])
        eq(p, "assignee shape", Object.keys(a.user).sort(), ["displayName", "id"]);
      for (const role of ["manager", "lead", "security_analyst", "developer", "viewer"]) {
        const r = await api.get(`role:${role}`, `/reporting/workload?workspaceId=${w.wsA0}`);
        ok(p, r.status === 403, `${role} workload answered ${r.status}`);
      }
      return p;
    },
  },
  {
    id: "RPT-S03",
    name: "Reporting no-leak DTO (RPT-011, SPEC 9 and 12): every response of every endpoint (all breakdown dimensions and pages, every trend series, the as-of posture, both workspaces and tenant B) parses against its frozen strict schema, contains none of the FORBIDDEN_REPORTING_DTO_KEYS at any depth, and none of the canary strings planted in evidence, scm ref, URL, rationale, comment, advisory reasoning, exception justification and controls, nor another tenant's ids or any tenant id",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      const { api } = w;
      const forbid = new Set(FORBIDDEN_REPORTING_DTO_KEYS.map((k) => k.toLowerCase()));
      const asOf = dayOffset(1);
      const requests = [
        ...WORKSPACE_ENDPOINTS.flatMap((e) => [
          { who: "role:admin", route: e.name, path: e.path(w.wsA0) },
          { who: "role:admin", route: e.name, path: e.path(w.wsA1) },
        ]),
        ...["repository", "pipeline", "scan_type", "rule"].map((by) => ({
          who: "role:admin",
          route: "breakdown",
          path: `/reporting/breakdown?workspaceId=${w.wsA0}&by=${by}&limit=2`,
        })),
        ...["flow", "severity", "backlog", "net_change", "awaiting_verification"].map((s) => ({
          who: "role:admin",
          route: "trends",
          path: `/reporting/trends?workspaceId=${w.wsA0}&period=90&series=${s}`,
        })),
        {
          who: "role:admin",
          route: "posture",
          path: `/reporting/posture?workspaceId=${w.wsA0}&asOf=${asOf}`,
        },
        { who: "role:admin", route: "overview", path: OVERVIEW.path() },
        { who: "role:admin", route: "overview", path: "/reporting/overview?period=90" },
        { who: "adminB", route: "posture", path: `/reporting/posture?workspaceId=${w.wsB0}` },
        { who: "adminB", route: "overview", path: OVERVIEW.path() },
      ];
      // a second breakdown page (the cursor)
      const first = await api.get(
        "role:admin",
        `/reporting/breakdown?workspaceId=${w.wsA0}&by=rule&limit=2`,
      );
      const cursor = first.json?.data?.nextCursor;
      ok(p, typeof cursor === "string", "control: the first breakdown page has no next cursor");
      if (cursor)
        requests.push({
          who: "role:admin",
          route: "breakdown",
          path: `/reporting/breakdown?workspaceId=${w.wsA0}&by=rule&limit=2&cursor=${cursor}`,
        });
      const schemaOf = (route) => REPORTING_ROUTE_SCHEMAS[`GET /reporting/${route}`];
      const foreign = (who) =>
        who === "adminB" ? [w.tenantA, w.wsA0, w.wsA1] : [w.tenantB, w.wsB0, w.fb.id];
      let walked = 0;
      for (const r of requests) {
        const res = await api.get(r.who, r.path);
        const label = `${r.who} ${r.path.slice(0, 70)}`;
        if (res.status !== 200) {
          p.push(`${label}: answered ${res.status}`);
          continue;
        }
        walked += 1;
        const s = schemaOf(r.route);
        const data = s.data.safeParse(res.json.data);
        ok(
          p,
          data.success,
          `${label}: data fails its strict schema (${data.success ? "" : j(data.error.issues[0])})`,
        );
        const meta = s.meta.safeParse(res.json.meta);
        ok(
          p,
          meta.success,
          `${label}: meta fails its strict schema (${meta.success ? "" : j(meta.error.issues[0])})`,
        );
        for (const key of keysOf(res.json))
          ok(p, !forbid.has(key.toLowerCase()), `${label}: forbidden key "${key}"`);
        const text = j(res.json);
        ok(p, !text.includes(CANARY_TAG), `${label}: a canary appears`);
        for (const id of foreign(r.who))
          ok(p, !text.includes(id), `${label}: a foreign id appears`);
        ok(
          p,
          !text.includes(r.who === "adminB" ? w.tenantB : w.tenantA),
          `${label}: the tenant id appears`,
        );
        ok(p, !/@\w+\.example/.test(text), `${label}: an e-mail address appears`);
        ok(
          p,
          ["live", "rollup"].includes(res.json.meta?.source) &&
            typeof res.json.meta?.stale === "boolean" &&
            typeof res.json.meta?.timeZone === "string",
          `${label}: meta lacks asOf, source, stale or timeZone`,
        );
      }
      ok(p, walked >= 36, `only ${walked} responses were walked`);
      // the planted canaries really exist where the views could have exposed them (control)
      const planted = await c.db.$queryRaw`
        SELECT (SELECT count(*) FROM finding_evidence WHERE snippet LIKE ${`%${CANARY_TAG}%`})::int AS ev,
               (SELECT count(*) FROM finding_reviews WHERE rationale LIKE ${`%${CANARY_TAG}%`})::int AS rev,
               (SELECT count(*) FROM finding_comments WHERE body LIKE ${`%${CANARY_TAG}%`})::int AS com,
               (SELECT count(*) FROM finding_ai_advisories WHERE reasoning LIKE ${`%${CANARY_TAG}%`})::int AS adv,
               (SELECT count(*) FROM finding_exceptions WHERE justification LIKE ${`%${CANARY_TAG}%`})::int AS exc`;
      for (const [k, n] of Object.entries(planted[0]))
        ok(p, n >= 1, `control: no canary planted in ${k}`);
      return p;
    },
  },
  {
    id: "RPT-S03b",
    name: "Reporting hostile input: an unknown query key, a period given twice, a period over 400 days, a future end, a bad series or dimension, an injection-shaped value, an out-of-range limit, an as-of day that is not in the past or that no rollup covers, and a breakdown cursor that is tampered with or minted for another workspace or dimension are all refused with a stable 4xx code (never a 500, never data), and the same request made legitimately succeeds",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      const { api } = w;
      const ws = `workspaceId=${w.wsA0}`;
      const expect = async (label, path, status, code) => {
        const r = await api.get("role:admin", path);
        ok(p, r.status === status, `${label}: answered ${r.status}, want ${status}`);
        if (code)
          ok(
            p,
            r.json?.error?.code === code,
            `${label}: code ${r.json?.error?.code}, want ${code}`,
          );
        ok(p, r.status < 500, `${label}: a server error`);
        if (status >= 400) ok(p, !r.json?.data, `${label}: carries data`);
      };
      await expect("unknown key", `/reporting/posture?${ws}&nope=1`, 400);
      await expect(
        "period and range",
        `/reporting/trends?${ws}&period=30&from=2026-01-01&to=2026-01-31`,
        400,
      );
      await expect("bad preset", `/reporting/trends?${ws}&period=45`, 400);
      await expect(
        "range too long",
        `/reporting/trends?${ws}&from=2025-01-01&to=${dayOffset(0)}`,
        400,
        "REPORT_PERIOD_TOO_LONG",
      );
      await expect(
        "future end",
        `/reporting/trends?${ws}&from=${dayOffset(1)}&to=${dayOffset(-3)}`,
        400,
        "REPORT_PERIOD_INVALID",
      );
      await expect(
        "from after to",
        `/reporting/trends?${ws}&from=${dayOffset(1)}&to=${dayOffset(5)}`,
        400,
      );
      await expect("bad series", `/reporting/trends?${ws}&series=flow,drop`, 400);
      await expect(
        "bad dimension",
        `/reporting/breakdown?${ws}&by=${encodeURIComponent("repository';--")}`,
        400,
      );
      await expect("limit too big", `/reporting/breakdown?${ws}&by=rule&limit=1000`, 400);
      await expect("top-risk limit", `/reporting/top-risk?${ws}&limit=500`, 400);
      await expect(
        "non-uuid workspace",
        `/reporting/sla?workspaceId=${encodeURIComponent("x' OR '1'='1")}`,
        400,
      );
      await expect(
        "as-of today",
        `/reporting/posture?${ws}&asOf=${dayOffset(0)}`,
        400,
        "REPORT_PERIOD_INVALID",
      );
      await expect("as-of not a day", `/reporting/posture?${ws}&asOf=2026-13-40`, 400);
      await expect(
        "as-of before any rollup",
        `/reporting/posture?${ws}&asOf=${dayOffset(40)}`,
        409,
        "REPORT_AS_OF_UNAVAILABLE",
      );
      await expect(
        "control: as-of a rolled-up day",
        `/reporting/posture?${ws}&asOf=${dayOffset(1)}`,
        200,
      );
      await expect(
        "control: a valid range",
        `/reporting/trends?${ws}&from=${dayOffset(10)}&to=${dayOffset(0)}`,
        200,
      );
      const page = await api.get("role:admin", `/reporting/breakdown?${ws}&by=rule&limit=2`);
      const cursor = page.json?.data?.nextCursor;
      ok(p, typeof cursor === "string", "control: no first cursor");
      if (typeof cursor === "string") {
        await expect(
          "control: the cursor of this request",
          `/reporting/breakdown?${ws}&by=rule&limit=2&cursor=${cursor}`,
          200,
        );
        const flipped = `${cursor.slice(0, -2)}${cursor.endsWith("AA") ? "BB" : "AA"}`;
        await expect(
          "tampered cursor",
          `/reporting/breakdown?${ws}&by=rule&limit=2&cursor=${flipped}`,
          400,
          "INVALID_CURSOR",
        );
        await expect(
          "cursor of another dimension",
          `/reporting/breakdown?${ws}&by=repository&limit=2&cursor=${cursor}`,
          400,
          "INVALID_CURSOR",
        );
        await expect(
          "cursor of another workspace",
          `/reporting/breakdown?workspaceId=${w.wsA1}&by=rule&limit=2&cursor=${cursor}`,
          400,
          "INVALID_CURSOR",
        );
        const asB = await api.get(
          "adminB",
          `/reporting/breakdown?workspaceId=${w.wsB0}&by=rule&limit=2&cursor=${cursor}`,
        );
        ok(p, asB.status === 400, `a cursor of another tenant answered ${asB.status}`);
        await expect(
          "garbage cursor",
          `/reporting/breakdown?${ws}&by=rule&limit=2&cursor=abc`,
          400,
          "INVALID_CURSOR",
        );
      }
      return p;
    },
  },
  {
    id: "RPT-S04",
    name: "Reporting role grants in use (SPEC 12 item 7): every one of the sixteen read-repository methods runs to completion acting as the read role qm_reporting_ro, which therefore needs nothing beyond the report views and tables; as that role a read of findings, finding_evidence, finding_reviews, finding_comments, users or tenant_llm_settings is refused, and so is any INSERT, UPDATE, DELETE or TRUNCATE of a report table or a source table, while a SELECT of a report view (control) succeeds",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      const { db } = c;
      const asRole = async (fn) =>
        attempt(() =>
          db.$transaction(async (tx) => {
            await tx.$executeRawUnsafe("SET LOCAL ROLE qm_reporting_ro");
            return fn(tx);
          }),
        );
      mustAccept(
        p,
        "the read role selects a report view",
        await asRole((tx) => tx.$queryRawUnsafe("SELECT count(*) FROM report_findings_v")),
      );
      for (const table of [
        "findings",
        "finding_evidence",
        "finding_reviews",
        "finding_comments",
        "finding_exceptions",
        "finding_ai_advisories",
        "users",
        "executions",
        "tenant_llm_settings",
      ])
        mustReject(
          p,
          `the read role reads ${table}`,
          await asRole((tx) => tx.$queryRawUnsafe(`SELECT count(*) FROM ${table}`)),
          "permission denied",
        );
      const day = dayOffset(0);
      for (const [label, sql] of [
        [
          "insert a rollup row",
          `INSERT INTO report_daily_sbom (tenant_id, workspace_id, repository_id, pipeline_id, day) VALUES ('${w.tenantA}', '${w.wsA0}', '${w.p1.pipeline.repositoryId}', '${w.p1.pipeline.id}', '${day}')`,
        ],
        ["update a rollup row", "UPDATE report_daily_findings SET open_count = 0"],
        ["delete a rollup row", "DELETE FROM report_daily_findings"],
        ["truncate a rollup table", "TRUNCATE report_daily_executions"],
        ["update a finding", "UPDATE findings SET title = 'x'"],
        ["delete a finding", "DELETE FROM findings"],
        ["update a report export", "UPDATE report_exports SET status = 'ready'"],
        [
          "write a run",
          `INSERT INTO report_rollup_runs (id, tenant_id, day, mode) VALUES ('${randomUUID()}', '${w.tenantA}', '${day}', 'close')`,
        ],
      ])
        mustReject(
          p,
          `the read role: ${label}`,
          await asRole((tx) => tx.$executeRawUnsafe(sql)),
          "permission denied",
        );
      // every method of the repository, through the read role, with arguments of the real shape
      const repo = createReportingReadRepository({ db: (await bWorld(c)).api.roDb });
      const scope = { tenantId: w.tenantA, workspaceId: w.wsA0 };
      const now = new Date();
      const from = dayOffset(10);
      const to = dayOffset(0);
      const start = new Date(now.getTime() - 10 * 86_400_000);
      const range = { from, to, start, endExclusive: now };
      const calls = {
        getTenantSettings: [{ tenantId: w.tenantA }],
        getRollupFreshness: [{ tenantId: w.tenantA }],
        getPosture: [{ ...scope, now, includePipelines: true }],
        getPostureAsOf: [{ ...scope, day: dayOffset(1) }],
        getTrends: [{ ...scope, from, to, series: ["flow"] }],
        getRemediation: [{ ...scope, ...range }],
        getSla: [{ ...scope, start, endExclusive: now, now }],
        getAging: [{ ...scope, now }],
        getScanActivity: [{ ...scope, ...range }],
        getCoverage: [{ ...scope, now, windowDays: 30 }],
        getSbom: [{ ...scope, from, to }],
        getQuality: [{ ...scope, ...range }],
        getBreakdown: [{ ...scope, by: "repository", limit: 5, after: null }],
        getTopRisk: [{ ...scope, limit: 5 }],
        getWorkload: [{ ...scope, now }],
        getOverview: [
          {
            tenantId: w.tenantA,
            workspaceIds: [w.wsA0],
            from,
            to,
            start,
            endExclusive: now,
            limit: 5,
          },
        ],
      };
      eq(p, "the sixteen methods", Object.keys(calls).sort(), Object.keys(repo).sort());
      for (const [method, args] of Object.entries(calls)) {
        const r = await attempt(() => repo[method](...args));
        mustAccept(p, `the read role runs ${method}`, r);
      }
      return p;
    },
  },
  {
    id: "RPT-S04b",
    name: "Reporting reads are read-only and bounded in the statements they issue: every repository transaction starts READ ONLY at repeatable read with a 5 second statement timeout, a write inside one is refused by the database (control: the same write in a plain transaction succeeds), and no statement of any method contains a write, DDL or lock verb, or lacks a tenant filter (every workspace statement also filters by workspace or workspaces)",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      const { db } = c;
      // 1. the transaction wrapper itself
      const runId = randomUUID();
      const insert = (tx) =>
        tx.$executeRaw`INSERT INTO report_rollup_runs (id, tenant_id, day, mode) VALUES (${runId}::uuid, ${w.tenantA}::uuid, ${dayOffset(0)}::date, 'close')`;
      const inReadTx = await attempt(() => readTx(db, (tx) => insert(tx)));
      mustReject(p, "a write inside the read transaction", inReadTx, "read-only");
      const settings = await readTx(db, async (tx) => ({
        level: (await tx.$queryRaw`SHOW transaction_isolation`)[0]?.transaction_isolation,
        readOnly: (await tx.$queryRaw`SHOW transaction_read_only`)[0]?.transaction_read_only,
        timeout: (await tx.$queryRaw`SHOW statement_timeout`)[0]?.statement_timeout,
      }));
      eq(p, "read transaction settings", settings, {
        level: "repeatable read",
        readOnly: "on",
        timeout: "5s",
      });
      const ROLLBACK = new Error("rollback");
      const plain = await attempt(() =>
        db.$transaction(async (tx) => {
          await insert(tx);
          throw ROLLBACK;
        }),
      );
      ok(
        p,
        plain.message.includes("rollback"),
        "control: the same write in a plain transaction was refused",
      );
      // 2. the statements of every method
      const seen = [];
      const spy = {
        $transaction: (fn, options) =>
          db.$transaction(async (tx) => {
            const record =
              (kind) =>
              (first, ...values) => {
                const text =
                  typeof first === "string"
                    ? first
                    : first.join("?") + values.map((v) => (v?.sql ? ` ${v.sql} ` : "")).join("");
                seen.push({ kind, text });
                return tx[kind](first, ...values);
              };
            const proxy = new Proxy(tx, {
              get: (target, prop) =>
                ["$queryRaw", "$executeRaw", "$queryRawUnsafe", "$executeRawUnsafe"].includes(prop)
                  ? record(prop)
                  : target[prop],
            });
            return fn(proxy);
          }, options),
      };
      const repo = createReportingReadRepository({ db: spy });
      const now = new Date();
      const scope = { tenantId: w.tenantA, workspaceId: w.wsA0 };
      const range = {
        from: dayOffset(10),
        to: dayOffset(0),
        start: new Date(now.getTime() - 10 * 86_400_000),
        endExclusive: now,
      };
      await repo.getTenantSettings({ tenantId: w.tenantA });
      await repo.getRollupFreshness({ tenantId: w.tenantA });
      await repo.getPosture({ ...scope, now, includePipelines: true });
      await repo.getPostureAsOf({ ...scope, day: dayOffset(1) });
      await repo.getTrends({ ...scope, ...range, series: [] });
      await repo.getRemediation({ ...scope, ...range });
      await repo.getSla({ ...scope, ...range, now });
      await repo.getAging({ ...scope, now });
      await repo.getScanActivity({ ...scope, ...range });
      await repo.getCoverage({ ...scope, now, windowDays: 30 });
      await repo.getSbom({ ...scope, from: range.from, to: range.to });
      await repo.getQuality({ ...scope, ...range });
      await repo.getBreakdown({ ...scope, by: "pipeline", limit: 5, after: null });
      await repo.getTopRisk({ ...scope, limit: 5 });
      await repo.getWorkload({ ...scope, now });
      await repo.getOverview({
        tenantId: w.tenantA,
        workspaceIds: [w.wsA0, w.wsA1],
        from: range.from,
        to: range.to,
        start: range.start,
        endExclusive: range.endExclusive,
        limit: 5,
      });
      ok(p, seen.length >= 30, `only ${seen.length} statements were recorded`);
      const setStatements = seen.filter((s) => /^\s*SET\b/i.test(s.text));
      ok(
        p,
        setStatements.some((s) => /READ ONLY/i.test(s.text)),
        "no READ ONLY statement",
      );
      ok(
        p,
        setStatements.some((s) => /statement_timeout/i.test(s.text)),
        "no statement_timeout statement",
      );
      const VERBS =
        /\b(INSERT|UPDATE|DELETE|TRUNCATE|DROP|ALTER|CREATE|GRANT|REVOKE|COPY|VACUUM|LOCK|CALL|DO)\b|FOR\s+(UPDATE|SHARE)|pg_advisory/i;
      for (const s of seen.filter((x) => !/^\s*SET\b/i.test(x.text))) {
        const t = s.text.replace(/\s+/g, " ");
        ok(p, !VERBS.test(t), `a statement has a write or lock verb: ${t.slice(0, 90)}`);
        ok(p, /^\s*(WITH|SELECT)\b/i.test(t), `a statement is not a SELECT: ${t.slice(0, 60)}`);
        ok(p, /tenant_id\s*=/i.test(t), `a statement has no tenant filter: ${t.slice(0, 90)}`);
        if (!/report_tenant_settings_v|report_rollup_runs|report_exports/i.test(t))
          ok(
            p,
            /workspace_id\s*(=|=\s*ANY)/i.test(t),
            `a statement has no workspace filter: ${t.slice(0, 90)}`,
          );
      }
      return p;
    },
  },
  {
    id: "RPT-S11",
    name: "Reporting cache scoping (SPEC 7.1, D-4, RPT-014): entries are written through the tenant-scoped cache under namespace rpt with the tenant of the SESSION in the key, so two tenants asking for the overview with identical parameters and one tenant asking for two workspaces with identical parameters each get their OWN data (a hit never crosses tenants or workspaces); no key of one tenant contains another tenant's id; callers with different permission sets (execution.view or not, different visible workspaces) never share an entry",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      const { api, redis } = w;
      redis.store.clear();
      redis.state.calls.length = 0;
      const a1 = await api.get("role:admin", OVERVIEW.path());
      const b1 = await api.get("adminB", OVERVIEW.path());
      const a2 = await api.get("role:admin", OVERVIEW.path()); // served from the cache
      const b2 = await api.get("adminB", OVERVIEW.path());
      const ids = (r) => (r.json?.data?.workspaces ?? []).map((x) => x.workspaceId).sort();
      eq(p, "A overview", ids(a1), [w.wsA0, w.wsA1].sort());
      eq(p, "B overview", ids(b1), [w.wsB0]);
      eq(p, "A overview again (a hit)", ids(a2), ids(a1));
      eq(p, "B overview again (a hit)", ids(b2), ids(b1));
      ok(
        p,
        redis.state.calls.some((x) => x[0] === "set"),
        "control: nothing was cached",
      );
      const keys = redis.keys();
      ok(
        p,
        keys.some((k) => k.startsWith(`qmentis:t:${w.tenantA}:cache:rpt:`)),
        "no tenant-A cache key of the expected shape",
      );
      ok(
        p,
        keys.some((k) => k.startsWith(`qmentis:t:${w.tenantB}:cache:rpt:`)),
        "no tenant-B cache key of the expected shape",
      );
      for (const k of keys.filter((x) => x.includes(":cache:rpt:"))) {
        const mine = k.startsWith(`qmentis:t:${w.tenantA}:`) ? w.tenantA : w.tenantB;
        const other = mine === w.tenantA ? w.tenantB : w.tenantA;
        ok(p, !k.includes(other), `a key contains another tenant's id: ${k.slice(0, 60)}`);
      }
      // the second call really was a hit: no second `set` for the same overview of tenant A
      const setsA = redis.state.calls.filter(
        (x) => x[0] === "set" && x[1].includes(`:t:${w.tenantA}:`) && x[1].includes(".overview."),
      );
      ok(p, setsA.length === 1, `the overview of tenant A was cached ${setsA.length} times`);
      // two workspaces of one tenant, identical parameters, different data
      const q0 = await api.get("role:admin", `/reporting/quality?workspaceId=${w.wsA0}&period=30`);
      const q1 = await api.get("role:admin", `/reporting/quality?workspaceId=${w.wsA1}&period=30`);
      const q0b = await api.get("role:admin", `/reporting/quality?workspaceId=${w.wsA0}&period=30`);
      const q1b = await api.get("role:admin", `/reporting/quality?workspaceId=${w.wsA1}&period=30`);
      ok(
        p,
        q0.json?.data?.falsePositiveRate?.overall?.denominator !==
          q1.json?.data?.falsePositiveRate?.overall?.denominator,
        "control: the two workspaces have the same quality data",
      );
      eq(p, "workspace 0 from the cache", q0b.json?.data, q0.json?.data);
      eq(p, "workspace 1 from the cache", q1b.json?.data, q1.json?.data);
      // permission sets: execution.view or not changes the posture DTO (pipelinesHealthy); never shared
      const withExec = await api.get("role:admin", `/reporting/posture?workspaceId=${w.wsA0}`);
      const noExec = await api.get("ws0only", `/reporting/posture?workspaceId=${w.wsA0}`);
      const noExec2 = await api.get("ws0only", `/reporting/posture?workspaceId=${w.wsA0}`);
      const withExec2 = await api.get("role:admin", `/reporting/posture?workspaceId=${w.wsA0}`);
      ok(
        p,
        withExec.json?.data?.pipelinesHealthy !== null,
        "control: pipelinesHealthy missing with execution.view",
      );
      ok(
        p,
        noExec.json?.data?.pipelinesHealthy === null,
        "pipelinesHealthy shown without execution.view",
      );
      ok(
        p,
        noExec2.json?.data?.pipelinesHealthy === null,
        "pipelinesHealthy shown from a shared cache entry (no execution.view)",
      );
      ok(
        p,
        withExec2.json?.data?.pipelinesHealthy !== null,
        "pipelinesHealthy lost from the cache (execution.view)",
      );
      // the overview of a caller who sees one workspace never gets the admin's cached entry
      const one = await api.get("ws0only", OVERVIEW.path());
      eq(p, "one-workspace overview after the admin's was cached", ids(one), [w.wsA0]);
      return p;
    },
  },
  {
    id: "RPT-S11b",
    name: "Reporting cache epoch (D-4): the epoch counter of (tenant, workspace) is read BEFORE the key is built; a cached live answer is served until the finding.changed hint of that workspace arrives, then ONE increment (made by the real hint handler on a verified finding hint, with the tenant and workspace of the database row) makes every live key of that workspace stale at once, while another workspace and another tenant keep their entries; a hint of a non-finding type does not move it",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      const { api, redis } = w;
      redis.store.clear();
      redis.state.calls.length = 0;
      const open = async (ws = w.wsA0) =>
        (await api.get("role:admin", `/reporting/posture?workspaceId=${ws}`)).json?.data?.open;
      const aging = async (ws = w.wsA0) =>
        (await api.get("role:admin", `/reporting/aging?workspaceId=${ws}`)).json?.data?.oldest
          ?.length;
      const before0 = await open();
      const beforeAging = await aging();
      const before1 = await open(w.wsA1);
      // ordering: the first Redis command of a request is the epoch read, and the cache key carries the epoch it read
      const calls = redis.state.calls;
      ok(
        p,
        calls[0]?.[0] === "get" && calls[0]?.[1].includes(":rptepoch:"),
        "the first Redis command is not the epoch read",
      );
      const firstKey = calls.find((x) => x[0] === "get" && x[1].includes(":cache:rpt:"))?.[1] ?? "";
      ok(
        p,
        new RegExp(`${w.wsA0}\\.posture\\.0\\.`).test(firstKey),
        `the key does not carry the epoch read first: ${firstKey.slice(-90)}`,
      );
      // a new open finding lands (a fixture write, no hint yet): the cached answers do not move
      await c.finding(w.p1.pipeline, {
        severity: "critical",
        toolSeverity: "critical",
        severityRank: 4,
        scanType: "sast",
        firstDetectedAt: new Date(),
      });
      eq(p, "cached posture before the hint", await open(), before0);
      eq(p, "cached aging before the hint", await aging(), beforeAging);
      // the REAL hint handler, on a verified finding message, bumps the epoch once
      const bump = createReportingEpochBumper({ redis, enabled: true });
      const target = { tenantId: w.tenantA, workspaceId: w.wsA0, findingId: w.F.f1.id };
      const emitted = [];
      const handler = createHintHandler({
        resolver: { targetOf: () => target },
        realtime: { emit: (h) => emitted.push(h) },
        onFindingChanged: bump,
      });
      await handler({
        type: "finding.created",
        tenantId: w.tenantA,
        payload: { findingId: w.F.f1.id, workspaceId: w.wsA0 },
      });
      ok(p, emitted.length === 1, "the hint was not emitted to the room (control)");
      eq(
        p,
        "the epoch of the workspace",
        redis.store.get(`qmentis:t:${w.tenantA}:rptepoch:${w.wsA0}`)?.value,
        "1",
      );
      eq(
        p,
        "the tenant-wide epoch",
        redis.store.get(`qmentis:t:${w.tenantA}:rptepoch:tenant`)?.value,
        "1",
      );
      ok(
        p,
        !redis.store.has(`qmentis:t:${w.tenantA}:rptepoch:${w.wsA1}`),
        "another workspace's epoch moved",
      );
      ok(
        p,
        ![...redis.store.keys()].some((k) => k.startsWith(`qmentis:t:${w.tenantB}:rptepoch`)),
        "another tenant's epoch moved",
      );
      eq(p, "posture after the hint", await open(), before0 + 1);
      ok(p, (await aging()) >= beforeAging, "aging after the hint");
      eq(p, "the other workspace is still cached", await open(w.wsA1), before1);
      // a message that is not a finding hint does not move the epoch
      await handler({
        type: "execution.started",
        tenantId: w.tenantA,
        payload: { executionId: randomUUID() },
      }).catch(() => {});
      eq(
        p,
        "the epoch after a non-finding message",
        redis.store.get(`qmentis:t:${w.tenantA}:rptepoch:${w.wsA0}`)?.value,
        "1",
      );
      // a failing Redis never fails the hint
      const failing = createFakeRedis();
      failing.state.mode = "error";
      const quiet = createReportingEpochBumper({ redis: failing, enabled: true });
      const r = await attempt(() => quiet({ tenantId: w.tenantA, workspaceId: w.wsA0 }));
      mustAccept(p, "a bump with Redis down", r);
      const off = createReportingEpochBumper({ redis, enabled: false });
      await off({ tenantId: w.tenantA, workspaceId: w.wsA1 });
      ok(
        p,
        !redis.store.has(`qmentis:t:${w.tenantA}:rptepoch:${w.wsA1}`),
        "a disabled module bumped the epoch",
      );
      return p;
    },
  },
  {
    id: "RPT-S11c",
    name: "Reporting cache fallback (D-4): with Redis failing, hanging or absent every endpoint still answers 200 with the right data, uncached and well inside the request budget (a cache problem never fails a request, and an unreadable epoch means no cache, never a stale hit); with Redis healthy again the cache is used again",
    async run(c) {
      const p = [];
      const w = await bWorld(c);
      const paths = [...WORKSPACE_ENDPOINTS.map((e) => e.path(w.wsA0)), OVERVIEW.path()];
      for (const mode of ["error", "hang"]) {
        const redis = createFakeRedis();
        redis.state.mode = mode;
        const api = await startReadApi(c.db, { redis });
        api.register("admin", {
          userId: w.user.id,
          tenantId: w.tenantA,
          tenant: ["dashboard.view"],
          workspaces: [
            {
              id: w.wsA0,
              permissions: [
                "finding.view",
                "execution.view",
                "security_review.view",
                "finding.assign",
              ],
            },
          ],
        });
        const started = Date.now();
        for (const path of paths) {
          const r = await api.get("admin", path);
          ok(p, r.status === 200, `Redis ${mode}: ${path.slice(0, 40)} answered ${r.status}`);
        }
        const per = (Date.now() - started) / paths.length;
        ok(p, per < 3000, `Redis ${mode}: ${Math.round(per)} ms per request`);
        ok(p, redis.store.size === 0, `Redis ${mode}: something was stored`);
        // the data equals the healthy answer
        const healthy = await w.api.get("role:admin", `/reporting/top-risk?workspaceId=${w.wsA0}`);
        const degraded = await api.get("admin", `/reporting/top-risk?workspaceId=${w.wsA0}`);
        eq(p, `Redis ${mode}: top risk`, degraded.json?.data, healthy.json?.data);
        // it recovers: the same client with Redis healthy again caches
        redis.state.mode = "ok";
        await api.get("admin", `/reporting/aging?workspaceId=${w.wsA0}`);
        ok(
          p,
          redis.keys().some((k) => k.includes(":cache:rpt:")),
          `Redis ${mode}: the cache is not used after recovery`,
        );
        await api.close();
      }
      // no Redis at all
      const none = await startReadApi(c.db, { redis: null });
      none.register("admin", {
        userId: w.user.id,
        tenantId: w.tenantA,
        workspaces: [{ id: w.wsA0, permissions: ["finding.view"] }],
      });
      const r = await none.get("admin", `/reporting/posture?workspaceId=${w.wsA0}`);
      ok(p, r.status === 200, `no Redis: answered ${r.status}`);
      await none.close();
      await sleep(0);
      return p;
    },
  },
];
