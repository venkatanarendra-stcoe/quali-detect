import { randomBytes } from "node:crypto";
import { createDbClient, createReportingReadRepository } from "@qmentisai/db";
import {
  FORBIDDEN_REPORTING_DTO_KEYS,
  REPORTING_ROUTE_SCHEMAS,
  postureDtoSchema,
  trendPointSchema,
  trendsDtoSchema,
} from "@qmentisai/shared";
import { buildFindingsWorld } from "../findings/findings-world.js";
import { driveExecution } from "../execution-db.js";
import { attempt, mustAccept, mustReject } from "../pipeline-db.js";
import {
  dayOffset,
  daysAgo,
  hoursAgo,
  makeUser,
  startReadApi,
} from "./reporting-b-fixtures.js";

/**
 * Reporting amendment AM checks (ADR-008 area 20; docs/modules/reporting-dashboards/AS_BUILT_AM.md, SPEC 17.5): the three views added to the
 * read surface (`report_repositories_v`, `report_pipelines_v`, `report_sla_targets_v`), their grants and tenant scoping through a REAL
 * `qm_reporting_ro` login, the GitHub connection counts per tenant, and the FORWARD-ONLY state series (null before the first exact day, never a
 * 0). The checks run on their OWN two fresh tenants (a world of their own), so they neither depend on nor disturb the data of the other parts.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const eq = (p, label, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want))
    p.push(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
};
const VIEWS = ["report_repositories_v", "report_pipelines_v", "report_sla_targets_v"];
/** The source tables behind the three views: no reporting role may touch them. */
const BEHIND = ["repositories", "pipelines", "pipeline_config_versions", "finding_sla_targets"];
const ROLES = ["qm_reporting_ro", "qm_reporting"];
const hex = (n = 4) => randomBytes(n).toString("hex");

/** Runs `fn(tx)` as `role` in a transaction (the owner's connection with `SET LOCAL ROLE`). */
const asRole = (db, role, fn) =>
  db.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(`SET LOCAL ROLE ${role}`);
    return fn(tx);
  });

/** Sets columns of a finding with the transition triggers off for this transaction (a fixture, not a lifecycle). */
async function force(db, f, data) {
  await db.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT set_config('session_replication_role', 'replica', true)`;
    await tx.finding.update({ where: { tenantId_id: { tenantId: f.tenantId, id: f.id } }, data });
  });
}

/** The world of the AM checks: two fresh tenants, repositories in every connection state, pipelines with configurations, the read API. */
function amWorld(c) {
  c.__rptAM ??= (async () => {
    const { db } = c;
    const f = await buildFindingsWorld(db);
    const { A, B } = f;
    const tag = hex(4);
    const canary = (label) => `CANARY-AM-${label}-${tag}`;
    const wsA0 = A.ws[0].id;
    const wsA1 = A.ws[1].id;
    const wsB0 = B.ws[0].id;

    const addRepo = async (tree, wsIndex, name, extra = {}) => {
      const workspaceId = tree.ws[wsIndex].id;
      const wl = await db.scmWorkspaceLink.findFirst({
        where: { tenantId: tree.tenant.id, workspaceId },
      });
      return db.repository.create({
        data: {
          tenantId: tree.tenant.id,
          workspaceId,
          linkId: tree.link.id,
          workspaceLinkId: wl.id,
          provider: "github",
          externalRepoId: `am-${tag}-${name}`,
          fullName: `am-org/${tag}-${name}`,
          name,
          ownerLogin: "am-org",
          connectedByUserId: tree.user.id,
          ...extra,
        },
      });
    };
    const publish = async (tree, wsIndex, repo, config, extra = {}) => {
      const pipeline = await f.pipeline(tree, wsIndex, { repositoryId: repo.id, ...extra });
      const version = await f.version(pipeline, 1, {
        config: { schemaVersion: 1, triggers: [], ...config },
      });
      const updated = await db.pipeline.update({
        where: { id: pipeline.id },
        data: { currentVersion: 1, currentVersionId: version.id },
      });
      return { pipeline: updated, version };
    };
    const run = async (p, status, at) => {
      const e = await f.execution(p.pipeline, p.version, { requestedAt: at });
      await driveExecution(db, e.id, "running");
      await driveExecution(db, e.id, status);
      return e;
    };

    // tenant A, workspace 0: repo0 (the tree's own) active with an enabled pipeline that succeeded and a deleted one; rE active whose
    // enabled pipeline failed; rP active with only a disabled pipeline; rN active with none; rU unavailable; rD disconnected; rX archived
    const repo0 = await db.repository.update({
      where: { id: A.repo[0].id },
      data: {
        htmlUrl: `https://example.test/${canary("htmlurl")}`,
        description: canary("description"),
        lastSyncError: canary("syncerror"),
        disconnectReason: canary("reason"),
      },
    });
    const rE = await addRepo(A, 0, "rE");
    const rP = await addRepo(A, 0, "rP");
    const rN = await addRepo(A, 0, "rN");
    const rU = await addRepo(A, 0, "rU", { status: "unavailable" });
    const rD = await addRepo(A, 0, "rD", { status: "disconnected", disconnectedAt: new Date() });
    const rX = await addRepo(A, 0, "rX", { archived: true });
    const pA1 = await publish(
      A,
      0,
      repo0,
      {
        scans: { sca: { enabled: true }, sbom: { enabled: true }, sast: { enabled: false } },
        canaryNote: canary("config"),
      },
      { enabled: true, description: canary("pipedescription") },
    );
    const pA3 = await publish(
      A,
      0,
      repo0,
      { scans: { sca: { enabled: true } } },
      { enabled: true, deletedAt: new Date(), deletedByUserId: A.user.id },
    );
    const pA4 = await publish(A, 0, rE, { scans: { secrets: { enabled: true } } }, { enabled: true });
    const pA2 = await publish(A, 0, rP, { scans: { sast: { enabled: true } } }, { enabled: false });
    const pAU = await publish(A, 0, rU, { scans: { sca: { enabled: true } } }, { enabled: true });
    const pNoVersion = await f.pipeline(A, 0, { repositoryId: rN.id, enabled: false });
    await run(pA1, "succeeded", hoursAgo(5));
    await run(pA4, "failed", hoursAgo(6));
    // tenant A, workspace 1: only the tree's repository
    // tenant B: its repository plus one unavailable, a pipeline
    const rBU = await addRepo(B, 0, "rBU", { status: "unavailable" });
    const pB = await publish(B, 0, B.repo[0], { scans: { sast: { enabled: true } } }, { enabled: true });
    await run(pB, "succeeded", hoursAgo(4));
    // SLA targets: tenant A critical 10 hours, tenant B critical 9999 hours (high and the rest: the shared default)
    await db.findingSlaTarget.create({
      data: { tenantId: A.tenant.id, severity: "critical", hours: 10, updatedByUserId: A.user.id },
    });
    await db.findingSlaTarget.create({
      data: { tenantId: B.tenant.id, severity: "critical", hours: 9999, updatedByUserId: B.user.id },
    });
    // closed findings (verified 9 days ago): A critical 40 h after its clock started (over A's 10 h, under the 168 h default), A high 40 h
    // (under the 720 h default), B critical 400 h (over the 168 h default, under B's 9999 h)
    const closed = async (p, severity, hoursToFix) => {
      const started = daysAgo(20);
      const fnd = await f.finding(p.pipeline, {
        scanType: "sast",
        severity,
        toolSeverity: severity,
        severityRank: { critical: 4, high: 3 }[severity],
      });
      await force(db, fnd, {
        status: "verified_fixed",
        slaStartedAt: started,
        verifiedAt: new Date(started.getTime() + hoursToFix * 3_600_000),
        closedAt: new Date(started.getTime() + hoursToFix * 3_600_000),
        slaDueAt: null,
      });
      return fnd;
    };
    await closed(pA1, "critical", 40);
    await closed(pA1, "high", 40);
    await closed(pB, "critical", 400);

    // a REAL login of qm_reporting_ro, the repository on it
    const login = `qm_am_chk_${hex(3)}`;
    const password = randomBytes(16).toString("hex");
    await db.$executeRawUnsafe(
      `CREATE ROLE ${login} LOGIN PASSWORD '${password}' IN ROLE qm_reporting_ro`,
    );
    const url = new URL(process.env.SECURITY_DATABASE_URL);
    url.username = login;
    url.password = password;
    const readDb = createDbClient({ datasourceUrl: url.toString() });
    const repo = createReportingReadRepository({ db: readDb });

    // the API (no Redis: every call reads the database) with principals of both tenants
    const api = await startReadApi(db, { redis: null });
    const userA = await makeUser(db, A, "am");
    const userB = await makeUser(db, B, "am-b");
    api.register("am", {
      userId: userA.id,
      tenantId: A.tenant.id,
      workspaces: [
        { id: wsA0, permissions: ["finding.view", "execution.view"] },
        { id: wsA1, permissions: ["finding.view", "execution.view"] },
      ],
    });
    api.register("amNoExec", {
      userId: userA.id,
      tenantId: A.tenant.id,
      workspaces: [{ id: wsA0, permissions: ["finding.view"] }],
    });
    api.register("amB", {
      userId: userB.id,
      tenantId: B.tenant.id,
      workspaces: [{ id: wsB0, permissions: ["finding.view", "execution.view"] }],
    });
    return {
      f,
      A,
      B,
      tag,
      canary,
      wsA0,
      wsA1,
      wsB0,
      repos: { repo0, rE, rP, rN, rU, rD, rX, rBU },
      pipes: { pA1, pA2, pA3, pA4, pAU, pB, pNoVersion },
      login,
      readDb,
      repo,
      api,
    };
  })();
  return c.__rptAM;
}

/** A canary-free JSON text of a row set. */
const text = (rows) => JSON.stringify(rows, (_k, v) => (typeof v === "bigint" ? String(v) : v));

export const REPORTING_AM_CHECKS = [
  {
    id: "RPTAM-01",
    name: "Amendment views are redaction safe (SPEC 17.5, RPT-011): `report_repositories_v`, `report_pipelines_v` and `report_sla_targets_v` read as qm_reporting_ro return rows for the planted repositories, pipelines and SLA targets (controls) and NO cell of any row, serialised, holds a canary planted in the repository URL, description, sync error and disconnect reason, the pipeline description and a free key inside the configuration JSON, nor the configuration JSON itself, an owner, an e-mail or a user id; the repository view shows the connection state, enabled and archived flags exactly as stored; the pipeline view folds the CURRENT configuration version into the list of enabled scan types (sbom and sca for one, only the enabled one for another, none for a pipeline without a version, the deleted flag for a soft-deleted pipeline) and never shows a disabled type",
    async run(c) {
      const p = [];
      const w = await amWorld(c);
      const { db } = c;
      const tenant = w.A.tenant.id;
      const seen = await asRole(db, "qm_reporting_ro", async (tx) => ({
        repos: await tx.$queryRaw`SELECT * FROM report_repositories_v WHERE tenant_id = ${tenant}::uuid`,
        pipes: await tx.$queryRaw`SELECT * FROM report_pipelines_v WHERE tenant_id = ${tenant}::uuid`,
        sla: await tx.$queryRaw`SELECT * FROM report_sla_targets_v WHERE tenant_id = ${tenant}::uuid`,
      }));
      ok(p, seen.repos.length === 8, `control: ${seen.repos.length} repository rows, want 8`);
      ok(p, seen.pipes.length === 6, `control: ${seen.pipes.length} pipeline rows, want 6`);
      eq(p, "A's SLA target rows", seen.sla.map((r) => [r.severity, r.hours]), [["critical", 10]]);
      const serialised = text(seen);
      ok(p, !serialised.includes(w.tag), "a planted canary reached a reporting view");
      ok(p, !/canaryNote|schemaVersion|triggers/.test(serialised), "the configuration JSON leaked");
      ok(
        p,
        !serialised.includes(w.A.user.id) && !/@/.test(serialised),
        "a user id or an e-mail address leaked",
      );
      const byName = (n) => seen.repos.find((r) => r.repository_name === `am-org/${w.tag}-${n}`);
      const state = (n) => {
        const r = byName(n);
        return r ? [r.connection_status, r.enabled, r.archived] : null;
      };
      eq(p, "rU", state("rU"), ["unavailable", true, false]);
      eq(p, "rD", state("rD"), ["disconnected", true, false]);
      eq(p, "rX", state("rX"), ["active", true, true]);
      eq(p, "rE", state("rE"), ["active", true, false]);
      ok(p, byName("rE")?.provider === "github", "the provider is not shown");
      const pipe = (x) => seen.pipes.find((r) => r.pipeline_id === x.pipeline.id);
      eq(p, "pA1 types", pipe(w.pipes.pA1)?.scan_types_enabled, ["sbom", "sca"]);
      eq(p, "pA2 types", pipe(w.pipes.pA2)?.scan_types_enabled, ["sast"]);
      eq(p, "pA4 types", pipe(w.pipes.pA4)?.scan_types_enabled, ["secrets"]);
      eq(p, "pA3 deleted", [pipe(w.pipes.pA3)?.pipeline_deleted, pipe(w.pipes.pA3)?.enabled], [
        true,
        true,
      ]);
      eq(p, "pA2 enabled flag", pipe(w.pipes.pA2)?.enabled, false);
      const noVersion = seen.pipes.find((r) => r.pipeline_id === w.pipes.pNoVersion.id);
      eq(p, "a pipeline without a version", noVersion?.scan_types_enabled, []);
      ok(
        p,
        seen.pipes.every((r) => typeof r.pipeline_name === "string"),
        "a pipeline has no display name",
      );
      return p;
    },
  },
  {
    id: "RPTAM-02",
    name: "Amendment views grants (SPEC 12 item 7, 17.5): for the three new views BOTH reporting roles hold SELECT and nothing else (no INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES or TRIGGER), neither role holds any privilege on the source tables behind them (repositories, pipelines, pipeline_config_versions, finding_sla_targets), SELECT on those tables is denied as either role while the same SELECT works for the owner (control), a write through a view is denied as either role, and the views are plain views with the owner's rights (not security_invoker); the provisioning script grants the same three views",
    async run(c) {
      const p = [];
      const w = await amWorld(c);
      const { db } = c;
      for (const role of ROLES) {
        for (const view of VIEWS) {
          const [row] = await db.$queryRawUnsafe(
            `SELECT ${["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
              .map((x) => `has_table_privilege('${role}', 'public.${view}', '${x}') AS "${x}"`)
              .join(", ")}`,
          );
          eq(
            p,
            `${role} on ${view}`,
            Object.entries(row)
              .filter(([, v]) => v)
              .map(([k]) => k),
            ["SELECT"],
          );
        }
        for (const table of BEHIND) {
          const [row] = await db.$queryRawUnsafe(
            `SELECT ${["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
              .map((x) => `has_table_privilege('${role}', 'public.${table}', '${x}') AS "${x}"`)
              .join(", ")}`,
          );
          eq(
            p,
            `${role} on ${table}`,
            Object.entries(row)
              .filter(([, v]) => v)
              .map(([k]) => k),
            [],
          );
          mustReject(
            p,
            `${role} reads ${table}`,
            await attempt(() =>
              asRole(db, role, (tx) => tx.$queryRawUnsafe(`SELECT 1 FROM ${table} LIMIT 1`)),
            ),
            "permission denied",
          );
        }
        for (const sql of [
          "UPDATE report_sla_targets_v SET hours = 1",
          "DELETE FROM report_repositories_v",
          "INSERT INTO report_pipelines_v (tenant_id) VALUES (gen_random_uuid())",
        ])
          mustReject(
            p,
            `${role}: ${sql}`,
            await attempt(() => asRole(db, role, (tx) => tx.$executeRawUnsafe(sql))),
          );
      }
      for (const table of BEHIND)
        mustAccept(
          p,
          `the owner reads ${table}`,
          await attempt(() => db.$queryRawUnsafe(`SELECT 1 FROM ${table} LIMIT 1`)),
        );
      const views = await db.$queryRaw`
        SELECT c.relname AS name, c.relkind AS kind, c.reloptions AS options FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = ANY(${VIEWS})`;
      eq(p, "the three views exist", views.map((v) => v.name).sort(), [...VIEWS].sort());
      ok(p, views.every((v) => v.kind === "v"), "a new relation is not a plain view");
      ok(
        p,
        views.every((v) => !(v.options ?? []).some((o) => /security_invoker/.test(o))),
        "a new view is security_invoker",
      );
      const script = await import("node:fs").then((fs) =>
        fs.readFileSync(
          new URL("../../../../../../packages/db/scripts/provision-reporting-logins.js", import.meta.url),
          "utf8",
        ),
      );
      for (const view of VIEWS)
        ok(p, script.includes(`"${view}"`), `the provisioning script does not grant ${view}`);
      ok(p, w.tag.length > 0, "world");
      return p;
    },
  },
  {
    id: "RPTAM-03",
    name: "Amendment views are tenant scoped through a REAL qm_reporting_ro login (ADR-003, RPT-001): connected as a login member of the read group (not the owner, not a superuser), the real read repository answers the coverage, posture and SLA reads of tenant A with ONLY tenant A's repositories, pipelines and SLA hours and the same reads of tenant B with only tenant B's (controls: both answers are non-empty and differ), a read that names tenant B with tenant A's workspace returns nothing, and a direct read of each new view filtered by one tenant never returns a row of the other",
    async run(c) {
      const p = [];
      const w = await amWorld(c);
      const { repo, readDb } = w;
      const [who] = await readDb.$queryRaw`SELECT current_user AS u, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS su`;
      eq(p, "the read connection", [who.u, who.su], [w.login, false]);
      const now = new Date();
      const cov = (tenantId, workspaceId) => repo.getCoverage({ tenantId, workspaceId, now, windowDays: 30 });
      const a = await cov(w.A.tenant.id, w.wsA0);
      const b = await cov(w.B.tenant.id, w.wsB0);
      const idsOf = (x) => [...x.repositories.map((r) => r.repositoryId), ...x.pipelines.map((r) => r.pipelineId)];
      const aOwn = new Set(
        (
          await c.db.$queryRaw`SELECT id::text AS id FROM repositories WHERE tenant_id = ${w.A.tenant.id}::uuid UNION ALL SELECT id::text FROM pipelines WHERE tenant_id = ${w.A.tenant.id}::uuid`
        ).map((r) => r.id),
      );
      ok(p, a.repositories.length === 5 && a.pipelines.length === 4, `control: A has ${a.repositories.length} repositories and ${a.pipelines.length} pipelines, want 5 and 4`);
      ok(p, b.repositories.length === 2 && b.pipelines.length === 1, `control: B has ${b.repositories.length} repositories and ${b.pipelines.length} pipelines, want 2 and 1`);
      ok(p, idsOf(a).every((id) => aOwn.has(id)), "tenant A's coverage names a row that is not tenant A's");
      ok(p, idsOf(b).every((id) => !aOwn.has(id)), "tenant B's coverage names a row of tenant A");
      const cross = await cov(w.B.tenant.id, w.wsA0);
      eq(p, "tenant B asking for A's workspace", [cross.repositories.length, cross.pipelines.length], [0, 0]);
      const range = { start: new Date(now.getTime() - 30 * 86_400_000), endExclusive: new Date(now.getTime() + 1000) };
      const slaOf = async (tenantId, workspaceId) =>
        Object.fromEntries((await repo.getSla({ tenantId, workspaceId, ...range, now })).closed.map((r) => [r.severity, [r.withTarget, r.withinSla]]));
      eq(p, "A's closed SLA (critical over A's 10 h, high within the default)", await slaOf(w.A.tenant.id, w.wsA0), { critical: [1, 0], high: [1, 1] });
      eq(p, "B's closed SLA (critical within B's 9999 h)", await slaOf(w.B.tenant.id, w.wsB0), { critical: [1, 1] });
      const g = (tenantId, workspaceId) => repo.getPosture({ tenantId, workspaceId, now, includePipelines: true });
      const pa = await g(w.A.tenant.id, w.wsA0);
      const pb = await g(w.B.tenant.id, w.wsB0);
      ok(p, JSON.stringify(pa.connections) !== JSON.stringify(pb.connections), "control: both tenants show the same connections");
      for (const [tenant, other] of [
        [w.A.tenant.id, w.B.tenant.id],
        [w.B.tenant.id, w.A.tenant.id],
      ])
        for (const view of VIEWS) {
          const rows = await readDb.$queryRawUnsafe(`SELECT DISTINCT tenant_id::text AS t FROM ${view} WHERE tenant_id = $1::uuid`, tenant);
          ok(p, rows.every((r) => r.t === tenant) && rows.length === 1, `${view} filtered by one tenant returned ${JSON.stringify(rows)}`);
          ok(p, !rows.some((r) => r.t === other), `${view} leaked a row of another tenant`);
        }
      return p;
    },
  },
  {
    id: "RPTAM-04",
    name: "GitHub connection summary per tenant and workspace (SPEC 6.1, C-4, O-5): the posture read shows the repository counts by connection state of the REQUESTED workspace only, equal to an independent count of the repositories table (tenant A workspace 0: 5 active, 1 unavailable, 1 disconnected; workspace 1: 1 active; tenant B: 1 active, 1 unavailable), never another tenant's or workspace's, shown only to a caller with execution.view (null otherwise, like pipelines healthy), and `partial` is false for the live posture; pipelines healthy counts enabled, not deleted pipelines whose latest finished execution succeeded (tenant A workspace 0: 1 of 2); every response parses against the strict posture schema",
    async run(c) {
      const p = [];
      const w = await amWorld(c);
      const { api } = w;
      const truth = async (tenantId, workspaceId) => {
        const rows = await c.db.$queryRaw`SELECT status::text AS s, count(*)::int AS n FROM repositories WHERE tenant_id = ${tenantId}::uuid AND workspace_id = ${workspaceId}::uuid GROUP BY 1`;
        const out = { active: 0, unavailable: 0, disconnected: 0 };
        for (const r of rows) out[r.s] = r.n;
        return out;
      };
      const get = async (who, ws) => api.get(who, `/reporting/posture?workspaceId=${ws}`);
      const cases = [
        ["am", w.A.tenant.id, w.wsA0, { active: 5, unavailable: 1, disconnected: 1 }],
        ["am", w.A.tenant.id, w.wsA1, { active: 1, unavailable: 0, disconnected: 0 }],
        ["amB", w.B.tenant.id, w.wsB0, { active: 1, unavailable: 1, disconnected: 0 }],
      ];
      for (const [who, tenantId, ws, want] of cases) {
        const r = await get(who, ws);
        ok(p, r.status === 200, `${who} ${ws}: status ${r.status}`);
        eq(p, `${who} connections`, r.json?.data?.githubConnections, want);
        eq(p, `${who} connections equal the repositories table`, r.json?.data?.githubConnections, await truth(tenantId, ws));
        eq(p, `${who} partial`, r.json?.data?.partial, false);
        const parsed = postureDtoSchema.safeParse(r.json?.data);
        ok(p, parsed.success, `${who}: the posture does not parse: ${parsed.success ? "" : parsed.error.issues[0]?.message}`);
      }
      eq(p, "pipelines healthy, A workspace 0", (await get("am", w.wsA0)).json?.data?.pipelinesHealthy, { healthy: 1, total: 2 });
      eq(p, "pipelines healthy, B", (await get("amB", w.wsB0)).json?.data?.pipelinesHealthy, { healthy: 1, total: 1 });
      const noExec = await get("amNoExec", w.wsA0);
      ok(p, noExec.status === 200, `no execution.view: status ${noExec.status}`);
      eq(p, "no execution.view: connections", noExec.json?.data?.githubConnections, null);
      eq(p, "no execution.view: pipelines healthy", noExec.json?.data?.pipelinesHealthy, null);
      // another tenant's workspace is the same 404 as a missing one (the existing isolation), never counts
      const foreign = await api.get("amB", `/reporting/posture?workspaceId=${w.wsA0}`);
      ok(p, foreign.status === 404, `tenant B asking for A's workspace: ${foreign.status}`);
      ok(p, !JSON.stringify(foreign.json).includes('"active"'), "the foreign answer carries counts");
      return p;
    },
  },
  {
    id: "RPTAM-05",
    name: "Forward-only state series (SPEC 0.1 and 17.5, ADR-015 item 3): on a tenant whose first LIVE run (incremental or close; a backfill and a FAILED run never count) is day D, every state series (open by severity, backlog, awaiting verification) is an explicit null for each day before D and for each later day no live run wrote, and a number from D on; the flow series are numbers on every day a succeeded run of any kind covers and null elsewhere; `stateSeriesFrom` is D, `severityBackfilled` is always false even with a succeeded backfill run, a state row planted before D is still shown as null; the as-of posture of a day before D (covered only by the backfill) is 200 with partial true and every state field null, of a live day it carries numbers for the counters the rollup keeps and null for the statuses and groups it does not (never 0), and of a day no run covers it is the unavailable 409; each response parses against the strict schema",
    async run(c) {
      const p = [];
      const w = await amWorld(c);
      const { api, A, wsA0 } = w;
      const { db } = c;
      const tenant = A.tenant.id;
      const pa1 = w.pipes.pA1.pipeline;
      const d = dayOffset;
      const run = (day, mode, status, rangeTo = null) =>
        status === "failed"
          ? db.$executeRaw`INSERT INTO report_rollup_runs (id, tenant_id, day, range_to, mode, status, started_at, finished_at, rows_written, error_code, time_zone) VALUES (gen_random_uuid(), ${tenant}::uuid, ${day}::date, ${rangeTo}::date, ${mode}, 'failed', now() - interval '10 minutes', now() - interval '5 minutes', 0, 'internal', 'UTC')`
          : db.$executeRaw`INSERT INTO report_rollup_runs (id, tenant_id, day, range_to, mode, status, started_at, finished_at, rows_written, time_zone) VALUES (gen_random_uuid(), ${tenant}::uuid, ${day}::date, ${rangeTo}::date, ${mode}, 'succeeded', now() - interval '10 minutes', now() - interval '5 minutes', 1, 'UTC')`;
      const row = (day, v) =>
        db.$executeRaw`INSERT INTO report_daily_findings (tenant_id, workspace_id, repository_id, pipeline_id, day, scan_type, severity, open_count, backlog_count, wip_count, awaiting_verification_count, exceptions_in_force, new_count, fixed_count, closed_other_count, reopened_count)
          VALUES (${tenant}::uuid, ${wsA0}::uuid, ${pa1.repositoryId}::uuid, ${pa1.id}::uuid, ${day}::date, 'sast', ${v.severity ?? "critical"}::finding_severity, ${v.open ?? 0}, ${v.backlog ?? v.open ?? 0}, ${v.wip ?? 0}, ${v.av ?? 0}, ${v.exc ?? 0}, ${v.new ?? 0}, ${v.fixed ?? 0}, ${v.closed ?? 0}, ${v.reopened ?? 0})`;
      // a failed incremental long before D must not move it; a backfill covers d(40) to d(6)
      await run(d(12), "incremental", "failed");
      await run(d(40), "backfill", "succeeded", d(6));
      await run(d(5), "incremental", "succeeded");
      await run(d(3), "close", "succeeded");
      await row(d(20), { new: 2, fixed: 1 }); // flow of the backfill
      await row(d(8), { open: 4 }); // a state row that must not be shown (before D)
      await row(d(5), { open: 3, av: 1, wip: 1, backlog: 2, exc: 2 });
      await row(d(3), { open: 2 });
      const ws = `workspaceId=${wsA0}`;
      const trends = await api.get("am", `/reporting/trends?${ws}&period=30`);
      ok(p, trends.status === 200, `trends: status ${trends.status}`);
      const data = trends.json?.data;
      const parsedTrends = REPORTING_ROUTE_SCHEMAS["GET /reporting/trends"].data.safeParse(data);
      ok(p, parsedTrends.success, `trends do not parse: ${parsedTrends.success ? "" : JSON.stringify(parsedTrends.error.issues[0])}`);
      eq(p, "stateSeriesFrom", data?.stateSeriesFrom, d(5));
      eq(p, "severityBackfilled with a succeeded backfill run", data?.severityBackfilled, false);
      ok(p, data?.dataFrom === d(20), `dataFrom ${data?.dataFrom}`);
      const point = (day) => data?.points?.find((x) => x.day === day);
      const stateKeys = ["openBySeverity", "open", "awaitingVerification"];
      for (const n of [29, 25, 12, 10, 8, 7, 6, 4, 2, 1, 0])
        for (const k of stateKeys)
          ok(p, point(d(n))?.[k] === null, `${d(n)} ${k}: ${JSON.stringify(point(d(n))?.[k])}, want null`);
      for (const k of stateKeys) ok(p, k in (point(d(5)) ?? {}), `${d(5)} lacks ${k}`);
      eq(p, "open at D", point(d(5))?.open, 3);
      eq(p, "open by severity at D", point(d(5))?.openBySeverity?.critical, 3);
      eq(p, "awaiting verification at D", point(d(5))?.awaitingVerification, 1);
      eq(p, "open on the close day", point(d(3))?.open, 2);
      // flow: backfill days d(40)..d(6) (visible from d(29)), live days d(5) and d(3); gaps d(4), d(2), d(1), d(0)
      eq(p, "new on a backfilled day", [point(d(20))?.new, point(d(20))?.fixed], [2, 1]);
      eq(p, "a covered day without rows is a real zero", [point(d(15))?.new, point(d(15))?.netChange], [0, 0]);
      for (const n of [4, 2, 1, 0])
        for (const k of ["new", "fixed", "closedWithoutFix", "reopened", "netChange"])
          ok(p, point(d(n))?.[k] === null, `${d(n)} ${k} is not null on a gap day`);
      ok(p, !JSON.stringify(data?.points).includes("NaN"), "NaN in the points");
      // a series that was not requested is absent, not null
      const only = await api.get("am", `/reporting/trends?${ws}&period=30&series=backlog`);
      ok(p, only.json?.data?.points?.every((x) => !("new" in x) && "open" in x), "an unrequested series is present or the requested one is missing");
      // as-of posture
      const asOf = (day) => api.get("am", `/reporting/posture?${ws}&asOf=${day}`);
      const before = await asOf(d(8));
      ok(p, before.status === 200, `as-of before D: status ${before.status}`);
      const b = before.json?.data;
      eq(p, "as-of before D: partial", b?.partial, true);
      for (const k of ["open", "bySeverity", "byType", "byGroup", "byStatus", "backlog", "workInProgress", "criticalHighOpen", "newLast24Hours", "pipelinesHealthy", "githubConnections"])
        ok(p, b?.[k] === null, `as-of before D: ${k} is ${JSON.stringify(b?.[k])}, want null`);
      eq(p, "as-of before D: exceptions and decisions", [b?.exceptions, b?.awaitingDecision], [{ inForce: null, expiringWithin30Days: null }, { awaitingApproval: null, pendingExceptions: null }]);
      ok(p, postureDtoSchema.safeParse(b).success, "as-of before D does not parse");
      const live = await asOf(d(5));
      const l = live.json?.data;
      ok(p, live.status === 200 && l?.partial === true, `as-of live day: ${live.status}`);
      eq(p, "as-of live: open, backlog, wip", [l?.open, l?.backlog, l?.workInProgress], [3, 2, 1]);
      eq(p, "as-of live: exceptions in force", l?.exceptions?.inForce, 2);
      eq(p, "as-of live: the one status the rollup knows", l?.byStatus?.fixed_pending_verification, 1);
      eq(p, "as-of live: a status it does not know", [l?.byStatus?.assigned, l?.byStatus?.new, l?.byGroup?.needs_triage], [null, null, null]);
      eq(p, "as-of live: groups it knows", [l?.byGroup?.awaiting_verification, l?.byGroup?.accepted_or_suppressed], [1, 2]);
      eq(p, "as-of live: expiring and awaiting decision", [l?.exceptions?.expiringWithin30Days, l?.awaitingDecision?.awaitingApproval], [null, null]);
      ok(p, postureDtoSchema.safeParse(l).success, "as-of live does not parse");
      const gap = await asOf(d(4));
      ok(p, gap.status === 409 && gap.json?.error?.code === "REPORT_AS_OF_UNAVAILABLE", `as-of a day no run covers: ${gap.status} ${gap.json?.error?.code}`);
      // controls: the live-day numbers are not an artifact of a missing row (the planted pre-D row exists)
      const planted = await db.$queryRaw`SELECT open_count::int AS n FROM report_daily_findings WHERE tenant_id = ${tenant}::uuid AND day = ${d(8)}::date`;
      eq(p, "control: the pre-D state row exists", planted.map((r) => r.n), [4]);
      // a tenant with no run at all: every state value null, no first exact day
      const none = await api.get("amB", `/reporting/trends?workspaceId=${w.wsB0}&period=7`);
      eq(p, "no runs: stateSeriesFrom", none.json?.data?.stateSeriesFrom, null);
      ok(p, none.json?.data?.points?.every((x) => x.open === null && x.openBySeverity === null && x.new === null), "no runs: a series is not null");
      return p;
    },
  },
  {
    id: "RPTAM-06",
    name: "Coverage reasons and per-pipeline scan types from the new views (SPEC 6.4 S-4 and S-5): of the five countable repositories of tenant A workspace 0 (disconnected and archived ones are outside the universe) exactly one is covered; the reasons are connection_unavailable for the unavailable one, pipeline_disabled for the repository whose only pipeline is disabled, no_pipeline for the one with none, no_recent_scan for the one whose enabled pipeline failed; the pipelines listed are the live ones (the soft-deleted one is absent) with the scan types of the CURRENT configuration (an enabled type of a disabled pipeline is shown disabled); the answer parses against the strict coverage schema and names nothing of tenant B",
    async run(c) {
      const p = [];
      const w = await amWorld(c);
      const r = await w.api.get("am", `/reporting/coverage?workspaceId=${w.wsA0}`);
      ok(p, r.status === 200, `coverage: status ${r.status}`);
      const data = r.json?.data;
      const parsed = REPORTING_ROUTE_SCHEMAS["GET /reporting/coverage"].data.safeParse(data);
      ok(p, parsed.success, `coverage does not parse: ${parsed.success ? "" : JSON.stringify(parsed.error.issues[0])}`);
      eq(p, "covered and total", [data?.repositories?.covered, data?.repositories?.total], [1, 5]);
      const reasons = Object.fromEntries((data?.uncovered ?? []).map((u) => [u.repositoryName.split("-").pop(), u.reason]));
      eq(p, "reasons", reasons, { rU: "connection_unavailable", rP: "pipeline_disabled", rN: "no_pipeline", rE: "no_recent_scan" });
      const pipes = data?.pipelines ?? [];
      const byId = (x) => pipes.find((q) => q.pipelineId === x.pipeline.id);
      ok(p, !byId(w.pipes.pA3), "the soft-deleted pipeline is listed");
      ok(p, pipes.length === 4, `${pipes.length} pipelines listed, want 4`);
      const enabled = (x) => (byId(x)?.scanTypes ?? []).filter((s) => s.enabled).map((s) => s.type);
      eq(p, "pA1 enabled types", enabled(w.pipes.pA1), ["sbom", "sca"]);
      eq(p, "pA4 enabled types", enabled(w.pipes.pA4), ["secrets"]);
      eq(p, "pA2 (disabled pipeline) enabled types", enabled(w.pipes.pA2), []);
      eq(p, "scan type order", (byId(w.pipes.pA1)?.scanTypes ?? []).map((s) => s.type), ["sbom", "sca", "sast", "secrets"]);
      ok(p, !JSON.stringify(data).includes(w.B.repo[0].id) && !JSON.stringify(data).includes(w.pipes.pB.pipeline.id), "tenant B appears in A's coverage");
      return p;
    },
  },
  {
    id: "RPTAM-07",
    name: "Amended DTO contract (SPEC 17.5): the posture schema accepts the live shape and the partial shape with nulls in every field the rollup cannot tell, refuses a negative count, a missing `partial`, a missing `githubConnections` and any extra key; the trend point accepts an explicit null per series and still refuses a string, a negative count and an extra key; the trends schema refuses `severityBackfilled: true` and requires `stateSeriesFrom`; none of the amended DTOs carries a forbidden key",
    async run(c) {
      const p = [];
      const zero = (keys) => Object.fromEntries(keys.map((k) => [k, 0]));
      const sev = zero(["critical", "high", "medium", "low", "info"]);
      const types = zero(["sca", "sbom", "sast", "secrets"]);
      const groups = [
        "needs_triage",
        "in_review",
        "confirmed_in_remediation",
        "awaiting_verification",
        "accepted_or_suppressed",
        "false_positive",
        "fixed",
      ];
      const statuses = [
        "new",
        "in_review",
        "awaiting_approval",
        "approved",
        "assigned",
        "in_remediation",
        "fixed_pending_verification",
        "verified_fixed",
        "false_positive",
        "accepted_risk",
        "suppressed",
        "reopened",
      ];
      const live = {
        asOfDay: null,
        partial: false,
        open: 0,
        bySeverity: sev,
        byType: Object.fromEntries(Object.keys(types).filter((k) => k !== "sbom").map((k) => [k, 0])),
        byGroup: zero(groups),
        byStatus: zero(statuses),
        backlog: 0,
        workInProgress: 0,
        criticalHighOpen: 0,
        exceptions: { inForce: 0, expiringWithin30Days: 0 },
        awaitingDecision: { awaitingApproval: 0, pendingExceptions: 0 },
        newLast24Hours: 0,
        pipelinesHealthy: { healthy: 0, total: 0 },
        githubConnections: { active: 0, unavailable: 0, disconnected: 0 },
      };
      const partial = {
        ...live,
        asOfDay: "2026-11-01",
        partial: true,
        byGroup: Object.fromEntries(groups.map((g) => [g, null])),
        byStatus: Object.fromEntries(statuses.map((s) => [s, null])),
        exceptions: { inForce: 2, expiringWithin30Days: null },
        awaitingDecision: { awaitingApproval: null, pendingExceptions: null },
        newLast24Hours: null,
        pipelinesHealthy: null,
        githubConnections: null,
      };
      const allNull = {
        ...partial,
        open: null,
        bySeverity: null,
        byType: null,
        byGroup: null,
        byStatus: null,
        backlog: null,
        workInProgress: null,
        criticalHighOpen: null,
        exceptions: { inForce: null, expiringWithin30Days: null },
      };
      const accepts = (label, schema, value) => {
        const r = schema.safeParse(value);
        if (!r.success) p.push(`${label}: refused (${JSON.stringify(r.error.issues[0])})`);
      };
      const refuses = (label, schema, value) => {
        if (schema.safeParse(value).success) p.push(`${label}: accepted`);
      };
      accepts("live posture", postureDtoSchema, live);
      accepts("partial posture", postureDtoSchema, partial);
      accepts("posture with nothing known", postureDtoSchema, allNull);
      refuses("negative open", postureDtoSchema, { ...live, open: -1 });
      refuses("missing partial", postureDtoSchema, { ...live, partial: undefined });
      refuses("missing githubConnections", postureDtoSchema, { ...live, githubConnections: undefined });
      refuses("extra key", postureDtoSchema, { ...live, tenantId: "x" });
      refuses("a fractional count", postureDtoSchema, { ...live, backlog: 1.5 });
      refuses("a connection count that is null inside", postureDtoSchema, { ...live, githubConnections: { active: null, unavailable: 0, disconnected: 0 } });
      accepts("a gap point", trendPointSchema, { day: "2026-11-01", new: null, fixed: null, closedWithoutFix: null, reopened: null, openBySeverity: null, open: null, netChange: null, awaitingVerification: null });
      accepts("a known point", trendPointSchema, { day: "2026-11-01", open: 3, netChange: -2, openBySeverity: sev });
      accepts("a day only", trendPointSchema, { day: "2026-11-01" });
      refuses("a string count", trendPointSchema, { day: "2026-11-01", open: "3" });
      refuses("a negative count", trendPointSchema, { day: "2026-11-01", new: -1 });
      refuses("a point extra key", trendPointSchema, { day: "2026-11-01", tenantId: "x" });
      const trends = { period: { from: "2026-11-01", to: "2026-11-01", dayCount: 1, preset: null }, points: [{ day: "2026-11-01", open: null }], severityBackfilled: false, stateSeriesFrom: null, dataFrom: null, recomputing: false, projection: null };
      accepts("trends", trendsDtoSchema, trends);
      refuses("severityBackfilled true", trendsDtoSchema, { ...trends, severityBackfilled: true });
      refuses("missing stateSeriesFrom", trendsDtoSchema, { ...trends, stateSeriesFrom: undefined });
      refuses("a bad stateSeriesFrom", trendsDtoSchema, { ...trends, stateSeriesFrom: "yesterday" });
      const forbidden = new Set(FORBIDDEN_REPORTING_DTO_KEYS);
      const keysOf = (v, out = new Set()) => {
        if (Array.isArray(v)) v.forEach((x) => keysOf(x, out));
        else if (v && typeof v === "object")
          for (const [k, x] of Object.entries(v)) {
            out.add(k);
            keysOf(x, out);
          }
        return out;
      };
      eq(p, "forbidden keys in the amended DTO examples", [...keysOf([live, partial, allNull, trends])].filter((k) => forbidden.has(k)), []);
      return p;
    },
  },
];
