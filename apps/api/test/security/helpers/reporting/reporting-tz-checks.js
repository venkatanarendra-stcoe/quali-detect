import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import express from "express";
import pino from "pino";
import { createOutboxRepository } from "@qmentisai/db";
import { createOutbox } from "@qmentisai/infra";
import { BUILT_IN_ROLES, REPORTING_PERMISSION_BY_ROUTE, localDayOf } from "@qmentisai/shared";
import { createAuditService } from "../../../../src/audit/audit-service.js";
import { configureCursorSigning } from "../../../../src/lib/cursor-signing.js";
import { createRouteKit } from "../../../../src/lib/route-kit.js";
import { createAuthorization } from "../../../../src/middleware/authorization.js";
import { correlation } from "../../../../src/middleware/correlation.js";
import { envelope } from "../../../../src/middleware/envelope.js";
import { errorHandler, notFoundHandler } from "../../../../src/middleware/error-handler.js";
import { reportingSettingsRoutes } from "../../../../src/modules/reporting/routes/settings.routes.js";
import { createReportingSettingsRepository } from "../../../../src/modules/reporting/repositories/settings.js";
import { createReportingSettingsService } from "../../../../src/modules/reporting/services/settings.js";
import { createFakeRedis, makeUser, splitKeys } from "./reporting-b-fixtures.js";
import { eWorld } from "./reporting-e-checks.js";

/**
 * Reporting tenant time-zone setting checks (ADR-008 area 20, docs/modules/reporting-dashboards/AS_BUILT_TZ.md), ids `RPTTZ-01..08`.
 * The REAL settings routes (route kit validation, central authorization, service, repository, the real audit writer and the real
 * transactional outbox) run behind a stub authentication chain whose principals are given by the check; one check uses the REAL second API
 * process (real sessions, the real Idempotency-Key middleware). Redis is the in-memory double. NOT proved here: a real worker consuming the
 * rebuild (the rebuild itself is `RPT-S10f`) and the screen (UI tests are outside the suite).
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const silent = pino({ level: "silent" });
const MSG = "reporting.rollup.requested";
const ACTION = "tenant.reporting_timezone_changed";
const j = (v) => JSON.stringify(v);
const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const same = (p, label, got, want) => {
  if (j(got) !== j(want))
    p.push(`${label}: got ${j(got)?.slice(0, 300)}, want ${j(want)?.slice(0, 300)}`);
};
const hex = (n = 4) => randomBytes(n).toString("hex");
const bare = (r) =>
  j({ status: r.status, ...r.json, meta: { ...r.json?.meta, correlationId: undefined } });

/** The stub API: the real settings routes, a principal table, the real audit and outbox, a fake Redis. */
async function startSettingsApi(db, { enabled = true, redis }) {
  configureCursorSigning([
    "reporting-tz-suite-cursor-secret-1",
    "reporting-tz-suite-cursor-secret-2",
  ]);
  const principals = new Map();
  const pass = (_req, _res, next) => next();
  const authenticate = (req, res, next) => {
    const p = principals.get(String(req.headers["x-test-principal"] ?? ""));
    if (!p) return res.status(401).json({ success: false, error: { code: "UNAUTHENTICATED" } });
    req.principal = {
      user: { id: p.userId },
      tenant: { id: p.tenantId, status: "active" },
      membership: { status: "active" },
      permissions: p.permissions,
    };
    req.log = silent;
    return next();
  };
  const kit = createRouteKit({
    chains: { public: [pass], user: [authenticate], tenant: [authenticate], platform: [pass] },
    limiters: { forRoute: () => pass },
    idempotency: { forRoute: () => pass },
  });
  await reportingSettingsRoutes({
    db,
    readDb: () => db,
    authz: createAuthorization({ db }),
    audit: createAuditService({ db, logger: silent }),
    outbox: createOutbox({ repository: createOutboxRepository({ db }) }),
    entitlements: null,
    config: { reporting: { enabled, cacheRedis: redis } },
    log: silent,
  })(kit.registrar("/api/v1"));
  const app = express();
  app.set("query parser", "simple");
  app.use(correlation());
  app.use(envelope());
  app.use(express.json());
  app.use("/api/v1", kit.routers.tenant);
  app.use(notFoundHandler());
  app.use(errorHandler({ logger: silent }));
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  server.unref();
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    routeTable: kit.table,
    register(name, { userId, tenantId, tenant = [] }) {
      principals.set(name, {
        userId,
        tenantId,
        permissions: { tenant: [...tenant], allWorkspaces: [], workspaces: [] },
      });
    },
    async call(name, method, body, { headers, path = "/reporting/settings" } = {}) {
      const response = await fetch(`${base}/api/v1${path}`, {
        method,
        headers: {
          "x-test-principal": name,
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
          ...headers,
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
      return { status: response.status, json: await response.json().catch(() => null) };
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** Builds (once) the two APIs (module on and off), the principals and the fake Redis. */
function tzWorld(c) {
  c.__rptTz ??= (async () => {
    const { db } = c;
    const redis = createFakeRedis();
    const on = await startSettingsApi(db, { enabled: true, redis });
    const off = await startSettingsApi(db, { enabled: false, redis });
    const userA = await makeUser(db, c.A, "tz");
    const userB = await makeUser(db, c.B, "tz-b");
    const tenantA = c.A.tenant.id;
    const tenantB = c.B.tenant.id;
    for (const role of BUILT_IN_ROLES) {
      const { tenant } = splitKeys(role.permissions);
      on.register(`role:${role.key}`, { userId: userA.id, tenantId: tenantA, tenant });
    }
    off.register("role:admin", {
      userId: userA.id,
      tenantId: tenantA,
      tenant: splitKeys(BUILT_IN_ROLES.find((r) => r.key === "admin").permissions).tenant,
    });
    on.register("custom:none", { userId: userA.id, tenantId: tenantA, tenant: [] });
    on.register("custom:view", {
      userId: userA.id,
      tenantId: tenantA,
      tenant: ["tenant_settings.view"],
    });
    on.register("adminB", {
      userId: userB.id,
      tenantId: tenantB,
      tenant: splitKeys(BUILT_IN_ROLES.find((r) => r.key === "admin").permissions).tenant,
    });
    return { on, off, redis, userA, userB, tenantA, tenantB };
  })();
  return c.__rptTz;
}

const zoneOf = async (db, tenantId) =>
  (await db.tenantReportingSettings.findUnique({ where: { tenantId } }))?.reportingTimezone ?? null;
const reset = (db, tenantId) => db.tenantReportingSettings.deleteMany({ where: { tenantId } });
const auditCount = (db, tenantId) => db.auditLog.count({ where: { tenantId, action: ACTION } });
const queued = (db, tenantId) =>
  db.outboxMessage.findMany({
    where: { tenantId, queue: "reporting", type: MSG },
    orderBy: { createdAt: "asc" },
  });
const snapshot = async (db, tenantId) => ({
  zone: await zoneOf(db, tenantId),
  audit: await auditCount(db, tenantId),
  outbox: (await queued(db, tenantId)).length,
});

const HOLDS = Object.freeze({
  admin: { view: true, manage: true },
  manager: { view: false, manage: false },
  lead: { view: false, manage: false },
  security_analyst: { view: false, manage: false },
  dev_lead: { view: false, manage: false },
  developer: { view: false, manage: false },
  viewer: { view: false, manage: false },
});

const TZ01 = {
  id: "RPTTZ-01",
  name: "Reporting settings permission matrix (docs/AUTHORIZATION.md, the keys of the Organization Settings screen): GET /reporting/settings needs tenant_settings.view and PUT needs tenant_settings.manage; for each of the seven built-in roles (written out here from AUTHORIZATION.md: only the administrator holds them) and a custom role the answer is 200 exactly when the key is held and 403 otherwise (a tenant key hides no resource, so no 404), a refused PUT changes nothing (zone, audit, outbox), a role that may only view reads but cannot change, an unauthenticated call is 401, the route map names the same two keys, a member of tenant B reads and changes ONLY tenant B (tenant A's zone, audit and outbox are untouched) and a tenant id in the body or the query is a 400",
  async run(c) {
    const p = [];
    const { db } = c;
    const w = await tzWorld(c);
    await reset(db, w.tenantA);
    await reset(db, w.tenantB);
    same(
      p,
      "route map GET",
      REPORTING_PERMISSION_BY_ROUTE["GET /reporting/settings"],
      "tenant_settings.view",
    );
    same(
      p,
      "route map PUT",
      REPORTING_PERMISSION_BY_ROUTE["PUT /reporting/settings"],
      "tenant_settings.manage",
    );
    const table = w.on.routeTable
      .map((r) => `${r.method} ${r.url} ${r.permission} ${r.rateLimit} ${r.idempotent}`)
      .sort();
    same(p, "the registered routes", table, [
      "GET /api/v1/reporting/settings tenant_settings.view read false",
      "PUT /api/v1/reporting/settings tenant_settings.manage write true",
    ]);
    const before = await snapshot(db, w.tenantA);
    for (const role of BUILT_IN_ROLES) {
      const holds = HOLDS[role.key];
      if (!holds) {
        p.push(`role ${role.key} has no row in the expected table`);
        continue;
      }
      const who = `role:${role.key}`;
      const get = await w.on.call(who, "GET");
      same(p, `${role.key} GET`, get.status, holds.view ? 200 : 403);
      if (!holds.view) ok(p, !get.json?.data, `${role.key}: a 403 carries data`);
      const put = await w.on.call(who, "PUT", { reportingTimezone: "Asia/Tokyo" });
      same(p, `${role.key} PUT`, put.status, holds.manage ? 200 : 403);
      if (holds.manage) await w.on.call(who, "PUT", { reportingTimezone: "UTC" }); // the control is undone
    }
    // the refused calls above left no trace: only the administrator's two real changes (to Tokyo and back) exist
    const mid = await snapshot(db, w.tenantA);
    same(p, "audit entries after the matrix (admin: two changes)", mid.audit - before.audit, 2);
    same(
      p,
      "rebuild messages after the matrix (admin: two changes)",
      mid.outbox - before.outbox,
      2,
    );
    const viewOnly = await w.on.call("custom:view", "GET");
    same(p, "a view-only role reads", viewOnly.status, 200);
    const denied = await w.on.call("custom:view", "PUT", { reportingTimezone: "Europe/Paris" });
    same(
      p,
      "a view-only role cannot change",
      [denied.status, denied.json?.error?.code],
      [403, "FORBIDDEN"],
    );
    same(p, "a role without keys cannot read", (await w.on.call("custom:none", "GET")).status, 403);
    same(p, "no principal", (await w.on.call("nobody", "GET")).status, 401);
    same(p, "the denials changed nothing", await snapshot(db, w.tenantA), mid);
    // another tenant
    const beforeB = await snapshot(db, w.tenantB);
    const putB = await w.on.call("adminB", "PUT", { reportingTimezone: "Pacific/Auckland" });
    same(p, "tenant B's admin changes B", putB.status, 200);
    same(p, "tenant B's zone", await zoneOf(db, w.tenantB), "Pacific/Auckland");
    same(p, "tenant A's zone is untouched by B's change", await zoneOf(db, w.tenantA), "UTC");
    same(p, "tenant A has no new audit entry or message", await snapshot(db, w.tenantA), mid);
    same(
      p,
      "tenant B got one audit entry",
      (await snapshot(db, w.tenantB)).audit - beforeB.audit,
      1,
    );
    same(
      p,
      "tenant B's read",
      (await w.on.call("adminB", "GET")).json?.data?.reportingTimezone,
      "Pacific/Auckland",
    );
    same(
      p,
      "tenant A's read",
      (await w.on.call("role:admin", "GET")).json?.data?.reportingTimezone,
      "UTC",
    );
    const queuedB = await queued(db, w.tenantB);
    ok(
      p,
      queuedB.every((m) => m.payload?.tenantId === w.tenantB && m.tenantId === w.tenantB),
      "a rebuild message of B names another tenant",
    );
    // a tenant id from the request is never read
    for (const [label, body, path] of [
      [
        "a tenantId in the body",
        { reportingTimezone: "UTC", tenantId: w.tenantB },
        "/reporting/settings",
      ],
      [
        "a tenantId in the query",
        { reportingTimezone: "UTC" },
        `/reporting/settings?tenantId=${w.tenantB}`,
      ],
    ]) {
      const r = await w.on.call("role:admin", "PUT", body, { path });
      same(p, label, [r.status, r.json?.error?.code], [400, "VALIDATION_FAILED"]);
    }
    same(
      p,
      "tenant B is unchanged by A's attempts",
      await zoneOf(db, w.tenantB),
      "Pacific/Auckland",
    );
    await reset(db, w.tenantA);
    await reset(db, w.tenantB);
    return p;
  },
};

const TZ02 = {
  id: "RPTTZ-02",
  name: "Reporting zone validation: an unknown name, an empty string, a non-string (number, null, array, object, boolean), an over-long value (65 characters), surrounding blanks, a lower-case spelling, a wrong-case location, a legacy alias (US/Pacific), an Etc/ zone, an offset (+01:00), a path trick (../), a missing key and an extra key are each a 400 VALIDATION_FAILED with the same stable shape; none of them changes the zone, writes an audit entry or queues a message; a legacy spelling the runtime does not list (Asia/Kolkata while it lists Asia/Calcutta) is refused too; canonical names (UTC, Europe/Berlin, a three-part name, Asia/Calcutta where the runtime lists it) are accepted (the control)",
  async run(c) {
    const p = [];
    const { db } = c;
    const w = await tzWorld(c);
    await reset(db, w.tenantA);
    const before = await snapshot(db, w.tenantA);
    const bad = [
      { reportingTimezone: "Mars/Olympus_Mons" },
      { reportingTimezone: "" },
      { reportingTimezone: 5 },
      { reportingTimezone: null },
      { reportingTimezone: ["UTC"] },
      { reportingTimezone: { name: "UTC" } },
      { reportingTimezone: true },
      { reportingTimezone: `Europe/${"A".repeat(60)}` },
      { reportingTimezone: " UTC" },
      { reportingTimezone: "utc" },
      { reportingTimezone: "europe/berlin" },
      { reportingTimezone: "Europe/berlin" },
      { reportingTimezone: "US/Pacific" },
      ...(Intl.supportedValuesOf("timeZone").includes("Asia/Kolkata")
        ? []
        : [{ reportingTimezone: "Asia/Kolkata" }]),
      { reportingTimezone: "Etc/GMT+5" },
      { reportingTimezone: "Etc/UTC" },
      { reportingTimezone: "+01:00" },
      { reportingTimezone: "../../etc/passwd" },
      {},
      { reportingTimezone: "Europe/Berlin", extra: 1 },
    ];
    const shapes = new Set();
    for (const body of bad) {
      const r = await w.on.call("role:admin", "PUT", body);
      same(
        p,
        `refused ${j(body).slice(0, 60)}`,
        [r.status, r.json?.error?.code],
        [400, "VALIDATION_FAILED"],
      );
      shapes.add(j({ status: r.status, code: r.json?.error?.code, success: r.json?.success }));
    }
    same(p, "one stable error shape", shapes.size, 1);
    same(p, "nothing changed after the refusals", await snapshot(db, w.tenantA), before);
    const listed = Intl.supportedValuesOf("timeZone");
    const deep = listed.find((z) => z.split("/").length === 3);
    const names = ["Europe/Berlin", ...(deep ? [deep] : []), "UTC"];
    if (Intl.supportedValuesOf("timeZone").includes("Asia/Calcutta")) names.push("Asia/Calcutta");
    for (const zone of names) {
      const r = await w.on.call("role:admin", "PUT", { reportingTimezone: zone });
      same(p, `accepted ${zone}`, r.status, 200);
    }
    const g = await w.on.call("role:admin", "GET");
    same(p, "the stored zone after the controls", g.json?.data?.reportingTimezone, names.at(-1));
    await reset(db, w.tenantA);
    return p;
  },
};

const TZ03 = {
  id: "RPTTZ-03",
  name: "A real zone change (one transaction): it flips the stored zone, writes EXACTLY ONE audit entry `tenant.reporting_timezone_changed` (actor, tenant, previous and new zone, nothing else) and queues EXACTLY ONE rebuild message in the outbox (right tenant and queue, `reporting.rollup.requested`, mode backfill, reason timezone_changed, range from the tenant's earliest history day in the NEW zone (retention cap) to today in the NEW zone, a message id that names the tenant and the zone); the DTO shows the new zone, who changed it by display name only (no id, no e-mail) and `recomputing` true until a succeeded backfill of the new zone covers the range, then false; a failure after the audit write rolls everything back (zone, audit and message)",
  async run(c) {
    const p = [];
    const { db } = c;
    const w = await tzWorld(c);
    await reset(db, w.tenantA);
    const before = await snapshot(db, w.tenantA);
    const t0 = new Date();
    const r = await w.on.call("role:admin", "PUT", { reportingTimezone: "Pacific/Kiritimati" });
    same(p, "status", r.status, 200);
    const data = r.json?.data;
    same(p, "the zone in the answer", data?.reportingTimezone, "Pacific/Kiritimati");
    same(p, "recomputing right after the change", data?.recomputing, true);
    same(p, "updatedBy is a display name only", Object.keys(data?.updatedBy ?? {}), [
      "displayName",
    ]);
    same(p, "the DTO keys", Object.keys(data ?? {}).sort(), [
      "recomputing",
      "reportingTimezone",
      "updatedAt",
      "updatedBy",
    ]);
    ok(
      p,
      !JSON.stringify(r.json).includes(w.userA.email),
      "the e-mail of the actor is in the answer",
    );
    ok(p, !JSON.stringify(r.json).includes(w.userA.id), "the id of the actor is in the answer");
    same(p, "the stored zone", await zoneOf(db, w.tenantA), "Pacific/Kiritimati");
    const audits = await db.auditLog.findMany({
      where: { tenantId: w.tenantA, action: ACTION },
      orderBy: { createdAt: "asc" },
    });
    same(p, "audit entries added", audits.length - before.audit, 1);
    const entry = audits.at(-1);
    same(p, "audit actor", entry?.actorUserId, w.userA.id);
    same(
      p,
      "audit metadata",
      entry?.metadata && {
        previous: entry.metadata.previous,
        new: entry.metadata.new,
        keys: Object.keys(entry.metadata).sort(),
      },
      { previous: "UTC", new: "Pacific/Kiritimati", keys: ["new", "previous"] },
    );
    const messages = await queued(db, w.tenantA);
    same(p, "messages added", messages.length - before.outbox, 1);
    const m = messages.at(-1);
    same(p, "the outbox row", [m?.queue, m?.type, m?.tenantId], ["reporting", MSG, w.tenantA]);
    const payload = m?.payload?.payload ?? {};
    same(
      p,
      "payload mode and reason",
      [payload.mode, payload.reason, payload.tenantId],
      ["backfill", "timezone_changed", w.tenantA],
    );
    const today = localDayOf(new Date(), "Pacific/Kiritimati");
    ok(
      p,
      payload.to === today || payload.to === localDayOf(t0, "Pacific/Kiritimati"),
      `the range ends ${payload.to}, not today in the new zone (${today})`,
    );
    const earliest = (
      await db.$queryRaw`SELECT min(created_at) AS at FROM finding_status_history WHERE tenant_id = ${w.tenantA}::uuid`
    )[0]?.at;
    const expectedFrom = earliest ? localDayOf(earliest, "Pacific/Kiritimati") : today;
    same(
      p,
      "the range starts at the earliest history day in the new zone",
      payload.from,
      expectedFrom,
    );
    ok(
      p,
      /^reporting-rollup-/.test(m?.messageId ?? "") &&
        m.messageId.includes(w.tenantA) &&
        m.messageId.includes("Pacific-Kiritimati"),
      `the message id ${m?.messageId} does not name the tenant and the zone`,
    );
    ok(p, (m?.messageId ?? "").length <= 128, "the message id is longer than the envelope allows");
    // recomputing turns false once a succeeded backfill of the new zone reaches the range
    await db.reportRollupRun.create({
      data: {
        tenantId: w.tenantA,
        day: new Date(`${payload.from}T00:00:00.000Z`),
        rangeTo: new Date(`${payload.to}T00:00:00.000Z`),
        mode: "backfill",
        status: "succeeded",
        timeZone: "Pacific/Kiritimati",
        finishedAt: new Date(),
      },
    });
    same(
      p,
      "recomputing after a finished rebuild",
      (await w.on.call("role:admin", "GET")).json?.data?.recomputing,
      false,
    );
    // a run of ANOTHER zone, or one that started before the change, does not end the recomputing
    await reset(db, w.tenantA);
    // rollback: the audit write fails (a service with an audit that throws), nothing is left
    const failing = createReportingSettingsService({
      db,
      repository: createReportingSettingsRepository({ db }),
      audit: {
        tenant: {
          record: async () => {
            throw new Error("audit down");
          },
        },
      },
      outbox: createOutbox({ repository: createOutboxRepository({ db }) }),
      bumpEpochs: async () => {},
    });
    const base = await snapshot(db, w.tenantA);
    let threw = false;
    try {
      await failing.update(
        { tenantId: w.tenantA, userId: w.userA.id },
        { reportingTimezone: "Asia/Tokyo" },
      );
    } catch {
      threw = true;
    }
    ok(p, threw, "a failing audit write did not fail the change");
    same(p, "a failed change left nothing", await snapshot(db, w.tenantA), base);
    // the same for a failing outbox
    const failingOutbox = createReportingSettingsService({
      db,
      repository: createReportingSettingsRepository({ db }),
      audit: createAuditService({ db, logger: silent }),
      outbox: {
        enqueue: async () => {
          throw new Error("outbox down");
        },
      },
      bumpEpochs: async () => {},
    });
    threw = false;
    try {
      await failingOutbox.update(
        { tenantId: w.tenantA, userId: w.userA.id },
        { reportingTimezone: "Asia/Tokyo" },
      );
    } catch {
      threw = true;
    }
    ok(p, threw, "a failing outbox write did not fail the change");
    same(
      p,
      "a failed enqueue left nothing (no zone, no audit entry)",
      await snapshot(db, w.tenantA),
      base,
    );
    return p;
  },
};

const TZ04 = {
  id: "RPTTZ-04",
  name: "Saving the zone the tenant already has is a no-op: 200 with the current DTO, no audit entry, no rebuild message, the row's updatedAt is unchanged, and a tenant without a settings row asking for UTC gets no row created; a change followed by the same value again writes once",
  async run(c) {
    const p = [];
    const { db } = c;
    const w = await tzWorld(c);
    await reset(db, w.tenantA);
    const base = await snapshot(db, w.tenantA);
    const utc = await w.on.call("role:admin", "PUT", { reportingTimezone: "UTC" });
    same(
      p,
      "UTC on a tenant without a row",
      [
        utc.status,
        utc.json?.data?.reportingTimezone,
        utc.json?.data?.recomputing,
        utc.json?.data?.updatedAt,
      ],
      [200, "UTC", false, null],
    );
    same(p, "no row was created and nothing was written", await snapshot(db, w.tenantA), base);
    const first = await w.on.call("role:admin", "PUT", { reportingTimezone: "Asia/Tokyo" });
    same(p, "first change", first.status, 200);
    const afterFirst = await snapshot(db, w.tenantA);
    const stamp = (
      await db.tenantReportingSettings.findUnique({ where: { tenantId: w.tenantA } })
    ).updatedAt.toISOString();
    const again = await w.on.call("role:admin", "PUT", { reportingTimezone: "Asia/Tokyo" });
    same(
      p,
      "same zone again",
      [again.status, again.json?.data?.reportingTimezone, again.json?.data?.updatedAt],
      [200, "Asia/Tokyo", stamp],
    );
    same(p, "the same zone wrote nothing", await snapshot(db, w.tenantA), afterFirst);
    same(
      p,
      "the first change wrote once",
      [afterFirst.audit - base.audit, afterFirst.outbox - base.outbox],
      [1, 1],
    );
    await reset(db, w.tenantA);
    return p;
  },
};

const TZ05 = {
  id: "RPTTZ-05",
  name: "The rebuild message id is distinct per change: two real changes inside the same hour (UTC to Berlin to Tokyo, and back to Berlin) queue three messages with three different ids (the hour-bucket ids of the other rollup messages would collapse them), the id carries no hour bucket; a replay of the SAME Idempotency-Key (the id derives from the key) is the same id and the outbox keeps one row for it; two requests without a key get different ids",
  async run(c) {
    const p = [];
    const { db } = c;
    const w = await tzWorld(c);
    await reset(db, w.tenantA);
    const base = (await queued(db, w.tenantA)).length;
    for (const zone of ["Europe/Berlin", "Asia/Tokyo", "Europe/Berlin"]) {
      const r = await w.on.call("role:admin", "PUT", { reportingTimezone: zone });
      same(p, `change to ${zone}`, r.status, 200);
    }
    const rows = (await queued(db, w.tenantA)).slice(base);
    same(p, "three changes queued three messages", rows.length, 3);
    same(p, "three distinct ids", new Set(rows.map((m) => m.messageId)).size, 3);
    ok(
      p,
      rows.every((m) => !/-op\d+$/.test(m.messageId) && !/\d{4}-\d{2}-\d{2}/.test(m.messageId)),
      "an id carries an hour bucket or a day",
    );
    // the same Idempotency-Key reaching the service twice (the middleware replay is proven live in RPTTZ-08)
    const service = createReportingSettingsService({
      db,
      repository: createReportingSettingsRepository({ db }),
      audit: createAuditService({ db, logger: silent }),
      outbox: createOutbox({ repository: createOutboxRepository({ db }) }),
      bumpEpochs: async () => {},
    });
    const actor = { tenantId: w.tenantA, userId: w.userA.id };
    const key = `tz-replay-${hex(6)}`;
    await service.update(actor, { reportingTimezone: "Asia/Seoul" }, { idempotencyKey: key });
    await db.tenantReportingSettings.update({
      where: { tenantId: w.tenantA },
      data: { reportingTimezone: "Europe/Berlin" },
    });
    await service.update(actor, { reportingTimezone: "Asia/Seoul" }, { idempotencyKey: key });
    const seoul = (await queued(db, w.tenantA)).filter((m) => m.messageId.includes("Seoul"));
    same(p, "the replayed key queued one message", seoul.length, 1);
    await db.tenantReportingSettings.update({
      where: { tenantId: w.tenantA },
      data: { reportingTimezone: "Europe/Berlin" },
    });
    await service.update(
      actor,
      { reportingTimezone: "Asia/Seoul" },
      { idempotencyKey: `tz-other-${hex(6)}` },
    );
    same(
      p,
      "another key queued another message",
      (await queued(db, w.tenantA)).filter((m) => m.messageId.includes("Seoul")).length,
      2,
    );
    const expected = createHash("sha256").update(`${w.tenantA}:${key}`).digest("hex").slice(0, 16);
    ok(p, seoul[0]?.messageId.endsWith(expected), "the id does not derive from the key");
    await reset(db, w.tenantA);
    return p;
  },
};

const TZ06 = {
  id: "RPTTZ-06",
  name: "Module off (REPORTING_ENABLED not true): GET and PUT /reporting/settings answer the byte-identical 404 RESOURCE_NOT_FOUND for the administrator (a valid request, so it is the flag), with no state change (zone, audit, outbox); the module on answers 200 to the same call (the control)",
  async run(c) {
    const p = [];
    const { db } = c;
    const w = await tzWorld(c);
    await reset(db, w.tenantA);
    const before = await snapshot(db, w.tenantA);
    const bodies = new Set();
    for (const [method, body] of [["GET"], ["PUT", { reportingTimezone: "Asia/Tokyo" }]]) {
      const r = await w.off.call("role:admin", method, body);
      same(p, `${method} while off`, [r.status, r.json?.error?.code], [404, "RESOURCE_NOT_FOUND"]);
      bodies.add(bare(r));
    }
    same(p, "identical 404 bodies", bodies.size, 1);
    same(p, "the off module wrote nothing", await snapshot(db, w.tenantA), before);
    same(p, "the control (module on)", (await w.on.call("role:admin", "GET")).status, 200);
    return p;
  },
};

const TZ07 = {
  id: "RPTTZ-07",
  name: "Cache epoch: a real zone change bumps the reporting cache epoch of EVERY workspace of the tenant and of the tenant-wide overview (through the public helper of the read cache; the keys carry the tenant id), a refused request and a same-zone request bump nothing, another tenant's epoch keys are never touched, and a Redis that is down does not fail the change",
  async run(c) {
    const p = [];
    const { db } = c;
    const w = await tzWorld(c);
    await reset(db, w.tenantA);
    const epochKeys = () => w.redis.keys().filter((k) => k.includes("rptepoch"));
    const mine = () => epochKeys().filter((k) => k.includes(w.tenantA));
    const others = () => epochKeys().filter((k) => !k.includes(w.tenantA));
    w.redis.store.clear();
    const bad = await w.on.call("role:admin", "PUT", { reportingTimezone: "Nowhere/None" });
    same(p, "a refused request", bad.status, 400);
    same(p, "a refusal bumps nothing", epochKeys(), []);
    const same0 = await w.on.call("role:admin", "PUT", { reportingTimezone: "UTC" });
    same(p, "a same-zone request", same0.status, 200);
    same(p, "a no-op bumps nothing", epochKeys(), []);
    const real = await w.on.call("role:admin", "PUT", { reportingTimezone: "Asia/Tokyo" });
    same(p, "a real change", real.status, 200);
    const workspaces = (
      await db.workspace.findMany({ where: { tenantId: w.tenantA }, select: { id: true } })
    ).map((x) => x.id);
    ok(p, workspaces.length > 0, "the tenant has no workspace");
    for (const id of [...workspaces, "tenant"]) {
      const key = mine().find((k) => k.endsWith(id) || k.includes(`:${id}`) || k.includes(id));
      ok(p, key !== undefined, `no epoch key for ${id}`);
      if (key) ok(p, Number(w.redis.store.get(key)?.value) >= 1, `the epoch of ${id} did not move`);
    }
    ok(
      p,
      epochKeys().every((k) => /[0-9a-f]{8}-[0-9a-f]{4}-/.test(k)),
      "an epoch key without a tenant id",
    );
    same(p, "no key of another tenant", others(), []);
    const afterFirst = Object.fromEntries(mine().map((k) => [k, w.redis.store.get(k).value]));
    await w.on.call("role:admin", "PUT", { reportingTimezone: "Europe/Paris" });
    ok(
      p,
      mine().every((k) => Number(w.redis.store.get(k).value) > Number(afterFirst[k])),
      "a second change did not move every epoch again",
    );
    // Redis down: the change still succeeds
    w.redis.state.mode = "error";
    const down = await w.on.call("role:admin", "PUT", { reportingTimezone: "Asia/Seoul" });
    w.redis.state.mode = "ok";
    same(
      p,
      "a change while Redis is down",
      [down.status, down.json?.data?.reportingTimezone],
      [200, "Asia/Seoul"],
    );
    await reset(db, w.tenantA);
    return p;
  },
};

const TZ08 = {
  id: "RPTTZ-08",
  name: "On the REAL second API process (real session, real Idempotency-Key middleware): the administrator's PUT with a key changes the zone once; the replay of the same key answers the same body (Idempotent-Replayed) and queues no second message and writes no second audit entry; the same key with another zone is refused; a PUT without a key still works; the GET shows the zone, updatedBy by display name and `recomputing`; another tenant's owner never sees or changes it; a member without the key gets 403; the zone is left at UTC",
  async run(c) {
    const p = [];
    const { db } = c;
    const e = await eWorld(c);
    const T = e.A.tenantId;
    await reset(db, T);
    const before = await snapshot(db, T);
    const key = `tz-live-${hex(8)}`;
    const body = { reportingTimezone: "Europe/Berlin" };
    const one = await e.api("PUT", "/reporting/settings", {
      cookie: e.A.cookie,
      body,
      headers: { "Idempotency-Key": key },
    });
    same(p, "first PUT", [one.status, one.json?.data?.reportingTimezone], [200, "Europe/Berlin"]);
    const two = await e.api("PUT", "/reporting/settings", {
      cookie: e.A.cookie,
      body,
      headers: { "Idempotency-Key": key },
    });
    same(p, "the replay", [two.status, j(two.json?.data)], [200, j(one.json?.data)]);
    ok(
      p,
      String(two.headers?.get?.("idempotent-replayed") ?? two.headers?.["idempotent-replayed"]) ===
        "true",
      "the replay is not marked Idempotent-Replayed",
    );
    const after = await snapshot(db, T);
    same(
      p,
      "one audit entry and one message for the key and its replay",
      [after.audit - before.audit, after.outbox - before.outbox],
      [1, 1],
    );
    const clash = await e.api("PUT", "/reporting/settings", {
      cookie: e.A.cookie,
      body: { reportingTimezone: "Asia/Tokyo" },
      headers: { "Idempotency-Key": key },
    });
    ok(p, clash.status >= 400, `the same key with another zone answered ${clash.status}`);
    same(p, "the clash changed nothing", await snapshot(db, T), after);
    const noKey = await e.api("PUT", "/reporting/settings", {
      cookie: e.A.cookie,
      body: { reportingTimezone: "Asia/Tokyo" },
    });
    same(p, "PUT without a key", noKey.status, 200);
    const get = await e.api("GET", "/reporting/settings", { cookie: e.A.cookie });
    same(
      p,
      "GET",
      [
        get.status,
        get.json?.data?.reportingTimezone,
        typeof get.json?.data?.updatedBy?.displayName,
        get.json?.data?.recomputing,
      ],
      [200, "Asia/Tokyo", "string", true],
    );
    const other = await e.api("GET", "/reporting/settings", { cookie: e.B.cookie });
    same(
      p,
      "another tenant's owner reads its own zone",
      [other.status, other.json?.data?.reportingTimezone],
      [200, "UTC"],
    );
    const developer = await e.api("PUT", "/reporting/settings", {
      cookie: e.w.sessions.developer,
      body,
    });
    same(
      p,
      "a developer (no tenant_settings key)",
      [developer.status, developer.json?.error?.code],
      [403, "FORBIDDEN"],
    );
    const anon = await e.api("GET", "/reporting/settings", {});
    same(p, "no session", anon.status, 401);
    await reset(db, T);
    return p;
  },
};

export const REPORTING_TZ_CHECKS = [TZ01, TZ02, TZ03, TZ04, TZ05, TZ06, TZ07, TZ08];
