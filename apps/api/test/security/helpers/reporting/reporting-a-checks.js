import { randomBytes, randomUUID } from "node:crypto";
import { QUEUE_NAMES, createJobEnvelope, parseMessage } from "@qmentisai/contracts";
import { createDbClient, createReportingRollupRepository } from "@qmentisai/db";
import { NonRetryableError, TransientError } from "@qmentisai/infra";
import {
  LIFECYCLE_GROUP_OF_STATUS,
  OPEN_FINDING_STATUSES,
  ROLLUP_ERROR_CODES,
  addDays,
  dayCloseInstant,
  dayRange,
  deriveSlaState,
  localDayOf,
} from "@qmentisai/shared";
import {
  createRollupHandler,
  startRollupTick,
} from "../../../../../workers/src/reporting/rollup/index.js";
import { runPurge, runTick } from "../../../../../workers/src/reporting/rollup/tick.js";
import { subtractMonths } from "../../../../../workers/src/reporting/rollup/job.js";
import { buildFindingsWorld } from "../findings/findings-world.js";
import { attempt } from "../pipeline-db.js";
import {
  HOUR,
  DAY_MS,
  buildExecution,
  buildFinding,
  buildRichDataset,
  truthAt,
  truthState,
} from "./reporting-a-dataset.js";

/**
 * Reporting Part A (rollup core): `RPT-S09` (rollup idempotency and tenant isolation, the retention purge, the failure classes and the
 * bounded, resumable, role-restricted run) and `RPT-S10` (equivalence with the live numbers, backfill equals incremental, DST day
 * boundaries, rebuild after a time-zone change, and the PROOF that the severity series cannot be reconstructed for a past day, which is
 * why it is FORWARD-ONLY). The rollup runs through the real worker repository on a real LOGIN member of `qm_reporting`; the expected values
 * come from the ground truth the dataset keeps in memory (never from the rollup itself) and from independent queries of the views.
 * Out of scope here (ADR-008 area 20): SLA arithmetic itself, risk weights, chart quality.
 */

/** JSON with sorted keys: two structures are the same when their canonical text is. */
const canon = (v) =>
  JSON.stringify(v, (_k, x) =>
    x && typeof x === "object" && !Array.isArray(x)
      ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : x,
  );
const same = (p, label, got, want) => {
  if (canon(got) !== canon(want))
    p.push(`${label}: got ${canon(got)?.slice(0, 400)}, want ${canon(want)?.slice(0, 400)}`);
};
const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const quiet = { info() {}, warn() {}, error() {}, debug() {} };
const MSG = "reporting.rollup.requested";
const SUITE_DATABASE_URL = () => process.env.SECURITY_DATABASE_URL;
const jsonSafe = (v) =>
  JSON.parse(
    JSON.stringify(v, (_k, x) =>
      typeof x === "bigint" ? Number(x) : x instanceof Date ? x.toISOString() : x,
    ),
  );

const STATE_COLUMNS = [
  "open_count",
  "backlog_count",
  "wip_count",
  "awaiting_verification_count",
  "sla_on_track",
  "sla_due_soon",
  "sla_breached",
  "exceptions_in_force",
  "open_age_seconds_sum",
];
const FLOW_COLUMNS = ["new_count", "fixed_count", "closed_other_count", "reopened_count"];
const TABLES = {
  report_daily_findings: "pipeline_id, day, scan_type, severity",
  report_daily_executions: "pipeline_id, day",
  report_daily_decisions: "pipeline_id, day, scan_type",
  report_daily_sbom: "pipeline_id, day",
};

/** Everything of the harness is built once per suite world. */
const worlds = new WeakMap();

async function harness(c) {
  if (worlds.has(c)) return worlds.get(c);
  const promise = (async () => {
    const now = new Date();
    const data = await buildRichDataset(c, { now });
    const adminUrl = SUITE_DATABASE_URL();
    const login = `qm_rollup_chk_${randomBytes(3).toString("hex")}`;
    const password = randomBytes(16).toString("hex");
    await c.db.$executeRawUnsafe(
      `CREATE ROLE ${login} LOGIN PASSWORD '${password}' IN ROLE qm_reporting`,
    );
    const u = new URL(adminUrl);
    u.username = login;
    u.password = password;
    const workerDb = createDbClient({ datasourceUrl: u.toString() });
    const repo = createReportingRollupRepository({ db: workerDb });
    const clock = { now };
    const tenantA = data.pipelines.A1.tenantId;
    const tenantB = data.pipelines.B1.tenantId;
    const h = {
      db: c.db,
      workerDb,
      repo,
      data,
      clock,
      login,
      tenantA,
      tenantB,
      mine: new Set(Object.values(data.pipelines).map((x) => x.id)),
      handler: (over = {}) =>
        createRollupHandler({
          rollupRepository: over.repo ?? repo,
          config: { reporting: { enabled: over.enabled ?? true, rollupRetentionMonths: 25 } },
          logger: quiet,
          now: () => clock.now,
          options: { throttleMs: 0, ...over.options },
        }),
      /** A real, catalogue-validated envelope. */
      message: (tenantId, payload, { payloadTenant = tenantId } = {}) =>
        parseMessage(
          createJobEnvelope({
            messageId: `suite-${randomUUID()}`,
            type: MSG,
            schemaVersion: 1,
            tenantId,
            initiator: { type: "system", id: "suite" },
            payload: { tenantId: payloadTenant, ...payload },
          }),
        ),
      setZone: (tenantId, zone) =>
        c.db
          .$executeRaw`INSERT INTO tenant_reporting_settings (tenant_id, reporting_timezone) VALUES (${tenantId}::uuid, ${zone}) ON CONFLICT (tenant_id) DO UPDATE SET reporting_timezone = ${zone}`,
      clearAll: async (tenantId) => {
        await repo.clearRange({ tenantId, from: "2000-01-01", to: "2099-12-31" });
        await c.db
          .$executeRaw`DELETE FROM report_rollup_runs WHERE tenant_id = ${tenantId}::uuid`.catch(
          () => {},
        );
      },
      /** Every daily row of a tenant as plain JSON (all four tables), ordered by the natural key. */
      snapshot: async (tenantId, { from = "2000-01-01", to = "2099-12-31", drop = [] } = {}) => {
        const out = {};
        for (const [table, order] of Object.entries(TABLES)) {
          const rows = await c.db.$queryRawUnsafe(
            `SELECT * FROM ${table} WHERE tenant_id = $1::uuid AND day BETWEEN $2::date AND $3::date ORDER BY ${order}`,
            tenantId,
            from,
            to,
          );
          out[table] = jsonSafe(rows).map((r) => {
            const copy = { ...r };
            for (const col of drop) delete copy[col];
            return copy;
          });
        }
        return out;
      },
    };
    // the clean slate: the rollups of the dataset's tenants (and the zone) are this check's own
    await c.db
      .$executeRaw`DELETE FROM report_rollup_runs WHERE tenant_id IN (${tenantA}::uuid, ${tenantB}::uuid)`.catch(
      () => {},
    );
    return h;
  })();
  worlds.set(c, promise);
  return promise;
}

/** The columns of a snapshot without the clock, and without all-zero rows (a combination that has no data). */
const normalize = (snap, { stateOff = false } = {}) => {
  const out = {};
  for (const [table, rows] of Object.entries(snap)) {
    out[table] = rows
      .map((r) => {
        const { computed_at: _c, ...rest } = r;
        if (stateOff && table === "report_daily_findings")
          for (const col of STATE_COLUMNS) delete rest[col];
        return rest;
      })
      .filter((r) => Object.entries(r).some(([, v]) => typeof v === "number" && v !== 0));
  }
  return out;
};

const rowsOf = (snap, table) => snap[table] ?? [];
const sum = (rows, col) => rows.reduce((a, r) => a + (r[col] ?? 0), 0);

const FIELD_OF = {
  open: "openCount",
  backlog: "backlogCount",
  wip: "wipCount",
  awaiting: "awaitingVerificationCount",
  onTrack: "slaOnTrack",
  dueSoon: "slaDueSoon",
  breached: "slaBreached",
  exceptions: "exceptionsInForce",
  ageSeconds: "openAgeSecondsSum",
};
const keyOf = (r) => `${r.pipelineId}|${r.scanType}|${r.severity}`;

/** The state rows of the dataset's pipelines at T, keyed. */
async function stateAt(h, T) {
  const m = {};
  for (const tenantId of [h.tenantA, h.tenantB]) {
    const rows = await h.repo.computeFindingsStateAsOf({ tenantId, instant: T });
    for (const r of rows) if (h.mine.has(r.pipelineId)) m[keyOf(r)] = r;
  }
  return m;
}

/** Keys whose counters differ from the ground truth (`fields` limits the comparison). */
function differences(got, truth, fields) {
  const bad = [];
  for (const k of new Set([...Object.keys(got), ...Object.keys(truth)]))
    for (const f of fields) {
      const w = truth[k]?.[f] ?? 0;
      const g = got[k]?.[FIELD_OF[f]] ?? 0;
      if (w !== g) bad.push(`${k.slice(37)} ${f}: rollup ${g}, truth ${w}`);
    }
  return bad;
}

/** The totals across severities per (pipeline, scan type): what a past instant CAN certify. */
function totals(rowsOrTruth, fieldOf) {
  const out = {};
  for (const [k, v] of Object.entries(rowsOrTruth)) {
    const [pipe, scan] = k.split("|");
    const t = (out[`${pipe}|${scan}`] ??= {
      open: 0,
      backlog: 0,
      wip: 0,
      awaiting: 0,
      exceptions: 0,
    });
    for (const f of Object.keys(t)) t[f] += v[fieldOf(f)] ?? 0;
  }
  return out;
}

const DAYS = (h, n) => localDayOf(new Date(h.data.base.getTime() + n * DAY_MS), "UTC");

export const REPORTING_A_CHECKS = [
  {
    id: "RPT-S09a",
    name: "Rollup idempotency (SPEC 7.2, 10; ADR-011): running the same incremental message twice, and a second message with another id, leaves every daily row of every table EXACTLY as the first run left it (counters AND `computed_at`: an unchanged row is not rewritten); a backfill run twice is the same, and a backfill message repeated is RESUMED (the covered batches are skipped, no new run row), while a `repair` backfill recomputes everything and still changes nothing; each run is recorded in `report_rollup_runs` as succeeded with `as_of_history_id` equal to the newest history row at the clock (data as of); the whole path runs on a real LOGIN member of qm_reporting, never the owner",
    async run(c) {
      const p = [];
      const h = await harness(c);
      const { tenantA: A, tenantB: B, clock, repo } = h;
      await h.clearAll(A);
      await h.clearAll(B);
      await h.setZone(A, "UTC");
      await h.setZone(B, "UTC");
      clock.now = new Date();
      const who = (
        await h.workerDb
          .$queryRaw`SELECT current_user::text AS u, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS su`
      )[0];
      same(p, "the rollup connection", [who.u, who.su], [h.login, false]);
      const handler = h.handler();
      const inc = h.message(A, { mode: "incremental" });
      await handler(inc, { log: quiet });
      const s1 = await h.snapshot(A);
      ok(
        p,
        rowsOf(s1, "report_daily_findings").length > 10,
        "the incremental run wrote no findings rows (a vacuous check)",
      );
      ok(
        p,
        sum(rowsOf(s1, "report_daily_findings"), "open_count") > 0,
        "no state counters were written",
      );
      await handler(inc, { log: quiet });
      await handler(h.message(A, { mode: "incremental" }), { log: quiet });
      same(p, "after the same incremental twice and another id", await h.snapshot(A), s1);
      // backfill, twice
      const range = { from: DAYS(h, 0), to: localDayOf(clock.now, "UTC") };
      await handler(h.message(A, { mode: "backfill", ...range }), { log: quiet });
      const b1 = await h.snapshot(A);
      ok(
        p,
        rowsOf(b1, "report_daily_executions").length > 0,
        "the backfill wrote no executions rows",
      );
      ok(
        p,
        rowsOf(b1, "report_daily_decisions").length > 0,
        "the backfill wrote no decisions rows",
      );
      ok(p, rowsOf(b1, "report_daily_sbom").length > 0, "the backfill wrote no SBOM rows");
      const runsAfterFirst = (
        await repo.listRuns({ tenantId: A, from: range.from, to: range.to, mode: "backfill" })
      ).length;
      ok(p, runsAfterFirst >= 1, "the backfill left no run rows");
      await handler(h.message(A, { mode: "backfill", ...range }), { log: quiet });
      same(p, "the backfill repeated (resumed)", await h.snapshot(A), b1);
      same(
        p,
        "a resumed backfill adds no run row",
        (await repo.listRuns({ tenantId: A, from: range.from, to: range.to, mode: "backfill" }))
          .length,
        runsAfterFirst,
      );
      await handler(h.message(A, { mode: "backfill", ...range, reason: "repair" }), { log: quiet });
      same(p, "a repair backfill (recomputes everything)", await h.snapshot(A), b1);
      ok(
        p,
        (await repo.listRuns({ tenantId: A, from: range.from, to: range.to, mode: "backfill" }))
          .length > runsAfterFirst,
        "a repair backfill did not recompute",
      );
      // the ledger
      const runs = await h.db
        .$queryRaw`SELECT mode, status, error_code, as_of_history_id::text AS asof, finished_at FROM report_rollup_runs WHERE tenant_id = ${A}::uuid`;
      ok(
        p,
        runs.length > 0 &&
          runs.every((r) => r.status === "succeeded" && r.error_code === null && r.finished_at),
        "a run is not recorded as succeeded",
      );
      ok(
        p,
        runs.every((r) => r.asof !== null),
        "a run lacks as_of_history_id",
      );
      const newest = (
        await h.db
          .$queryRaw`SELECT id::text AS id FROM report_status_events_v WHERE tenant_id = ${A}::uuid AND created_at <= ${clock.now}::timestamptz ORDER BY created_at DESC, rev DESC, id DESC LIMIT 1`
      )[0];
      const inc1 = runs.find((r) => r.mode === "incremental");
      same(
        p,
        "as_of_history_id of the incremental run is the newest history row at the clock",
        inc1?.asof,
        newest?.id,
      );
      return p;
    },
  },
  {
    id: "RPT-S09b",
    name: "Rollup tenant isolation (ADR-003): a message whose envelope names tenant A and whose payload names tenant B is refused as non-retryable `ownership_mismatch` and writes nothing for either tenant (no row, no run); an unknown tenant and a suspended tenant are refused the same way; a row for another tenant's pipeline handed to the repository of tenant A is refused (explicitly, by the tenant check; and, with the tenant left out, by the COMPOSITE KEY of the database, as is a mismatched workspace or repository), with a control that the right row is accepted; after full runs no row of tenant A names a pipeline of tenant B and the reverse; with `REPORTING_ENABLED` false the handler writes nothing and the tick is not even started, and with it true the tick queues ONE incremental message per tenant per hour (a second tick in the same hour queues nothing new), the close of the previous day until it succeeded, and the first-enablement backfill of a tenant never rolled up; every queued message parses against the catalogue and carries its own tenant",
    async run(c) {
      const p = [];
      const h = await harness(c);
      const { tenantA: A, tenantB: B, clock, repo, db } = h;
      await h.clearAll(A);
      await h.clearAll(B);
      await h.setZone(A, "UTC");
      await h.setZone(B, "UTC");
      // noon UTC today: the hours the tick checks below stay inside one UTC day
      const noon = new Date();
      noon.setUTCHours(12, 0, 0, 0);
      clock.now = noon;
      const handler = h.handler();
      const reason = async (fn) => {
        try {
          await fn();
          return "accepted";
        } catch (error) {
          return error instanceof NonRetryableError
            ? `non-retryable:${error.reason}`
            : `other:${error?.name}`;
        }
      };
      const before = [await h.snapshot(A), await h.snapshot(B)];
      const runsBefore = (
        await db.$queryRaw`SELECT count(*)::int AS n FROM report_rollup_runs WHERE tenant_id IN (${A}::uuid, ${B}::uuid)`
      )[0].n;
      same(
        p,
        "envelope A with a payload naming B",
        await reason(() =>
          handler(h.message(A, { mode: "incremental" }, { payloadTenant: B }), { log: quiet }),
        ),
        "non-retryable:ownership_mismatch",
      );
      same(
        p,
        "envelope B with a payload naming A",
        await reason(() =>
          handler(h.message(B, { mode: "incremental" }, { payloadTenant: A }), { log: quiet }),
        ),
        "non-retryable:ownership_mismatch",
      );
      const ghost = randomUUID();
      same(
        p,
        "an unknown tenant",
        await reason(() => handler(h.message(ghost, { mode: "incremental" }), { log: quiet })),
        "non-retryable:ownership_mismatch",
      );
      await db.$executeRaw`UPDATE tenants SET status = 'suspended' WHERE id = ${B}::uuid`;
      same(
        p,
        "a suspended tenant",
        await reason(() => handler(h.message(B, { mode: "incremental" }), { log: quiet })),
        "non-retryable:ownership_mismatch",
      );
      await db.$executeRaw`UPDATE tenants SET status = 'active' WHERE id = ${B}::uuid`;
      same(
        p,
        "nothing was written by the refused messages",
        [await h.snapshot(A), await h.snapshot(B)],
        before,
      );
      same(
        p,
        "and no run was recorded",
        (
          await db.$queryRaw`SELECT count(*)::int AS n FROM report_rollup_runs WHERE tenant_id IN (${A}::uuid, ${B}::uuid)`
        )[0].n,
        runsBefore,
      );
      // the repository: a row of another tenant's pipeline
      const pa = h.data.pipelines.A1;
      const pb = h.data.pipelines.B1;
      const rowFor = (pipe, over = {}) => ({
        workspaceId: pipe.workspaceId,
        repositoryId: pipe.repositoryId,
        pipelineId: pipe.id,
        day: "2026-11-20",
        scanType: "sast",
        severity: "high",
        newCount: 1,
        fixedCount: 0,
        closedOtherCount: 0,
        reopenedCount: 0,
        ...over,
      });
      const fails = async (fn) => {
        try {
          await fn();
          return null;
        } catch (error) {
          return error?.rollupCode ?? error?.code ?? error?.meta?.code ?? error?.name ?? "error";
        }
      };
      same(
        p,
        "a row that names tenant B in A's call",
        await fails(() =>
          repo.upsertFindingsDays({ tenantId: A, rows: [rowFor(pb, { tenantId: B })] }),
        ),
        "ownership_mismatch",
      );
      const fk = await fails(() => repo.upsertFindingsDays({ tenantId: A, rows: [rowFor(pb)] }));
      ok(
        p,
        fk !== null && fk !== "ownership_mismatch",
        `B's pipeline under tenant A (no tenant on the row) was not refused by the composite key (${fk})`,
      );
      ok(
        p,
        (await fails(() =>
          repo.upsertFindingsDays({
            tenantId: A,
            rows: [rowFor(pa, { workspaceId: h.data.pipelines.A2.workspaceId })],
          }),
        )) !== null,
        "a mismatched workspace was accepted",
      );
      ok(
        p,
        (await fails(() =>
          repo.upsertFindingsDays({
            tenantId: A,
            rows: [rowFor(pa, { repositoryId: h.data.pipelines.A2.repositoryId })],
          }),
        )) !== null,
        "a mismatched repository was accepted",
      );
      ok(
        p,
        (await fails(() =>
          repo.upsertExecutionsDays({
            tenantId: A,
            rows: [
              {
                ...rowFor(pb),
                total: 1,
                succeededCount: 1,
                failedCount: 0,
                partialCount: 0,
                timedOutCount: 0,
                cancelledCount: 0,
                skippedCount: 0,
                blockedCount: 0,
                durationMsSum: 0,
                queueWaitMsSum: 0,
                eligibleCount: 0,
                resultCompleteCount: 0,
                resultPartialCount: 0,
              },
            ],
          }),
        )) !== null,
        "an executions row of B's pipeline under A was accepted",
      );
      same(
        p,
        "a hostile tenant id",
        await fails(() =>
          repo.computeFindingsFlow({
            tenantId: "x'; DROP TABLE report_daily_findings; --",
            from: "2026-11-01",
            to: "2026-11-02",
            timeZone: "UTC",
          }),
        ),
        "ownership_mismatch",
      );
      same(
        p,
        "a hostile day",
        await fails(() =>
          repo.upsertFindingsDays({ tenantId: A, rows: [rowFor(pa, { day: "2026-11-20'; --" })] }),
        ),
        "invalid_range",
      );
      same(
        p,
        "the refused rows left nothing behind",
        [await h.snapshot(A), await h.snapshot(B)],
        before,
      );
      same(
        p,
        "control: the right row is accepted",
        await fails(() => repo.upsertFindingsDays({ tenantId: A, rows: [rowFor(pa)] })),
        null,
      );
      await h.clearAll(A);
      // full runs, then no row crosses a tenant
      await handler(h.message(A, { mode: "incremental" }), { log: quiet });
      await handler(h.message(B, { mode: "incremental" }), { log: quiet });
      await handler(
        h.message(A, { mode: "backfill", from: DAYS(h, 0), to: localDayOf(clock.now, "UTC") }),
        { log: quiet },
      );
      const aIds = [h.data.pipelines.A1.id, h.data.pipelines.A2.id];
      for (const table of Object.keys(TABLES)) {
        const cross = (
          await db.$queryRawUnsafe(
            `SELECT count(*)::int AS n FROM ${table} WHERE (tenant_id = $1::uuid AND pipeline_id <> ALL($3::uuid[])) OR (tenant_id = $2::uuid AND pipeline_id = ANY($3::uuid[]))`,
            A,
            B,
            aIds,
          )
        )[0].n;
        same(p, `${table}: rows naming another tenant's pipeline`, cross, 0);
      }
      ok(
        p,
        rowsOf(await h.snapshot(B), "report_daily_findings").length > 0,
        "tenant B's own run wrote nothing (a vacuous check)",
      );
      // the flag
      await h.clearAll(A);
      const off = await h.snapshot(A);
      await h.handler({ enabled: false })(h.message(A, { mode: "incremental" }), { log: quiet });
      same(p, "REPORTING_ENABLED false: the handler writes nothing", await h.snapshot(A), off);
      same(
        p,
        "REPORTING_ENABLED false: and records no run",
        (
          await db.$queryRaw`SELECT count(*)::int AS n FROM report_rollup_runs WHERE tenant_id = ${A}::uuid`
        )[0].n,
        0,
      );
      await handler(h.message(A, { mode: "incremental" }), { log: quiet });
      same(
        p,
        "REPORTING_ENABLED false: no tick is started",
        startRollupTick({
          db,
          rollupRepository: repo,
          config: { reporting: { enabled: false } },
          logger: quiet,
        }),
        null,
      );
      // the tick
      const fresh = await buildFindingsWorld(db);
      const fp = (await fresh.published(fresh.A, 0)).pipeline;
      await buildFinding(fresh, fp, {
        toolSeverity: "high",
        firstAt: new Date(clock.now.getTime() - 3 * DAY_MS),
        steps: [],
      });
      const tenantsToCheck = [A, B, fp.tenantId];
      const queued = async (type = MSG) =>
        (
          await db.outboxMessage.findMany({
            where: { tenantId: { in: tenantsToCheck }, type, queue: QUEUE_NAMES.REPORTING },
          })
        ).map((r) => r.payload);
      const deps = {
        db,
        rollupRepository: repo,
        config: { reporting: { enabled: true, rollupRetentionMonths: 25 } },
        logger: quiet,
        now: () => clock.now,
      };
      await db.outboxMessage.deleteMany({
        where: { tenantId: { in: tenantsToCheck }, queue: QUEUE_NAMES.REPORTING },
      });
      await runTick(deps);
      const first = await queued();
      const count = (list, tenant, mode) =>
        list.filter((m) => m.tenantId === tenant && m.payload.mode === mode).length;
      for (const t of [A, B, fp.tenantId])
        same(
          p,
          `tick: one incremental for ${t === A ? "A" : t === B ? "B" : "the fresh tenant"}`,
          count(first, t, "incremental"),
          1,
        );
      same(
        p,
        "tick: the close of yesterday is queued until it succeeded (A)",
        count(first, A, "close"),
        1,
      );
      same(
        p,
        "tick: the first-enablement backfill of a tenant never rolled up",
        [count(first, fp.tenantId, "backfill"), count(first, A, "backfill")],
        [1, 0],
      );
      for (const m of first) {
        const parsed = parseMessage(m);
        ok(
          p,
          parsed.tenantId === parsed.payload.tenantId,
          "a queued message names a payload tenant different from its envelope",
        );
      }
      const bf = first.find((m) => m.tenantId === fp.tenantId && m.payload.mode === "backfill");
      same(
        p,
        "the backfill payload",
        [bf?.payload.reason, bf?.payload.to, bf?.payload.from <= bf?.payload.to],
        ["first_enablement", localDayOf(clock.now, "UTC"), true],
      );
      await runTick(deps);
      same(
        p,
        "a second tick in the same hour queues nothing new",
        (await queued()).length,
        first.length,
      );
      clock.now = new Date(clock.now.getTime() + HOUR);
      await runTick(deps);
      ok(
        p,
        count(await queued(), A, "incremental") === 2,
        "the next hour did not queue another incremental message",
      );
      // the close succeeds once, then it is not queued again
      const yesterday = addDays(localDayOf(clock.now, "UTC"), -1);
      await handler(h.message(A, { mode: "close", day: yesterday }), { log: quiet });
      const before2 = count(await queued(), A, "close");
      clock.now = new Date(clock.now.getTime() + HOUR);
      await runTick(deps);
      same(
        p,
        "no new close once yesterday's close succeeded",
        count(await queued(), A, "close"),
        before2,
      );
      clock.now = new Date();
      return p;
    },
  },
  {
    id: "RPT-S09c",
    name: "Rollup failure classes, bounds and the role (SPEC 10): a transient database error becomes a RETRYABLE failure (`source_unavailable`), a statement timeout a retryable `timeout`, an input or ownership problem and an unknown error NON-retryable (`invalid_range` / `ownership_mismatch` / `internal`), each leaving a `failed` run row with a stable code of the vocabulary and a finish time; an invalid range, an invalid mode and a tenant whose time zone this runtime does not know are non-retryable; every transaction of the repository starts with `SET LOCAL statement_timeout`; a backfill is processed in batches of the configured number of days (one run row each, none longer), is RESUMABLE after a failure in the middle (the completed batches are skipped and the final rows equal an uninterrupted run), and is capped at the rollup retention; the worker login has no privilege on any source table",
    async run(c) {
      const p = [];
      const h = await harness(c);
      const { tenantA: A, clock, repo, db } = h;
      await h.clearAll(A);
      await h.setZone(A, "UTC");
      clock.now = new Date();
      const failing = (name, error) => ({
        ...repo,
        [name]: async () => {
          throw error;
        },
      });
      const trial = async (over, payload = { mode: "incremental" }, raw = false) => {
        try {
          // `raw`: a payload the catalogue itself would refuse (the handler must not rely on that)
          const message = raw
            ? { ...h.message(A, { mode: "incremental" }), payload: { tenantId: A, ...payload } }
            : h.message(A, payload);
          await h.handler({ repo: over })(message, { log: quiet });
          return "accepted";
        } catch (error) {
          return error instanceof TransientError
            ? "transient"
            : error instanceof NonRetryableError
              ? `non-retryable:${error.reason}`
              : `other:${error?.name}`;
        }
      };
      const lastRun = async () =>
        (
          await db.$queryRaw`SELECT status, error_code, finished_at FROM report_rollup_runs WHERE tenant_id = ${A}::uuid ORDER BY started_at DESC, id DESC LIMIT 1`
        )[0];
      const cases = [
        [
          "a connection error",
          Object.assign(new Error("db down"), { code: "P1001" }),
          "transient",
          "source_unavailable",
        ],
        [
          "a deadlock",
          Object.assign(new Error("deadlock"), { meta: { code: "40P01" } }),
          "transient",
          "source_unavailable",
        ],
        [
          "a statement timeout",
          Object.assign(new Error("canceling statement due to statement timeout"), {
            meta: { code: "57014" },
          }),
          "transient",
          "timeout",
        ],
        ["an unknown error", new Error("boom"), "non-retryable:internal", "internal"],
      ];
      for (const [label, error, want, code] of cases) {
        same(p, label, await trial(failing("computeFindingsStateAsOf", error)), want);
        const run = await lastRun();
        same(
          p,
          `${label}: the run row`,
          [run?.status, run?.error_code, run?.finished_at !== null],
          ["failed", code, true],
        );
        ok(
          p,
          ROLLUP_ERROR_CODES.includes(run?.error_code),
          `${label}: the code is not in the vocabulary`,
        );
      }
      const inputError = Object.assign(new Error("bad"), { rollupCode: "invalid_range" });
      same(
        p,
        "an input error",
        await trial(failing("computeFindingsStateAsOf", inputError)),
        "non-retryable:invalid_range",
      );
      same(
        p,
        "an invalid backfill range",
        await trial(repo, { mode: "backfill", from: "2026-11-05", to: "2026-11-01" }, true),
        "non-retryable:invalid_range",
      );
      same(
        p,
        "an unknown mode",
        await trial(repo, { mode: "everything" }, true),
        "non-retryable:invalid_range",
      );
      same(
        p,
        "a close for today",
        await trial(repo, { mode: "close", day: localDayOf(clock.now, "UTC") }),
        "non-retryable:invalid_range",
      );
      await h.setZone(A, "Mars/Olympus_Mons");
      same(
        p,
        "a time zone this runtime does not know",
        await trial(repo),
        "non-retryable:invalid_range",
      );
      await h.setZone(A, "UTC");
      // SET LOCAL statement_timeout first in every transaction
      const seen = [];
      const spy = {
        $transaction: (fn, o) =>
          h.workerDb.$transaction((tx) => {
            let first = null;
            const proxy = new Proxy(tx, {
              get: (t, k) =>
                k === "$executeRawUnsafe" ||
                k === "$queryRaw" ||
                k === "$queryRawUnsafe" ||
                k === "$executeRaw"
                  ? (...a) => (
                      (first ??= String(a[0]?.strings?.[0] ?? a[0]).slice(0, 40)),
                      t[k](...a)
                    )
                  : t[k],
            });
            return fn(proxy).finally(() => seen.push(first));
          }, o),
        $queryRaw: (...a) => h.workerDb.$queryRaw(...a),
        $queryRawUnsafe: (...a) => h.workerDb.$queryRawUnsafe(...a),
        $executeRaw: (...a) => h.workerDb.$executeRaw(...a),
        $executeRawUnsafe: (...a) => h.workerDb.$executeRawUnsafe(...a),
      };
      const spyRepo = createReportingRollupRepository({ db: spy });
      await spyRepo.computeFindingsFlow({
        tenantId: A,
        from: DAYS(h, 30),
        to: DAYS(h, 31),
        timeZone: "UTC",
      });
      await spyRepo.computeFindingsStateAsOf({ tenantId: A, instant: clock.now });
      await spyRepo.upsertFindingsDays({ tenantId: A, rows: [] });
      ok(
        p,
        seen.length === 3 && seen.every((s) => /^SET LOCAL statement_timeout = \d+$/.test(s)),
        `a transaction does not start with SET LOCAL statement_timeout: ${JSON.stringify(seen)}`,
      );
      // batches, resume, cap
      await h.clearAll(A);
      const range = { from: DAYS(h, 0), to: localDayOf(clock.now, "UTC") };
      await h.handler({ options: { backfillBatchDays: 10 } })(
        h.message(A, { mode: "backfill", ...range }),
        { log: quiet },
      );
      const full = await h.snapshot(A);
      const runs =
        await db.$queryRaw`SELECT to_char(day, 'YYYY-MM-DD') AS d, to_char(range_to, 'YYYY-MM-DD') AS t, status FROM report_rollup_runs WHERE tenant_id = ${A}::uuid AND mode = 'backfill' ORDER BY day`;
      ok(
        p,
        runs.length >= 4 &&
          runs.every(
            (r) => r.status === "succeeded" && (Date.parse(r.t) - Date.parse(r.d)) / DAY_MS < 10,
          ),
        `the backfill was not processed in batches of at most 10 days (${runs.length} runs)`,
      );
      await h.clearAll(A);
      let calls = 0;
      const flaky = {
        ...repo,
        computeExecutionsDays: (args) =>
          ++calls === 3
            ? Promise.reject(Object.assign(new Error("gone"), { code: "P1001" }))
            : repo.computeExecutionsDays(args),
      };
      same(
        p,
        "a failure in the third batch",
        await (async () => {
          try {
            await h.handler({ repo: flaky, options: { backfillBatchDays: 10 } })(
              h.message(A, { mode: "backfill", ...range }),
              { log: quiet },
            );
            return "accepted";
          } catch (error) {
            return error instanceof TransientError ? "transient" : "other";
          }
        })(),
        "transient",
      );
      const okRuns = (
        await db.$queryRaw`SELECT count(*)::int AS n FROM report_rollup_runs WHERE tenant_id = ${A}::uuid AND mode = 'backfill' AND status = 'succeeded'`
      )[0].n;
      same(p, "two batches completed before it", okRuns, 2);
      await h.handler({ options: { backfillBatchDays: 10 } })(
        h.message(A, { mode: "backfill", ...range }),
        { log: quiet },
      );
      same(
        p,
        "the resumed run equals an uninterrupted one",
        normalize(await h.snapshot(A)),
        normalize(full),
      );
      same(
        p,
        "and re-ran only the missing batches",
        (
          await db.$queryRaw`SELECT count(*)::int AS n FROM report_rollup_runs WHERE tenant_id = ${A}::uuid AND mode = 'backfill' AND status = 'succeeded'`
        )[0].n,
        runs.length,
      );
      // the cap at the retention: a start before the floor is cut
      await h.clearAll(A);
      await h.handler()(h.message(A, { mode: "backfill", from: "2020-01-01", to: "2020-01-31" }), {
        log: quiet,
      });
      same(
        p,
        "a range wholly before the retention does nothing",
        (
          await db.$queryRaw`SELECT count(*)::int AS n FROM report_rollup_runs WHERE tenant_id = ${A}::uuid`
        )[0].n,
        0,
      );
      // the worker login cannot read any source table
      for (const table of [
        "findings",
        "finding_evidence",
        "finding_reviews",
        "finding_ai_advisories",
        "executions",
      ]) {
        const r = await attempt(() => h.workerDb.$queryRawUnsafe(`SELECT 1 FROM ${table} LIMIT 1`));
        ok(p, !r.ok && /permission denied/.test(r.message), `the worker login can read ${table}`);
      }
      return p;
    },
  },
  {
    id: "RPT-S09d",
    name: "Retention purge (SPEC 8.6): through the SECURITY DEFINER function, rollup rows older than the cutoff day, run rows older than the cutoff instant and export rows older than theirs are removed in bounded calls while newer rows and running runs stay; the worker's tick purge uses the 25-month retention for rollups and 13 months for runs; the purge of the role without DELETE works only through the function",
    async run(c) {
      const p = [];
      const h = await harness(c);
      const { tenantA: A, clock, repo, db } = h;
      await h.clearAll(A);
      clock.now = new Date();
      const pa = h.data.pipelines.A1;
      const old = subtractMonths(localDayOf(clock.now, "UTC"), 26);
      const young = subtractMonths(localDayOf(clock.now, "UTC"), 24);
      const row = (day) => ({
        tenantId: A,
        workspaceId: pa.workspaceId,
        repositoryId: pa.repositoryId,
        pipelineId: pa.id,
        day,
        scanType: "sast",
        severity: "high",
        newCount: 1,
        fixedCount: 0,
        closedOtherCount: 0,
        reopenedCount: 0,
      });
      await repo.upsertFindingsDays({ tenantId: A, rows: [row(old), row(young)] });
      const oldRun = await repo.startRun({
        tenantId: A,
        mode: "close",
        day: old,
        timeZone: "UTC",
        now: new Date(clock.now.getTime() - 14 * 31 * DAY_MS),
      });
      await repo.finishRun({
        tenantId: A,
        runId: oldRun.id,
        status: "succeeded",
        rowsWritten: 1,
        now: new Date(clock.now.getTime() - 14 * 31 * DAY_MS),
      });
      const youngRun = await repo.startRun({
        tenantId: A,
        mode: "close",
        day: young,
        timeZone: "UTC",
        now: new Date(clock.now.getTime() - 30 * DAY_MS),
      });
      await repo.finishRun({
        tenantId: A,
        runId: youngRun.id,
        status: "succeeded",
        rowsWritten: 1,
        now: new Date(clock.now.getTime() - 30 * DAY_MS),
      });
      const stuck = await repo.startRun({
        tenantId: A,
        mode: "incremental",
        day: old,
        timeZone: "UTC",
        now: new Date(clock.now.getTime() - 20 * 31 * DAY_MS),
      });
      const days = async () =>
        (
          await db.$queryRaw`SELECT to_char(day, 'YYYY-MM-DD') AS d FROM report_daily_findings WHERE tenant_id = ${A}::uuid ORDER BY day`
        ).map((r) => r.d);
      same(p, "before", await days(), [old, young]);
      const direct = await attempt(
        () =>
          h.workerDb.$executeRaw`DELETE FROM report_daily_findings WHERE tenant_id = ${A}::uuid`,
      );
      ok(
        p,
        !direct.ok && /permission denied/.test(direct.message),
        "the worker role can DELETE directly",
      );
      const removed = await runPurge({
        rollupRepository: repo,
        config: { reporting: { rollupRetentionMonths: 25 } },
        logger: quiet,
        now: () => clock.now,
      });
      ok(p, removed >= 2, `the purge removed ${removed} rows`);
      same(p, "after: only the young rollup row", await days(), [young]);
      const runIds = (
        await db.$queryRaw`SELECT id::text AS id FROM report_rollup_runs WHERE tenant_id = ${A}::uuid`
      ).map((r) => r.id);
      ok(
        p,
        !runIds.includes(oldRun.id) && runIds.includes(youngRun.id),
        "the old run row was not purged or the young one was",
      );
      ok(p, runIds.includes(stuck.id), "a running run row was purged");
      // the limit bounds one call
      await repo.upsertFindingsDays({
        tenantId: A,
        rows: [row(old), row(addDays(old, 1)), row(addDays(old, 2))],
      });
      const one = await repo.purgeExpired({
        rollupBefore: young,
        runsBefore: new Date(0),
        exportsBefore: new Date(0),
        limit: 1,
      });
      same(p, "a call with limit 1 removes at most one row per table", one, 1);
      await runPurge({
        rollupRepository: repo,
        config: { reporting: { rollupRetentionMonths: 25 } },
        logger: quiet,
        now: () => clock.now,
      });
      same(p, "the repeated purge drains the rest", await days(), [young]);
      await h.clearAll(A);
      return p;
    },
  },
  {
    id: "RPT-S10a",
    name: "Equivalence with the live numbers at T = now (SPEC 7.2, 16.1; the severity gate of the owner ruling, part 1): on a dataset with severity overrides by approved reviews, a tool re-rate, reopenings, accepted risk with an expiry (one already expired by time) and suppression, fixed and verified findings, false positives, in two workspaces and two tenants, the rollup's `computeFindingsStateAsOf(now)` equals (a) the ground truth the dataset recorded and (b) an independent computation over `report_findings_v` with the shared SLA function, for EVERY (pipeline, scan type, severity) key and every counter (open, backlog, work in progress, awaiting verification, SLA on track, due soon, breached, exceptions in force, age); the per-severity open counts equal the live counts; the rows of one tenant never contain the other's pipelines; every row is flagged severity-exact at now",
    async run(c) {
      const p = [];
      const h = await harness(c);
      const T = new Date();
      const got = await stateAt(h, T);
      const want = truthState(h.data.truths, T);
      ok(
        p,
        Object.keys(want).length > 20,
        `the dataset is too small (${Object.keys(want).length} keys)`,
      );
      for (const msg of differences(got, want, Object.keys(FIELD_OF)))
        p.push(`vs ground truth: ${msg}`);
      // (b) the live computation from the view, independent of the rollup SQL
      const live = {};
      for (const tenantId of [h.tenantA, h.tenantB]) {
        const rows = await h.workerDb.$queryRaw`
          SELECT pipeline_id::text AS pid, scan_type::text AS scan, severity::text AS sev, status::text AS status, sla_started_at, sla_due_at, first_detected_at, exception_expires_at
          FROM report_findings_v WHERE tenant_id = ${tenantId}::uuid`;
        for (const r of rows) {
          if (!h.mine.has(r.pid)) continue;
          const open = OPEN_FINDING_STATUSES.includes(r.status);
          const exc =
            ["accepted_risk", "suppressed"].includes(r.status) &&
            (!r.exception_expires_at || r.exception_expires_at.getTime() > T.getTime());
          if (!open && !exc) continue;
          const k = `${r.pid}|${r.scan}|${r.sev}`;
          const l = (live[k] ??= {
            open: 0,
            backlog: 0,
            wip: 0,
            awaiting: 0,
            onTrack: 0,
            dueSoon: 0,
            breached: 0,
            exceptions: 0,
            ageSeconds: 0,
          });
          if (exc) l.exceptions += 1;
          if (!open) continue;
          l.open += 1;
          const group = LIFECYCLE_GROUP_OF_STATUS[r.status];
          if (
            ["confirmed_in_remediation", "awaiting_verification"].includes(group) &&
            r.status !== "approved"
          )
            l.wip += 1;
          else l.backlog += 1;
          if (r.status === "fixed_pending_verification") l.awaiting += 1;
          l.ageSeconds += Math.floor(
            Math.max(0, T.getTime() - r.first_detected_at.getTime()) / 1000,
          );
          const s = deriveSlaState({ startedAt: r.sla_started_at, dueAt: r.sla_due_at, now: T });
          if (s === "on_track") l.onTrack += 1;
          if (s === "due_soon") l.dueSoon += 1;
          if (s === "breached") l.breached += 1;
        }
      }
      for (const msg of differences(got, live, Object.keys(FIELD_OF)))
        p.push(`vs the live view: ${msg}`);
      const bySev = (m, f) =>
        Object.fromEntries(
          ["critical", "high", "medium", "low", "info"].map((s) => [
            s,
            Object.entries(m)
              .filter(([k]) => k.endsWith(`|${s}`))
              .reduce((a, [, v]) => a + (v[f] ?? 0), 0),
          ]),
        );
      same(
        p,
        "open per severity, rollup against live",
        bySev(got, "openCount"),
        bySev(live, "open"),
      );
      ok(
        p,
        Object.values(bySev(live, "open")).filter((n) => n > 0).length >= 4,
        "the dataset does not cover the severities",
      );
      ok(
        p,
        Object.values(got).every((r) => r.severityExact === true),
        "a row at now is not flagged severity-exact",
      );
      // the groups used are the shared ones
      ok(
        p,
        Object.values(got).every(
          (r) =>
            r.openCount === r.backlogCount + r.wipCount &&
            r.awaitingVerificationCount <= r.wipCount,
        ),
        "a row breaks open = backlog + work in progress",
      );
      // dataset covers what the issue demands
      const statusesNow = new Set(h.data.truths.map((t) => truthAt(t, T)?.status));
      for (const s of [
        "accepted_risk",
        "suppressed",
        "verified_fixed",
        "reopened",
        "false_positive",
        "fixed_pending_verification",
        "assigned",
      ])
        ok(p, statusesNow.has(s), `the dataset has no finding in ${s}`);
      return p;
    },
  },
  {
    id: "RPT-S10b",
    name: "The severity series is FORWARD-ONLY (owner ruling 2026-11-26, severity gate part 2; the check proves the REASON and the BEHAVIOUR). Proof that the severity split of a past day cannot be reconstructed exactly from the views: (1) the counts that do not depend on severity (status totals per pipeline and scan type) ARE exact at past instants, against the ground truth; (2) the split by severity is NOT: at an instant before an approved review override the finding is counted under its CURRENT severity (flagged `severityExact` false), and at an instant before a tool re-rate (which leaves no history row and no decision) the rollup is wrong while still flagged exact, so no flag can certify a past day. Behaviour: a backfill writes the flow, executions, decisions and SBOM series and NEVER a state counter (every state column of a past day stays 0, and it does not zero a state snapshot a live run wrote); a close within the lag writes the day's state, a close past the lag leaves the hourly snapshot untouched, and a close with a later severity override in the way also leaves it; the first exact day is recorded as the day of the first succeeded incremental or close run",
    async run(c) {
      const p = [];
      const h = await harness(c);
      const { tenantA: A, clock, repo, db } = h;
      await h.clearAll(A);
      await h.setZone(A, "UTC");
      const NOW = new Date();
      // (1) exact totals at several past instants
      const instants = [10, 17, 24, 31].map((d) => new Date(NOW.getTime() - d * DAY_MS));
      for (const T of instants) {
        const got = await stateAt(h, T);
        const want = truthState(h.data.truths, T);
        const t1 = totals(got, (f) => FIELD_OF[f]);
        const t2 = totals(want, (f) => f);
        same(
          p,
          `status totals per pipeline and scan type at ${T.toISOString().slice(0, 10)}`,
          t1,
          t2,
        );
      }
      // (2) the severity split is not reconstructable
      const later = h.data.truths.filter((t) => t.severityTimeline.length > 1);
      ok(p, later.length >= 4, "the dataset has no severity changes");
      let flaggedInexact = 0;
      let wrongButFlaggedExact = 0;
      for (const t of later) {
        // one hour before the severity of this finding changed
        const T = new Date(t.severityTimeline[1].at.getTime() - HOUR);
        const got = await stateAt(h, T);
        const want = truthState(h.data.truths, T);
        for (const k of Object.keys({ ...got, ...want })) {
          if ((got[k]?.openCount ?? 0) === (want[k]?.open ?? 0)) continue;
          if (got[k]?.severityExact === false) flaggedInexact += 1;
          if (got[k]?.severityExact === true) wrongButFlaggedExact += 1;
        }
      }
      ok(
        p,
        flaggedInexact > 0,
        "no override-affected row was flagged severity-inexact at a past instant",
      );
      ok(
        p,
        wrongButFlaggedExact > 0,
        "no re-rate showed a wrong past severity under an exact flag (the dataset lost its re-rate)",
      );
      // behaviour: a backfill writes no state and zeroes none
      clock.now = new Date();
      const handler = h.handler();
      await handler(h.message(A, { mode: "incremental" }), { log: quiet });
      const today = localDayOf(clock.now, "UTC");
      const live = await h.snapshot(A, { from: today, to: today });
      ok(
        p,
        sum(rowsOf(live, "report_daily_findings"), "open_count") > 0,
        "the live run wrote no state (a vacuous check)",
      );
      await handler(
        h.message(A, { mode: "backfill", from: DAYS(h, 0), to: today, reason: "repair" }),
        { log: quiet },
      );
      const all = await h.snapshot(A);
      const past = rowsOf(all, "report_daily_findings").filter((r) => r.day < today);
      ok(p, past.length > 10, "the backfill wrote no past flow rows (a vacuous check)");
      same(
        p,
        "state columns of past days after a backfill",
        STATE_COLUMNS.map((col) => sum(past, col)),
        STATE_COLUMNS.map(() => 0),
      );
      ok(p, sum(past, "new_count") > 0, "the backfill wrote no flow counters");
      same(
        p,
        "a backfill leaves today's state snapshot as the live run wrote it",
        (await h.snapshot(A, { from: today, to: today })).report_daily_findings.map((r) =>
          Object.fromEntries(STATE_COLUMNS.map((c2) => [c2, r[c2]])),
        ),
        live.report_daily_findings.map((r) =>
          Object.fromEntries(STATE_COLUMNS.map((c2) => [c2, r[c2]])),
        ),
      );
      // the first exact day
      const first = (
        await db.$queryRaw`SELECT to_char(min(day), 'YYYY-MM-DD') AS d FROM report_rollup_runs WHERE tenant_id = ${A}::uuid AND mode IN ('incremental', 'close') AND status = 'succeeded'`
      )[0].d;
      same(p, "the first exact day (first succeeded live run)", first, today);
      // close: within the lag, past the lag, and with a severity override in the way
      const yesterday = addDays(today, -1);
      const yClose = dayCloseInstant(yesterday, "UTC");
      await repo.clearRange({ tenantId: A, from: yesterday, to: yesterday });
      clock.now = new Date(yClose.getTime() + HOUR);
      await h.handler({ options: { closeStateMaxLagMs: 6 * HOUR } })(
        h.message(A, { mode: "close", day: yesterday }),
        { log: quiet },
      );
      const closed = await h.snapshot(A, { from: yesterday, to: yesterday });
      const wantClose = await repo.computeFindingsStateAsOf({ tenantId: A, instant: yClose });
      ok(
        p,
        wantClose.some((r) => h.mine.has(r.pipelineId)),
        "no state at the close instant (a vacuous check)",
      );
      same(
        p,
        "a close within the lag writes the state at the end of the day",
        sum(closed.report_daily_findings, "open_count"),
        wantClose.reduce((a, r) => a + r.openCount, 0),
      );
      await repo.clearRange({ tenantId: A, from: yesterday, to: yesterday });
      clock.now = new Date(yClose.getTime() + 10 * HOUR);
      await h.handler({ options: { closeStateMaxLagMs: 6 * HOUR } })(
        h.message(A, { mode: "close", day: yesterday }),
        { log: quiet },
      );
      same(
        p,
        "a close past the lag writes no state",
        sum(
          (await h.snapshot(A, { from: yesterday, to: yesterday })).report_daily_findings,
          "open_count",
        ),
        0,
      );
      // an override decided after T is in the way: pick the day before an override of the dataset
      const mineA = new Set([h.data.pipelines.A1.id, h.data.pipelines.A2.id]);
      const override = h.data.truths.find(
        (t) =>
          mineA.has(t.pipelineId) &&
          t.timeline.some((x) => x.status === "approved") &&
          t.severityTimeline.length > 1 &&
          t.severityTimeline[1].at.getTime() < NOW.getTime() - 4 * DAY_MS,
      );
      ok(p, override !== undefined, "the dataset has no approved severity override in tenant A");
      if (override) {
        const day = localDayOf(
          new Date(override.severityTimeline[1].at.getTime() - 2 * DAY_MS),
          "UTC",
        );
        const dClose = dayCloseInstant(day, "UTC");
        await repo.clearRange({ tenantId: A, from: day, to: day });
        clock.now = new Date(dClose.getTime() + HOUR);
        const wantDay = await repo.computeFindingsStateAsOf({ tenantId: A, instant: dClose });
        ok(
          p,
          wantDay.reduce((a, r) => a + r.openCount, 0) > 0 &&
            wantDay.some((r) => r.severityExact === false),
          "the chosen day has no open findings or no override in the way (a vacuous check)",
        );
        await h.handler({ options: { closeStateMaxLagMs: 400 * DAY_MS } })(
          h.message(A, { mode: "close", day }),
          { log: quiet },
        );
        same(
          p,
          "a close with a later severity override in the way leaves the day's state alone",
          sum((await h.snapshot(A, { from: day, to: day })).report_daily_findings, "open_count"),
          0,
        );
      }
      clock.now = new Date();
      await h.clearAll(A);
      return p;
    },
  },
  {
    id: "RPT-S10c",
    name: "Backfill equals incremental (severity gate part 3), with a CONTROLLED CLOCK: the incremental job run with the clock at the close of a past tenant-local day (Europe/Berlin) and the backfill of the same two days give, row by row and column by column, the same flow, executions, decisions and SBOM series (every row of the four tables diffed, none missing, none extra), the backfill leaves the live state snapshot of those days exactly as written, and a backfill into a CLEARED range reproduces every non-state column of the incremental rows while its state columns are 0 (the state comes only from a live run); the day close run later on the unchanged data rewrites nothing (identical rows, `computed_at` included)",
    async run(c) {
      const p = [];
      const h = await harness(c);
      const { tenantA: A, clock, repo } = h;
      const tz = "Europe/Berlin";
      await h.clearAll(A);
      await h.setZone(A, tz);
      // a day on which the dataset has executions
      const withExec = h.data.executions.find(
        (e) =>
          e.status === "succeeded" &&
          e.row.requestedAt.getTime() < Date.now() - 3 * DAY_MS &&
          e.row.requestedAt.getTime() > h.data.base.getTime() + 2 * DAY_MS,
      );
      ok(p, withExec !== undefined, "the dataset has no suitable execution");
      const D = localDayOf(new Date(withExec.row.requestedAt.getTime() + 10 * HOUR), tz);
      const D1 = addDays(D, -1);
      const T = dayCloseInstant(D, tz);
      clock.now = T;
      const handler = h.handler();
      await handler(h.message(A, { mode: "incremental" }), { log: quiet });
      const inc = await h.snapshot(A, { from: D1, to: D });
      const flowRows = rowsOf(inc, "report_daily_findings").filter((r) =>
        FLOW_COLUMNS.some((col) => r[col] > 0),
      );
      ok(
        p,
        flowRows.length >= 2,
        `the two days have too little flow to compare (${flowRows.length})`,
      );
      ok(p, rowsOf(inc, "report_daily_executions").length >= 1, "the two days have no executions");
      ok(
        p,
        sum(rowsOf(inc, "report_daily_findings"), "open_count") > 0,
        "the incremental run wrote no state",
      );
      // (1) the backfill of the same days on top of the incremental rows: nothing changes
      await handler(h.message(A, { mode: "backfill", from: D1, to: D }), { log: quiet });
      same(
        p,
        "backfill over the incremental rows, every row of the four tables",
        await h.snapshot(A, { from: D1, to: D }),
        inc,
      );
      // (2) the backfill into a cleared range reproduces the non-state columns
      await repo.clearRange({ tenantId: A, from: D1, to: D });
      await handler(h.message(A, { mode: "backfill", from: D1, to: D, reason: "repair" }), {
        log: quiet,
      });
      const bf = await h.snapshot(A, { from: D1, to: D });
      same(
        p,
        "backfill alone, every non-state column of the four tables",
        normalize(bf, { stateOff: true }),
        normalize(inc, { stateOff: true }),
      );
      same(
        p,
        "backfill alone writes no state column",
        STATE_COLUMNS.map((col) => sum(rowsOf(bf, "report_daily_findings"), col)),
        STATE_COLUMNS.map(() => 0),
      );
      // (3) the same flow equals an independent bucketing of the history rows in the tenant zone
      const events = await h.db.$queryRaw`
        SELECT e.pipeline_id::text AS pid, e.created_at, e.from_status::text AS f, e.to_status::text AS t FROM report_status_events_v e WHERE e.tenant_id = ${A}::uuid`;
      const want = { new: 0, fixed: 0, closed: 0, reopened: 0 };
      for (const e of events) {
        const day = localDayOf(e.created_at, tz);
        if (day !== D && day !== D1) continue;
        if (e.f === null) want.new += 1;
        else if (e.t === "verified_fixed") want.fixed += 1;
        else if (["false_positive", "suppressed", "accepted_risk"].includes(e.t)) want.closed += 1;
        else if (e.t === "reopened") want.reopened += 1;
      }
      same(
        p,
        "flow totals against an independent bucketing",
        ["new_count", "fixed_count", "closed_other_count", "reopened_count"].map((col) =>
          sum(rowsOf(bf, "report_daily_findings"), col),
        ),
        [want.new, want.fixed, want.closed, want.reopened],
      );
      // (4) the state of the day: from the live run, equal to the state recomputed at T, and the later close rewrites nothing
      await repo.clearRange({ tenantId: A, from: D1, to: D });
      await handler(h.message(A, { mode: "incremental" }), { log: quiet });
      const live = await h.snapshot(A, { from: D, to: D });
      const stateAtT = await repo.computeFindingsStateAsOf({ tenantId: A, instant: T });
      same(
        p,
        "the day's state rows equal the state recomputed at the close instant",
        sum(rowsOf(live, "report_daily_findings"), "open_count"),
        stateAtT.reduce((a, r) => a + r.openCount, 0),
      );
      clock.now = new Date(T.getTime() + HOUR);
      await handler(h.message(A, { mode: "close", day: D }), { log: quiet });
      const afterClose = await h.snapshot(A, { from: D, to: D });
      same(
        p,
        "the day close on unchanged data: state and flow rows of the day",
        afterClose.report_daily_findings,
        live.report_daily_findings,
      );
      clock.now = new Date();
      await h.clearAll(A);
      return p;
    },
  },
  {
    id: "RPT-S10d",
    name: "DST day boundaries (SPEC 17 D-5, 7.2) in Europe/Berlin: events placed one second either side of local midnight across the SPRING-FORWARD day (2026-03-29, 23 hours) and the FALL-BACK day (2026-10-25, 25 hours) are bucketed into the right tenant-local day by the flow, executions and decisions series, with hard-coded expectations (22:59:59Z the 28th is day 28, 23:00:00Z is the 29th, 21:59:59Z on the 29th is still the 29th, 22:00:00Z is the 30th; 21:59:59Z on 10-24 is the 24th, 22:00:00Z the 25th, 22:59:59Z on the 25th still the 25th, 23:00:00Z the 26th); the close instant of the 23-hour and the 25-hour day is the last millisecond of that local day, and the state at it counts a finding created at 23:59:59 local and not one created a second later; the day lengths in the rows' bucketing are 23 and 25 hours",
    async run(c) {
      const p = [];
      const w = await buildFindingsWorld(c.db);
      const pipe = (await w.published(w.A, 0)).pipeline;
      const pipe2 = (await w.published(w.A, 1)).pipeline;
      const version = await c.db.pipelineConfigVersion.findFirst({
        where: { tenantId: pipe.tenantId, pipelineId: pipe.id },
      });
      const tenantId = pipe.tenantId;
      const tz = "Europe/Berlin";
      const workerDb = (await harness(c)).workerDb;
      const repo = createReportingRollupRepository({ db: workerDb });
      await c.db
        .$executeRaw`INSERT INTO tenant_reporting_settings (tenant_id, reporting_timezone) VALUES (${tenantId}::uuid, ${tz}) ON CONFLICT (tenant_id) DO UPDATE SET reporting_timezone = ${tz}`;
      const z = (s) => new Date(s);
      // [instant (UTC), expected tenant-local day]
      const cases = [
        ["2026-03-28T22:59:59Z", "2026-03-28"],
        ["2026-03-28T23:00:00Z", "2026-03-29"],
        ["2026-03-29T21:59:59Z", "2026-03-29"],
        ["2026-03-29T22:00:00Z", "2026-03-30"],
        ["2026-10-24T21:59:59Z", "2026-10-24"],
        ["2026-10-24T22:00:00Z", "2026-10-25"],
        ["2026-10-25T22:59:59Z", "2026-10-25"],
        ["2026-10-25T23:00:00Z", "2026-10-26"],
      ];
      for (const [iso] of cases) {
        await buildFinding(w, pipe, {
          toolSeverity: "high",
          firstAt: z(iso),
          steps: [],
          scanType: "sast",
        });
        await buildExecution(w, pipe, version, {
          status: "failed",
          requestedAt: z(iso),
          startedAt: new Date(z(iso).getTime() + 1000),
          finishedAt: new Date(z(iso).getTime() + 61000),
        });
      }
      // decisions: an approved false-positive review decided at each boundary instant
      for (const [iso] of cases.slice(0, 4)) {
        await buildFinding(w, pipe2, {
          toolSeverity: "low",
          firstAt: new Date(z(iso).getTime() - 3 * HOUR),
          steps: [
            { at: new Date(z(iso).getTime() - 2 * HOUR), to: "in_review" },
            {
              at: new Date(z(iso).getTime() - HOUR),
              to: "awaiting_approval",
              decision: "false_positive",
            },
            { at: z(iso), to: "false_positive" },
          ],
        });
      }
      const flow = await repo.computeFindingsFlow({
        tenantId,
        from: "2026-03-27",
        to: "2026-03-31",
        timeZone: tz,
      });
      const flow2 = await repo.computeFindingsFlow({
        tenantId,
        from: "2026-10-23",
        to: "2026-10-27",
        timeZone: tz,
      });
      const execs = [
        ...(await repo.computeExecutionsDays({
          tenantId,
          from: "2026-03-27",
          to: "2026-03-31",
          timeZone: tz,
        })),
        ...(await repo.computeExecutionsDays({
          tenantId,
          from: "2026-10-23",
          to: "2026-10-27",
          timeZone: tz,
        })),
      ];
      const decs = [
        ...(await repo.computeDecisionsDays({
          tenantId,
          from: "2026-03-27",
          to: "2026-03-31",
          timeZone: tz,
        })),
        ...(await repo.computeDecisionsDays({
          tenantId,
          from: "2026-10-23",
          to: "2026-10-27",
          timeZone: tz,
        })),
      ];
      const perDay = (rows, field) =>
        Object.fromEntries(
          Object.entries(rows.reduce((m, r) => ((m[r.day] = (m[r.day] ?? 0) + r[field]), m), {})),
        );
      // each boundary instant made one finding (new) and one failed execution; the four decision findings add their own `new` rows 3 h before
      const expectNew = {};
      const expectExec = {};
      for (const [, day] of cases) {
        expectNew[day] = (expectNew[day] ?? 0) + 1;
        expectExec[day] = (expectExec[day] ?? 0) + 1;
      }
      for (const [iso] of cases.slice(0, 4)) {
        const d = localDayOf(new Date(z(iso).getTime() - 3 * HOUR), tz);
        expectNew[d] = (expectNew[d] ?? 0) + 1;
      }
      same(
        p,
        "new per tenant-local day (both DST windows)",
        perDay([...flow, ...flow2], "newCount"),
        expectNew,
      );
      same(p, "executions per tenant-local day", perDay(execs, "failedCount"), expectExec);
      const expectDec = {};
      for (const [, day] of cases.slice(0, 4)) expectDec[day] = (expectDec[day] ?? 0) + 1;
      same(p, "decisions per tenant-local day", perDay(decs, "fpCount"), expectDec);
      same(
        p,
        "the DST days are 23 and 25 hours long",
        [dayRange("2026-03-29", tz).hours, dayRange("2026-10-25", tz).hours],
        [23, 25],
      );
      same(
        p,
        "the close instant is the last millisecond of the local day",
        [
          dayCloseInstant("2026-03-29", tz).toISOString(),
          dayCloseInstant("2026-10-25", tz).toISOString(),
        ],
        ["2026-03-29T21:59:59.999Z", "2026-10-25T22:59:59.999Z"],
      );
      // the state at the close instant: the finding created at 21:59:59Z is in the day, the one at 22:00:00Z is not
      const countAt = async (instant) =>
        (
          await repo.computeFindingsStateAsOf({ tenantId, instant, workspaceId: pipe.workspaceId })
        ).reduce((a, r) => a + r.openCount, 0);
      same(
        p,
        "state at the end of the 23-hour day vs the instant before the second finding",
        [
          (await countAt(dayCloseInstant("2026-03-29", tz))) -
            (await countAt(z("2026-03-29T21:59:58Z"))),
          (await countAt(z("2026-03-29T22:00:00Z"))) -
            (await countAt(dayCloseInstant("2026-03-29", tz))),
        ],
        [1, 1],
      );
      same(
        p,
        "state grows by the findings of the 25-hour day only",
        (await countAt(dayCloseInstant("2026-10-25", tz))) -
          (await countAt(dayCloseInstant("2026-10-24", tz))),
        2,
      );
      // through the handler (a backfill in the zone) the rows agree with the series above
      const handler = createRollupHandler({
        rollupRepository: repo,
        config: { reporting: { enabled: true, rollupRetentionMonths: 25 } },
        logger: quiet,
        options: { throttleMs: 0 },
      });
      const msg = parseMessage(
        createJobEnvelope({
          messageId: `suite-${randomUUID()}`,
          type: MSG,
          schemaVersion: 1,
          tenantId,
          initiator: { type: "system", id: "suite" },
          payload: { tenantId, mode: "backfill", from: "2026-03-27", to: "2026-03-31" },
        }),
      );
      await handler(msg, { log: quiet });
      const stored = await c.db
        .$queryRaw`SELECT to_char(day, 'YYYY-MM-DD') AS day, sum(new_count)::int AS n FROM report_daily_findings WHERE tenant_id = ${tenantId}::uuid AND day BETWEEN '2026-03-27' AND '2026-03-31' GROUP BY day`;
      same(
        p,
        "the stored rows of the spring window",
        Object.fromEntries(stored.map((r) => [r.day, r.n])),
        perDay(flow, "newCount"),
      );
      return p;
    },
  },
  {
    id: "RPT-S10e",
    name: "Rebuild after a time-zone change (SPEC 7.2, RPT-020, ADR-015): a tenant built in Europe/Berlin is switched to Pacific/Auckland and rebuilt (`timezone_changed`: the range is cleared through the SECURITY DEFINER function, then recomputed); the result equals, row by row and column by column, a FRESH build of the same range in the new zone (cleared, then an ordinary backfill), differs from the build in the old zone (the check is not vacuous) and holds no row of a day only the old zone had; the rebuild is repeated without change; the state snapshots of the cleared range are gone by design (forward-only, stated in AS_BUILT_A.md)",
    async run(c) {
      const p = [];
      const h = await harness(c);
      const { tenantA: A, clock, repo } = h;
      await h.clearAll(A);
      clock.now = new Date();
      const today = localDayOf(clock.now, "UTC");
      const range = { from: DAYS(h, 2), to: today };
      const handler = h.handler();
      await h.setZone(A, "Europe/Berlin");
      await handler(h.message(A, { mode: "backfill", ...range }), { log: quiet });
      const berlin = normalize(await h.snapshot(A));
      ok(
        p,
        berlin.report_daily_findings.length > 10,
        "the Berlin build is empty (a vacuous check)",
      );
      await h.setZone(A, "Pacific/Auckland");
      await handler(h.message(A, { mode: "backfill", ...range, reason: "timezone_changed" }), {
        log: quiet,
      });
      const rebuilt = await h.snapshot(A);
      const rebuiltN = normalize(rebuilt);
      // a fresh build in the new zone
      await h.clearAll(A);
      await handler(h.message(A, { mode: "backfill", ...range }), { log: quiet });
      const fresh = normalize(await h.snapshot(A));
      same(
        p,
        "rebuild equals a fresh build (every non-clock column of the four tables)",
        rebuiltN,
        fresh,
      );
      ok(
        p,
        JSON.stringify(rebuiltN) !== JSON.stringify(berlin),
        "the Auckland build equals the Berlin build (the zone changed nothing: a vacuous check)",
      );
      // a repeated rebuild changes nothing
      await h.setZone(A, "Pacific/Auckland");
      await handler(h.message(A, { mode: "backfill", ...range, reason: "timezone_changed" }), {
        log: quiet,
      });
      same(p, "a repeated rebuild", normalize(await h.snapshot(A)), fresh);
      // no state snapshot survives the cleared range
      same(
        p,
        "no state counter in a rebuilt range",
        STATE_COLUMNS.map((col) => sum(rebuilt.report_daily_findings, col)),
        STATE_COLUMNS.map(() => 0),
      );
      // and the runs record the zone used
      const zones = (
        await h.db
          .$queryRaw`SELECT DISTINCT time_zone FROM report_rollup_runs WHERE tenant_id = ${A}::uuid AND mode = 'backfill'`
      ).map((r) => r.time_zone);
      same(p, "the run rows record the zone", zones, ["Pacific/Auckland"]);
      await h.setZone(A, "UTC");
      await h.clearAll(A);
      void repo;
      return p;
    },
  },
];
