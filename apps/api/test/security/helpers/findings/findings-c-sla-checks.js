import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseMessage } from "@qmentisai/contracts";
import { transitionFinding } from "@qmentisai/db";
import { FINDING_SEVERITY_RANK, slaSettingsDtoSchema } from "@qmentisai/shared";
import { createFindingsIngestHandler } from "../../../../../workers/src/findings/handler.js";
import { SLA_SWEEP_BATCH, createSlaSweepHandler } from "../../../../../workers/src/findings/sla.js";
import { HOUR, cWorld, codeOf, eq, ok } from "./findings-c-world.js";
import { quietLog } from "./findings-a-fixtures.js";

/**
 * Findings checks of part C, the SLA (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1): FND-S14 (SLA events: due soon and breached
 * once per finding and cycle, idempotent, scoped, nothing but the marker changes) and the settings routes (validation, tenant scoping,
 * audit, the per-tenant targets applied by the transition function). SLA arithmetic itself (the 25 percent threshold, the defaults) is
 * out of the suite's scope (SPEC 14.1): the checks use the thresholds only to place findings clearly on either side of them.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const NOW = new Date();
const at = (hours) => new Date(NOW.getTime() + hours * HOUR);
const message = (bucket = 1) => ({
  type: "findings.sla.sweep",
  tenantId: null,
  payload: { bucket },
});

/** A finding of `pipe` with a running clock: started `startH` hours from NOW, due `dueH` hours from NOW. */
const clocked = (c, pipe, startH, dueH, o = {}) =>
  c.finding(pipe, { slaStartedAt: at(startH), slaDueAt: at(dueH), ...o });

/** A finding in `fixed_pending_verification` (a person's claim) built through the legitimate machine. */
async function pendingFinding(c, pipe, o = {}) {
  let f = await c.finding(pipe, o);
  f = await c.step(f, "in_review", {
    set: { claimedByUserId: randomUUID() },
    reason: "review_started",
  });
  const r = await c.review(f, { reviewerUserId: f.claimedByUserId });
  f = await c.step(f, "awaiting_approval", {
    set: { pendingReviewId: r.id },
    reason: "review_recorded",
  });
  f = await c.step(f, "approved", { set: { pendingReviewId: null }, reason: "approved_tp" });
  f = await c.step(f, "assigned", {
    set: { assigneeUserId: randomUUID(), assignedAt: new Date() },
    reason: "assigned",
  });
  return c.step(f, "fixed_pending_verification", {
    set: { fixClaimedAt: new Date(), slaDueAt: null },
    reason: "fix_submitted",
  });
}

export const FINDINGS_C_SLA_CHECKS = [
  {
    id: "FND-S14b",
    name: "The SLA sweep (SPEC 5.9 SL-4, 9.1, FND-S14): the scheduled job `findings.sla.sweep` marks each open finding whose clock crossed due soon or breached and emits `finding.sla_due_soon` or `finding.sla_breached` ONCE per finding and cycle (a second run, a concurrent second instance and a later breach after the due-soon notice emit exactly one of each; a reopening that restarts the clock starts a new cycle); a finding that is on track, has no clock, or is closed is never notified; the events parse against the catalog, carry the finding, workspace, severity and due date only, in the finding's own tenant; the sweep changes nothing but the marker (status, history, assignee); another job type is refused; the findings worker dispatches it and the scheduler enqueues it only under the same flag as the other findings jobs",
    async run(c) {
      const w = await cWorld(c);
      const p = [];
      const { db } = w;
      const events = async (f, type) =>
        (await db.outboxMessage.findMany({ where: { tenantId: f.tenantId, type } })).filter(
          (r) => r.payload?.payload?.findingId === f.id,
        );
      const count = async (f) => ({
        soon: (await events(f, "finding.sla_due_soon")).length,
        breached: (await events(f, "finding.sla_breached")).length,
      });
      const onTrack = await clocked(c, w.pipeline, -10, 158);
      const soon = await clocked(c, w.pipeline, -140, 28);
      const breach = await clocked(c, w.pipeline, -200, -32);
      const noClock = await w.fnd();
      const breachB = await clocked(c, w.pipelineB, -200, -32, {
        severity: "critical",
        toolSeverity: "critical",
        severityRank: FINDING_SEVERITY_RANK.critical,
      });
      // a CLOSED finding with an overdue clock (it cannot happen through the product, which clears the clock; the sweep must not trust that)
      const closed = await pendingFinding(c, w.pipeline);
      const closedV = await c.step(closed, "verified_fixed", {
        actor: "system",
        reason: "verified",
        set: {
          absentCount: 1,
          verifiedAt: NOW,
          closedAt: NOW,
          slaStartedAt: at(-300),
          slaDueAt: at(-100),
        },
      });
      const histories = {};
      for (const f of [onTrack, soon, breach, noClock, closedV])
        histories[f.id] = (await w.history(f)).length;
      const sweep = createSlaSweepHandler({ db, clock: () => NOW });
      await sweep(message(1), { log: quietLog });
      eq(p, "due soon: one notice, no breach", await count(soon), { soon: 1, breached: 0 });
      eq(p, "breached: one notice, no due soon", await count(breach), { soon: 0, breached: 1 });
      eq(
        p,
        "the same in another tenant, in its own tenant",
        [await count(breachB), (await events(breachB, "finding.sla_breached"))[0]?.tenantId],
        [{ soon: 0, breached: 1 }, c.B.tenant.id],
      );
      for (const [label, f] of [
        ["on track", onTrack],
        ["without a clock", noClock],
        ["closed", closedV],
      ])
        eq(p, `${label}: never notified`, await count(f), { soon: 0, breached: 0 });
      // payloads
      const ev = (await events(soon, "finding.sla_due_soon"))[0];
      eq(p, "the due soon event parses", parseMessage(ev.payload)?.type, "finding.sla_due_soon");
      eq(
        p,
        "and carries ids, the severity and the due date only",
        [
          Object.keys(ev.payload.payload).sort(),
          ev.payload.payload.dueAt,
          ev.payload.payload.severity,
          ev.payload.payload.workspaceId,
          ev.payload.initiator,
        ],
        [
          ["dueAt", "findingId", "severity", "workspaceId"],
          (await w.row(soon)).slaDueAt.toISOString(),
          "high",
          soon.workspaceId,
          { type: "system", id: "findings-sla" },
        ],
      );
      const bev = (await events(breach, "finding.sla_breached"))[0];
      eq(p, "the breach event parses", parseMessage(bev.payload)?.type, "finding.sla_breached");
      // the markers and nothing else
      const rs = await w.row(soon);
      const rb = await w.row(breach);
      ok(
        p,
        rs.slaDueSoonNotifiedAt !== null && rs.slaBreachNotifiedAt === null,
        "the due soon marker is set, the breach marker is not",
      );
      ok(
        p,
        rb.slaBreachNotifiedAt !== null && rb.slaDueSoonNotifiedAt !== null,
        "a breach also covers the due soon notice",
      );
      eq(
        p,
        "no status, assignee or history change",
        [rs.status, rb.status, (await w.history(soon)).length, (await w.history(breach)).length],
        ["new", "new", histories[soon.id], histories[breach.id]],
      );
      eq(
        p,
        "a closed or clockless finding was not even touched",
        [(await w.row(closedV)).rev, (await w.row(noClock)).rev],
        [closedV.rev, noClock.rev],
      );
      // ONCE: a second run, and two instances at once
      await sweep(message(1), { log: quietLog });
      eq(
        p,
        "a second run emits nothing",
        [await count(soon), await count(breach)],
        [
          { soon: 1, breached: 0 },
          { soon: 0, breached: 1 },
        ],
      );
      const soon2 = await clocked(c, w.pipeline, -140, 28);
      const breach2 = await clocked(c, w.pipeline, -200, -32);
      await Promise.all([
        sweep(message(2), { log: quietLog }),
        createSlaSweepHandler({ db, clock: () => NOW })(message(2), { log: quietLog }),
      ]);
      eq(
        p,
        "two instances at once emit one each",
        [await count(soon2), await count(breach2)],
        [
          { soon: 1, breached: 0 },
          { soon: 0, breached: 1 },
        ],
      );
      // the clock moves on: due soon, then breached, each once
      const later = createSlaSweepHandler({ db, clock: () => at(30) });
      await later(message(3), { log: quietLog });
      eq(
        p,
        "the finding that was due soon is now breached: one of each in total",
        await count(soon),
        { soon: 1, breached: 1 },
      );
      eq(p, "the one on track is still quiet", await count(onTrack), { soon: 0, breached: 0 });
      const muchLater = createSlaSweepHandler({ db, clock: () => at(130) });
      await muchLater(message(4), { log: quietLog });
      eq(p, "the on-track finding is due soon at last, once", await count(onTrack), {
        soon: 1,
        breached: 0,
      });
      await muchLater(message(5), { log: quietLog });
      eq(p, "and not again", await count(onTrack), { soon: 1, breached: 0 });
      // a reopening restarts the clock: a new cycle notifies again
      await db.$executeRaw`UPDATE findings SET sla_started_at = ${at(31)}::timestamptz, sla_due_at = ${at(31 + 168)}::timestamptz, rev = rev + 1 WHERE tenant_id = ${soon.tenantId}::uuid AND id = ${soon.id}::uuid`;
      await createSlaSweepHandler({ db, clock: () => at(31 + 150) })(message(6), { log: quietLog });
      eq(
        p,
        "a new cycle notifies due soon again (two in all), not breached again",
        await count(soon),
        { soon: 2, breached: 1 },
      );
      const ids = (await events(soon, "finding.sla_due_soon")).map((r) => r.messageId);
      eq(p, "the two notices have different message ids", new Set(ids).size, 2);
      // the job type and the wiring
      let wrong = null;
      try {
        await sweep(
          { type: "findings.exception.expire", payload: { bucket: 1 } },
          { log: quietLog },
        );
      } catch (error) {
        wrong = error;
      }
      ok(p, wrong instanceof TypeError, "another job type must be refused");
      const viaWorker = await clocked(c, w.pipeline, -200, -32);
      const handler = createFindingsIngestHandler({
        db,
        config: { findings: { ingestionEnabled: true, agentEnabled: false, fixConfirmations: 1 } },
      });
      await handler(message(7), { log: quietLog });
      eq(p, "the findings worker dispatches the job", await count(viaWorker), {
        soon: 0,
        breached: 1,
      });
      const scheduler = readFileSync(
        new URL("../../../../../workers/src/scheduler/index.js", import.meta.url),
        "utf8",
      );
      const slaAt = scheduler.indexOf('type: "findings.sla.sweep"');
      const guardAt = scheduler.lastIndexOf("if (config.findings?.ingestionEnabled)", slaAt);
      const expiryAt = scheduler.indexOf('type: "findings.exception.expire"');
      ok(
        p,
        slaAt > 0 && guardAt > expiryAt,
        "the scheduler enqueues the sweep only under the flag of the other findings jobs",
      );
      ok(p, SLA_SWEEP_BATCH > 0, "the sweep is bounded");
      return p;
    },
  },

  {
    id: "FND-S14c",
    name: "The findings SLA settings (SPEC 5.9 SL-1, 8.1, 8.2, FND-S01, FND-S14): GET needs `tenant_settings.view` and PUT `tenant_settings.manage` (403 otherwise, 401 without a session) and both act on the SESSION'S tenant only (another tenant's targets are never read or changed); the defaults are served as defaults; a target outside 1 to 87,600 hours, a fraction, a string, `info`, a duplicate or unknown severity, an empty or oversized list and any extra key are 400 and write nothing; a change replaces the targets (a severity left out returns to its default), is audited once with the previous and new hours of what changed (ids and numbers only), and writing what is stored changes nothing and audits nothing; the transition function applies the tenant's own targets when a clock restarts (tenant A and tenant B differ)",
    async run(c) {
      const w = await cWorld(c);
      const p = [];
      const { api, db, users } = w;
      const tenantA = c.A.tenant.id;
      const tenantB = c.B.tenant.id;
      const rows = (tenantId) =>
        db.findingSlaTarget.findMany({ where: { tenantId }, orderBy: { severity: "asc" } });
      const audits = (tenantId) =>
        db.auditLog.findMany({
          where: { tenantId, action: "tenant.findings_sla_changed" },
          orderBy: { createdAt: "asc" },
        });
      await db.findingSlaTarget.deleteMany({ where: { tenantId: { in: [tenantA, tenantB] } } });
      try {
        // defaults, and who may read
        const g0 = await api.get("slaViewer", "/settings/findings-sla");
        eq(
          p,
          "a viewer of tenant settings reads the defaults",
          [g0.status, g0.json?.data?.targets],
          [
            200,
            [
              { severity: "critical", hours: 168, isDefault: true },
              { severity: "high", hours: 720, isDefault: true },
              { severity: "medium", hours: 2160, isDefault: true },
              { severity: "low", hours: 4320, isDefault: true },
              { severity: "info", hours: null, isDefault: true },
            ],
          ],
        );
        ok(
          p,
          slaSettingsDtoSchema.safeParse(g0.json?.data).success,
          "the answer validates against the contract",
        );
        eq(p, "the answer holds the targets and nothing else", Object.keys(g0.json?.data ?? {}), [
          "targets",
        ]);
        for (const who of ["viewer", "analyst", "dev"]) {
          const r = await api.get(who, "/settings/findings-sla");
          eq(
            p,
            `${who} cannot read (no tenant_settings.view)`,
            [r.status, codeOf(r)],
            [403, "FORBIDDEN"],
          );
        }
        const anon = await api.get("nobody-registered", "/settings/findings-sla");
        eq(p, "no session", anon.status, 401);
        const body = { targets: [{ severity: "critical", hours: 24 }] };
        for (const who of ["slaViewer", "viewer", "devlead"]) {
          const r = await api.put(who, "/settings/findings-sla", body);
          eq(
            p,
            `${who} cannot write (no tenant_settings.manage)`,
            [r.status, codeOf(r)],
            [403, "FORBIDDEN"],
          );
        }
        eq(
          p,
          "the refusals wrote nothing",
          [(await rows(tenantA)).length, (await audits(tenantA)).length],
          [0, 0],
        );
        // validation
        const invalid = [
          ["zero hours", { targets: [{ severity: "critical", hours: 0 }] }],
          ["negative hours", { targets: [{ severity: "critical", hours: -5 }] }],
          ["over the maximum", { targets: [{ severity: "critical", hours: 87601 }] }],
          ["a fraction", { targets: [{ severity: "critical", hours: 1.5 }] }],
          ["a string", { targets: [{ severity: "critical", hours: "24" }] }],
          ["no hours", { targets: [{ severity: "critical" }] }],
          ["info has no target", { targets: [{ severity: "info", hours: 24 }] }],
          ["an unknown severity", { targets: [{ severity: "urgent", hours: 24 }] }],
          [
            "a duplicate severity",
            {
              targets: [
                { severity: "high", hours: 24 },
                { severity: "high", hours: 48 },
              ],
            },
          ],
          ["an empty list", { targets: [] }],
          [
            "five targets",
            {
              targets: ["critical", "high", "medium", "low", "info"].map((severity) => ({
                severity,
                hours: 5,
              })),
            },
          ],
          [
            "a forged tenant",
            { targets: [{ severity: "critical", hours: 24 }], tenantId: tenantB },
          ],
          [
            "an extra key in a target",
            { targets: [{ severity: "critical", hours: 24, isDefault: false }] },
          ],
          ["no targets key", {}],
        ];
        for (const [label, b] of invalid) {
          const r = await api.put("slaAdmin", "/settings/findings-sla", b);
          eq(p, `${label}`, [r.status, codeOf(r)], [400, "VALIDATION_FAILED"]);
        }
        eq(
          p,
          "no invalid write left a row or an audit entry",
          [(await rows(tenantA)).length, (await audits(tenantA)).length],
          [0, 0],
        );
        // a change
        const put1 = await api.put("slaAdmin", "/settings/findings-sla", {
          targets: [
            { severity: "critical", hours: 24 },
            { severity: "high", hours: 100 },
          ],
        });
        eq(
          p,
          "control: a change is applied and returned",
          [put1.status, put1.json?.data?.targets],
          [
            200,
            [
              { severity: "critical", hours: 24, isDefault: false },
              { severity: "high", hours: 100, isDefault: false },
              { severity: "medium", hours: 2160, isDefault: true },
              { severity: "low", hours: 4320, isDefault: true },
              { severity: "info", hours: null, isDefault: true },
            ],
          ],
        );
        const stored = await rows(tenantA);
        eq(
          p,
          "two rows, by the admin",
          [stored.map((r) => [r.severity, r.hours, r.updatedByUserId])],
          [
            [
              ["critical", 24, users.slaAdmin],
              ["high", 100, users.slaAdmin],
            ],
          ],
        );
        const a1 = await audits(tenantA);
        eq(
          p,
          "one audit entry for the change",
          [a1.length, a1[0]?.actorUserId, a1[0]?.targetType, a1[0]?.targetId, a1[0]?.workspaceId],
          [1, users.slaAdmin, "tenant", tenantA, null],
        );
        eq(
          p,
          "with the previous and new hours of what changed, numbers and enums only",
          a1[0]?.metadata,
          {
            changes: [
              { severity: "critical", previousHours: 168, newHours: 24 },
              { severity: "high", previousHours: 720, newHours: 100 },
            ],
          },
        );
        const g1 = await api.get("slaViewer", "/settings/findings-sla");
        eq(p, "the viewer reads the new targets", g1.json?.data?.targets?.slice(0, 2), [
          { severity: "critical", hours: 24, isDefault: false },
          { severity: "high", hours: 100, isDefault: false },
        ]);
        // writing what is stored changes nothing
        const stamp = (await rows(tenantA)).map((r) => r.updatedAt.getTime());
        const put2 = await api.put("slaAdmin", "/settings/findings-sla", {
          targets: [
            { severity: "critical", hours: 24 },
            { severity: "high", hours: 100 },
          ],
        });
        eq(p, "the same write again", put2.status, 200);
        eq(
          p,
          "writes and audits nothing",
          [(await rows(tenantA)).map((r) => r.updatedAt.getTime()), (await audits(tenantA)).length],
          [stamp, 1],
        );
        // replace semantics: a severity left out returns to its default
        const put3 = await api.put("slaAdmin", "/settings/findings-sla", {
          targets: [{ severity: "high", hours: 100 }],
        });
        eq(
          p,
          "a severity left out returns to its default",
          [put3.status, put3.json?.data?.targets?.[0]],
          [200, { severity: "critical", hours: 168, isDefault: true }],
        );
        const a3 = await audits(tenantA);
        eq(
          p,
          "audited as a change of that severity only",
          [a3.length, a3[1]?.metadata],
          [2, { changes: [{ severity: "critical", previousHours: 24, newHours: 168 }] }],
        );
        // tenant scoping
        const bBefore = await api.get("slaAdminB", "/settings/findings-sla");
        eq(
          p,
          "tenant B still has the defaults",
          bBefore.json?.data?.targets?.every((t) => t.isDefault),
          true,
        );
        const putB = await api.put("slaAdminB", "/settings/findings-sla", {
          targets: [{ severity: "low", hours: 50 }],
        });
        eq(
          p,
          "tenant B writes its own",
          [putB.status, putB.json?.data?.targets?.[3]],
          [200, { severity: "low", hours: 50, isDefault: false }],
        );
        const aAfter = await api.get("slaAdmin", "/settings/findings-sla");
        eq(p, "tenant A is untouched by tenant B", aAfter.json?.data?.targets?.[3], {
          severity: "low",
          hours: 4320,
          isDefault: true,
        });
        eq(
          p,
          "audit rows are per tenant",
          [(await audits(tenantA)).length, (await audits(tenantB)).length],
          [2, 1],
        );
        eq(
          p,
          "the rows are per tenant",
          [
            (await rows(tenantA)).map((r) => r.severity),
            (await rows(tenantB)).map((r) => r.severity),
          ],
          [["high"], ["low"]],
        );
        // the transition function applies the tenant's own targets when a clock restarts
        const reopen = async (f) => {
          await db.$transaction((tx) =>
            transitionFinding(tx, {
              scope: { tenantId: f.tenantId, workspaceId: f.workspaceId },
              findingId: f.id,
              to: "reopened",
              actor: { type: "system", code: "ingestion" },
              reasonCode: "recurred",
              columns: { reopenCount: { increment: 1 }, absentCount: 0, fixClaimedAt: null },
            }),
          );
          const r = await w.row(f);
          return Math.round((r.slaDueAt.getTime() - r.slaStartedAt.getTime()) / HOUR);
        };
        await db.findingSlaTarget.upsert({
          where: { tenantId_severity: { tenantId: tenantB, severity: "high" } },
          create: { tenantId: tenantB, severity: "high", hours: 720 },
          update: { hours: 720 },
        });
        const fa = await pendingFinding(c, w.pipeline);
        const fb = await pendingFinding(c, w.pipelineB);
        eq(
          p,
          "a reopening restarts the clock with the tenant's own target (A: high 100 hours, B: high 720 hours)",
          [await reopen(fa), await reopen(fb)],
          [100, 720],
        );
        const fc = await pendingFinding(c, w.pipeline, {
          severity: "low",
          toolSeverity: "low",
          severityRank: FINDING_SEVERITY_RANK.low,
        });
        eq(p, "a severity with no row of its own gets the default", await reopen(fc), 4320);
      } finally {
        await db.findingSlaTarget.deleteMany({ where: { tenantId: { in: [tenantA, tenantB] } } });
      }
      return p;
    },
  },
];
