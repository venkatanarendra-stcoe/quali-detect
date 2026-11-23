import { parseMessage } from "@qmentisai/contracts";
import { CANARY, UNKNOWN, cWorld, codeOf, eq, j, ok, rand, reasonOf } from "./findings-c-world.js";
import { startWriteApi } from "./findings-b-fixtures.js";

/**
 * Findings checks of part C, events, atomicity, idempotency and rate limits (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1):
 * FND-S14 (atomicity and events of assignment and remediation) and FND-S11 (idempotency keys and the rate limits of the part's routes).
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const FORCE = "fnd_c_force_failure";
/** Makes the insert of one outbox message type fail (a forced failure in the SAME transaction as the change). */
async function forceFailureOn(db, type, fn) {
  await db.$executeRawUnsafe(
    `CREATE OR REPLACE FUNCTION ${FORCE}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION '${FORCE}'; END $$`,
  );
  await db.$executeRawUnsafe(
    `CREATE TRIGGER ${FORCE} BEFORE INSERT ON outbox_messages FOR EACH ROW WHEN (NEW.type = '${type}') EXECUTE FUNCTION ${FORCE}()`,
  );
  try {
    return await fn();
  } finally {
    await db.$executeRawUnsafe(`DROP TRIGGER IF EXISTS ${FORCE} ON outbox_messages`);
    await db.$executeRawUnsafe(`DROP FUNCTION IF EXISTS ${FORCE}()`);
  }
}

export const FINDINGS_C_EVENTS_CHECKS = [
  {
    id: "FND-S14a",
    name: "Events, audit and atomicity of assignment and remediation (FND-S14, SPEC 8.2, 11.4): every transition writes exactly one history row, one `finding.status_changed` hint and one audit entry in the same transaction, and the domain events (`finding.assigned` for an assignment, a reassignment and an unassignment, `finding.fix_submitted` for a fix) parse against the message catalog, name the real assignment or remediation record and carry ids and enums only; a canary placed in the assignment note, the fix note and the PR link never reaches an outbox payload or an audit entry; a forced failure of the event insert leaves no assignment row, no remediation record, no history row, no revision change and no assignee, and the same call succeeds once the failure is gone",
    async run(c) {
      const w = await cWorld(c);
      const p = [];
      const { api, users, db } = w;
      const NOTE = `NOTE-${rand(6)}-private-text`;
      const f = await w.approved();
      const rev0 = (await w.row(f)).rev;
      // assign, reassign, start, submit, as real calls with notes
      const a1 = await api.post("devlead", `/findings/${f.id}/assignments`, {
        assigneeUserId: users.dev,
        note: NOTE,
        expectedRev: rev0,
      });
      eq(p, "assign", a1.status, 201);
      const a2 = await api.post("devlead", `/findings/${f.id}/assignments`, {
        assigneeUserId: users.dev2,
        note: NOTE,
        expectedRev: (await w.row(f)).rev,
      });
      eq(p, "reassign", a2.status, 201);
      const st = await api.post("dev2", `/findings/${f.id}/remediation/start`, {
        expectedRev: (await w.row(f)).rev,
      });
      eq(p, "start", st.status, 200);
      const sb = await api.post("dev2", `/findings/${f.id}/remediation/submit`, {
        expectedRev: (await w.row(f)).rev,
        note: NOTE,
        pullRequestUrl: "https://github.com/acme/app/pull/11",
        ticketKey: "SEC-7",
      });
      eq(p, "submit", sb.status, 200);

      const hist = await w.history(f);
      const mine = hist.filter((h) => h.rev > rev0);
      eq(
        p,
        "four transitions, four history rows with consecutive revisions",
        mine.map((h) => [h.rev - rev0, h.reasonCode]),
        [
          [1, "assigned"],
          [2, "reassigned"],
          [3, "work_started"],
          [4, "fix_submitted"],
        ],
      );
      const out = await w.outbox(f);
      const hints = out.filter((r) => r.type === "finding.status_changed");
      eq(
        p,
        "exactly one status hint per transition, naming the new revision",
        hints.map((r) => r.payload.payload.rev).sort((x, y) => x - y),
        mine.map((h) => h.rev).sort((x, y) => x - y),
      );
      const assignedEvents = out.filter((r) => r.type === "finding.assigned");
      const fixEvents = out.filter((r) => r.type === "finding.fix_submitted");
      eq(
        p,
        "one assigned event per assignment change, one fix event",
        [assignedEvents.length, fixEvents.length],
        [2, 1],
      );
      const rows = await w.assignments(f);
      const recs = await w.records(f);
      for (const ev of assignedEvents) {
        const parsed = parseMessage(ev.payload);
        eq(p, "an assigned event parses against the catalog", parsed?.type, "finding.assigned");
        ok(
          p,
          rows.some(
            (r) =>
              r.id === ev.payload.payload.assignmentId &&
              r.assigneeUserId === ev.payload.payload.assigneeUserId,
          ),
          "the event names a real assignment and its assignee",
        );
        eq(
          p,
          "the event carries ids and the revision only",
          Object.keys(ev.payload.payload).sort(),
          ["assigneeUserId", "assignmentId", "findingId", "rev", "workspaceId"],
        );
      }
      const fix = fixEvents[0];
      eq(p, "the fix event parses", parseMessage(fix.payload)?.type, "finding.fix_submitted");
      eq(
        p,
        "the fix event names the real remediation record",
        [fix.payload.payload.remediationId, Object.keys(fix.payload.payload).sort()],
        [
          recs.find((r) => r.kind === "fix_submitted").id,
          ["findingId", "remediationId", "rev", "workspaceId"],
        ],
      );
      for (const ev of [...hints, ...assignedEvents, ...fixEvents]) {
        eq(
          p,
          `${ev.type}: tenant and workspace of the row`,
          [ev.tenantId, ev.payload.workspaceId, ev.payload.initiator.type],
          [f.tenantId, w.wsA, "user"],
        );
      }
      // the clear emits the assignment event with no assignee
      const g = await w.assigned("dev");
      const cl = await api.post("devlead", `/findings/${g.id}/assignments/clear`, {
        note: NOTE,
        expectedRev: (await w.row(g)).rev,
      });
      eq(p, "unassign", cl.status, 200);
      const gOut = (await w.outbox(g)).filter((r) => r.type === "finding.assigned");
      const last = gOut.sort((x, y) => x.payload.payload.rev - y.payload.payload.rev).at(-1);
      eq(
        p,
        "the unassignment event has no assignee",
        [last.payload.payload.assignmentId, last.payload.payload.assigneeUserId],
        [null, null],
      );
      eq(p, "it parses", parseMessage(last.payload)?.type, "finding.assigned");
      // audit entries: one per action, ids and enums only
      const audit = await w.audit(f);
      eq(
        p,
        "the audit actions of the four calls, in order",
        audit
          .filter(
            (a) =>
              a.createdAt >= hist[0].createdAt &&
              a.action !== "finding.review_started" &&
              a.action !== "finding.review_recorded",
          )
          .map((a) => a.action)
          .slice(-4),
        [
          "finding.assigned",
          "finding.assigned",
          "finding.remediation_started",
          "finding.fix_submitted",
        ],
      );
      ok(
        p,
        audit.every((a) => a.actorType === "user" || a.actorType === "system"),
        "every entry has an actor type",
      );
      // the canary and the notes never reach an outbox payload or an audit entry
      const everything = j([
        out.map((r) => r.payload),
        audit.map((a) => a.metadata),
        (await w.audit(g)).map((a) => a.metadata),
        gOut.map((r) => r.payload),
      ]);
      ok(p, !everything.includes(NOTE), "a note reached an outbox payload or an audit entry");
      ok(
        p,
        !everything.includes("pull/11"),
        "the PR link reached an outbox payload or an audit entry",
      );
      for (const t of Object.values(CANARY))
        ok(p, !everything.includes(t), "a canary reached an event");
      // the note is stored where it belongs (history, assignment, remediation record)
      eq(
        p,
        "the notes are in their own rows",
        [
          rows.every((r) => r.note === NOTE),
          recs.find((r) => r.kind === "fix_submitted").note,
          mine[0].note,
        ],
        [true, NOTE, NOTE],
      );

      // ---- a forced failure in the same transaction leaves nothing behind ----
      const t = await w.approved();
      const snap = await w.snapshot(t);
      const forcedAssign = await forceFailureOn(db, "finding.assigned", () =>
        api.post("devlead", `/findings/${t.id}/assignments`, {
          assigneeUserId: users.dev,
          expectedRev: snap.rev,
        }),
      );
      eq(p, "the forced failure of an assignment is a 500", forcedAssign.status, 500);
      eq(p, "nothing of the assignment was applied", await w.snapshot(t), snap);
      const ok1 = await api.post("devlead", `/findings/${t.id}/assignments`, {
        assigneeUserId: users.dev,
        expectedRev: snap.rev,
      });
      eq(
        p,
        "control: the same assignment succeeds once the failure is gone",
        [ok1.status, ok1.json?.data?.status],
        [201, "assigned"],
      );
      const snap2 = await w.snapshot(t);
      const forcedFix = await forceFailureOn(db, "finding.fix_submitted", () =>
        api.post("dev", `/findings/${t.id}/remediation/submit`, {
          expectedRev: snap2.rev,
          pullRequestUrl: "https://github.com/acme/app/pull/12",
        }),
      );
      eq(p, "the forced failure of a fix is a 500", forcedFix.status, 500);
      eq(
        p,
        "no remediation record, no history row, no claim, no revision change",
        await w.snapshot(t),
        snap2,
      );
      const ok2 = await api.post("dev", `/findings/${t.id}/remediation/submit`, {
        expectedRev: snap2.rev,
        pullRequestUrl: "https://github.com/acme/app/pull/12",
      });
      eq(
        p,
        "control: the fix succeeds once the failure is gone",
        [ok2.status, ok2.json?.data?.status],
        [200, "fixed_pending_verification"],
      );
      // the status hint failing (the transition function's own row) also rolls everything back
      const u = await w.approved();
      const snap3 = await w.snapshot(u);
      const forcedHint = await forceFailureOn(db, "finding.status_changed", () =>
        api.post("devlead", `/findings/${u.id}/assignments`, {
          assigneeUserId: users.dev,
          expectedRev: snap3.rev,
        }),
      );
      eq(p, "a failed status hint is a 500", forcedHint.status, 500);
      eq(p, "and nothing was written", await w.snapshot(u), snap3);
      return p;
    },
  },

  {
    id: "FND-S11c",
    name: "Idempotency keys and rate limits of part C (FND-S11): every mutating POST of the part takes `Idempotency-Key` and the write rate limit, the board reads and the SLA read the read limit, the SLA write the write limit, all on the tenant audience (the route table); a replay returns the stored answer once and writes nothing twice, a different request under the same key is IDEMPOTENCY_CONFLICT, a key is per user and per route, a failed call does not keep its key; the real limiter refuses the call over the limit (429, per user and route) and reads are counted apart",
    async run(c) {
      const w = await cWorld(c);
      const p = [];
      const { api, users } = w;
      const posts = [
        "/api/v1/findings/bulk/assign",
        "/api/v1/findings/:id/assignments",
        "/api/v1/findings/:id/assignments/clear",
        "/api/v1/findings/:id/remediation/start",
        "/api/v1/findings/:id/remediation/submit",
      ];
      for (const url of posts) {
        const r = api.routeTable.find((x) => x.method === "POST" && x.url === url);
        eq(
          p,
          `route table ${url}`,
          [r?.idempotent, r?.rateLimit, r?.audience],
          [true, "write", "tenant"],
        );
      }
      for (const url of [
        "/api/v1/remediation/board",
        "/api/v1/remediation/board/:column",
        "/api/v1/settings/findings-sla",
      ]) {
        const r = api.routeTable.find((x) => x.method === "GET" && x.url === url);
        eq(p, `route table GET ${url}`, [r?.rateLimit, r?.audience], ["read", "tenant"]);
      }
      const put = api.routeTable.find(
        (x) => x.method === "PUT" && x.url === "/api/v1/settings/findings-sla",
      );
      eq(
        p,
        "route table PUT /settings/findings-sla",
        [put?.rateLimit, put?.audience],
        ["write", "tenant"],
      );

      // replay of an assignment
      const f = await w.approved();
      const key = `idem-${rand(8)}`;
      const url = `/findings/${f.id}/assignments`;
      const body = { assigneeUserId: users.dev, expectedRev: (await w.row(f)).rev };
      const a = await api.post("devlead", url, body, { key });
      const b = await api.post("devlead", url, body, { key });
      eq(
        p,
        "first call",
        [a.status, a.json?.data?.status, a.headers.get("idempotent-replayed")],
        [201, "assigned", null],
      );
      eq(
        p,
        "replay",
        [b.status, b.json?.data?.rev, b.headers.get("idempotent-replayed")],
        [201, a.json?.data?.rev, "true"],
      );
      eq(
        p,
        "the replay did not run twice",
        [(await w.assignments(f)).length, (await w.history(f)).length],
        [1, 5],
      );
      const diff = await api.post("devlead", url, { ...body, assigneeUserId: users.dev2 }, { key });
      eq(
        p,
        "the same key with a different request",
        [diff.status, codeOf(diff), reasonOf(diff)],
        [409, "IDEMPOTENCY_CONFLICT", "different_request"],
      );
      // per user and per route
      const g = await w.approved();
      const other = await api.post(
        "devlead2",
        `/findings/${g.id}/assignments`,
        { assigneeUserId: users.dev, expectedRev: (await w.row(g)).rev },
        { key },
      );
      eq(
        p,
        "the same key by another user is a different key",
        [other.status, other.headers.get("idempotent-replayed")],
        [201, null],
      );
      const h = await w.approved();
      const route = await api.post(
        "devlead",
        `/findings/bulk/assign`,
        { workspaceId: w.wsA, findingIds: [h.id], assigneeUserId: users.dev },
        { key },
      );
      eq(
        p,
        "the same key on another route is a different key",
        [route.status, route.headers.get("idempotent-replayed")],
        [200, null],
      );
      // a failed call does not keep its key
      const k2 = `idem-${rand(8)}`;
      const i = await w.approved();
      const bad = await api.post(
        "devlead",
        `/findings/${i.id}/assignments`,
        { assigneeUserId: users.dev, expectedRev: 99 },
        { key: k2 },
      );
      eq(p, "a stale call fails", [bad.status, reasonOf(bad)], [409, "stale_revision"]);
      const fixed = await api.post(
        "devlead",
        `/findings/${i.id}/assignments`,
        { assigneeUserId: users.dev, expectedRev: (await w.row(i)).rev },
        { key: k2 },
      );
      eq(
        p,
        "the failed call freed its key",
        [fixed.status, fixed.headers.get("idempotent-replayed")],
        [201, null],
      );
      // replay of a start and a submit
      const s = await w.assigned("dev");
      const k3 = `idem-${rand(8)}`;
      const sb = { expectedRev: (await w.row(s)).rev };
      const s1 = await api.post("dev", `/findings/${s.id}/remediation/start`, sb, { key: k3 });
      const s2 = await api.post("dev", `/findings/${s.id}/remediation/start`, sb, { key: k3 });
      eq(
        p,
        "start and its replay",
        [s1.status, s2.status, s2.headers.get("idempotent-replayed")],
        [200, 200, "true"],
      );
      eq(p, "one record, one history row", [(await w.records(s)).length], [1]);
      const k4 = `idem-${rand(8)}`;
      const sm = { expectedRev: (await w.row(s)).rev, ticketKey: "SEC-9" };
      const m1 = await api.post("dev", `/findings/${s.id}/remediation/submit`, sm, { key: k4 });
      const m2 = await api.post("dev", `/findings/${s.id}/remediation/submit`, sm, { key: k4 });
      eq(
        p,
        "submit and its replay",
        [m1.status, m2.status, m2.headers.get("idempotent-replayed")],
        [200, 200, "true"],
      );
      eq(
        p,
        "the fix was recorded once",
        (await w.records(s)).filter((r) => r.kind === "fix_submitted").length,
        1,
      );
      // bulk replay
      const bulkIds = [(await w.approved()).id, (await w.approved()).id];
      const k5 = `idem-${rand(8)}`;
      const bb = { workspaceId: w.wsA, findingIds: bulkIds, assigneeUserId: users.dev };
      const bk1 = await api.post("devlead", "/findings/bulk/assign", bb, { key: k5 });
      const bk2 = await api.post("devlead", "/findings/bulk/assign", bb, { key: k5 });
      eq(
        p,
        "bulk and its replay",
        [bk1.status, bk2.status, bk2.headers.get("idempotent-replayed"), j(bk2.json?.data)],
        [200, 200, "true", j(bk1.json?.data)],
      );
      eq(
        p,
        "each finding was assigned once",
        await Promise.all(
          bulkIds.map(
            async (id) =>
              await w.db.findingAssignment.count({
                where: { tenantId: w.A.tenant.id, findingId: id },
              }),
          ),
        ),
        [1, 1],
      );

      // ---- the real limiter ----
      const limited = await startWriteApi(w.db, {
        limits: { write: { windowMs: 60_000, max: 3 }, read: { windowMs: 60_000, max: 2 } },
      });
      try {
        limited.register("lim", {
          userId: users.devlead,
          tenantId: w.A.tenant.id,
          workspaces: [
            {
              id: w.wsA,
              permissions: [
                "finding.view",
                "finding.assign",
                "finding.remediate",
                "remediation.view",
              ],
            },
          ],
        });
        limited.register("lim2", {
          userId: users.devlead2,
          tenantId: w.A.tenant.id,
          workspaces: [
            {
              id: w.wsA,
              permissions: [
                "finding.view",
                "finding.assign",
                "finding.remediate",
                "remediation.view",
              ],
            },
          ],
        });
        const codes = [];
        for (let n = 0; n < 5; n += 1) {
          const r = await limited.post("lim", `/findings/${UNKNOWN}/assignments`, {
            assigneeUserId: users.dev,
            expectedRev: 0,
          });
          codes.push(r.status);
        }
        eq(
          p,
          "three writes pass, the rest are limited (404 is the answer for the unknown id)",
          codes,
          [404, 404, 404, 429, 429],
        );
        const limitedBody = await limited.post("lim", `/findings/${UNKNOWN}/assignments`, {
          assigneeUserId: users.dev,
          expectedRev: 0,
        });
        eq(p, "the error code", codeOf(limitedBody), "RATE_LIMITED");
        const other2 = await limited.post("lim2", `/findings/${UNKNOWN}/assignments`, {
          assigneeUserId: users.dev,
          expectedRev: 0,
        });
        eq(p, "another user has their own budget", other2.status, 404);
        const otherRoute = await limited.post("lim2", `/findings/${UNKNOWN}/remediation/start`, {
          expectedRev: 0,
        });
        ok(p, otherRoute.status !== 429, "the limit is per route as well as per user");
        const reads = [];
        for (let n = 0; n < 3; n += 1)
          reads.push((await limited.get("lim", `/remediation/board?workspaceId=${w.wsA}`)).status);
        eq(p, "reads are counted apart (two pass, the third is limited)", reads, [200, 200, 429]);
      } finally {
        await limited.close();
      }
      return p;
    },
  },
];
