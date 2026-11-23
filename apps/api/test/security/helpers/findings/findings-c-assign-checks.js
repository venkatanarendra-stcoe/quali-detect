import { randomUUID } from "node:crypto";
import {
  CANARY,
  UNKNOWN,
  actionOf,
  cWorld,
  codeOf,
  eq,
  j,
  ok,
  reasonOf,
  shape,
} from "./findings-c-world.js";
import {
  at,
  findingsOf,
  footprint,
  ingest,
  runExecution,
  sast,
  scenario,
} from "./findings-a-fixtures.js";

/**
 * Findings checks of part C, assignment and remediation (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1): its share of FND-S08
 * (transition permissions and conflicts), FND-S11 (idempotency and rate limits of its routes) and FND-S14 (atomicity and events). The
 * REAL routes run behind the stub authentication chain of part B with the real authorization middleware, scope resolvers, route kit
 * validation, `Idempotency-Key` middleware, services, repositories, mappers, error handler and the real transition function. Every
 * denial has a control (the same write made legitimately succeeds) so a check cannot pass vacuously.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const full = (items = {}, over = {}) => ({
  types: {
    sca: { items: items.sca ?? [] },
    sast: { items: items.sast ?? [] },
    secrets: { items: items.secrets ?? [] },
  },
  ...over,
});

/** Lowers the rev guard for a deleted-pipeline case: the pipeline row is soft-deleted and restored by the check. */
const softDelete = (db, pipeline, deletedAt) =>
  db.pipeline.update({ where: { id: pipeline.id }, data: { deletedAt } });

export const FINDINGS_C_ASSIGN_CHECKS = [
  {
    id: "FND-S08c",
    name: "Assignment (SM-9, SM-10, SM-11, SM-17, AS-1, AS-2, FND-S01, FND-S02, FND-S08): assign, reassign and unassign answer an identical 404 for a hidden workspace, another tenant and an unknown id, 403 without `finding.assign`, 400 for a forged tenant, workspace, status or user key and for an assignee who is not an active member holding `finding.remediate` (a viewer, an analyst, a user of another tenant, a stranger), 409 `FINDING_STATE_CONFLICT` for a status the transition does not allow, a stale revision and a reassignment to the same person; a reassignment keeps the status, ends the previous assignment and writes a new one; an unassignment returns the finding to `approved` and clears the assignee; a reopened finding is assigned again; the bulk call is capped at 50 distinct findings, authorized in its workspace and reports each finding on its own (a finding of another tenant is not found, never forbidden); an archived workspace refuses it",
    async run(c) {
      const w = await cWorld(c);
      const p = [];
      const { api, users, db } = w;
      const f = await w.approved();
      const rev = async (x) => (await w.row(x)).rev;
      const body = async (x, who = "dev", extra = {}) => ({
        assigneeUserId: users[who],
        expectedRev: await rev(x),
        ...extra,
      });
      const url = (x) => `/findings/${x.id}/assignments`;
      const before = await w.snapshot(f);

      // 403 without the key (the permission, not the 404)
      for (const who of ["viewer", "analyst", "dev"]) {
        const r = await api.post(who, url(f), await body(f));
        eq(p, `${who} without finding.assign`, [r.status, codeOf(r)], [403, "FORBIDDEN"]);
      }
      // the identical 404: hidden workspace, another tenant, an unknown id
      const hidden = await api.post("ws2lead", url(f), await body(f));
      const foreign = await api.post("leadB", url(f), await body(f));
      const missing = await api.post("devlead", `/findings/${UNKNOWN}/assignments`, await body(f));
      eq(p, "hidden workspace", [hidden.status, codeOf(hidden)], [404, "RESOURCE_NOT_FOUND"]);
      ok(p, shape(hidden) === shape(foreign), "another tenant must look like a hidden workspace");
      ok(p, shape(hidden) === shape(missing), "an unknown id must look like a hidden workspace");
      // forged keys are refused by the strict schema
      for (const extra of [
        { tenantId: c.B.tenant.id },
        { workspaceId: w.wsA2 },
        { status: "assigned" },
        { pipelineId: w.pipeline.id },
        { assignedByUserId: users.analyst },
      ]) {
        const r = await api.post("devlead", url(f), await body(f, "dev", extra));
        eq(p, `forged ${Object.keys(extra)[0]}`, [r.status, codeOf(r)], [400, "VALIDATION_FAILED"]);
      }
      // the assignee must be an active member holding finding.remediate in this workspace
      for (const [label, id] of [
        ["a viewer", users.viewer],
        ["an analyst", users.analyst],
        ["a user of another tenant", users.devB],
        ["a stranger", randomUUID()],
      ]) {
        const r = await api.post("devlead", url(f), {
          assigneeUserId: id,
          expectedRev: await rev(f),
        });
        eq(
          p,
          `${label} as assignee`,
          [r.status, codeOf(r), reasonOf(r)],
          [400, "VALIDATION_FAILED", "assignee_not_eligible"],
        );
      }
      eq(p, "no refusal wrote anything", await w.snapshot(f), before);
      // wrong source statuses
      for (const [label, o] of [
        ["new", {}],
        ["in_review", { to: "in_review" }],
      ]) {
        let g = await w.fnd();
        if (o.to) g = await c.step(g, "in_review", { set: { claimedByUserId: users.analyst } });
        const r = await api.post("devlead", url(g), await body(g));
        eq(
          p,
          `assign a ${label} finding`,
          [r.status, codeOf(r), reasonOf(r)],
          [409, "FINDING_STATE_CONFLICT", "transition_not_allowed"],
        );
      }
      // stale revision
      const stale = await api.post("devlead", url(f), {
        assigneeUserId: users.dev,
        expectedRev: (await rev(f)) + 5,
      });
      eq(p, "stale revision", [stale.status, reasonOf(stale)], [409, "stale_revision"]);
      // control: the lead assigns (SM-9)
      const a1 = await api.post(
        "devlead",
        url(f),
        await body(f, "dev", { note: "Please take this." }),
      );
      eq(p, "control: assign", [a1.status, a1.json?.data?.status], [201, "assigned"]);
      eq(p, "the DTO names the assignee", a1.json?.data?.assignee?.id, users.dev);
      const r1 = await w.row(f);
      eq(
        p,
        "the row",
        [r1.status, r1.assigneeUserId, r1.rev],
        ["assigned", users.dev, before.rev + 1],
      );
      const as1 = await w.assignments(f);
      eq(
        p,
        "one open assignment by the lead",
        [
          as1.length,
          as1[0]?.assigneeUserId,
          as1[0]?.assignedByUserId,
          as1[0]?.endedAt,
          as1[0]?.note,
        ],
        [1, users.dev, users.devlead, null, "Please take this."],
      );
      eq(
        p,
        "the DTO shows the assignment",
        a1.json?.data?.remediation?.assignment?.assignee?.id,
        users.dev,
      );
      ok(p, a1.headers.get("etag") === `W/"finding-${r1.rev}"`, "the answer carries the new ETag");
      // reassignment to the same person is not a reassignment
      const same = await api.post("devlead", url(f), await body(f, "dev"));
      eq(
        p,
        "reassign to the same person",
        [same.status, reasonOf(same)],
        [409, "transition_not_allowed"],
      );
      // reassign (SM-10): the status stays, the previous assignment ends
      const a2 = await api.post("devlead", url(f), await body(f, "dev2"));
      eq(p, "reassign", [a2.status, a2.json?.data?.status], [201, "assigned"]);
      const as2 = await w.assignments(f);
      eq(
        p,
        "two rows, the first ended as reassigned, the second open",
        [as2.length, as2[0].endedReason, as2[1].endedAt, as2[1].assigneeUserId],
        [2, "reassigned", null, users.dev2],
      );
      const h2 = await w.history(f);
      eq(
        p,
        "the history row of the reassignment keeps the status",
        [h2.at(-1).reasonCode, h2.at(-1).fromStatus, h2.at(-1).toStatus, h2.at(-1).actorUserId],
        ["reassigned", "assigned", "assigned", users.devlead],
      );
      // reassignment while in progress keeps in_remediation
      const st = await api.post("dev2", `/findings/${f.id}/remediation/start`, {
        expectedRev: await rev(f),
      });
      eq(
        p,
        "control: the new assignee starts work",
        [st.status, st.json?.data?.status],
        [200, "in_remediation"],
      );
      const a3 = await api.post("devlead2", url(f), await body(f, "dev"));
      eq(
        p,
        "reassign while in progress",
        [a3.status, a3.json?.data?.status],
        [201, "in_remediation"],
      );
      // unassign (SM-11)
      for (const who of ["viewer", "analyst", "dev"]) {
        const r = await api.post(who, `${url(f)}/clear`, { expectedRev: await rev(f) });
        eq(p, `${who} cannot unassign`, [r.status, codeOf(r)], [403, "FORBIDDEN"]);
      }
      const hiddenClear = await api.post("ws2lead", `${url(f)}/clear`, {
        expectedRev: await rev(f),
      });
      ok(p, shape(hiddenClear) === shape(hidden), "unassign: hidden workspace is the same 404");
      const staleClear = await api.post("devlead", `${url(f)}/clear`, { expectedRev: 0 });
      eq(
        p,
        "unassign with a stale revision",
        [staleClear.status, reasonOf(staleClear)],
        [409, "stale_revision"],
      );
      const c1 = await api.post("devlead", `${url(f)}/clear`, {
        note: "Wrong team.",
        expectedRev: await rev(f),
      });
      eq(p, "control: unassign", [c1.status, c1.json?.data?.status], [200, "approved"]);
      const r3 = await w.row(f);
      eq(p, "the assignee is cleared", [r3.assigneeUserId, r3.assignedAt], [null, null]);
      const as3 = await w.assignments(f);
      eq(
        p,
        "the open assignment ended as unassigned, none is open",
        [as3.at(-1).endedReason, as3.filter((x) => x.endedAt === null).length],
        ["unassigned", 0],
      );
      const again = await api.post("devlead", `${url(f)}/clear`, { expectedRev: await rev(f) });
      eq(
        p,
        "unassign an approved finding",
        [again.status, reasonOf(again)],
        [409, "transition_not_allowed"],
      );
      // a reopened finding is assigned again (SM-17)
      let g = await w.assigned("dev");
      g = await c.step(g, "fixed_pending_verification", {
        set: { fixClaimedAt: new Date() },
        reason: "fix_submitted",
      });
      g = await c.step(g, "reopened", {
        actor: "system",
        reason: "recurred",
        set: { reopenedAt: new Date(), reopenCount: 1, absentCount: 0, fixClaimedAt: null },
      });
      const detail = await w.det("devlead", g);
      eq(
        p,
        "a reopened finding offers assign",
        [actionOf(detail, "assign")?.allowed, actionOf(detail, "unassign")],
        [true, undefined],
      );
      const reassign = await api.post("devlead", url(g), await body(g, "dev2"));
      eq(
        p,
        "assign a reopened finding",
        [reassign.status, reassign.json?.data?.status, reassign.json?.data?.assignee?.id],
        [201, "assigned", users.dev2],
      );
      const gs = await w.assignments(g);
      eq(
        p,
        "the earlier assignment was superseded, the new one is open",
        [gs.length, gs[0].endedAt !== null, gs[1].endedAt],
        [2, true, null],
      );

      // ---- the bulk call ----
      const b1 = await w.approved();
      const b2 = await w.approved();
      const newOne = await w.fnd();
      const foreignFinding = await c.finding(w.pipelineB);
      const bulk = (name, workspaceId, ids, extra = {}) =>
        api.post(name, "/findings/bulk/assign", {
          workspaceId,
          findingIds: ids,
          assigneeUserId: users.dev,
          ...extra,
        });
      const ids = [b1.id, newOne.id, UNKNOWN, foreignFinding.id, b2.id];
      for (const who of ["viewer", "analyst", "dev"]) {
        const r = await bulk(who, w.wsA, [b1.id]);
        eq(p, `bulk assign by ${who}`, [r.status, codeOf(r)], [403, "FORBIDDEN"]);
      }
      const bHidden = await bulk("ws2lead", w.wsA, [b1.id]);
      const bForeignWs = await bulk("devlead", w.wsB, [b1.id]);
      const bUnknownWs = await bulk("devlead", UNKNOWN, [b1.id]);
      eq(
        p,
        "bulk, a workspace the caller cannot see",
        [bHidden.status, codeOf(bHidden)],
        [404, "RESOURCE_NOT_FOUND"],
      );
      ok(p, shape(bHidden) === shape(bForeignWs), "bulk: another tenant's workspace looks hidden");
      ok(p, shape(bHidden) === shape(bUnknownWs), "bulk: an unknown workspace looks hidden");
      const tooMany = await bulk(
        "devlead",
        w.wsA,
        Array.from({ length: 51 }, () => randomUUID()),
      );
      eq(p, "51 findings", [tooMany.status, codeOf(tooMany)], [400, "VALIDATION_FAILED"]);
      const dup = await bulk("devlead", w.wsA, [b1.id, b1.id]);
      eq(p, "a duplicate id", [dup.status, codeOf(dup)], [400, "VALIDATION_FAILED"]);
      const empty = await bulk("devlead", w.wsA, []);
      eq(p, "no findings", [empty.status, codeOf(empty)], [400, "VALIDATION_FAILED"]);
      const badAssignee = await bulk("devlead", w.wsA, [b1.id], { assigneeUserId: users.viewer });
      eq(
        p,
        "an ineligible assignee fails the whole call",
        [badAssignee.status, reasonOf(badAssignee)],
        [400, "assignee_not_eligible"],
      );
      const forgedBulk = await bulk("devlead", w.wsA, [b1.id], { tenantId: c.B.tenant.id });
      eq(
        p,
        "a forged tenant key",
        [forgedBulk.status, codeOf(forgedBulk)],
        [400, "VALIDATION_FAILED"],
      );
      eq(p, "none of that changed b1", (await w.row(b1)).status, "approved");
      const res = await bulk("devlead", w.wsA, ids);
      eq(p, "bulk answers 200", res.status, 200);
      const byId = new Map((res.json?.data?.results ?? []).map((x) => [x.findingId, x]));
      eq(
        p,
        "approved finding b1 is assigned",
        [byId.get(b1.id)?.ok, byId.get(b2.id)?.ok],
        [true, true],
      );
      eq(
        p,
        "a new finding is a state conflict",
        [byId.get(newOne.id)?.ok, byId.get(newOne.id)?.errorCode, byId.get(newOne.id)?.reason],
        [false, "FINDING_STATE_CONFLICT", "transition_not_allowed"],
      );
      eq(
        p,
        "an unknown id and another tenant's finding are not found, never forbidden",
        [byId.get(UNKNOWN)?.errorCode, byId.get(foreignFinding.id)?.errorCode],
        ["RESOURCE_NOT_FOUND", "RESOURCE_NOT_FOUND"],
      );
      eq(
        p,
        "the foreign finding was not touched",
        [(await w.row(foreignFinding)).status, (await w.assignments(foreignFinding)).length],
        ["new", 0],
      );
      eq(
        p,
        "each finding is its own transaction",
        [(await w.row(b1)).status, (await w.row(newOne)).status],
        ["assigned", "new"],
      );

      // ---- an archived workspace refuses it (AUTHORIZATION 5.7) ----
      const archivedTarget = await w.approved();
      await db.workspace.update({ where: { id: w.wsA }, data: { status: "archived" } });
      try {
        const r = await api.post("devlead", url(archivedTarget), await body(archivedTarget));
        eq(
          p,
          "an archived workspace refuses an assignment",
          [r.status, codeOf(r), reasonOf(r)],
          [409, "CONFLICT", "workspace_archived"],
        );
      } finally {
        await db.workspace.update({ where: { id: w.wsA }, data: { status: "active" } });
      }
      const okAgain = await api.post("devlead", url(archivedTarget), await body(archivedTarget));
      eq(p, "control: the restored workspace works", okAgain.status, 201);
      return p;
    },
  },

  {
    id: "FND-S08d",
    name: "Start work and submit a fix (SM-12, SM-13, RM-1, FND-S02, FND-S08): 403 without `finding.remediate` (an assigner who cannot remediate, a viewer, an analyst), 404 identical for a hidden workspace, another tenant and an unknown id; a developer moves ONLY the findings assigned to them (`not_assignee`, nothing written) while a lead who also holds `finding.assign` moves any; the per-caller `allowedActions` agree with what the routes enforce; a disallowed source status and a stale revision are 409; a deleted pipeline refuses the fix (`pipeline_deleted`); the pull request link (https only, no userinfo, no credential, the stored shape), the ticket key and the note are validated and a credential-shaped text is refused before anything is written; a submitted fix is `fixed_pending_verification` with the claim time set and the SLA stopped, never `verified_fixed`; a second submission is a conflict",
    async run(c) {
      const w = await cWorld(c);
      const p = [];
      const { api, users, db } = w;
      const f = await w.assigned("dev");
      const rev = async (x) => (await w.row(x)).rev;
      const startBody = async (x, extra = {}) => ({ expectedRev: await rev(x), ...extra });
      const url = (x, what) => `/findings/${x.id}/remediation/${what}`;
      const before = await w.snapshot(f);

      // permissions
      for (const who of ["admin", "viewer", "analyst"]) {
        const r = await api.post(who, url(f, "start"), await startBody(f));
        eq(
          p,
          `${who} cannot start (no finding.remediate)`,
          [r.status, codeOf(r)],
          [403, "FORBIDDEN"],
        );
        const s = await api.post(who, url(f, "submit"), await startBody(f));
        eq(p, `${who} cannot submit`, [s.status, codeOf(s)], [403, "FORBIDDEN"]);
      }
      const hidden = await api.post("ws2lead", url(f, "start"), await startBody(f));
      const foreign = await api.post("devB", url(f, "start"), await startBody(f));
      const missing = await api.post(
        "dev",
        `/findings/${UNKNOWN}/remediation/start`,
        await startBody(f),
      );
      eq(p, "hidden workspace", [hidden.status, codeOf(hidden)], [404, "RESOURCE_NOT_FOUND"]);
      ok(p, shape(hidden) === shape(foreign), "another tenant looks like a hidden workspace");
      ok(p, shape(hidden) === shape(missing), "an unknown id looks like a hidden workspace");
      // a developer moves only their own cards
      const other = await api.post("dev2", url(f, "start"), await startBody(f));
      eq(
        p,
        "another developer cannot start it",
        [other.status, codeOf(other), reasonOf(other)],
        [403, "FORBIDDEN", "not_assignee"],
      );
      const otherSubmit = await api.post("dev2", url(f, "submit"), await startBody(f));
      eq(
        p,
        "another developer cannot submit it",
        [otherSubmit.status, reasonOf(otherSubmit)],
        [403, "not_assignee"],
      );
      eq(p, "the refusals wrote nothing", await w.snapshot(f), before);
      // the per-caller actions agree with the routes
      const dOwn = await w.det("dev", f);
      const dOther = await w.det("dev2", f);
      const dLead = await w.det("devlead", f);
      eq(
        p,
        "the assignee may start and submit",
        [actionOf(dOwn, "start_work")?.allowed, actionOf(dOwn, "submit_fix")?.allowed],
        [true, true],
      );
      eq(
        p,
        "another developer sees them disabled with the reason",
        [
          actionOf(dOther, "start_work")?.allowed,
          actionOf(dOther, "start_work")?.disabledReason,
          actionOf(dOther, "submit_fix")?.allowed,
        ],
        [false, "You can only move findings assigned to you.", false],
      );
      eq(
        p,
        "a lead who can assign may move it",
        [actionOf(dLead, "start_work")?.allowed, actionOf(dLead, "submit_fix")?.allowed],
        [true, true],
      );
      // wrong source statuses (the status is decided before the caller)
      const approved = await w.approved();
      const wrong = await api.post("devlead", url(approved, "start"), await startBody(approved));
      eq(
        p,
        "start an approved finding",
        [wrong.status, reasonOf(wrong)],
        [409, "transition_not_allowed"],
      );
      const wrongSubmit = await api.post(
        "devlead",
        url(approved, "submit"),
        await startBody(approved),
      );
      eq(
        p,
        "submit an approved finding",
        [wrongSubmit.status, reasonOf(wrongSubmit)],
        [409, "transition_not_allowed"],
      );
      const fresh = await w.fnd();
      const newSubmit = await api.post("dev", url(fresh, "submit"), await startBody(fresh));
      eq(
        p,
        "submit a new finding",
        [newSubmit.status, reasonOf(newSubmit)],
        [409, "transition_not_allowed"],
      );
      const staleStart = await api.post("dev", url(f, "start"), { expectedRev: 99 });
      eq(
        p,
        "start with a stale revision",
        [staleStart.status, reasonOf(staleStart)],
        [409, "stale_revision"],
      );
      eq(p, "still nothing written", await w.snapshot(f), before);
      // forged keys
      for (const extra of [
        { status: "verified_fixed" },
        { tenantId: c.B.tenant.id },
        { assigneeUserId: users.dev2 },
      ]) {
        const r = await api.post("dev", url(f, "start"), await startBody(f, extra));
        eq(p, `forged ${Object.keys(extra)[0]}`, [r.status, codeOf(r)], [400, "VALIDATION_FAILED"]);
      }
      // control: the assignee starts work (SM-12)
      const s1 = await api.post("dev", url(f, "start"), await startBody(f));
      eq(p, "control: start", [s1.status, s1.json?.data?.status], [200, "in_remediation"]);
      eq(
        p,
        "the DTO shows the work-started record",
        s1.json?.data?.remediation?.lastRecord?.kind,
        "work_started",
      );
      const h1 = await w.history(f);
      eq(
        p,
        "the history row",
        [h1.at(-1).reasonCode, h1.at(-1).actorUserId],
        ["work_started", users.dev],
      );
      const rec1 = await w.records(f);
      eq(
        p,
        "one remediation record bound to the open assignment",
        [
          rec1.length,
          rec1[0]?.kind,
          rec1[0]?.actorUserId,
          rec1[0]?.assignmentId === (await w.assignments(f)).at(-1).id,
        ],
        [1, "work_started", users.dev, true],
      );
      const startAgain = await api.post("dev", url(f, "start"), await startBody(f));
      eq(
        p,
        "start twice",
        [startAgain.status, reasonOf(startAgain)],
        [409, "transition_not_allowed"],
      );
      // a lead who also holds finding.assign starts another developer's finding
      const g = await w.assigned("dev");
      const leadStart = await api.post("devlead", url(g, "start"), await startBody(g));
      eq(
        p,
        "control: a lead with finding.assign starts it",
        [leadStart.status, leadStart.json?.data?.status],
        [200, "in_remediation"],
      );

      // ---- the submission ----
      const midBefore = await w.snapshot(f);
      const prUrl = "https://github.com/acme/app/pull/7";
      const bad = [
        ["a plain http link", { pullRequestUrl: "http://github.com/acme/app/pull/7" }],
        ["a link with userinfo", { pullRequestUrl: "https://user:pw@github.com/acme/app/pull/7" }],
        ["not a link", { pullRequestUrl: "github.com/acme/app/pull/7" }],
        ["a javascript link", { pullRequestUrl: "javascript:alert(1)" }],
        [
          "a link with a credential",
          { pullRequestUrl: `https://github.com/acme/app?token=${CANARY.github}` },
        ],
        ["a link with whitespace", { pullRequestUrl: "https://github.com/acme/app/pull 7" }],
        ["a lower case ticket key", { ticketKey: "sec-12" }],
        ["a ticket key that is a link", { ticketKey: "https://jira/SEC-12" }],
        ["a credential in the note", { note: `deployed with ${CANARY.stripe}` }],
        ["a second credential shape in the note", { note: `token ${CANARY.slack}` }],
      ];
      for (const [label, extra] of bad) {
        const r = await api.post("dev", url(f, "submit"), await startBody(f, extra));
        eq(p, `submit with ${label}`, [r.status, codeOf(r)], [400, "VALIDATION_FAILED"]);
      }
      eq(p, "no refused submission wrote anything", await w.snapshot(f), midBefore);
      for (const text of Object.values(CANARY))
        ok(
          p,
          !JSON.stringify(
            await db.remediationRecord.findMany({ where: { tenantId: f.tenantId } }),
          ).includes(text),
          "a canary secret reached a remediation record",
        );
      const sub = await api.post(
        "dev",
        url(f, "submit"),
        await startBody(f, {
          pullRequestUrl: prUrl,
          ticketKey: "SEC-123",
          note: "Upgraded and added a test.",
        }),
      );
      eq(
        p,
        "control: submit",
        [sub.status, sub.json?.data?.status],
        [200, "fixed_pending_verification"],
      );
      const r2 = await w.row(f);
      ok(
        p,
        r2.fixClaimedAt !== null && r2.absentCount === 0,
        "a human claim sets the claim time and a zero absence count",
      );
      eq(
        p,
        "the SLA clock stopped and the finding is not verified",
        [r2.slaDueAt, r2.verifiedAt, r2.closedAt],
        [null, null, null],
      );
      const rec2 = (await w.records(f)).at(-1);
      eq(
        p,
        "the stored record",
        [rec2.kind, rec2.pullRequestUrl, rec2.ticketKey, rec2.note, rec2.actorUserId],
        ["fix_submitted", prUrl, "SEC-123", "Upgraded and added a test.", users.dev],
      );
      eq(
        p,
        "the DTO shows the record",
        [
          sub.json?.data?.remediation?.lastRecord?.kind,
          sub.json?.data?.remediation?.lastRecord?.pullRequestUrl,
          sub.json?.data?.remediation?.lastRecord?.ticketKey,
        ],
        ["fix_submitted", prUrl, "SEC-123"],
      );
      const again = await api.post("dev", url(f, "submit"), await startBody(f));
      eq(
        p,
        "a second submission",
        [again.status, reasonOf(again)],
        [409, "transition_not_allowed"],
      );
      const noStart = await api.post("dev", url(f, "start"), await startBody(f));
      eq(
        p,
        "start after submit",
        [noStart.status, reasonOf(noStart)],
        [409, "transition_not_allowed"],
      );
      // a submission straight from `assigned` (no start) and with no optional field
      const direct = await w.assigned("dev2");
      const ds = await api.post("dev2", url(direct, "submit"), await startBody(direct));
      eq(
        p,
        "submit from assigned, nothing optional",
        [ds.status, ds.json?.data?.status],
        [200, "fixed_pending_verification"],
      );
      const drec = (await w.records(direct)).at(-1);
      eq(
        p,
        "the optional fields are null",
        [drec.pullRequestUrl, drec.ticketKey, drec.note],
        [null, null, null],
      );
      // a bare https link is a valid link
      const bare = await w.assigned("dev");
      const bs = await api.post(
        "dev",
        url(bare, "submit"),
        await startBody(bare, { pullRequestUrl: "https://example.com" }),
      );
      eq(p, "control: a bare https link", bs.status, 200);

      // a deleted pipeline cannot verify a fix (5.13)
      const dp = await c.pipeline(c.A, 0);
      const dFinding = await w.assigned("dev", {}, dp);
      await softDelete(db, dp, new Date());
      try {
        const dDetail = await w.det("dev", dFinding);
        eq(
          p,
          "submit_fix is disabled on a deleted pipeline",
          [actionOf(dDetail, "submit_fix")?.allowed, actionOf(dDetail, "start_work")?.allowed],
          [false, true],
        );
        const refused = await api.post("dev", url(dFinding, "submit"), await startBody(dFinding));
        eq(
          p,
          "submit on a deleted pipeline",
          [refused.status, codeOf(refused), reasonOf(refused)],
          [409, "FINDING_STATE_CONFLICT", "pipeline_deleted"],
        );
        eq(p, "nothing written", (await w.row(dFinding)).status, "assigned");
      } finally {
        await softDelete(db, dp, null);
      }
      const dControl = await api.post("dev", url(dFinding, "submit"), await startBody(dFinding));
      eq(p, "control: the live pipeline accepts it", dControl.status, 200);
      return p;
    },
  },

  {
    id: "FND-S08e",
    name: "Verification stays with ingestion (RM-2, D-2, D-25, FND-S06): a human fix claim moves a finding only to `fixed_pending_verification`; no route can verify or reopen it (a verify route does not exist, assignment, start and submit answer 409); an incremental, a partial, a failed and a fork run that does not contain the finding change nothing (status, revision, absence count, verification records, history, audit, events); the next eligible full scan that does not contain it verifies it (a verification record, `verified_fixed`, closed); a detection of a claimed finding, even by an incremental run, reopens it (outcome `failed`, the SLA restarts) and it can be assigned again",
    async run(c) {
      const w = await cWorld(c);
      const p = [];
      const { api, users, db } = w;
      const scn = await scenario(c);
      const keep = sast({ path: "src/keep.py", line: 1, code: "keep(1)" });
      const claimed = sast({ path: "src/claimed.py", line: 2, code: "claimed(2)" });
      const recur = sast({ path: "src/recur.py", line: 3, code: "recur(3)" });
      const e0 = await runExecution(scn, {
        ...full({ sast: [keep, claimed, recur] }),
        startedAt: at(0),
      });
      await ingest(scn, e0);
      const byPath = async (path) => (await findingsOf(scn, { path }))[0];
      // move two findings to `approved` through the machine, then assign, start and submit through the REAL routes
      const toFixed = async (path) => {
        let f = await byPath(path);
        f = await c.step(f, "in_review", {
          set: { claimedByUserId: users.analyst },
          reason: "review_started",
        });
        const r = await c.review(f, { reviewerUserId: users.analyst });
        f = await c.step(f, "awaiting_approval", {
          set: { pendingReviewId: r.id },
          reason: "review_recorded",
        });
        f = await c.step(f, "approved", { set: { pendingReviewId: null }, reason: "approved_tp" });
        f = await w.assignTo(f, "dev");
        const s = await api.post("dev", `/findings/${f.id}/remediation/start`, {
          expectedRev: f.rev,
        });
        if (s.status !== 200) throw new Error(`start answered ${s.status}`);
        const sub = await api.post("dev", `/findings/${f.id}/remediation/submit`, {
          expectedRev: (await w.row(f)).rev,
          pullRequestUrl: "https://github.com/acme/app/pull/9",
        });
        if (sub.status !== 200) throw new Error(`submit answered ${sub.status} ${j(sub.json)}`);
        return w.row(f);
      };
      const x = await toFixed("src/claimed.py");
      const z = await toFixed("src/recur.py");
      eq(
        p,
        "both are pending verification, claimed by a person",
        [x.status, z.status, x.fixClaimedAt !== null],
        ["fixed_pending_verification", "fixed_pending_verification", true],
      );
      eq(
        p,
        "no verification record exists yet",
        await db.verificationRecord.count({ where: { tenantId: x.tenantId, findingId: x.id } }),
        0,
      );

      // no route verifies or reopens
      const noVerify = await api.post("devlead", `/findings/${x.id}/remediation/verify`, {
        expectedRev: x.rev,
      });
      eq(p, "there is no verify route", noVerify.status, 404);
      const noReopen = await api.post("devlead", `/findings/${x.id}/remediation/reopen`, {
        expectedRev: x.rev,
      });
      eq(p, "there is no reopen route", noReopen.status, 404);
      const cut = await w.snapshot(x);
      for (const [label, path, body] of [
        ["start", `/findings/${x.id}/remediation/start`, {}],
        ["submit", `/findings/${x.id}/remediation/submit`, {}],
        ["assign", `/findings/${x.id}/assignments`, { assigneeUserId: users.dev2 }],
        ["unassign", `/findings/${x.id}/assignments/clear`, {}],
      ]) {
        for (const who of ["devlead", "dev"]) {
          const r = await api.post(who, path, { ...body, expectedRev: x.rev });
          ok(
            p,
            r.status === 409 || r.status === 403,
            `${who} ${label} on a pending finding answered ${r.status}`,
          );
          ok(
            p,
            r.status !== 200 && r.status !== 201,
            `${label} must not succeed on a pending finding`,
          );
        }
      }
      eq(p, "no attempt changed it", await w.snapshot(x), cut);
      const detail = await w.det("devlead", x);
      eq(
        p,
        "the card offers no action that moves a pending fix",
        detail.lifecycle.allowedActions.filter((a) =>
          ["assign", "reassign", "unassign", "start_work", "submit_fix"].includes(a.action),
        ),
        [],
      );

      // runs that must NOT resolve it
      const none = (over = {}) => full({}, { startedAt: at(100), ...over });
      const cases = [
        ["an incremental run", none({ scanKind: "incremental" })],
        ["a partial run", none({ status: "partial" })],
        ["a failed run", none({ status: "failed" })],
        ["a fork pull request", none({ trust: "untrusted_fork" })],
        ["a tag", none({ refType: "tag", refName: "v1" })],
        ["a feature branch", none({ refName: "feature/x" })],
      ];
      for (const [label, spec] of cases) {
        // the recorded skip (`finding_ingestions`) is bookkeeping of the ingestion itself, not a change of any finding
        const quiet = async () => ({ ...(await footprint(scn)), ingestions: 0 });
        const before = await quiet();
        const e = await runExecution(scn, spec);
        await ingest(scn, e);
        const after = await quiet();
        eq(p, `${label}: nothing is written`, after, before);
        const now = await byPath("src/claimed.py");
        eq(
          p,
          `${label}: still pending, not verified`,
          [now.status, now.absentCount, now.rev],
          ["fixed_pending_verification", 0, x.rev],
        );
      }
      eq(
        p,
        "no verification record from the ineligible runs",
        await db.verificationRecord.count({
          where: { tenantId: x.tenantId, pipelineId: x.pipelineId },
        }),
        0,
      );

      // the next ELIGIBLE full scan that does not contain it verifies it (claimed.py absent; recur.py present again: reopens)
      const eFull = await runExecution(scn, { ...full({ sast: [keep] }), startedAt: at(200) });
      await ingest(scn, eFull);
      const vx = await byPath("src/claimed.py");
      eq(
        p,
        "an eligible absence verifies a claimed fix",
        [vx.status, vx.absentCount],
        ["verified_fixed", 1],
      );
      ok(
        p,
        vx.verifiedAt !== null && vx.closedAt !== null,
        "verified and closed timestamps are set by the scan",
      );
      const ver = await db.verificationRecord.findMany({
        where: { tenantId: x.tenantId, findingId: x.id },
      });
      eq(p, "one verification record", [ver.length, ver[0]?.outcome], [1, "verified"]);
      const hx = await w.history(x);
      eq(
        p,
        "the verified row belongs to the system actor",
        [hx.at(-1).reasonCode, hx.at(-1).actorType, hx.at(-1).actorCode],
        ["verified", "system", "ingestion"],
      );
      eq(
        p,
        "the other claimed finding is also verified by that run (absent too)",
        (await byPath("src/recur.py")).status,
        "verified_fixed",
      );
      // the control finding that was never claimed stays open
      eq(p, "a finding still detected is untouched", (await byPath("src/keep.py")).status, "new");

      // a detection of a CLAIMED finding reopens it, even from an incremental run
      const y = await toFixed2(w, c, scn, "src/keep.py", users, api, byPath);
      const eInc = await runExecution(scn, {
        ...full({ sast: [keep] }),
        scanKind: "incremental",
        startedAt: at(300),
      });
      await ingest(scn, eInc);
      const ry = await byPath("src/keep.py");
      eq(
        p,
        "a detection reopens a claimed fix, whatever the scan kind",
        [ry.status, ry.reopenCount, ry.fixClaimedAt],
        ["reopened", 1, null],
      );
      ok(p, ry.slaDueAt !== null, "the SLA clock restarts on reopening");
      const vy = await db.verificationRecord.findMany({
        where: { tenantId: y.tenantId, findingId: y.id },
      });
      eq(
        p,
        "a failed-fix record from the detection",
        vy.map((v) => v.outcome),
        ["failed"],
      );
      // and it can be assigned again through the route
      const re = await api.post("devlead", `/findings/${y.id}/assignments`, {
        assigneeUserId: users.dev2,
        expectedRev: ry.rev,
      });
      eq(
        p,
        "a reopened finding is assigned again",
        [re.status, re.json?.data?.status],
        [201, "assigned"],
      );
      return p;
    },
  },
];

/** Moves the finding at `path` to `fixed_pending_verification` through the product's routes (a person's fix claim). */
async function toFixed2(w, c, scn, path, users, api, byPath) {
  let f = await byPath(path);
  f = await c.step(f, "in_review", {
    set: { claimedByUserId: users.analyst },
    reason: "review_started",
  });
  const r = await c.review(f, { reviewerUserId: users.analyst });
  f = await c.step(f, "awaiting_approval", {
    set: { pendingReviewId: r.id },
    reason: "review_recorded",
  });
  f = await c.step(f, "approved", { set: { pendingReviewId: null }, reason: "approved_tp" });
  f = await w.assignTo(f, "dev");
  const sub = await api.post("dev", `/findings/${f.id}/remediation/submit`, {
    expectedRev: (await w.row(f)).rev,
  });
  if (sub.status !== 200) throw new Error(`submit answered ${sub.status}`);
  return w.row(f);
}
