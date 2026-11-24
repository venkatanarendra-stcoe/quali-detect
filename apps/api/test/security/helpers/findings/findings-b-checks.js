import { randomUUID } from "node:crypto";
import { findingEtag } from "../../../../src/modules/findings/mappers/etag.js";
import { buildFindingMessage } from "@qmentisai/db";
import { FINDING_ACTIONS } from "@qmentisai/shared";
import { createAuthResolvers } from "../../../../src/auth/context.js";
import { createExceptionExpiryHandler } from "../../../../../workers/src/findings/expiry.js";
import {
  PERMS,
  makeUser,
  rand,
  startFindingsRealtime,
  startWriteApi,
  waitFor,
} from "./findings-b-fixtures.js";

/**
 * Findings checks of part B (lifecycle, review, approval, SOD, exceptions, comments, the findings realtime room) (ADR-008 area 19,
 * docs/modules/findings/SPEC.md 14.1): FND-S02, FND-S07 to FND-S09, FND-S10 (rationales and comments), FND-S11, FND-S15, FND-S16 and
 * FNDDB-05. The REAL write and read routes run behind a stub authentication chain (the permissions of a principal are given by the
 * check) with the real authorization middleware, scope resolvers, route kit validation, `Idempotency-Key` middleware, services,
 * repositories, mappers, error handler and the real transition function; the expiry job is the real handler with an injected clock; the
 * realtime room is the real server and consumer on a broker double. Every denial has a control (the same write made legitimately
 * succeeds) so a check cannot pass vacuously.
 *
 * A check is `{ id, name, run }`; `run(c)` receives the findings world and returns the problems (empty means it passed).
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const j = (v) => JSON.stringify(v);
const eq = (p, label, got, want) => {
  if (j(got) !== j(want)) p.push(`${label}: got ${j(got)}, want ${j(want)}`);
};
const DAY = 86_400_000;
const inDays = (n) => new Date(Date.now() + n * DAY).toISOString();
const RATIONALE = "Reachable from user input; confirmed by reading the handler and the call site.";
const JUSTIFICATION = "The code path is behind an internal-only gateway until the next quarter.";
const UNKNOWN = "00000000-0000-4000-8000-0000000000bb";
const SOD_WORDS = "You recorded a decision on this finding. Another lead must approve it.";

/** Canary secrets assembled at run time (no literal secret in the source). */
const CANARY = Object.freeze({
  github: `${"ghp"}_${"q1w2e3r4t5".repeat(4)}`,
  stripe: `${"sk"}_${"live"}_${"Zq8Lm3".repeat(5)}`,
  slack: `${"xox"}${"b"}-1234567890-0987654321-${"Ab1Cd2".repeat(4)}`,
  jwt: `${"eyJ"}hbGciOiJIUzI1NiJ9.${"eyJ"}zdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y`,
  url: `https://deploy:${"p4ssw0rd".repeat(2)}@git.example.test/repo.git`,
});

// ---- the world ------------------------------------------------------------------------------------------------------------------

/** Builds (once) the API, the users and the helpers every check of this file shares. */
function bWorld(c) {
  c.__fndB ??= (async () => {
    const { db, A, B } = c;
    const wsA = A.ws[0].id;
    const wsA2 = A.ws[1].id;
    const wsB = B.ws[0].id;
    const pipeline = await c.pipeline(A, 0);
    const pipeline2 = await c.pipeline(A, 1);
    const pipelineB = await c.pipeline(B, 0);
    const api = await startWriteApi(db);
    const users = {};
    const reg = async (name, perms, tree = A, ws = wsA) => {
      const u = await makeUser(db, tree, name);
      users[name] = u.id;
      api.register(name, {
        userId: u.id,
        tenantId: tree.tenant.id,
        workspaces: [{ id: ws, permissions: perms }],
      });
    };
    for (const k of Object.keys(PERMS)) await reg(k, PERMS[k]);
    await reg("analyst2", PERMS.analyst);
    await reg("lead2", PERMS.lead);
    await reg("accepter", ["finding.view", "finding.accept_risk"]);
    await reg("ws2only", PERMS.hybrid, A, wsA2); // sees only the SECOND workspace of tenant A
    await reg("ws2lead", PERMS.lead, A, wsA2);
    await reg("leadB", [...PERMS.hybrid, ...PERMS.lead], B, wsB);
    await reg("leadB2", PERMS.lead, B, wsB);
    const row = (f) =>
      db.finding.findUnique({ where: { tenantId_id: { tenantId: f.tenantId, id: f.id } } });
    const w = {
      c,
      db,
      A,
      B,
      wsA,
      wsA2,
      wsB,
      pipeline,
      pipeline2,
      pipelineB,
      api,
      users,
      row,
      fnd: (o = {}, pipe = pipeline) => c.finding(pipe, o),
      det: async (name, f) => {
        const r = await api.get(name, `/findings/${f.id}`);
        if (r.status !== 200) throw new Error(`detail answered ${r.status}`);
        return r.json.data;
      },
      history: (f) =>
        db.findingStatusHistory.findMany({
          where: { tenantId: f.tenantId, findingId: f.id },
          orderBy: { rev: "asc" },
        }),
      audit: (f) =>
        db.auditLog.findMany({
          where: { tenantId: f.tenantId, targetType: "finding", targetId: f.id },
          orderBy: { createdAt: "asc" },
        }),
      outbox: async (f) =>
        (await db.outboxMessage.findMany({ where: { tenantId: f.tenantId } })).filter(
          (r) => r.payload?.payload?.findingId === f.id,
        ),
      /** Records a review as `name` at the finding's current revision; returns the HTTP result. */
      record: async (name, f, decision = "true_positive", extra = {}) =>
        api.post(name, `/findings/${f.id}/reviews`, {
          decision,
          rationale: RATIONALE,
          expectedRev: (await row(f)).rev,
          ...extra,
        }),
      reviewIdOf: async (f) => (await row(f)).pendingReviewId,
      approve: async (name, f, reviewId, extra = {}) =>
        api.post(name, `/findings/${f.id}/reviews/${reviewId}/approve`, {
          expectedRev: (await row(f)).rev,
          ...extra,
        }),
      reject: async (name, f, reviewId, extra = {}) =>
        api.post(name, `/findings/${f.id}/reviews/${reviewId}/reject`, {
          comment: "The rationale does not show the call path; please add it.",
          expectedRev: (await row(f)).rev,
          ...extra,
        }),
      requestException: async (name, f, kind = "accept_risk", extra = {}) =>
        api.post(name, `/findings/${f.id}/exceptions`, {
          kind,
          justification: JUSTIFICATION,
          ...(kind === "accept_risk" ? { expiresAt: inDays(30) } : {}),
          expectedRev: (await row(f)).rev,
          ...extra,
        }),
      /** A finding with a pending TP review by `reviewer`. @returns {Promise<{ f: any, reviewId: string }>} */
      pending: async (
        reviewer = "analyst",
        decision = "true_positive",
        o = {},
        pipe = pipeline,
      ) => {
        const f = await w.fnd(o, pipe);
        const r = await w.record(reviewer, f, decision);
        if (r.status !== 201) throw new Error(`record answered ${r.status} ${j(r.json)}`);
        return { f, reviewId: await w.reviewIdOf(f) };
      },
      /** A finding in `accepted_risk` (or `suppressed`), approved by lead. */
      accepted: async (kind = "accept_risk", requester = "analyst", approver = "lead") => {
        const f = await w.fnd();
        const r = await w.requestException(requester, f, kind);
        if (r.status !== 201) throw new Error(`request answered ${r.status} ${j(r.json)}`);
        const ex = r.json.data.exception;
        const a = await api.post(approver, `/findings/${f.id}/exceptions/${ex.id}/approve`, {
          expectedRev: (await row(f)).rev,
        });
        if (a.status !== 200) throw new Error(`approve answered ${a.status} ${j(a.json)}`);
        return { f, exceptionId: ex.id };
      },
    };
    return w;
  })();
  return c.__fndB;
}

const codeOf = (r) => r.json?.error?.code;
const reasonOf = (r) => r.json?.error?.details?.reason;
const actionOf = (d, action) => d.lifecycle.allowedActions.find((a) => a.action === action);

// ---- the checks -----------------------------------------------------------------------------------------------------------------

export const FINDINGS_B_CHECKS = [
  {
    id: "FND-S02a",
    name: "403 versus 404 on EVERY Part B write route: a visible finding without the key is 403, a hidden workspace, another tenant's finding and an unknown id are one identical 404, forged tenant or workspace keys in a body are refused, Admin cannot approve (no `approval.approve` by default); the controls succeed",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const f = await w.fnd();
      const rid = UNKNOWN;
      const body = (rev = 0) => ({
        claim: { expectedRev: rev },
        reviews: { decision: "true_positive", rationale: RATIONALE, expectedRev: rev },
        withdraw: { expectedRev: rev },
        approve: { expectedRev: rev },
        reject: { comment: "No call path shown.", expectedRev: rev },
        reopen: { reason: "Needs a new look after the refactor.", expectedRev: rev },
        comment: { body: "Looking at this today." },
        exception: {
          kind: "accept_risk",
          justification: JUSTIFICATION,
          expiresAt: inDays(20),
          expectedRev: rev,
        },
        suppress: {
          kind: "suppress",
          justification: JUSTIFICATION,
          expectedRev: rev,
        },
        exWithdraw: {},
        exApprove: { expectedRev: rev },
        exReject: { comment: "Not convincing.", expectedRev: rev },
        exRevoke: { reason: "Controls changed.", expectedRev: rev },
      });
      const routes = (fid, bodies = body()) => [
        ["claim", `/findings/${fid}/claim`, bodies.claim],
        ["reviews", `/findings/${fid}/reviews`, bodies.reviews],
        ["withdraw", `/findings/${fid}/reviews/${rid}/withdraw`, bodies.withdraw],
        ["approve", `/findings/${fid}/reviews/${rid}/approve`, bodies.approve],
        ["reject", `/findings/${fid}/reviews/${rid}/reject`, bodies.reject],
        ["reopen-review", `/findings/${fid}/reopen-review`, bodies.reopen],
        ["comments", `/findings/${fid}/comments`, bodies.comment],
        ["exceptions", `/findings/${fid}/exceptions`, bodies.exception],
        ["exceptions(suppress)", `/findings/${fid}/exceptions`, bodies.suppress],
        ["exception approve", `/findings/${fid}/exceptions/${rid}/approve`, bodies.exApprove],
        ["exception reject", `/findings/${fid}/exceptions/${rid}/reject`, bodies.exReject],
        ["bulk claim", `/findings/bulk/claim`, { workspaceId: w.wsA, findingIds: [fid] }],
      ];
      // 403: a visible finding, but the viewer holds none of the write keys (withdraw and revoke need only `finding.view`: service rules)
      for (const [label, path, b] of routes(f.id)) {
        const r = await w.api.post("viewer", path, b);
        eq(p, `${label} as a viewer (status)`, r.status, 403);
        eq(p, `${label} as a viewer (code)`, codeOf(r), "FORBIDDEN");
      }
      // Admin has no approval keys by default: approve and reject (reviews and exceptions) are 403
      for (const [label, path, b] of routes(f.id).filter(([l]) => /approve|reject/.test(l))) {
        const r = await w.api.post("admin", path, b);
        eq(p, `${label} as Admin (no approval key by default)`, r.status, 403);
      }
      // 404: hidden workspace (ws2only sees tenant A's OTHER workspace), another tenant, unknown id: identical bodies
      const bodies404 = [];
      for (const [who, fid] of [
        ["ws2only", f.id],
        ["leadB", f.id],
        ["hybrid", UNKNOWN],
      ])
        for (const [label, path, b] of routes(fid)) {
          // a bulk call names a WORKSPACE; an unknown finding in a visible workspace is a per-item "not found" (asserted below)
          if (label === "bulk claim" && who === "hybrid") continue;
          const r = await w.api.post(who, path, b);
          eq(
            p,
            `${label} as ${who} on ${fid === f.id ? "a foreign finding" : "an unknown id"}`,
            r.status,
            404,
          );
          bodies404.push(j({ ...r.json?.error, details: undefined }));
        }
      eq(p, "the 404 bodies are identical", [...new Set(bodies404)].length, 1);
      // bulk: a workspace that is hidden, foreign or unknown is the same 404
      for (const [who, ws] of [
        ["ws2only", w.wsA],
        ["leadB", w.wsA],
        ["hybrid", UNKNOWN],
      ]) {
        const r = await w.api.post(who, "/findings/bulk/claim", {
          workspaceId: ws,
          findingIds: [f.id],
        });
        eq(
          p,
          `bulk claim as ${who} on workspace ${ws === UNKNOWN ? "unknown" : "foreign"}`,
          r.status,
          404,
        );
      }
      const per = await w.api.post("hybrid", "/findings/bulk/claim", {
        workspaceId: w.wsA,
        findingIds: [UNKNOWN],
      });
      eq(
        p,
        "bulk claim of an unknown finding in a visible workspace",
        [per.status, per.json?.data?.results],
        [200, [{ findingId: UNKNOWN, ok: false, errorCode: "RESOURCE_NOT_FOUND" }]],
      );
      // forged keys in a body are refused (strict schemas), the finding is untouched
      for (const extra of [
        { tenantId: w.B.tenant.id },
        { workspaceId: w.wsA2 },
        { status: "approved" },
      ]) {
        const r = await w.api.post("analyst", `/findings/${f.id}/claim`, {
          expectedRev: 0,
          ...extra,
        });
        eq(p, `claim with ${Object.keys(extra)[0]} in the body`, r.status, 400);
      }
      eq(p, "the finding was untouched by every refusal", (await w.row(f)).rev, 0);
      // controls: the same writes succeed for the principals that hold the keys
      const ok1 = await w.api.post("analyst", `/findings/${f.id}/claim`, { expectedRev: 0 });
      eq(p, "control: claim as an analyst", ok1.status, 200);
      eq(p, "control: the claim moved the finding", ok1.json?.data?.status, "in_review");
      const ok2 = await w.api.post("analyst", `/findings/${f.id}/comments`, {
        body: "Looking at this today.",
      });
      eq(p, "control: comment as an analyst", ok2.status, 201);
      eq(
        p,
        "control: a tenant-B lead claims a finding of its OWN tenant",
        (await w.api.get("leadB", `/findings/${f.id}`)).status,
        404,
      );
      return p;
    },
  },

  {
    id: "FND-S02b",
    name: "The Reviews queue and the Approvals queue: 404 for a hidden, foreign or unknown workspace, 403 without `security_review.view` or `approval.view`, only the requested workspace's findings, canDecide per caller, keyset and numbered pages agree, a cursor under another filter or workspace and a tampered cursor are INVALID_CURSOR",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      // a pipeline of its own, so the queues of a world shared with other checks can be read through one filter
      const qp = await c.pipeline(w.A, 0);
      const F = `&pipelineId=${qp.id}`;
      const pend = [];
      for (let i = 0; i < 3; i += 1) pend.push(await w.pending("analyst", "true_positive", {}, qp));
      const byHybrid = await w.pending("hybrid", "true_positive", {}, qp);
      const newOne = await w.fnd({}, qp);
      const exF = await w.fnd({}, qp);
      const exReq = await w.requestException("analyst", exF, "suppress");
      eq(p, "control: an exception request is accepted", exReq.status, 201);
      // a finding of the OTHER workspace of the tenant, pending in its own queue
      const otherF = await w.fnd({}, w.pipeline2);
      const otherRec = await w.api.post("ws2only", `/findings/${otherF.id}/reviews`, {
        decision: "false_positive",
        rationale: RATIONALE,
        expectedRev: 0,
      });
      eq(p, "control: a review in the other workspace", otherRec.status, 201);

      // ---- the Reviews queue
      const rq = (who, ws, qs = "") => w.api.get(who, `/review-queue?workspaceId=${ws}${qs}`);
      const q = await rq("analyst", w.wsA, F);
      eq(p, "review queue as an analyst", q.status, 200);
      const qIds = (q.json?.data ?? []).map((i) => i.id);
      ok(p, qIds.includes(newOne.id), "the review queue lists a new finding");
      ok(
        p,
        !qIds.includes(pend[0].f.id),
        "the review queue does not list a finding awaiting approval",
      );
      ok(p, !qIds.includes(otherF.id), "the review queue never lists another workspace's finding");
      ok(
        p,
        (q.json?.data ?? []).every((i) => ["new", "in_review"].includes(i.status)),
        "only new and in-review findings",
      );
      eq(
        p,
        "review queue as Admin (holds security_review.view)",
        (await rq("admin", w.wsA)).status,
        200,
      );
      eq(p, "review queue without the key", (await rq("viewer", w.wsA)).status, 403);
      for (const [who, ws, label] of [
        ["ws2only", w.wsA, "a hidden workspace"],
        ["leadB", w.wsA, "another tenant's workspace"],
        ["analyst", UNKNOWN, "an unknown workspace"],
      ])
        eq(p, `review queue on ${label}`, (await rq(who, ws)).status, 404);
      eq(
        p,
        "review queue with a forged key",
        (await w.api.get("analyst", `/review-queue?workspaceId=${w.wsA}&tenantId=${w.B.tenant.id}`))
          .status,
        400,
      );

      // ---- the Approvals queue
      const aq = (who, qs = "", ws = w.wsA) => w.api.get(who, `/approvals?workspaceId=${ws}${qs}`);
      const lead = await aq("lead", F);
      eq(p, "approvals as a lead", lead.status, 200);
      const leadItems = new Map((lead.json?.data ?? []).map((i) => [i.requestId, i]));
      for (const x of pend) {
        const item = leadItems.get(x.reviewId);
        ok(
          p,
          item && item.kind === "review" && item.finding.id === x.f.id,
          "a pending review is in the queue",
        );
        eq(
          p,
          "canDecide for a lead who did not review",
          [item?.canDecide, item?.cannotDecideReason],
          [true, null],
        );
      }
      const ex = leadItems.get(exReq.json?.data?.exception?.id);
      eq(
        p,
        "the exception request is in the queue",
        [ex?.kind, ex?.exceptionKind],
        ["exception", "suppress"],
      );
      ok(
        p,
        !leadItems.has(otherRec.json?.data?.review?.current?.id),
        "the other workspace's pending decision is not in this queue",
      );
      ok(
        p,
        !(lead.json?.data ?? []).some((i) => i.finding.id === otherF.id),
        "no finding of another workspace",
      );
      const hy = new Map(((await aq("hybrid", F)).json?.data ?? []).map((i) => [i.requestId, i]));
      eq(
        p,
        "canDecide for the user who recorded the review (holds both keys)",
        [hy.get(byHybrid.reviewId)?.canDecide, hy.get(byHybrid.reviewId)?.cannotDecideReason],
        [false, "separation_of_duties"],
      );
      eq(
        p,
        "canDecide for the same user on someone else's review",
        [hy.get(pend[0].reviewId)?.canDecide, hy.get(pend[0].reviewId)?.cannotDecideReason],
        [true, null],
      );
      const ad = new Map(((await aq("admin", F)).json?.data ?? []).map((i) => [i.requestId, i]));
      eq(
        p,
        "canDecide for Admin (no approval key)",
        [ad.get(pend[0].reviewId)?.canDecide, ad.get(pend[0].reviewId)?.cannotDecideReason],
        [false, "missing_permission"],
      );
      eq(p, "approvals without `approval.view`", (await aq("viewer")).status, 403);
      for (const [who, ws, label] of [
        ["ws2only", w.wsA, "a hidden workspace"],
        ["leadB", w.wsA, "another tenant's workspace"],
        ["lead", UNKNOWN, "an unknown workspace"],
      ])
        eq(p, `approvals on ${label}`, (await aq(who, "", ws)).status, 404);
      const other = await aq("ws2only", "", w.wsA2);
      ok(
        p,
        (other.json?.data ?? []).some((i) => i.finding.id === otherF.id),
        "control: the other workspace's own queue lists its finding",
      );
      const onlyEx = await aq("lead", `${F}&kind=exception`);
      ok(
        p,
        (onlyEx.json?.data ?? []).length > 0 &&
          (onlyEx.json?.data ?? []).every((i) => i.kind === "exception"),
        "the kind filter",
      );

      // ---- paging: keyset pages concatenate to the numbered page
      const numbered = await aq("lead", `${F}&page=1&pageSize=100`);
      eq(p, "numbered approvals", numbered.status, 200);
      const total = numbered.json?.meta?.pagination?.totalItems;
      eq(p, "numbered page has its total", (numbered.json?.data ?? []).length, total);
      const collected = [];
      let cursor = null;
      let first = null;
      for (let guard = 0; guard < 50; guard += 1) {
        const page = await aq(
          "lead",
          `${F}&limit=2${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
        );
        if (page.status !== 200) {
          p.push(`keyset page answered ${page.status}`);
          break;
        }
        first ??= page;
        collected.push(...page.json.data.map((i) => i.requestId));
        cursor = page.json.meta.pagination.nextCursor;
        if (!page.json.meta.pagination.hasMore) break;
      }
      eq(
        p,
        "keyset pages equal the numbered page",
        collected,
        (numbered.json?.data ?? []).map((i) => i.requestId),
      );
      const cur = first?.json?.meta?.pagination?.nextCursor;
      ok(p, typeof cur === "string", "the first keyset page has a next cursor");
      if (cur) {
        const bad = `${cur.slice(0, -2)}${cur.endsWith("A") ? "B" : "A"}x`;
        for (const [label, who, qs, ws] of [
          ["a tampered cursor", "lead", `${F}&limit=2&cursor=${encodeURIComponent(bad)}`, w.wsA],
          [
            "a cursor under another filter",
            "lead",
            `${F}&limit=2&kind=review&cursor=${encodeURIComponent(cur)}`,
            w.wsA,
          ],
          [
            "a cursor of another workspace",
            "ws2only",
            `&limit=2&cursor=${encodeURIComponent(cur)}`,
            w.wsA2,
          ],
        ]) {
          const r = await aq(who, qs, ws);
          eq(p, label, [r.status, codeOf(r)], [400, "INVALID_CURSOR"]);
        }
        eq(
          p,
          "page with cursor is refused",
          (await aq("lead", `&page=1&cursor=${encodeURIComponent(cur)}`)).status,
          400,
        );
      }
      return p;
    },
  },

  {
    id: "FND-S07a",
    name: "Segregation of duties over HTTP (reviews): the user who recorded a review cannot approve or reject it (403 separation_of_duties, audited with both user ids and the decision id, nothing changes), also when they hold both keys, also for an EARLIER rejected round; a second eligible user succeeds; only the reviewer withdraws; Admin has no bypass",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      // 1. a user holding review AND approval (a custom role) approves or rejects their own decision
      const own = await w.pending("hybrid");
      const before = await w.row(own.f);
      const self = await w.approve("hybrid", own.f, own.reviewId);
      eq(
        p,
        "self-approval",
        [self.status, codeOf(self), reasonOf(self)],
        [403, "FORBIDDEN", "separation_of_duties"],
      );
      const selfReject = await w.reject("hybrid", own.f, own.reviewId);
      eq(
        p,
        "self-rejection",
        [selfReject.status, reasonOf(selfReject)],
        [403, "separation_of_duties"],
      );
      const after = await w.row(own.f);
      eq(
        p,
        "nothing changed",
        [after.status, after.rev, after.pendingReviewId],
        [before.status, before.rev, before.pendingReviewId],
      );
      eq(
        p,
        "no approval row was written",
        await w.db.findingApproval.count({
          where: { tenantId: own.f.tenantId, findingId: own.f.id },
        }),
        0,
      );
      const denied = (await w.audit(own.f)).filter((a) => a.action === "finding.approval_denied");
      eq(p, "both refusals are audited", denied.length, 2);
      for (const a of denied)
        eq(
          p,
          "the audit entry names both user ids and the decision id",
          [
            a.actorUserId,
            a.metadata?.approverUserId,
            a.metadata?.counterpartUserId,
            a.metadata?.decisionId,
            a.metadata?.reason,
            a.metadata?.kind,
          ],
          [
            w.users.hybrid,
            w.users.hybrid,
            w.users.hybrid,
            own.reviewId,
            "separation_of_duties",
            "review",
          ],
        );
      // control: another lead approves the same decision
      const good = await w.approve("lead", own.f, own.reviewId);
      eq(
        p,
        "control: another lead approves",
        [good.status, good.json?.data?.status],
        [200, "approved"],
      );
      eq(
        p,
        "control: the approval row is the lead's",
        (
          await w.db.findingApproval.findMany({
            where: { tenantId: own.f.tenantId, findingId: own.f.id },
          })
        ).map((a) => [a.approverUserId, a.decision]),
        [[w.users.lead, "approve"]],
      );
      const h = await w.history(own.f);
      const last = h.at(-1);
      eq(
        p,
        "history: the approval is a user action",
        [last.toStatus, last.actorType, last.actorUserId, last.reasonCode],
        ["approved", "user", w.users.lead, "approved_tp"],
      );

      // 2. an earlier reviewer of a REJECTED round is refused on the next round
      const R = await w.fnd();
      eq(p, "round 1 recorded", (await w.record("hybrid", R)).status, 201);
      const id1 = await w.reviewIdOf(R);
      eq(
        p,
        "round 1 rejected by a lead",
        (await w.reject("lead", R, id1)).json?.data?.status,
        "in_review",
      );
      eq(p, "round 2 recorded by another analyst", (await w.record("analyst2", R)).status, 201);
      const id2 = await w.reviewIdOf(R);
      const early = await w.approve("hybrid", R, id2);
      eq(
        p,
        "the earlier reviewer cannot approve round 2",
        [early.status, reasonOf(early)],
        [403, "separation_of_duties"],
      );
      const ctl = await w.approve("lead2", R, id2);
      eq(
        p,
        "control: a second lead approves round 2",
        [ctl.status, ctl.json?.data?.status],
        [200, "approved"],
      );

      // 3. only the reviewer withdraws
      const W = await w.pending("analyst");
      const rev = (await w.row(W.f)).rev;
      const wrong = await w.api.post(
        "analyst2",
        `/findings/${W.f.id}/reviews/${W.reviewId}/withdraw`,
        { expectedRev: rev },
      );
      eq(p, "withdraw by another reviewer", [wrong.status, reasonOf(wrong)], [403, "not_reviewer"]);
      const right = await w.api.post(
        "analyst",
        `/findings/${W.f.id}/reviews/${W.reviewId}/withdraw`,
        { expectedRev: rev },
      );
      eq(
        p,
        "control: withdraw by the reviewer",
        [right.status, right.json?.data?.status],
        [200, "in_review"],
      );
      const wr = await w.db.findingReview.findFirst({
        where: { tenantId: W.f.tenantId, id: W.reviewId },
      });
      eq(
        p,
        "the withdrawn review keeps its row and moves its state once",
        [wr?.state, wr?.decidedAt !== null],
        ["withdrawn", true],
      );
      eq(p, "the pending pointer is cleared", (await w.row(W.f)).pendingReviewId, null);
      eq(
        p,
        "the reviewer may record the next version",
        (await w.record("analyst", W.f)).status,
        201,
      );
      // approving a withdrawn review is a conflict, not a success
      const stale = await w.approve("lead", W.f, W.reviewId);
      ok(
        p,
        stale.status === 409 && codeOf(stale) === "FINDING_STATE_CONFLICT",
        `approving a withdrawn review answered ${stale.status}`,
      );
      return p;
    },
  },

  {
    id: "FND-S07b",
    name: "Segregation of duties for exceptions: the requester cannot approve or reject their own request, nor can any reviewer of the finding (403 separation_of_duties, audited, the request stays pending); a second eligible lead approves",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      // the requester holds both keys
      const f = await w.fnd();
      const req = await w.requestException("hybrid", f, "accept_risk");
      eq(p, "the request is accepted", [req.status, req.json?.data?.status], [201, "new"]);
      const exId = req.json?.data?.exception?.id;
      const base = `/findings/${f.id}/exceptions/${exId}`;
      const rev = async () => (await w.row(f)).rev;
      const a1 = await w.api.post("hybrid", `${base}/approve`, { expectedRev: await rev() });
      eq(p, "the requester approves", [a1.status, reasonOf(a1)], [403, "separation_of_duties"]);
      const a2 = await w.api.post("hybrid", `${base}/reject`, {
        comment: "I changed my mind.",
        expectedRev: await rev(),
      });
      eq(p, "the requester rejects", [a2.status, reasonOf(a2)], [403, "separation_of_duties"]);
      eq(
        p,
        "the request stays pending",
        [(await w.row(f)).status, (await w.row(f)).pendingExceptionId === exId],
        ["new", true],
      );
      const denied = (await w.audit(f)).filter((a) => a.action === "finding.approval_denied");
      eq(p, "both refusals are audited", denied.length, 2);
      eq(
        p,
        "the audit names both ids and the decision",
        [
          denied[0]?.metadata?.approverUserId,
          denied[0]?.metadata?.counterpartUserId,
          denied[0]?.metadata?.decisionId,
          denied[0]?.metadata?.kind,
        ],
        [w.users.hybrid, w.users.hybrid, exId, "exception"],
      );
      eq(
        p,
        "no approval row",
        await w.db.findingApproval.count({ where: { tenantId: f.tenantId, findingId: f.id } }),
        0,
      );
      const ok1 = await w.api.post("lead", `${base}/approve`, { expectedRev: await rev() });
      eq(
        p,
        "control: another lead approves",
        [ok1.status, ok1.json?.data?.status],
        [200, "accepted_risk"],
      );

      // a reviewer of the finding (an earlier round, withdrawn) cannot approve someone else's exception
      const g = await w.fnd();
      eq(p, "the reviewer records", (await w.record("hybrid", g)).status, 201);
      const rid = await w.reviewIdOf(g);
      eq(
        p,
        "and withdraws",
        (
          await w.api.post("hybrid", `/findings/${g.id}/reviews/${rid}/withdraw`, {
            expectedRev: (await w.row(g)).rev,
          })
        ).status,
        200,
      );
      const gReq = await w.requestException("analyst2", g, "suppress");
      eq(p, "another user requests a suppression", gReq.status, 201);
      const gId = gReq.json?.data?.exception?.id;
      const early = await w.api.post("hybrid", `/findings/${g.id}/exceptions/${gId}/approve`, {
        expectedRev: (await w.row(g)).rev,
      });
      eq(
        p,
        "the reviewer of the finding cannot approve the exception",
        [early.status, reasonOf(early)],
        [403, "separation_of_duties"],
      );
      const fine = await w.api.post("lead2", `/findings/${g.id}/exceptions/${gId}/approve`, {
        expectedRev: (await w.row(g)).rev,
      });
      eq(
        p,
        "control: a second lead approves",
        [fine.status, fine.json?.data?.status],
        [200, "suppressed"],
      );
      return p;
    },
  },

  {
    id: "FNDDB-05",
    name: "The database refuses the segregation-of-duties violation too: a direct insert of an approval by a reviewer (any round) or by the requester of an exception on the same finding fails; the same insert by another user succeeds",
    async run(c) {
      const p = [];
      const rejected = async (fn) => {
        try {
          await fn();
          return null;
        } catch (error) {
          return String(error?.message ?? error);
        }
      };
      const f = await c.finding(await c.pipeline(c.A, 0));
      const reviewer = randomUUID();
      const other = randomUUID();
      const r1 = await c.review(f, { reviewerUserId: reviewer });
      const bad = await rejected(() =>
        c.approval(f, { reviewId: r1.id, approverUserId: reviewer }),
      );
      ok(
        p,
        bad !== null && /separation_of_duties/.test(bad),
        `an approval by the reviewer must be refused (${bad ?? "accepted"})`,
      );
      ok(
        p,
        (await rejected(() =>
          c.approval(f, { reviewId: r1.id, approverUserId: other, decision: "approve" }),
        )) === null,
        "control: an approval by another user must succeed",
      );
      // ANY round: the first reviewer's round was rejected; they are still refused on the next round
      const f2 = await c.finding(await c.pipeline(c.A, 0));
      const round1 = await c.review(f2, {
        reviewerUserId: reviewer,
        state: "rejected",
        decidedAt: new Date(),
      });
      void round1;
      const round2 = await c.review(f2, { reviewerUserId: other });
      const early = await rejected(() =>
        c.approval(f2, { reviewId: round2.id, approverUserId: reviewer }),
      );
      ok(
        p,
        early !== null && /separation_of_duties/.test(early),
        "an earlier-round reviewer must be refused on the next round",
      );
      // the requester of an exception
      const f3 = await c.finding(await c.pipeline(c.A, 0));
      const requester = randomUUID();
      const ex = await c.exception(f3, { requestedByUserId: requester });
      const badEx = await rejected(() =>
        c.approval(f3, { reviewId: undefined, exceptionId: ex.id, approverUserId: requester }),
      );
      ok(
        p,
        badEx !== null && /separation_of_duties/.test(badEx),
        `an approval by the requester must be refused (${badEx ?? "accepted"})`,
      );
      ok(
        p,
        (await rejected(() =>
          c.approval(f3, { reviewId: undefined, exceptionId: ex.id, approverUserId: other }),
        )) === null,
        "control: an approval of the exception by another user must succeed",
      );
      // the same user is refused on a DIFFERENT review of the same finding, but not on another finding
      const f4 = await c.finding(await c.pipeline(c.A, 0));
      const r4 = await c.review(f4, { reviewerUserId: other });
      ok(
        p,
        (await rejected(() => c.approval(f4, { reviewId: r4.id, approverUserId: reviewer }))) ===
          null,
        "control: a user who reviewed ANOTHER finding may approve this one",
      );
      return p;
    },
  },

  {
    id: "FND-S07c",
    name: "The SERVER computes `lifecycle.allowedActions` and `canDecide` for each caller (omitted when the caller can never do it, `allowed: false` with a `disabledReason` in words when they may reasonably ask): permission, state machine, segregation of duties, take-over, pending requests; the computation agrees with what the write routes then enforce",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const ids = (d) => d.lifecycle.allowedActions.map((a) => a.action).sort();
      const sane = (label, d) => {
        for (const a of d.lifecycle.allowedActions) {
          ok(
            p,
            Object.keys(FINDING_ACTIONS).includes(a.action),
            `${label}: unknown action ${a.action}`,
          );
          if (a.allowed)
            ok(
              p,
              !("disabledReason" in a),
              `${label}: ${a.action} is allowed but carries a reason`,
            );
          else
            ok(
              p,
              typeof a.disabledReason === "string" &&
                a.disabledReason.length > 3 &&
                a.disabledReason.length <= 200,
              `${label}: ${a.action} is disabled without words`,
            );
        }
      };
      const seen = async (who, f, label) => {
        const d = await w.det(who, f);
        sane(`${label} as ${who}`, d);
        return d;
      };

      // ---- a new finding
      const fresh = await w.fnd();
      for (const [who, want] of [
        [
          "analyst",
          [
            "claim",
            "comment",
            "record_review",
            "request_accept_risk",
            "request_advisory",
            "request_suppression",
          ],
        ],
        ["lead", ["comment", "request_accept_risk", "request_suppression"]],
        [
          "admin",
          [
            "claim",
            "comment",
            "record_review",
            "request_accept_risk",
            "request_advisory",
            "request_suppression",
          ],
        ],
        ["viewer", []],
        ["developer", ["comment"]],
      ]) {
        const d = await seen(who, fresh, "new");
        eq(p, `new finding, actions of ${who}`, ids(d), want);
        ok(
          p,
          d.lifecycle.allowedActions.every((a) => a.allowed),
          `new finding: everything listed for ${who} is allowed`,
        );
      }

      // ---- awaiting approval: a user who holds both keys and recorded the decision, a lead, an analyst, Admin
      const own = await w.pending("hybrid");
      const forHybrid = await seen("hybrid", own.f, "awaiting");
      eq(p, "the reviewer may withdraw", actionOf(forHybrid, "withdraw_review"), {
        action: "withdraw_review",
        allowed: true,
      });
      for (const a of ["approve_review", "reject_review"])
        eq(p, `the reviewer's ${a} is disabled in words`, actionOf(forHybrid, a), {
          action: a,
          allowed: false,
          disabledReason: SOD_WORDS,
        });
      const forLead = await seen("lead", own.f, "awaiting");
      for (const a of ["approve_review", "reject_review"])
        eq(p, `a lead's ${a}`, actionOf(forLead, a), { action: a, allowed: true });
      ok(p, !actionOf(forLead, "withdraw_review"), "a lead never sees withdraw");
      const forAnalyst = await seen("analyst", own.f, "awaiting");
      ok(
        p,
        !actionOf(forAnalyst, "approve_review") &&
          !actionOf(forAnalyst, "reject_review") &&
          !actionOf(forAnalyst, "withdraw_review"),
        "an analyst who is not the reviewer sees neither approve, reject nor withdraw",
      );
      const forAdmin = await seen("admin", own.f, "awaiting");
      ok(
        p,
        !actionOf(forAdmin, "approve_review") && !actionOf(forAdmin, "reject_review"),
        "Admin sees no approve or reject (no key by default)",
      );
      eq(p, "a viewer sees nothing to do", ids(await seen("viewer", own.f, "awaiting")), []);
      // the computation agrees with the enforcement
      const refused = await w.approve("hybrid", own.f, own.reviewId);
      eq(p, "enforcement: the disabled action is refused", refused.status, 403);
      const done = await w.approve("lead", own.f, own.reviewId);
      eq(
        p,
        "enforcement: the allowed action succeeds",
        [done.status, done.json?.data?.status],
        [200, "approved"],
      );
      eq(
        p,
        "the response is the finding AS THE CALLER now sees it",
        [done.json?.data?.id, done.headers.get("etag")],
        [own.f.id, findingEtag(done.json?.data)],
      );

      ok(
        p,
        done.headers.get("etag")?.startsWith(`W/"finding-${(await w.row(own.f)).rev}-`),
        "the ETag carries the stored revision",
      );

      // ---- a false positive and a reopened finding go back to review
      const fp = await w.pending("analyst", "false_positive");
      await w.approve("lead", fp.f, fp.reviewId);
      eq(
        p,
        "false positive: an analyst may reopen it for review",
        ids(await seen("analyst", fp.f, "fp")).includes("reopen_review"),
        true,
      );

      // ---- take-over of a claim
      const claimed = await w.fnd();
      await w.api.post("analyst", `/findings/${claimed.id}/claim`, { expectedRev: 0 });
      ok(
        p,
        !actionOf(await seen("analyst", claimed, "claimed"), "claim"),
        "the claimant does not see claim",
      );
      eq(
        p,
        "another reviewer may take the claim over",
        actionOf(await seen("analyst2", claimed, "claimed"), "claim"),
        { action: "claim", allowed: true },
      );

      // ---- a pending exception: requester, lead, a reviewer of the finding
      const ex = await w.fnd();
      await w.api.post("hybrid", `/findings/${ex.id}/claim`, { expectedRev: 0 });
      const exReq = await w.requestException("analyst", ex, "accept_risk");
      eq(p, "a request is accepted", exReq.status, 201);
      const reqSees = await seen("analyst", ex, "pending exception");
      eq(p, "the requester may withdraw", actionOf(reqSees, "withdraw_exception"), {
        action: "withdraw_exception",
        allowed: true,
      });
      eq(
        p,
        "a second request is disabled in words",
        actionOf(reqSees, "request_accept_risk")?.disabledReason,
        "A request is already pending for this finding.",
      );
      eq(
        p,
        "so is a decision while a request is pending",
        actionOf(reqSees, "record_review")?.allowed,
        false,
      );
      ok(
        p,
        !actionOf(reqSees, "approve_exception"),
        "the requester (no approval key) does not see approve",
      );
      const leadSees = await seen("lead", ex, "pending exception");
      eq(
        p,
        "a lead may approve",
        [actionOf(leadSees, "approve_exception"), actionOf(leadSees, "reject_exception")],
        [
          { action: "approve_exception", allowed: true },
          { action: "reject_exception", allowed: true },
        ],
      );
      // hybrid claimed (not a reviewer record) so is NOT blocked; now make hybrid a reviewer of another finding's exception
      const ex2 = await w.fnd();
      const ex2Req = await w.requestException("hybrid", ex2, "suppress");
      eq(p, "hybrid requests a suppression", ex2Req.status, 201);
      const own2 = await seen("hybrid", ex2, "own exception");
      eq(
        p,
        "the requester's own approve is disabled in words",
        actionOf(own2, "approve_exception"),
        {
          action: "approve_exception",
          allowed: false,
          disabledReason: "You requested this. Another lead must approve it.",
        },
      );
      eq(p, "the requester may withdraw", actionOf(own2, "withdraw_exception")?.allowed, true);

      // ---- accepted risk and suppression: revoke
      const acc = await w.accepted("accept_risk");
      eq(
        p,
        "accepted risk: an analyst may revoke",
        actionOf(await seen("analyst", acc.f, "accepted"), "revoke_accept_risk"),
        { action: "revoke_accept_risk", allowed: true },
      );
      ok(
        p,
        !actionOf(await seen("lead", acc.f, "accepted"), "revoke_suppression"),
        "no revoke-suppression on an accepted risk",
      );
      const sup = await w.accepted("suppress");
      eq(
        p,
        "suppressed: an analyst may revoke",
        actionOf(await seen("analyst", sup.f, "suppressed"), "revoke_suppression"),
        { action: "revoke_suppression", allowed: true },
      );
      ok(
        p,
        !actionOf(await seen("accepter", sup.f, "suppressed"), "revoke_suppression"),
        "a caller without `finding.suppress` does not see revoke-suppression",
      );

      // ---- the Approvals queue says the same as the DTO
      const queue = new Map(
        ((await w.api.get("hybrid", `/approvals?workspaceId=${w.wsA}`)).json?.data ?? []).map(
          (i) => [i.requestId, i],
        ),
      );
      const item = queue.get(ex2Req.json?.data?.exception?.id);
      eq(
        p,
        "the queue agrees: the requester cannot decide",
        [item?.canDecide, item?.cannotDecideReason],
        [false, "separation_of_duties"],
      );
      return p;
    },
  },

  {
    id: "FND-S08a",
    name: "Allowed transitions only and optimistic concurrency: a stale `expectedRev`, a disallowed source status, a pending exception and an already decided request are 409 FINDING_STATE_CONFLICT with the reason and change nothing; every transition writes exactly one `finding.status_changed` row; two concurrent approvals give exactly one success",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const conflict = (label, r, reason) =>
        eq(p, label, [r.status, codeOf(r), reasonOf(r)], [409, "FINDING_STATE_CONFLICT", reason]);
      const f = await w.fnd();
      const claim = (rev) => w.api.post("analyst", `/findings/${f.id}/claim`, { expectedRev: rev });
      conflict("a stale revision", await claim(7), "stale_revision");
      eq(p, "the stale write changed nothing", (await w.row(f)).rev, 0);
      const first = await claim(0);
      eq(
        p,
        "control: claim at the right revision",
        [first.status, first.json?.data?.status, first.json?.data?.rev],
        [200, "in_review", 1],
      );
      conflict("claiming your own claim again", await claim(1), "transition_not_allowed");
      conflict(
        "reopen-review of an in-review finding",
        await w.api.post("analyst", `/findings/${f.id}/reopen-review`, {
          reason: "Looks wrong to me.",
          expectedRev: 1,
        }),
        "transition_not_allowed",
      );
      eq(p, "record a decision", (await w.record("analyst", f)).status, 201);
      const rid = await w.reviewIdOf(f);
      conflict(
        "claim while awaiting approval",
        await claim((await w.row(f)).rev),
        "transition_not_allowed",
      );
      conflict(
        "a second decision while awaiting approval",
        await w.record("analyst", f),
        "transition_not_allowed",
      );
      conflict(
        "an exception request while awaiting approval",
        await w.requestException("analyst", f, "suppress"),
        "transition_not_allowed",
      );
      const approved = await w.approve("lead", f, rid);
      eq(p, "approve", [approved.status, approved.json?.data?.status], [200, "approved"]);
      conflict(
        "approving an approved decision again",
        await w.approve("lead2", f, rid),
        "already_decided",
      );
      conflict(
        "a decision on an approved finding",
        await w.record("analyst", f),
        "transition_not_allowed",
      );
      conflict(
        "withdrawing a decided review",
        await w.api.post("analyst", `/findings/${f.id}/reviews/${rid}/withdraw`, {
          expectedRev: (await w.row(f)).rev,
        }),
        "already_decided",
      );
      // a pending exception blocks a decision; a second request is refused
      const g = await w.fnd();
      eq(
        p,
        "request on a new finding",
        (await w.requestException("analyst", g, "suppress")).status,
        201,
      );
      conflict(
        "a second request while one is pending",
        await w.requestException("analyst2", g, "accept_risk"),
        "exception_pending",
      );
      conflict(
        "a review while a request is pending",
        await w.record("analyst", g),
        "exception_pending",
      );
      // exactly one status_changed row per transition (and none for a refused write)
      const h = await w.history(f);
      const hints = (await w.outbox(f)).filter((r) => r.type === "finding.status_changed");
      eq(
        p,
        "status_changed rows equal the transitions",
        hints.map((r) => r.payload.payload.rev).sort(),
        h.filter((x) => x.rev > 0).map((x) => x.rev),
      );
      ok(
        p,
        hints.every((r) => r.queue === "realtime" && r.payload.payload.actorType === "user"),
        "every hint is a realtime user hint",
      );
      // two concurrent approvals: exactly one wins, the loser is a 409 and is audited
      const race = await w.pending("analyst");
      const [r1, r2] = await Promise.all([
        w.approve("lead", race.f, race.reviewId),
        w.approve("lead2", race.f, race.reviewId),
      ]);
      const codes = [r1.status, r2.status].sort();
      eq(p, "two concurrent approvals", codes, [200, 409]);
      const loser = r1.status === 409 ? r1 : r2;
      eq(p, "the loser is a state conflict", codeOf(loser), "FINDING_STATE_CONFLICT");
      eq(
        p,
        "one approval row",
        await w.db.findingApproval.count({
          where: { tenantId: race.f.tenantId, findingId: race.f.id },
        }),
        1,
      );
      const log = await w.audit(race.f);
      eq(
        p,
        "both attempts are audited (the decision and the refusal)",
        [
          log.filter((a) => a.action === "finding.approval_decided").length,
          log.filter((a) => a.action === "finding.approval_denied").length,
        ],
        [1, 1],
      );
      return p;
    },
  },

  {
    id: "FND-S08b",
    name: "The review lifecycle is recorded completely: history rows for every transition (the actor is the user), the audit entry of each action, the events without any text, the severity override applied on approval with the SLA recomputed, a rejection or a false-positive decision stops the clock, a forced failure leaves nothing behind",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const now = Date.now();
      const sla = (o = {}) => ({
        toolSeverity: "medium",
        severity: "medium",
        severityRank: 2,
        slaStartedAt: new Date(now - DAY),
        slaDueAt: new Date(now - DAY + 2160 * 3_600_000),
        ...o,
      });
      // A. a true positive with a severity override, from `new` (two history rows), approved
      const f = await w.fnd(sla());
      const rec = await w.record("analyst", f, "true_positive", { severityOverride: "critical" });
      eq(p, "record from new", [rec.status, rec.json?.data?.status], [201, "awaiting_approval"]);
      eq(
        p,
        "the override is NOT applied before the approval",
        [(await w.row(f)).severity, rec.json?.data?.severityOverridden],
        ["medium", false],
      );
      const rid = await w.reviewIdOf(f);
      const comment = "Confirmed after reading the rationale and the call path.";
      const ap = await w.approve("lead", f, rid, { comment });
      eq(
        p,
        "approve",
        [
          ap.status,
          ap.json?.data?.status,
          ap.json?.data?.severity,
          ap.json?.data?.severityOverridden,
        ],
        [200, "approved", "critical", true],
      );
      const after = await w.row(f);
      eq(
        p,
        "the SLA follows the effective severity (critical, 168 hours from first detection)",
        after.slaDueAt?.getTime(),
        after.slaStartedAt.getTime() + 168 * 3_600_000,
      );
      eq(
        p,
        "the override is stored with the tool severity kept",
        [after.toolSeverity, after.severityOverride, after.severity, after.severityRank],
        ["medium", "critical", "critical", 4],
      );
      const hist = await w.history(f);
      eq(
        p,
        "history: detected, review started, review recorded, approved",
        hist.map((x) => [x.rev, x.fromStatus, x.toStatus, x.actorType, x.reasonCode]),
        [
          [0, null, "new", "system", "detected"],
          [1, "new", "in_review", "user", "review_started"],
          [2, "in_review", "awaiting_approval", "user", "review_recorded"],
          [3, "awaiting_approval", "approved", "user", "approved_tp"],
        ],
      );
      eq(
        p,
        "history actors",
        hist.slice(1).map((x) => x.actorUserId),
        [w.users.analyst, w.users.analyst, w.users.lead],
      );
      eq(
        p,
        "the notes are the plain texts the users wrote",
        [hist[2].note, hist[3].note],
        [RATIONALE, comment],
      );
      const log = await w.audit(f);
      eq(
        p,
        "audit: one entry per action, by the user",
        log.map((a) => [a.action, a.actorUserId]),
        [
          ["finding.review_started", w.users.analyst],
          ["finding.review_recorded", w.users.analyst],
          ["finding.approval_decided", w.users.lead],
          ["finding.severity_overridden", w.users.lead],
        ],
      );
      ok(
        p,
        !j(log.map((a) => a.metadata)).includes(RATIONALE) &&
          !j(log.map((a) => a.metadata)).includes(comment),
        "no rationale or comment text in an audit entry",
      );
      const events = await w.outbox(f);
      eq(p, "events written", [...new Set(events.map((e) => e.type))].sort(), [
        "finding.approval_decided",
        "finding.review_recorded",
        "finding.status_changed",
      ]);
      ok(
        p,
        !j(events.map((e) => e.payload)).includes(RATIONALE) &&
          !j(events.map((e) => e.payload)).includes(comment),
        "no text in any event payload",
      );
      const review = await w.db.findingReview.findFirst({
        where: { tenantId: f.tenantId, id: rid },
      });
      eq(
        p,
        "the review row",
        [
          review.state,
          review.decision,
          review.severityOverride,
          review.reviewerUserId,
          review.decidedAt !== null,
          review.advisoryIdAtDecision,
        ],
        ["approved", "true_positive", "critical", w.users.analyst, true, null],
      );
      const tl = await w.api.get("lead", `/findings/${f.id}/history`);
      ok(
        p,
        ["review", "approval", "status"].every((t) =>
          (tl.json?.data ?? []).some((e) => e.type === t),
        ),
        "the timeline merges reviews, approvals and status changes",
      );

      // B. a false positive stops the clock; an override is refused with it
      const g = await w.fnd(sla());
      const bad = await w.record("analyst", g, "false_positive", { severityOverride: "low" });
      eq(
        p,
        "an override with a false positive",
        [bad.status, bad.json?.error?.details?.issues?.[0]?.reason ?? reasonOf(bad)],
        [400, "override_requires_tp"],
      );
      eq(
        p,
        "record the false positive",
        (await w.record("analyst", g, "false_positive")).status,
        201,
      );
      const fpOk = await w.approve("lead", g, await w.reviewIdOf(g));
      eq(
        p,
        "approve a false positive",
        [fpOk.status, fpOk.json?.data?.status],
        [200, "false_positive"],
      );
      eq(
        p,
        "the SLA is stopped",
        [(await w.row(g)).slaDueAt, fpOk.json?.data?.sla?.state],
        [null, "not_applicable"],
      );

      // C. a rejection needs a comment, returns the finding to review and applies nothing
      const r = await w.pending("analyst", "true_positive", sla());
      const noComment = await w.api.post(
        "lead",
        `/findings/${r.f.id}/reviews/${r.reviewId}/reject`,
        { expectedRev: (await w.row(r.f)).rev },
      );
      eq(p, "a rejection without a comment", noComment.status, 400);
      const rej = await w.reject("lead", r.f, r.reviewId);
      eq(
        p,
        "reject",
        [rej.status, rej.json?.data?.status, rej.json?.data?.review?.current],
        [200, "in_review", null],
      );
      const rejected = await w.db.findingReview.findFirst({
        where: { tenantId: r.f.tenantId, id: r.reviewId },
      });
      eq(
        p,
        "the rejected review keeps its row",
        [rejected.state, (await w.row(r.f)).pendingReviewId],
        ["rejected", null],
      );
      eq(
        p,
        "the rejection is recorded with its comment",
        (
          await w.db.findingApproval.findMany({
            where: { tenantId: r.f.tenantId, findingId: r.f.id },
          })
        ).map((a) => [a.decision, a.approverUserId, a.comment !== null]),
        [["reject", w.users.lead, true]],
      );

      // D. reopening a false positive for review needs a reason and is a user transition
      const noReason = await w.api.post("analyst", `/findings/${g.id}/reopen-review`, {
        expectedRev: (await w.row(g)).rev,
      });
      eq(p, "reopen-review without a reason", noReason.status, 400);
      const back = await w.api.post("analyst", `/findings/${g.id}/reopen-review`, {
        reason: "New evidence from the incident review.",
        expectedRev: (await w.row(g)).rev,
      });
      eq(p, "reopen-review", [back.status, back.json?.data?.status], [200, "in_review"]);
      const hg = (await w.history(g)).at(-1);
      eq(
        p,
        "history of the reopening",
        [hg.reasonCode, hg.actorType, hg.actorUserId, hg.note],
        ["fp_reopened", "user", w.users.analyst, "New evidence from the incident review."],
      );

      // E. a forced failure in the same transaction leaves nothing behind
      const t = await w.pending("analyst");
      const approvalsBefore = await w.db.findingApproval.count({
        where: { tenantId: t.f.tenantId },
      });
      await w.db.$executeRawUnsafe(
        `CREATE OR REPLACE FUNCTION fnd_b_force_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fnd_b_forced_failure'; END $$`,
      );
      await w.db.$executeRawUnsafe(
        `CREATE TRIGGER fnd_b_force_failure BEFORE INSERT ON outbox_messages FOR EACH ROW WHEN (NEW.type = 'finding.approval_decided') EXECUTE FUNCTION fnd_b_force_failure()`,
      );
      let forced;
      try {
        forced = await w.approve("lead", t.f, t.reviewId);
      } finally {
        await w.db.$executeRawUnsafe(
          "DROP TRIGGER IF EXISTS fnd_b_force_failure ON outbox_messages",
        );
        await w.db.$executeRawUnsafe("DROP FUNCTION IF EXISTS fnd_b_force_failure()");
      }
      eq(p, "the forced failure is a 500", forced.status, 500);
      const left = await w.row(t.f);
      eq(
        p,
        "nothing was applied",
        [left.status, left.rev, left.pendingReviewId],
        ["awaiting_approval", (await w.row(t.f)).rev, t.reviewId],
      );
      eq(
        p,
        "no approval row, the review is still pending",
        [
          await w.db.findingApproval.count({ where: { tenantId: t.f.tenantId } }),
          (
            await w.db.findingReview.findFirst({
              where: { tenantId: t.f.tenantId, id: t.reviewId },
            })
          ).state,
        ],
        [approvalsBefore, "pending"],
      );
      eq(
        p,
        "no history row of the approval",
        (await w.history(t.f)).some((x) => x.reasonCode === "approved_tp"),
        false,
      );
      const control = await w.approve("lead", t.f, t.reviewId);
      eq(
        p,
        "control: the same approval succeeds once the failure is gone",
        [control.status, control.json?.data?.status],
        [200, "approved"],
      );
      return p;
    },
  },

  {
    id: "FND-S09a",
    name: "Accepted risk and suppression: the expiry is required (at most 180 days; 365 for a suppression), a pending request changes nothing, a second request and a review are refused while it is pending, only the requester withdraws, a rejection needs a comment, approval accepts the risk (SLA stops), revoke needs the key of the exception's kind and reopens the finding",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const bad = async (label, name, f, kind, extra, reason) => {
        const r = await w.requestException(name, f, kind, extra);
        eq(p, label, [r.status, codeOf(r), reasonOf(r)], [400, "VALIDATION_FAILED", reason]);
      };
      const f = await w.fnd();
      await bad(
        "accept risk without an expiry",
        "analyst",
        f,
        "accept_risk",
        { expiresAt: undefined },
        "expiry_out_of_range",
      );
      await bad(
        "accept risk in the past",
        "analyst",
        f,
        "accept_risk",
        { expiresAt: inDays(-1) },
        "expiry_out_of_range",
      );
      await bad(
        "accept risk beyond 180 days",
        "analyst",
        f,
        "accept_risk",
        { expiresAt: inDays(181) },
        "expiry_out_of_range",
      );
      await bad(
        "suppression beyond 365 days",
        "analyst",
        f,
        "suppress",
        { expiresAt: inDays(366) },
        "expiry_out_of_range",
      );
      await bad(
        "suppression in the past",
        "analyst",
        f,
        "suppress",
        { expiresAt: inDays(-3) },
        "expiry_out_of_range",
      );
      await bad(
        "compensating controls on a suppression",
        "analyst",
        f,
        "suppress",
        { compensatingControls: "A WAF rule." },
        "expiry_out_of_range",
      );
      await bad(
        "the requester as the approver hint",
        "analyst",
        f,
        "accept_risk",
        { requestedApproverUserId: w.users.analyst },
        "approver_not_eligible",
      );
      await bad(
        "an approver hint without the approval key",
        "analyst",
        f,
        "accept_risk",
        { requestedApproverUserId: w.users.viewer },
        "approver_not_eligible",
      );
      await bad(
        "an approver hint that is not a member",
        "analyst",
        f,
        "accept_risk",
        { requestedApproverUserId: UNKNOWN },
        "approver_not_eligible",
      );
      eq(
        p,
        "nothing was written by the refusals",
        [
          (await w.row(f)).rev,
          await w.db.findingException.count({ where: { tenantId: f.tenantId, findingId: f.id } }),
        ],
        [0, 0],
      );
      const edge = await w.requestException("analyst", f, "accept_risk", {
        expiresAt: inDays(179),
        compensatingControls: "A WAF rule blocks the path.",
        requestedApproverUserId: w.users.lead,
      });
      eq(
        p,
        "control: 179 days, with controls and an eligible approver hint",
        [edge.status, edge.json?.data?.exception?.kind, edge.json?.data?.exception?.state],
        [201, "accept_risk", "pending"],
      );
      // a pending request changes nothing but the pointer and the revision
      const row = await w.row(f);
      eq(
        p,
        "the status is unchanged while pending",
        [row.status, row.rev, row.pendingExceptionId !== null, row.activeExceptionId],
        ["new", 1, true, null],
      );
      eq(
        p,
        "the DTO shows the pending decision",
        edge.json?.data?.pendingDecision?.kind,
        "exception",
      );
      const exId = edge.json.data.exception.id;
      const exRow = await w.db.findingException.findFirst({
        where: { tenantId: f.tenantId, id: exId },
      });
      eq(
        p,
        "the stored request",
        [
          exRow.state,
          exRow.acceptedSeverity,
          exRow.requestedByUserId,
          exRow.requestedApproverUserId,
        ],
        ["pending", row.severity, w.users.analyst, w.users.lead],
      );
      const second = await w.requestException("analyst2", f, "suppress");
      eq(
        p,
        "a second request while pending",
        [second.status, reasonOf(second)],
        [409, "exception_pending"],
      );
      const review = await w.record("analyst", f);
      eq(
        p,
        "a review while pending",
        [review.status, reasonOf(review)],
        [409, "exception_pending"],
      );
      // withdraw: only the requester
      const notMine = await w.api.post("lead", `/findings/${f.id}/exceptions/${exId}/withdraw`, {});
      eq(
        p,
        "withdraw by someone else",
        [notMine.status, reasonOf(notMine)],
        [403, "not_requester"],
      );
      const mine = await w.api.post("analyst", `/findings/${f.id}/exceptions/${exId}/withdraw`, {});
      eq(
        p,
        "withdraw by the requester",
        [mine.status, mine.json?.data?.pendingDecision],
        [200, null],
      );
      const withdrawn = await w.db.findingException.findFirst({
        where: { tenantId: f.tenantId, id: exId },
      });
      eq(
        p,
        "the withdrawn request keeps its row",
        [withdrawn.state, withdrawn.endedAt !== null, (await w.row(f)).pendingExceptionId],
        ["withdrawn", true, null],
      );
      // reject needs a comment and changes no state
      const again = await w.requestException("analyst", f, "accept_risk");
      eq(p, "a new request after the withdrawal", again.status, 201);
      const againId = again.json.data.exception.id;
      const noComment = await w.api.post("lead", `/findings/${f.id}/exceptions/${againId}/reject`, {
        expectedRev: (await w.row(f)).rev,
      });
      eq(p, "reject without a comment", noComment.status, 400);
      const rej = await w.api.post("lead", `/findings/${f.id}/exceptions/${againId}/reject`, {
        comment: "The gateway rule is not in place yet.",
        expectedRev: (await w.row(f)).rev,
      });
      eq(
        p,
        "reject",
        [rej.status, rej.json?.data?.status, rej.json?.data?.exception ?? null],
        [200, "new", null],
      );
      eq(
        p,
        "a rejection ends the request",
        [
          (await w.row(f)).pendingExceptionId,
          (await w.db.findingException.findFirst({ where: { tenantId: f.tenantId, id: againId } }))
            .state,
        ],
        [null, "rejected"],
      );
      // approve: the risk is accepted, the SLA stops, nothing can be edited
      const acc = await w.accepted("accept_risk");
      const ar = await w.row(acc.f);
      eq(
        p,
        "accepted risk",
        [ar.status, ar.activeExceptionId, ar.pendingExceptionId, ar.slaDueAt, ar.acceptedSeverity],
        ["accepted_risk", acc.exceptionId, null, null, ar.severity],
      );
      ok(
        p,
        ar.exceptionExpiresAt instanceof Date && ar.exceptionExpiresAt.getTime() > Date.now(),
        "the finding carries the expiry",
      );
      const dto = await w.det("lead", acc.f);
      eq(
        p,
        "the DTO: accepted, SLA not applicable",
        [dto.status, dto.sla.state, dto.exception?.state, dto.exception?.approvedBy?.id],
        ["accepted_risk", "not_applicable", "approved", w.users.lead],
      );
      const hist = (await w.history(acc.f)).at(-1);
      eq(
        p,
        "history",
        [hist.toStatus, hist.reasonCode, hist.actorType, hist.actorUserId],
        ["accepted_risk", "risk_accepted", "user", w.users.lead],
      );
      eq(
        p,
        "the approval of an approved request again",
        (
          await w.api.post("lead2", `/findings/${acc.f.id}/exceptions/${acc.exceptionId}/approve`, {
            expectedRev: ar.rev,
          })
        ).status,
        409,
      );
      // revoke: the key of the kind, a reason, then the finding is reopened
      const viewer = await w.api.post(
        "viewer",
        `/findings/${acc.f.id}/exceptions/${acc.exceptionId}/revoke`,
        { reason: "Controls changed.", expectedRev: ar.rev },
      );
      eq(
        p,
        "revoke without any key",
        [viewer.status, reasonOf(viewer)],
        [403, "missing_permission"],
      );
      const sup = await w.accepted("suppress");
      const wrongKey = await w.api.post(
        "accepter",
        `/findings/${sup.f.id}/exceptions/${sup.exceptionId}/revoke`,
        { reason: "Controls changed.", expectedRev: (await w.row(sup.f)).rev },
      );
      eq(
        p,
        "revoke a suppression with only the accept-risk key",
        [wrongKey.status, reasonOf(wrongKey)],
        [403, "missing_permission"],
      );
      const noReason = await w.api.post(
        "accepter",
        `/findings/${acc.f.id}/exceptions/${acc.exceptionId}/revoke`,
        { expectedRev: ar.rev },
      );
      eq(p, "revoke without a reason", noReason.status, 400);
      const rv = await w.api.post(
        "accepter",
        `/findings/${acc.f.id}/exceptions/${acc.exceptionId}/revoke`,
        { reason: "Controls changed.", expectedRev: ar.rev },
      );
      eq(
        p,
        "revoke",
        [rv.status, rv.json?.data?.status, rv.json?.data?.reopenCount],
        [200, "reopened", 1],
      );
      const after = await w.row(acc.f);
      eq(
        p,
        "after the revocation",
        [
          after.activeExceptionId,
          after.exceptionExpiresAt,
          after.acceptedSeverity,
          after.slaDueAt !== null,
        ],
        [null, null, null, true],
      );
      eq(
        p,
        "the exception row is revoked",
        (
          await w.db.findingException.findFirst({
            where: { tenantId: acc.f.tenantId, id: acc.exceptionId },
          })
        ).state,
        "revoked",
      );
      const rh = (await w.history(acc.f)).at(-1);
      eq(
        p,
        "history of the revocation",
        [rh.toStatus, rh.reasonCode, rh.actorType, rh.actorUserId],
        ["reopened", "revoked", "user", w.users.accepter],
      );
      eq(
        p,
        "revoking twice",
        (
          await w.api.post(
            "accepter",
            `/findings/${acc.f.id}/exceptions/${acc.exceptionId}/revoke`,
            { reason: "Again.", expectedRev: after.rev },
          )
        ).status,
        409,
      );
      // a suppression may have no expiry
      eq(
        p,
        "a suppression without an expiry",
        [(await w.row(sup.f)).status, (await w.row(sup.f)).exceptionExpiresAt],
        ["suppressed", null],
      );
      const log = await w.audit(acc.f);
      eq(
        p,
        "audit of the accepted risk: requested, decided, the refused second approval, revoked",
        log.map((a) => a.action),
        [
          "finding.exception_requested",
          "finding.exception_decided",
          "finding.approval_denied",
          "finding.exception_revoked",
        ],
      );
      return p;
    },
  },

  {
    id: "FND-S09b",
    name: "Expiry (EX-3): at its expiry the exception becomes `expired` and the finding is reopened by the system (history, audit, events, SLA restarted); the job is idempotent and tenant scoped; a suppression without an expiry never expires; an overdue acceptance reads as reopened BEFORE the job and the next write expires it first",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const acc = await w.accepted("accept_risk");
      const noExpiry = await w.accepted("suppress");
      // a second tenant's acceptance: the one job handles each tenant under its own scope
      const fB = await w.fnd({}, w.pipelineB);
      const rB = await w.api.post("leadB", `/findings/${fB.id}/exceptions`, {
        kind: "accept_risk",
        justification: JUSTIFICATION,
        expiresAt: inDays(30),
        expectedRev: 0,
      });
      eq(p, "tenant B requests", rB.status, 201);
      const aB = await w.api.post(
        "leadB2",
        `/findings/${fB.id}/exceptions/${rB.json?.data?.exception?.id}/approve`,
        { expectedRev: (await w.row(fB)).rev },
      );
      eq(p, "tenant B approves", [aB.status, aB.json?.data?.status], [200, "accepted_risk"]);
      const message = { type: "findings.exception.expire", payload: { bucket: 1 } };
      const log = { info() {}, error() {}, warn() {} };
      // not due yet: nothing happens
      await createExceptionExpiryHandler({ db: w.db })(message, { log });
      eq(
        p,
        "not due: still accepted",
        [(await w.row(acc.f)).status, (await w.row(fB)).status],
        ["accepted_risk", "accepted_risk"],
      );
      const revBefore = (await w.row(acc.f)).rev;
      // 31 days later (injected clock): both are due
      const later = () => new Date(Date.now() + 31 * DAY);
      await createExceptionExpiryHandler({ db: w.db, clock: later })(message, { log });
      for (const [label, f] of [
        ["tenant A", acc.f],
        ["tenant B", fB],
      ]) {
        const row = await w.row(f);
        eq(
          p,
          `${label}: reopened`,
          [
            row.status,
            row.reopenCount,
            row.activeExceptionId,
            row.exceptionExpiresAt,
            row.acceptedSeverity,
          ],
          ["reopened", 1, null, null, null],
        );
        ok(
          p,
          row.slaDueAt !== null && row.slaStartedAt.getTime() > Date.now() - 60_000,
          `${label}: the SLA restarted`,
        );
        const hist = (await w.history(f)).at(-1);
        eq(
          p,
          `${label}: history is a system action`,
          [hist.toStatus, hist.actorType, hist.actorUserId, hist.actorCode, hist.reasonCode],
          ["reopened", "system", null, "expiry", "risk_acceptance_expired"],
        );
        const audit = (await w.audit(f)).at(-1);
        eq(
          p,
          `${label}: audit`,
          [audit.action, audit.actorType, audit.actorUserId, audit.tenantId],
          ["finding.exception_expired", "system", null, f.tenantId],
        );
        eq(
          p,
          `${label}: events`,
          (await w.outbox(f))
            .map((e) => e.type)
            .filter((t) => ["finding.exception_expired", "finding.reopened"].includes(t))
            .sort(),
          ["finding.exception_expired", "finding.reopened"],
        );
      }
      eq(
        p,
        "the exception rows are expired",
        (
          await w.db.findingException.findFirst({
            where: { tenantId: acc.f.tenantId, id: acc.exceptionId },
          })
        ).state,
        "expired",
      );
      eq(
        p,
        "a suppression without an expiry never expires",
        (await w.row(noExpiry.f)).status,
        "suppressed",
      );
      // idempotent: a second run (and a second instance) changes nothing
      const revAfter = (await w.row(acc.f)).rev;
      const histCount = (await w.history(acc.f)).length;
      await createExceptionExpiryHandler({ db: w.db, clock: later })(message, { log });
      eq(
        p,
        "the second run is a no-op",
        [(await w.row(acc.f)).rev, (await w.history(acc.f)).length, revAfter > revBefore],
        [revAfter, histCount, true],
      );

      // the read path: an overdue acceptance reads as reopened BEFORE the job, and the next write expires it first
      const lazy = await w.accepted("accept_risk");
      const seenBefore = await w.det("analyst", lazy.f);
      eq(p, "control: accepted before the expiry", seenBefore.status, "accepted_risk");
      await w.db.$transaction(async (tx) => {
        await tx.$executeRaw`SELECT set_config('qm.finding_actor_type', 'user', true)`;
        await tx.$executeRaw`UPDATE findings SET exception_expires_at = now() - interval '1 hour', rev = rev + 1 WHERE tenant_id = ${lazy.f.tenantId}::uuid AND id = ${lazy.f.id}::uuid`;
      });
      const overdue = await w.det("analyst", lazy.f);
      eq(p, "an overdue acceptance is NEVER shown as accepted", overdue.status, "reopened");
      eq(
        p,
        "the DB row is not expired yet (the job has not run)",
        (await w.row(lazy.f)).status,
        "accepted_risk",
      );
      const listed = (status) =>
        w.api.get("analyst", `/findings?workspaceId=${w.wsA}&status=${status}&pageSize=100&page=1`);
      ok(
        p,
        !((await listed("accepted_risk")).json?.data ?? []).some((i) => i.id === lazy.f.id),
        "the accepted filter excludes it",
      );
      ok(
        p,
        ((await listed("reopened")).json?.data ?? []).some((i) => i.id === lazy.f.id),
        "the reopened filter includes it",
      );
      // the client's first write, at the revision it saw, works: the expiry happens inside it
      const write = await w.api.post("analyst", `/findings/${lazy.f.id}/reopen-review`, {
        reason: "The acceptance ran out; look again.",
        expectedRev: overdue.rev,
      });
      eq(
        p,
        "the first write after the expiry",
        [write.status, write.json?.data?.status],
        [200, "in_review"],
      );
      const hist = (await w.history(lazy.f))
        .map((x) => [x.toStatus, x.actorType, x.reasonCode])
        .slice(-2);
      eq(p, "the expiry was recorded before the user's transition", hist, [
        ["reopened", "system", "risk_acceptance_expired"],
        ["in_review", "user", "rereview"],
      ]);
      eq(
        p,
        "the exception row is expired",
        (
          await w.db.findingException.findFirst({
            where: { tenantId: lazy.f.tenantId, id: lazy.exceptionId },
          })
        ).state,
        "expired",
      );
      // an old acceptance cannot be revoked after it expired: it is already over
      const rv = await w.api.post(
        "analyst",
        `/findings/${lazy.f.id}/exceptions/${lazy.exceptionId}/revoke`,
        { reason: "Too late.", expectedRev: (await w.row(lazy.f)).rev },
      );
      eq(p, "revoke of an expired acceptance", rv.status, 409);
      return p;
    },
  },

  {
    id: "FND-S10a",
    name: "No secrets in what people write: a credential-shaped string in a rationale, comment, approval or rejection comment, justification, compensating controls, reopen reason or revoke reason is refused (400 VALIDATION_FAILED, reason credential_shape, never echoed, nothing stored), the narrow database list AND the wider platform list (Stripe, Slack, JWT, URL credentials); benign text is accepted and no row, event or audit entry holds a canary",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const R1 = await w.fnd();
      const R2 = await w.pending("analyst");
      const R3 = await w.pending("analyst", "false_positive");
      await w.approve("lead", R3.f, R3.reviewId);
      const R4 = await w.fnd();
      const req4 = await w.requestException("analyst", R4, "suppress");
      const ex4 = req4.json?.data?.exception?.id;
      const R5 = await w.accepted("accept_risk");
      const tenantId = R1.tenantId;
      const snapshot = async () =>
        j([
          await w.db.findingReview.count({ where: { tenantId } }),
          await w.db.findingComment.count({ where: { tenantId } }),
          await w.db.findingException.count({ where: { tenantId } }),
          await w.db.findingApproval.count({ where: { tenantId } }),
          await w.db.findingStatusHistory.count({ where: { tenantId } }),
          await w.db.auditLog.count({ where: { tenantId } }),
          await w.db.outboxMessage.count({ where: { tenantId } }),
        ]);
      const rev = async (f) => (await w.row(f)).rev;
      const cases = (secret) => [
        [
          "rationale",
          async () =>
            w.api.post("analyst", `/findings/${R1.id}/reviews`, {
              decision: "true_positive",
              rationale: `${RATIONALE} ${secret}`,
              expectedRev: await rev(R1),
            }),
        ],
        [
          "comment",
          async () =>
            w.api.post("analyst", `/findings/${R1.id}/comments`, { body: `look at ${secret}` }),
        ],
        [
          "justification",
          async () =>
            w.api.post("analyst", `/findings/${R1.id}/exceptions`, {
              kind: "suppress",
              justification: `${JUSTIFICATION} ${secret}`,
              expectedRev: await rev(R1),
            }),
        ],
        [
          "compensating controls",
          async () =>
            w.api.post("analyst", `/findings/${R1.id}/exceptions`, {
              kind: "accept_risk",
              justification: JUSTIFICATION,
              compensatingControls: `rotate ${secret}`,
              expiresAt: inDays(20),
              expectedRev: await rev(R1),
            }),
        ],
        [
          "approval comment",
          async () => w.approve("lead", R2.f, R2.reviewId, { comment: `ok ${secret}` }),
        ],
        [
          "rejection comment",
          async () => w.reject("lead", R2.f, R2.reviewId, { comment: `no ${secret}` }),
        ],
        [
          "reopen reason",
          async () =>
            w.api.post("analyst", `/findings/${R3.f.id}/reopen-review`, {
              reason: `new ${secret}`,
              expectedRev: await rev(R3.f),
            }),
        ],
        [
          "exception approval comment",
          async () =>
            w.api.post("lead", `/findings/${R4.id}/exceptions/${ex4}/approve`, {
              comment: `ok ${secret}`,
              expectedRev: await rev(R4),
            }),
        ],
        [
          "exception rejection comment",
          async () =>
            w.api.post("lead", `/findings/${R4.id}/exceptions/${ex4}/reject`, {
              comment: `no ${secret}`,
              expectedRev: await rev(R4),
            }),
        ],
        [
          "revoke reason",
          async () =>
            w.api.post("analyst", `/findings/${R5.f.id}/exceptions/${R5.exceptionId}/revoke`, {
              reason: `gone ${secret}`,
              expectedRev: await rev(R5.f),
            }),
        ],
      ];
      const before = await snapshot();
      for (const [name, secret] of Object.entries(CANARY))
        for (const [field, send] of cases(secret)) {
          const r = await send();
          eq(
            p,
            `${field} with a ${name} canary`,
            [r.status, codeOf(r), reasonOf(r)],
            [400, "VALIDATION_FAILED", "credential_shape"],
          );
          ok(
            p,
            !j(r.json).includes(secret),
            `${field} with a ${name} canary: the refusal echoes the secret`,
          );
        }
      eq(p, "nothing was stored, audited or queued by any refusal", await snapshot(), before);
      // controls: the same writes with plain text succeed
      const plain = "The handler validates the input before the call; reviewed by hand.";
      const ctl = [
        [
          "comment",
          await w.api.post("analyst", `/findings/${R1.id}/comments`, { body: plain }),
          201,
        ],
        ["rationale", await w.record("analyst", R1, "true_positive", { rationale: plain }), 201],
        ["rejection comment", await w.reject("lead", R2.f, R2.reviewId, { comment: plain }), 200],
        [
          "reopen reason",
          await w.api.post("analyst", `/findings/${R3.f.id}/reopen-review`, {
            reason: plain,
            expectedRev: await rev(R3.f),
          }),
          200,
        ],
        [
          "exception approval comment",
          await w.api.post("lead", `/findings/${R4.id}/exceptions/${ex4}/approve`, {
            comment: plain,
            expectedRev: await rev(R4),
          }),
          200,
        ],
        [
          "revoke reason",
          await w.api.post("analyst", `/findings/${R5.f.id}/exceptions/${R5.exceptionId}/revoke`, {
            reason: plain,
            expectedRev: await rev(R5.f),
          }),
          200,
        ],
      ];
      for (const [label, r, want] of ctl)
        eq(p, `control: ${label} with plain text`, r.status, want);
      const fresh = await w.fnd();
      eq(
        p,
        "control: justification and controls with plain text",
        (await w.requestException("analyst", fresh, "accept_risk", { compensatingControls: plain }))
          .status,
        201,
      );
      // no row, event or audit entry holds any canary
      const dump = j([
        await w.db.findingReview.findMany({ where: { tenantId } }),
        await w.db.findingComment.findMany({ where: { tenantId } }),
        await w.db.findingException.findMany({ where: { tenantId } }),
        await w.db.findingApproval.findMany({ where: { tenantId } }),
        await w.db.findingStatusHistory.findMany({ where: { tenantId } }),
        await w.db.auditLog.findMany({ where: { tenantId, targetType: "finding" } }),
        await w.db.outboxMessage.findMany({ where: { tenantId } }),
      ]);
      for (const [name, secret] of Object.entries(CANARY))
        ok(p, !dump.includes(secret), `the ${name} canary reached a stored row`);
      // events and audit never carry the free text of a decision
      const events = j((await w.outbox(R1)).map((e) => e.payload));
      ok(
        p,
        !events.includes(plain) && !events.includes(RATIONALE),
        "an event payload carries free text",
      );
      return p;
    },
  },

  {
    id: "FND-S11a",
    name: "Idempotency keys and bulk caps: every mutating POST of this part takes `Idempotency-Key` and the write rate limit (the route table); a replay returns the stored answer once, a different request under the same key is IDEMPOTENCY_CONFLICT, a key is per user and per route, a failed call does not keep its key; a bulk call is capped at 50 distinct findings, authorized in its workspace, and reports each finding on its own",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const posts = [
        "/api/v1/findings/bulk/claim",
        "/api/v1/findings/:id/claim",
        "/api/v1/findings/:id/reviews",
        "/api/v1/findings/:id/reviews/:reviewId/withdraw",
        "/api/v1/findings/:id/reopen-review",
        "/api/v1/findings/:id/comments",
        "/api/v1/findings/:id/reviews/:reviewId/approve",
        "/api/v1/findings/:id/reviews/:reviewId/reject",
        "/api/v1/findings/:id/exceptions",
        "/api/v1/findings/:id/exceptions/:exceptionId/withdraw",
        "/api/v1/findings/:id/exceptions/:exceptionId/approve",
        "/api/v1/findings/:id/exceptions/:exceptionId/reject",
        "/api/v1/findings/:id/exceptions/:exceptionId/revoke",
      ];
      for (const url of posts) {
        const r = w.api.routeTable.find((x) => x.method === "POST" && x.url === url);
        eq(
          p,
          `route table ${url}`,
          [r?.idempotent, r?.rateLimit, r?.audience],
          [true, "write", "tenant"],
        );
      }
      for (const url of ["/api/v1/review-queue", "/api/v1/approvals"]) {
        const r = w.api.routeTable.find((x) => x.method === "GET" && x.url === url);
        eq(p, `route table GET ${url}`, [r?.rateLimit, r?.audience], ["read", "tenant"]);
      }
      // replay
      const f = await w.fnd();
      const key = `idem-${rand(8)}`;
      const claim = `/findings/${f.id}/claim`;
      const a = await w.api.post("analyst", claim, { expectedRev: 0 }, { key });
      const b = await w.api.post("analyst", claim, { expectedRev: 0 }, { key });
      eq(
        p,
        "first call",
        [a.status, a.json?.data?.status, a.headers.get("idempotent-replayed")],
        [200, "in_review", null],
      );
      eq(
        p,
        "replay",
        [b.status, b.json?.data?.rev, b.headers.get("idempotent-replayed")],
        [200, a.json?.data?.rev, "true"],
      );
      eq(p, "the replay did not run twice", (await w.history(f)).length, 2);
      const diff = await w.api.post("analyst", claim, { expectedRev: 1 }, { key });
      eq(
        p,
        "the same key with a different request",
        [diff.status, codeOf(diff), reasonOf(diff)],
        [409, "IDEMPOTENCY_CONFLICT", "different_request"],
      );
      // per user and per route
      const g = await w.fnd();
      const other = await w.api.post(
        "analyst2",
        `/findings/${g.id}/claim`,
        { expectedRev: 0 },
        { key },
      );
      eq(
        p,
        "the same key by another user is a different key",
        [other.status, other.headers.get("idempotent-replayed")],
        [200, null],
      );
      const cm = await w.api.post(
        "analyst",
        `/findings/${f.id}/comments`,
        { body: "Same key, another route." },
        { key },
      );
      eq(
        p,
        "the same key on another route is a different key",
        [cm.status, cm.headers.get("idempotent-replayed")],
        [201, null],
      );
      // a created review is created once
      const h = await w.fnd();
      const k2 = `idem-${rand(8)}`;
      const body = { decision: "true_positive", rationale: RATIONALE, expectedRev: 0 };
      const r1 = await w.api.post("analyst", `/findings/${h.id}/reviews`, body, { key: k2 });
      const r2 = await w.api.post("analyst", `/findings/${h.id}/reviews`, body, { key: k2 });
      eq(
        p,
        "review create and replay",
        [r1.status, r2.status, r2.headers.get("idempotent-replayed")],
        [201, 201, "true"],
      );
      eq(
        p,
        "one review row",
        await w.db.findingReview.count({ where: { tenantId: h.tenantId, findingId: h.id } }),
        1,
      );
      // a failed call does not keep its key
      const i = await w.fnd();
      const k3 = `idem-${rand(8)}`;
      const stale = await w.api.post(
        "analyst",
        `/findings/${i.id}/claim`,
        { expectedRev: 9 },
        { key: k3 },
      );
      eq(p, "a stale call fails", stale.status, 409);
      const retry = await w.api.post(
        "analyst",
        `/findings/${i.id}/claim`,
        { expectedRev: 0 },
        { key: k3 },
      );
      eq(
        p,
        "the key is free again after a failure",
        [retry.status, retry.headers.get("idempotent-replayed")],
        [200, null],
      );
      eq(
        p,
        "a malformed key",
        (await w.api.post("analyst", `/findings/${i.id}/comments`, { body: "x" }, { key: "no" }))
          .status,
        400,
      );

      // bulk
      const ids = Array.from({ length: 51 }, () => randomUUID());
      for (const [label, findingIds] of [
        ["51 findings", ids],
        ["no findings", []],
        ["a duplicate", [ids[0], ids[0]]],
      ])
        eq(
          p,
          `bulk with ${label}`,
          (await w.api.post("analyst", "/findings/bulk/claim", { workspaceId: w.wsA, findingIds }))
            .status,
          400,
        );
      eq(
        p,
        "bulk without the key",
        (
          await w.api.post("viewer", "/findings/bulk/claim", {
            workspaceId: w.wsA,
            findingIds: [ids[0]],
          })
        ).status,
        403,
      );
      const fresh = await w.fnd();
      const taken = await w.fnd();
      await w.api.post("analyst2", `/findings/${taken.id}/claim`, { expectedRev: 0 });
      const elsewhere = await w.fnd({}, w.pipeline2);
      const mix = await w.api.post("analyst", "/findings/bulk/claim", {
        workspaceId: w.wsA,
        findingIds: [fresh.id, taken.id, elsewhere.id, UNKNOWN],
      });
      eq(p, "bulk: one result per finding, each on its own", mix.json?.data?.results, [
        { findingId: fresh.id, ok: true },
        {
          findingId: taken.id,
          ok: false,
          errorCode: "FINDING_STATE_CONFLICT",
          reason: "transition_not_allowed",
        },
        { findingId: elsewhere.id, ok: false, errorCode: "RESOURCE_NOT_FOUND" },
        { findingId: UNKNOWN, ok: false, errorCode: "RESOURCE_NOT_FOUND" },
      ]);
      eq(
        p,
        "bulk: the finding of another workspace was not touched",
        [(await w.row(elsewhere)).status, (await w.row(elsewhere)).rev],
        ["new", 0],
      );
      eq(
        p,
        "bulk: the claimed finding has its own audit entry",
        (await w.audit(fresh)).map((x) => [x.action, x.actorUserId]),
        [["finding.review_started", w.users.analyst]],
      );
      const cross = await w.api.post("ws2only", "/findings/bulk/claim", {
        workspaceId: w.wsA2,
        findingIds: [fresh.id, elsewhere.id],
      });
      eq(
        p,
        "bulk in a workspace the caller holds: a finding of ANOTHER workspace is not found, never forbidden",
        cross.json?.data?.results?.map((x) => [x.ok, x.errorCode ?? null]),
        [
          [false, "RESOURCE_NOT_FOUND"],
          [true, null],
        ],
      );
      return p;
    },
  },

  {
    id: "FND-S11b",
    name: "Write rate limits: the `write` profile is counted per tenant and user and per route (the fourth write inside the window is 429 RATE_LIMITED, another user and another route are not affected, reads are not counted against it)",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const limited = await startWriteApi(w.db, {
        limits: { write: { windowMs: 60_000, max: 3 } },
      });
      try {
        for (const name of ["analyst", "analyst2"])
          limited.register(name, {
            userId: w.users[name],
            tenantId: w.A.tenant.id,
            workspaces: [{ id: w.wsA, permissions: PERMS.analyst }],
          });
        const fs = [];
        for (let i = 0; i < 6; i += 1) fs.push(await w.fnd());
        const statuses = [];
        for (let i = 0; i < 4; i += 1)
          statuses.push(
            (await limited.post("analyst", `/findings/${fs[i].id}/claim`, { expectedRev: 0 }))
              .status,
          );
        eq(p, "three writes pass, the fourth is limited", statuses, [200, 200, 200, 429]);
        const blocked = await limited.post("analyst", `/findings/${fs[4].id}/claim`, {
          expectedRev: 0,
        });
        eq(
          p,
          "the refusal",
          [blocked.status, codeOf(blocked), blocked.json?.error?.details?.profile],
          [429, "RATE_LIMITED", "write"],
        );
        eq(p, "the limited write changed nothing", (await w.row(fs[4])).rev, 0);
        eq(
          p,
          "another user is not limited",
          (await limited.post("analyst2", `/findings/${fs[4].id}/claim`, { expectedRev: 0 }))
            .status,
          200,
        );
        eq(
          p,
          "another route has its own counter",
          (await limited.post("analyst", `/findings/${fs[0].id}/comments`, { body: "A note." }))
            .status,
          201,
        );
        for (let i = 0; i < 5; i += 1)
          await limited.get("analyst", `/review-queue?workspaceId=${w.wsA}`);
        eq(
          p,
          "reads are not counted against the write limit",
          (await limited.post("analyst2", `/findings/${fs[5].id}/claim`, { expectedRev: 0 }))
            .status,
          200,
        );
      } finally {
        await limited.close();
      }
      return p;
    },
  },

  {
    id: "FND-S15",
    name: "Realtime (SPEC 9.5): the findings room is joinable only with `finding.view` in that workspace (execution.view alone, another tenant, a hidden workspace and a client-chosen room are refused alike), the hints a real write produces reach the room carrying ids, status, rev and a type only (no title, no text), a forged or mismatched message produces no hint, and a revoked permission leaves the room",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const rt = await startFindingsRealtime(w.db);
      try {
        await rt.register("viewer", {
          userId: w.users.viewer,
          tenantId: w.A.tenant.id,
          workspaces: [{ id: w.wsA, permissions: ["finding.view"] }],
        });
        await rt.register("execOnly", {
          userId: w.users.developer,
          tenantId: w.A.tenant.id,
          workspaces: [{ id: w.wsA, permissions: ["execution.view"] }],
        });
        await rt.register("outsider", {
          userId: w.users.leadB,
          tenantId: w.B.tenant.id,
          workspaces: [{ id: w.wsB, permissions: ["finding.view", "execution.view"] }],
        });
        const sViewer = await rt.connect("viewer");
        const sExec = await rt.connect("execOnly");
        const sOut = await rt.connect("outsider");
        ok(p, sViewer && sExec && sOut, "the sockets connect");
        if (!(sViewer && sExec && sOut)) return p;
        eq(
          p,
          "join with finding.view",
          await rt.subscribe(sViewer, { findingsWorkspaceId: w.wsA }),
          { ok: true },
        );
        eq(
          p,
          "execution.view alone is refused",
          await rt.subscribe(sExec, { findingsWorkspaceId: w.wsA }),
          { ok: false, code: "FORBIDDEN" },
        );
        eq(
          p,
          "control: the same user joins the execution room",
          await rt.subscribe(sExec, { workspaceId: w.wsA }),
          { ok: true },
        );
        eq(
          p,
          "another tenant is told the workspace does not exist",
          await rt.subscribe(sOut, { findingsWorkspaceId: w.wsA }),
          { ok: false, code: "NOT_FOUND" },
        );
        eq(
          p,
          "control: that user joins its OWN workspace's room",
          await rt.subscribe(sOut, { findingsWorkspaceId: w.wsB }),
          { ok: true },
        );
        eq(
          p,
          "a hidden workspace of the same tenant",
          await rt.subscribe(sViewer, { findingsWorkspaceId: w.wsA2 }),
          { ok: false, code: "NOT_FOUND" },
        );
        for (const bad of [
          { findingsWorkspaceId: w.wsA, room: "findings:workspace:x:y" },
          { findingsWorkspaceId: w.wsA, workspaceId: w.wsA },
          { room: `findings:workspace:${w.A.tenant.id}:${w.wsA}` },
          { findingsWorkspaceId: "not-a-uuid" },
        ])
          eq(
            p,
            `a client-chosen room or malformed payload ${j(Object.keys(bad))}`,
            await rt.subscribe(sViewer, bad),
            { ok: false, code: "NOT_FOUND" },
          );

        // a REAL write produces the hints the room receives (the rows of the outbox are handed to the consumer as the relay would)
        const f = await w.fnd({ title: "A private finding title" });
        const wr = await w.api.post("analyst", `/findings/${f.id}/claim`, { expectedRev: 0 });
        eq(p, "control: the write", wr.status, 200);
        const rows = (await w.outbox(f)).filter((r) => r.queue === "realtime");
        ok(p, rows.length >= 1, "the write queued a hint");
        for (const row of rows) await rt.deliver(row.payload);
        await waitFor(() => sViewer.received.some((r) => r.event === "finding.changed"));
        const hint = sViewer.received.find((r) => r.event === "finding.changed");
        eq(
          p,
          "the room's hint is exactly ids, status, revision and type",
          [
            Object.keys(hint?.payload ?? {}).sort(),
            hint?.payload?.type,
            hint?.payload?.status,
            hint?.payload?.findingId,
            hint?.payload?.workspaceId,
          ],
          [
            ["findingId", "rev", "status", "type", "workspaceId"],
            "finding.status_changed",
            "in_review",
            f.id,
            w.wsA,
          ],
        );
        eq(
          p,
          "no other socket received it",
          [
            sExec.received.filter((r) => r.event === "finding.changed").length,
            sOut.received.filter((r) => r.event === "finding.changed").length,
          ],
          [0, 0],
        );
        // a created-finding event carries a title: the hint does not
        const base = {
          tenantId: w.A.tenant.id,
          workspaceId: w.wsA,
          repositoryId: f.repositoryId,
          pipelineId: f.pipelineId,
          initiator: { type: "system", id: "findings-ingestion" },
        };
        await rt.deliver(
          buildFindingMessage({
            ...base,
            kind: "event",
            type: "finding.created",
            messageId: `fnd-b-created-${rand(6)}`,
            subject: { type: "finding", id: f.id },
            payload: {
              findingId: f.id,
              workspaceId: w.wsA,
              repositoryId: f.repositoryId,
              pipelineId: f.pipelineId,
              scanType: "sast",
              severity: "high",
              title: "A private finding title",
            },
          }),
        );
        await waitFor(() => sViewer.received.some((r) => r.payload?.type === "finding.created"));
        const created = sViewer.received.find((r) => r.payload?.type === "finding.created");
        ok(p, created !== undefined, "the created hint arrives");
        ok(
          p,
          !j(sViewer.received).includes("A private finding title"),
          "no title ever reaches a socket",
        );
        // a forged message: tenant A's envelope naming a tenant-B finding, and a right finding with another workspace
        const fB = await w.fnd({}, w.pipelineB);
        const before = sViewer.received.length;
        const status = (finding, wsId, rev) => ({
          findingId: finding.id,
          workspaceId: wsId,
          fromStatus: "new",
          toStatus: "in_review",
          rev,
          actorType: "user",
        });
        await rt.deliver(
          buildFindingMessage({
            ...base,
            kind: "event",
            type: "finding.status_changed",
            messageId: `fnd-b-forged-${rand(6)}`,
            subject: { type: "finding", id: fB.id },
            payload: status(fB, w.wsB, 9),
          }),
        );
        await rt.deliver(
          buildFindingMessage({
            ...base,
            kind: "event",
            type: "finding.status_changed",
            messageId: `fnd-b-forged-${rand(6)}`,
            subject: { type: "finding", id: f.id },
            payload: status(f, w.wsA2, 9),
          }),
        );
        await new Promise((resolve) => setTimeout(resolve, 150));
        eq(p, "a forged or mismatched message produces no hint", sViewer.received.length, before);
        // a revoked permission leaves the room
        rt.setPermissions("viewer", [{ id: w.wsA, permissions: ["execution.view"] }]);
        await rt.server.sweep();
        await waitFor(() => sViewer.received.some((r) => r.event === "subscription.ended"));
        eq(
          p,
          "the socket is told the subscription ended",
          sViewer.received.find((r) => r.event === "subscription.ended")?.payload,
          { scope: "findings", id: w.wsA },
        );
        const seen = sViewer.received.length;
        await rt.deliver(
          buildFindingMessage({
            ...base,
            kind: "event",
            type: "finding.status_changed",
            messageId: `fnd-b-after-${rand(6)}`,
            subject: { type: "finding", id: f.id },
            payload: status(f, w.wsA, 10),
          }),
        );
        await new Promise((resolve) => setTimeout(resolve, 150));
        eq(p, "no hint after the permission was revoked", sViewer.received.length, seen);
      } finally {
        await rt.close();
      }
      return p;
    },
  },

  {
    id: "FND-S16",
    name: "Archived workspace and suspended tenant: every Part B mutation in an archived workspace is refused (409 workspace_archived, nothing changes) while reads follow permissions; a suspended tenant has no tenant context at all (TENANT_SUSPENDED) and every write route is a tenant route; the writes work again once the workspace is restored",
    async run(c) {
      const w = await bWorld(c);
      const p = [];
      const f = await w.fnd({}, w.pipeline2);
      const pend = await w.api.post(
        "ws2only",
        `/findings/${(await w.fnd({}, w.pipeline2)).id}/reviews`,
        { decision: "true_positive", rationale: RATIONALE, expectedRev: 0 },
      );
      eq(p, "control: a review in the second workspace", pend.status, 201);
      const pendF = { id: pend.json.data.id, tenantId: w.A.tenant.id };
      const pendReview = pend.json.data.review.current.id;
      const ex = await w.fnd({}, w.pipeline2);
      const exReq = await w.api.post("ws2only", `/findings/${ex.id}/exceptions`, {
        kind: "suppress",
        justification: JUSTIFICATION,
        expectedRev: 0,
      });
      eq(p, "control: an exception request in the second workspace", exReq.status, 201);
      const rows = async () =>
        j([(await w.row(f)).rev, (await w.row(pendF)).rev, (await w.row(ex)).rev]);
      const before = await rows();
      await w.db.workspace.update({
        where: { id: w.wsA2 },
        data: { status: "archived", archivedAt: new Date() },
      });
      try {
        const writes = [
          ["claim", w.api.post("ws2only", `/findings/${f.id}/claim`, { expectedRev: 0 })],
          [
            "review",
            w.api.post("ws2only", `/findings/${f.id}/reviews`, {
              decision: "true_positive",
              rationale: RATIONALE,
              expectedRev: 0,
            }),
          ],
          ["comment", w.api.post("ws2only", `/findings/${f.id}/comments`, { body: "A note." })],
          [
            "reopen-review",
            w.api.post("ws2only", `/findings/${f.id}/reopen-review`, {
              reason: "Look again.",
              expectedRev: 0,
            }),
          ],
          [
            "exception request",
            w.api.post("ws2only", `/findings/${f.id}/exceptions`, {
              kind: "suppress",
              justification: JUSTIFICATION,
              expectedRev: 0,
            }),
          ],
          [
            "approve",
            w.api.post("ws2lead", `/findings/${pendF.id}/reviews/${pendReview}/approve`, {
              expectedRev: 1,
            }),
          ],
          [
            "reject",
            w.api.post("ws2lead", `/findings/${pendF.id}/reviews/${pendReview}/reject`, {
              comment: "No.",
              expectedRev: 1,
            }),
          ],
          [
            "exception approve",
            w.api.post(
              "ws2lead",
              `/findings/${ex.id}/exceptions/${exReq.json.data.exception.id}/approve`,
              { expectedRev: 1 },
            ),
          ],
          [
            "exception withdraw",
            w.api.post(
              "ws2only",
              `/findings/${ex.id}/exceptions/${exReq.json.data.exception.id}/withdraw`,
              {},
            ),
          ],
        ];
        for (const [label, promise] of writes) {
          const r = await promise;
          eq(
            p,
            `${label} in an archived workspace`,
            [r.status, reasonOf(r)],
            [409, "workspace_archived"],
          );
        }
        const bulk = await w.api.post("ws2only", "/findings/bulk/claim", {
          workspaceId: w.wsA2,
          findingIds: [f.id],
        });
        eq(p, "bulk claim in an archived workspace", bulk.json?.data?.results, [
          { findingId: f.id, ok: false, errorCode: "CONFLICT", reason: "workspace_archived" },
        ]);
        eq(p, "nothing changed", await rows(), before);
        // reads follow permissions
        for (const path of [
          `/findings/${f.id}`,
          `/findings/${f.id}/history`,
          `/findings/${f.id}/comments`,
          `/findings?workspaceId=${w.wsA2}`,
          `/review-queue?workspaceId=${w.wsA2}`,
          `/approvals?workspaceId=${w.wsA2}`,
        ])
          eq(
            p,
            `read ${path.split("?")[0].replace(f.id, ":id")} in an archived workspace`,
            (await w.api.get("ws2only", path)).status,
            200,
          );
      } finally {
        await w.db.workspace.update({
          where: { id: w.wsA2 },
          data: { status: "active", archivedAt: null },
        });
      }
      eq(
        p,
        "control: the same claim works after the workspace is restored",
        (await w.api.post("ws2only", `/findings/${f.id}/claim`, { expectedRev: 0 })).status,
        200,
      );

      // a suspended tenant: the tenant context is refused before any route runs; every write route is a tenant route
      const sfx = rand(4);
      const tenant = await w.db.tenant.create({
        data: { slug: `fnd-b-susp-${sfx}`, name: `Suspended ${sfx}`, status: "suspended" },
      });
      const user = await w.db.user.create({
        data: { email: `fnd-b-susp-${sfx}@fnd.example`, name: "Suspended" },
      });
      await w.db.tenantMembership.create({
        data: { tenantId: tenant.id, userId: user.id, status: "active", joinedAt: new Date() },
      });
      const resolvers = createAuthResolvers({ db: w.db, config: {}, sessions: {} });
      const principal = { session: { activeTenantId: tenant.id }, user: { id: user.id } };
      let refused = null;
      try {
        await resolvers.resolveTenantContext(principal);
      } catch (error) {
        refused = error;
      }
      eq(
        p,
        "a suspended tenant has no tenant context",
        [refused?.code, refused?.statusCode],
        ["TENANT_SUSPENDED", 403],
      );
      await w.db.tenant.update({ where: { id: tenant.id }, data: { status: "active" } });
      eq(
        p,
        "control: the same session resolves once the tenant is active",
        (await resolvers.resolveTenantContext(principal)).tenant.id,
        tenant.id,
      );
      const mine = w.api.routeTable.filter(
        (r) => r.method === "POST" && /\/findings\//.test(r.url),
      );
      ok(
        p,
        mine.length >= 13 && mine.every((r) => r.audience === "tenant"),
        "every write route runs behind the tenant authentication and tenant context chain",
      );
      return p;
    },
  },
];
