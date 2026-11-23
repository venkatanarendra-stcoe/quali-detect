import { randomBytes, randomUUID } from "node:crypto";
import { createFindingsRepository } from "@qmentisai/db";
import {
  FINDING_SEVERITY_RANK,
  FORBIDDEN_FINDING_DTO_KEYS,
  boardDtoSchema,
} from "@qmentisai/shared";
import {
  CANARY,
  DAY,
  HOUR,
  UNKNOWN,
  actionOf,
  cWorld,
  codeOf,
  eq,
  hasKey,
  j,
  ok,
  rand,
  shape,
} from "./findings-c-world.js";

/**
 * Findings checks of part C, the board and the advisory read path (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1): FND-S12 (DTO
 * no-leak of the board, with its scoping and keyset paging) and FND-S12d (the pending and stale advisory state of the detail read).
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const sev = (name) => ({
  severity: name,
  toolSeverity: name,
  severityRank: FINDING_SEVERITY_RANK[name],
});
const hex64 = () => randomBytes(32).toString("hex");
const COLUMNS = [
  "assigned",
  "in_remediation",
  "fixed_pending_verification",
  "verified_fixed",
  "reopened",
];

export const FINDINGS_C_BOARD_CHECKS = [
  {
    id: "FND-S12c",
    name: 'The remediation board (SPEC 8.1, SCREENS T-36, FND-S01, FND-S12, FND-S13): five columns with their counts, the first 25 cards most severe first and a signed cursor; a column pages by keyset (no card twice, none missed) and a cursor from another column, filter set, workspace, tenant, user or a tampered one is INVALID_CURSOR; filters narrow and never widen (a pipeline of another tenant gives an empty board); 404 identical for a hidden workspace, another tenant and an unknown workspace, 403 without `remediation.view`; the card carries the PR link and ticket key of the latest submitted fix (null otherwise) and `canRemediate` computed for the caller (a developer only on their own assigned or in-progress cards, a lead who can assign on any, never on a pending, verified or reopened card); "Verified fixed" shows the last 30 days; no forbidden key, no e-mail and no canary appears in any card and the whole answer validates against the contract',
    async run(c) {
      const w = await cWorld(c);
      const p = [];
      const { api, users } = w;
      const bp = await c.pipeline(c.A, 0); // a pipeline of its own: the board is read through `pipelineId`, so other checks' findings do not count
      const NOTE = `BOARD-NOTE-${rand(6)}`;
      const sevs = ["critical", "high", "medium", "low"];
      const assignedIds = [];
      for (let n = 0; n < 30; n += 1) {
        const name = sevs[n % 4];
        const o = { ...sev(name) };
        if (n === 0) {
          // one clock that is already over: the `sla=breached` filter must find exactly this card
          o.slaStartedAt = new Date(Date.now() - 20 * DAY);
          o.slaDueAt = new Date(Date.now() - 2 * DAY);
        }
        const f = await w.assigned(n < 3 ? "dev2" : "dev", o, bp);
        assignedIds.push(f.id);
      }
      const breachedId = assignedIds[0];
      // one in progress and one with a submitted fix (PR and ticket), through the real routes
      const prog = await w.assigned("dev", sev("high"), bp);
      const st = await api.post("dev", `/findings/${prog.id}/remediation/start`, {
        expectedRev: (await w.row(prog)).rev,
      });
      eq(p, "control: start", st.status, 200);
      const fixed = await w.assigned("dev", sev("high"), bp);
      const sb = await api.post("dev", `/findings/${fixed.id}/remediation/submit`, {
        expectedRev: (await w.row(fixed)).rev,
        pullRequestUrl: "https://github.com/acme/app/pull/21",
        ticketKey: "SEC-210",
        note: NOTE,
      });
      eq(p, "control: submit", sb.status, 200);
      // verified fixed (recent and 40 days ago) and reopened: written the way ingestion does (system actor)
      const toPending = async (f) =>
        c.step(await w.row(f), "fixed_pending_verification", {
          set: { fixClaimedAt: new Date() },
          reason: "fix_submitted",
        });
      const verify = async (f, at) => {
        const x = await toPending(f);
        return c.step(x, "verified_fixed", {
          actor: "system",
          reason: "verified",
          set: { absentCount: 1, verifiedAt: at, closedAt: at },
        });
      };
      const recent = await verify(
        await w.assigned("dev", sev("medium"), bp),
        new Date(Date.now() - 3 * DAY),
      );
      const old = await verify(
        await w.assigned("dev", sev("medium"), bp),
        new Date(Date.now() - 40 * DAY),
      );
      const reop = await c.step(
        await toPending(await w.assigned("dev", sev("low"), bp)),
        "reopened",
        {
          actor: "system",
          reason: "recurred",
          set: { reopenedAt: new Date(), reopenCount: 1, absentCount: 0, fixClaimedAt: null },
        },
      );
      const board = (name, query = "", ws = w.wsA) =>
        api.get(name, `/remediation/board?workspaceId=${ws}&pipelineId=${bp.id}${query}`);
      const col = (name, column, query = "", ws = w.wsA) =>
        api.get(name, `/remediation/board/${column}?workspaceId=${ws}&pipelineId=${bp.id}${query}`);

      const r = await board("devlead");
      eq(p, "the board answers", r.status, 200);
      const cols = r.json?.data?.columns ?? {};
      eq(p, "exactly the five columns, in the contract's order", Object.keys(cols), COLUMNS);
      eq(
        p,
        "counts",
        COLUMNS.map((k) => cols[k]?.count),
        [30, 1, 1, 1, 1],
      );
      eq(
        p,
        "the first 25 cards and a cursor on the long column",
        [cols.assigned?.items.length, typeof cols.assigned?.nextCursor],
        [25, "string"],
      );
      eq(
        p,
        "no cursor on the short ones",
        COLUMNS.slice(1).map((k) => cols[k]?.nextCursor),
        [null, null, null, null],
      );
      const ranks = cols.assigned.items.map((i) => FINDING_SEVERITY_RANK[i.severity]);
      ok(
        p,
        ranks.every((x, i) => i === 0 || ranks[i - 1] >= x),
        "cards are most severe first",
      );
      eq(p, "the first card is critical", cols.assigned.items[0].severity, "critical");
      const parsed = boardDtoSchema.safeParse(r.json?.data);
      ok(
        p,
        parsed.success,
        `the answer must validate against the contract: ${parsed.success ? "" : j(parsed.error?.issues?.slice(0, 2))}`,
      );
      // verified fixed: the last 30 days only
      eq(
        p,
        "verified fixed shows the recent finding, not the one verified 40 days ago",
        cols.verified_fixed.items.map((i) => i.id),
        [recent.id],
      );
      ok(p, old.id !== recent.id, "two different verified findings were built");
      eq(
        p,
        "the reopened card",
        cols.reopened.items.map((i) => [i.id, i.reopenCount, i.status]),
        [[reop.id, 1, "reopened"]],
      );
      // the PR link and the ticket key of the submitted fix
      const fixedCard = cols.fixed_pending_verification.items[0];
      eq(
        p,
        "the submitted fix carries its PR link and ticket key",
        [fixedCard.id, fixedCard.pullRequestUrl, fixedCard.ticketKey],
        [fixed.id, "https://github.com/acme/app/pull/21", "SEC-210"],
      );
      eq(
        p,
        "other cards carry null",
        [
          cols.assigned.items[0].pullRequestUrl,
          cols.assigned.items[0].ticketKey,
          cols.in_remediation.items[0].pullRequestUrl,
        ],
        [null, null, null],
      );
      // ---- keyset paging of the long column ----
      const next = await col(
        "devlead",
        "assigned",
        `&cursor=${encodeURIComponent(cols.assigned.nextCursor)}`,
      );
      eq(
        p,
        "the second page",
        [
          next.status,
          next.json?.data?.length,
          next.json?.meta?.pagination?.hasMore,
          next.json?.meta?.pagination?.nextCursor,
        ],
        [200, 5, false, null],
      );
      const seen = [...cols.assigned.items.map((i) => i.id), ...next.json.data.map((i) => i.id)];
      eq(
        p,
        "no card twice and none missed",
        [new Set(seen).size, [...seen].sort()],
        [30, [...assignedIds].sort()],
      );
      const pages = [];
      let cursor = null;
      for (let n = 0; n < 6; n += 1) {
        const q = `&limit=10${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
        const pg = await col("devlead", "assigned", q);
        pages.push(pg.json?.data?.length);
        cursor = pg.json?.meta?.pagination?.nextCursor;
        if (!cursor) break;
      }
      eq(p, "limit 10 pages 10, 10, 10", pages, [10, 10, 10]);
      // ---- cursor misuse ----
      const bad = async (label, res) =>
        eq(p, label, [res.status, codeOf(res)], [400, "INVALID_CURSOR"]);
      const cur = encodeURIComponent(cols.assigned.nextCursor);
      await bad(
        "a cursor of another column",
        await col("devlead", "in_remediation", `&cursor=${cur}`),
      );
      await bad(
        "a cursor under another filter",
        await col("devlead", "assigned", `&severity=high&cursor=${cur}`),
      );
      await bad("a cursor of another user", await col("devlead2", "assigned", `&cursor=${cur}`));
      await bad(
        "a tampered cursor",
        await col(
          "devlead",
          "assigned",
          `&cursor=${encodeURIComponent(`${cols.assigned.nextCursor.slice(0, -4)}AAAA`)}`,
        ),
      );
      await bad(
        "a cursor of another workspace and tenant",
        await api.get(
          "leadB",
          `/remediation/board/assigned?workspaceId=${w.wsB}&pipelineId=${bp.id}&cursor=${cur}`,
        ),
      );
      // ---- filters narrow, never widen ----
      const mine = await board("dev", "&assignee=me");
      eq(p, "assignee=me is the caller's own", mine.json?.data?.columns?.assigned?.count, 27);
      const dev2 = await board("devlead", `&assignee=${users.dev2}`);
      eq(p, "assignee=<user id>", dev2.json?.data?.columns?.assigned?.count, 3);
      const crit = await board("devlead", "&severity=critical");
      ok(
        p,
        crit.json?.data?.columns?.assigned?.items.every((i) => i.severity === "critical") &&
          crit.json.data.columns.assigned.count === 8,
        "severity=critical narrows the column",
      );
      const breached = await board("devlead", "&sla=breached");
      eq(
        p,
        "sla=breached finds the clock that is over",
        [breached.json?.data?.columns?.assigned?.items.map((i) => i.id)],
        [[breachedId]],
      );
      const foreignPipeline = await api.get(
        "devlead",
        `/remediation/board?workspaceId=${w.wsA}&pipelineId=${w.pipelineB.id}`,
      );
      eq(
        p,
        "a pipeline of another tenant gives an empty board, never its findings",
        [
          foreignPipeline.status,
          COLUMNS.map((k) => foreignPipeline.json?.data?.columns?.[k]?.count),
        ],
        [200, [0, 0, 0, 0, 0]],
      );
      const unknownQuery = await api.get(
        "devlead",
        `/remediation/board?workspaceId=${w.wsA}&tenantId=${c.B.tenant.id}`,
      );
      eq(
        p,
        "an unknown query key",
        [unknownQuery.status, codeOf(unknownQuery)],
        [400, "VALIDATION_FAILED"],
      );
      const noWs = await api.get("devlead", "/remediation/board");
      eq(p, "no workspace", [noWs.status, codeOf(noWs)], [400, "VALIDATION_FAILED"]);
      const badCol = await api.get(
        "devlead",
        `/remediation/board/accepted_risk?workspaceId=${w.wsA}`,
      );
      eq(
        p,
        "a column that is not on the board",
        [badCol.status, codeOf(badCol)],
        [400, "VALIDATION_FAILED"],
      );
      // ---- scope ----
      const viewer = await board("viewer");
      eq(p, "no `remediation.view`", [viewer.status, codeOf(viewer)], [403, "FORBIDDEN"]);
      const viewerCol = await col("viewer", "assigned");
      eq(p, "no `remediation.view` on a column", viewerCol.status, 403);
      const hidden = await board("ws2lead");
      const foreign = await board("leadB");
      const unknownWs = await api.get("devlead", `/remediation/board?workspaceId=${UNKNOWN}`);
      eq(
        p,
        "a workspace the caller cannot see",
        [hidden.status, codeOf(hidden)],
        [404, "RESOURCE_NOT_FOUND"],
      );
      ok(
        p,
        shape(hidden) === shape(foreign) && shape(hidden) === shape(unknownWs),
        "hidden, foreign and unknown workspaces answer the same 404",
      );
      const own2 = await api.get("ws2lead", `/remediation/board?workspaceId=${w.wsA2}`);
      eq(
        p,
        "the other workspace has its own (empty) board",
        [own2.status, COLUMNS.map((k) => own2.json?.data?.columns?.[k]?.count)],
        [200, [0, 0, 0, 0, 0]],
      );
      const boardonly = await board("boardonly");
      eq(p, "`remediation.view` alone reads the board", boardonly.status, 200);
      // ---- canRemediate per caller ----
      const flags = (res) =>
        Object.fromEntries(
          COLUMNS.map((k) => [
            k,
            [...new Set((res.json?.data?.columns?.[k]?.items ?? []).map((i) => i.canRemediate))],
          ]),
        );
      eq(p, "a lead who can assign: true on assigned and in progress, false elsewhere", flags(r), {
        assigned: [true],
        in_remediation: [true],
        fixed_pending_verification: [false],
        verified_fixed: [false],
        reopened: [false],
      });
      const asDev = await board("dev");
      const ownCards = asDev.json?.data?.columns?.assigned?.items ?? [];
      const dev2Card = (await col("dev", "assigned", `&assignee=${users.dev2}`)).json?.data ?? [];
      ok(
        p,
        ownCards.filter((i) => i.assignee.id === users.dev).every((i) => i.canRemediate === true),
        "a developer may move their own assigned cards",
      );
      ok(
        p,
        dev2Card.length === 3 && dev2Card.every((i) => i.canRemediate === false),
        "a developer may not move another's cards",
      );
      eq(
        p,
        "a developer's own in-progress card",
        asDev.json?.data?.columns?.in_remediation?.items.map((i) => i.canRemediate),
        [true],
      );
      eq(
        p,
        "never on a pending fix",
        asDev.json?.data?.columns?.fixed_pending_verification?.items.map((i) => i.canRemediate),
        [false],
      );
      eq(
        p,
        "a viewer of the board only cannot move anything",
        [
          ...new Set(
            COLUMNS.flatMap((k) =>
              (boardonly.json?.data?.columns?.[k]?.items ?? []).map((i) => i.canRemediate),
            ),
          ),
        ],
        [false],
      );
      // ---- no leak ----
      for (const [label, res] of [
        ["devlead", r],
        ["dev", asDev],
        ["boardonly", boardonly],
        ["column page", next],
      ]) {
        for (const key of FORBIDDEN_FINDING_DTO_KEYS)
          ok(
            p,
            !hasKey(res.json?.data, key),
            `${label}: the key "${key}" must not appear in a board answer`,
          );
        const text = j(res.json);
        for (const t of Object.values(CANARY))
          ok(p, !text.includes(t), `${label}: a canary reached the board`);
        ok(p, !text.includes(NOTE), `${label}: a fix note reached the board`);
        ok(p, !/@[a-z0-9-]+\.example/i.test(text), `${label}: an e-mail address reached the board`);
      }
      eq(
        p,
        "a card's assignee is an id and a name only",
        Object.keys(cols.assigned.items[0].assignee).sort(),
        ["displayName", "id"],
      );
      // an old verification stays out even when asked for directly
      eq(
        p,
        "the old verified finding is not on the board",
        cols.verified_fixed.items.some((i) => i.id === old.id),
        false,
      );
      return p;
    },
  },

  {
    id: "FND-S12d",
    name: "The advisory state of the finding detail (SPEC 9.3.6, 8.3): a requested advisory with no newer advisory row reads `pending` (a body-less card, the request action disabled) and nothing else changes; an answer makes it `ready`; a request that is older than five minutes, belongs to another tenant, or is answered never reads pending; a ready advisory is `stale` when it predates the evidence copy's capture or the last reopening, and fresh otherwise; the pending lookup is one read of the detail and none of the list; another tenant gets the same 404",
    async run(c) {
      const w = await cWorld(c);
      const p = [];
      const { api, db } = w;
      const previous = process.env.FINDINGS_AGENT_ENABLED;
      process.env.FINDINGS_AGENT_ENABLED = "true";
      try {
        const chain = (f) => c.chainOf(f);
        const advise = (f, o = {}) =>
          db.findingAiAdvisory.create({
            data: {
              ...chain(f),
              inputHash: hex64(),
              status: "ok",
              suggestion: "likely_true_positive",
              confidence: 80,
              reasoning: "The call reaches user input.",
              egressLevel: "metadata",
              provider: "ollama",
              model: "stub",
              ...o,
            },
          });
        const f = await w.fnd();
        const d0 = await w.det("analyst", f);
        eq(p, "no advisory at first", d0.advisory, { status: "none", stale: false });
        // a manual request (the real route): pending
        const req = await api.post("analyst", `/findings/${f.id}/advisory/request`, {});
        eq(p, "the request is accepted", [req.status, req.json?.data?.status], [202, "pending"]);
        const d1 = await w.det("analyst", f);
        eq(p, "the detail reads pending with no body", d1.advisory, {
          status: "pending",
          stale: false,
        });
        eq(
          p,
          "the request action is disabled while advice is being prepared",
          [
            actionOf(d1, "request_advisory")?.allowed,
            actionOf(d1, "request_advisory")?.disabledReason,
          ],
          [false, "Advice is already being prepared."],
        );
        eq(
          p,
          "the finding itself is untouched",
          [(await w.row(f)).status, (await w.row(f)).rev],
          ["new", 0],
        );
        // the agent answers: a row newer than the request
        const a1 = await advise(f);
        const d2 = await w.det("analyst", f);
        eq(
          p,
          "answered: ready, fresh",
          [
            d2.advisory.status,
            d2.advisory.suggestion,
            d2.advisory.confidence,
            d2.advisory.confidenceBand,
            d2.advisory.stale,
          ],
          ["ready", "likely_true_positive", 80, "high", false],
        );
        eq(p, "the request action is back", actionOf(d2, "request_advisory")?.allowed, true);
        // a second request after the answer: pending again, then ready again
        const req2 = await api.post("analyst", `/findings/${f.id}/advisory/request`, {});
        eq(p, "a second request", req2.status, 202);
        eq(
          p,
          "pending again although an older answer exists",
          (await w.det("analyst", f)).advisory.status,
          "pending",
        );
        await advise(f, { suggestion: "uncertain", confidence: 40 });
        const d3 = await w.det("analyst", f);
        eq(
          p,
          "ready again with the newer answer",
          [d3.advisory.status, d3.advisory.suggestion, d3.advisory.confidenceBand],
          ["ready", "uncertain", "low"],
        );
        ok(p, a1.id !== undefined, "the first answer exists");
        // a request that is too old, and a request of another tenant, never read pending
        const old = await w.fnd();
        await api.post("analyst", `/findings/${old.id}/advisory/request`, {});
        await db.$executeRaw`UPDATE outbox_messages SET created_at = now() - interval '6 minutes' WHERE tenant_id = ${old.tenantId}::uuid AND type = 'finding.advisory.requested' AND payload #>> '{payload,findingId}' = ${old.id}`;
        eq(
          p,
          "a request older than five minutes is not pending",
          (await w.det("analyst", old)).advisory.status,
          "none",
        );
        const other = await w.fnd();
        await db.outboxMessage.create({
          data: {
            tenantId: c.B.tenant.id,
            messageId: `finding-advisory-${other.id}-x${rand(4)}`,
            type: "finding.advisory.requested",
            queue: "findings-agent",
            payload: { payload: { findingId: other.id } },
          },
        });
        eq(
          p,
          "another tenant's message naming this finding is not a request",
          (await w.det("analyst", other)).advisory.status,
          "none",
        );
        const gone = await api.get("devB", `/findings/${f.id}`);
        eq(
          p,
          "another tenant gets the same 404",
          [gone.status, codeOf(gone)],
          [404, "RESOURCE_NOT_FOUND"],
        );
        // ---- stale: the advice predates the last observation or reopening ----
        const s = await w.fnd();
        const made = new Date(Date.now() - HOUR);
        await advise(s, { createdAt: made });
        const evidence = (capturedAt) => ({
          ...chain(s),
          kind: "block",
          language: "python",
          startLine: 1,
          endLine: 2,
          focusStart: 1,
          focusEnd: 1,
          snippet: "x = 1\n",
          truncated: false,
          capturedExecutionId: randomUUID(),
          capturedAt,
        });
        await db.findingEvidence.create({ data: evidence(new Date(made.getTime() - HOUR)) });
        eq(
          p,
          "evidence captured before the advice: fresh",
          (await w.det("analyst", s)).advisory.stale,
          false,
        );
        await db.findingEvidence.update({
          where: { tenantId_findingId: { tenantId: s.tenantId, findingId: s.id } },
          data: { capturedAt: new Date() },
        });
        eq(
          p,
          "evidence captured after the advice: stale",
          (await w.det("analyst", s)).advisory.stale,
          true,
        );
        await db.findingEvidence.update({
          where: { tenantId_findingId: { tenantId: s.tenantId, findingId: s.id } },
          data: { capturedAt: new Date(made.getTime() - HOUR) },
        });
        eq(p, "back to fresh", (await w.det("analyst", s)).advisory.stale, false);
        await db.$executeRaw`UPDATE findings SET reopened_at = now(), rev = rev + 1 WHERE tenant_id = ${s.tenantId}::uuid AND id = ${s.id}::uuid`;
        eq(p, "reopened after the advice: stale", (await w.det("analyst", s)).advisory.stale, true);
        // a failed or absent advisory is never stale
        const t = await w.fnd();
        await advise(t, {
          status: "failed",
          suggestion: null,
          confidence: null,
          reasoning: null,
          createdAt: made,
        });
        eq(
          p,
          "a failed advisory shows failed and not stale",
          [(await w.det("analyst", t)).advisory.status, (await w.det("analyst", t)).advisory.stale],
          ["failed", false],
        );

        // ---- the cost: one pending lookup for the detail, none for the list ----
        const calls = [];
        const spy = new Proxy(db, {
          get(target, prop) {
            if (prop === "$queryRaw")
              return (first, ...rest) => {
                calls.push(Array.isArray(first) ? first.join("?") : String(first?.sql ?? first));
                return target.$queryRaw(first, ...rest);
              };
            return Reflect.get(target, prop);
          },
        });
        const repo = createFindingsRepository({ db: spy });
        const scope = { tenantId: s.tenantId, workspaceId: s.workspaceId };
        await repo.list(
          scope,
          { limit: 25, sort: "severity", withTotal: true, now: new Date() },
          { userId: w.users.analyst },
        );
        eq(
          p,
          "the list never reads the outbox",
          calls.filter((q) => q.includes("outbox_messages")).length,
          0,
        );
        calls.length = 0;
        await repo.getDetail(scope, s.id);
        eq(
          p,
          "the detail reads it once",
          calls.filter((q) => q.includes("outbox_messages")).length,
          1,
        );
      } finally {
        if (previous === undefined) delete process.env.FINDINGS_AGENT_ENABLED;
        else process.env.FINDINGS_AGENT_ENABLED = previous;
      }
      return p;
    },
  },
];
