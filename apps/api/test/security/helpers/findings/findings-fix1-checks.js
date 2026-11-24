import { randomBytes } from "node:crypto";
import { findingEtag } from "../../../../src/modules/findings/mappers/etag.js";
import { PERMS, makeUser } from "./findings-b-fixtures.js";
import { fWorld } from "./findings-f-checks.js";

/**
 * Findings checks of the fix round after Part F (ADR-008 area 19, docs/modules/findings/SPEC.md 8.3, `AS_BUILT_FIX1.md`, 2026-11-24).
 *  - `FNDFX-01` D-F4 / S-1: the ETag of `GET /findings/{id}` covers the WHOLE detail DTO as the caller sees it, so state that changes
 *    WITHOUT a revision change (the advisory card, the caller's allowed actions, the SLA state) moves it; identical reads keep it (304);
 *    two callers with different DTOs differ; the tag is a hash and never holds a raw value; a write answers with the tag a following read
 *    of the same caller sends.
 * (D-F1 is asserted in `FND-S16b` and D-F2 in `FND-S10e`: the assertions that pinned the defects were flipped in place.)
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const eq = (p, label, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want))
    p.push(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
};
const DAY = 86_400_000;
const SHAPE = /^W\/"finding-\d+-[0-9a-f]{32}"$/;

export const FINDINGS_FIX1_CHECKS = [
  {
    id: "FNDFX-01",
    name: "the ETag of GET /findings/{id} covers the whole detail DTO as the caller sees it (SPEC 8.3, D-F4 / S-1 fixed 2026-11-24): it changes when the advisory card changes WITHOUT a revision change, when the caller's permissions change (allowedActions), and when the SLA state changes (due soon, breached), each time with the revision unchanged (control); it stays equal across identical reads and a conditional read with it answers an empty 304 (a stale or foreign tag gets the full 200); two callers whose DTOs differ (allowedActions) get different tags, and the tag is `W/\"finding-<rev>-<32 hex>\"` of the caller's own DTO (the same function the write routes use, so a write answers with the tag a following read of the same caller sends) and holds no raw field value",
    async run(c) {
      const p = [];
      const w = await fWorld(c);
      const { api, db, A, wsA } = w;
      const f = await c.finding(await c.pipeline(A, 0));
      const url = `/findings/${f.id}`;
      const rev = async () => (await w.row(f)).rev;
      const read = (name, headers) => api.get(name, url, { headers });
      const tagOf = (r) => r.headers.get("etag");

      // identical reads: equal tag, the tag is a hash of the caller's own DTO, no raw value inside, 304 on a matching validator
      const r1 = await read("fFull");
      const r2 = await read("fFull");
      eq(p, "control: the detail is readable", [r1.status, r2.status], [200, 200]);
      ok(p, SHAPE.test(tagOf(r1) ?? ""), `the tag is not W/"finding-<rev>-<hash>": ${tagOf(r1)}`);
      eq(p, "identical reads give the same tag", tagOf(r2), tagOf(r1));
      eq(
        p,
        "the tag is the hash of the DTO the caller received",
        tagOf(r1),
        findingEtag(r1.json?.data),
      );
      for (const raw of [f.id, r1.json?.data?.title, r1.json?.data?.path, r1.json?.data?.ruleId])
        ok(p, !raw || !tagOf(r1).includes(raw), "the tag holds a raw field value");
      const cond = await read("fFull", { "If-None-Match": tagOf(r1) });
      eq(p, "a matching validator answers 304", cond.status, 304);
      eq(p, "the 304 repeats the tag", tagOf(cond), tagOf(r1));
      const stale = await read("fFull", { "If-None-Match": 'W/"finding-0"' });
      eq(p, "a stale validator (the old rev-only tag) gets the full answer", stale.status, 200);

      // 1. the advisory card changes, the revision does not
      const rev0 = await rev();
      const chain = c.chainOf(f);
      const advise = (suggestion) =>
        db.findingAiAdvisory.create({
          data: {
            ...chain,
            inputHash: randomBytes(32).toString("hex"),
            status: "ok",
            suggestion,
            confidence: 80,
            reasoning: "The call reaches user input.",
            egressLevel: "metadata",
            provider: "ollama",
            model: "stub",
          },
        });
      await advise("likely_true_positive");
      const afterAdvisory = await read("fFull");
      eq(p, "control: the advisory change left the revision alone", await rev(), rev0);
      ok(p, tagOf(afterAdvisory) !== tagOf(r1), "the advisory card changed but the tag did not");
      const sameAfter = await read("fFull", { "If-None-Match": tagOf(r1) });
      eq(
        p,
        "the old validator no longer answers 304 once the advisory changed",
        sameAfter.status,
        200,
      );
      await advise("likely_false_positive");
      ok(
        p,
        tagOf(await read("fFull")) !== tagOf(afterAdvisory),
        "a second advisory with another suggestion did not move the tag",
      );

      // 2. the SLA state changes with the CLOCK alone: a due date two seconds away reads "due soon", two seconds later it reads "breached",
      // and nothing was written between the two reads (the database refuses an update without a revision raise, so the clock is the only way)
      const now = Date.now();
      await db.finding.update({
        where: { tenantId_id: { tenantId: f.tenantId, id: f.id } },
        data: {
          slaStartedAt: new Date(now - 10 * DAY),
          slaDueAt: new Date(now + 2000),
          rev: { increment: 1 },
        },
      });
      const revSla = await rev();
      const early = await read("fFull");
      await new Promise((resolve) => setTimeout(resolve, 2300));
      const late = await read("fFull");
      eq(
        p,
        "control: the SLA state moved with the clock",
        [early.json?.data?.sla?.state, late.json?.data?.sla?.state],
        ["due_soon", "breached"],
      );
      eq(
        p,
        "control: the clock change left the revision alone",
        [early.json?.data?.rev, late.json?.data?.rev, await rev()],
        [revSla, revSla, revSla],
      );
      ok(p, tagOf(early) !== tagOf(late), "the SLA state changed but the tag did not");
      eq(
        p,
        "the old tag no longer validates once the SLA state moved",
        (await read("fFull", { "If-None-Match": tagOf(early) })).status,
        200,
      );

      // 3. the caller's permissions change: the same user, the same finding, other allowedActions
      const u = await makeUser(db, A, "fxvar");
      const as = (permissions) =>
        api.register("fxVar", {
          userId: u.id,
          tenantId: A.tenant.id,
          workspaces: [{ id: wsA, permissions }],
        });
      as(PERMS.viewer);
      const asViewer = await read("fxVar");
      as(PERMS.analyst);
      const asAnalyst = await read("fxVar");
      const actions = (r) => JSON.stringify(r.json?.data?.lifecycle?.allowedActions ?? null);
      ok(
        p,
        actions(asViewer) !== actions(asAnalyst),
        "control: the allowed actions did not differ",
      );
      ok(
        p,
        tagOf(asViewer) !== tagOf(asAnalyst),
        "the caller's permissions changed but the tag did not",
      );
      eq(p, "control: the permission change left the revision alone", await rev(), revSla);
      const back = await (async () => {
        as(PERMS.viewer);
        return read("fxVar");
      })();
      eq(p, "the same permissions give the same tag again", tagOf(back), tagOf(asViewer));
      // two callers at the same time: different DTOs, different tags; the same DTO, the same tag (the tag depends on the DTO only)
      const full = await read("fFull");
      ok(
        p,
        actions(full) !== actions(asViewer),
        "control: the two callers see other allowed actions",
      );
      ok(p, tagOf(full) !== tagOf(asViewer), "two callers with different DTOs share a tag");
      eq(
        p,
        "each tag is the hash of that caller's own DTO",
        [tagOf(full), tagOf(asViewer)],
        [findingEtag(full.json?.data), findingEtag(asViewer.json?.data)],
      );
      // the other caller's tag never validates this caller's read
      const crossed = await read("fFull", { "If-None-Match": tagOf(asViewer) });
      eq(p, "another caller's tag does not validate this caller's read", crossed.status, 200);

      // 4. a write answers with the tag the same caller's next read sends (one derivation for the reads and the writes)
      const claim = await api.post("fFull", `${url}/claim`, { expectedRev: await rev() });
      eq(p, "control: the claim answered", claim.status, 200);
      const next = await read("fFull");
      eq(
        p,
        "the write response carries the tag of the DTO the next read sends",
        tagOf(claim),
        tagOf(next),
      );
      ok(p, SHAPE.test(tagOf(claim) ?? ""), "the write tag has the same shape");
      return p;
    },
  },
];
