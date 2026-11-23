import { randomUUID } from "node:crypto";
import { parseMessage } from "@qmentisai/contracts";
import {
  FINDING_STATUSES,
  FORBIDDEN_FINDING_DETAIL_DTO_KEYS,
  FORBIDDEN_FINDING_DTO_KEYS,
} from "@qmentisai/shared";
import {
  SHA40,
  at,
  footprint,
  findingsOf,
  handlerConfig,
  ingest,
  runExecution,
  sast,
  sca,
  qs,
  scenario,
  secret,
  startReadApi,
} from "./findings-a-fixtures.js";

/**
 * Findings checks of part A1 (core: identity, ingestion, reads, seed) (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1). The ingestion
 * checks run the REAL findings ingestion handler in process against the disposable database, over executions, scan results, items,
 * details and tool runs written the way the engines write them (`findings-a-fixtures.js`); the read checks mount the REAL read routes
 * behind a stub authentication chain. Nothing here uses a broker, GitHub or a model. Every denial has a control (the same operation made
 * legitimately works) so a check cannot pass vacuously.
 *
 * Ids: FND-S01 (read part), FND-S03 to FND-S06, FND-S10 (stored rows), FND-S12 (reads), FND-S13, FND-S17, FNDDB-02 and FNDDB-03 through the
 * product's central transition function. A check is `{ id, name, run }`; `run(c)` receives the findings world and returns the problems.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */

const same = (p, label, got, want) => {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g !== w) p.push(`${label}: got ${g}, want ${w}`);
};
const ok = (p, cond, message) => {
  if (!cond) p.push(message);
};

/** A full baseline execution of the standard three-type result with the given items per type. */
const full = (items = {}, over = {}) => ({
  types: {
    sca: { items: items.sca ?? [] },
    sast: { items: items.sast ?? [] },
    secrets: { items: items.secrets ?? [] },
  },
  ...over,
});

// ---------------------------------------------------------------------------------------------------------------------------------
// Identity and ingestion
// ---------------------------------------------------------------------------------------------------------------------------------
const ingestionChecks = [
  {
    id: "FND-S03",
    name: "identity never crosses pipelines, workspaces or tenants (ADR-004, ID-1, FS-3, FS-4): the same item observed in two pipelines of one repository gives TWO findings with independent state and history (the unique key is per pipeline) that share only the display-only correlation key; the same item in another tenant has another correlation key; ingestion of an execution named under the wrong pipeline, workspace, repository or tenant is dropped and writes nothing; the control (the right chain) ingests",
    run: async (c) => {
      const p = [];
      const a = await scenario(c, c.A, { i: 0 });
      const b = await scenario(c, c.A, { i: 0 });
      const x = await scenario(c, c.B, { i: 0 });
      const item = () => sca({ key: "shared-lib", advisory: "CVE-2024-11111" });
      const ea = await runExecution(a, full({ sca: [item()] }));
      const eb = await runExecution(b, full({ sca: [item()] }));
      const ex = await runExecution(x, full({ sca: [item()] }));
      for (const [scn, e] of [
        [a, ea],
        [b, eb],
        [x, ex],
      ])
        await ingest(scn, e);
      const fa = (await findingsOf(a))[0];
      const fb = (await findingsOf(b))[0];
      const fx = (await findingsOf(x))[0];
      ok(p, fa && fb && fa.id !== fb.id, "the same item in two pipelines must be two findings");
      ok(
        p,
        fa.fingerprint !== fb.fingerprint,
        "the fingerprint carries the pipeline: two pipelines, two fingerprints",
      );
      ok(
        p,
        fa.correlationKey === fb.correlationKey,
        "the correlation key (display only) is shared inside one tenant",
      );
      ok(
        p,
        fa.correlationKey !== fx.correlationKey,
        "the correlation key must never be equal across tenants",
      );
      // independent state: a transition of one leaves the other alone
      await c.step(fa, "in_review", { set: { claimedByUserId: randomUUID() } });
      same(p, "the other pipeline's finding is untouched", (await findingsOf(b))[0].status, "new");
      // a forged chain: the execution of pipeline `a` named under pipeline `b`, under another workspace, repository or tenant
      const e2 = await runExecution(a, full({ sca: [sca({ key: "later-lib" })] }));
      const before = await footprint(a);
      const beforeB = await footprint(b);
      for (const [label, ids, tenantId] of [
        ["wrong pipeline", { ...a.ids(e2.id), pipelineId: b.pipeline.id }],
        ["wrong workspace", { ...a.ids(e2.id), workspaceId: c.A.ws[1].id }],
        ["wrong repository", { ...a.ids(e2.id), repositoryId: c.A.repo[1].id }],
        ["another tenant", a.ids(e2.id), c.B.tenant.id],
      ]) {
        await ingest(a, e2, { ids, tenantId });
        same(p, `${label}: nothing is written for the stated pipeline`, await footprint(a), before);
        same(p, `${label}: nothing is written for the other pipeline`, await footprint(b), beforeB);
      }
      await ingest(a, e2);
      ok(
        p,
        (await footprint(a)).findings === before.findings + 1,
        "control: the right chain ingests the new finding",
      );
      return p;
    },
  },
  {
    id: "FND-S04",
    name: "a secret never reaches a finding (SE-40, D-26, FND-016): two secrets with DIFFERENT previews behind the same masked line give the SAME fingerprint (the preview and value length are ignored), the stored finding, evidence, history, outbox and audit rows contain neither the preview nor any value-derived datum, a masked-line-less secret falls back to the ordinal anchor and still stores nothing secret; a credential-shaped string in a title or an evidence excerpt is redacted or refused instead of stored; the control (a normal code finding) stores its excerpt",
    run: async (c) => {
      const p = [];
      const scn = await scenario(c);
      const withPreview = (preview) => secret({ preview, path: "config/a.env", line: 5 });
      const e1 = await runExecution(scn, full({ secrets: [withPreview("AKIA")] }));
      await ingest(scn, e1);
      const first = (await findingsOf(scn))[0];
      const e2 = await runExecution(scn, {
        ...full({ secrets: [withPreview("wJal")] }),
        startedAt: at(10),
      });
      await ingest(scn, e2);
      const rows = await findingsOf(scn);
      same(p, "different previews, same masked line: one finding", rows.length, 1);
      same(p, "the identity is unchanged", rows[0]?.fingerprint, first.fingerprint);
      ok(p, rows[0].occurrenceCount === 2, "the second observation recurs the same finding");
      same(p, "the anchor of a masked secret", rows[0].anchorKind, "masked_line");
      // nothing secret-derived anywhere a finding writes
      const dump = JSON.stringify([
        await c.db.finding.findMany({
          where: { tenantId: scn.tenantId, pipelineId: scn.pipeline.id },
        }),
        await c.db.findingEvidence.findMany({
          where: { tenantId: scn.tenantId, pipelineId: scn.pipeline.id },
        }),
        await c.db.findingStatusHistory.findMany({
          where: { tenantId: scn.tenantId, pipelineId: scn.pipeline.id },
        }),
        await c.db
          .$queryRaw`SELECT payload FROM outbox_messages WHERE tenant_id = ${scn.tenantId}::uuid AND payload->>'pipelineId' = ${scn.pipeline.id}`,
      ]);
      for (const needle of ["AKIA", "wJal", "valueLength", "preview"])
        ok(
          p,
          !dump.includes(needle),
          `"${needle}" must never be stored in a finding row, evidence copy, history or event`,
        );
      ok(
        p,
        dump.includes("[REDACTED:api_key]"),
        "control: the masked line itself is kept as the evidence",
      );
      // a masked-line-less secret: ordinal anchor, still nothing secret
      const bare = secret({ path: "config/b.env", line: 9 });
      bare.detail.evidence = null;
      const e3 = await runExecution(scn, { ...full({ secrets: [bare] }), startedAt: at(20) });
      await ingest(scn, e3);
      const anchors = (await findingsOf(scn)).map((f) => f.anchorKind).sort();
      same(p, "the fallback anchor of a secret without a masked line", anchors, [
        "masked_line",
        "ordinal",
      ]);
      // credential shapes in free text. The scan tables refuse them (a CHECK), so the defence of the ingestion is proved by handing
      // `applyPlan` observations that carry them anyway: the title is redacted, the excerpt is refused, nothing credential-shaped is stored
      const { createFindingsIngestionRepository } = await import("@qmentisai/db");
      const { planIngestion } = await import("@qmentisai/shared");
      const repo = createFindingsIngestionRepository({ db: c.db });
      const e4 = await runExecution(scn, { types: { sast: { items: [] } }, startedAt: at(30) });
      const ids = scn.ids(e4.id);
      const facts = await repo.loadExecutionFacts(ids, "sast");
      Object.assign(facts, {
        resolutionEligibleEvent: false,
        fixConfirmations: 1,
        agentEnabled: false,
        ingestStartedMs: Date.now(),
      });
      const token = `ghp_${"a1B2".repeat(9)}`;
      const observed = [
        {
          ordinal: 0,
          scanType: "sast",
          ruleId: "r.leak",
          title: `leaks ${token}`,
          severity: "high",
          confidence: "medium",
          location: { path: "src/evil.py", startLine: 3, endLine: 3 },
          evidence: {
            kind: "block",
            startLine: 2,
            endLine: 4,
            focusStart: 3,
            focusEnd: 3,
            snippet: `# x\ntoken = "${token}"\n# y`,
          },
          toolIds: ["opengrep"],
        },
        {
          ordinal: 1,
          scanType: "sast",
          ruleId: "r.good",
          title: "fine",
          severity: "high",
          confidence: "medium",
          location: { path: "src/good.py", startLine: 4, endLine: 4 },
          evidence: {
            kind: "block",
            startLine: 3,
            endLine: 5,
            focusStart: 4,
            focusEnd: 4,
            snippet: "# x\neval(x)\n# y",
          },
          toolIds: ["opengrep"],
        },
      ];
      await c.db.$transaction(async (tx) => {
        await repo.lockAndCheck(tx, ids, "sast");
        const existing = await repo.loadExisting(
          { tenantId: scn.tenantId, pipelineId: scn.pipeline.id, scanType: "sast" },
          tx,
        );
        await repo.applyPlan(tx, planIngestion({ existing, observed, execution: facts }), facts);
      });
      const sastRows = await findingsOf(scn, { scanType: "sast" });
      same(p, "both code findings are stored", sastRows.length, 2);
      const all = JSON.stringify([
        sastRows,
        await c.db.findingEvidence.findMany({
          where: { tenantId: scn.tenantId, pipelineId: scn.pipeline.id },
        }),
        await c.db
          .$queryRaw`SELECT payload FROM outbox_messages WHERE tenant_id = ${scn.tenantId}::uuid AND payload->>'pipelineId' = ${scn.pipeline.id}`,
      ]);
      ok(
        p,
        !all.includes("ghp_"),
        "a credential-shaped string must not be stored (title redacted, excerpt refused)",
      );
      const evilRow = sastRows.find((r) => r.path === "src/evil.py");
      ok(
        p,
        evilRow && evilRow.title.includes("[REDACTED"),
        "the title keeps its words and loses the credential",
      );
      same(
        p,
        "the credential-shaped excerpt is not stored (the location is kept)",
        (
          await c.db.findingEvidence.findMany({
            where: { tenantId: scn.tenantId, findingId: evilRow.id },
          })
        ).map((r) => r.snippet),
        [null],
      );
      const good = await c.db.findingEvidence.findMany({
        where: {
          tenantId: scn.tenantId,
          findingId: sastRows.find((r) => r.path === "src/good.py").id,
        },
      });
      ok(p, good[0]?.snippet?.includes("eval(x)"), "control: the normal code excerpt is stored");
      return p;
    },
  },
  {
    id: "FND-S05a",
    name: "ingestion is idempotent and transactional (IN-4, FND-005): replaying the same execution changes nothing (rows, revisions, history, evidence, outbox, audit), two concurrent deliveries of one execution create each finding once, a unit that fails half way rolls back completely (no finding, no ingestion row, no outbox row) and the retry then succeeds; the control (the first delivery) writes the findings, the history rows, one ingestion row per scan type and the events",
    run: async (c) => {
      const p = [];
      const scn = await scenario(c);
      const e = await runExecution(
        scn,
        full({
          sca: [sca({ key: "a" }), sca({ key: "b" })],
          sast: [sast({ path: "src/x.py" })],
          secrets: [secret({ path: "c.env" })],
        }),
      );
      await ingest(scn, e);
      const first = await footprint(scn);
      same(
        p,
        "control: four findings, a history row each, an ingestion row per scan type",
        [first.findings, first.history, first.ingestions],
        [4, 4, 3],
      );
      ok(p, first.outbox >= 4, "control: a finding.created event per finding");
      await ingest(scn, e);
      same(p, "a replay changes nothing", await footprint(scn), first);
      // two deliveries racing on a fresh execution
      const e2 = await runExecution(scn, {
        types: { sca: { items: [sca({ key: "race" })] } },
        startedAt: at(10),
      });
      await Promise.all([ingest(scn, e2), ingest(scn, e2)]);
      const raced = await footprint(scn);
      same(
        p,
        "two concurrent deliveries create the finding once",
        raced.findings,
        first.findings + 1,
      );
      same(p, "and one ingestion row per scan type", raced.ingestions, first.ingestions + 3);
      // a failure half way rolls the whole unit back: a finding the database refuses (a fingerprint of the wrong shape cannot arise from
      // the plan, so the failure is injected through an unusable commit sha column length) is simulated by a trigger that raises once
      const e3 = await runExecution(scn, {
        types: { sca: { items: [sca({ key: "boom-1" }), sca({ key: "boom-2" })] } },
        startedAt: at(20),
      });
      const before = await footprint(scn);
      await c.db.$executeRawUnsafe(
        `CREATE OR REPLACE FUNCTION qm_a1_boom() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.title LIKE '%boom-2%' THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END; $$`,
      );
      await c.db.$executeRawUnsafe(
        `CREATE TRIGGER qm_a1_boom_trigger BEFORE INSERT ON findings FOR EACH ROW EXECUTE FUNCTION qm_a1_boom()`,
      );
      let failed = false;
      try {
        await ingest(scn, e3);
      } catch {
        failed = true;
      } finally {
        await c.db.$executeRawUnsafe(`DROP TRIGGER IF EXISTS qm_a1_boom_trigger ON findings`);
        await c.db.$executeRawUnsafe(`DROP FUNCTION IF EXISTS qm_a1_boom()`);
      }
      ok(p, failed, "the injected failure must surface (so the message is retried)");
      const after = await footprint(scn);
      same(
        p,
        "nothing of the failed unit is left (findings, history, outbox)",
        [after.findings, after.history, after.outbox, after.evidence],
        [before.findings, before.history, before.outbox, before.evidence],
      );
      await ingest(scn, e3);
      same(
        p,
        "the retry succeeds and creates both findings",
        (await footprint(scn)).findings,
        before.findings + 2,
      );
      return p;
    },
  },
  {
    id: "FND-S05b",
    name: "recurrence keeps identity and reopens (D-1, D-25, IN-5, IN-6, FND-002): a re-detected finding keeps its id and fingerprint, moves last_seen forward and counts the occurrence; a line shift alone does not create a new finding; a fixed-pending or verified finding reopens on ANY positive observation, even from an incremental run, with a verification record and a reopened event and the SLA clock restarted; a false positive stays a false positive; an OLDER execution never moves last_seen backwards or reopens; the control (a new item) is a new finding",
    run: async (c) => {
      const p = [];
      const scn = await scenario(c);
      const e1 = await runExecution(scn, {
        ...full({
          sast: [
            sast({ path: "src/a.py", line: 10 }),
            sast({ path: "src/fp.py", line: 4, code: "os.system(x)" }),
          ],
        }),
        startedAt: at(0),
        commitSha: SHA40(1),
      });
      await ingest(scn, e1);
      const [f] = await findingsOf(scn, { path: "src/a.py" });
      const fpRow = (await findingsOf(scn, { path: "src/fp.py" }))[0];
      // a line shift (same text) is the same finding
      const e2 = await runExecution(scn, {
        ...full({
          sast: [
            sast({ path: "src/a.py", line: 42 }),
            sast({ path: "src/fp.py", line: 4, code: "os.system(x)" }),
          ],
        }),
        startedAt: at(10),
        commitSha: SHA40(2),
      });
      await ingest(scn, e2);
      const after = (await findingsOf(scn, { path: "src/a.py" }))[0];
      same(p, "a line shift keeps the id", after.id, f.id);
      same(p, "and updates the attribute", after.startLine, 42);
      same(p, "the occurrence is counted", after.occurrenceCount, 2);
      ok(p, new Date(after.lastSeenAt) > new Date(f.lastSeenAt), "last_seen moves forward");
      same(p, "last seen commit", after.lastSeenCommitSha, SHA40(2));
      // a false positive stays one
      const fpFresh = await c.db.finding.findUnique({
        where: { tenantId_id: { tenantId: scn.tenantId, id: fpRow.id } },
      });
      let cur = await c.step(fpFresh, "in_review", { set: { claimedByUserId: randomUUID() } });
      const review = await c.review(cur, { reviewerUserId: cur.claimedByUserId });
      cur = await c.step(cur, "awaiting_approval", {
        set: { pendingReviewId: review.id },
        reason: "review_recorded",
      });
      cur = await c.step(cur, "false_positive", {
        set: { pendingReviewId: null },
        reason: "approved_fp",
      });
      const e3 = await runExecution(scn, {
        ...full({
          sast: [
            sast({ path: "src/a.py", line: 42 }),
            sast({ path: "src/fp.py", line: 4, code: "os.system(x)" }),
          ],
        }),
        startedAt: at(20),
      });
      await ingest(scn, e3);
      same(
        p,
        "a false positive stays a false positive on recurrence",
        (await findingsOf(scn, { path: "src/fp.py" }))[0].status,
        "false_positive",
      );
      // an eligible covering absence moves the finding to fixed pending verification; then an INCREMENTAL run still sees it: reopened
      const e4 = await runExecution(scn, {
        ...full({ sast: [sast({ path: "src/fp.py", line: 4, code: "os.system(x)" })] }),
        startedAt: at(30),
      });
      await ingest(scn, e4);
      const pending = (await findingsOf(scn, { path: "src/a.py" }))[0];
      same(
        p,
        "an eligible covering absence moves the finding to fixed_pending_verification",
        pending.status,
        "fixed_pending_verification",
      );
      const e5 = await runExecution(scn, {
        scanKind: "incremental",
        types: { sast: { items: [sast({ path: "src/a.py", line: 42 })], scopeKind: "targets" } },
        startedAt: at(40),
      });
      await ingest(scn, e5);
      const reopened = (await findingsOf(scn, { path: "src/a.py" }))[0];
      same(p, "ANY positive observation (even incremental) reopens", reopened.status, "reopened");
      same(p, "the reopen is counted", reopened.reopenCount, 1);
      ok(
        p,
        reopened.slaStartedAt &&
          new Date(reopened.slaStartedAt) > new Date(pending.slaStartedAt ?? 0),
        "the SLA clock restarts on reopen",
      );
      const ver = await c.db.verificationRecord.findMany({
        where: { tenantId: scn.tenantId, findingId: f.id },
        orderBy: { createdAt: "asc" },
      });
      same(
        p,
        "a recurrence is recorded",
        ver.map((v) => v.outcome),
        ["recurred"],
      );
      const events = await c.db
        .$queryRaw`SELECT type FROM outbox_messages WHERE tenant_id = ${scn.tenantId}::uuid AND payload->>'pipelineId' = ${scn.pipeline.id} AND type = 'finding.reopened'`;
      ok(p, events.length === 1, "one finding.reopened event");
      // an OLDER execution never moves last_seen backwards or reopens
      const old = await runExecution(scn, {
        ...full({ sast: [sast({ path: "src/a.py", line: 7 })] }),
        startedAt: at(-500),
      });
      const seenBefore = (await findingsOf(scn, { path: "src/a.py" }))[0];
      await ingest(scn, old);
      const seenAfter = (await findingsOf(scn, { path: "src/a.py" }))[0];
      same(
        p,
        "an older execution does not move last_seen",
        new Date(seenAfter.lastSeenAt).getTime(),
        new Date(seenBefore.lastSeenAt).getTime(),
      );
      same(p, "nor the counters", seenAfter.occurrenceCount, seenBefore.occurrenceCount);
      // control: a genuinely new item is a new finding
      const e6 = await runExecution(scn, {
        ...full({
          sast: [
            sast({ path: "src/a.py", line: 42 }),
            sast({ path: "src/new.py", line: 1, code: "exec(y)" }),
          ],
        }),
        startedAt: at(50),
      });
      await ingest(scn, e6);
      ok(
        p,
        (await findingsOf(scn, { path: "src/new.py" })).length === 1,
        "control: a new item is a new finding",
      );
      return p;
    },
  },
  {
    id: "FND-S06a",
    name: "resolution gating (D-2, D-25, 5.4, FND-004): for an incremental run, a partial, failed, cancelled and timed-out execution, an untrusted fork, a tag and a non-baseline branch, an incomplete, a truncated, a tool-degraded, a legacy (no coverage), a targeted-scope and a tool-not-run result, a gap that covers the finding, a type disabled after the finding appeared, an execution OLDER than the watermark, and an event that disagrees with the database in either direction, NO finding changes status; the control (a full, trusted, complete, covering baseline run) moves every finding to fixed pending verification",
    run: async (c) => {
      const p = [];
      const seed = async () => {
        const scn = await scenario(c);
        const e0 = await runExecution(
          scn,
          full({
            sca: [sca({ key: "gate-lib" })],
            sast: [sast({ path: "src/gate.py" })],
            secrets: [secret({ path: "gate.env" })],
          }),
        );
        await ingest(scn, e0);
        return scn;
      };
      const statuses = async (scn) =>
        Object.fromEntries((await findingsOf(scn)).map((f) => [f.scanType, f.status]));
      const none = () => full({}, { startedAt: at(100) });
      const cases = [
        ["incremental run", { ...none(), scanKind: "incremental" }],
        ["partial execution", { ...none(), status: "partial" }],
        ["failed execution", { ...none(), status: "failed" }],
        ["cancelled execution", { ...none(), status: "cancelled" }],
        ["timed-out execution", { ...none(), status: "timed_out" }],
        ["untrusted fork", { ...none(), trust: "untrusted_fork" }],
        ["a tag", { ...none(), refType: "tag", refName: "v1.0" }],
        ["a non-baseline branch", { ...none(), refName: "feature/x" }],
        [
          "an incomplete result",
          {
            startedAt: at(100),
            types: {
              sca: { completeness: "incomplete" },
              sast: { completeness: "incomplete" },
              secrets: { completeness: "incomplete" },
            },
          },
        ],
        [
          "a truncated result",
          {
            startedAt: at(100),
            types: {
              sca: { truncated: true, completeness: "incomplete" },
              sast: { truncated: true, completeness: "incomplete" },
              secrets: { truncated: true, completeness: "incomplete" },
            },
          },
        ],
        [
          "degraded tools",
          {
            startedAt: at(100),
            types: {
              sca: {
                completeness: "incomplete",
                coverage: {
                  state: "degraded",
                  coverageGaps: [],
                  toolsDegraded: 1,
                  tools: [{ toolId: "trivy", status: "succeeded" }],
                },
              },
              sast: {
                completeness: "incomplete",
                coverage: { state: "degraded", coverageGaps: [], toolsDegraded: 1, tools: [] },
              },
              secrets: {
                completeness: "incomplete",
                coverage: { state: "degraded", coverageGaps: [], toolsDegraded: 1, tools: [] },
              },
            },
          },
        ],
        [
          "no coverage statement (legacy engine)",
          {
            startedAt: at(100),
            types: {
              sca: { coverage: null },
              sast: { coverage: null },
              secrets: { coverage: null },
            },
          },
        ],
        [
          "targeted scope",
          {
            startedAt: at(100),
            types: {
              sca: { scopeKind: "targets" },
              sast: { scopeKind: "targets" },
              secrets: { scopeKind: "full_filtered" },
            },
          },
        ],
        [
          "a tool that did not run",
          {
            startedAt: at(100),
            types: {
              sca: { toolStatus: "failed" },
              sast: { toolStatus: "failed" },
              secrets: { toolStatus: "failed" },
            },
          },
        ],
      ];
      for (const [label, spec] of cases) {
        const scn = await seed();
        const e = await runExecution(scn, spec);
        await ingest(scn, e);
        same(p, `${label}: nothing is marked fixed`, await statuses(scn), {
          sca: "new",
          sast: "new",
          secrets: "new",
        });
      }
      // a coverage gap that covers the finding (ecosystem npm), the others are resolved
      {
        const scn = await seed();
        const gap = {
          state: "complete",
          coverageGaps: ["npm"],
          toolsDegraded: 0,
          tools: [{ toolId: "trivy", status: "succeeded" }],
        };
        const e = await runExecution(scn, {
          startedAt: at(100),
          types: { sca: { coverage: gap }, sast: {}, secrets: {} },
        });
        await ingest(scn, e);
        const s = await statuses(scn);
        same(p, "a coverage gap covering the finding keeps it", s.sca, "new");
        same(
          p,
          "control: the other types, with full coverage, resolve",
          [s.sast, s.secrets],
          ["fixed_pending_verification", "fixed_pending_verification"],
        );
      }
      // a type disabled after the finding appeared: the later execution runs a version without it
      {
        const scn = await seed();
        const v2 = await c.version(scn.pipeline, 2, {
          config: {
            schemaVersion: 1,
            triggers: [],
            scans: { sca: { enabled: true }, secrets: { enabled: true } },
          },
        });
        const e = await runExecution(
          { ...scn, version: v2 },
          { startedAt: at(100), types: { sca: {}, secrets: {} } },
        );
        await ingest(scn, e);
        same(
          p,
          "a type disabled later: its finding is never resolved",
          (await statuses(scn)).sast,
          "new",
        );
      }
      // an execution OLDER than the watermark never resolves
      {
        const scn = await seed();
        const old = await runExecution(scn, { ...full({}), startedAt: at(-300) });
        await ingest(scn, old);
        same(p, "an execution older than the watermark does not resolve", await statuses(scn), {
          sca: "new",
          sast: "new",
          secrets: "new",
        });
      }
      // the event and the database must agree: either disagreement resolves nothing
      {
        const scn = await seed();
        const inc = await runExecution(scn, { ...none(), scanKind: "incremental" });
        await ingest(scn, inc, { eligible: true });
        same(
          p,
          "an event that claims eligibility for an incremental run changes nothing",
          await statuses(scn),
          { sca: "new", sast: "new", secrets: "new" },
        );
        const eligibleRun = await runExecution(scn, { ...none(), startedAt: at(200) });
        await ingest(scn, eligibleRun, { eligible: false });
        same(
          p,
          "an event that denies eligibility the database grants changes nothing (the minimum wins)",
          await statuses(scn),
          { sca: "new", sast: "new", secrets: "new" },
        );
      }
      // control
      const scn = await seed();
      const e = await runExecution(scn, none());
      await ingest(scn, e);
      same(p, "control: an eligible, covering, complete baseline absence", await statuses(scn), {
        sca: "fixed_pending_verification",
        sast: "fixed_pending_verification",
        secrets: "fixed_pending_verification",
      });
      return p;
    },
  },
  {
    id: "FND-S06b",
    name: "the two-step fix (D-25, OD-5, SM-14, SM-15, SM-16): an eligible absence gives fixed pending verification (absent count 1, the SLA stopped), a SECOND eligible absence gives verified fixed with a verification record, and a later detection reopens it (reopen count, recurred record); a HUMAN fix claim is verified by the next eligible absence and reopens as `failed` when the finding is detected again; a pending review is superseded by the automatic fix; accepted risk, suppression and false positive are never resolved by absence",
    run: async (c) => {
      const p = [];
      const scn = await scenario(c);
      const keep = sast({ path: "src/keep.py", line: 1, code: "keep(1)" });
      const gone = sast({ path: "src/gone.py", line: 2, code: "gone(2)" });
      const fp = sast({ path: "src/fp.py", line: 3, code: "fp(3)" });
      const risk = sast({ path: "src/risk.py", line: 4, code: "risk(4)" });
      const review = sast({ path: "src/review.py", line: 5, code: "review(5)" });
      const claimed = sast({ path: "src/claimed.py", line: 6, code: "claimed(6)" });
      const e0 = await runExecution(scn, {
        ...full({ sast: [keep, gone, fp, risk, review, claimed] }),
        startedAt: at(0),
      });
      await ingest(scn, e0);
      const row = async (path) => (await findingsOf(scn, { path }))[0];
      // set up the parked states through the legitimate machine
      let f = await row("src/fp.py");
      f = await c.step(f, "in_review", { set: { claimedByUserId: randomUUID() } });
      const rv = await c.review(f, {
        decision: "false_positive",
        reviewerUserId: f.claimedByUserId,
      });
      f = await c.step(f, "awaiting_approval", {
        set: { pendingReviewId: rv.id },
        reason: "review_recorded",
      });
      await c.step(f, "false_positive", { set: { pendingReviewId: null }, reason: "approved_fp" });
      const pending = await row("src/review.py");
      let r = await c.step(pending, "in_review", { set: { claimedByUserId: randomUUID() } });
      const rv2 = await c.review(r, { reviewerUserId: r.claimedByUserId });
      r = await c.step(r, "awaiting_approval", {
        set: { pendingReviewId: rv2.id },
        reason: "review_recorded",
      });
      // accepted risk: an approved exception and the finding in `accepted_risk` with its active pointer
      const k = await row("src/risk.py");
      const ex = await c.exception(k);
      await c.db.findingException.update({
        where: { tenantId_id: { tenantId: scn.tenantId, id: ex.id } },
        data: { state: "approved", decidedAt: new Date() },
      });
      await c.step(k, "accepted_risk", {
        set: {
          activeExceptionId: ex.id,
          exceptionExpiresAt: ex.expiresAt,
          acceptedSeverity: "high",
        },
        reason: "risk_accepted",
      });
      // a human fix claim: new -> in_review -> awaiting -> approved -> assigned -> fixed pending (SM-13)
      let h = await row("src/claimed.py");
      const dev = randomUUID();
      h = await c.step(h, "in_review", { set: { claimedByUserId: randomUUID() } });
      const rv3 = await c.review(h, { reviewerUserId: h.claimedByUserId });
      h = await c.step(h, "awaiting_approval", {
        set: { pendingReviewId: rv3.id },
        reason: "review_recorded",
      });
      h = await c.step(h, "approved", { set: { pendingReviewId: null }, reason: "approved_tp" });
      h = await c.step(h, "assigned", {
        set: { assigneeUserId: dev, assignedAt: new Date() },
        reason: "assigned",
      });
      await c.step(h, "fixed_pending_verification", {
        set: { fixClaimedAt: new Date() },
        reason: "fix_submitted",
      });
      // first eligible absence of everything but `keep`
      const e1 = await runExecution(scn, { ...full({ sast: [keep] }), startedAt: at(10) });
      await ingest(scn, e1);
      const gone1 = await row("src/gone.py");
      same(
        p,
        "an eligible absence: fixed pending verification",
        [gone1.status, gone1.absentCount],
        ["fixed_pending_verification", 1],
      );
      ok(p, gone1.slaDueAt === null, "the SLA clock stops while the fix is pending verification");
      same(
        p,
        "a false positive is not resolved by absence",
        (await row("src/fp.py")).status,
        "false_positive",
      );
      same(
        p,
        "a pending review is superseded by the automatic fix",
        [(await row("src/review.py")).status, (await row("src/review.py")).pendingReviewId],
        ["fixed_pending_verification", null],
      );
      same(
        p,
        "the superseded review row",
        (
          await c.db.findingReview.findUnique({
            where: { tenantId_id: { tenantId: scn.tenantId, id: rv2.id } },
          })
        ).state,
        "superseded",
      );
      same(
        p,
        "a human fix claim is verified by the next eligible absence",
        (await row("src/claimed.py")).status,
        "verified_fixed",
      );
      same(p, "the kept finding is untouched", (await row("src/keep.py")).status, "new");
      // second eligible absence verifies
      const e2 = await runExecution(scn, { ...full({ sast: [keep] }), startedAt: at(20) });
      await ingest(scn, e2);
      const gone2 = await row("src/gone.py");
      same(p, "a second eligible absence verifies the fix", gone2.status, "verified_fixed");
      ok(
        p,
        gone2.verifiedAt !== null && gone2.closedAt !== null,
        "verified and closed timestamps are set",
      );
      const ver = await c.db.verificationRecord.findMany({
        where: { tenantId: scn.tenantId, findingId: gone2.id },
      });
      same(
        p,
        "the verification record",
        ver.map((v) => v.outcome),
        ["verified"],
      );
      // the detection returns: reopened, recurred
      const e3 = await runExecution(scn, { ...full({ sast: [keep, gone] }), startedAt: at(30) });
      await ingest(scn, e3);
      const back = await row("src/gone.py");
      same(
        p,
        "a later detection reopens",
        [back.status, back.reopenCount, back.absentCount],
        ["reopened", 1, 0],
      );
      same(
        p,
        "the recurrence is recorded",
        (
          await c.db.verificationRecord.findMany({
            where: { tenantId: scn.tenantId, findingId: back.id },
            orderBy: { createdAt: "asc" },
          })
        ).map((v) => v.outcome),
        ["verified", "recurred"],
      );
      // the human-claimed finding returns: the claim FAILED
      const e4 = await runExecution(scn, {
        ...full({ sast: [keep, gone, claimed] }),
        startedAt: at(40),
      });
      await ingest(scn, e4);
      const cl = await row("src/claimed.py");
      same(p, "a verified human-claimed fix that returns reopens", cl.status, "reopened");
      // history is complete and ordered
      const hist = await c.db.findingStatusHistory.findMany({
        where: { tenantId: scn.tenantId, findingId: back.id },
        orderBy: { rev: "asc" },
      });
      same(
        p,
        "the history of the cycle",
        hist.map((x) => x.toStatus),
        ["new", "fixed_pending_verification", "verified_fixed", "reopened"],
      );
      ok(
        p,
        hist.slice(1).every((x) => x.actorType === "system" && x.actorCode === "ingestion"),
        "automatic transitions are system:ingestion",
      );
      return p;
    },
  },
  {
    id: "FND-S06c",
    name: "only a trusted execution on the tracked baseline is ingested (D-24, OD-1, IN-3): an untrusted fork, a tag, a pull request, another branch, a repository without a default branch and a deleted pipeline each produce a recorded SKIP (reason named) and NO finding; the control (the default branch, trusted) creates the finding; the pipeline's tracked ref, when set, replaces the default branch",
    run: async (c) => {
      const p = [];
      const item = () => full({ sca: [sca({ key: "baseline-lib" })] });
      const skipOf = async (scn) =>
        (
          await c.db.findingIngestion.findMany({
            where: { tenantId: scn.tenantId, pipelineId: scn.pipeline.id, scanType: "sca" },
          })
        ).map((r) => [r.status, r.skipReason]);
      for (const [label, spec, reason] of [
        ["an untrusted fork", { trust: "untrusted_fork" }, "untrusted_fork"],
        ["a tag", { refType: "tag", refName: "v2" }, "not_baseline_ref"],
        ["a pull request", { refType: "pull_request", refName: "12" }, "not_baseline_ref"],
        ["another branch", { refName: "release/1" }, "not_baseline_ref"],
      ]) {
        const scn = await scenario(c);
        const e = await runExecution(scn, { ...item(), ...spec });
        await ingest(scn, e);
        same(p, `${label}: no finding`, (await findingsOf(scn)).length, 0);
        same(p, `${label}: a recorded skip`, await skipOf(scn), [["skipped", reason]]);
      }
      {
        const scn = await scenario(c);
        await c.db.repository.update({
          where: { id: scn.repositoryId },
          data: { defaultBranch: null },
        });
        const e = await runExecution(scn, item());
        await c.db.repository.update({
          where: { id: scn.repositoryId },
          data: { defaultBranch: null },
        });
        await ingest(scn, e);
        same(p, "no tracked baseline: skipped no_baseline", await skipOf(scn), [
          ["skipped", "no_baseline"],
        ]);
        await c.db.repository.update({
          where: { id: scn.repositoryId },
          data: { defaultBranch: "main" },
        });
      }
      {
        const scn = await scenario(c);
        const e = await runExecution(scn, item());
        await c.db.pipeline.update({
          where: { id: scn.pipeline.id },
          data: { deletedAt: new Date(), deletedByUserId: scn.tree.user.id },
        });
        await ingest(scn, e);
        same(
          p,
          "a deleted pipeline: skipped pipeline_deleted, no finding",
          [await skipOf(scn), (await findingsOf(scn)).length],
          [[["skipped", "pipeline_deleted"]], 0],
        );
      }
      {
        // the tracked ref of the pipeline replaces the default branch
        const scn = await scenario(c);
        await c.db.findingPipelineState.create({
          data: {
            tenantId: scn.tenantId,
            workspaceId: scn.workspaceId,
            repositoryId: scn.repositoryId,
            pipelineId: scn.pipeline.id,
            trackedRef: "release/1",
          },
        });
        const onDefault = await runExecution(scn, item());
        await ingest(scn, onDefault);
        same(p, "with a tracked ref, the default branch is not the baseline", await skipOf(scn), [
          ["skipped", "not_baseline_ref"],
        ]);
        const onTracked = await runExecution(scn, {
          ...item(),
          refName: "release/1",
          startedAt: at(5),
        });
        await ingest(scn, onTracked);
        same(p, "the tracked ref is ingested", (await findingsOf(scn)).length, 1);
      }
      {
        const scn = await scenario(c);
        const e = await runExecution(scn, item());
        await ingest(scn, e);
        same(
          p,
          "control: the trusted default branch creates the finding",
          [(await findingsOf(scn)).length, (await findingsOf(scn))[0]?.originTrust],
          [1, "trusted"],
        );
      }
      return p;
    },
  },
  {
    id: "FND-S05c",
    name: "the ingestion flag defaults OFF and then nothing is ingested (IN-1): the worker configuration reads FINDINGS_INGESTION_ENABLED as false by default, a handler run with the flag off writes no finding, history, ingestion row or event for an execution that WOULD ingest (the control with the flag on does), the orchestrator writes the second outbox row only inside the flag, and the producer's second row has the documented message id and queue and parses as the same `pipeline.execution.completed` envelope",
    run: async (c) => {
      const p = [];
      const { loadWorkerConfig } = await import("../../../../../workers/src/config.js");
      const baseEnv = {
        NODE_ENV: "test",
        RABBITMQ_URL: "amqp://x:y@127.0.0.1:1",
        DATABASE_URL: "postgresql://x@127.0.0.1:1/x",
      };
      same(
        p,
        "default flag",
        loadWorkerConfig(baseEnv, { workerName: "findings" }).findings.ingestionEnabled,
        false,
      );
      same(
        p,
        "flag on",
        loadWorkerConfig(
          { ...baseEnv, FINDINGS_INGESTION_ENABLED: "true" },
          { workerName: "findings" },
        ).findings.ingestionEnabled,
        true,
      );
      const scn = await scenario(c);
      const e = await runExecution(scn, full({ sca: [sca({ key: "flag-lib" })] }));
      const before = await footprint(scn);
      await ingest(scn, e, { config: handlerConfig({ ingestionEnabled: false }) });
      same(p, "flag off: nothing is written", await footprint(scn), before);
      await ingest(scn, e);
      ok(p, (await footprint(scn)).findings === before.findings + 1, "control: flag on ingests");
      // the orchestrator: the second row only inside the flag
      const { readFile } = await import("node:fs/promises");
      const source = await readFile(
        new URL("../../../../../workers/src/execution/orchestrator.js", import.meta.url),
        "utf8",
      );
      const guard = source.indexOf("config.findings?.ingestionEnabled === true");
      const call = source.indexOf("producer.completedForFindings(");
      ok(
        p,
        guard > 0 && call > guard && call - guard < 200,
        "the orchestrator writes the findings row only inside the ingestion flag",
      );
      // the producer's second row
      const { createMessageProducer } =
        await import("../../../../../workers/src/execution/messages.js");
      const producer = createMessageProducer({ db: c.db });
      const exec = {
        id: e.id,
        tenantId: e.tenantId,
        workspaceId: e.workspaceId,
        repositoryId: e.repositoryId,
        pipelineId: e.pipelineId,
        correlationId: null,
      };
      const payload = {
        executionId: e.id,
        pipelineId: e.pipelineId,
        repositoryId: e.repositoryId,
        workspaceId: e.workspaceId,
        status: "succeeded",
        statusReason: null,
        scanKind: "full",
        trust: "trusted",
        refType: "branch",
        refName: "main",
        commitSha: SHA40(1),
        pullRequestNumber: null,
        configVersion: 1,
        configHash: "h",
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        cancelRequested: false,
        resolutionEligible: true,
        tasks: [],
      };
      await c.db.$transaction(async (tx) => {
        await producer.completedForFindings(tx, exec, payload, null);
      });
      const rows = await c.db.outboxMessage.findMany({
        where: { tenantId: e.tenantId, messageId: `execution-completed-findings-${e.id}` },
      });
      same(
        p,
        "one row, queue findings",
        rows.map((r) => r.queue),
        ["findings"],
      );
      const parsed = parseMessage(rows[0].payload);
      same(
        p,
        "the same event type and payload",
        [parsed.type, parsed.payload.executionId],
        ["pipeline.execution.completed", e.id],
      );
      return p;
    },
  },
  // @@MORE@@
];

// ---------------------------------------------------------------------------------------------------------------------------------
// The central transition function (SPEC 6.2) and the messages the findings code writes
// ---------------------------------------------------------------------------------------------------------------------------------
/** A real user (the audit log keeps a foreign key to users). */
const newUser = async (c) =>
  (
    await c.db.user.create({
      data: { email: `fnd-${randomUUID()}@fnd.example`, name: "Findings suite user" },
    })
  ).id;
const rejects = async (fn) => {
  try {
    await fn();
    return null;
  } catch (error) {
    return error;
  }
};
const countsOf = async (c, f) => {
  const [h, a, o, row] = await Promise.all([
    c.db.findingStatusHistory.count({ where: { tenantId: f.tenantId, findingId: f.id } }),
    c.db.auditLog.count({
      where: { tenantId: f.tenantId, targetId: f.id, action: { startsWith: "finding." } },
    }),
    c.db.outboxMessage.count({
      where: { tenantId: f.tenantId, messageId: { startsWith: `finding-status-${f.id}-` } },
    }),
    c.db.finding.findUnique({ where: { tenantId_id: { tenantId: f.tenantId, id: f.id } } }),
  ]);
  return { history: h, audit: a, outbox: o, status: row.status, rev: row.rev };
};

const transitionChecks = [
  {
    id: "FNDDB-02",
    name: "the central transition function (SPEC 6.2, FND-006, FND-S08): a legal chain of human and system transitions each writes exactly ONE history row, ONE audit entry and ONE outbox hint with the next revision, in the caller's transaction (a rollback leaves nothing); an illegal pair, a transition of the wrong actor kind, a reason that does not belong to the transition, a stale revision, a foreign workspace or tenant, an unknown column and a credential-shaped note are all refused with the finding untouched; two concurrent transitions at one revision let exactly one through",
    run: async (c) => {
      const { transitionFinding, FindingConflictError, FindingNotFoundError } =
        await import("@qmentisai/db");
      const p = [];
      const pipeline = await c.pipeline(c.A, 0);
      const f = await c.finding(pipeline);
      const scope = { tenantId: f.tenantId, workspaceId: f.workspaceId };
      const user = await newUser(c);
      const user2 = await newUser(c);
      const user3 = await newUser(c);
      const system = { type: "system", code: "ingestion" };
      const T = (input) =>
        c.db.$transaction((tx) => transitionFinding(tx, { scope, findingId: f.id, ...input }));
      let rev = 0;
      const chain = [
        ["in_review", { type: "user", userId: user }, "review_started", { claimedByUserId: user }],
        ["awaiting_approval", { type: "user", userId: user }, "review_recorded", "review"],
        ["approved", { type: "user", userId: user2 }, "approved_tp", { pendingReviewId: null }],
        [
          "assigned",
          { type: "user", userId: user3 },
          "assigned",
          { assigneeUserId: user2, assignedAt: new Date() },
        ],
        [null, { type: "user", userId: user3 }, "reassigned", { assigneeUserId: user }],
        ["in_remediation", { type: "user", userId: user }, "work_started", {}],
        [
          "fixed_pending_verification",
          { type: "user", userId: user },
          "fix_submitted",
          { fixClaimedAt: new Date() },
        ],
        ["verified_fixed", system, "verified", { verifiedAt: new Date(), closedAt: new Date() }],
        [
          "reopened",
          system,
          "recurred",
          { reopenCount: { increment: 1 }, closedAt: null, fixClaimedAt: null },
        ],
        [
          "assigned",
          { type: "user", userId: user3 },
          "assigned",
          { assigneeUserId: user2, assignedAt: new Date() },
        ],
      ];
      for (const [to, actor, reasonCode, columns] of chain) {
        const before = await countsOf(c, f);
        const cols =
          columns === "review"
            ? {
                pendingReviewId: (
                  await c.review(
                    await c.db.finding.findUnique({
                      where: { tenantId_id: { tenantId: f.tenantId, id: f.id } },
                    }),
                    { reviewerUserId: user },
                  )
                ).id,
              }
            : columns;
        const done = await T({
          to,
          actor,
          reasonCode,
          columns: cols,
          expectedRev: rev,
          links: { executionId: randomUUID(), commitSha: SHA40(3) },
        });
        rev += 1;
        const after = await countsOf(c, f);
        same(
          p,
          `${reasonCode}: one history row, one audit entry, one hint, one revision`,
          [
            after.history - before.history,
            after.audit - before.audit,
            after.outbox - before.outbox,
            after.rev,
          ],
          [1, 1, 1, rev],
        );
        same(
          p,
          `${reasonCode}: the result names the revision and the target`,
          [done.rev, done.to],
          [rev, to ?? done.from],
        );
      }
      // every hint parses against the catalog and carries ids, statuses and the revision only
      const hints = await c.db.outboxMessage.findMany({
        where: { tenantId: f.tenantId, messageId: { startsWith: `finding-status-${f.id}-` } },
        orderBy: { createdAt: "asc" },
      });
      same(p, "one hint per transition", hints.length, chain.length);
      for (const h of hints) {
        const m = parseMessage(h.payload);
        same(
          p,
          `hint ${m.messageId}: type, queue and keys`,
          [m.type, h.queue, Object.keys(m.payload).sort()],
          [
            "finding.status_changed",
            "realtime",
            ["actorType", "findingId", "fromStatus", "rev", "toStatus", "workspaceId"],
          ],
        );
      }
      const audit = await c.db.auditLog.findMany({
        where: { tenantId: f.tenantId, targetId: f.id },
        orderBy: { createdAt: "asc" },
      });
      ok(
        p,
        audit.every((a) => a.targetType === "finding" && a.workspaceId === f.workspaceId),
        "every audit entry names the finding and its workspace",
      );
      ok(
        p,
        audit.some(
          (a) =>
            a.actorType === "system" && a.actorUserId === null && a.action === "finding.verified",
        ),
        "a system transition is audited as the system, with no user id",
      );
      // refusals leave the finding untouched
      const base = await countsOf(c, f);
      const refuse = async (label, input, expected) => {
        const error = await rejects(() => T(input));
        const got =
          error instanceof FindingConflictError
            ? error.reason
            : error instanceof FindingNotFoundError
              ? "not_found"
              : error?.name;
        same(p, `${label}: refused`, got, expected);
        same(p, `${label}: the finding is untouched`, await countsOf(c, f), base);
      };
      await refuse(
        "an illegal pair (assigned to verified_fixed)",
        { to: "verified_fixed", actor: { type: "user", userId: user }, reasonCode: "verified" },
        "transition_not_allowed",
      );
      await refuse(
        "a user doing the system verify",
        {
          to: "verified_fixed",
          actor: { type: "user", userId: user },
          reasonCode: "verified",
          expectedRev: rev,
        },
        "transition_not_allowed",
      );
      await refuse(
        "a system actor doing a human assignment",
        { to: "assigned", actor: system, reasonCode: "assigned" },
        "transition_not_allowed",
      );
      await refuse(
        "a reason that belongs to another transition",
        {
          to: "in_remediation",
          actor: { type: "user", userId: user },
          reasonCode: "verified",
          columns: {},
        },
        "transition_not_allowed",
      );
      await refuse(
        "a stale revision",
        {
          to: "in_remediation",
          actor: { type: "user", userId: user },
          reasonCode: "work_started",
          expectedRev: rev - 1,
        },
        "stale_revision",
      );
      const wrongWs = await rejects(() =>
        c.db.$transaction((tx) =>
          transitionFinding(tx, {
            scope: { ...scope, workspaceId: c.A.ws[1].id },
            findingId: f.id,
            to: "in_remediation",
            actor: { type: "user", userId: user },
            reasonCode: "work_started",
          }),
        ),
      );
      ok(
        p,
        wrongWs instanceof FindingNotFoundError,
        "another workspace of the same tenant finds nothing",
      );
      const wrongTenant = await rejects(() =>
        c.db.$transaction((tx) =>
          transitionFinding(tx, {
            scope: { tenantId: c.B.tenant.id, workspaceId: c.B.ws[0].id },
            findingId: f.id,
            to: "in_remediation",
            actor: { type: "user", userId: user },
            reasonCode: "work_started",
          }),
        ),
      );
      ok(
        p,
        wrongTenant instanceof FindingNotFoundError,
        "another tenant finds nothing (never by id alone)",
      );
      ok(
        p,
        (
          await rejects(() =>
            T({
              to: "in_remediation",
              actor: { type: "user", userId: user },
              reasonCode: "work_started",
              columns: { status: "verified_fixed" },
            }),
          )
        )?.name === "TypeError",
        "a column outside the derived set (status) is refused",
      );
      ok(
        p,
        (
          await rejects(() =>
            T({
              to: "in_remediation",
              actor: { type: "user", userId: user },
              reasonCode: "work_started",
              columns: { rev: 99 },
            }),
          )
        )?.name === "TypeError",
        "a column outside the derived set (rev) is refused",
      );
      ok(
        p,
        (
          await rejects(() =>
            T({
              to: "in_remediation",
              actor: { type: "user", userId: user },
              reasonCode: "work_started",
              note: `see ghp_${"a1B2".repeat(9)}`,
            }),
          )
        )?.name === "TypeError",
        "a credential-shaped note is refused",
      );
      same(p, "all refusals changed nothing", await countsOf(c, f), base);
      // atomicity: the caller's transaction rolls the whole transition back
      const boom = await rejects(() =>
        c.db.$transaction(async (tx) => {
          await transitionFinding(tx, {
            scope,
            findingId: f.id,
            to: "in_remediation",
            actor: { type: "user", userId: user },
            reasonCode: "work_started",
          });
          throw new Error("later step failed");
        }),
      );
      ok(p, boom?.message === "later step failed", "the caller's failure surfaces");
      same(
        p,
        "a rolled-back transition leaves no history, audit, hint or status change",
        await countsOf(c, f),
        base,
      );
      // control and concurrency: two transitions at one revision, exactly one wins
      const race = await Promise.allSettled([
        T({
          to: "in_remediation",
          actor: { type: "user", userId: user },
          reasonCode: "work_started",
          expectedRev: rev,
        }),
        T({
          to: null,
          actor: { type: "user", userId: user },
          reasonCode: "reassigned",
          expectedRev: rev,
          columns: { assigneeUserId: user3 },
        }),
      ]);
      same(
        p,
        "exactly one of two concurrent transitions at the same revision succeeds",
        race.filter((r) => r.status === "fulfilled").length,
        1,
      );
      const loser = race.find((r) => r.status === "rejected");
      same(p, "the loser is a stale-revision conflict", loser?.reason?.reason, "stale_revision");
      same(
        p,
        "control: the winner advanced the revision once",
        (await countsOf(c, f)).rev,
        rev + 1,
      );
      return p;
    },
  },
  {
    id: "FNDDB-03",
    name: "derived columns and the messages findings write (SPEC 5.9 SL-2, 6.2, 9.1, ADR-011): the severity override sets the effective severity and rank together, a stopped status clears the SLA due date, a reopen restarts the SLA clock from now with the tenant's target of the effective severity (a tenant row beats the default, `info` has none), an approval from `false_positive` re-arms the clock from first detection, and every message the ingestion and the transition function build parses against the contracts catalog on the documented queue with ids, enums and the title only; the queue names equal the contracts' queue names",
    run: async (c) => {
      const { transitionFinding, FINDING_QUEUES } = await import("@qmentisai/db");
      const { QUEUE_NAMES } = await import("@qmentisai/contracts");
      const p = [];
      same(p, "the realtime queue name", FINDING_QUEUES.REALTIME, QUEUE_NAMES.REALTIME);
      same(p, "the agent queue name", FINDING_QUEUES.FINDINGS_AGENT, QUEUE_NAMES.FINDINGS_AGENT);
      const pipeline = await c.pipeline(c.A, 0);
      const started = new Date(Date.now() - 10 * 86_400_000);
      const f = await c.finding(pipeline, {
        slaStartedAt: started,
        slaDueAt: new Date(started.getTime() + 30 * 86_400_000),
        toolSeverity: "high",
        severity: "high",
        severityRank: 3,
      });
      const scope = { tenantId: f.tenantId, workspaceId: f.workspaceId };
      const user = await newUser(c);
      const other = await newUser(c);
      const T = (input) =>
        c.db.$transaction((tx) => transitionFinding(tx, { scope, findingId: f.id, ...input }));
      const row = () =>
        c.db.finding.findUnique({ where: { tenantId_id: { tenantId: f.tenantId, id: f.id } } });
      const review = async () => (await c.review(await row(), { reviewerUserId: user })).id;
      await T({
        to: "in_review",
        actor: { type: "user", userId: user },
        reasonCode: "review_started",
        columns: { claimedByUserId: user },
      });
      await T({
        to: "awaiting_approval",
        actor: { type: "user", userId: user },
        reasonCode: "review_recorded",
        columns: { pendingReviewId: await review() },
      });
      const a = await T({
        to: "approved",
        actor: { type: "user", userId: other },
        reasonCode: "approved_tp",
        columns: { pendingReviewId: null, severityOverride: "critical" },
      });
      const approved = await row();
      same(
        p,
        "the override sets severity and rank together (the CHECK holds)",
        [
          approved.severity,
          approved.severityRank,
          approved.toolSeverity,
          approved.severityOverride,
        ],
        ["critical", 4, "high", "critical"],
      );
      ok(p, a.rev === 3 && approved.slaDueAt !== null, "the SLA clock keeps running on approval");
      await T({
        to: "assigned",
        actor: { type: "user", userId: other },
        reasonCode: "assigned",
        columns: { assigneeUserId: user, assignedAt: new Date() },
      });
      await T({
        to: "fixed_pending_verification",
        actor: { type: "user", userId: user },
        reasonCode: "fix_submitted",
        columns: { fixClaimedAt: new Date() },
      });
      same(p, "a stopped status clears the SLA due date", (await row()).slaDueAt, null);
      await T({
        to: "verified_fixed",
        actor: { type: "system", code: "ingestion" },
        reasonCode: "verified",
        columns: { verifiedAt: new Date(), closedAt: new Date() },
      });
      // a tenant row beats the default (critical 168 h by default)
      await c.db.findingSlaTarget.upsert({
        where: { tenantId_severity: { tenantId: f.tenantId, severity: "critical" } },
        create: { tenantId: f.tenantId, severity: "critical", hours: 24 },
        update: { hours: 24 },
      });
      const before = Date.now();
      await T({
        to: "reopened",
        actor: { type: "system", code: "ingestion" },
        reasonCode: "recurred",
        columns: { reopenCount: { increment: 1 } },
      });
      const reopened = await row();
      ok(
        p,
        new Date(reopened.slaStartedAt).getTime() >= before - 1000,
        "a reopen restarts the SLA clock from now",
      );
      same(
        p,
        "with the tenant's target of the effective severity (24 h)",
        Math.round((new Date(reopened.slaDueAt) - new Date(reopened.slaStartedAt)) / 3_600_000),
        24,
      );
      same(
        p,
        "the reopen is counted and stamped",
        [reopened.reopenCount, reopened.reopenedAt !== null],
        [1, true],
      );
      await c.db.findingSlaTarget.delete({
        where: { tenantId_severity: { tenantId: f.tenantId, severity: "critical" } },
      });
      // `info` has no target: a reopened info finding has no due date
      const info = await c.finding(pipeline, {
        toolSeverity: "info",
        severity: "info",
        severityRank: 0,
      });
      const walk = async (g, steps) => {
        let cur = g;
        for (const [to, actor, reasonCode, columns] of steps) {
          await c.db.$transaction((tx) =>
            transitionFinding(tx, { scope, findingId: cur.id, to, actor, reasonCode, columns }),
          );
          cur = await c.db.finding.findUnique({
            where: { tenantId_id: { tenantId: f.tenantId, id: cur.id } },
          });
        }
        return cur;
      };
      const sys = { type: "system", code: "ingestion" };
      const infoDone = await walk(info, [
        ["fixed_pending_verification", sys, "absent_in_complete_scan", { absentCount: 1 }],
        ["reopened", sys, "recurred", { reopenCount: { increment: 1 } }],
      ]);
      same(p, "an info finding has no SLA target after a reopen", infoDone.slaDueAt, null);
      // a false positive reopened for review and approved again re-arms the clock from first detection
      const g = await c.finding(pipeline, {
        slaStartedAt: started,
        slaDueAt: new Date(started.getTime() + 30 * 86_400_000),
      });
      const gUser = { type: "user", userId: user };
      let cur = await walk(g, [["in_review", gUser, "review_started", { claimedByUserId: user }]]);
      const fpReview = await c.review(cur, { reviewerUserId: user, decision: "false_positive" });
      cur = await walk(cur, [
        ["awaiting_approval", gUser, "review_recorded", { pendingReviewId: fpReview.id }],
      ]);
      cur = await walk(cur, [
        [
          "false_positive",
          { type: "user", userId: other },
          "approved_fp",
          { pendingReviewId: null },
        ],
      ]);
      await c.db.findingReview.update({
        where: { tenantId_id: { tenantId: f.tenantId, id: fpReview.id } },
        data: { state: "approved", decidedAt: new Date() },
      });
      same(p, "an approved false positive has no SLA", cur.slaDueAt, null);
      cur = await walk(cur, [["in_review", gUser, "fp_reopened", {}]]);
      same(p, "reopened for review: no SLA until approved again", cur.slaDueAt, null);
      cur = await walk(cur, [
        [
          "awaiting_approval",
          gUser,
          "review_recorded",
          { pendingReviewId: (await c.review(cur, { reviewerUserId: user })).id },
        ],
      ]);
      cur = await walk(cur, [
        ["approved", { type: "user", userId: other }, "approved_tp", { pendingReviewId: null }],
      ]);
      same(
        p,
        "approved again: the clock runs again from first detection",
        [
          cur.slaStartedAt?.getTime(),
          cur.slaDueAt === null ? null : Math.round((cur.slaDueAt - cur.slaStartedAt) / 3_600_000),
        ],
        [started.getTime(), 720],
      );
      return p;
    },
  },
  {
    id: "FNDA1-01",
    name: "every message ingestion writes is valid and minimal (ADR-011, SPEC 9.1): finding.created, finding.verified, finding.reopened and (with the agent flag on) finding.advisory.requested parse against the catalog on their documented queues with ids, enums and the redacted title only, are idempotent per message id, carry NO snippet, rationale, path, fingerprint or secret, and the advisory job is never written for a secret finding or an info finding; with the agent flag off no job is written",
    run: async (c) => {
      const p = [];
      const scn = await scenario(c);
      const items = full({
        sca: [sca({ key: "msg-a", severity: "high" })],
        sast: [
          sast({ path: "src/msg.py", severity: "medium" }),
          sast({ path: "src/info.py", severity: "info", code: "info(1)" }),
        ],
        secrets: [secret({ path: "msg.env" })],
      });
      const e1 = await runExecution(scn, { ...items, startedAt: at(0) });
      await ingest(scn, e1, { config: handlerConfig({ agentEnabled: true }) });
      const rows = await c.db.outboxMessage.findMany({
        where: {
          tenantId: scn.tenantId,
          payload: { path: ["pipelineId"], equals: scn.pipeline.id },
        },
      });
      const byType = (t) => rows.filter((r) => r.type === t);
      same(p, "a created event per finding", byType("finding.created").length, 4);
      same(
        p,
        "created events go to the realtime queue",
        [...new Set(byType("finding.created").map((r) => r.queue))],
        ["realtime"],
      );
      const jobs = byType("finding.advisory.requested");
      same(
        p,
        "an advisory job for the high SCA and the medium SAST finding only (never a secret, never info)",
        jobs.length,
        2,
      );
      same(
        p,
        "jobs go to the agent queue",
        [...new Set(jobs.map((r) => r.queue))],
        ["findings-agent"],
      );
      for (const r of rows) {
        const m = parseMessage(r.payload);
        const text = JSON.stringify(m);
        for (const forbidden of [
          "src/msg.py",
          "msg.env",
          "REDACTED",
          "fp1:",
          "eval(",
          "snippet",
          "rationale",
          "package-lock",
        ])
          ok(p, !text.includes(forbidden), `${m.type}: the message must not carry "${forbidden}"`);
        same(
          p,
          `${m.type}: the chain ids are the verified ones`,
          [m.tenantId, m.workspaceId, m.repositoryId, m.pipelineId],
          [scn.tenantId, scn.workspaceId, scn.repositoryId, scn.pipeline.id],
        );
      }
      // verify and reopen events: two eligible absences then a detection
      await ingest(scn, await runExecution(scn, { ...full({}), startedAt: at(10) }), {
        config: handlerConfig({ agentEnabled: true }),
      });
      await ingest(scn, await runExecution(scn, { ...full({}), startedAt: at(20) }), {
        config: handlerConfig({ agentEnabled: true }),
      });
      await ingest(
        scn,
        await runExecution(scn, {
          ...full({ sca: [sca({ key: "msg-a", severity: "high" })] }),
          startedAt: at(30),
        }),
        { config: handlerConfig({ agentEnabled: true }) },
      );
      const later = await c.db.outboxMessage.findMany({
        where: {
          tenantId: scn.tenantId,
          payload: { path: ["pipelineId"], equals: scn.pipeline.id },
        },
      });
      const verified = later.filter((r) => r.type === "finding.verified");
      const reopened = later.filter((r) => r.type === "finding.reopened");
      ok(p, verified.length >= 1, "a finding.verified event");
      same(
        p,
        "one finding.reopened event with its reason",
        reopened.map((r) => parseMessage(r.payload).payload.reason),
        ["recurred"],
      );
      for (const r of [...verified, ...reopened]) parseMessage(r.payload);
      ok(
        p,
        later.filter((r) => r.type === "finding.advisory.requested").length === 3,
        "a reopened finding is queued for a new advisory (the created ones stay two)",
      );
      // the same message id is written once (idempotent): replaying changes nothing
      const countBefore = later.length;
      await ingest(scn, await c.db.execution.findUnique({ where: { id: e1.id } }), {
        config: handlerConfig({ agentEnabled: true }),
      });
      same(
        p,
        "a replay writes no message",
        await c.db.outboxMessage.count({
          where: {
            tenantId: scn.tenantId,
            payload: { path: ["pipelineId"], equals: scn.pipeline.id },
          },
        }),
        countBefore,
      );
      // agent flag off: no job
      const off = await scenario(c);
      await ingest(
        off,
        await runExecution(off, full({ sca: [sca({ key: "msg-b", severity: "high" })] })),
      );
      const offRows = await c.db.outboxMessage.findMany({
        where: {
          tenantId: off.tenantId,
          payload: { path: ["pipelineId"], equals: off.pipeline.id },
        },
      });
      same(
        p,
        "agent flag off: no advisory job",
        offRows.filter((r) => r.type === "finding.advisory.requested").length,
        0,
      );
      ok(
        p,
        offRows.some((r) => r.type === "finding.created"),
        "control: the created event is written",
      );
      return p;
    },
  },
];

// ---------------------------------------------------------------------------------------------------------------------------------
// The read routes (SPEC 8.1): the REAL routes behind a stub authentication chain
// ---------------------------------------------------------------------------------------------------------------------------------
const NOW_MS = Date.now();
const DAY = 86_400_000;
const strip = (json) => JSON.stringify({ ...json, meta: undefined });
const idsOf = (json) => (json?.data ?? []).map((i) => i.id);

/** Principals, pipelines and the API, built once per findings world. */
const readWorlds = new WeakMap();
async function readWorld(c) {
  if (readWorlds.has(c)) return readWorlds.get(c);
  const building = (async () => {
    const api = await startReadApi(c.db);
    const A = c.A;
    const B = c.B;
    const w = { api, A, B };
    w.userX = await newUser(c);
    w.userY = await newUser(c);
    const view = ["finding.view"];
    api.register("viewerA", {
      tenantId: A.tenant.id,
      userId: w.userX,
      workspaces: [{ id: A.ws[0].id, permissions: view }],
    });
    api.register("viewerA2", {
      tenantId: A.tenant.id,
      userId: w.userY,
      workspaces: [{ id: A.ws[0].id, permissions: view }],
    });
    api.register("bothA", {
      tenantId: A.tenant.id,
      userId: w.userX,
      workspaces: [
        { id: A.ws[0].id, permissions: view },
        { id: A.ws[1].id, permissions: view },
      ],
    });
    api.register("blindA", {
      tenantId: A.tenant.id,
      userId: w.userX,
      workspaces: [
        { id: A.ws[0].id, permissions: view },
        { id: A.ws[1].id, permissions: [] },
      ],
    });
    api.register("viewerB", {
      tenantId: B.tenant.id,
      workspaces: [{ id: B.ws[0].id, permissions: view }],
    });
    // forged: a principal of tenant B that claims tenant A's workspace in its permission set (the tenant filter must still refuse)
    api.register("forgedB", {
      tenantId: B.tenant.id,
      workspaces: [{ id: A.ws[0].id, permissions: view }],
    });
    w.p0a = await c.pipeline(A, 0);
    w.p0b = await c.pipeline(A, 0);
    w.p1 = await c.pipeline(A, 1);
    w.pb = await c.pipeline(B, 0);
    w.fA0 = await c.finding(w.p0a, { title: "visible finding" });
    w.fA1 = await c.finding(w.p1, { title: "hidden-workspace finding" });
    w.fB = await c.finding(w.pb, { title: "foreign finding" });
    return w;
  })();
  readWorlds.set(c, building);
  return building;
}

/** A finding with a chosen look; the world factory writes the history row the database demands. */
const makeFinding = (c, pipeline, o = {}) => c.finding(pipeline, o);
const rankOf = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const withSeverity = (severity) => ({
  toolSeverity: severity,
  severity,
  severityRank: rankOf[severity],
});

const readChecks = [
  {
    id: "FND-S01a",
    name: "collection reads are workspace scoped (FS-1, FS-2, FND-S01): the list and the summary answer an identical 404 for another tenant's workspace, a workspace the caller cannot see and an unknown id (a principal of another tenant that merely CLAIMS the workspace in its permissions gets the same 404), 403 for a visible workspace without finding.view, 400 for a missing or forged parameter (a tenantId in the query is refused, a pipeline or repository of another workspace narrows to nothing and never widens), 401 without a session; the control (the right principal) reads its rows",
    run: async (c) => {
      const p = [];
      const w = await readWorld(c);
      const { api } = w;
      const ws0 = w.A.ws[0].id;
      const ok200 = await api.get(
        "viewerA",
        `/findings?${qs({ workspaceId: ws0, pipelineId: w.p0a.id })}`,
      );
      same(
        p,
        "control: the list of the right workspace",
        [ok200.status, idsOf(ok200.json)],
        [200, [w.fA0.id]],
      );
      for (const [path, label] of [
        ["/findings", "list"],
        ["/findings/summary", "summary"],
      ]) {
        const control = await api.get("viewerA", `${path}?${qs({ workspaceId: ws0 })}`);
        same(p, `control: the ${label}`, control.status, 200);
        const missing = await api.get("viewerA", `${path}?${qs({ workspaceId: randomUUID() })}`);
        same(p, `${label}: an unknown workspace`, missing.status, 404);
        const bodies = new Set([strip(missing.json)]);
        for (const [who, workspaceId, why] of [
          ["viewerA", w.B.ws[0].id, "another tenant's workspace"],
          ["viewerA", w.A.ws[1].id, "a workspace the caller cannot see"],
          ["viewerB", ws0, "another tenant asking for this workspace"],
          ["forgedB", ws0, "a principal of another tenant that claims this workspace"],
        ]) {
          const r = await api.get(who, `${path}?${qs({ workspaceId })}`);
          same(p, `${label}: ${why}`, r.status, 404);
          bodies.add(strip(r.json));
        }
        same(p, `${label}: every 404 is the identical body`, bodies.size, 1);
        const blind = await api.get("blindA", `${path}?${qs({ workspaceId: w.A.ws[1].id })}`);
        same(p, `${label}: a visible workspace without finding.view`, blind.status, 403);
        same(
          p,
          `${label}: no session`,
          (await api.get("nobody", `${path}?${qs({ workspaceId: ws0 })}`)).status,
          401,
        );
        same(p, `${label}: no workspace parameter`, (await api.get("viewerA", path)).status, 400);
        same(
          p,
          `${label}: a forged tenantId is refused (strict query)`,
          (await api.get("viewerA", `${path}?${qs({ workspaceId: ws0, tenantId: w.B.tenant.id })}`))
            .status,
          400,
        );
      }
      for (const [label, extra] of [
        ["a pipeline of another tenant", { pipelineId: w.pb.id }],
        ["a pipeline of another workspace", { pipelineId: w.p1.id }],
        ["a repository of another workspace", { repositoryId: w.A.repo[1].id }],
      ]) {
        const r = await api.get("viewerA", `/findings?${qs({ workspaceId: ws0, ...extra })}`);
        same(p, `${label} narrows to nothing`, [r.status, idsOf(r.json)], [200, []]);
      }
      same(
        p,
        "an unknown filter is refused",
        (await api.get("viewerA", `/findings?${qs({ workspaceId: ws0, surprise: 1 })}`)).status,
        400,
      );
      return p;
    },
  },
  {
    id: "FND-S01b",
    name: "item reads are scoped by tenant AND the finding's own workspace (FS-1, FS-2): detail, history, comments and similar answer an identical 404 for another tenant's finding, a finding of a workspace the caller cannot see and an unknown id, 403 for a visible workspace without finding.view, 401 without a session, and a forged workspaceId in the query is refused or ignored; the control (the visible finding) reads on every route",
    run: async (c) => {
      const p = [];
      const w = await readWorld(c);
      const { api } = w;
      const routes = (id) => [
        `/findings/${id}`,
        `/findings/${id}/history`,
        `/findings/${id}/comments`,
        `/findings/${id}/similar`,
      ];
      const control = await Promise.all(routes(w.fA0.id).map((path) => api.get("viewerA", path)));
      same(
        p,
        "control: the visible finding on every route",
        control.map((r) => r.status),
        [200, 200, 200, 200],
      );
      same(p, "control: the detail names the finding", control[0].json?.data?.id, w.fA0.id);
      for (const [i, label] of ["detail", "history", "comments", "similar"].entries()) {
        const bodies = new Set();
        for (const [who, id, why] of [
          ["viewerA", w.fB.id, "another tenant's finding"],
          ["viewerA", w.fA1.id, "a finding of a hidden workspace"],
          ["viewerA", randomUUID(), "an unknown id"],
          ["viewerB", w.fA0.id, "another tenant asking for this finding"],
          ["forgedB", w.fA0.id, "a principal that claims the workspace of another tenant"],
        ]) {
          const r = await api.get(who, routes(id)[i]);
          same(p, `${label}: ${why}`, r.status, 404);
          bodies.add(strip(r.json));
        }
        same(p, `${label}: every 404 is the identical body`, bodies.size, 1);
        same(
          p,
          `${label}: visible workspace, no finding.view`,
          (await api.get("blindA", routes(w.fA1.id)[i])).status,
          403,
        );
        same(p, `${label}: no session`, (await api.get("nobody", routes(w.fA0.id)[i])).status, 401);
      }
      same(
        p,
        "a forged workspaceId on the history route is refused (strict query)",
        (await api.get("viewerA", `/findings/${w.fB.id}/history?workspaceId=${w.B.ws[0].id}`))
          .status,
        400,
      );
      const forged = await api.get(
        "viewerA",
        `/findings/${w.fB.id}?workspaceId=${w.B.ws[0].id}&tenantId=${w.B.tenant.id}`,
      );
      same(
        p,
        "a forged tenant or workspace on the detail never reaches another tenant's finding",
        forged.status,
        404,
      );
      same(
        p,
        "a non-uuid id is a validation error, not a lookup",
        (await api.get("viewerA", "/findings/not-a-uuid")).status,
        400,
      );
      return p;
    },
  },
  {
    id: "FND-S12",
    name: "DTO no-leak on the reads (SPEC 8.3, FND-S12, FND-016): every response of the list, summary, detail, history, comments and similar routes parses with the strict shared DTO schemas, contains none of the forbidden keys (tenantId, workspaceId, correlationKey, execution and result ids, e-mail, preview, valueLength, prompt, keys) and none of the identifiers or secret-derived text that exist in the database (tenant id, execution ids, the secret preview, a user e-mail); the commit-pinned link is shown only when it is https, on the closed provider table and pinned to the commit of its structured reference (a tampered host or commit gives no link); a secret finding's excerpt is the masked line or nothing; the control is that the DTOs carry the real data",
    run: async (c) => {
      const p = [];
      const w = await readWorld(c);
      const { api } = w;
      const scn = await scenario(c);
      const e = await runExecution(
        scn,
        full({
          sca: [sca({ key: "dto-lib" })],
          sast: [sast({ path: "src/dto.py", line: 8 })],
          secrets: [secret({ path: "dto.env", preview: "AKIA" })],
        }),
      );
      await ingest(scn, e);
      const rows = await findingsOf(scn);
      const scaRow = rows.find((r) => r.scanType === "sca");
      const secretRow = rows.find((r) => r.scanType === "secrets");
      const codeRow = rows.find((r) => r.scanType === "sast");
      const author = await newUser(c);
      await c.db.findingComment.create({
        data: {
          ...c.chainOf(scaRow),
          authorUserId: author,
          body: "Looks real; assigning to the platform team.",
        },
      });
      await c.db.tenantMembership.upsert({
        where: { tenantId_userId: { tenantId: scn.tenantId, userId: author } },
        create: { tenantId: scn.tenantId, userId: author, status: "active" },
        update: {},
      });
      const other = await c.finding(w.p0b, {
        correlationKey: scaRow.correlationKey,
        title: "same vulnerability, another pipeline",
      });
      const ws = scn.workspaceId;
      const list = await api.get(
        "viewerA",
        `/findings?${qs({ workspaceId: ws, pipelineId: scn.pipeline.id })}`,
      );
      const summary = await api.get("viewerA", `/findings/summary?${qs({ workspaceId: ws })}`);
      const detail = {};
      for (const r of rows) detail[r.scanType] = await api.get("viewerA", `/findings/${r.id}`);
      const history = await api.get("viewerA", `/findings/${scaRow.id}/history`);
      const comments = await api.get("viewerA", `/findings/${scaRow.id}/comments`);
      const similar = await api.get("viewerA", `/findings/${scaRow.id}/similar`);
      same(
        p,
        "every read answers 200",
        [
          list.status,
          summary.status,
          history.status,
          comments.status,
          similar.status,
          ...Object.values(detail).map((d) => d.status),
        ],
        [200, 200, 200, 200, 200, 200, 200, 200],
      );
      const {
        findingListItemSchema,
        findingDetailSchema,
        historyEntrySchema,
        commentDtoSchema,
        similarFindingSchema,
        summaryDtoSchema,
      } = await import("@qmentisai/shared");
      const parse = (label, schema, value) => {
        const r = schema.safeParse(value);
        if (!r.success)
          p.push(
            `${label}: ${r.error.issues
              .slice(0, 2)
              .map((i) => `${i.path.join(".")} ${i.message}`)
              .join("; ")}`,
          );
      };
      for (const item of list.json.data) parse("list item", findingListItemSchema, item);
      for (const [type, r] of Object.entries(detail))
        parse(`${type} detail`, findingDetailSchema, r.json.data);
      for (const item of history.json.data) parse("history entry", historyEntrySchema, item);
      for (const item of comments.json.data) parse("comment", commentDtoSchema, item);
      for (const item of similar.json.data) parse("similar", similarFindingSchema, item);
      parse("summary", summaryDtoSchema, summary.json.data);
      same(p, "control: the list carries the three findings", list.json.data.length, 3);
      same(
        p,
        "control: the comment author is a name, not an e-mail",
        comments.json.data[0]?.author?.displayName,
        "Findings suite user",
      );
      same(
        p,
        "control: the similar list names the other pipeline",
        similar.json.data.map((s) => s.id),
        [other.id],
      );
      same(
        p,
        "control: the history starts with the detection",
        history.json.data.at(-1)?.toStatus,
        "new",
      );
      same(
        p,
        "control: the SCA detail has the fix, the advisory and the link",
        [
          detail.sca.json.data.fix?.fixedVersions,
          detail.sca.json.data.advisories.length,
          detail.sca.json.data.link?.provider,
        ],
        [["9.9.9"], 1, "github"],
      );
      same(
        p,
        "control: the code detail has the excerpt",
        detail.sast.json.data.evidence?.snippet?.includes("eval(user_input)"),
        true,
      );
      // recursive scan of every response
      const keys = new Set();
      const walk = (v) => {
        if (Array.isArray(v)) v.forEach(walk);
        else if (v && typeof v === "object")
          for (const [k, x] of Object.entries(v)) {
            keys.add(k);
            walk(x);
          }
      };
      // owner decision 2026-11-24: ONLY the detail DTO may carry `workspaceId`, and only at its top level (not nested, not elsewhere)
      const nonDetail = [list, summary, history, comments, similar].map((r) => r.json);
      const details = Object.values(detail).map((r) => r.json);
      const all = [...nonDetail, ...details];
      nonDetail.forEach((j) => walk(j));
      for (const k of FORBIDDEN_FINDING_DTO_KEYS)
        ok(p, !keys.has(k), `forbidden key "${k}" appears in a non-detail response`);
      for (const d of details) {
        const { workspaceId: ws, ...rest } = d.data ?? {};
        ok(p, typeof ws === "string" && ws.length > 0, "the detail DTO must carry its workspaceId");
        const detailKeys = new Set();
        keys.clear();
        walk(rest);
        for (const k of keys) detailKeys.add(k);
        for (const k of FORBIDDEN_FINDING_DETAIL_DTO_KEYS)
          ok(p, !detailKeys.has(k), `forbidden key "${k}" appears in a detail response`);
        ok(
          p,
          !detailKeys.has("workspaceId"),
          "workspaceId appears below the top level of a detail",
        );
      }
      const text = JSON.stringify(all);
      const email = (await c.db.user.findUnique({ where: { id: author } })).email;
      for (const needle of [
        scn.tenantId,
        scaRow.lastSeenExecutionId,
        scaRow.firstExecutionId,
        scaRow.correlationKey,
        email,
        "AKIA",
        "valueLength",
        "preview",
        "clone_url",
      ])
        ok(p, !text.includes(needle), `a response must not carry ${needle.slice(0, 12)}...`);
      // the secret detail: only the masked line
      same(
        p,
        "a secret's excerpt is the masked line",
        detail.secrets.json.data.evidence?.snippet,
        'API_KEY = "[REDACTED:api_key]"',
      );
      await c.db.findingEvidence.update({
        where: { tenantId_findingId: { tenantId: scn.tenantId, findingId: secretRow.id } },
        data: { snippet: "plain text that is not the masked line" },
      });
      same(
        p,
        "a secret excerpt that is not the masked line is withheld",
        (await api.get("viewerA", `/findings/${secretRow.id}`)).json.data.evidence.snippet,
        null,
      );
      // the link: tampered host, tampered commit, http-less shape
      const evidence = (data) =>
        c.db.findingEvidence.update({
          where: { tenantId_findingId: { tenantId: scn.tenantId, findingId: codeRow.id } },
          data,
        });
      const linkOf = async () =>
        (await api.get("viewerA", `/findings/${codeRow.id}`)).json.data.link;
      ok(
        p,
        (await linkOf())?.url?.startsWith("https://github.com/"),
        "control: a pinned github link",
      );
      await evidence({ url: "https://evil.example/pdb-org/a-1/blob/" + SHA40(1) + "/src/dto.py" });
      same(p, "a host outside the closed table gives no link", await linkOf(), null);
      await evidence({ url: `https://github.com/pdb-org/a-1/blob/${SHA40(9)}/src/dto.py` });
      same(
        p,
        "a link pinned to another commit than its reference gives no link",
        await linkOf(),
        null,
      );
      await evidence({ url: `https://deploy@github.com/pdb-org/a-1/blob/${SHA40(1)}/src/dto.py` });
      same(p, "a link with userinfo gives no link", await linkOf(), null);
      return p;
    },
  },
  {
    id: "FND-S13a",
    name: "pagination (SPEC 8, FND-S13, API standards): over 60 findings with ties and NULL SLA dates, keyset pages of every sort and direction visit every finding exactly once in the documented order (severity in declaration order, the id as the last term, microsecond-safe dates, NULLs last ascending and first descending); a page walked while new findings arrive loses and repeats nothing; numbered pages (25) give totals and the same order; a cursor from another filter, sort, workspace, tenant, user or endpoint, or a tampered one, is 400 INVALID_CURSOR; page with cursor, an unlisted pageSize, a limit over 100 and a page beyond the window are refused",
    run: async (c) => {
      const p = [];
      const w = await readWorld(c);
      const { api } = w;
      const ws0 = w.A.ws[0].id;
      const pk = await c.pipeline(w.A, 0);
      const sevs = ["critical", "high", "medium", "low", "info"];
      const base = NOW_MS - 20 * DAY;
      const made = [];
      for (let i = 0; i < 60; i += 1) {
        const sev = sevs[i % 5];
        made.push(
          await makeFinding(c, pk, {
            title: `Item ${String(i).padStart(2, "0")}`,
            ...withSeverity(sev),
            // ties: groups of four findings share one first-detection time; the last-seen times differ by microseconds-scale steps
            firstDetectedAt: new Date(base + Math.floor(i / 4) * 60_000),
            lastSeenAt: new Date(base + (i % 7) * 1000),
            slaStartedAt: i % 3 === 0 ? null : new Date(base),
            slaDueAt: i % 3 === 0 ? null : new Date(base + (1 + (i % 6)) * DAY),
          }),
        );
      }
      const filter = { workspaceId: ws0, pipelineId: pk.id };
      const compare = (key, dir, tieAsc) => (a, b) => {
        const x = key(a);
        const y = key(b);
        let o = 0;
        if (x === y) o = 0;
        else if (x === null)
          o = 1; // NULLs sort last ascending
        else if (y === null) o = -1;
        else o = x < y ? -1 : 1;
        if (dir === "desc") o = -o;
        if (o !== 0) return o;
        return tieAsc ? (a.id < b.id ? -1 : 1) : a.id < b.id ? 1 : -1;
      };
      const sorts = {
        severity: (dir) => compare((r) => -r.severityRank, dir === "desc" ? "asc" : "desc", true),
        slaDueAt: (dir) =>
          compare((r) => (r.slaDueAt ? r.slaDueAt.getTime() : null), dir, dir === "asc"),
        firstDetectedAt: (dir) => compare((r) => r.firstDetectedAt.getTime(), dir, dir === "asc"),
        lastSeenAt: (dir) => compare((r) => r.lastSeenAt.getTime(), dir, dir === "asc"),
        title: (dir) => compare((r) => r.title, dir, dir === "asc"),
      };
      const walk = async (who, params, limit = 7) => {
        const seen = [];
        let cursor;
        for (let guard = 0; guard < 40; guard += 1) {
          const r = await api.get(who, `/findings?${qs({ ...filter, ...params, limit, cursor })}`);
          if (r.status !== 200) return { error: r };
          seen.push(...idsOf(r.json));
          cursor = r.json.meta.pagination.nextCursor;
          if (!cursor) return { seen };
        }
        return { seen, runaway: true };
      };
      for (const [sort, order] of Object.entries(sorts))
        for (const direction of ["asc", "desc"]) {
          const expected = [...made].sort(order(direction)).map((r) => r.id);
          const got = await walk("viewerA", { sort, direction });
          same(
            p,
            `${sort} ${direction}: every finding once, in order`,
            got.error ? `HTTP ${got.error.status}` : got.seen.join(),
            expected.join(),
          );
        }
      // the default sort is severity, most severe first, and the first page starts with the critical ones
      const first = await api.get("viewerA", `/findings?${qs({ ...filter, limit: 12 })}`);
      same(
        p,
        "the default order starts with the most severe",
        first.json.data.slice(0, 12).map((i) => i.severity),
        [
          "critical",
          "critical",
          "critical",
          "critical",
          "critical",
          "critical",
          "critical",
          "critical",
          "critical",
          "critical",
          "critical",
          "critical",
        ],
      );
      // stable under inserts: arrivals before and after the position of the cursor
      const page1 = await api.get(
        "viewerA",
        `/findings?${qs({ ...filter, sort: "title", direction: "asc", limit: 10 })}`,
      );
      const before = idsOf(page1.json);
      await makeFinding(c, pk, { title: "Item 00 early arrival", ...withSeverity("low") });
      await makeFinding(c, pk, { title: "Item 99 late arrival", ...withSeverity("low") });
      const rest = [];
      let cursor = page1.json.meta.pagination.nextCursor;
      while (cursor) {
        const r = await api.get(
          "viewerA",
          `/findings?${qs({ ...filter, sort: "title", direction: "asc", limit: 10, cursor })}`,
        );
        rest.push(...idsOf(r.json));
        cursor = r.json.meta.pagination.nextCursor;
      }
      const walked = [...before, ...rest];
      same(p, "no finding repeats while rows arrive", walked.length, new Set(walked).size);
      ok(
        p,
        made.every((r) => walked.includes(r.id)),
        "no original finding is skipped while rows arrive",
      );
      ok(
        p,
        rest.length > 0 &&
          walked.includes(
            (
              await c.db.finding.findFirst({
                where: { tenantId: pk.tenantId, pipelineId: pk.id, title: "Item 99 late arrival" },
              })
            ).id,
          ),
        "a row that arrives AFTER the position is seen",
      );
      // numbered pages
      const n1 = await api.get("viewerA", `/findings?${qs({ ...filter, page: 1, pageSize: 25 })}`);
      const n2 = await api.get("viewerA", `/findings?${qs({ ...filter, page: 2, pageSize: 25 })}`);
      const n3 = await api.get("viewerA", `/findings?${qs({ ...filter, page: 3, pageSize: 25 })}`);
      same(
        p,
        "numbered page sizes and totals",
        [
          n1.json.data.length,
          n2.json.data.length,
          n3.json.data.length,
          n1.json.meta.pagination.totalItems,
          n1.json.meta.pagination.totalPages,
        ],
        [25, 25, 12, 62, 3],
      );
      const numberedIds = [...idsOf(n1.json), ...idsOf(n2.json), ...idsOf(n3.json)];
      same(p, "numbered pages are disjoint", numberedIds.length, new Set(numberedIds).size);
      const all = await walk("viewerA", {}, 100);
      same(
        p,
        "numbered pages and the cursor walk see the same order",
        numberedIds.join(),
        all.seen.join(),
      );
      // refusals
      const mint = async (extra, who = "viewerA", ws = ws0) =>
        (
          await api.get(
            who,
            `/findings?${qs({ workspaceId: ws, pipelineId: pk.id, limit: 5, ...extra })}`,
          )
        ).json.meta.pagination.nextCursor;
      const sev = await mint({ severity: "critical,high" });
      ok(p, typeof sev === "string", "control: a cursor is minted");
      const cursorFor = async (params, who = "viewerA", cursorOverride) =>
        api.get(
          who,
          `/findings?${qs({ workspaceId: ws0, pipelineId: pk.id, limit: 5, ...params, cursor: cursorOverride })}`,
        );
      const expectInvalid = async (label, r) =>
        same(p, label, [r.status, r.json?.error?.code], [400, "INVALID_CURSOR"]);
      await expectInvalid("a cursor under another filter set", await cursorFor({}, "viewerA", sev));
      await expectInvalid(
        "a cursor under another sort",
        await cursorFor({ severity: "critical,high", sort: "title" }, "viewerA", sev),
      );
      await expectInvalid(
        "a cursor under another direction",
        await cursorFor({ severity: "critical,high", direction: "asc" }, "viewerA", sev),
      );
      same(
        p,
        "control: the same cursor under the same filters works",
        (await cursorFor({ severity: "critical,high" }, "viewerA", sev)).status,
        200,
      );
      const wsCursor = await mint({}, "bothA");
      const other = await api.get(
        "bothA",
        `/findings?${qs({ workspaceId: w.A.ws[1].id, limit: 5, cursor: wsCursor })}`,
      );
      await expectInvalid("a cursor of another workspace", other);
      const tenantCursor = await mint({}, "bothA");
      await expectInvalid(
        "a cursor of another tenant's principal",
        await api.get(
          "viewerB",
          `/findings?${qs({ workspaceId: w.B.ws[0].id, limit: 5, cursor: tenantCursor })}`,
        ),
      );
      const tampered = `${wsCursor.slice(0, -2)}${wsCursor.endsWith("AA") ? "BB" : "AA"}`;
      await expectInvalid("a tampered cursor", await cursorFor({}, "viewerA", tampered));
      await expectInvalid("garbage", await cursorFor({}, "viewerA", "not-a-cursor"));
      same(
        p,
        "page with cursor is refused",
        (await cursorFor({ page: 2 }, "viewerA", sev)).status,
        400,
      );
      same(
        p,
        "an unlisted pageSize is refused",
        (await api.get("viewerA", `/findings?${qs({ ...filter, page: 1, pageSize: 30 })}`)).status,
        400,
      );
      same(
        p,
        "a limit over 100 is refused",
        (await api.get("viewerA", `/findings?${qs({ ...filter, limit: 101 })}`)).status,
        400,
      );
      same(
        p,
        "a page beyond the window is refused",
        (await api.get("viewerA", `/findings?${qs({ ...filter, page: 100000, pageSize: 100 })}`))
          .status,
        400,
      );
      same(
        p,
        "an unknown sort is refused",
        (await api.get("viewerA", `/findings?${qs({ ...filter, sort: "tenantId" })}`)).status,
        400,
      );
      return p;
    },
  },
  {
    id: "FND-S13b",
    name: "filters, saved views and counts (SPEC 5.11, 8.1, FND-S13): the four saved views match their definitions (all open, needs review, assigned to me bound to the session, breached SLA), the severity, status, scan type, assignee (me, unassigned, a user), SLA state, AI suggestion and text filters select exactly what they say and combine, a text with LIKE wildcards matches literally, an accepted risk whose expiry passed is listed as reopened and never as accepted even before the job runs, the summary counts equal the list totals, the cursor of `assignee=me` is bound to the user, and no filter widens the scope",
    run: async (c) => {
      const p = [];
      const w = await readWorld(c);
      const { api } = w;
      const ws0 = w.A.ws[0].id;
      const pf = await c.pipeline(w.A, 0);
      const f = { workspaceId: ws0, pipelineId: pf.id };
      const now = Date.now();
      const sla = (state) =>
        state === "breached"
          ? { slaStartedAt: new Date(now - 31 * DAY), slaDueAt: new Date(now - DAY) }
          : state === "due_soon"
            ? { slaStartedAt: new Date(now - 29 * DAY), slaDueAt: new Date(now + DAY) }
            : state === "on_track"
              ? { slaStartedAt: new Date(now - DAY), slaDueAt: new Date(now + 29 * DAY) }
              : {};
      const row = {};
      row.crit = await makeFinding(c, pf, {
        title: "critical breached eval xylophone",
        ...withSeverity("critical"),
        ...sla("breached"),
        assigneeUserId: w.userX,
      });
      row.high = await makeFinding(c, pf, {
        title: "high due soon",
        ...withSeverity("high"),
        ...sla("due_soon"),
        assigneeUserId: w.userY,
      });
      row.med = await makeFinding(c, pf, {
        title: "medium on track 100% sure",
        ...withSeverity("medium"),
        ...sla("on_track"),
      });
      row.low = await makeFinding(c, pf, {
        title: "low no sla",
        ...withSeverity("low"),
        scanType: "secrets",
        kind: "secret",
        ruleId: "generic-api-key",
      });
      row.underscore = await makeFinding(c, pf, {
        title: "plain a_b text",
        ...withSeverity("medium"),
        ...sla("on_track"),
      });
      row.plain = await makeFinding(c, pf, {
        title: "plain aXb text",
        ...withSeverity("medium"),
        ...sla("on_track"),
      });
      row.review = await c.step(
        await makeFinding(c, pf, {
          title: "in review",
          ...withSeverity("high"),
          ...sla("on_track"),
        }),
        "in_review",
        { set: { claimedByUserId: w.userY } },
      );
      const pending = await makeFinding(c, pf, {
        title: "fixed pending",
        ...withSeverity("low"),
        ...sla("on_track"),
      });
      const pendingRow = await c.step(pending, "fixed_pending_verification", {
        actor: "system",
        reason: "absent_in_complete_scan",
        set: { slaDueAt: null },
      });
      const stillPending = await makeFinding(c, pf, {
        title: "fixed pending, not yet verified",
        ...withSeverity("low"),
        ...sla("on_track"),
      });
      row.pending = await c.step(stillPending, "fixed_pending_verification", {
        actor: "system",
        reason: "absent_in_complete_scan",
        set: { slaDueAt: null },
      });
      row.verified = await c.step(pendingRow, "verified_fixed", {
        actor: "system",
        reason: "verified",
        set: {},
      });
      const risky = await makeFinding(c, pf, {
        title: "accepted risk expired",
        ...withSeverity("high"),
        ...sla("on_track"),
      });
      const ex = await c.exception(risky);
      await c.db.findingException.update({
        where: { tenantId_id: { tenantId: risky.tenantId, id: ex.id } },
        data: { state: "approved", decidedAt: new Date() },
      });
      row.expired = await c.step(risky, "accepted_risk", {
        set: {
          activeExceptionId: ex.id,
          exceptionExpiresAt: new Date(now - 3_600_000),
          acceptedSeverity: "high",
          slaDueAt: null,
        },
        reason: "risk_accepted",
      });
      const keep = await makeFinding(c, pf, {
        title: "accepted risk valid",
        ...withSeverity("high"),
        ...sla("on_track"),
      });
      const ex2 = await c.exception(keep);
      await c.db.findingException.update({
        where: { tenantId_id: { tenantId: keep.tenantId, id: ex2.id } },
        data: { state: "approved", decidedAt: new Date() },
      });
      row.accepted = await c.step(keep, "accepted_risk", {
        set: {
          activeExceptionId: ex2.id,
          exceptionExpiresAt: new Date(now + 30 * DAY),
          acceptedSeverity: "high",
          slaDueAt: null,
        },
        reason: "risk_accepted",
      });
      // an advisory
      await c.db.findingAiAdvisory.create({
        data: {
          ...c.chainOf(row.high),
          inputHash: "a".repeat(64),
          status: "ok",
          suggestion: "likely_false_positive",
          confidence: 91,
          reasoning: "Test fixture only.",
          egressLevel: "metadata",
          provider: "ollama",
          model: "m",
        },
      });
      const ids = async (who, params) => {
        const r = await api.get(who, `/findings?${qs({ ...f, limit: 100, ...params })}`);
        return r.status === 200 ? new Set(idsOf(r.json)) : `HTTP ${r.status}`;
      };
      const is = (label, got, rows) =>
        same(
          p,
          label,
          typeof got === "string" ? got : [...got].sort(),
          rows.map((r) => r.id).sort(),
        );
      const open = [
        row.crit,
        row.high,
        row.med,
        row.low,
        row.underscore,
        row.plain,
        row.review,
        row.expired,
        row.pending,
      ];
      is(
        "view all_open lists the open set, fixed-pending included (an expired acceptance counts as reopened)",
        await ids("viewerA", { view: "all_open" }),
        open,
      );
      is("view needs_review: new and in review", await ids("viewerA", { view: "needs_review" }), [
        row.crit,
        row.high,
        row.med,
        row.low,
        row.underscore,
        row.plain,
        row.review,
      ]);
      is(
        "view assigned_to_me is bound to the session (user X)",
        await ids("viewerA", { view: "assigned_to_me" }),
        [row.crit],
      );
      is(
        "view assigned_to_me for another user (Y)",
        await ids("viewerA2", { view: "assigned_to_me" }),
        [row.high],
      );
      is("view breached_sla", await ids("viewerA", { view: "breached_sla" }), [row.crit]);
      is("severity csv", await ids("viewerA", { severity: "critical,high" }), [
        row.crit,
        row.high,
        row.review,
        row.expired,
        row.accepted,
      ]);
      is("status csv", await ids("viewerA", { status: "in_review,fixed_pending_verification" }), [
        row.review,
        row.pending,
      ]);
      is("status verified_fixed", await ids("viewerA", { status: "verified_fixed" }), [
        row.verified,
      ]);
      is(
        "an expired acceptance is NOT listed as accepted",
        await ids("viewerA", { status: "accepted_risk" }),
        [row.accepted],
      );
      is(
        "an expired acceptance is listed as reopened",
        await ids("viewerA", { status: "reopened" }),
        [row.expired],
      );
      is("scan type", await ids("viewerA", { scanType: "secrets" }), [row.low]);
      is("assignee me", await ids("viewerA", { assignee: "me" }), [row.crit]);
      is("assignee a user id", await ids("viewerA", { assignee: w.userY }), [row.high]);
      is(
        "assignee unassigned",
        await ids("viewerA", { assignee: "unassigned" }),
        Object.values(row).filter((r) => !r.assigneeUserId && ![row.crit, row.high].includes(r)),
      );
      is("sla breached", await ids("viewerA", { sla: "breached" }), [row.crit]);
      is("sla due_soon", await ids("viewerA", { sla: "due_soon" }), [row.high]);
      is("sla on_track", await ids("viewerA", { sla: "on_track" }), [
        row.med,
        row.underscore,
        row.plain,
        row.review,
      ]);
      is("sla none", await ids("viewerA", { sla: "none" }), [
        row.low,
        row.pending,
        row.verified,
        row.expired,
        row.accepted,
      ]);
      is("sla csv", await ids("viewerA", { sla: "breached,due_soon" }), [row.crit, row.high]);
      is("ai suggestion", await ids("viewerA", { aiSuggestion: "likely_false_positive" }), [
        row.high,
      ]);
      is(
        "ai suggestion none",
        await ids("viewerA", { aiSuggestion: "none" }),
        Object.values(row).filter((r) => r !== row.high),
      );
      is("text in the title", await ids("viewerA", { q: "xylophone" }), [row.crit]);
      is("text with a percent sign matches literally", await ids("viewerA", { q: "100%" }), [
        row.med,
      ]);
      is("text with an underscore matches literally", await ids("viewerA", { q: "a_b" }), [
        row.underscore,
      ]);
      is("text in the rule id", await ids("viewerA", { q: "generic-api" }), [row.low]);
      is("filters combine", await ids("viewerA", { severity: "high", status: "in_review" }), [
        row.review,
      ]);
      is(
        "a view combined with a filter narrows it",
        await ids("viewerA", { view: "all_open", severity: "critical" }),
        [row.crit],
      );
      // the expired acceptance is reopened in the detail DTO too, and the counts agree with the list
      same(
        p,
        "the detail of an expired acceptance reads as reopened",
        (await api.get("viewerA", `/findings/${row.expired.id}`)).json?.data?.status,
        "reopened",
      );
      same(
        p,
        "the detail of a valid acceptance reads as accepted",
        (await api.get("viewerA", `/findings/${row.accepted.id}`)).json?.data?.status,
        "accepted_risk",
      );
      const summary = (await api.get("viewerA", `/findings/summary?${qs({ workspaceId: ws0 })}`))
        .json.data;
      const total = async (params) =>
        (
          await api.get(
            "viewerA",
            `/findings?${qs({ workspaceId: ws0, page: 1, pageSize: 25, ...params })}`,
          )
        ).json.meta.pagination.totalItems;
      same(
        p,
        "summary allOpen equals the all_open total",
        summary.views.allOpen,
        await total({ view: "all_open" }),
      );
      same(
        p,
        "summary needsReview equals the needs_review total",
        summary.views.needsReview,
        await total({ view: "needs_review" }),
      );
      same(
        p,
        "summary assignedToMe equals the assigned_to_me total",
        summary.views.assignedToMe,
        await total({ view: "assigned_to_me" }),
      );
      same(
        p,
        "summary breachedSla equals the breached_sla total",
        summary.views.breachedSla,
        await total({ view: "breached_sla" }),
      );
      same(
        p,
        "summary byStatus equals the status filter totals",
        [
          summary.byStatus.reopened,
          summary.byStatus.accepted_risk,
          summary.byStatus.verified_fixed,
        ],
        [
          await total({ status: "reopened" }),
          await total({ status: "accepted_risk" }),
          await total({ status: "verified_fixed" }),
        ],
      );
      const db = await c.db
        .$queryRaw`SELECT count(*)::int AS n FROM findings WHERE tenant_id = ${w.A.tenant.id}::uuid AND workspace_id = ${ws0}::uuid`;
      same(
        p,
        "the status counts add up to the workspace's rows",
        Object.values(summary.byStatus).reduce((a, b) => a + b, 0),
        db[0].n,
      );
      same(
        p,
        "control: the severity counts only count open findings",
        Object.values(summary.bySeverity).reduce((a, b) => a + b, 0),
        summary.views.allOpen,
      );
      // the cursor of `assignee=me` is bound to the user
      const mine = await api.get(
        "viewerA",
        `/findings?${qs({ ...f, assignee: "me", limit: 1, view: "all_open" })}`,
      );
      same(p, "assignee=me returns only the caller's finding", idsOf(mine.json), [row.crit.id]);
      const everyone = await api.get(
        "viewerA",
        `/findings?${qs({ ...f, view: "all_open", limit: 2 })}`,
      );
      const cur = everyone.json.meta.pagination.nextCursor;
      same(
        p,
        "control: the cursor works for its own user",
        (
          await api.get(
            "viewerA",
            `/findings?${qs({ ...f, view: "all_open", limit: 2, cursor: cur })}`,
          )
        ).status,
        200,
      );
      same(
        p,
        "a cursor of another user is refused (the session is part of the binding)",
        (
          await api.get(
            "viewerA2",
            `/findings?${qs({ ...f, view: "all_open", limit: 2, cursor: cur })}`,
          )
        ).json?.error?.code,
        "INVALID_CURSOR",
      );
      return p;
    },
  },
  {
    id: "FNDA1-02",
    name: "the advisory agent's repository (SPEC 9.3.4 layer 2, owner decisions OD-3 and OD-9): it has exactly the five frozen methods and none that writes finding state, a review, an assignment or the outbox, and its source imports nothing; the finding is read through the narrow view by tenant, workspace, repository, pipeline and id (a wrong link of the chain or another tenant gives null), a secret finding is never visible to it, code excerpts come only with code findings; the consent is read by the tenant of the finding row (the second tier counts only with the first); the single write is one advisory row, idempotent per input hash (a replay creates nothing, the same id comes back), refused by the database for a secret finding, a wrong chain or a credential-shaped reasoning",
    run: async (c) => {
      const p = [];
      const { createFindingsAgentRepository } = await import("@qmentisai/db");
      const repo = createFindingsAgentRepository({ db: c.db });
      same(p, "the frozen method names, and no others", Object.keys(repo).sort(), [
        "countAdvisoriesSince",
        "findAdvisoryByHash",
        "getFindingForAdvisory",
        "insertAdvisory",
        "readConsent",
      ]);
      const { readFile } = await import("node:fs/promises");
      const source = await readFile(
        new URL("../../../../../../packages/db/src/findings/agent-repository.js", import.meta.url),
        "utf8",
      );
      ok(
        p,
        !/^\s*import\s/m.test(source),
        "the agent repository imports nothing (no writer module can be reached from it)",
      );
      const stripped = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
      ok(
        p,
        !/\.(update|updateMany|delete|deleteMany|upsert|createMany)\(|outbox|\$executeRaw|transitionFinding/i.test(
          stripped,
        ),
        "the agent repository has no statement that changes finding state or the outbox",
      );
      const scn = await scenario(c);
      const e = await runExecution(
        scn,
        full({
          sca: [sca({ key: "agent-lib" })],
          sast: [sast({ path: "src/agent.py", line: 5 })],
          secrets: [secret({ path: "agent.env" })],
        }),
      );
      await ingest(scn, e);
      const rows = await findingsOf(scn);
      const code = rows.find((r) => r.scanType === "sast");
      const dep = rows.find((r) => r.scanType === "sca");
      const sec = rows.find((r) => r.scanType === "secrets");
      const ids = (r, over = {}) => ({
        tenantId: r.tenantId,
        workspaceId: r.workspaceId,
        repositoryId: r.repositoryId,
        pipelineId: r.pipelineId,
        findingId: r.id,
        ...over,
      });
      const seen = await repo.getFindingForAdvisory(ids(code));
      ok(
        p,
        seen && seen.scanType === "sast" && seen.evidence?.snippet?.includes("eval(user_input)"),
        "control: a code finding with its excerpt",
      );
      ok(
        p,
        seen && !("title" in seen) && !("fingerprint" in seen),
        "the view carries no title and no fingerprint",
      );
      same(
        p,
        "an SCA finding has no excerpt",
        (await repo.getFindingForAdvisory(ids(dep)))?.evidence,
        null,
      );
      same(
        p,
        "a secret finding is invisible to the agent",
        await repo.getFindingForAdvisory(ids(sec)),
        null,
      );
      for (const [label, over] of [
        ["another pipeline of the chain", { pipelineId: randomUUID() }],
        ["another workspace", { workspaceId: c.A.ws[1].id }],
        ["another repository", { repositoryId: c.A.repo[1].id }],
        ["another tenant", { tenantId: c.B.tenant.id }],
      ])
        same(p, `${label}: no finding`, await repo.getFindingForAdvisory(ids(code, over)), null);
      // consent
      same(p, "no settings row: both off", await repo.readConsent({ tenantId: scn.tenantId }), {
        externalConsent: false,
        codeSnippetConsent: false,
      });
      await c.db.tenantLlmSettings.upsert({
        where: { tenantId: scn.tenantId },
        create: { tenantId: scn.tenantId, externalConsent: true },
        update: { externalConsent: true, codeSnippetConsent: false },
      });
      same(p, "the metadata consent alone", await repo.readConsent({ tenantId: scn.tenantId }), {
        externalConsent: true,
        codeSnippetConsent: false,
      });
      await c.db.tenantLlmSettings.update({
        where: { tenantId: scn.tenantId },
        data: { codeSnippetConsent: true },
      });
      same(p, "both consents", await repo.readConsent({ tenantId: scn.tenantId }), {
        externalConsent: true,
        codeSnippetConsent: true,
      });
      same(
        p,
        "another tenant's consent is not this tenant's",
        await repo.readConsent({ tenantId: c.B.tenant.id }),
        { externalConsent: false, codeSnippetConsent: false },
      );
      await c.db.tenantLlmSettings.update({
        where: { tenantId: scn.tenantId },
        data: { codeSnippetConsent: false, externalConsent: false },
      });
      // the single write
      const hash = "b".repeat(64);
      const since = new Date();
      const row = (r, over = {}) => ({
        ...ids(r),
        inputHash: hash,
        status: "ok",
        suggestion: "uncertain",
        confidence: 40,
        reasoning: "Plain advisory text.",
        egressLevel: "metadata",
        provider: "ollama",
        model: "m",
        usage: { tokens: 10 },
        ...over,
      });
      const first = await repo.insertAdvisory(row(code));
      same(p, "control: the advisory is inserted", first.created, true);
      const again = await repo.insertAdvisory(row(code));
      same(
        p,
        "a replay creates nothing and returns the same id",
        [again.created, again.id],
        [false, first.id],
      );
      ok(
        p,
        (
          await repo.insertAdvisory(
            row(code, {
              inputHash: "c".repeat(64),
              status: "timeout",
              suggestion: null,
              confidence: null,
              reasoning: null,
              egressLevel: "none",
            }),
          )
        ).created,
        "a failure status is stored without advice",
      );
      same(
        p,
        "found by hash for the right tenant",
        (await repo.findAdvisoryByHash({ tenantId: scn.tenantId }, code.id, hash))?.id,
        first.id,
      );
      same(
        p,
        "never for another tenant",
        await repo.findAdvisoryByHash({ tenantId: c.B.tenant.id }, code.id, hash),
        null,
      );
      same(
        p,
        "the daily cap counts this tenant's rows",
        await repo.countAdvisoriesSince({ tenantId: scn.tenantId }, since),
        2,
      );
      same(
        p,
        "and nothing in the future",
        await repo.countAdvisoriesSince(
          { tenantId: scn.tenantId },
          new Date(Date.now() + 3_600_000),
        ),
        0,
      );
      ok(
        p,
        (await rejects(() => repo.insertAdvisory(row(sec, { inputHash: "d".repeat(64) })))) !==
          null,
        "the database refuses an advisory for a secret finding",
      );
      ok(
        p,
        (await rejects(() =>
          repo.insertAdvisory(row(code, { inputHash: "e".repeat(64), pipelineId: randomUUID() })),
        )) !== null,
        "a wrong chain is refused by the composite key",
      );
      ok(
        p,
        (await rejects(() =>
          repo.insertAdvisory(
            row(code, { inputHash: "f".repeat(64), reasoning: `see ghp_${"a1B2".repeat(9)}` }),
          ),
        )) !== null,
        "a credential-shaped reasoning is refused",
      );
      same(
        p,
        "the finding itself is untouched by the agent",
        [
          (
            await c.db.finding.findUnique({
              where: { tenantId_id: { tenantId: code.tenantId, id: code.id } },
            })
          ).rev,
          (
            await c.db.finding.findUnique({
              where: { tenantId_id: { tenantId: code.tenantId, id: code.id } },
            })
          ).status,
        ],
        [code.rev, "new"],
      );
      return p;
    },
  },
  {
    id: "FND-S17",
    name: "the seed script (SPEC 9.4, FND-S17, FND-018): it refuses NODE_ENV=production, a run without FINDINGS_SEED_ALLOWED=true and an unknown tenant, before writing anything and without printing a connection string; the control creates the demo data deterministically (every status, severity and scan type, secrets with masked previews only, the same vulnerability in two pipelines, a deleted pipeline, SLA states, an expiring and an expired acceptance), a second run creates nothing, and every seeded finding reads back through the product's own list",
    run: async (c) => {
      const p = [];
      const { execFile } = await import("node:child_process");
      const { fileURLToPath } = await import("node:url");
      const script = fileURLToPath(
        new URL("../../../../../../packages/db/prisma/seed-findings.js", import.meta.url),
      );
      const url = process.env.SECURITY_DATABASE_URL ?? process.env.DATABASE_URL;
      const run = (args, env) =>
        new Promise((resolve) => {
          execFile(
            process.execPath,
            [script, "--", ...args],
            {
              env: { PATH: process.env.PATH, DATABASE_URL: url, ...env },
              timeout: 120_000,
              maxBuffer: 4_000_000,
            },
            (error, stdout, stderr) =>
              resolve({ code: error ? (error.code ?? 1) : 0, out: `${stdout}\n${stderr}` }),
          );
        });
      const tenant = await c.db.tenant.create({
        data: { slug: `seed-${randomUUID().slice(0, 8)}`, name: "Seed suite tenant" },
      });
      const workspace = await c.db.workspace.create({
        data: { tenantId: tenant.id, name: "Seed suite workspace" },
      });
      const count = () => c.db.finding.count({ where: { tenantId: tenant.id } });
      const refused = async (label, args, env, needle) => {
        const r = await run(args, env);
        ok(
          p,
          r.code !== 0 && r.out.includes(needle),
          `${label}: must refuse with "${needle}" (exit ${r.code})`,
        );
        ok(
          p,
          !r.out.includes(url ?? "no url") && !/postgres(ql)?:\/\//.test(r.out),
          `${label}: the output must not contain a connection string`,
        );
        same(p, `${label}: nothing is written`, await count(), 0);
      };
      await refused(
        "production",
        ["--tenant", tenant.slug],
        { NODE_ENV: "production", FINDINGS_SEED_ALLOWED: "true" },
        "NODE_ENV=production",
      );
      await refused(
        "without the explicit permission",
        ["--tenant", tenant.slug],
        {},
        "FINDINGS_SEED_ALLOWED",
      );
      await refused(
        "an unknown tenant",
        ["--tenant", `nobody-${randomUUID().slice(0, 8)}`],
        { FINDINGS_SEED_ALLOWED: "true" },
        "tenant does not exist",
      );
      await refused(
        "an unknown scale",
        ["--tenant", tenant.slug, "--scale", "huge"],
        { FINDINGS_SEED_ALLOWED: "true" },
        "scale",
      );
      const first = await run(
        ["--tenant", tenant.slug, "--workspace", workspace.id, "--scale", "small"],
        { FINDINGS_SEED_ALLOWED: "true" },
      );
      if (first.code !== 0)
        p.push(
          `control: the seed failed (exit ${first.code}): ${first.out
            .replace(/postgres(ql)?:\/\/\S+/g, "<url>")
            .trim()
            .slice(-600)}`,
        );
      const total = await count();
      ok(p, total >= 120, `control: at least 120 findings (got ${total})`);
      const second = await run(
        ["--tenant", tenant.slug, "--workspace", workspace.id, "--scale", "small"],
        { FINDINGS_SEED_ALLOWED: "true" },
      );
      same(
        p,
        "a second run succeeds and creates nothing",
        [second.code, await count()],
        [0, total],
      );
      ok(p, second.out.includes("0 created"), "the second run says it created nothing");
      const rows = await c.db.finding.findMany({
        where: { tenantId: tenant.id },
        select: {
          status: true,
          severity: true,
          scanType: true,
          pipelineId: true,
          correlationKey: true,
          fingerprint: true,
        },
      });
      const seen = (k) => new Set(rows.map((r) => r[k]));
      same(p, "every scan type", [...seen("scanType")].sort(), ["sast", "sca", "secrets"]);
      same(p, "every severity", [...seen("severity")].sort(), [
        "critical",
        "high",
        "info",
        "low",
        "medium",
      ]);
      ok(
        p,
        FINDING_STATUSES.every((s) => seen("status").has(s)),
        `every one of the 12 statuses is seeded (missing: ${FINDING_STATUSES.filter((s) => !seen("status").has(s)).join(", ")})`,
      );
      const pairs = new Map();
      for (const r of rows)
        pairs.set(
          r.correlationKey,
          new Set([...(pairs.get(r.correlationKey) ?? []), r.pipelineId]),
        );
      ok(
        p,
        [...pairs.values()].some((s) => s.size >= 2),
        "the same vulnerability exists in two pipelines (two findings, one correlation key)",
      );
      same(p, "fingerprints are unique", seen("fingerprint").size, rows.length);
      const deleted = await c.db.pipeline.count({
        where: { tenantId: tenant.id, deletedAt: { not: null } },
      });
      same(p, "a deleted pipeline with readable findings", deleted, 1);
      const sla = await c.db
        .$queryRaw`SELECT count(*) FILTER (WHERE sla_due_at < now())::int AS breached, count(*) FILTER (WHERE sla_due_at > now())::int AS running FROM findings WHERE tenant_id = ${tenant.id}::uuid`;
      ok(p, sla[0].breached > 0 && sla[0].running > 0, "SLA states: some breached, some running");
      const exceptions = await c.db.findingException.findMany({
        where: { tenantId: tenant.id },
        select: { state: true, expiresAt: true },
      });
      ok(
        p,
        exceptions.some(
          (x) =>
            x.state === "approved" && x.expiresAt && x.expiresAt.getTime() - Date.now() < 3 * DAY,
        ),
        "an acceptance expiring in two days",
      );
      ok(
        p,
        exceptions.some((x) => x.state === "expired"),
        "an expired acceptance (the finding was reopened by the system)",
      );
      // secrets are masked previews only
      const secrets = await c.db.findingEvidence.findMany({
        where: { tenantId: tenant.id, finding: { scanType: "secrets" } },
        select: { snippet: true },
      });
      ok(
        p,
        secrets.length > 0 && secrets.every((s) => s.snippet.includes("[REDACTED:")),
        "every seeded secret excerpt is the masked line",
      );
      // the product's own list reads them
      const w = await readWorld(c);
      w.api.register("seedViewer", {
        tenantId: tenant.id,
        workspaces: [{ id: workspace.id, permissions: ["finding.view"] }],
      });
      const list = await w.api.get(
        "seedViewer",
        `/findings?${qs({ workspaceId: workspace.id, page: 1, pageSize: 100 })}`,
      );
      same(
        p,
        "the seeded findings read back through the list",
        [list.status, list.json?.meta?.pagination?.totalItems],
        [200, total],
      );
      const summary = await w.api.get(
        "seedViewer",
        `/findings/summary?${qs({ workspaceId: workspace.id })}`,
      );
      same(
        p,
        "and through the summary",
        [
          summary.status,
          Object.values(summary.json?.data?.byStatus ?? {}).reduce((a, b) => a + b, 0),
        ],
        [200, total],
      );
      return p;
    },
  },
  // @@READS@@
];

export const FINDINGS_A_CHECKS = [...ingestionChecks, ...transitionChecks, ...readChecks];
