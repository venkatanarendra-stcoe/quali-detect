import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { createScanDbSnapshotRepository, createScanToolRunRepository } from "@qmentisai/db";
import { dbProvenance } from "@qmentisai/shared";
import { createJobEnvelope } from "@qmentisai/contracts";
import { NonRetryableError } from "@qmentisai/infra";
import { toPlatformAuditEntryDto } from "../../../src/modules/platform-audit-logs/mappers/index.js";
import { createDbRefreshHandler } from "../../../../workers/src/dbrefresh/index.js";
import { promotionSanity, refreshTool } from "../../../../workers/src/dbrefresh/refresh.js";
import { createDbSnapshotResolver } from "../../../../workers/src/execution/engines/ensemble/db/resolve-db.js";
import { enqueuePlatformJob } from "../../../../workers/src/scheduler/jobs.js";
import { hostileExtra, refreshExtra, snapshotsExtra } from "./dbmirror-boundary-checks.js";
import { inState, runningTask } from "./execution-db.js";
import { attempt, mustAccept, mustReject, probe } from "./pipeline-db.js";
import {
  NOW,
  bundle,
  clock,
  daysAgo,
  fakeDownloader,
  hoursAgo,
  recordingLog,
  scanDbConfig,
  sha256,
  tempStore,
} from "./dbmirror-fixtures.js";

/**
 * Scan engines, part F, database parts (ADR-008 area 18, SPEC scan-engines 5.12, 7.3, 14.1 ENG-S12): the snapshot table's own integrity
 * (one active per tool, one-way status changes, immutable identity, no DELETE or TRUNCATE, closed values), the refresh flow with a FAKE
 * downloader (promotion gate, canary, integrity, hostile and quarantined input, idempotency, retention), the atomic switch under
 * concurrent readers and a crash between its steps, the handler and the scheduler message, and the tenant scoping of the provenance a
 * result records, in process against the disposable PostgreSQL. The tool state is global (two tools), so every check starts by retiring
 * whatever is active and abandoning candidates (the only moves the table allows) and asserts on its own digests.
 * NOT proved: the real downloads and the real tools (ENG-L09, ENG-L19), a multi-process promotion race across hosts, or the Redis lock
 * against a real Redis (the lock is a fake with the real interface; the database enforces the invariants).
 */

const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const same = (p, label, got, want) =>
  ok(
    p,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)?.slice(0, 300)}, want ${JSON.stringify(want)?.slice(0, 300)}`,
  );
const hex = () => randomBytes(32).toString("hex");

async function reset(db) {
  await db.$executeRaw`UPDATE scan_db_snapshots SET status = 'retired', retired_at = now() WHERE status = 'active'`;
  await db.$executeRaw`UPDATE scan_db_snapshots SET status = 'rejected', rejected_reason = 'abandoned' WHERE status = 'candidate'`;
}

const candidateInput = (over = {}) => ({
  toolId: "trivy",
  sourceVersion: "v1",
  upstreamBuiltAt: hoursAgo(3),
  sizeBytes: 1000,
  sha256: hex(),
  sources: [
    { id: "ghsa", licence: "CC-BY-4.0", attributionRequired: true, attribution: "ghsa-cc-by-4.0" },
  ],
  recordCounts: { records: 3 },
  ...over,
});

async function makeActive(repo, over = {}) {
  const { snapshot } = await repo.insertCandidate(candidateInput(over));
  const r = await repo.promote({ id: snapshot.id, toolId: snapshot.toolId });
  if (!r.promoted) throw new Error("fixture: not promoted");
  return snapshot;
}

/** A refresh rig: a temporary real store, the real repository, the fake downloader, a scripted canary, a fixed clock. */
function rigOf(c, { canary, lock = null, cfg = {} } = {}) {
  const t = tempStore();
  const repo = createScanDbSnapshotRepository({ db: c.db });
  const downloader = fakeDownloader();
  const canaryCalls = [];
  const deps = {
    repo,
    store: t.store,
    downloader,
    canary: async (input) => {
      canaryCalls.push(input);
      return (canary ?? (async () => ({ ok: true })))(input);
    },
    lock,
    now: clock,
  };
  const { log, lines } = recordingLog();
  const scanDb = scanDbConfig(cfg);
  return {
    t,
    repo,
    downloader,
    deps,
    canaryCalls,
    lines,
    scanDb,
    run: (toolId = "trivy", over = {}) =>
      refreshTool({ toolId, deps: { ...deps, ...over }, scanDb, log }),
    done: () => t.done(),
  };
}

const statusOf = async (repo, toolId, sha) =>
  (await repo.getBySha({ toolId, sha256: sha }))?.status ?? null;
const objects = (rig, tool) => rig.t.store.list(tool).then((l) => l.map((o) => o.sha256));

export const DBMIRROR_DB_CHECKS = [
  {
    id: "ENG-S12h",
    name: "scan_db_snapshots integrity in the database (SPEC scan-engines 7.3, SE-33, SE-35): the table has no tenant column and no foreign key to tenant data; at most ONE active snapshot per tool; a snapshot enters only as candidate (or rejected); of all ordered pairs of statuses only candidate to active, candidate to rejected and active to retired are accepted; the identifying and provenance columns (tool, digest, size, build and fetch times, version, sources, counts) are immutable; `promoted_at`, `retired_at` and the reject reason change only with a status transition; DELETE and TRUNCATE are refused; Grype and unknown tools, a malformed digest, a zero size, a malformed version, an unknown reject reason and non-array sources are refused for a raw writer too; the same digest is one row per tool (an idempotent insert); each denial has a control",
    async run(c) {
      const p = [];
      const { db } = c;
      await reset(db);
      const repo = createScanDbSnapshotRepository({ db });
      // no tenant data
      const cols =
        await db.$queryRaw`SELECT column_name FROM information_schema.columns WHERE table_name = 'scan_db_snapshots'`;
      ok(
        p,
        cols.length > 10 &&
          !cols.some((x) =>
            /tenant|workspace|repository|user|pipeline|execution/.test(x.column_name),
          ),
        "the table has no tenant-owned column",
      );
      const fks =
        await db.$queryRaw`SELECT 1 FROM pg_constraint WHERE conrelid = 'scan_db_snapshots'::regclass AND contype = 'f'`;
      same(p, "foreign keys", fks.length, 0);
      // control and the idempotent insert
      const first = await repo.insertCandidate(candidateInput({ toolId: "osv-scanner" }));
      ok(
        p,
        first.created === true &&
          first.snapshot.status === "candidate" &&
          typeof first.snapshot.sizeBytes === "number",
        "control: a candidate is inserted",
      );
      const again = await repo.insertCandidate({
        ...candidateInput({ toolId: "osv-scanner" }),
        sha256: first.snapshot.sha256,
      });
      ok(
        p,
        again.created === false && again.snapshot.id === first.snapshot.id,
        "the same digest of the same tool is one row",
      );
      const otherTool = await repo.insertCandidate({
        ...candidateInput({ toolId: "trivy" }),
        sha256: first.snapshot.sha256,
      });
      ok(p, otherTool.created === true, "the same digest of another tool is its own row");
      // one active per tool
      await reset(db);
      const a1 = await makeActive(repo, { toolId: "trivy" });
      const second = (await repo.insertCandidate(candidateInput({ toolId: "trivy" }))).snapshot;
      const dup = await attempt(() => db.$transaction((tx) => repo.activate(second.id, tx)));
      mustReject(p, "a second active snapshot of the same tool", dup, "23505");
      const otherActive = await attempt(() => makeActive(repo, { toolId: "osv-scanner" }));
      mustAccept(p, "an active snapshot of ANOTHER tool", otherActive);
      same(p, "the first stays active", (await repo.getActive("trivy"))?.id, a1.id);
      // entering
      for (const status of ["active", "retired"]) {
        const r = await attempt(
          () => db.$executeRaw`
          INSERT INTO scan_db_snapshots (id, tool_id, source_version, upstream_built_at, size_bytes, sha256, status, promoted_at)
          VALUES (gen_random_uuid(), 'trivy', 'v1', now(), 10, ${hex()}, ${status}, now())`,
        );
        mustReject(p, `insert as ${status}`, r, "not allowed");
      }
      mustAccept(
        p,
        "insert as rejected",
        await attempt(() =>
          repo.insertRejected({
            toolId: "trivy",
            sourceVersion: "v1",
            upstreamBuiltAt: hoursAgo(1),
            sizeBytes: 5,
            sha256: hex(),
            reason: "integrity_mismatch",
          }),
        ),
      );
      // transitions
      const states = ["candidate", "active", "retired", "rejected"];
      const make = async (status) => {
        await reset(db);
        if (status === "candidate") return (await repo.insertCandidate(candidateInput())).snapshot;
        if (status === "active") return makeActive(repo);
        if (status === "retired") {
          const s = await makeActive(repo);
          await makeActive(repo);
          return s;
        }
        const { snapshot } = await repo.insertCandidate(candidateInput());
        await repo.reject({ id: snapshot.id, reason: "canary_failed" });
        return snapshot;
      };
      const move = {
        candidate: {
          active: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='active', promoted_at=now() WHERE id=${id}::uuid`,
          rejected: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='rejected', rejected_reason='canary_failed' WHERE id=${id}::uuid`,
          retired: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='retired', promoted_at=now(), retired_at=now() WHERE id=${id}::uuid`,
        },
        active: {
          retired: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='retired', retired_at=now() WHERE id=${id}::uuid`,
          candidate: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='candidate', promoted_at=NULL WHERE id=${id}::uuid`,
          rejected: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='rejected', promoted_at=NULL, rejected_reason='canary_failed' WHERE id=${id}::uuid`,
        },
        retired: {
          active: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='active', retired_at=NULL WHERE id=${id}::uuid`,
          candidate: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='candidate', promoted_at=NULL, retired_at=NULL WHERE id=${id}::uuid`,
          rejected: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='rejected', promoted_at=NULL, retired_at=NULL, rejected_reason='canary_failed' WHERE id=${id}::uuid`,
        },
        rejected: {
          active: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='active', promoted_at=now(), rejected_reason=NULL WHERE id=${id}::uuid`,
          candidate: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='candidate', rejected_reason=NULL WHERE id=${id}::uuid`,
          retired: (id) =>
            db.$executeRaw`UPDATE scan_db_snapshots SET status='retired', promoted_at=now(), retired_at=now(), rejected_reason=NULL WHERE id=${id}::uuid`,
        },
      };
      let accepted = 0;
      for (const from of states) {
        for (const to of states) {
          if (from === to) continue;
          const row = await make(from);
          const r = await attempt(() => move[from][to](row.id));
          const allowed =
            `${from}>${to}` === "candidate>active" ||
            `${from}>${to}` === "candidate>rejected" ||
            `${from}>${to}` === "active>retired";
          if (allowed) {
            mustAccept(p, `${from} -> ${to}`, r);
            accepted += r.ok ? 1 : 0;
          } else mustReject(p, `${from} -> ${to}`, r);
        }
      }
      same(p, "accepted transitions", accepted, 3);
      // immutable columns, delete, truncate
      const row = await make("candidate");
      for (const [label, sql] of [
        [
          "sha256",
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET sha256=${hex()} WHERE id=${row.id}::uuid`,
        ],
        [
          "tool_id",
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET tool_id='osv-scanner' WHERE id=${row.id}::uuid`,
        ],
        [
          "size_bytes",
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET size_bytes=size_bytes+1 WHERE id=${row.id}::uuid`,
        ],
        [
          "upstream_built_at",
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET upstream_built_at=now() WHERE id=${row.id}::uuid`,
        ],
        [
          "fetched_at",
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET fetched_at=now() - interval '1 day' WHERE id=${row.id}::uuid`,
        ],
        [
          "source_version",
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET source_version='v2' WHERE id=${row.id}::uuid`,
        ],
        [
          "sources",
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET sources='[]'::jsonb WHERE id=${row.id}::uuid`,
        ],
        [
          "record_counts",
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET record_counts='{}'::jsonb WHERE id=${row.id}::uuid`,
        ],
        [
          "promoted_at alone",
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET promoted_at=now() WHERE id=${row.id}::uuid`,
        ],
        [
          "rejected_reason alone",
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET rejected_reason='empty' WHERE id=${row.id}::uuid`,
        ],
        ["delete", () => db.$executeRaw`DELETE FROM scan_db_snapshots WHERE id=${row.id}::uuid`],
      ])
        mustReject(p, label, await attempt(sql));
      mustReject(
        p,
        "truncate",
        await probe(db, (tx) => tx.$executeRawUnsafe("TRUNCATE scan_db_snapshots")),
      );
      mustAccept(p, "control: content_pruned_at", await attempt(() => repo.markPruned(row.id)));
      mustReject(
        p,
        "content_pruned_at changed twice",
        await attempt(
          () =>
            db.$executeRaw`UPDATE scan_db_snapshots SET content_pruned_at=now() + interval '1 day' WHERE id=${row.id}::uuid`,
        ),
      );
      // values
      const raw = (over) => {
        const v = {
          tool: "trivy",
          ver: "v1",
          size: 10,
          sha: hex(),
          src: "[]",
          cnt: "{}",
          reason: null,
          ...over,
        };
        return attempt(
          () => db.$executeRaw`
          INSERT INTO scan_db_snapshots (id, tool_id, source_version, upstream_built_at, size_bytes, sha256, status, rejected_reason, sources, record_counts)
          VALUES (gen_random_uuid(), ${v.tool}, ${v.ver}, now(), ${v.size}::bigint, ${v.sha}, ${v.reason ? "rejected" : "candidate"}, ${v.reason}, ${v.src}::jsonb, ${v.cnt}::jsonb)`,
        );
      };
      mustAccept(p, "a well-formed raw insert", await raw({}));
      for (const [label, over] of [
        ["grype", { tool: "grype" }],
        ["an unknown tool", { tool: "nope" }],
        ["a short digest", { sha: "abc" }],
        ["an upper-case digest", { sha: "A".repeat(64) }],
        ["zero size", { size: 0 }],
        ["a version with a space", { ver: "v 1" }],
        ["a version with a URL", { ver: "https://x/y" }],
        ["an empty version", { ver: "" }],
        ["an unknown reject reason", { reason: "because" }],
        ["sources that are not an array", { src: "{}" }],
        ["too many sources", { src: JSON.stringify(Array.from({ length: 60 }, () => "x")) }],
        ["huge counts", { cnt: JSON.stringify({ k: "x".repeat(5000) }) }],
      ])
        mustReject(p, label, await raw(over));
      await reset(db);
      await snapshotsExtra(c, p);
      return p;
    },
  },
  {
    id: "ENG-S12i",
    name: "the refresh job with a fake downloader and the promotion gate (SPEC scan-engines SE-33..SE-35, SE-45, 14.1 ENG-S12): a good snapshot is downloaded, hashed, verified against the upstream metadata, inspected, committed to its content address, written as a candidate, gated, materialized, canary-scanned and promoted atomically with the sources and the GHSA attribution recorded; a repeat of the same digest downloads nothing; a newer snapshot retires the previous one and exactly one stays active; a FAILED CANARY rejects the candidate, keeps the previous active snapshot and removes the object; a canary that cannot RUN keeps the candidate and the active snapshot, and the next refresh resumes it without downloading; the size and age sanity checks reject too_small, too_old and future_built (with the exact boundaries of `promotionSanity`); only the newest N retired snapshots keep their content; Grype is refused and nothing is downloaded; a lock held elsewhere skips the run and a lock taken is released; a downloader failure changes nothing; each denial has a control",
    async run(c) {
      const p = [];
      const { db } = c;
      await reset(db);
      // the pure gate, at its boundaries
      const cand = (size, built) => ({ sizeBytes: size, upstreamBuiltAt: built });
      const pol = { now: NOW, minSizePercent: 50, maxUpstreamAgeDays: 30 };
      same(p, "50 percent", promotionSanity(cand(50, hoursAgo(1)), { sizeBytes: 100 }, pol), null);
      same(
        p,
        "49 of 100",
        promotionSanity(cand(49, hoursAgo(1)), { sizeBytes: 100 }, pol),
        "too_small",
      );
      same(p, "no active", promotionSanity(cand(1, hoursAgo(1)), null, pol), null);
      same(p, "zero", promotionSanity(cand(0, hoursAgo(1)), null, pol), "empty");
      same(p, "age 30 days", promotionSanity(cand(10, daysAgo(30)), null, pol), null);
      same(
        p,
        "age 30 days + 1 ms",
        promotionSanity(cand(10, new Date(daysAgo(30).getTime() - 1)), null, pol),
        "too_old",
      );
      same(
        p,
        "now + 24 h",
        promotionSanity(cand(10, new Date(NOW.getTime() + 86_400_000)), null, pol),
        null,
      );
      same(
        p,
        "now + 24 h + 1 ms",
        promotionSanity(cand(10, new Date(NOW.getTime() + 86_400_001)), null, pol),
        "future_built",
      );

      // ---- happy path, repeat, newer snapshot
      const r1 = rigOf(c);
      try {
        const b1 = bundle({ padBytes: 2000 });
        r1.downloader.script("trivy", { bundle: b1 });
        const o1 = await r1.run();
        same(p, "first outcome", [o1.outcome, o1.sha256], ["promoted", sha256(b1)]);
        const active = await r1.repo.getActive("trivy");
        ok(
          p,
          active?.sha256 === sha256(b1) && active.status === "active" && active.promotedAt,
          "the snapshot is active",
        );
        ok(
          p,
          active.sources.some(
            (s) => s.id === "ghsa" && s.attributionRequired === true && s.licence === "CC-BY-4.0",
          ),
          "GHSA attribution is recorded",
        );
        ok(
          p,
          active.sources.every((s) => !/https?:/.test(JSON.stringify(s))),
          "no URL in the sources",
        );
        ok(
          p,
          active.recordCounts.bySource?.ghsa === 1 && active.recordCounts.quarantined === 0,
          "counts by source",
        );
        same(
          p,
          "upstream build time",
          active.upstreamBuiltAt.toISOString(),
          hoursAgo(2).toISOString(),
        );
        ok(
          p,
          active.sizeBytes === b1.length && active.sourceVersion === "2026.11.20.1",
          "size and version",
        );
        same(p, "object stored once", await objects(r1, "trivy"), [sha256(b1)]);
        ok(
          p,
          existsSync(r1.t.store.cacheDirFor({ tool: "trivy", sha256: sha256(b1) })),
          "materialized",
        );
        same(
          p,
          "canary ran against the materialized directory",
          r1.canaryCalls.map((x) => [x.toolId, x.sha256, x.dir]),
          [["trivy", sha256(b1), r1.t.store.cacheDirFor({ tool: "trivy", sha256: sha256(b1) })]],
        );
        // repeat: same digest
        r1.downloader.script("trivy", { bundle: b1 });
        const again = await r1.run();
        ok(
          p,
          again.outcome === "unchanged" &&
            r1.downloader.calls.download === 1 &&
            r1.canaryCalls.length === 1,
          `a repeat downloads and scans nothing (${again.outcome}, downloads ${r1.downloader.calls.download})`,
        );
        // another tool is independent
        r1.downloader.script("osv-scanner", { bundle: b1 });
        ok(
          p,
          (await r1.run("osv-scanner")).outcome === "promoted",
          "the same bytes for another tool are promoted separately",
        );
        same(p, "trivy is untouched", (await r1.repo.getActive("trivy")).sha256, sha256(b1));
        // newer
        const b2 = bundle({ padBytes: 2000 });
        r1.downloader.script("trivy", { bundle: b2 });
        const o2 = await r1.run();
        same(p, "newer outcome", o2.outcome, "promoted");
        same(p, "new active", (await r1.repo.getActive("trivy")).sha256, sha256(b2));
        same(p, "previous is retired", await statusOf(r1.repo, "trivy", sha256(b1)), "retired");
        const actives =
          await db.$queryRaw`SELECT count(*)::int AS n FROM scan_db_snapshots WHERE tool_id = 'trivy' AND status = 'active'`;
        same(p, "one active", actives[0].n, 1);
        ok(
          p,
          (await objects(r1, "trivy")).includes(sha256(b1)),
          "the previous object is kept for rollback",
        );
      } finally {
        r1.done();
      }

      // ---- failed canary keeps the previous snapshot
      await reset(db);
      const r2 = rigOf(c);
      try {
        const good = bundle();
        r2.downloader.script("trivy", { bundle: good });
        await r2.run();
        const poisoned = bundle();
        r2.deps.canary = async () => ({ ok: false, reason: "missing_advisory" });
        r2.downloader.script("trivy", { bundle: poisoned });
        const out = await r2.run("trivy", {
          canary: async () => ({ ok: false, reason: "missing_advisory" }),
        });
        same(p, "canary failure outcome", [out.outcome, out.reason], ["rejected", "canary_failed"]);
        same(
          p,
          "the previous snapshot is still active",
          (await r2.repo.getActive("trivy")).sha256,
          sha256(good),
        );
        same(p, "the poisoned row", await statusOf(r2.repo, "trivy", sha256(poisoned)), "rejected");
        ok(
          p,
          !(await objects(r2, "trivy")).includes(sha256(poisoned)),
          "the rejected object is removed",
        );
        ok(
          p,
          !existsSync(r2.t.store.cacheDirFor({ tool: "trivy", sha256: sha256(poisoned) })),
          "the rejected tree is removed",
        );
        // a rejected digest is not fetched again
        r2.downloader.script("trivy", { bundle: poisoned });
        const dl = r2.downloader.calls.download;
        const rej = await r2.run("trivy");
        ok(
          p,
          rej.outcome === "rejected" &&
            rej.reason === "canary_failed" &&
            r2.downloader.calls.download === dl,
          "a rejected digest stays rejected without a download",
        );
        // a throwing canary is `unavailable`, never a pass
        const b3 = bundle();
        r2.downloader.script("trivy", { bundle: b3 });
        const thrown = await r2.run("trivy", {
          canary: async () => {
            throw new Error("runtime down");
          },
        });
        ok(p, thrown.outcome === "canary_unavailable", `a canary that throws: ${thrown.outcome}`);
        same(p, "candidate kept", await statusOf(r2.repo, "trivy", sha256(b3)), "candidate");
        same(p, "active unchanged", (await r2.repo.getActive("trivy")).sha256, sha256(good));
        // resume without downloading
        const downloads = r2.downloader.calls.download;
        const resumed = await r2.run("trivy", { canary: async () => ({ ok: true }) });
        ok(
          p,
          resumed.outcome === "promoted" && r2.downloader.calls.download === downloads,
          `resumed (${resumed.outcome}, downloads ${r2.downloader.calls.download - downloads})`,
        );
      } finally {
        r2.done();
      }

      // ---- sanity gate on real rows
      await reset(db);
      const r3 = rigOf(c);
      try {
        r3.downloader.script("trivy", { bundle: bundle({ padBytes: 60000 }) });
        await r3.run();
        const activeSha = (await r3.repo.getActive("trivy")).sha256;
        for (const [label, step, reason] of [
          ["too small", { bundle: bundle({ padBytes: 100 }) }, "too_small"],
          [
            "too old",
            {
              bundle: bundle({ padBytes: 60000 }),
              metadata: { builtAt: daysAgo(40).toISOString() },
            },
            "too_old",
          ],
          [
            "future build",
            {
              bundle: bundle({ padBytes: 60000 }),
              metadata: { builtAt: new Date(NOW.getTime() + 3 * 86_400_000).toISOString() },
            },
            "future_built",
          ],
        ]) {
          r3.downloader.script("trivy", step);
          const out = await r3.run();
          ok(
            p,
            out.outcome === "rejected" && out.reason === reason,
            `${label}: ${out.outcome}/${out.reason}`,
          );
          same(
            p,
            `${label}: previous active`,
            (await r3.repo.getActive("trivy")).sha256,
            activeSha,
          );
          ok(p, !(await objects(r3, "trivy")).includes(out.sha256), `${label}: object removed`);
        }
        same(p, "canary never ran for a failed sanity check", r3.canaryCalls.length, 1);
        // control: a snapshot above 50 percent
        r3.downloader.script("trivy", { bundle: bundle({ padBytes: 40000 }) });
        ok(
          p,
          (await r3.run()).outcome === "promoted",
          "control: 2/3 of the active size is promoted",
        );
      } finally {
        r3.done();
      }

      // ---- retention of the previous N
      await reset(db);
      const r4 = rigOf(c, { cfg: { keepRetired: 1 } });
      try {
        const shas = [];
        for (let i = 0; i < 4; i += 1) {
          const b = bundle({ padBytes: 500 });
          shas.push(sha256(b));
          r4.downloader.script("osv-scanner", { bundle: b });
          const out = await r4.run("osv-scanner");
          ok(p, out.outcome === "promoted", `snapshot ${i} promoted`);
        }
        const stored = await objects(r4, "osv-scanner");
        same(
          p,
          "stored objects: the active one and one retired",
          stored.sort(),
          [shas[2], shas[3]].sort(),
        );
        const pruned = await db.scanDbSnapshot.findMany({
          where: { toolId: "osv-scanner", sha256: { in: shas.slice(0, 2) } },
        });
        ok(
          p,
          pruned.length === 2 && pruned.every((r) => r.contentPrunedAt && r.status === "retired"),
          "pruned rows are kept as provenance",
        );
        ok(
          p,
          (await db.scanDbSnapshot.findFirst({ where: { sha256: shas[2] } })).contentPrunedAt ===
            null,
          "the kept retired row is not pruned",
        );
      } finally {
        r4.done();
      }

      // ---- Grype, locks, downloader failure
      await reset(db);
      const r5 = rigOf(c);
      try {
        r5.downloader.script("trivy", { bundle: bundle() });
        const grype = await attempt(() => r5.run("grype"));
        ok(
          p,
          !grype.ok && r5.downloader.calls.latest === 0 && r5.downloader.calls.download === 0,
          "Grype is refused before any download",
        );
        let released = 0;
        const held = rigOf(c, { lock: { acquirePlatform: async () => null } });
        try {
          held.downloader.script("trivy", { bundle: bundle() });
          const skipped = await held.run();
          ok(
            p,
            skipped.outcome === "skipped_locked" && held.downloader.calls.latest === 0,
            "a lock held elsewhere skips the run",
          );
        } finally {
          held.done();
        }
        const lock = {
          acquirePlatform: async ({ resource, ttlMs }) =>
            resource === "scan-db-refresh-trivy" && ttlMs === 3_600_000
              ? {
                  release: async () => {
                    released += 1;
                    return true;
                  },
                }
              : null,
        };
        const locked = rigOf(c, { lock });
        try {
          locked.downloader.script("trivy", { bundle: bundle() });
          ok(
            p,
            (await locked.run()).outcome === "promoted" && released === 1,
            "the lock is taken per tool and released",
          );
          const failing = {
            ...locked.deps.downloader,
            latest: async () => {
              throw new Error("network down");
            },
          };
          const before = (await locked.repo.getActive("trivy")).sha256;
          const err = await attempt(() => locked.run("trivy", { downloader: failing }));
          ok(p, !err.ok && released === 2, "a failing downloader releases the lock");
          same(p, "nothing changed", (await locked.repo.getActive("trivy")).sha256, before);
        } finally {
          locked.done();
        }
      } finally {
        r5.done();
      }
      await reset(db);
      await refreshExtra(c, p);
      return p;
    },
  },
  {
    id: "ENG-S12j",
    name: "a tampered, hostile or unclean download never becomes active (SPEC scan-engines SE-34, SE-45, SE-46, T13, ENG-S12, ENG-L19): bytes that differ from the upstream sha256, a lying size, a stream over the size cap, a corrupted or truncated archive, a zip bomb, a traversal or symlink entry, a Chainguard/Wolfi or non-commercial record, a distro record and an unknown or quarantined declared source are each REJECTED (recorded under the digest this process computed, or not at all before a download), the previous active snapshot stays active, no object or staging file is left, a quarantined or unknown declared source downloads NOTHING, invalid upstream metadata stops before any download, and an upstream cannot poison the table with a digest it merely claims; a crash between the object commit and the candidate row, and between the candidate row and the promotion, is recovered by the next refresh (the object is reused, the candidate resumed) and the abandon sweep rejects a stale candidate; each denial has a control",
    async run(c) {
      const p = [];
      const { db } = c;
      await reset(db);
      const rig = rigOf(c);
      try {
        const base = bundle({ padBytes: 3000 });
        rig.downloader.script("trivy", { bundle: base });
        await rig.run();
        const baseSha = sha256(base);
        const stageLeft = () =>
          existsSync(path.join(rig.t.root, "stage"))
            ? readdirSync(path.join(rig.t.root, "stage")).length
            : 0;
        const expectRejected = async (label, step, reason, { row = true, downloads = 1 } = {}) => {
          const dl0 = rig.downloader.calls.download;
          rig.downloader.script("trivy", step);
          const out = await rig.run();
          ok(
            p,
            out.outcome === "rejected" && out.reason === reason,
            `${label}: ${out.outcome}/${out.reason}`,
          );
          same(p, `${label}: previous active`, (await rig.repo.getActive("trivy")).sha256, baseSha);
          same(p, `${label}: downloads`, rig.downloader.calls.download - dl0, downloads);
          same(p, `${label}: stage left`, stageLeft(), 0);
          same(p, `${label}: objects`, await objects(rig, "trivy"), [baseSha]);
          if (row)
            ok(
              p,
              !!out.sha256 && (await statusOf(rig.repo, "trivy", out.sha256)) === "rejected",
              `${label}: recorded as rejected`,
            );
          return out;
        };
        // integrity
        const good = bundle({ padBytes: 3000 });
        const tampered = Buffer.from(good);
        tampered[tampered.length - 50] ^= 0x01;
        const t1 = await expectRejected(
          "bytes differ from the upstream digest",
          { bundle: good, downloaded: tampered },
          "integrity_mismatch",
        );
        ok(
          p,
          t1.sha256 !== sha256(good),
          "the row is recorded under the digest of the bytes received, not the claim",
        );
        ok(
          p,
          (await statusOf(rig.repo, "trivy", sha256(good))) === null,
          "the claimed digest is NOT in the table (no poisoning)",
        );
        await expectRejected(
          "a lying size",
          { bundle: good, metadata: { sizeBytes: good.length + 1 } },
          "integrity_mismatch",
        );
        const other = bundle({ padBytes: 3000 });
        const claimed = bundle({ padBytes: 3000 });
        await expectRejected(
          "another file under a valid digest claim",
          { bundle: claimed, downloaded: other },
          "integrity_mismatch",
        );
        // the stream cap: the claim is small, the stream is large
        const capRig = rigOf(c, { cfg: { maxBytes: 5000 } });
        try {
          const big = bundle({ padBytes: 20000 });
          capRig.downloader.script("trivy", {
            bundle: big,
            metadata: { sizeBytes: 100, sha256: sha256(big) },
          });
          const out = await capRig.run();
          ok(
            p,
            out.outcome === "rejected" && out.reason === "too_large",
            `a stream over the cap: ${out.reason}`,
          );
          same(
            p,
            "nothing staged or stored",
            [
              existsSync(path.join(capRig.t.root, "stage"))
                ? readdirSync(path.join(capRig.t.root, "stage")).length
                : 0,
              await objects(capRig, "trivy"),
            ],
            [0, []],
          );
          const claimBig = bundle({ padBytes: 20000 });
          capRig.downloader.script("trivy", { bundle: claimBig });
          const d0 = capRig.downloader.calls.download;
          const out2 = await capRig.run();
          ok(
            p,
            out2.reason === "too_large" && capRig.downloader.calls.download === d0,
            "a claimed size over the cap is refused before the download",
          );
          capRig.downloader.calls.download -= 0;
        } finally {
          capRig.done();
        }
        // hostile and unclean content (row recorded with the real digest)
        const records = (...r) => bundle({ records: r, padBytes: 3000 });
        const rec = (id, over = {}) => ({
          id,
          aliases: [],
          affected: [{ package: { ecosystem: "npm", name: "x" } }],
          ...over,
        });
        const cases = [
          [
            "a zip bomb",
            bundle({
              extra: [{ name: "data/zeros.bin", content: Buffer.alloc(24 * 1024 * 1024) }],
            }),
            "archive_hostile",
          ],
          [
            "a traversal entry",
            bundle({ extra: [{ raw: true, name: "../../evil", content: "x" }] }),
            "archive_hostile",
          ],
          [
            "a symbolic link",
            bundle({ extra: [{ name: "records/npm/l.json", type: "2", linkname: "/etc/shadow" }] }),
            "archive_hostile",
          ],
          ["a truncated archive", good.subarray(0, Math.floor(good.length / 2)), "archive_hostile"],
          [
            "a Chainguard record",
            records(rec("GHSA-aaaa-bbbb-cccc"), rec("CGA-aaaa-bbbb-cccc")),
            "quarantined_source",
          ],
          [
            "a Wolfi ecosystem record",
            records(
              rec("GHSA-aaaa-bbbb-cccc", { affected: [{ package: { ecosystem: "Wolfi" } }] }),
            ),
            "quarantined_source",
          ],
          [
            "a non-commercial licence record",
            records(rec("GHSA-aaaa-bbbb-cccc", { database_specific: { license: "CC-BY-NC-4.0" } })),
            "quarantined_source",
          ],
          [
            "a distro record",
            records(rec("DSA-1-1", { affected: [{ package: { ecosystem: "Debian:12" } }] })),
            "source_not_allowed",
          ],
          ["a malformed record", records("{ nope"), "record_invalid"],
          [
            "a bundle declaring Chainguard",
            bundle({ sources: ["ghsa", "chainguard"], padBytes: 3000 }),
            "quarantined_source",
          ],
        ];
        for (const [label, buffer, reason] of cases) {
          let step = { bundle: buffer };
          // a truncated archive cannot carry its own digest claim computed from a full file: the claim is the digest of the bytes served
          step = { bundle: buffer };
          await expectRejected(label, step, reason);
        }
        // declared sources: nothing is downloaded at all
        for (const [label, sources, reason] of [
          ["a declared Chainguard source", ["ghsa", "chainguard"], "quarantined_source"],
          ["a declared Grype DB source", ["grype-db"], "quarantined_source"],
          ["a declared Wolfi source", ["wolfi"], "quarantined_source"],
          ["a declared unknown source", ["ghsa", "somewhere"], "source_not_allowed"],
        ]) {
          const dl0 = rig.downloader.calls.download;
          const b = bundle({ padBytes: 3000 });
          rig.downloader.script("trivy", { bundle: b, metadata: { sources } });
          const out = await rig.run();
          ok(
            p,
            out.outcome === "rejected" &&
              out.reason === reason &&
              rig.downloader.calls.download === dl0,
            `${label}: ${out.outcome}/${out.reason}, downloads ${rig.downloader.calls.download - dl0}`,
          );
          same(p, `${label}: no row`, await statusOf(rig.repo, "trivy", sha256(b)), null);
        }
        // invalid upstream metadata stops before any download
        for (const [label, over] of [
          ["an extra key (a URL)", { url: "https://example.invalid/db" }],
          ["a malformed digest", { sha256: "xyz" }],
          ["a zero size", { sizeBytes: 0 }],
          ["a version with a token", { sourceVersion: "v1 ghp_abcdefghijklmnopqrstuv1234" }],
          ["no sources", { sources: [] }],
          ["a date that is not a date", { builtAt: "yesterday" }],
        ]) {
          const dl0 = rig.downloader.calls.download;
          rig.downloader.script("trivy", { bundle: bundle(), metadata: over });
          const r = await attempt(() => rig.run());
          ok(
            p,
            !r.ok && rig.downloader.calls.download === dl0,
            `${label}: refused before a download`,
          );
          ok(p, !/ghp_/.test(r.message), `${label}: the error does not echo the value`);
        }
        same(
          p,
          "the active snapshot never moved",
          (await rig.repo.getActive("trivy")).sha256,
          baseSha,
        );
        // control: the same pipeline accepts a clean bundle
        rig.downloader.script("trivy", {
          bundle: records(
            rec("GHSA-aaaa-bbbb-cccc"),
            rec("PYSEC-2021-1", { affected: [{ package: { ecosystem: "PyPI" } }] }),
          ),
        });
        ok(p, (await rig.run()).outcome === "promoted", "control: a clean bundle is promoted");
      } finally {
        rig.done();
      }

      // ---- crash recovery
      await reset(db);
      const r2 = rigOf(c);
      try {
        const b = bundle({ padBytes: 1000 });
        // a crash after the object commit and before the candidate row: the object exists, no row
        const staged = await r2.t.store.stage((await import("node:stream")).Readable.from([b]), {
          maxBytes: 1 << 20,
        });
        await r2.t.store.commit({ tool: "trivy", sha256: sha256(b), stageId: staged.stageId });
        r2.downloader.script("trivy", { bundle: b });
        ok(
          p,
          (await r2.run()).outcome === "promoted",
          "an orphan object is reused by the next refresh",
        );
        same(p, "one object", await objects(r2, "trivy"), [sha256(b)]);
        // a crash between the candidate row and the promotion: the canary was unavailable
        const b2 = bundle({ padBytes: 1000 });
        r2.downloader.script("trivy", { bundle: b2 });
        const first = await r2.run("trivy", {
          canary: async () => ({ ok: false, reason: "unavailable" }),
        });
        same(p, "interrupted", first.outcome, "canary_unavailable");
        same(
          p,
          "the previous snapshot serves meanwhile",
          (await r2.repo.getActive("trivy")).sha256,
          sha256(b),
        );
        // a stale candidate is abandoned by the sweep; a fresh one is not
        const stale = await r2.repo.abandonStaleCandidates({ olderThanSeconds: 3600 });
        same(
          p,
          "a fresh candidate is kept",
          stale.filter((s) => s.sha256 === sha256(b2)).length,
          0,
        );
        const swept = await r2.repo.abandonStaleCandidates({ olderThanSeconds: 0 });
        ok(
          p,
          swept.some((s) => s.sha256 === sha256(b2)),
          "a stale candidate is abandoned",
        );
        same(
          p,
          "abandoned",
          (await db.scanDbSnapshot.findFirst({ where: { sha256: sha256(b2) } })).rejectedReason,
          "abandoned",
        );
      } finally {
        r2.done();
      }
      await reset(db);
      await hostileExtra(c, p);
      return p;
    },
  },
  {
    id: "ENG-S12k",
    name: "the switch to a new snapshot is atomic (SPEC scan-engines SE-35, SE-33): while snapshots are promoted one after another, concurrent readers of the active snapshot ALWAYS see exactly one active row (never none, never two) and never a candidate or retired row; a crash between the two steps of the switch (the old snapshot retired, the new one not yet active) rolls BOTH back and the previous snapshot stays active; activating without retiring is refused by the one-active index; two promotions racing for one tool serialize and leave exactly one active; a candidate that is no longer a candidate is not promoted; promotion of a rejected or retired row promotes nothing; each denial has a control",
    async run(c) {
      const p = [];
      const { db } = c;
      await reset(db);
      const repo = createScanDbSnapshotRepository({ db });
      const tool = "osv-scanner";
      const first = await makeActive(repo, { toolId: tool });
      // crash between the steps
      const next = (await repo.insertCandidate(candidateInput({ toolId: tool }))).snapshot;
      const crash = await attempt(() =>
        db.$transaction(async (tx) => {
          const retired = await repo.retireActive(tool, tx);
          if (retired !== first.id)
            throw new Error("fixture: the old snapshot was not retired inside the transaction");
          throw new Error("simulated crash between the two steps");
        }),
      );
      ok(p, !crash.ok && /simulated crash/.test(crash.message), "the crash surfaced");
      same(p, "previous still active after the crash", (await repo.getActive(tool))?.id, first.id);
      same(p, "candidate still a candidate", await statusOf(repo, tool, next.sha256), "candidate");
      const crash2 = await attempt(() =>
        db.$transaction(async (tx) => {
          await repo.retireActive(tool, tx);
          await repo.activate(next.id, tx);
          throw new Error("simulated crash after both steps, before commit");
        }),
      );
      ok(p, !crash2.ok, "second crash surfaced");
      same(
        p,
        "previous still active after the late crash",
        (await repo.getActive(tool))?.id,
        first.id,
      );
      mustAccept(
        p,
        "control: the complete switch",
        await attempt(() => repo.promote({ id: next.id, toolId: tool })),
      );
      same(p, "new active", (await repo.getActive(tool))?.id, next.id);
      same(p, "old retired", await statusOf(repo, tool, first.sha256), "retired");
      // promote of non-candidates
      same(
        p,
        "promote a retired row",
        (await repo.promote({ id: first.id, toolId: tool })).promoted,
        false,
      );
      const { snapshot: rejected } = await repo.insertCandidate(candidateInput({ toolId: tool }));
      await repo.reject({ id: rejected.id, reason: "canary_failed" });
      same(
        p,
        "promote a rejected row",
        (await repo.promote({ id: rejected.id, toolId: tool })).promoted,
        false,
      );
      same(
        p,
        "promote an unknown id",
        (await repo.promote({ id: randomUUID(), toolId: tool })).promoted,
        false,
      );
      same(p, "the active one is untouched", (await repo.getActive(tool))?.id, next.id);
      ok(
        p,
        (await repo.reject({ id: next.id, reason: "canary_failed" })) === false,
        "an active row cannot be rejected",
      );
      // two promotions racing
      const a = (await repo.insertCandidate(candidateInput({ toolId: tool }))).snapshot;
      const b = (await repo.insertCandidate(candidateInput({ toolId: tool }))).snapshot;
      const race = await Promise.all([
        repo.promote({ id: a.id, toolId: tool }),
        repo.promote({ id: b.id, toolId: tool }),
      ]);
      ok(
        p,
        race.every((r) => r.promoted),
        "both racing promotions completed (serialized)",
      );
      const n =
        await db.$queryRaw`SELECT count(*)::int AS n FROM scan_db_snapshots WHERE tool_id = ${tool} AND status = 'active'`;
      same(p, "exactly one active after the race", n[0].n, 1);
      // concurrent readers during a series of promotions
      let stop = false;
      const seen = { none: 0, many: 0, notActive: 0, reads: 0 };
      const reader = async () => {
        while (!stop) {
          const rows =
            await db.$queryRaw`SELECT count(*) FILTER (WHERE status = 'active')::int AS active, count(*)::int AS total FROM scan_db_snapshots WHERE tool_id = ${tool} AND status IN ('active', 'retired') AND promoted_at IS NOT NULL`;
          seen.reads += 1;
          if (rows[0].active === 0) seen.none += 1;
          if (rows[0].active > 1) seen.many += 1;
          const act = await repo.getActive(tool);
          if (act === null) seen.none += 1;
          else if (act.status !== "active") seen.notActive += 1;
        }
      };
      const readers = Array.from({ length: 6 }, reader);
      for (let i = 0; i < 12; i += 1) {
        const { snapshot } = await repo.insertCandidate(candidateInput({ toolId: tool }));
        await repo.promote({ id: snapshot.id, toolId: tool });
      }
      stop = true;
      await Promise.all(readers);
      ok(p, seen.reads > 50, `the readers ran (${seen.reads} reads)`);
      same(p, "reads that saw no active snapshot", seen.none, 0);
      same(p, "reads that saw two active snapshots", seen.many, 0);
      same(p, "reads that saw a non-active row as active", seen.notActive, 0);
      // activate without retire
      await reset(db);
      await makeActive(repo, { toolId: tool });
      const c2 = (await repo.insertCandidate(candidateInput({ toolId: tool }))).snapshot;
      mustReject(
        p,
        "activate without retiring the old one",
        await attempt(() => db.$transaction((tx) => repo.activate(c2.id, tx))),
        "23505",
      );
      await reset(db);
      return p;
    },
  },
  {
    id: "ENG-S12l",
    name: "the dbrefresh handler, the scheduler message and the logs (SPEC scan-engines SE-34, SE-39, 9.2, ADR-011): the handler refreshes the tools the message names AND the process allows (an extra tool in the message is ignored), tools one after another, continues after one tool's unexpected failure and re-throws it at the end so the queue retries (the refresh is idempotent), re-throws a non-retryable refusal at once, sweeps abandoned candidates and old staging files, and logs only tool ids, outcome words, reason words, counts and digests (no URL, host, token, path or upstream text, even when the upstream or the downloader errors carry one); the scheduler's message for one time bucket is enqueued ONCE however many schedulers tick; the message is a platform job with no tenant; the refresh is not enqueued at all unless configured",
    async run(c) {
      const p = [];
      const { db } = c;
      await reset(db);
      const rig = rigOf(c);
      try {
        const { log, lines } = recordingLog();
        const config = { scanDb: scanDbConfig({ tools: ["trivy", "osv-scanner"] }) };
        const handler = createDbRefreshHandler({ config, deps: rig.deps });
        const job = (tools) =>
          createJobEnvelope({
            type: "maintenance.scan_db.refresh_requested",
            schemaVersion: 1,
            initiator: { type: "system", id: "scheduler" },
            payload: { tools },
          });
        const bT = bundle({ padBytes: 500 });
        const bO = bundle({ padBytes: 500 });
        rig.downloader.script("trivy", { bundle: bT }).script("osv-scanner", { bundle: bO });
        await handler(job(["trivy", "osv-scanner"]), { log });
        same(
          p,
          "both tools refreshed",
          [
            (await rig.repo.getActive("trivy")).sha256,
            (await rig.repo.getActive("osv-scanner")).sha256,
          ],
          [sha256(bT), sha256(bO)],
        );
        const summary = lines.find((l) => /refresh finished/i.test(l.msg ?? ""));
        ok(p, !!summary && summary.obj.outcomes.length === 2, "the summary line");
        // the process's own list wins
        const narrow = createDbRefreshHandler({
          config: { scanDb: scanDbConfig({ tools: ["osv-scanner"] }) },
          deps: rig.deps,
        });
        const dl0 = rig.downloader.calls.tools.length;
        rig.downloader.script("osv-scanner", { bundle: bundle({ padBytes: 500 }) });
        await narrow(job(["trivy", "osv-scanner"]), { log });
        same(p, "only the allowed tool was contacted", rig.downloader.calls.tools.slice(dl0), [
          "osv-scanner",
        ]);
        // failure of one tool does not stop the other; the error is re-thrown after
        const secretError = new Error(
          "GET https://secret.example.invalid/db?token=ghp_abcdefghijklmnopqrstuv1234 failed",
        );
        const failingDownloader = {
          ...rig.downloader,
          latest: async ({ toolId }) => {
            if (toolId === "trivy") throw secretError;
            return rig.downloader.latest({ toolId });
          },
        };
        const failing = createDbRefreshHandler({
          config,
          deps: { ...rig.deps, downloader: failingDownloader },
        });
        const bO2 = bundle({ padBytes: 500 });
        rig.downloader.script("osv-scanner", { bundle: bO2 });
        const failure = await attempt(() => failing(job(["trivy", "osv-scanner"]), { log }));
        ok(
          p,
          !failure.ok && failure.message.includes("secret.example"),
          "the unexpected error is re-thrown for the queue retry",
        );
        same(
          p,
          "the second tool was still refreshed",
          (await rig.repo.getActive("osv-scanner")).sha256,
          sha256(bO2),
        );
        // a non-retryable refusal is thrown at once
        const refusing = createDbRefreshHandler({
          config,
          deps: {
            ...rig.deps,
            downloader: {
              latest: async () => {
                throw new NonRetryableError("x", { reason: "downloader-unconfigured" });
              },
              download: async () => {},
            },
          },
        });
        const refused = await refusing(job(["trivy", "osv-scanner"]), { log }).then(
          () => null,
          (e) => e,
        );
        ok(p, refused instanceof NonRetryableError, "a non-retryable refusal is not retried");
        // logs: no URL, token, path
        const text = JSON.stringify(lines);
        ok(
          p,
          !/https?:|secret\.example|ghp_|token=|\/tmp\/|qm-dbm|\/srv\//i.test(text),
          `a log line carries a URL, token or path: ${text.slice(0, 200)}`,
        );
        ok(
          p,
          lines.every((l) => l.obj && typeof l.obj === "object"),
          "structured lines",
        );
        // housekeeping: stale staging files
        const staged = await rig.t.store.stage(
          (await import("node:stream")).Readable.from([Buffer.from("x")]),
          { maxBytes: 100 },
        );
        const old = new Date(Date.now() - 2 * 3600_000);
        const { utimesSync } = await import("node:fs");
        utimesSync(path.join(rig.t.root, "stage", staged.stageId), old, old);
        rig.downloader.script("trivy", { bundle: bundle({ padBytes: 500 }) });
        await handler(job(["trivy"]), { log });
        ok(
          p,
          !existsSync(path.join(rig.t.root, "stage", staged.stageId)),
          "an old staging file is swept",
        );
      } finally {
        rig.done();
      }
      // scheduler: one message per bucket
      const intervalSeconds = 21600;
      const now = new Date("2026-11-20T12:00:00.000Z");
      for (let i = 0; i < 3; i += 1)
        await enqueuePlatformJob({
          db,
          queue: "dbrefresh",
          type: "maintenance.scan_db.refresh_requested",
          prefix: "scan-db-refresh",
          intervalSeconds,
          payload: { tools: ["trivy", "osv-scanner"] },
          now: new Date(now.getTime() + i * 1000),
        });
      const rows = await db.outboxMessage.findMany({
        where: {
          queue: "dbrefresh",
          messageId: `scan-db-refresh-${Math.floor(now.getTime() / (intervalSeconds * 1000))}`,
        },
      });
      same(p, "messages enqueued for one bucket", rows.length, 1);
      ok(
        p,
        rows[0]?.tenantId === null && rows[0]?.type === "maintenance.scan_db.refresh_requested",
        "a platform message without a tenant",
      );
      same(p, "the payload names tools only", Object.keys(rows[0]?.payload?.payload ?? {}), [
        "tools",
      ]);
      return p;
    },
  },
  {
    id: "ENG-S12m",
    name: "the provenance of a result is tenant-scoped and leaks nothing (SPEC scan-engines SE-37, ENG-S08, 7.3, ENG-L09): the active snapshot of the shared platform table is resolved for a scan, its digest and build time are recorded in the TENANT-OWNED `scan_tool_runs` row of a task and read back with the digest and the date; tenant B reads nothing of tenant A's tool run (the read needs the tenant AND the task) and cannot insert a run for A's task; the provenance object has the digest, the dates, the tier and the attribution flag and no internal id, store path, reject reason or source URL; a stale snapshot yields a partial/`db_stale` tool run that the database accepts and that rolls up as incomplete, never as a failed task; a missing snapshot yields `unavailable` / `db_unavailable` with no digest",
    async run(c) {
      const p = [];
      const { db, A, B } = c;
      await reset(db);
      const rig = rigOf(c);
      try {
        const bundleA = bundle({ padBytes: 500 });
        rig.downloader.script("trivy", {
          bundle: bundleA,
          metadata: { builtAt: daysAgo(5).toISOString() },
        });
        const out = await rig.run();
        ok(p, out.outcome === "promoted", `fixture promoted (${out.outcome}/${out.reason})`);
        const resolver = createDbSnapshotResolver({
          repo: rig.repo,
          store: rig.t.store,
          now: clock,
        });
        const resolved = await resolver.resolve("trivy");
        ok(
          p,
          resolved.state === "ok" && resolved.provenance.stalenessTier === "aging",
          "resolved: aging",
        );
        const eA = await inState(c, A, "running", 0);
        const eB = await inState(c, B, "running", 0);
        const taskA = await runningTask(c, eA, "sca");
        await runningTask(c, eB, "sca");
        const runs = createScanToolRunRepository({ db });
        const stamp = {
          startedAt: "2026-11-20T10:00:00.000Z",
          finishedAt: "2026-11-20T10:00:05.000Z",
        };
        const inserted = await runs.insertMany({
          tenantId: eA.tenantId,
          executionId: eA.id,
          scanTaskId: taskA.id,
          attempt: taskA.attempt,
          runs: [
            {
              toolId: "trivy",
              toolVersion: "0.58.0",
              imageDigest: `sha256:${"ab".repeat(32)}`,
              configDigest: "cd".repeat(32),
              status: resolved.effect.toolStatus,
              reason: resolved.effect.reason,
              dbSnapshotSha256: resolved.provenance.dbSnapshotSha256,
              dbBuiltAt: resolved.provenance.dbBuiltAt,
              exitCode: 0,
              durationMs: 5000,
              scope: { kind: "full" },
              ...stamp,
            },
          ],
        });
        same(p, "the stale tool run is accepted", inserted.inserted, 1);
        const readA = await runs.listForTask({
          tenantId: eA.tenantId,
          executionId: eA.id,
          scanTaskId: taskA.id,
        });
        ok(
          p,
          readA.length === 1 &&
            readA[0].dbSnapshotSha256 === sha256(bundleA) &&
            new Date(readA[0].dbBuiltAt).toISOString() === daysAgo(5).toISOString() &&
            readA[0].status === "partial" &&
            readA[0].reason === "db_stale",
          "the tenant reads its provenance back",
        );
        // tenant B
        same(
          p,
          "tenant B reads nothing",
          (
            await runs.listForTask({
              tenantId: eB.tenantId,
              executionId: eA.id,
              scanTaskId: taskA.id,
            })
          ).length,
          0,
        );
        same(
          p,
          "tenant B reads nothing even with its own execution",
          (
            await runs.listForTask({
              tenantId: eB.tenantId,
              executionId: eB.id,
              scanTaskId: taskA.id,
            })
          ).length,
          0,
        );
        const forged = await runs
          .insertMany({
            tenantId: eB.tenantId,
            executionId: eA.id,
            scanTaskId: taskA.id,
            attempt: taskA.attempt,
            runs: [
              {
                toolId: "osv-scanner",
                toolVersion: "1",
                configDigest: "cd".repeat(32),
                imageDigest: `sha256:${"ab".repeat(32)}`,
                status: "succeeded",
                exitCode: 0,
                durationMs: 1,
                scope: { kind: "full" },
                ...stamp,
              },
            ],
          })
          .catch(() => ({ inserted: 0 }));
        same(p, "tenant B cannot insert a run for A's task", forged.inserted, 0);
        // the DTO
        const keys = Object.keys(resolved.provenance).sort();
        same(p, "provenance keys", keys, [
          "attributionRequired",
          "dbBuiltAt",
          "dbFetchedAt",
          "dbSnapshotSha256",
          "stalenessTier",
          "toolId",
        ]);
        ok(
          p,
          !/https?:|\/tmp\/|rejected|"id"/.test(JSON.stringify(resolved.provenance)),
          "no URL, path, reason or id in the provenance",
        );
        const row = await rig.repo.getActive("trivy");
        ok(
          p,
          dbProvenance(row, { now: clock() }).attributionRequired === true,
          "the attribution flag follows the recorded sources",
        );
        // the roll-up of a stale run
        const { rollUpTask } = await import("@qmentisai/shared");
        const roll = rollUpTask({
          tools: [
            { toolId: "trivy", status: readA[0].status, reason: readA[0].reason },
            { toolId: "osv-scanner", status: "succeeded", reason: null },
          ],
        });
        ok(
          p,
          roll.taskStatus === "succeeded" &&
            roll.completeness === "incomplete" &&
            !roll.resolutionEligible,
          "a stale run is an incomplete success",
        );
        // missing snapshot
        await reset(db);
        const none = await resolver.resolve("trivy");
        ok(
          p,
          none.state === "missing" &&
            none.effect.reason === "db_unavailable" &&
            none.provenance === undefined,
          "no active snapshot: unavailable, no digest",
        );
      } finally {
        rig.done();
      }
      await reset(db);
      return p;
    },
  },
  {
    id: "ENG-S12n",
    name: "a refresh blocked by quarantine raises the operator alert, once per digest, and the alert leaks nothing (SPEC scan-engines SE-39, 5.12.1, D-24 (f), ENG-S12): a snapshot that contains quarantined records (stage inspected) and a refresh whose upstream DECLARES a quarantined source (stage declared, nothing downloaded) each write ONE platform audit entry scan_db.quarantine_denied (system actor, no tenant, no target id) carrying only the tool id, the fixed reason word, the stage word, the digest and integer counts, and ONE warn log line with fixed words; a repeated refresh of the same rejected digest writes no second entry and no second line and downloads nothing; a different quarantined digest alerts again; rejections that are not quarantine (integrity, hostile archive, a distro or unknown source) raise no alert; a failure to record the alert never changes the outcome, is logged with a fixed word without echoing the cause, and the next refresh of the same digest records it; five concurrent recordings of one digest write one entry; the repository refuses an unknown tool, a malformed digest and an unknown stage and turns hostile counts into null; no upstream text, URL, source name, record id or token reaches the entry or the log, and the Root Console audit mapper shows it as a failure of the system actor",
    async run(c) {
      const p = [];
      const { db } = c;
      await reset(db);
      const rig = rigOf(c);
      const ACTION = "scan_db.quarantine_denied";
      const alertRows = (sha) =>
        db.$queryRaw`SELECT id, actor_type::text AS "actorType", actor_platform_user_id AS "actorId", tenant_id AS "tenantId", target_type AS "targetType", target_id AS "targetId", action, metadata
                     FROM platform_audit_logs WHERE action = ${ACTION} AND metadata->>'sha256' = ${sha}`;
      const alertTotal = async () =>
        Number(
          (
            await db.$queryRaw`SELECT count(*)::int AS n FROM platform_audit_logs WHERE action = ${ACTION}`
          )[0].n,
        );
      const blockedLines = () =>
        rig.lines.filter((l) => l.msg === "Vulnerability DB refresh blocked by quarantine");
      const records = (...r) => bundle({ records: r, padBytes: 3000 });
      const rec = (id, over = {}) => ({
        id,
        aliases: [],
        affected: [{ package: { ecosystem: "npm", name: "x" } }],
        ...over,
      });
      try {
        const base = bundle({ padBytes: 3000 });
        rig.downloader.script("trivy", { bundle: base });
        const first = await rig.run();
        ok(p, first.outcome === "promoted", `fixture promoted (${first.outcome})`);
        const total0 = await alertTotal();

        // 1. a snapshot that contains quarantined records
        const quarantined = records(rec("GHSA-aaaa-bbbb-cccc"), rec("CGA-aaaa-bbbb-cccc"));
        const qSha = sha256(quarantined);
        rig.downloader.script("trivy", { bundle: quarantined });
        const out1 = await rig.run();
        ok(
          p,
          out1.outcome === "rejected" &&
            out1.reason === "quarantined_source" &&
            out1.alerted === true &&
            out1.sha256 === qSha,
          `inspected quarantine: ${JSON.stringify(out1)}`,
        );
        const rows1 = await alertRows(qSha);
        same(p, "one entry for the digest", rows1.length, 1);
        const r1 = rows1[0];
        same(
          p,
          "the entry is a platform system entry without tenant or target id",
          [r1?.actorType, r1?.actorId, r1?.tenantId, r1?.targetType, r1?.targetId],
          ["system", null, null, "scan_db_snapshot", null],
        );
        same(p, "metadata keys", Object.keys(r1?.metadata ?? {}).sort(), [
          "invalid",
          "notAllowed",
          "quarantined",
          "reason",
          "records",
          "sha256",
          "stage",
          "toolId",
        ]);
        same(
          p,
          "metadata values",
          [
            r1?.metadata.toolId,
            r1?.metadata.reason,
            r1?.metadata.stage,
            r1?.metadata.records,
            r1?.metadata.quarantined,
            r1?.metadata.notAllowed,
            r1?.metadata.invalid,
          ],
          ["trivy", "quarantined_source", "inspected", 2, 1, 0, 0],
        );
        same(p, "one warn line", blockedLines().length, 1);
        same(
          p,
          "the warn line carries only the tool, the reason, the stage, the digest and the marker",
          Object.keys(blockedLines()[0]?.obj ?? {}).sort(),
          ["alert", "reason", "sha256", "stage", "toolId"],
        );
        same(p, "the warn line level", blockedLines()[0]?.level, "warn");

        // 2. the same digest again: no download, no second entry, no second line
        const dl0 = rig.downloader.calls.download;
        rig.downloader.script("trivy", { bundle: quarantined });
        const out2 = await rig.run();
        ok(
          p,
          out2.outcome === "rejected" &&
            out2.reason === "quarantined_source" &&
            out2.alerted === false,
          `repeat: ${JSON.stringify(out2)}`,
        );
        same(p, "repeat: downloads", rig.downloader.calls.download - dl0, 0);
        same(p, "repeat: entries", (await alertRows(qSha)).length, 1);
        same(p, "repeat: warn lines", blockedLines().length, 1);

        // 3. another quarantined digest alerts again
        const quarantined2 = records(rec("GHSA-aaaa-bbbb-dddd"), rec("CGA-aaaa-bbbb-dddd"));
        rig.downloader.script("trivy", { bundle: quarantined2 });
        const out3 = await rig.run();
        ok(p, out3.alerted === true, "a new digest alerts");
        same(p, "two digests, two entries", (await alertTotal()) - total0, 2);

        // 4. a declared quarantined source: nothing downloaded, the digest is the upstream's claim
        const declaredBundle = bundle({ padBytes: 3000 });
        const dSha = sha256(declaredBundle);
        const dl1 = rig.downloader.calls.download;
        rig.downloader.script("trivy", {
          bundle: declaredBundle,
          metadata: { sources: ["ghsa", "chainguard"] },
        });
        const out4 = await rig.run();
        ok(
          p,
          out4.outcome === "rejected" &&
            out4.reason === "quarantined_source" &&
            out4.alerted === true &&
            out4.sha256 === dSha &&
            rig.downloader.calls.download === dl1,
          `declared quarantine: ${JSON.stringify(out4)}`,
        );
        const rows4 = await alertRows(dSha);
        same(
          p,
          "declared entry",
          [
            rows4.length,
            rows4[0]?.metadata.stage,
            rows4[0]?.metadata.records,
            rows4[0]?.metadata.quarantined,
          ],
          [1, "declared", null, 1],
        );
        rig.downloader.script("trivy", {
          bundle: declaredBundle,
          metadata: { sources: ["ghsa", "chainguard"] },
        });
        const out4b = await rig.run();
        ok(
          p,
          out4b.outcome === "rejected" && out4b.alerted === false,
          `a declared refusal is alerted once per digest: ${JSON.stringify(out4b)}`,
        );
        same(p, "declared repeat: still one entry", (await alertRows(dSha)).length, 1);
        same(p, "declared: warn lines", blockedLines().length, 3);

        // 5. rejections that are not quarantine raise no alert
        const total5 = await alertTotal();
        const good = bundle({ padBytes: 3000 });
        const tampered = Buffer.from(good);
        tampered[tampered.length - 50] ^= 0x01;
        for (const [label, step] of [
          ["integrity", { bundle: good, downloaded: tampered }],
          [
            "a distro record",
            {
              bundle: records(
                rec("DSA-1-1", { affected: [{ package: { ecosystem: "Debian:12" } }] }),
              ),
            },
          ],
          ["a malformed record", { bundle: records("{ nope") }],
          [
            "a traversal entry",
            { bundle: bundle({ extra: [{ raw: true, name: "../../evil", content: "x" }] }) },
          ],
          [
            "an unknown declared source",
            { bundle: bundle({ padBytes: 3000 }), metadata: { sources: ["ghsa", "somewhere"] } },
          ],
        ]) {
          rig.downloader.script("trivy", step);
          const out = await rig.run();
          ok(
            p,
            out.outcome === "rejected" &&
              out.reason !== "quarantined_source" &&
              out.alerted === undefined,
            `${label}: ${JSON.stringify(out)}`,
          );
        }
        same(
          p,
          "no alert for a rejection that is not quarantine",
          (await alertTotal()) - total5,
          0,
        );
        // the same non-quarantine digest again (a known rejected row): still no alert and no `alerted` field
        const distro = records(
          rec("DSA-9-9", { affected: [{ package: { ecosystem: "Debian:12" } }] }),
        );
        for (const round of [1, 2]) {
          rig.downloader.script("trivy", { bundle: distro });
          const again = await rig.run();
          ok(
            p,
            again.outcome === "rejected" &&
              again.reason === "source_not_allowed" &&
              again.alerted === undefined,
            `a known non-quarantine digest, round ${round}: ${JSON.stringify(again)}`,
          );
        }
        same(p, "and still no alert", (await alertTotal()) - total5, 0);

        // 6. a failure to record the alert never changes the outcome and is retried by the next refresh of the digest
        const quarantined3 = records(rec("GHSA-aaaa-bbbb-eeee"), rec("CGA-aaaa-bbbb-eeee"));
        const q3 = sha256(quarantined3);
        const failing = {
          ...rig.repo,
          recordQuarantineAlert: async () => {
            throw new Error("boom ghp_abcdefghijklmnopqrstuvwxyz123456 postgres://u:p@h/db");
          },
        };
        rig.downloader.script("trivy", { bundle: quarantined3 });
        const warn0 = blockedLines().length;
        const out6 = await rig.run("trivy", { repo: failing });
        ok(
          p,
          out6.outcome === "rejected" &&
            out6.reason === "quarantined_source" &&
            out6.alerted === false,
          `a failing alert write: ${JSON.stringify(out6)}`,
        );
        same(p, "no entry yet", (await alertRows(q3)).length, 0);
        const errLines = rig.lines.filter((l) => l.level === "error");
        same(
          p,
          "the error line has fixed words and does not echo the cause",
          [errLines.length, errLines[0]?.msg, Object.keys(errLines[0]?.obj ?? {}).sort()],
          [1, "The quarantine alert could not be recorded", ["reason", "sha256", "toolId"]],
        );
        ok(
          p,
          !JSON.stringify(errLines).includes("ghp_") &&
            !JSON.stringify(errLines).includes("postgres"),
          "the cause leaked into the log",
        );
        rig.downloader.script("trivy", { bundle: quarantined3 });
        const out6b = await rig.run();
        ok(p, out6b.alerted === true, "the next refresh records the missing alert");
        same(p, "now one entry", (await alertRows(q3)).length, 1);
        same(p, "and one more warn line", blockedLines().length - warn0, 1);

        // 7. concurrency: one entry however many recordings race
        const raced = hex();
        const results = await Promise.all(
          Array.from({ length: 5 }, () =>
            rig.repo.recordQuarantineAlert({
              toolId: "trivy",
              sha256: raced,
              stage: "inspected",
              counts: { records: 3, quarantined: 1 },
            }),
          ),
        );
        same(
          p,
          "concurrent recordings",
          [results.filter((r) => r.recorded).length, (await alertRows(raced)).length],
          [1, 1],
        );

        // the per-digest advisory lock is what makes it once: a recording waits while another transaction holds the lock of its digest
        const held = hex();
        let finished = false;
        let pending;
        await db.$transaction(
          async (tx) => {
            await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`scan_db_alert:trivy:${held}`}, 0))`;
            pending = rig.repo
              .recordQuarantineAlert({ toolId: "trivy", sha256: held, stage: "inspected" })
              .then((r) => {
                finished = true;
                return r;
              });
            await new Promise((resolve) => setTimeout(resolve, 600));
            if (finished) p.push("a recording did not wait for the advisory lock of its digest");
          },
          { timeout: 20000 },
        );
        same(
          p,
          "after the lock is released the recording completes once",
          (await pending).recorded,
          true,
        );

        // 8. input validation and hostile counts
        for (const [label, input] of [
          ["an unknown tool", { toolId: "grype", sha256: hex(), stage: "inspected" }],
          ["a malformed digest", { toolId: "trivy", sha256: "xyz", stage: "inspected" }],
          [
            "an upper-case digest",
            { toolId: "trivy", sha256: hex().toUpperCase(), stage: "inspected" },
          ],
          ["an unknown stage", { toolId: "trivy", sha256: hex(), stage: "elsewhere" }],
        ]) {
          const r = await attempt(() => rig.repo.recordQuarantineAlert(input));
          ok(p, !r.ok && r.message.length > 0, `${label} was accepted`);
        }
        const odd = hex();
        await rig.repo.recordQuarantineAlert({
          toolId: "trivy",
          sha256: odd,
          stage: "declared",
          counts: { records: -1, quarantined: 1.5, notAllowed: "7", invalid: 2_000_000_000 },
        });
        const oddRow = (await alertRows(odd))[0];
        same(
          p,
          "hostile counts become null",
          [
            oddRow?.metadata.records,
            oddRow?.metadata.quarantined,
            oddRow?.metadata.notAllowed,
            oddRow?.metadata.invalid,
          ],
          [null, null, null, null],
        );

        // 9. nothing of the upstream or of the records reaches the entries or the log
        const all = JSON.stringify([
          await db.$queryRaw`SELECT metadata FROM platform_audit_logs WHERE action = ${ACTION}`,
          rig.lines,
        ]);
        for (const needle of [
          "chainguard",
          "wolfi",
          "grype",
          "CGA-",
          "GHSA-",
          "ghp_",
          "http",
          "postgres",
          "somewhere",
        ])
          if (all.includes(needle)) p.push(`the alerts or the log contain "${needle}"`);

        // 10. the Root Console audit view shows it as a failure of the system actor
        const dto = toPlatformAuditEntryDto({
          ...r1,
          createdAt: new Date(),
          correlationId: null,
          ipAddress: null,
          actor: null,
        });
        same(
          p,
          "audit view",
          [dto.action, dto.result, dto.actor.type, dto.tenantId, dto.metadata.toolId],
          [ACTION, "failure", "system", null, "trivy"],
        );
      } finally {
        rig.done();
      }
      await reset(db);
      return p;
    },
  },
];
