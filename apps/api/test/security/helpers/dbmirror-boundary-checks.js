import { randomBytes } from "node:crypto";
import { statSync } from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import {
  ALLOWED_SOURCES,
  DEFAULT_SNAPSHOT_ARCHIVE_CAPS,
  DbMirrorTooLargeError,
  FakeSandboxRuntime,
  MAX_STRING_SCAN,
  NonRetryableError,
  checkDeclaredSources,
  classifyRecord,
  createLocalDbMirrorStore,
  createSandboxRunner,
  inspectSnapshotArchive,
} from "@qmentisai/infra";
import { classifyDbStaleness, dbProvenance, dbStalenessEffect } from "@qmentisai/shared";
import { createScanDbSnapshotRepository } from "@qmentisai/db";
import { ConfigError, loadWorkerConfig } from "../../../../workers/src/config.js";
import { CANARY_FIXTURE, createSandboxCanary } from "../../../../workers/src/dbrefresh/canary.js";
import {
  DBREFRESH_CONSUMER,
  buildDbRefreshDeps,
  createDbRefreshHandlerFor,
} from "../../../../workers/src/dbrefresh/index.js";
import { promotionSanity, refreshTool } from "../../../../workers/src/dbrefresh/refresh.js";
import { bundle, fakeDownloader, hoursAgo, NOW, tempStore } from "./dbmirror-fixtures.js";
import { CONFIG_INPUT } from "./sandbox-checks.js";
import { tar } from "./archive-checks.js";
import { attempt, mustReject } from "./pipeline-db.js";
import { recordingLog, scanDbConfig, clock, sha256 } from "./dbmirror-fixtures.js";

/**
 * Boundary and constant assertions of the Part F checks (SPEC scan-engines 17.n, mutation sweep of 2026-11-20): every function here
 * pins an exact number, an exact size limit, an exact return shape or a configuration bound that the main checks only exercised
 * loosely, so that a one-character change of a limit, a comparison or a default is caught. Called from the checks of dbmirror-checks.js
 * and dbmirror-db-checks.js; each takes the problem list `p`.
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
const stream = (b) => Readable.from([b]);
const throws = (fn) => {
  try {
    fn();
    return null;
  } catch (e) {
    return e;
  }
};
const rec = (id, over = {}) => ({
  id,
  aliases: [],
  affected: [{ package: { ecosystem: "npm", name: "x" } }],
  ...over,
});

export function staleExtra(p) {
  const day = 86_400_000;
  same(
    p,
    "ISO string build time",
    classifyDbStaleness({ builtAt: new Date(NOW - 5 * day).toISOString(), now: NOW }).tier,
    "aging",
  );
  same(
    p,
    "epoch build time and numeric now",
    classifyDbStaleness({ builtAt: NOW.getTime() - 20 * day, now: NOW.getTime() }).tier,
    "stale",
  );
  same(
    p,
    "age in seconds",
    classifyDbStaleness({ builtAt: new Date(NOW - 3 * day), now: NOW }).ageSeconds,
    259200,
  );
  same(p, "unreadable age", classifyDbStaleness({ builtAt: "nope", now: NOW }).ageSeconds, null);
  same(
    p,
    "future age",
    classifyDbStaleness({ builtAt: new Date(NOW.getTime() + day), now: NOW }).ageSeconds,
    0,
  );
  same(p, "equal times", classifyDbStaleness({ builtAt: NOW, now: NOW }).ageSeconds, 0);
  ok(
    p,
    throws(() =>
      classifyDbStaleness({ builtAt: NOW, now: NOW }, { aging: 1, stale: 2, expired: 2 }),
    ) instanceof RangeError,
    "stale must be below expired",
  );
  same(p, "fresh never fails", dbStalenessEffect("fresh").failsScan, false);
  const snap = { toolId: "trivy", sha256: "a".repeat(64), upstreamBuiltAt: NOW, fetchedAt: NOW };
  same(p, "no sources", dbProvenance(snap, { now: NOW }).attributionRequired, false);
  same(
    p,
    "sources without attribution",
    dbProvenance({ ...snap, sources: [ALLOWED_SOURCES.nvd, ALLOWED_SOURCES.osv] }, { now: NOW })
      .attributionRequired,
    false,
  );
}

export function sourcesExtra(p) {
  for (const id of ["nvd", "osv"]) {
    ok(p, ALLOWED_SOURCES[id].attribution === null, `${id}: no attribution key`);
    ok(p, ALLOWED_SOURCES[id].attributionRequired === false, `${id}: no attribution required`);
  }
  same(p, "ghsa attribution", ALLOWED_SOURCES.ghsa.attribution, "ghsa-cc-by-4.0");
  for (const r of [null, { id: "x" }, rec("CGA-xxxx-yyyy-zzzz")])
    same(p, "no source for invalid or quarantined", classifyRecord(r).source, null);
  same(p, "no source for a distro id", classifyRecord(rec("DSA-1-1")).source, null);
  same(
    p,
    "an allowed record is not quarantined",
    classifyRecord(rec("GHSA-aaaa-bbbb-cccc")).quarantined,
    false,
  );
  // a marker is never cut away
  const at = (n) => "y".repeat(n - 5) + "wolfi";
  const withSource = (s) => rec("GHSA-aaaa-bbbb-cccc", { database_specific: { source: s } });
  ok(p, MAX_STRING_SCAN === 4096, "the scan limit");
  same(p, "a marker after 300 characters", classifyRecord(withSource(at(400))).quarantined, true);
  same(p, "a marker at the limit", classifyRecord(withSource(at(4096))).quarantined, true);
  const refused = (r) => {
    const v = classifyRecord(r);
    return (
      v.reason === "invalid" && v.allowed === false && v.source === null && v.quarantined === false
    );
  };
  ok(p, refused(withSource(at(4097))), "one past the limit is refused as invalid");
  ok(p, refused(rec("GHSA-aaaa-bbbb-cccc", { aliases: ["a".repeat(4097)] })), "a long alias");
  ok(
    p,
    refused(
      rec("GHSA-aaaa-bbbb-cccc", { affected: [{ package: { ecosystem: "n".repeat(4097) } }] }),
    ),
    "a long ecosystem",
  );
  ok(
    p,
    refused(rec("GHSA-aaaa-bbbb-cccc", { database_specific: { license: "l".repeat(4097) } })),
    "a long licence",
  );
  same(p, "a long id", classifyRecord(rec("G".repeat(121))).reason, "invalid");
  // the counts of a refused declaration
  for (const [declared, n] of [
    [[], 1],
    [["unknown"], 1],
    [["a", "b"], 2],
    ["ghsa", 1],
    [null, 1],
    [[5], 1],
    [["ghsa", "x"], 1],
  ])
    same(
      p,
      `notAllowed of ${JSON.stringify(declared)}`,
      checkDeclaredSources(declared).notAllowed,
      n,
    );
}

/** A JSON record of exactly `bytes` bytes that is a valid allowed record. */
const recordOfSize = (bytes) => {
  const base = JSON.stringify({
    id: "GHSA-aaaa-bbbb-cccc",
    affected: [{ package: { ecosystem: "npm" } }],
    pad: "",
  });
  return JSON.stringify({
    id: "GHSA-aaaa-bbbb-cccc",
    affected: [{ package: { ecosystem: "npm" } }],
    pad: "x".repeat(bytes - base.length),
  });
};
const metadataOfSize = (bytes) => {
  const base = JSON.stringify({ sources: ["ghsa"], pad: "" });
  return JSON.stringify({ sources: ["ghsa"], pad: "x".repeat(bytes - base.length) });
};

export async function inspectExtra(p) {
  same(p, "default archive caps", DEFAULT_SNAPSHOT_ARCHIVE_CAPS, {
    maxEntries: 2_000_000,
    maxFileBytes: 512 * 1024 * 1024,
    maxTotalBytes: 8 * 1024 * 1024 * 1024,
    maxRatio: 200,
    maxDepth: 8,
    maxPathLength: 512,
  });
  const inspect = (buffer) => inspectSnapshotArchive(stream(buffer));
  const exact = recordOfSize(1024 * 1024);
  same(p, "exact record size", Buffer.byteLength(exact), 1024 * 1024);
  const a = await inspect(bundle({ records: [exact] }));
  same(p, "a record of exactly 1 MiB", [a.verdict, a.bySource.ghsa, a.invalid], ["ok", 1, 0]);
  const b = await inspect(bundle({ records: [recordOfSize(1024 * 1024 + 1)] }));
  same(p, "a record one byte over", [b.verdict, b.invalid, b.records], ["record_invalid", 1, 0]);
  const m1 = await inspect(
    bundle({ records: [], extra: [] }).length
      ? tarWithMetadata(metadataOfSize(65536))
      : Buffer.alloc(0),
  );
  same(
    p,
    "metadata of exactly 64 KiB",
    [m1.verdict, m1.declaredSources.map((s) => s.id)],
    ["ok", ["ghsa"]],
  );
  const m2 = await inspect(tarWithMetadata(metadataOfSize(65537)));
  same(p, "metadata one byte over", [m2.verdict, m2.notAllowed], ["source_not_allowed", 1]);
  const none = await inspect(bundle({ sources: null }));
  same(p, "no metadata file", [none.verdict, none.declaredSources, none.notAllowed], ["ok", [], 0]);
  const clean = await inspect(bundle());
  same(p, "files of a clean bundle", [clean.files, clean.records], [3, 1]);
  const mixed = await inspect(
    bundle({
      records: [
        rec("GHSA-aaaa-bbbb-cccc"),
        rec("CGA-xxxx-yyyy-zzzz"),
        rec("DSA-1-1", { affected: [{ package: { ecosystem: "Debian:12" } }] }),
        "{ bad",
      ],
    }),
  );
  same(
    p,
    "mixed counts",
    [
      mixed.verdict,
      mixed.records,
      mixed.quarantined,
      mixed.notAllowed,
      mixed.invalid,
      mixed.bySource.ghsa,
    ],
    ["quarantined_source", 4, 1, 1, 1, 1],
  );
  same(
    p,
    "two unknown declared sources",
    (await inspect(bundle({ sources: ["u1", "u2"] }))).notAllowed,
    2,
  );
  same(
    p,
    "one unknown declared source",
    (await inspect(bundle({ sources: ["u1"] }))).notAllowed,
    1,
  );
  same(
    p,
    "two quarantined declared sources",
    (await inspect(bundle({ sources: ["chainguard", "wolfi"] }))).quarantined,
    2,
  );
}

function tarWithMetadata(content) {
  return tar([
    { name: "metadata.json", content },
    {
      name: "records/npm/GHSA-aaaa-bbbb-cccc.json",
      content: JSON.stringify(rec("GHSA-aaaa-bbbb-cccc")),
    },
  ]);
}

export async function storeExtra(p) {
  for (const [label, input] of [
    ["a relative root", { root: "rel/dir", cacheRoot: "/tmp/qm-x" }],
    ["a relative cache", { root: "/tmp/qm-x", cacheRoot: "rel/dir" }],
    ["a numeric root", { root: 5, cacheRoot: "/tmp/qm-x" }],
    ["no cache", { root: "/tmp/qm-x", cacheRoot: undefined }],
  ])
    ok(
      p,
      throws(() => createLocalDbMirrorStore(input)) instanceof TypeError,
      `${label} must be refused`,
    );
  const t = tempStore();
  try {
    const { store } = t;
    const data = Buffer.alloc(1000, 1);
    const exact = await store.stage(stream(data), { maxBytes: 1000 });
    same(p, "a stage of exactly the cap", exact.bytes, 1000);
    const over = await store.stage(stream(data), { maxBytes: 999 }).then(
      () => null,
      (e) => e,
    );
    ok(
      p,
      over instanceof DbMirrorTooLargeError && over.maxBytes === 999,
      "a stage one byte over the cap",
    );
    ok(
      p,
      (await attempt(() => store.discardStaged("0".repeat(24)))).ok,
      "discarding an unknown stage is not an error",
    );
    ok(
      p,
      (await attempt(() => store.remove({ tool: "trivy", sha256: "a".repeat(64) }))).ok,
      "removing an unknown object is not an error",
    );
    // the sweep boundary and exact counts
    const mtime = statSync(path.join(t.root, "stage", exact.stageId)).mtimeMs;
    same(
      p,
      "not older than the limit",
      await store.sweepStage({ olderThanMs: 1000, now: mtime + 1000 }),
      0,
    );
    const second = await store.stage(stream(data), { maxBytes: 1000 });
    const mtime2 = statSync(path.join(t.root, "stage", second.stageId)).mtimeMs;
    same(
      p,
      "older than the limit removes exactly the old files",
      await store.sweepStage({ olderThanMs: 1000, now: Math.max(mtime, mtime2) + 1001 }),
      2,
    );
  } finally {
    t.done();
  }
}

export async function canaryExtra(p) {
  const sha = "c".repeat(64);
  const dir = `/var/lib/qm/db/trivy/${sha}`;
  const resolver = {
    resolve: () => ({ image: `registry.example/trivy@sha256:${"b".repeat(64)}` }),
  };
  const ids = (id) => JSON.stringify({ Results: [{ Vulnerabilities: [{ VulnerabilityID: id }] }] });
  const rig = (stdout) => {
    const runtime = new FakeSandboxRuntime({ config: CONFIG_INPUT }).script("trivy", {
      exitCode: 0,
      stdout,
    });
    return {
      runtime,
      canary: createSandboxCanary({
        runner: createSandboxRunner({ runtime }),
        resolver,
        now: () => NOW.getTime(),
      }),
    };
  };
  const r = rig(ids("CVE-2021-23337"));
  await r.canary({ toolId: "trivy", sha256: sha, dir });
  const spec = r.runtime.calls.find((c) => c.type === "run").spec;
  same(p, "limits", spec.limits, {
    cpus: 1,
    memoryMiB: 1024,
    pids: 128,
    wallClockSeconds: 120,
    stdoutBytes: 8 * 1024 * 1024,
    tmpfsMiB: 256,
  });
  same(p, "stdin is the fixture", JSON.parse(spec.stdin), CANARY_FIXTURE);
  same(
    p,
    "fixture component",
    [
      CANARY_FIXTURE.specVersion,
      CANARY_FIXTURE.version,
      CANARY_FIXTURE.components.map((c) => c.purl),
    ],
    ["1.5", 1, ["pkg:npm/lodash@4.17.20"]],
  );
  same(p, "environment", spec.env, {
    TRIVY_SKIP_VERSION_CHECK: "true",
    TRIVY_DISABLE_TELEMETRY: "true",
  });
  same(p, "labels", spec.labels, {
    tenantId: "platform",
    executionId: "dbrefresh",
    taskId: `canary-${sha.slice(0, 12)}`,
    attempt: 1,
    deadlineEpoch: Math.floor(NOW.getTime() / 1000) + 180,
  });
  const verdict = (stdout) => rig(stdout).canary({ toolId: "trivy", sha256: sha, dir });
  const nest = (k) => '{"a":'.repeat(k) + '{"VulnerabilityID":"CVE-2021-23337"}' + "}".repeat(k);
  same(p, "an id at depth 12", (await verdict(nest(12))).ok, true);
  same(p, "an id at depth 13", (await verdict(nest(13))).ok, false);
  same(
    p,
    "null members",
    (await verdict('{"Results":[null,{"Vulnerabilities":[{"VulnerabilityID":"CVE-2021-23337"}]}]}'))
      .ok,
    true,
  );
  same(
    p,
    "an id of the osv shape",
    (
      await verdict(
        '{"results":[{"packages":[{"vulnerabilities":[{"id":"GHSA-35jh-r3h4-6jhm"}]}]}]}',
      )
    ).ok,
    true,
  );
}

export async function workerExtra(p) {
  same(p, "consumer", DBREFRESH_CONSUMER, {
    name: "dbrefresh",
    queue: "dbrefresh",
    requireTenant: false,
  });
  const base = {
    RABBITMQ_URL: "amqp://x:y@localhost:5672",
    DATABASE_URL: "postgresql://u:pw@localhost:5432/d",
  };
  const off = loadWorkerConfig(base, { workerName: "dbrefresh" });
  const disabled = createDbRefreshHandlerFor({ db: null, config: off });
  const { log } = recordingLog();
  const refused = await disabled
    .handler(
      { type: "maintenance.scan_db.refresh_requested", payload: { tools: ["trivy"] } },
      { log },
    )
    .then(
      () => null,
      (e) => e,
    );
  ok(
    p,
    refused instanceof NonRetryableError && refused.reason === "refresh-disabled",
    "disabled: refused",
  );
  ok(p, (await attempt(() => disabled.close())).ok, "disabled: close");
  const on = loadWorkerConfig(
    {
      ...base,
      SCAN_DB_REFRESH_ENABLED: "true",
      SCAN_DB_MIRROR_ROOT: "/srv/qm/mirror",
      SCAN_DB_CACHE_ROOT: "/srv/qm/cache",
    },
    { workerName: "dbrefresh" },
  );
  const built = buildDbRefreshDeps({ db: {}, config: on });
  ok(p, built.deps.lock === null, "no Redis URL: no lock manager");
  same(p, "store kind", built.deps.store.kind, "local-fs");
  ok(
    p,
    typeof built.deps.canary === "function" && typeof built.deps.repo.promote === "function",
    "wired",
  );
  const unconfigured = await built.deps.downloader.latest({ toolId: "trivy" }).then(
    () => null,
    (e) => e,
  );
  ok(p, unconfigured instanceof NonRetryableError, "the default downloader refuses");
  ok(p, (await attempt(() => built.close())).ok, "close");
  const custom = { latest: async () => 1, download: async () => 2 };
  ok(
    p,
    buildDbRefreshDeps({ db: {}, config: on, downloader: custom }).deps.downloader === custom,
    "an injected downloader is used",
  );
  const enabled = createDbRefreshHandlerFor({ db: {}, config: on });
  ok(
    p,
    typeof enabled.handler === "function" && typeof enabled.close === "function",
    "enabled: handler",
  );
  const production = { ...on, scanEngines: { ...on.scanEngines, production: true } };
  ok(
    p,
    throws(() => buildDbRefreshDeps({ db: {}, config: production })) !== null,
    "a production process refuses the unpinned image lock",
  );
}

export function configExtra(p) {
  const base = {
    RABBITMQ_URL: "amqp://x:y@localhost:5672",
    DATABASE_URL: "postgresql://u:pw@localhost:5432/d",
  };
  const cfg = loadWorkerConfig(base, { workerName: "dbrefresh" }).scanDb;
  same(
    p,
    "defaults",
    [
      cfg.intervalSeconds,
      cfg.maxBytes,
      cfg.minSizePercent,
      cfg.maxUpstreamAgeDays,
      cfg.keepRetired,
      cfg.candidateAbandonSeconds,
      cfg.lockTtlSeconds,
    ],
    [21600, 4294967296, 50, 30, 3, 3600, 3600],
  );
  const problem = (env) => {
    try {
      loadWorkerConfig({ ...base, ...env }, { workerName: "dbrefresh" });
      return null;
    } catch (e) {
      return e instanceof ConfigError ? e.message : `threw ${e?.name}`;
    }
  };
  const bounds = [
    ["SCAN_DB_REFRESH_INTERVAL_SECONDS", 300, 604800, {}],
    ["SCAN_DB_MAX_BYTES", 1048576, 68719476736, {}],
    ["SCAN_DB_MIN_SIZE_PERCENT", 1, 100, {}],
    ["SCAN_DB_MAX_UPSTREAM_AGE_DAYS", 1, 365, {}],
    ["SCAN_DB_KEEP_RETIRED", 0, 20, {}],
    ["SCAN_DB_CANDIDATE_ABANDON_SECONDS", 60, 604800, {}],
    ["SCAN_DB_LOCK_TTL_SECONDS", 60, 86400, {}],
    ["SCAN_DB_STALE_AGING_DAYS", 1, null, {}],
    ["SCAN_DB_STALE_STALE_DAYS", null, 365, { SCAN_DB_STALE_EXPIRED_DAYS: "730" }],
    ["SCAN_DB_STALE_EXPIRED_DAYS", null, 730, {}],
  ];
  for (const [name, min, max, extra] of bounds) {
    if (min !== null) {
      same(p, `${name} accepts ${min}`, problem({ [name]: String(min), ...extra }), null);
      ok(p, problem({ [name]: String(min - 1) })?.includes(name), `${name} refuses ${min - 1}`);
    } else ok(p, problem({ [name]: "0" })?.includes(name), `${name} refuses 0`);
    if (max !== null) {
      same(p, `${name} accepts ${max}`, problem({ [name]: String(max), ...extra }), null);
      ok(
        p,
        problem({ [name]: String(max + 1), ...extra })?.includes(name),
        `${name} refuses ${max + 1}`,
      );
    }
  }
  ok(
    p,
    problem({ SCAN_DB_REFRESH_TOOLS: "x".repeat(101) })?.includes("SCAN_DB_REFRESH_TOOLS"),
    "the tool list length",
  );
  ok(
    p,
    problem({ SCAN_DB_STALE_AGING_DAYS: "14" })?.includes("strictly increasing"),
    "aging equal to stale",
  );
  ok(
    p,
    problem({ SCAN_DB_STALE_STALE_DAYS: "20", SCAN_DB_STALE_EXPIRED_DAYS: "20" })?.includes(
      "strictly increasing",
    ),
    "stale equal to expired",
  );
  const enabled = {
    ...base,
    SCAN_DB_REFRESH_ENABLED: "true",
    SCAN_DB_MIRROR_ROOT: "/srv/qm/mirror",
    SCAN_DB_CACHE_ROOT: "/srv/qm/cache",
  };
  ok(
    p,
    problem({ ...enabled, DATABASE_URL: undefined, REDIS_URL: "redis://localhost" })?.includes(
      "required while SCAN_DB_REFRESH_ENABLED=true",
    ),
    "the database message",
  );
  ok(
    p,
    problem({ ...enabled, SCAN_DB_CACHE_ROOT: "rel" })?.includes(
      "an absolute path is required while SCAN_DB_REFRESH_ENABLED=true",
    ),
    "the root message",
  );
  ok(
    p,
    problem({ ...enabled, SCAN_DB_CACHE_ROOT: "/srv/qm/mirror" })?.includes("must differ"),
    "equal roots",
  );
}

// ------------------------------------------------------------------------------------------------ database parts

export async function snapshotsExtra(c, p) {
  const { db } = c;
  const repo = createScanDbSnapshotRepository({ db });
  await db.$executeRaw`UPDATE scan_db_snapshots SET status = 'retired', retired_at = now() WHERE status = 'active'`;
  await db.$executeRaw`UPDATE scan_db_snapshots SET status = 'rejected', rejected_reason = 'abandoned' WHERE status = 'candidate'`;
  same(p, "no active snapshot is null", await repo.getActive("osv-scanner"), null);
  same(
    p,
    "an unknown digest is null",
    await repo.getBySha({ toolId: "trivy", sha256: "9".repeat(64) }),
    null,
  );
  const mk = async (toolId) =>
    (
      await repo.insertCandidate({
        toolId,
        sourceVersion: "v1",
        upstreamBuiltAt: hoursAgo(1),
        sizeBytes: 10,
        sha256: sha256(Buffer.from(`${Math.random()}`)),
        sources: [],
        recordCounts: {},
      })
    ).snapshot;
  for (let i = 0; i < 3; i += 1) await mk("osv-scanner");
  same(p, "list limit 1", (await repo.list("osv-scanner", { limit: 1 })).length, 1);
  ok(p, (await repo.list("osv-scanner", { limit: 3 })).length === 3, "list limit 3");
  const only = await repo.list("osv-scanner", { statuses: ["candidate"], limit: 200 });
  ok(p, only.length >= 3 && only.every((r) => r.status === "candidate"), "list filters by status");
  const none = await db.$transaction((tx) => repo.retireActive("osv-scanner", tx));
  same(p, "retiring nothing", none, null);
  const cand = await mk("osv-scanner");
  const act = await db.$transaction((tx) => repo.activate(cand.id, tx));
  same(p, "activate returns true", act, true);
  const again = await db.$transaction((tx) =>
    repo.retireActive("osv-scanner", tx).then(() => repo.activate(cand.id, tx)),
  );
  same(p, "activating a non-candidate returns false", again, false);
  const toReject = await mk("osv-scanner");
  same(
    p,
    "reject returns true for a candidate",
    await repo.reject({ id: toReject.id, reason: "canary_failed" }),
    true,
  );
  same(
    p,
    "a second reject returns false",
    await repo.reject({ id: toReject.id, reason: "canary_failed" }),
    false,
  );
  const gone = await repo.promote({ id: cand.id, toolId: "osv-scanner" });
  same(p, "promote of a non-candidate", gone, { promoted: false, retiredId: null });

  // raw writers: each constraint on its own (the trigger and the state check overlap, so each probe isolates one of them)
  const hex = () => randomBytes(32).toString("hex");
  const rawInsert = ({
    status = "candidate",
    promoted = null,
    reason = null,
    ver = "v1",
    src = "[]",
    cnt = "{}",
  }) =>
    attempt(
      () => db.$executeRaw`
        INSERT INTO scan_db_snapshots (id, tool_id, source_version, upstream_built_at, size_bytes, sha256, status, promoted_at, rejected_reason, sources, record_counts)
        VALUES (gen_random_uuid(), 'osv-scanner', ${ver}, now(), 10, ${hex()}, ${status}, ${promoted}::timestamptz, ${reason}, ${src}::jsonb, ${cnt}::jsonb)`,
    );
  const bad = (label, r) => mustReject(p, label, r);
  bad(
    "a candidate that carries a promotion time",
    await rawInsert({ promoted: new Date().toISOString() }),
  );
  bad("a rejected row without a reason", await rawInsert({ status: "rejected" }));
  bad(
    "a rejected row that carries a promotion time",
    await rawInsert({ status: "rejected", reason: "empty", promoted: new Date().toISOString() }),
  );
  bad("a version of 129 characters", await rawInsert({ ver: "v".repeat(129) }));
  ok(p, (await rawInsert({ ver: "v".repeat(128) })).ok, "control: a version of 128 characters");
  bad(
    "sources above 4096 bytes",
    await rawInsert({ src: JSON.stringify(Array.from({ length: 49 }, () => "x".repeat(100))) }),
  );
  ok(
    p,
    (await rawInsert({ src: JSON.stringify(Array.from({ length: 5 }, () => "x".repeat(100))) })).ok,
    "control: five sources",
  );
  bad("record counts that are an array", await rawInsert({ cnt: "[]" }));
  bad("record counts that are a string", await rawInsert({ cnt: '"x"' }));
  // columns that change only with a status transition, on rows where the state check alone would not object
  await db.$executeRaw`UPDATE scan_db_snapshots SET status = 'retired', retired_at = now() WHERE status = 'active'`;
  const a = await mk("osv-scanner");
  await repo.promote({ id: a.id, toolId: "osv-scanner" });
  const b2 = await mk("osv-scanner");
  await repo.promote({ id: b2.id, toolId: "osv-scanner" });
  bad(
    "a retired row's retirement time",
    await attempt(
      () =>
        db.$executeRaw`UPDATE scan_db_snapshots SET retired_at = retired_at + interval '1 day' WHERE id = ${a.id}::uuid`,
    ),
  );
  bad(
    "an active row's promotion time",
    await attempt(
      () =>
        db.$executeRaw`UPDATE scan_db_snapshots SET promoted_at = promoted_at + interval '1 day' WHERE id = ${b2.id}::uuid`,
    ),
  );
  const r = await mk("osv-scanner");
  await repo.reject({ id: r.id, reason: "canary_failed" });
  bad(
    "a rejected row's reason",
    await attempt(
      () =>
        db.$executeRaw`UPDATE scan_db_snapshots SET rejected_reason = 'empty' WHERE id = ${r.id}::uuid`,
    ),
  );
  bad(
    "created_at",
    await attempt(
      () =>
        db.$executeRaw`UPDATE scan_db_snapshots SET created_at = created_at - interval '1 day' WHERE id = ${r.id}::uuid`,
    ),
  );
}

export async function refreshExtra(c, p) {
  const pol = { now: NOW, minSizePercent: 50, maxUpstreamAgeDays: 30 };
  same(
    p,
    "49.6 percent",
    promotionSanity({ sizeBytes: 496, upstreamBuiltAt: hoursAgo(1) }, { sizeBytes: 1000 }, pol),
    "too_small",
  );
  same(
    p,
    "50 percent",
    promotionSanity({ sizeBytes: 500, upstreamBuiltAt: hoursAgo(1) }, { sizeBytes: 1000 }, pol),
    null,
  );
  const { db } = c;
  const repo = createScanDbSnapshotRepository({ db });
  const mkRig = (cfg) => {
    const t = tempStore();
    const downloader = fakeDownloader();
    const { log, lines } = recordingLog();
    const scanDb = scanDbConfig(cfg);
    const deps = {
      repo,
      store: t.store,
      downloader,
      canary: async () => ({ ok: true }),
      lock: null,
      now: clock,
    };
    return {
      t,
      downloader,
      lines,
      scanDb,
      run: (toolId = "trivy", over = {}) =>
        refreshTool({ toolId, deps: { ...deps, ...over }, scanDb, log }),
      done: () => t.done(),
    };
  };
  // a size claim of exactly the cap is accepted
  const b = bundle({ padBytes: 800 });
  const r1 = mkRig({ maxBytes: b.length });
  try {
    r1.downloader.script("trivy", { bundle: b });
    same(p, "a claim of exactly the cap", (await r1.run()).outcome, "promoted");
    same(
      p,
      "log: nothing retired by the first snapshot",
      r1.lines.find((l) => /promoted/.test(l.msg ?? ""))?.obj.retired,
      false,
    );
  } finally {
    r1.done();
  }
  const r2 = mkRig({});
  try {
    const first = bundle({ padBytes: 800 });
    r2.downloader.script("trivy", { bundle: first });
    await r2.run();
    const second = bundle({ padBytes: 800, sources: ["ghsa", "nvd"] });
    r2.downloader.script("trivy", { bundle: second, metadata: { sources: ["ghsa"] } });
    same(p, "second promoted", (await r2.run()).outcome, "promoted");
    same(
      p,
      "log: the previous snapshot was retired",
      r2.lines.filter((l) => /promoted/.test(l.msg ?? "")).at(-1)?.obj.retired,
      true,
    );
    const active = await repo.getActive("trivy");
    same(p, "sources are the union, once each", active.sources.map((s) => s.id).sort(), [
      "ghsa",
      "nvd",
    ]);
  } finally {
    r2.done();
  }
}

export async function hostileExtra(c, p) {
  const { db } = c;
  const repo = createScanDbSnapshotRepository({ db });
  const t = tempStore();
  try {
    const downloader = fakeDownloader();
    const { log } = recordingLog();
    const scanDb = scanDbConfig({});
    const deps = {
      repo,
      store: t.store,
      downloader,
      canary: async () => ({ ok: true }),
      lock: null,
      now: clock,
    };
    const run = (over = {}) =>
      refreshTool({ toolId: "trivy", deps: { ...deps, ...over }, scanDb, log });
    // an empty download: recorded under the digest of nothing with the minimum size
    const good = bundle({ padBytes: 500 });
    downloader.script("trivy", { bundle: good, downloaded: Buffer.alloc(0) });
    const out = await run();
    same(
      p,
      "empty download",
      [out.outcome, out.reason, out.sha256],
      ["rejected", "integrity_mismatch", sha256(Buffer.alloc(0))],
    );
    same(
      p,
      "empty download row size",
      (await repo.getBySha({ toolId: "trivy", sha256: sha256(Buffer.alloc(0)) }))?.sizeBytes,
      1,
    );
    // a source id of 65 characters is a malformed upstream answer (thrown), not a source verdict
    downloader.script("trivy", { bundle: bundle(), metadata: { sources: ["x".repeat(65)] } });
    ok(p, !(await attempt(() => run())).ok, "a 65 character source id is refused by the schema");
    // a resumed candidate whose stored object is a bomb: materialization aborts, the candidate is rejected as hostile
    const bomb = bundle({
      extra: [{ name: "data/zeros.bin", content: Buffer.alloc(24 * 1024 * 1024) }],
    });
    const digest = sha256(bomb);
    const staged = await t.store.stage(stream(bomb), { maxBytes: 64 * 1024 * 1024 });
    await t.store.commit({ tool: "trivy", sha256: digest, stageId: staged.stageId });
    await repo.insertCandidate({
      toolId: "trivy",
      sourceVersion: "v1",
      upstreamBuiltAt: hoursAgo(2),
      sizeBytes: bomb.length,
      sha256: digest,
      sources: [],
      recordCounts: {},
    });
    downloader.script("trivy", { bundle: bomb });
    const resumed = await run();
    same(p, "resumed bomb", [resumed.outcome, resumed.reason], ["rejected", "archive_hostile"]);
    same(
      p,
      "resumed bomb row",
      (await repo.getBySha({ toolId: "trivy", sha256: digest }))?.status,
      "rejected",
    );
    same(
      p,
      "resumed bomb object removed",
      await t.store.stat({ tool: "trivy", sha256: digest }),
      null,
    );
  } finally {
    t.done();
  }
}
