import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { createGzip } from "node:zlib";
import { fileURLToPath } from "node:url";
import { createJobEnvelope, parseMessage } from "@qmentisai/contracts";
import {
  ALLOWED_SOURCES,
  DEFAULT_SNAPSHOT_ARCHIVE_CAPS,
  DbMirrorIntegrityError,
  DbMirrorTooLargeError,
  FakeSandboxRuntime,
  NonRetryableError,
  checkDeclaredSources,
  classifyRecord,
  createSandboxRunner,
  inspectSnapshotArchive,
  snapshotArchiveCapsFor,
} from "@qmentisai/infra";
import {
  DB_STALENESS_TIERS,
  classifyDbStaleness,
  dbProvenance,
  dbStalenessEffect,
  resolveDbStalenessDays,
  rollUpTask,
} from "@qmentisai/shared";
import { ConfigError, loadWorkerConfig } from "../../../../workers/src/config.js";
import { CANARY_PLANS, createSandboxCanary } from "../../../../workers/src/dbrefresh/canary.js";
import {
  createDbRefreshHandler,
  createUnconfiguredDownloader,
} from "../../../../workers/src/dbrefresh/index.js";
import { createDbSnapshotResolver } from "../../../../workers/src/execution/engines/ensemble/db/resolve-db.js";
import { tar } from "./archive-checks.js";
import {
  canaryExtra,
  configExtra,
  inspectExtra,
  sourcesExtra,
  staleExtra,
  storeExtra,
  workerExtra,
} from "./dbmirror-boundary-checks.js";
import { CONFIG_INPUT } from "./sandbox-checks.js";
import {
  NOW,
  bundle,
  clock,
  daysAgo,
  hoursAgo,
  makeWritable,
  recordingLog,
  scanDbConfig,
  sha256,
  tempStore,
} from "./dbmirror-fixtures.js";

/**
 * Scan engines, part F (ADR-008 area 18, SPEC scan-engines 5.12, 5.12.1, 14.1 ENG-S12, 17.p): the pure and file-system parts of the
 * vulnerability DB mirror: staleness tiers and their effect, the record-level source allowlist and quarantine, hostile archive
 * containment, the content-addressed store with its materialization cache, the sandbox canary against the fake runtime, the worker
 * configuration (refresh OFF by default), the message contract and the source guard of the sealed scan path. The database parts (one
 * active snapshot, the atomic switch, the promotion gate, the refresh flow) are in dbmirror-db-checks.js. Docker-free and
 * network-free: the downloader is a fake, the runtime is the FakeSandboxRuntime, the clock is fixed.
 * NOT proved: the real downloads, the real upstream integrity metadata, the real Trivy and OSV-Scanner data and canary (ENG-L09,
 * ENG-L19), or any behaviour of an object-storage driver (none exists).
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const same = (p, label, got, want) =>
  ok(
    p,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)?.slice(0, 300)}, want ${JSON.stringify(want)?.slice(0, 300)}`,
  );
const rec = (id, over = {}) => ({
  id,
  aliases: [],
  affected: [{ package: { ecosystem: "npm", name: "x" } }],
  ...over,
});
const stream = (buffer) => Readable.from([buffer]);
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;

function walkJs(dir, out = []) {
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, name.name);
    if (name.isDirectory()) walkJs(full, out);
    else if (name.name.endsWith(".js")) out.push(full);
  }
  return out;
}

export const DBMIRROR_CHECKS = [
  {
    id: "ENG-S12a",
    name: "staleness tiers never fail a scan (SPEC scan-engines SE-38 as rewritten, D-22): the four tiers are decided from the UPSTREAM build time at the exact boundaries (3, 14 and 30 days, exclusive), a missing or unreadable build time is the fail-safe `expired`, a future build time is age 0, every tier above fresh is a PARTIAL run with the reason `db_stale`, an incomplete result and not resolution eligible (the roll-up of the tool statuses agrees), no tier fails, skips or makes a tool unavailable, an unknown tier is treated as expired, thresholds must be strictly increasing, the provenance a result carries is the digest and the dates and nothing else, and a missing snapshot is the different case `unavailable` / `db_unavailable`",
    async run() {
      const p = [];
      const day = 86_400_000;
      const at = (ageMs) => classifyDbStaleness({ builtAt: new Date(NOW - ageMs), now: NOW }).tier;
      same(p, "fresh", at(0), "fresh");
      same(p, "3 days exactly", at(3 * day), "fresh");
      same(p, "3 days + 1 ms", at(3 * day + 1), "aging");
      same(p, "14 days exactly", at(14 * day), "aging");
      same(p, "14 days + 1 ms", at(14 * day + 1), "stale");
      same(p, "30 days exactly", at(30 * day), "stale");
      same(p, "30 days + 1 ms", at(30 * day + 1), "expired");
      same(p, "future build", at(-5 * day), "fresh");
      for (const bad of [null, undefined, "not a date", NaN, {}])
        same(
          p,
          `unreadable build time ${String(bad)}`,
          classifyDbStaleness({ builtAt: bad, now: NOW }).tier,
          "expired",
        );
      same(
        p,
        "custom thresholds",
        classifyDbStaleness({ builtAt: daysAgo(2), now: NOW }, { aging: 1, stale: 5, expired: 9 })
          .tier,
        "aging",
      );
      for (const bad of [
        { aging: 5, stale: 5 },
        { aging: 0 },
        { stale: 2, expired: 2 },
        { aging: 20 },
        { aging: Number.NaN },
      ])
        ok(
          p,
          (() => {
            try {
              resolveDbStalenessDays(bad);
              return false;
            } catch (e) {
              return e instanceof RangeError;
            }
          })(),
          `thresholds ${JSON.stringify(bad)} must be refused`,
        );
      same(p, "tier list", DB_STALENESS_TIERS, ["fresh", "aging", "stale", "expired"]);
      const fresh = dbStalenessEffect("fresh");
      ok(
        p,
        fresh.toolStatus === "succeeded" &&
          fresh.reason === null &&
          !fresh.resultIncomplete &&
          fresh.resolutionEligible &&
          fresh.notice === null,
        "fresh is a clean run",
      );
      for (const tier of ["aging", "stale", "expired", "bogus", undefined, 7]) {
        const e = dbStalenessEffect(tier);
        ok(
          p,
          e.toolStatus === "partial" &&
            e.reason === "db_stale" &&
            e.resultIncomplete === true &&
            e.resolutionEligible === false &&
            e.failsScan === false,
          `${String(tier)}: ${JSON.stringify(e)}`,
        );
        const roll = rollUpTask({
          tools: [
            { toolId: "trivy", status: e.toolStatus, reason: e.reason },
            { toolId: "osv-scanner", status: "succeeded", reason: null },
          ],
        });
        ok(
          p,
          roll.taskStatus === "succeeded" &&
            roll.completeness === "incomplete" &&
            roll.resolutionEligible === false &&
            roll.toolsDegraded === 0,
          `${String(tier)}: the roll-up is ${JSON.stringify(roll)}`,
        );
      }
      same(p, "aging notice", dbStalenessEffect("aging").notice, "db_aging");
      same(p, "stale notice", dbStalenessEffect("stale").notice, "db_out_of_date");
      same(p, "expired notice", dbStalenessEffect("expired").notice, "db_out_of_date");
      same(p, "unknown tier is expired", dbStalenessEffect("bogus").tier, "expired");
      // the control: a fresh pair is complete and eligible
      const control = rollUpTask({
        tools: [
          { toolId: "trivy", status: "succeeded", reason: null },
          { toolId: "osv-scanner", status: "succeeded", reason: null },
        ],
      });
      ok(p, control.completeness === "complete" && control.resolutionEligible, "control roll-up");
      // provenance DTO
      const snap = {
        id: "internal-id",
        toolId: "trivy",
        sha256: "a".repeat(64),
        upstreamBuiltAt: hoursAgo(5),
        fetchedAt: hoursAgo(4),
        rejectedReason: "x",
        sources: [ALLOWED_SOURCES.ghsa, ALLOWED_SOURCES.nvd],
        storePath: "/secret/path",
      };
      const prov = dbProvenance(snap, { now: NOW });
      same(
        p,
        "provenance keys",
        Object.keys(prov).sort(),
        [
          "attributionRequired",
          "dbBuiltAt",
          "dbFetchedAt",
          "dbSnapshotSha256",
          "stalenessTier",
          "toolId",
        ].sort(),
      );
      ok(
        p,
        prov.attributionRequired === true && prov.stalenessTier === "fresh",
        "GHSA attribution is recorded",
      );
      ok(
        p,
        dbProvenance({ ...snap, sources: [ALLOWED_SOURCES.nvd] }, { now: NOW })
          .attributionRequired === false,
        "no GHSA, no attribution flag",
      );
      staleExtra(p);
      return p;
    },
  },
  {
    id: "ENG-S12b",
    name: "record-level source allowlist and quarantine (SPEC scan-engines SE-45, SE-46, 5.12.1, D-15, D-21, ENG-L19): only npm, PyPI, Go and Maven records of GHSA, NVD (CVE) and OSV core (PYSEC, GO, OSV) are allowed; Chainguard/Wolfi by id, alias, ecosystem or source field and any non-commercial licence field are QUARANTINED (and win over every other verdict); distro ecosystems, unknown id prefixes and a record with no ecosystem are refused; malformed, non-object, oversized-string and prototype-keyed values are classified without throwing or polluting; declared source lists are checked (empty, quarantined, unknown, Grype); each denial has a control",
    async run() {
      const p = [];
      const verdict = (r) => classifyRecord(r);
      // controls
      for (const [id, source, eco] of [
        ["GHSA-aaaa-bbbb-cccc", "ghsa", "npm"],
        ["GHSA-aaaa-bbbb-cccc", "ghsa", "PyPI"],
        ["GHSA-aaaa-bbbb-cccc", "ghsa", "Go"],
        ["GHSA-aaaa-bbbb-cccc", "ghsa", "Maven"],
        ["PYSEC-2021-1", "osv", "PyPI"],
        ["GO-2021-0001", "osv", "Go"],
        ["OSV-2021-1", "osv", "npm"],
        ["CVE-2021-23337", "nvd", "npm"],
      ]) {
        const v = verdict(rec(id, { affected: [{ package: { ecosystem: eco } }] }));
        ok(p, v.allowed && v.source === source, `control ${id}/${eco}: ${JSON.stringify(v)}`);
      }
      ok(
        p,
        verdict({ id: "CVE-2021-23337", affected: [] }).allowed,
        "a CVE record may list no ecosystem",
      );
      // quarantine, each by a different marker, and the precedence over an otherwise allowed record
      for (const [label, r] of [
        ["CGA id", rec("CGA-xxxx-yyyy-zzzz")],
        ["CGA alias", rec("GHSA-aaaa-bbbb-cccc", { aliases: ["CGA-1111-2222-3333"] })],
        [
          "Chainguard ecosystem",
          rec("GHSA-aaaa-bbbb-cccc", { affected: [{ package: { ecosystem: "Chainguard" } }] }),
        ],
        [
          "Wolfi ecosystem",
          rec("GHSA-aaaa-bbbb-cccc", { affected: [{ package: { ecosystem: "Wolfi" } }] }),
        ],
        [
          "wolfi in the source field",
          rec("GHSA-aaaa-bbbb-cccc", { database_specific: { source: "https://x/wolfi/y" } }),
        ],
        ["cgr.dev host", rec("GHSA-aaaa-bbbb-cccc", { database_specific: { source: "cgr.dev" } })],
        [
          "CC-BY-NC licence",
          rec("GHSA-aaaa-bbbb-cccc", { database_specific: { license: "CC-BY-NC-4.0" } }),
        ],
        [
          "non-commercial text",
          rec("GHSA-aaaa-bbbb-cccc", { database_specific: { licence: "Non-Commercial use only" } }),
        ],
        ["Chainguard with a mixed case id", rec("chainguard-1234")],
      ]) {
        const v = verdict(r);
        ok(p, !v.allowed && v.quarantined, `${label} must be quarantined: ${JSON.stringify(v)}`);
      }
      ok(
        p,
        verdict(rec("GHSA-aaaa-bbbb-cccc", { database_specific: { license: "CC-BY-4.0" } }))
          .allowed,
        "control: CC-BY-4.0 is not a non-commercial term",
      );
      // not allowed
      for (const [label, r] of [
        ["Debian", rec("DSA-5000-1", { affected: [{ package: { ecosystem: "Debian:11" } }] })],
        [
          "Alpine",
          rec("GHSA-aaaa-bbbb-cccc", { affected: [{ package: { ecosystem: "Alpine:v3.18" } }] }),
        ],
        [
          "RubyGems",
          rec("GHSA-aaaa-bbbb-cccc", { affected: [{ package: { ecosystem: "RubyGems" } }] }),
        ],
        [
          "one of two ecosystems is distro",
          rec("GHSA-aaaa-bbbb-cccc", {
            affected: [{ package: { ecosystem: "npm" } }, { package: { ecosystem: "Ubuntu" } }],
          }),
        ],
        ["unknown prefix", rec("RHSA-2021-1")],
        ["no ecosystem on a GHSA", { id: "GHSA-aaaa-bbbb-cccc" }],
        ["MAL prefix", rec("MAL-2021-1")],
      ]) {
        const v = verdict(r);
        ok(
          p,
          !v.allowed && !v.quarantined && v.reason === "not_allowed",
          `${label} must be not_allowed: ${JSON.stringify(v)}`,
        );
      }
      // malformed
      const proto = JSON.parse(
        '{"id":"GHSA-aaaa-bbbb-cccc","__proto__":{"polluted":true},"constructor":{"x":1}}',
      );
      const hostile = [
        null,
        undefined,
        5,
        "GHSA-aaaa-bbbb-cccc",
        [],
        {},
        { id: 5 },
        { id: "x" },
        { id: "a".repeat(5000) },
        { id: "GHSA-aaaa-bbbb-cccc", affected: "npm" },
        { id: "GHSA-aaaa-bbbb-cccc", affected: [null, 5, { package: 5 }] },
        proto,
      ];
      for (const r of hostile) {
        let v;
        try {
          v = verdict(r);
        } catch (e) {
          p.push(`classifyRecord threw ${e?.name} for ${JSON.stringify(r)?.slice(0, 60)}`);
          continue;
        }
        ok(p, v.allowed === false, `${JSON.stringify(r)?.slice(0, 60)} must not be allowed`);
      }
      ok(p, {}.polluted === undefined, "prototype pollution");
      // declared sources
      ok(p, checkDeclaredSources(["ghsa", "osv", "nvd"]).ok, "control: the allowed sources");
      ok(p, checkDeclaredSources(["GHSA"]).ok, "control: case-insensitive");
      for (const bad of [
        [],
        null,
        undefined,
        "ghsa",
        {},
        ["unknown"],
        ["ghsa", "grype-db"],
        ["chainguard"],
        ["wolfi"],
        ["trivy-os"],
        ["Chainguard-NC"],
        [5],
        ["ghsa", "x".repeat(200)],
      ])
        ok(p, !checkDeclaredSources(bad).ok, `declared ${JSON.stringify(bad)} must be refused`);
      ok(
        p,
        checkDeclaredSources(["ghsa", "grype-db"]).quarantined.includes("grype-db"),
        "grype-db is quarantined",
      );
      same(
        p,
        "attribution of GHSA",
        checkDeclaredSources(["ghsa"]).sources.map((s) => [s.id, s.licence, s.attributionRequired]),
        [["ghsa", "CC-BY-4.0", true]],
      );
      ok(
        p,
        ALLOWED_SOURCES.ghsa.attributionRequired === true &&
          ALLOWED_SOURCES.nvd.attributionRequired === false &&
          Object.isFrozen(ALLOWED_SOURCES) &&
          Object.keys(ALLOWED_SOURCES).sort().join() === "ghsa,nvd,osv",
        "the allowlist is closed and frozen",
      );
      sourcesExtra(p);
      return p;
    },
  },
  {
    id: "ENG-S12c",
    name: "a downloaded snapshot archive is a hostile input (SPEC scan-engines SE-34, T13, ENG-L08 for the real tools): path traversal, absolute paths, symbolic links, a zip bomb (expansion ratio), an entry-count cap, a depth cap, a truncated or non-gzip stream and a corrupt header all give `archive_hostile` WITHOUT extracting anything; a quarantined record, a distro record, a malformed record, an oversized record, an empty archive and a declared quarantined or unknown source in the bundle's own metadata are each refused with their own verdict (quarantine wins); a clean bundle is `ok` with per-source counts and the declared sources with their licences; the record scan never executes or imports content",
    async run() {
      const p = [];
      const verdictOf = async (buffer, caps) =>
        (await inspectSnapshotArchive(stream(buffer), { caps })).verdict;
      const clean = bundle({
        records: [
          rec("GHSA-aaaa-bbbb-cccc"),
          rec("CVE-2021-1", { affected: [] }),
          rec("PYSEC-2021-1", { affected: [{ package: { ecosystem: "PyPI" } }] }),
        ],
      });
      const r = await inspectSnapshotArchive(stream(clean));
      ok(p, r.verdict === "ok", `control: clean bundle verdict ${r.verdict}`);
      same(
        p,
        "control: counts",
        [r.records, r.bySource, r.quarantined, r.notAllowed, r.invalid],
        [3, { ghsa: 1, nvd: 1, osv: 1 }, 0, 0, 0],
      );
      same(p, "control: declared", r.declaredSources.map((s) => s.id).sort(), [
        "ghsa",
        "nvd",
        "osv",
      ]);
      // hostile archives
      const hostile = {
        traversal: bundle({ extra: [{ raw: true, name: "../evil.json", content: "{}" }] }),
        absolute: bundle({ extra: [{ raw: true, name: "/etc/x.json", content: "{}" }] }),
        symlink: bundle({
          extra: [{ name: "records/npm/link.json", type: "2", linkname: "/etc/passwd" }],
        }),
        hardlink: bundle({
          extra: [
            {
              name: "records/npm/h.json",
              type: "1",
              linkname: "records/npm/GHSA-aaaa-bbbb-cccc.json",
            },
          ],
        }),
        device: bundle({ extra: [{ name: "dev", type: "3" }] }),
        bomb: bundle({
          extra: [{ name: "data/zeros.bin", content: Buffer.alloc(24 * 1024 * 1024) }],
        }),
        notGzip: Buffer.from("this is not a gzip stream at all, just text"),
        truncated: clean.subarray(0, Math.floor(clean.length / 2)),
        empty: Buffer.alloc(0),
        control: bundle({ extra: [{ name: "records/npm/a\u0001b.json", content: "{}" }] }),
        deep: bundle({ extra: [{ name: `${"d/".repeat(20)}records.json`, content: "{}" }] }),
      };
      for (const [label, buffer] of Object.entries(hostile)) {
        let v;
        try {
          v = await verdictOf(buffer);
        } catch (e) {
          p.push(`${label}: threw ${e?.name}`);
          continue;
        }
        ok(p, v === "archive_hostile", `${label}: verdict ${v}`);
      }
      same(
        p,
        "entry cap",
        await verdictOf(
          bundle({
            extra: Array.from({ length: 30 }, (_, i) => ({ name: `data/f${i}`, content: "x" })),
          }),
          { maxEntries: 10 },
        ),
        "archive_hostile",
      );
      same(
        p,
        "file size cap",
        await verdictOf(bundle({ padBytes: 4096 }), { maxFileBytes: 1024 }),
        "archive_hostile",
      );
      same(
        p,
        "total size cap",
        await verdictOf(bundle({ padBytes: 4096 }), { maxTotalBytes: 2048 }),
        "archive_hostile",
      );
      // B1 (E2E run): the real Trivy database is ONE unpacked file of about 1.7 GiB, over the 512 MiB single-file cap that rejected every
      // real Trivy refresh. Only the vulnerability-database snapshot of that tool gets the higher cap; every other cap and every other
      // tool stay as they were, and repository archives (another module) are not touched.
      {
        const GiB = 1024 * 1024 * 1024;
        const trivy = snapshotArchiveCapsFor("trivy");
        ok(p, trivy.maxFileBytes >= 2 * GiB, `trivy single-file cap ${trivy.maxFileBytes}`);
        for (const [k, v] of Object.entries(DEFAULT_SNAPSHOT_ARCHIVE_CAPS))
          if (k !== "maxFileBytes")
            ok(p, trivy[k] === v, `trivy ${k} must stay ${v} (got ${trivy[k]})`);
        for (const tool of [
          "osv-scanner",
          "grype",
          "unknown",
          "__proto__",
          "constructor",
          undefined,
        ])
          same(p, `caps of ${tool}`, snapshotArchiveCapsFor(tool), {
            ...DEFAULT_SNAPSHOT_ARCHIVE_CAPS,
          });
        same(
          p,
          "an explicit override still wins",
          snapshotArchiveCapsFor("trivy", { maxFileBytes: 1024 }).maxFileBytes,
          1024,
        );
        // a REAL 520 MiB single file (incompressible 1 MiB blocks: ratio about 1, so only the single-file cap can refuse it), streamed
        // through gzip without touching the disk: refused by default, accepted for trivy
        const MiB = 1024 * 1024;
        const block = randomBytes(MiB);
        const huge = () => {
          const size = 520 * MiB;
          const header = Buffer.alloc(512);
          header.write("bundle/trivy.db", 0);
          header.write("0000644\0", 100);
          header.write("0000000\0", 108);
          header.write("0000000\0", 116);
          header.write(`${size.toString(8).padStart(11, "0")}\0`, 124);
          header.write("00000000000\0", 136);
          header.write("        ", 148);
          header.write("0", 156);
          header.write("ustar\0", 257);
          header.write("00", 263);
          let sum = 0;
          for (const byte of header) sum += byte;
          header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
          return Readable.from(
            (async function* () {
              yield header;
              for (let i = 0; i < 520; i += 1) yield block;
              yield Buffer.alloc(512 * 2);
            })(),
          ).pipe(createGzip({ level: 1 }));
        };
        const byDefault = await inspectSnapshotArchive(huge());
        same(p, "520 MiB file, default caps", byDefault.verdict, "archive_hostile");
        const forTrivy = await inspectSnapshotArchive(huge(), { tool: "trivy" });
        ok(
          p,
          forTrivy.verdict !== "archive_hostile" && forTrivy.files === 1,
          `520 MiB file, trivy caps: ${forTrivy.verdict} files ${forTrivy.files}`,
        );
      }
      // record-level verdicts
      const cga = bundle({ records: [rec("GHSA-aaaa-bbbb-cccc"), rec("CGA-xxxx-yyyy-zzzz")] });
      const wolfi = bundle({
        records: [rec("GHSA-aaaa-bbbb-cccc", { affected: [{ package: { ecosystem: "Wolfi" } }] })],
      });
      const nc = bundle({
        records: [rec("GHSA-aaaa-bbbb-cccc", { database_specific: { license: "CC-BY-NC-4.0" } })],
      });
      const distro = bundle({
        records: [rec("DSA-1-1", { affected: [{ package: { ecosystem: "Debian:12" } }] })],
      });
      const bad = bundle({ records: ["{ not json"] });
      const huge = bundle({
        records: [JSON.stringify({ id: "GHSA-aaaa-bbbb-cccc", pad: "x".repeat(1_200_000) })],
      });
      const quarantinedAndDistro = bundle({
        records: [
          rec("CGA-xxxx-yyyy-zzzz"),
          rec("DSA-1-1", { affected: [{ package: { ecosystem: "Debian:12" } }] }),
          "{ nope",
        ],
      });
      same(p, "Chainguard id", await verdictOf(cga), "quarantined_source");
      same(p, "Wolfi ecosystem", await verdictOf(wolfi), "quarantined_source");
      same(p, "non-commercial licence", await verdictOf(nc), "quarantined_source");
      same(p, "distro record", await verdictOf(distro), "source_not_allowed");
      same(p, "malformed record", await verdictOf(bad), "record_invalid");
      same(p, "oversized record", await verdictOf(huge), "record_invalid");
      same(
        p,
        "quarantine wins over the rest",
        await verdictOf(quarantinedAndDistro),
        "quarantined_source",
      );
      same(
        p,
        "bundle declares Chainguard",
        await verdictOf(bundle({ sources: ["ghsa", "chainguard"] })),
        "quarantined_source",
      );
      same(
        p,
        "bundle declares Grype DB",
        await verdictOf(bundle({ sources: ["grype-db"] })),
        "quarantined_source",
      );
      same(
        p,
        "bundle declares an unknown source",
        await verdictOf(bundle({ sources: ["somewhere"] })),
        "source_not_allowed",
      );
      same(
        p,
        "bundle declares no sources",
        await verdictOf(bundle({ sources: [] })),
        "source_not_allowed",
      );
      // an opaque database file with a declared source list is accepted (its content is covered by ENG-L19, not here)
      same(
        p,
        "opaque database",
        await verdictOf(
          tar([
            { name: "metadata.json", content: JSON.stringify({ sources: ["ghsa"] }) },
            { name: "trivy.db", content: "opaque" },
          ]),
        ),
        "ok",
      );
      same(p, "no files at all", await verdictOf(tar([])), "empty");
      await inspectExtra(p);
      return p;
    },
  },
  {
    id: "ENG-S12d",
    name: "the content-addressed store and the materialization cache (SPEC scan-engines SE-32, SE-33, SE-36): staging is size-capped and hashes the bytes received, a commit of a staged file under another digest is refused and nothing is written, no caller-supplied path exists (tool and digest are validated), the object is addressed by its sha256 and written once, a corrupted stored object is NOT materialized and nothing is extracted, a good object is extracted by the hardened extractor into `<cache>/<tool>/<sha256>/` sealed 0555/0444 (not writable), concurrent materializations give one directory, the stage sweep removes only old staged files, removal deletes the object and the tree; each denial has a control",
    async run() {
      const p = [];
      const t = tempStore();
      try {
        const { store } = t;
        const good = bundle();
        const digest = sha256(good);
        // staging
        const staged = await store.stage(stream(good), { maxBytes: 1 << 20 });
        ok(
          p,
          staged.sha256 === digest && staged.bytes === good.length,
          "stage computes the digest of the bytes received",
        );
        let tooLarge = null;
        try {
          await store.stage(stream(good), { maxBytes: 100 });
        } catch (e) {
          tooLarge = e;
        }
        ok(p, tooLarge instanceof DbMirrorTooLargeError, "stage over the cap");
        ok(
          p,
          readdirSync(path.join(t.root, "stage")).length === 1,
          "a refused stage leaves no file behind",
        );
        // commit under a wrong digest
        const wrong = "f".repeat(64);
        let mismatch = null;
        try {
          await store.commit({ tool: "trivy", sha256: wrong, stageId: staged.stageId });
        } catch (e) {
          mismatch = e;
        }
        ok(p, mismatch instanceof DbMirrorIntegrityError, "commit under another digest");
        ok(
          p,
          !existsSync(path.join(t.root, "db", "trivy", `${wrong}.tar.gz`)),
          "nothing was written under the wrong digest",
        );
        // validation of references
        for (const bad of [
          { tool: "grype", sha256: digest },
          { tool: "../trivy", sha256: digest },
          { tool: "trivy", sha256: "../../etc/passwd" },
          { tool: "trivy", sha256: digest.toUpperCase() },
          { tool: "trivy", sha256: digest.slice(1) },
          { tool: "trivy", sha256: undefined },
        ])
          ok(
            p,
            (() => {
              try {
                store.open(bad);
                return false;
              } catch (e) {
                return e instanceof TypeError;
              }
            })(),
            `reference ${JSON.stringify(bad)} must be refused`,
          );
        ok(
          p,
          (() => {
            try {
              store.openStaged("../x");
              return false;
            } catch (e) {
              return e instanceof TypeError;
            }
          })(),
          "stage id",
        );
        // commit, once
        const staged2 = await store.stage(stream(good), { maxBytes: 1 << 20 });
        ok(
          p,
          (await store.commit({ tool: "trivy", sha256: digest, stageId: staged2.stageId }))
            .created === true,
          "control: commit",
        );
        const staged3 = await store.stage(stream(good), { maxBytes: 1 << 20 });
        ok(
          p,
          (await store.commit({ tool: "trivy", sha256: digest, stageId: staged3.stageId }))
            .created === false,
          "an existing object is kept",
        );
        same(
          p,
          "list",
          (await store.list("trivy")).map((o) => o.sha256),
          [digest],
        );
        same(p, "stat", (await store.stat({ tool: "trivy", sha256: digest })).bytes, good.length);
        ok(
          p,
          (await store.stat({ tool: "osv-scanner", sha256: digest })) === null,
          "another tool has no such object",
        );
        ok(p, (await store.verify({ tool: "trivy", sha256: digest })) === true, "control: verify");
        // materialize
        const a = await store.materialize({ tool: "trivy", sha256: digest });
        same(p, "cache dir", a.dir, store.cacheDirFor({ tool: "trivy", sha256: digest }));
        ok(p, a.created === true && existsSync(path.join(a.dir, "metadata.json")), "extracted");
        same(p, "directory mode", statSync(a.dir).mode & 0o777, 0o555);
        same(p, "file mode", statSync(path.join(a.dir, "metadata.json")).mode & 0o777, 0o444);
        same(p, "sub directory mode", statSync(path.join(a.dir, "records")).mode & 0o777, 0o555);
        if (!isRoot) {
          let wrote = true;
          try {
            writeFileSync(path.join(a.dir, "x"), "x");
          } catch {
            wrote = false;
          }
          ok(p, !wrote, "the materialized tree is read-only");
        }
        ok(
          p,
          (await store.materialize({ tool: "trivy", sha256: digest })).created === false,
          "a second materialization reuses the tree",
        );
        // concurrency
        const t2 = tempStore();
        try {
          await (async () => {
            const s = await t2.store.stage(stream(good), { maxBytes: 1 << 20 });
            await t2.store.commit({ tool: "osv-scanner", sha256: digest, stageId: s.stageId });
          })();
          const results = await Promise.all(
            Array.from({ length: 6 }, () =>
              t2.store.materialize({ tool: "osv-scanner", sha256: digest }),
            ),
          );
          ok(
            p,
            new Set(results.map((x) => x.dir)).size === 1 &&
              results.filter((x) => x.created).length === 1,
            `concurrent materializations: ${results.filter((x) => x.created).length} created`,
          );
          same(p, "no temporary copies left", readdirSync(path.join(t2.cacheRoot, ".tmp")), []);
        } finally {
          t2.done();
        }
        // corruption: flip a byte of the stored object (the file is 0444, so make it writable first, as a tamperer with the file's owner rights would)
        const t3 = tempStore();
        try {
          const s = await t3.store.stage(stream(good), { maxBytes: 1 << 20 });
          await t3.store.commit({ tool: "trivy", sha256: digest, stageId: s.stageId });
          const file = path.join(t3.root, "db", "trivy", `${digest}.tar.gz`);
          chmodSync(file, 0o644);
          const bytes = readFileSync(file);
          bytes[bytes.length - 40] ^= 0xff;
          writeFileSync(file, bytes);
          ok(
            p,
            (await t3.store.verify({ tool: "trivy", sha256: digest })) === false,
            "verify detects the corruption",
          );
          let refused = null;
          try {
            await t3.store.materialize({ tool: "trivy", sha256: digest });
          } catch (e) {
            refused = e;
          }
          ok(
            p,
            refused instanceof DbMirrorIntegrityError,
            "a corrupted object is not materialized",
          );
          ok(p, !existsSync(path.join(t3.cacheRoot, "trivy", digest)), "nothing was extracted");
          let missing = null;
          try {
            await t3.store.materialize({ tool: "osv-scanner", sha256: "e".repeat(64) });
          } catch (e) {
            missing = e;
          }
          ok(p, missing instanceof DbMirrorIntegrityError, "a missing object is not materialized");
        } finally {
          t3.done();
        }
        // stage sweep
        const old = await store.stage(stream(good), { maxBytes: 1 << 20 });
        const fresh = await store.stage(stream(good), { maxBytes: 1 << 20 });
        const removed = await store.sweepStage({ olderThanMs: 60_000, now: Date.now() + 120_000 });
        ok(p, removed >= 2, `the sweep removes staged files older than the limit (${removed})`);
        ok(
          p,
          (await store.sweepStage({ olderThanMs: 60_000, now: Date.now() })) === 0,
          "control: a fresh stage is kept",
        );
        void old;
        void fresh;
        // removal
        await store.remove({ tool: "trivy", sha256: digest });
        ok(
          p,
          !existsSync(path.join(t.root, "db", "trivy", `${digest}.tar.gz`)) && !existsSync(a.dir),
          "remove deletes the object and the tree",
        );
        // a hostile object cannot be materialized even when its digest is right
        const hostileBuffer = bundle({ extra: [{ raw: true, name: "../evil", content: "x" }] });
        const hd = sha256(hostileBuffer);
        const hs = await store.stage(stream(hostileBuffer), { maxBytes: 1 << 20 });
        await store.commit({ tool: "trivy", sha256: hd, stageId: hs.stageId });
        const hostileTree = await store.materialize({ tool: "trivy", sha256: hd }).then(
          (x) => x,
          (e) => e,
        );
        ok(
          p,
          !existsSync(path.join(t.root, "evil")) && !existsSync(path.join(t.cacheRoot, "evil")),
          "traversal wrote nothing outside the cache",
        );
        ok(
          p,
          hostileTree.dir === undefined || !existsSync(path.join(hostileTree.dir, "evil")),
          "the traversal entry was skipped",
        );
        const tmpLeft = existsSync(path.join(t.cacheRoot, ".tmp"))
          ? readdirSync(path.join(t.cacheRoot, ".tmp"))
          : [];
        same(p, "no temporary extraction left", tmpLeft, []);
      } finally {
        t.done();
      }
      await storeExtra(p);
      return p;
    },
  },
  {
    id: "ENG-S12e",
    name: "the canary scan of the promotion gate runs in the sealed sandbox (SPEC scan-engines SE-35, SE-36, 6.2, ENG-S12): the RunSpec built from the platform fixture mounts ONLY the candidate directory read-only at `/db`, has no network purpose, no archive and no repository content, carries the offline switches, and the container invocation recorded by the fake runtime has `--network=none` and a read-only bind of the `/db` mount; the expected advisory in the output passes, a missing advisory is `missing_advisory`, a runtime fault, a timeout, a non-exit status, an unresolvable image and an unknown tool are `unavailable` (never a pass); only trivy and osv-scanner have a plan (Grype is deferred, D-21); no credential or URL is in the spec",
    async run() {
      const p = [];
      const sha = "c".repeat(64);
      const dir = (tool) => `/var/lib/qm/db/${tool}/${sha}`;
      const image = (repo) => `registry.example/${repo}@sha256:${"b".repeat(64)}`;
      const resolver = {
        resolve(key) {
          if (!["trivy", "osv-scanner"].includes(key)) throw new Error("no image");
          return { image: image(key) };
        },
      };
      const newRig = (scripts = {}) => {
        const runtime = new FakeSandboxRuntime({ config: CONFIG_INPUT });
        for (const [tool, outcome] of Object.entries(scripts)) runtime.script(tool, outcome);
        const runner = createSandboxRunner({ runtime });
        return {
          runtime,
          canary: createSandboxCanary({
            runner,
            resolver,
            now: () => NOW.getTime(),
            rulesDir: "/opt/qm/rules",
          }),
        };
      };
      const advisory = (id) =>
        JSON.stringify({ Results: [{ Vulnerabilities: [{ VulnerabilityID: id }] }] });
      // controls
      for (const [tool, id] of [
        ["trivy", "CVE-2021-23337"],
        ["trivy", "GHSA-35jh-r3h4-6jhm"],
        ["osv-scanner", "GHSA-35jh-r3h4-6jhm"],
      ]) {
        const rig = newRig({ [tool]: { exitCode: 0, stdout: advisory(id) } });
        const v = await rig.canary({ toolId: tool, sha256: sha, dir: dir(tool) });
        ok(p, v.ok === true, `control ${tool}/${id}: ${JSON.stringify(v)}`);
      }
      const rig = newRig({ trivy: { exitCode: 0, stdout: advisory("CVE-2021-23337") } });
      await rig.canary({ toolId: "trivy", sha256: sha, dir: dir("trivy") });
      const run = rig.runtime.calls.find((c) => c.type === "run");
      ok(p, !!run, "the runtime ran the canary");
      if (run) {
        same(p, "mounts", run.spec.mounts, { db: dir("trivy"), rules: "/opt/qm/rules" });
        ok(p, run.spec.stdin === undefined, "the fixture is a platform file, not stdin");
        ok(p, run.spec.argv.at(-1) === "/rules/canary.cdx.json", "the fixture path");
        ok(
          p,
          run.args.some((a) => a === "--mount=type=bind,src=/opt/qm/rules,dst=/rules,readonly"),
          "the /rules bind is read-only",
        );
        ok(p, run.spec.networkPurpose === undefined, "no network purpose");
        ok(p, !run.spec.mounts.archive && !run.spec.paths, "no repository content");
        ok(
          p,
          run.spec.argv.includes("--offline-scan") && run.spec.argv.includes("--skip-db-update"),
          "the offline switches",
        );
        ok(p, run.args.includes("--network=none"), "the container has no network");
        ok(
          p,
          run.args.some((a) => a === `--mount=type=bind,src=${dir("trivy")},dst=/db,readonly`),
          "the /db bind is read-only",
        );
        ok(
          p,
          !run.args.some((a) => /socket|docker\.sock|--privileged|--network=host/.test(a)),
          "no socket, privilege or host network",
        );
        ok(p, run.spec.labels.tenantId === "platform", "labelled as a platform run");
        ok(
          p,
          !/https?:\/\/|token|secret|password/i.test(
            JSON.stringify(run.spec).replace(/"image":"[^"]*"/, ""),
          ),
          "no URL or credential in the spec",
        );
      }
      // denials
      const missing = await newRig({
        trivy: { exitCode: 0, stdout: advisory("CVE-1999-0001") },
      }).canary({ toolId: "trivy", sha256: sha, dir: dir("trivy") });
      same(p, "another advisory only", missing, { ok: false, reason: "missing_advisory" });
      same(
        p,
        "empty output",
        await newRig({ trivy: { exitCode: 0, stdout: "" } }).canary({
          toolId: "trivy",
          sha256: sha,
          dir: dir("trivy"),
        }),
        { ok: false, reason: "missing_advisory" },
      );
      same(
        p,
        "garbage output",
        await newRig({ trivy: { exitCode: 0, stdout: "\u0000{{{" } }).canary({
          toolId: "trivy",
          sha256: sha,
          dir: dir("trivy"),
        }),
        { ok: false, reason: "missing_advisory" },
      );
      for (const [label, outcome] of [
        ["runtime fault", { runtimeFault: true }],
        ["hang then abort", { hang: true }],
      ]) {
        const r = newRig({ trivy: outcome });
        const ac = new AbortController();
        const pending = r.canary({
          toolId: "trivy",
          sha256: sha,
          dir: dir("trivy"),
          signal: ac.signal,
        });
        if (outcome.hang) setTimeout(() => ac.abort(), 20);
        same(p, label, await pending, { ok: false, reason: "unavailable" });
      }
      same(
        p,
        "no rules directory",
        await createSandboxCanary({
          runner: createSandboxRunner({
            runtime: new FakeSandboxRuntime({ config: CONFIG_INPUT }),
          }),
          resolver,
        })({ toolId: "trivy", sha256: sha, dir: dir("trivy") }),
        { ok: false, reason: "unavailable" },
      );
      const noImage = createSandboxCanary({
        rulesDir: "/opt/qm/rules",
        runner: createSandboxRunner({ runtime: new FakeSandboxRuntime({ config: CONFIG_INPUT }) }),
        resolver: {
          resolve() {
            throw new Error("x");
          },
        },
      });
      same(
        p,
        "unresolvable image",
        await noImage({ toolId: "trivy", sha256: sha, dir: dir("trivy") }),
        { ok: false, reason: "unavailable" },
      );
      same(
        p,
        "unknown tool",
        await newRig().canary({ toolId: "grype", sha256: sha, dir: dir("trivy") }),
        { ok: false, reason: "unavailable" },
      );
      same(
        p,
        "an invalid mount root",
        await newRig().canary({ toolId: "trivy", sha256: sha, dir: "/etc/not-a-db-root" }),
        { ok: false, reason: "unavailable" },
      );
      same(p, "plans", Object.keys(CANARY_PLANS).sort(), ["osv-scanner", "trivy"]);
      await canaryExtra(p);
      return p;
    },
  },
  {
    id: "ENG-S12f",
    name: "the refresh is OFF unless configured and carries no secret (SPEC scan-engines SE-34, SE-39, 9.2, ADR-011): the worker configuration defaults to refresh disabled with fresh/aging/stale/expired thresholds 3, 14 and 30, enabling it requires a database, two different absolute directories and only trivy and osv-scanner (Grype is refused by name), thresholds must be strictly increasing and no value is echoed in an error; the message `maintenance.scan_db.refresh_requested` is a strict platform job (no tenant, unknown keys, Grype, an empty or oversized tool list, a URL or a path all refused); the handler refuses a job in a process where the refresh is off and any other message type (non-retryable), refreshes only the tools the process itself allows, and its log lines hold tool ids, outcome words and digests only; the default downloader refuses (non-retryable)",
    async run() {
      const p = [];
      const base = {
        RABBITMQ_URL: "amqp://x:y@localhost:5672",
        DATABASE_URL: "postgresql://u:pw@localhost:5432/d",
      };
      const cfg = loadWorkerConfig(base, { workerName: "scheduler" });
      ok(p, cfg.scanDb.refreshEnabled === false, "default OFF");
      same(p, "default thresholds", cfg.scanDb.stalenessDays, { aging: 3, stale: 14, expired: 30 });
      same(p, "default tools", [...cfg.scanDb.tools], ["trivy", "osv-scanner"]);
      ok(p, cfg.scanDb.mirrorRoot === null && cfg.scanDb.cacheRoot === null, "no roots by default");
      const enabled = {
        ...base,
        SCAN_DB_REFRESH_ENABLED: "true",
        SCAN_DB_MIRROR_ROOT: "/srv/qm/mirror",
        SCAN_DB_CACHE_ROOT: "/srv/qm/cache",
        SANDBOX_RULES_DIR: "/srv/qm/rules",
      };
      const on = loadWorkerConfig(enabled, { workerName: "dbrefresh" });
      ok(
        p,
        on.scanDb.refreshEnabled === true && on.scanDb.mirrorRoot === "/srv/qm/mirror",
        "control: enabled with roots",
      );
      const refuses = (env, needle) => {
        try {
          loadWorkerConfig(env, { workerName: "dbrefresh" });
          return `accepted ${needle}`;
        } catch (e) {
          if (!(e instanceof ConfigError)) return `threw ${e?.name}`;
          if (!e.message.includes(needle))
            return `message lacks ${needle}: ${e.message.slice(0, 120)}`;
          const secretish = ["pw", "amqp://", "/srv/qm"].find((s) => e.message.includes(s));
          return secretish ? `message echoes a value (${secretish})` : null;
        }
      };
      for (const [env, needle] of [
        [{ ...enabled, SCAN_DB_MIRROR_ROOT: undefined }, "SCAN_DB_MIRROR_ROOT"],
        [{ ...enabled, SCAN_DB_CACHE_ROOT: "relative/dir" }, "SCAN_DB_CACHE_ROOT"],
        [{ ...enabled, SANDBOX_RULES_DIR: undefined }, "SANDBOX_RULES_DIR"],
        [{ ...enabled, SANDBOX_RULES_DIR: "rules" }, "SANDBOX_RULES_DIR"],
        [{ ...enabled, SCAN_DB_CACHE_ROOT: "/srv/qm/mirror" }, "SCAN_DB_CACHE_ROOT"],
        [{ ...enabled, DATABASE_URL: undefined, REDIS_URL: "redis://localhost" }, "DATABASE_URL"],
        [{ ...enabled, SCAN_DB_REFRESH_TOOLS: "trivy,grype" }, "SCAN_DB_REFRESH_TOOLS"],
        [{ ...enabled, SCAN_DB_REFRESH_TOOLS: "trivy,whatever" }, "SCAN_DB_REFRESH_TOOLS"],
        [{ ...enabled, SCAN_DB_REFRESH_TOOLS: " , " }, "SCAN_DB_REFRESH_TOOLS"],
        [{ ...base, SCAN_DB_STALE_AGING_DAYS: "20" }, "SCAN_DB_STALE"],
        [{ ...base, SCAN_DB_STALE_STALE_DAYS: "3" }, "SCAN_DB_STALE"],
        [{ ...base, SCAN_DB_REFRESH_ENABLED: "yes" }, "SCAN_DB_REFRESH_ENABLED"],
        [{ ...base, SCAN_DB_REFRESH_INTERVAL_SECONDS: "5" }, "SCAN_DB_REFRESH_INTERVAL_SECONDS"],
      ]) {
        const problem = refuses(env, needle);
        if (problem) p.push(`${needle}: ${problem}`);
      }
      const grypeProblem = (() => {
        try {
          loadWorkerConfig(
            { ...enabled, SCAN_DB_REFRESH_TOOLS: "grype" },
            { workerName: "dbrefresh" },
          );
          return null;
        } catch (e) {
          return e.message;
        }
      })();
      ok(p, /D-21/.test(grypeProblem ?? ""), "Grype is refused by name with the decision");
      // the message contract
      const job = (payload, over = {}) =>
        createJobEnvelope({
          type: "maintenance.scan_db.refresh_requested",
          schemaVersion: 1,
          initiator: { type: "system", id: "scheduler" },
          payload,
          ...over,
        });
      const accepts = (m) => {
        try {
          parseMessage(m);
          return true;
        } catch {
          return false;
        }
      };
      ok(p, accepts(job({ tools: ["trivy", "osv-scanner"] })), "control: a valid message");
      for (const [label, m] of [
        ["grype", job({ tools: ["grype"] })],
        ["empty tools", job({ tools: [] })],
        ["three tools", job({ tools: ["trivy", "osv-scanner", "trivy"] })],
        ["an unknown key", job({ tools: ["trivy"], url: "https://example.com/db.tar.gz" })],
        ["a path", job({ tools: ["trivy"], root: "/etc" })],
        [
          "a tenant",
          job({ tools: ["trivy"] }, { tenantId: "11111111-1111-4111-8111-111111111111" }),
        ],
        ["no payload", job({})],
      ])
        ok(p, !accepts(m), `${label} must be refused by the contract`);
      // the handler
      const downloader = createUnconfiguredDownloader();
      let threw = null;
      try {
        await downloader.latest({ toolId: "trivy" });
      } catch (e) {
        threw = e;
      }
      ok(p, threw instanceof NonRetryableError, "the default downloader refuses (non-retryable)");
      const { log, lines } = recordingLog();
      const off = createDbRefreshHandler({
        config: { scanDb: scanDbConfig({ refreshEnabled: false }) },
        deps: null,
      });
      let offError = null;
      try {
        await off(job({ tools: ["trivy"] }), { log });
      } catch (e) {
        offError = e;
      }
      ok(
        p,
        offError instanceof NonRetryableError && offError.reason === "refresh-disabled",
        "refused where the refresh is off",
      );
      const wrongType = createDbRefreshHandler({ config: { scanDb: scanDbConfig() }, deps: null });
      let typeError = null;
      try {
        await wrongType({ type: "maintenance.sessions.purge_requested", payload: {} }, { log });
      } catch (e) {
        typeError = e;
      }
      ok(p, typeError instanceof NonRetryableError, "refused for another message type");
      ok(p, lines.length === 0, "a refusal logs nothing");
      configExtra(p);
      await workerExtra(p);
      return p;
    },
  },
  {
    id: "ENG-S12g",
    name: "the sealed scan path can neither download, promote nor reject (SPEC scan-engines ENG-S12): no file of the scan path (`execution/**`, including the ensemble engine and the DB resolver) imports the refresh worker, the downloader, the canary or the repository write methods of the snapshot table; the resolver returns only an `active` snapshot, materializes it only after the digest check, never returns a candidate, retired or rejected one, and answers `unavailable` / `db_unavailable` for no snapshot or for an object that does not match its digest (never mounting it); the resolver's result carries the staleness effect (partial / `db_stale`, never a failure) and a provenance with the digest and dates only",
    async run() {
      const p = [];
      const scanDir = path.join(ROOT, "apps/workers/src/execution");
      const banned = [
        /dbrefresh/,
        /createScanDbSnapshotRepository/,
        /\.promote\(|\.insertCandidate\(|\.reject\(|\.insertRejected\(|\.retireActive\(|\.activate\(/,
        /downloader/i,
        /createSandboxCanary/,
      ];
      let files = 0;
      for (const file of walkJs(scanDir)) {
        files += 1;
        const text = readFileSync(file, "utf8")
          .replace(/\/\*[\s\S]*?\*\//g, "")
          .replace(/\/\/[^\n]*/g, "");
        for (const re of banned)
          if (re.test(text))
            p.push(`${path.relative(ROOT, file)} reaches the refresh side (${re})`);
      }
      ok(p, files > 30, `source guard saw ${files} files`);
      const resolverText = readFileSync(
        path.join(scanDir, "engines/ensemble/db/resolve-db.js"),
        "utf8",
      );
      ok(
        p,
        /getActive\(/.test(resolverText) && /materialize\(/.test(resolverText),
        "the resolver reads the active snapshot and materializes it",
      );
      // behaviour with fakes
      const t = tempStore();
      try {
        const good = bundle();
        const digest = sha256(good);
        const s = await t.store.stage(stream(good), { maxBytes: 1 << 20 });
        await t.store.commit({ tool: "trivy", sha256: digest, stageId: s.stageId });
        const snap = (over = {}) => ({
          id: "i",
          toolId: "trivy",
          sha256: digest,
          upstreamBuiltAt: hoursAgo(1),
          fetchedAt: hoursAgo(1),
          status: "active",
          sources: [],
          ...over,
        });
        const resolverFor = (row, days) =>
          createDbSnapshotResolver({
            repo: { getActive: async () => row },
            store: t.store,
            now: clock,
            days,
          });
        const fresh = await resolverFor(snap()).resolve("trivy");
        ok(
          p,
          fresh.state === "ok" && fresh.effect.toolStatus === "succeeded" && existsSync(fresh.dir),
          "control: fresh active snapshot",
        );
        same(
          p,
          "provenance",
          [
            fresh.provenance.dbSnapshotSha256,
            fresh.provenance.dbBuiltAt,
            fresh.provenance.stalenessTier,
          ],
          [digest, hoursAgo(1).toISOString(), "fresh"],
        );
        for (const [tier, days] of [
          ["aging", 5],
          ["stale", 20],
          ["expired", 40],
        ]) {
          const r = await resolverFor(snap({ upstreamBuiltAt: daysAgo(days) })).resolve("trivy");
          ok(
            p,
            r.state === "ok" &&
              r.effect.toolStatus === "partial" &&
              r.effect.reason === "db_stale" &&
              r.effect.failsScan === false &&
              r.provenance.stalenessTier === tier,
            `${tier}: ${JSON.stringify(r.effect)}`,
          );
        }
        const none = await resolverFor(null).resolve("trivy");
        ok(
          p,
          none.state === "missing" &&
            none.effect.failsScan === false &&
            none.effect.toolStatus === "unavailable" &&
            none.effect.reason === "db_unavailable" &&
            none.dir === undefined,
          "no snapshot is unavailable",
        );
        const other = await resolverFor(snap({ sha256: "d".repeat(64) })).resolve("trivy");
        ok(
          p,
          other.state === "missing" && other.dir === undefined,
          "an object that is not stored is not mounted",
        );
        // corrupted object: never mounted
        const t2 = tempStore();
        try {
          const s2 = await t2.store.stage(stream(good), { maxBytes: 1 << 20 });
          await t2.store.commit({ tool: "trivy", sha256: digest, stageId: s2.stageId });
          const file = path.join(t2.root, "db", "trivy", `${digest}.tar.gz`);
          chmodSync(file, 0o644);
          const b = readFileSync(file);
          b[b.length - 30] ^= 0x55;
          writeFileSync(file, b);
          const r = await createDbSnapshotResolver({
            repo: { getActive: async () => snap() },
            store: t2.store,
            now: clock,
          }).resolve("trivy");
          ok(
            p,
            r.state === "missing" &&
              r.dir === undefined &&
              !existsSync(path.join(t2.cacheRoot, "trivy", digest)),
            "a corrupted object is neither extracted nor mounted",
          );
        } finally {
          t2.done();
        }
        // an infrastructure error is not swallowed as "missing"
        const boom = createDbSnapshotResolver({
          repo: {
            getActive: async () => {
              throw new Error("db down");
            },
          },
          store: t.store,
          now: clock,
        });
        ok(
          p,
          await boom.resolve("trivy").then(
            () => false,
            (e) => e.message === "db down",
          ),
          "a repository error propagates",
        );
      } finally {
        t.done();
      }
      void makeWritable;
      return p;
    },
  },
];
