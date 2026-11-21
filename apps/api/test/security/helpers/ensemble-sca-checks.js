import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  cvss3BaseScore,
  findingSchema,
  rollUpTask,
  normalizeOsvSeverity,
  parseCvssVersion,
  provenanceEntrySchema,
  severityFromCvssScore,
} from "@qmentisai/shared";
import {
  mergeTaskCandidates,
  runToolParse,
} from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import { classifyToolExit } from "../../../../workers/src/execution/engines/ensemble/engine/tool-exit.js";
import { TASK_A, ctxFor, fakeAdapter, out } from "./ensemble-fakes.js";

/**
 * Scan engines, part G (ADR-008 area 18, SPEC scan-engines 14.1 ENG-S06 and 16.1 part G): the framework pieces of the SCA ensemble
 * (CVSS calculator, OSV severity maps, advisory alias union-find and pairing). Pure functions: no container, process, database or
 * network. The CVSS calculator is proved against REAL data: the 44 distinct vector and score pairs of the real Trivy report of
 * 2026-11-21 (`fixtures/scan-engines/sca/real/trivy-sca-treeC.json`). Severity TABLES and tolerances stay out of ADR-008 scope; the
 * policy properties (unknown is medium with the flag, the highest wins, a hostile vector never throws or chooses a severity) are asserted.
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const FIX = path.join(ROOT, "apps/api/test/security/fixtures/scan-engines/sca/real");
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const same = (p, label, got, want) =>
  ok(
    p,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
  );

const TRIVY = fakeAdapter("trivy", "sca");
const OSV = fakeAdapter("osv-scanner", "sca");
const cands = (adapter, records, task = TASK_A) => {
  const r = runToolParse(adapter, out(records), ctxFor(task));
  if (r.candidates.length !== records.length)
    throw new Error(`fixture dropped records (${r.status}/${r.reason})`);
  return r.candidates;
};
const merge = (candidates) =>
  mergeTaskCandidates({ taskRef: TASK_A, scanType: "sca", candidates }).findings;
const shape = (findings) =>
  findings
    .map((f) => [
      f.component.purl,
      f.location?.path,
      f.provenance.map((x) => x.toolId).join("+"),
      f.rule.id,
    ])
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
const LODASH = "pkg:npm/lodash@4.17.20";

export const ENSEMBLE_SCA_CHECKS = [
  {
    id: "ENG-S06h",
    name: "the CVSS v3 calculator and the OSV severity maps (SPEC scan-engines 5.7, D-5, OQ-4, part G): the in-repo calculator reproduces every one of the 44 distinct vector and score pairs of the REAL Trivy report of 2026-11-21 (v3.0 and v3.1, scope changed and unchanged, every metric value), the FIRST reference vectors (9.8, 10.0, 0.0, 7.2), refuses everything that is not a strict base vector (a v2, v4, lower-case, repeated, missing, unknown or extra metric, a temporal metric, a hostile or oversized string, a non-string) with null and never throws; the OSV group severity is the label (GHSA CRITICAL, HIGH, MODERATE, LOW) first, else the scored v3 vector, the HIGHEST of the group wins, a v4-only, v2-only, malformed or absent severity is medium with the severity-unmapped flag, and a hostile vector key never pollutes the scores; the provenance entry carries at most two CVSS entries of a known version, no unknown key and stays within its 600 bytes",
    async run() {
      const p = [];
      const report = JSON.parse(readFileSync(path.join(FIX, "trivy-sca-treeC.json"), "utf8"));
      const pairs = new Map();
      for (const r of report.Results)
        for (const v of r.Vulnerabilities ?? [])
          for (const [source, c] of Object.entries(v.CVSS ?? {}))
            if (c.V3Vector)
              pairs.set(`${c.V3Vector}|${c.V3Score}`, [c.V3Vector, c.V3Score, source]);
      ok(p, pairs.size >= 30, `control: only ${pairs.size} real pairs`);
      ok(
        p,
        [...pairs.values()].some(([v]) => /\/E:[A-Z]$/.test(v)),
        "control: no real vector with a temporal metric",
      );
      ok(
        p,
        [...pairs.values()].some(([v]) => v.startsWith("CVSS:3.0/")) ||
          [...pairs.values()].some(([v]) => v.includes("S:C")),
        "control: the real pairs hold neither a v3.0 vector nor a changed scope",
      );
      // REAL discrepancy, recorded: for CVE-2021-45046 GHSA states 9.1 and NVD 9.0 for the SAME vector; the FIRST formula gives 9.0
      const disagree = [...pairs.values()].filter(
        ([vector, score]) => cvss3BaseScore(vector) !== score,
      );
      same(
        p,
        "pairs the calculator and the source disagree on",
        disagree.map(([vector, score, source]) => [vector, score, source]),
        [["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.1, "ghsa"]],
      );
      same(
        p,
        "that vector by the formula",
        cvss3BaseScore("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        9,
      );
      for (const [vector, score] of [
        ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
        ["CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
        ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10],
        ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0],
        ["CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2],
        ["CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6],
        ["CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4],
        ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1],
        ["CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1],
        ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9],
        ["CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8],
        ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L", 8.3],
        ["CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", 8.3],
        ["CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8],
        ["CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8],
      ])
        same(p, `reference ${vector}`, cvss3BaseScore(vector), score);
      const GOOD = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      for (const [label, bad] of [
        ["v2", "AV:N/AC:L/Au:N/C:P/I:P/A:P"],
        ["v4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"],
        ["version 3.2", GOOD.replace("3.1", "3.2")],
        ["lower case metric", GOOD.replace("AV:N", "av:N")],
        ["unknown value", GOOD.replace("AV:N", "AV:X")],
        [
          "a two-letter value that is a substring of the legal values",
          GOOD.replace("AV:N", "AV:NA"),
        ],
        ["a two-letter value for the complexity", GOOD.replace("AC:L", "AC:LH")],
        ["a base metric replaced by a temporal one", GOOD.replace("/A:H", "/E:F")],
        ["repeated metric", `${GOOD}/AV:N`.replace("/A:H/AV:N", "/AV:N")],
        ["missing metric", GOOD.replace("/A:H", "")],
        ["temporal metric with a lower-case value", `${GOOD}/E:f`],
        ["unknown extra metric", `${GOOD}/Q:F`],
        ["repeated temporal metric", `${GOOD}/E:F/E:H`],
        ["two-letter temporal value", `${GOOD}/E:FF`],
        ["extra text", `${GOOD} `],
        ["prototype key", `${GOOD.replace("/A:H", "")}/__proto__:H`],
        ["double colon", GOOD.replace("AV:N", "AV::N")],
        ["empty", ""],
        ["huge", `${GOOD}${"/A:H".repeat(100000)}`],
        ["number", 9.8],
        ["null", null],
        ["object", {}],
        ["array", [GOOD]],
      ])
        ok(p, cvss3BaseScore(bad) === null, `a ${label} vector was scored: ${cvss3BaseScore(bad)}`);
      same(p, "a temporal metric is ignored", cvss3BaseScore(`${GOOD}/E:F/RL:O/RC:C`), 9.8);
      same(p, "version of v4", parseCvssVersion("CVSS:4.0/AV:N"), "4.0");
      same(p, "version of v2", parseCvssVersion("AV:N/AC:L/Au:N/C:P/I:P/A:P"), "2.0");
      same(p, "version of garbage", parseCvssVersion("x"), null);

      const V3H = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"; // 9.8 critical
      const V3M = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"; // medium
      const V3L = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"; // low
      const V3I = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"; // 0.0
      const V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
      const sev = (entries) => {
        const r = normalizeOsvSeverity(entries);
        return [r.severity, r.assumed, r.raw, r.scale];
      };
      same(p, "label HIGH", sev([{ label: "HIGH" }]), ["high", false, "HIGH", "osv"]);
      same(p, "label MODERATE", sev([{ label: "moderate" }]), ["medium", false, "MODERATE", "osv"]);
      same(p, "label CRITICAL", sev([{ label: "CRITICAL" }]), [
        "critical",
        false,
        "CRITICAL",
        "osv",
      ]);
      same(p, "label LOW", sev([{ label: "LOW" }]), ["low", false, "LOW", "osv"]);
      same(p, "label beats a vector", sev([{ label: "LOW", vectors: [V3H] }]), [
        "low",
        false,
        "LOW",
        "osv",
      ]);
      same(p, "vector critical", sev([{ vectors: [V3H] }]), ["critical", false, V3H, "cvss"]);
      same(p, "vector medium", sev([{ vectors: [V3M] }])[0], "medium");
      same(p, "vector low", sev([{ vectors: [V3L] }])[0], "low");
      same(p, "vector zero is info", sev([{ vectors: [V3I] }]), ["info", false, V3I, "cvss"]);
      same(
        p,
        "the highest of the group wins",
        sev([{ label: "LOW" }, { vectors: [V3H] }, { label: "MODERATE" }])[0],
        "critical",
      );
      same(
        p,
        "the highest vector of one entry",
        sev([{ vectors: [V3L, V3H, V3M] }])[0],
        "critical",
      );
      for (const [label, entries] of [
        ["no entries", []],
        ["a Go advisory (nothing)", [{}]],
        ["v4 only", [{ vectors: [V4] }]],
        ["v2 only", [{ vectors: ["AV:N/AC:L/Au:N/C:P/I:P/A:P"] }]],
        ["an unknown label", [{ label: "SEVERE" }]],
        ["a malformed vector", [{ vectors: ["CVSS:3.1/AV:N"] }]],
        ["not an array", "x"],
        ["null", null],
        ["hostile entries", [null, 5, "x", { label: {}, vectors: [5, null, {}] }]],
      ])
        same(p, `unmapped: ${label}`, sev(entries), ["medium", true, "", "osv"]);
      same(p, "an unmapped entry next to a mapped one", sev([{}, { label: "HIGH" }]), [
        "high",
        false,
        "HIGH",
        "osv",
      ]);
      const polluted = normalizeOsvSeverity([{ vectors: ["__proto__", "constructor", V3H] }]);
      same(p, "scores", polluted.scores, { [V3H]: 9.8 });
      ok(p, {}.polluted === undefined && {}.__proto__ === Object.prototype, "prototype polluted");
      const lows = Array.from({ length: 40 }, () => ({
        vectors: [V3L, V3L, V3L, V3L, V3L, V3L, V3H],
      }));
      same(p, "only the first six vectors of an entry are read", sev(lows)[0], "low");
      same(
        p,
        "only the first 40 entries are read",
        sev([...lows, { label: "CRITICAL" }])[0],
        "low",
      );
      same(
        p,
        "the 40th entry is read",
        sev([...lows.slice(0, 39), { label: "CRITICAL" }])[0],
        "critical",
      );
      for (const [score, want] of [
        [9, "critical"],
        [8.9, "high"],
        [7, "high"],
        [6.9, "medium"],
        [4, "medium"],
        [3.9, "low"],
        [0.1, "low"],
        [0, "info"],
      ])
        same(p, `band ${score}`, severityFromCvssScore(score).severity, want);

      // provenance: the cvss entries
      const base = {
        toolId: "osv-scanner",
        toolVersion: "2.7.1",
        imageDigestShort: "sha256:c3c3c3c3",
        severityRaw: "HIGH",
        severityScale: "osv",
        rawRef: { toolRunId: "00000000-0000-4000-8000-0000000000a2", ordinal: 0 },
      };
      const entry = (cvss) =>
        provenanceEntrySchema.safeParse({ ...base, ...(cvss ? { cvss } : {}) });
      ok(p, entry().success, "control: an entry without cvss");
      ok(
        p,
        entry([{ version: "3.1", vector: V3H, score: 9.8 }]).success,
        "a v3.1 entry was refused",
      );
      ok(
        p,
        entry([
          { version: "4.0", vector: V4 },
          { version: "3.1", vector: V3H },
        ]).success,
        "two entries were refused",
      );
      const bad = (label, cvss) => ok(p, !entry(cvss).success, `${label} was accepted`);
      bad(
        "three entries",
        Array.from({ length: 3 }, () => ({ version: "3.1", vector: V3H })),
      );
      bad("version 2.0", [{ version: "2.0", vector: V3H }]);
      bad("an unknown key", [{ version: "3.1", vector: V3H, source: "x" }]);
      bad("a score of 11", [{ version: "3.1", vector: V3H, score: 11 }]);
      bad("a control character", [{ version: "3.1", vector: `${V3H}\u0001` }]);
      bad("a vector of 201 characters", [{ version: "3.1", vector: "C".repeat(201) }]);
      bad("an entry over 600 bytes", [
        { version: "3.1", vector: "V".repeat(200), score: 9.8 },
        { version: "4.0", vector: "W".repeat(200), score: 9.8 },
      ]);
      return p;
    },
  },
  {
    id: "ENG-S06i",
    name: "advisory alias resolution across the two SCA tools (SPEC scan-engines 5.6.2, SE-11, SE-12, part G; union-find over (component, manifest, advisory)): ids are normalized (a lower-case cve and an upper-case GHSA body meet the canonical form) and two tools meet through ANY shared alias, transitively and through a cycle (A names B, B names A), the canonical id is the CVE, then GHSA, then the ecosystem id, the guard still never puts two records of one tool into one finding, hostile aliases (empty, control characters, a prototype name, 200 characters, 41 aliases, a non-string) never merge anything or throw, look-alike (Cyrillic) ids never merge with the ASCII id, another version, ecosystem or purl never merges, and the same component and advisory in TWO lockfiles are two occurrences: each tool's record of one lockfile pairs with the other tool's record of the SAME lockfile (before 2026-11-21 the pairing was arbitrary and left one record of each tool alone), in any input order",
    async run() {
      const p = [];
      const rec = (over) => ({ purl: LODASH, severity: "HIGH", ...over });
      // normalization and the shared alias
      const a = merge([
        ...cands(TRIVY, [rec({ id: "cve-2021-23337", aliases: ["ghsa-35JH-R3H4-6JHM"] })]),
        ...cands(OSV, [rec({ id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"] })]),
      ]);
      ok(
        p,
        a.length === 1 && a[0].provenance.length === 2,
        `normalized ids did not meet: ${a.length}`,
      );
      same(p, "canonical id", a[0]?.rule.id, "CVE-2021-23337");
      same(
        p,
        "advisories",
        a[0]?.advisories.map((x) => x.id),
        ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"],
      );
      same(p, "dedupKey", a[0]?.dedupKey, `sca|${LODASH}|CVE-2021-23337`);
      // a cycle: A names B, B names A, plus an ecosystem id on one side only
      const cyc = merge([
        ...cands(TRIVY, [rec({ id: "CVE-2020-1", aliases: ["GHSA-aaaa-bbbb-cccc"] })]),
        ...cands(OSV, [rec({ id: "GHSA-aaaa-bbbb-cccc", aliases: ["CVE-2020-1", "GO-2020-1"] })]),
      ]);
      ok(p, cyc.length === 1, `a cycle gave ${cyc.length} findings`);
      same(
        p,
        "cycle advisories",
        cyc[0]?.advisories.map((x) => x.id),
        ["CVE-2020-1", "GHSA-aaaa-bbbb-cccc", "GO-2020-1"],
      );
      // only an ecosystem id and a GHSA: GHSA beats GO; no CVE
      const eco = merge([
        ...cands(TRIVY, [rec({ id: "GO-2020-9", aliases: ["GHSA-1111-2222-3333"] })]),
        ...cands(OSV, [rec({ id: "GHSA-1111-2222-3333", aliases: ["GO-2020-9"] })]),
      ]);
      same(p, "GHSA before an ecosystem id", eco[0]?.rule.id, "GHSA-1111-2222-3333");
      // never two records of one tool in one finding, also through a chain
      const chain = merge([
        ...cands(TRIVY, [
          rec({ id: "CVE-2020-1", aliases: ["GHSA-aaaa-aaaa-aaaa"] }),
          rec({ id: "CVE-2020-2", aliases: ["GHSA-bbbb-bbbb-bbbb"] }),
        ]),
        ...cands(OSV, [
          rec({
            id: "GHSA-aaaa-aaaa-aaaa",
            aliases: ["CVE-2020-1", "CVE-2020-2", "GHSA-bbbb-bbbb-bbbb"],
          }),
        ]),
      ]);
      ok(p, chain.length === 2, `the guard gave ${chain.length} findings`);
      ok(
        p,
        chain.every((f) => new Set(f.provenance.map((x) => x.toolId)).size === f.provenance.length),
        "a finding holds one tool twice",
      );
      // hostile aliases
      const hostileIds = [
        "",
        " ",
        "__proto__",
        "constructor",
        `GHSA-${"a".repeat(200)}`,
        "CVE-2020-1\u0007",
        "x y",
        "-",
        "CVE",
      ];
      const solo = (id) =>
        merge([
          ...cands(TRIVY, [rec({ id: "CVE-2020-5", aliases: [] })]),
          // a record the schema refuses is dropped, never merged: take whatever candidates survive
          ...runToolParse(
            OSV,
            out([rec({ id: "GHSA-5555-5555-5555", aliases: [id] })]),
            ctxFor(TASK_A),
          ).candidates,
        ]);
      for (const id of hostileIds) {
        let result;
        try {
          result = solo(id);
        } catch (error) {
          p.push(`hostile alias ${JSON.stringify(id).slice(0, 30)} threw ${error?.name}`);
          continue;
        }
        ok(
          p,
          result.every((f) => f.provenance.length === 1),
          `hostile alias ${JSON.stringify(id).slice(0, 30)} merged two findings`,
        );
      }
      // 41 aliases: the record schema refuses it (dropped and counted), never merges
      const tooMany = runToolParse(
        OSV,
        out([
          rec({
            id: "GHSA-5555-5555-5555",
            aliases: Array.from({ length: 41 }, (_, i) => `CVE-2020-${i}`),
          }),
        ]),
        ctxFor(TASK_A),
      );
      same(p, "41 aliases", [tooMany.status, tooMany.recordsDropped], ["failed", 1]);
      const cyr = merge([
        ...cands(TRIVY, [rec({ id: "CVE-2021-23337" })]),
        ...cands(OSV, [rec({ id: "GHSA-35jh-r3h4-6jhm", aliases: ["СVE-2021-23337"] })]),
      ]);
      ok(p, cyr.length === 2, "a Cyrillic look-alike id merged with the ASCII id");
      // other component
      for (const [label, other] of [
        ["another version", "pkg:npm/lodash@4.17.21"],
        ["another ecosystem", "pkg:pypi/lodash@4.17.20"],
        ["another name", "pkg:npm/lodasx@4.17.20"],
      ]) {
        const r = merge([
          ...cands(TRIVY, [rec({ id: "CVE-2021-23337" })]),
          ...cands(OSV, [rec({ id: "CVE-2021-23337", purl: other })]),
        ]);
        ok(p, r.length === 2, `${label} merged`);
      }
      // two lockfiles
      const files = ["web/package-lock.json", "package-lock.json"];
      const two = (order) =>
        merge(
          order([
            ...cands(
              TRIVY,
              files.map((path) => rec({ id: "CVE-2021-23337", path })),
            ),
            ...cands(
              OSV,
              files.map((path) =>
                rec({ id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], path }),
              ),
            ),
          ]),
        );
      const forward = two((x) => x);
      same(
        p,
        "two lockfiles pair per lockfile",
        shape(forward),
        files
          .map((f) => [LODASH, f, "trivy+osv-scanner", "CVE-2021-23337"])
          .sort((x, y) => JSON.stringify(x).localeCompare(JSON.stringify(y))),
      );
      const reversed = two((x) => [...x].reverse());
      same(p, "input order", shape(reversed), shape(forward));
      // a record with no path never pairs with a located one
      const unlocated = merge([
        ...cands(TRIVY, [rec({ id: "CVE-2021-23337", path: "package-lock.json" })]),
        ...cands(OSV, [rec({ id: "CVE-2021-23337", path: "other/yarn.lock" })]),
      ]);
      ok(p, unlocated.length === 2, "records of two different lockfiles merged");
      ok(
        p,
        forward.every((f) => findingSchema.safeParse(f).success),
        "a merged finding is not valid",
      );
      return p;
    },
  },
  {
    id: "ENG-S11d",
    name: "SCA exit classification and the database reasons of the roll-up (SPEC scan-engines 5.3, 5.4, D-22, part G; the stderr texts are the REAL ones of Trivy 0.76.2 and OSV-Scanner 2.7.1 captured on 2026-11-21): a Trivy exit 1 with `DB error:` (an empty cache, a corrupt file) and an OSV-Scanner exit 127 with `could not load db for <ecosystem> ecosystem` or `Error during extraction ... osvlocal` are `db_unavailable` (transient) in the SCA role only, a missing platform configuration is `config_invalid`, an unknown flag, any other exit and the accepted OSV exit codes 0, 1 and 128 are decided by the table (accepted is never classified), 137 is `out_of_memory`; a hostile or oversized stderr never throws and only the first 16 KiB are read; two tools without a snapshot make the task failed with the transient class, one makes it degraded and incomplete, every stale tier is a partial tool, an incomplete result and never resolution eligible, and `db_stale` on any other status is refused",
    async run() {
      const p = [];
      const TRIVY_EMPTY =
        '2026-11-21T11:02:21Z\tINFO\tLoaded\tfile_path="/rules/trivy.yaml"\n2026-11-21T11:02:21Z\tERROR\t[vulndb] The first run cannot skip downloading DB\n2026-11-21T11:02:21Z\tFATAL\tFatal error\trun error: init error: DB error: database error: --skip-db-update cannot be specified on the first run\n';
      const TRIVY_BAD =
        "2026-11-21T11:02:22Z\tFATAL\tFatal error\trun error: init error: DB error: error in vulnerability DB initialization: failed to open db: invalid database\n";
      const OSV_BAD_ZIP =
        "could not load db for Maven ecosystem: unable to fetch OSV database: could not read OSV database archive: zip: not a valid zip file\ncould not load db for npm ecosystem: unable to fetch OSV database: could not read OSV database archive: zip: not a valid zip file\n";
      const OSV_NO_DIR =
        "Scanned /src/go/go.mod file and found 3 packages\nError during extraction: (extracting as vulnmatch/osvlocal) could not create : mkdir /db/osv-scalibr: read-only file system\n";
      const OSV_CONFIG =
        "Failed to read config file: open /rules/missing.toml: no such file or directory\n";
      const cls = (toolId, exitCode, stderr, accepted, role = "sca") =>
        classifyToolExit({ exitCode, stderr, accepted, role, toolId });
      same(p, "trivy empty cache", cls("trivy", 1, TRIVY_EMPTY, [0]), "db_unavailable");
      same(p, "trivy corrupt db", cls("trivy", 1, TRIVY_BAD, [0]), "db_unavailable");
      same(
        p,
        "osv corrupt archive",
        cls("osv-scanner", 127, OSV_BAD_ZIP, [0, 1, 128]),
        "db_unavailable",
      );
      same(
        p,
        "osv missing directory",
        cls("osv-scanner", 127, OSV_NO_DIR, [0, 1, 128]),
        "db_unavailable",
      );
      same(
        p,
        "osv missing config",
        cls("osv-scanner", 127, OSV_CONFIG, [0, 1, 128]),
        "config_invalid",
      );
      same(
        p,
        "a config text in the middle of a line",
        cls("osv-scanner", 127, "x Failed to read config file", [0, 1, 128]),
        "exit_code",
      );
      same(
        p,
        "osv unknown flag",
        cls("osv-scanner", 127, "flag provided but not defined: -bogus-flag\n", [0, 1, 128]),
        "exit_code",
      );
      same(p, "osv any other exit", cls("osv-scanner", 2, "", [0, 1, 128]), "exit_code");
      for (const code of [0, 1, 128])
        same(p, `osv accepts ${code}`, cls("osv-scanner", code, OSV_BAD_ZIP, [0, 1, 128]), null);
      same(p, "128 is not accepted by default", cls("osv-scanner", 128, "", [0]), "exit_code");
      same(p, "trivy accepts 0 with any stderr", cls("trivy", 0, TRIVY_EMPTY, [0]), null);
      same(p, "trivy out of memory", cls("trivy", 137, "", [0]), "out_of_memory");
      same(
        p,
        "osv out of memory",
        cls("osv-scanner", 137, OSV_BAD_ZIP, [0, 1, 128]),
        "out_of_memory",
      );
      same(
        p,
        "the SBOM role never says db_unavailable",
        cls("trivy", 1, TRIVY_EMPTY, [0], "sbom"),
        "exit_code",
      );
      same(
        p,
        "a plain trivy error",
        cls("trivy", 1, "2026-11-21T11:02:21Z\tFATAL\tFatal error\tboom\n", [0]),
        "exit_code",
      );
      same(
        p,
        "an exit code of the other tool's database error",
        cls("trivy", 127, TRIVY_EMPTY, [0]),
        "db_unavailable",
      );
      same(p, "another tool id", cls("syft", 1, TRIVY_EMPTY, [0]), "exit_code");
      same(
        p,
        "no tool id",
        classifyToolExit({ exitCode: 1, stderr: TRIVY_EMPTY, role: "sca" }),
        "exit_code",
      );
      same(p, "a prototype tool id", cls("__proto__", 1, TRIVY_EMPTY, [0]), "exit_code");
      same(
        p,
        "DB error text outside a FATAL line",
        cls("trivy", 1, "my DB error: x\n", [0]),
        "exit_code",
      );
      const filler = "x".repeat(16 * 1024);
      same(
        p,
        "the marker after 16 KiB is not read",
        cls("trivy", 1, `${filler}${TRIVY_EMPTY}`, [0]),
        "exit_code",
      );
      same(
        p,
        "huge stderr",
        cls("osv-scanner", 127, `${"y".repeat(5_000_000)}`, [0, 1, 128]),
        "exit_code",
      );
      same(p, "a non-string stderr", cls("trivy", 1, 5, [0]), "exit_code");
      // roll-up
      const run = (tools) => rollUpTask({ tools });
      const down = { status: "unavailable", reason: "db_unavailable" };
      const both = run([
        { toolId: "trivy", ...down },
        { toolId: "osv-scanner", ...down },
      ]);
      same(
        p,
        "both without a snapshot",
        [both.taskStatus, both.reason, both.errorClass, both.matchedRow],
        ["failed", "tools_failed", "transient", 7],
      );
      const one = run([
        { toolId: "trivy", ...down },
        { toolId: "osv-scanner", status: "succeeded", reason: null },
      ]);
      same(
        p,
        "one without a snapshot",
        [
          one.taskStatus,
          one.completeness,
          one.matchedRow,
          one.resolutionEligible,
          one.toolsDegraded,
        ],
        ["succeeded", "incomplete", 6, false, 1],
      );
      const stale = run([
        { toolId: "trivy", status: "partial", reason: "db_stale" },
        { toolId: "osv-scanner", status: "partial", reason: "db_stale" },
      ]);
      same(
        p,
        "both stale",
        [
          stale.taskStatus,
          stale.completeness,
          stale.coverageState,
          stale.resolutionEligible,
          stale.toolsDegraded,
        ],
        ["succeeded", "incomplete", "partial", false, 0],
      );
      const mixed = run([
        { toolId: "trivy", status: "partial", reason: "db_stale" },
        { toolId: "osv-scanner", status: "succeeded", reason: null },
      ]);
      same(p, "one stale", [mixed.completeness, mixed.resolutionEligible], ["incomplete", false]);
      const fresh = run([
        { toolId: "trivy", status: "succeeded", reason: null },
        { toolId: "osv-scanner", status: "succeeded", reason: null },
      ]);
      same(
        p,
        "fresh",
        [fresh.completeness, fresh.resolutionEligible, fresh.matchedRow],
        ["complete", true, 5],
      );
      for (const status of [
        "succeeded",
        "failed",
        "unavailable",
        "timed_out",
        "cancelled",
        "skipped",
      ])
        ok(
          p,
          (() => {
            try {
              run([{ toolId: "trivy", status, reason: "db_stale" }]);
              return false;
            } catch (error) {
              return error instanceof TypeError;
            }
          })(),
          `db_stale on a ${status} tool was accepted`,
        );
      const mixedDown = run([
        { toolId: "trivy", status: "unavailable", reason: "db_unavailable" },
        { toolId: "osv-scanner", status: "failed", reason: "exit_code" },
      ]);
      same(
        p,
        "a permanent failure next to a missing snapshot",
        [mixedDown.taskStatus, mixedDown.errorClass],
        ["failed", "permanent"],
      );
      return p;
    },
  },
];
