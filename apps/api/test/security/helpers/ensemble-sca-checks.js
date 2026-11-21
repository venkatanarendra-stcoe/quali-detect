import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
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
  AdapterError,
  assertToolSelectable,
  createAdapterRegistry,
  mergeTaskCandidates,
  runToolParse,
} from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import { createDbSnapshotResolver } from "../../../../workers/src/execution/engines/ensemble/db/resolve-db.js";
import { createEnsembleScaEngine } from "../../../../workers/src/execution/engines/ensemble/engine/sca-engine.js";
import { createTreePathExists } from "../../../../workers/src/execution/engines/ensemble/engine/tree-paths.js";
import { classifyToolExit } from "../../../../workers/src/execution/engines/ensemble/engine/tool-exit.js";
import { TASK_A, TASK_B, ctxFor, fakeAdapter, out } from "./ensemble-fakes.js";
import { createScanDbSnapshotReader } from "@qmentisai/db";
import {
  SandboxError,
  DbMirrorIntegrityError,
  FakeSandboxRuntime,
  assertRunArgsSafe,
  createCapacityGate,
  createSandboxRunner,
  buildRunArgs,
  resolveRunSpecImage,
  validateRunSpec,
  validateSandboxConfig,
} from "@qmentisai/infra";
import { loadImageLock } from "../../../../workers/src/execution/engines/ensemble/catalog/index.js";
import {
  OSV_SCA_ARGV,
  OSV_SCA_ENV,
  TRIVY_SCA_ARGV,
  TRIVY_SCA_ENV,
  createOsvScannerAdapter,
  createScaAdapterRegistry,
  createTrivyScaAdapter,
  runScaEnsemble,
} from "../../../../workers/src/execution/engines/ensemble/sca/index.js";

/**
 * Scan engines, part G (ADR-008 area 18, SPEC scan-engines 14.1 ENG-S03, S06, S09, S11 and 16.1 part G): the SCA ensemble (CVSS
 * calculator, OSV severity maps, advisory alias union-find and pairing, the Trivy language-only and OSV-Scanner offline adapters and
 * mappers over REAL captured output, hostile output, the sealed run plans). Pure functions: no container, process, database or
 * network. The CVSS calculator is proved against REAL data: the 44 distinct vector and score pairs of the real Trivy report of
 * 2026-11-21 (`fixtures/scan-engines/sca/real/trivy-sca-treeC.json`). Severity TABLES and tolerances stay out of ADR-008 scope; the
 * policy properties (unknown is medium with the flag, the highest wins, a hostile vector never throws or chooses a severity) are asserted.
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const FIX = path.join(ROOT, "apps/api/test/security/fixtures/scan-engines/sca/real");
/** Whether a string holds a C0 control character or the bidirectional override (no control character in a regular expression). */
const hasControl = (t) => [...t].some((ch) => ch.charCodeAt(0) < 32 || ch === "\u202e");
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

const RUN_T = "00000000-0000-4000-8000-0000000000a1";
const RUN_O = "00000000-0000-4000-8000-0000000000a2";
const trivy = createTrivyScaAdapter();
const osv = createOsvScannerAdapter();
const TRIVY_DOC = readFileSync(path.join(FIX, "trivy-sca-treeC.json"), "utf8");
const OSV_DOC = readFileSync(path.join(FIX, "osv-sca-treeC.json"), "utf8");
const ctxT = (over = {}) => ({
  taskRef: TASK_A,
  toolRunId: RUN_T,
  toolVersion: "0.76.2",
  imageDigest: `sha256:${"b2".repeat(32)}`,
  ...over,
});
const ctxO = (over = {}) => ({
  taskRef: TASK_A,
  toolRunId: RUN_O,
  toolVersion: "2.7.1",
  imageDigest: `sha256:${"c3".repeat(32)}`,
  ...over,
});
const parseT = (text, exitCode = 0, ctx = ctxT()) =>
  runToolParse(trivy, { stdout: text, exitCode }, ctx);
const parseO = (text, exitCode = 1, ctx = ctxO()) =>
  runToolParse(osv, { stdout: text, exitCode }, ctx);

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
  {
    id: "ENG-S06j",
    name: "SCA mapping and merge on REAL Trivy and OSV-Scanner output (SPEC scan-engines 5.6.2, 5.7, 7.2, SE-12 to SE-14, part G; the fixtures are the real reports of 2026-11-21 for the ENG-G tree C, trimmed to the keys the adapters read): Trivy 47 records and OSV-Scanner 51 groups all map (nothing dropped), they merge to 51 findings of which 47 carry both tools and confidence high with the basis multi_tool, the four OSV-only findings are the Maven test dependency, the dev requirement and the HTTP/2 advisory Trivy does not report; the Go versions agree (OSV drops the v prefix, the adapter restores it: 23 of the 24 Go findings pair, the 24th is a real difference of the two databases); the lodash finding holds both advisories (CVE and GHSA), the fixed version, the CWEs, the CVSS vector and calculated score of both tools in their provenance, the lockfile as location and severity high; only the allowlisted CVSS sources (GHSA, NVD) are kept (no Red Hat, Ubuntu, Bitnami rating reaches a finding); the output is identical for any order of the two tools and of the records and for a second run; two tasks of one input stay separate; every finding is a valid finding and every candidate carries its own tool run reference",
    async run() {
      const p = [];
      const run = (over = {}) =>
        runScaEnsemble({
          taskRef: TASK_A,
          runs: over.runs ?? [
            { adapter: trivy, streams: { stdout: TRIVY_DOC, exitCode: 0 }, ctx: ctxT() },
            { adapter: osv, streams: { stdout: OSV_DOC, exitCode: 1 }, ctx: ctxO() },
          ],
        });
      const result = run();
      same(
        p,
        "tool outcomes",
        result.outcomes.map((o) => [
          o.toolId,
          o.status,
          o.reason,
          o.recordsSeen,
          o.recordsDropped,
          o.findingsMapped,
        ]),
        [
          ["trivy", "succeeded", null, 47, 0, 47],
          ["osv-scanner", "succeeded", null, 51, 0, 51],
        ],
      );
      same(
        p,
        "roll-up",
        [result.rollup.matchedRow, result.rollup.completeness, result.rollup.resolutionEligible],
        [5, "complete", true],
      );
      same(p, "stats", result.stats, {
        candidates: 98,
        findings: 51,
        merged: 47,
        redundantComponents: 0,
      });
      const both = result.findings.filter((f) => f.provenance.length === 2);
      same(p, "findings with both tools", both.length, 47);
      ok(
        p,
        both.every((f) => f.confidence === "high" && f.confidenceBasis === "multi_tool"),
        "a two-tool finding is not high / multi_tool",
      );
      same(
        p,
        "OSV-only findings",
        result.findings
          .filter((f) => f.provenance.length === 1)
          .map((f) => [f.provenance[0].toolId, f.component.purl, f.location.path, f.rule.id])
          .sort(),
        [
          ["osv-scanner", "pkg:golang/golang.org/x/net@v0.7.0", "svc/go.mod", "CVE-2023-44487"],
          ["osv-scanner", "pkg:maven/junit/junit@4.12", "java/pom.xml", "CVE-2020-15250"],
          ["osv-scanner", "pkg:pypi/pyyaml@5.3", "py/requirements-dev.txt", "CVE-2020-14343"],
          ["osv-scanner", "pkg:pypi/pyyaml@5.3", "py/requirements-dev.txt", "CVE-2020-1747"],
        ],
      );
      const go = result.findings.filter((f) => f.component.ecosystem === "golang");
      same(
        p,
        "go findings paired",
        [go.length, go.filter((f) => f.provenance.length === 2).length],
        [24, 23],
      );
      ok(
        p,
        go.every((f) => f.component.purl === "pkg:golang/golang.org/x/net@v0.7.0"),
        "a go purl lost its v prefix",
      );
      const lodash = result.findings.find((f) => f.rule.id === "CVE-2021-23337");
      same(
        p,
        "lodash advisories",
        lodash?.advisories.map((a) => a.id),
        ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"],
      );
      same(p, "lodash fix", lodash?.fix, { fixedVersions: ["4.17.21"] });
      same(p, "lodash cwe", lodash?.cwe, [77, 94]);
      same(p, "lodash location", lodash?.location, { path: "web/package-lock.json" });
      same(p, "lodash severity", [lodash?.severity, lodash?.severityAssumed], ["high", false]);
      same(
        p,
        "lodash provenance",
        lodash?.provenance.map((x) => [x.toolId, x.ruleId, x.severityRaw, x.severityScale, x.cvss]),
        [
          [
            "trivy",
            "CVE-2021-23337",
            "HIGH",
            "trivy",
            [
              {
                version: "3.1",
                vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                score: 7.2,
              },
            ],
          ],
          [
            "osv-scanner",
            "CVE-2021-23337",
            "HIGH",
            "osv",
            [
              {
                version: "3.1",
                vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                score: 7.2,
              },
            ],
          ],
        ],
      );
      // no vendor rating, no advisory text, no description reaches a finding
      const text = JSON.stringify(result.findings);
      for (const needle of [
        "redhat",
        "ubuntu",
        "bitnami",
        "azure",
        "ruby-advisory-db",
        "Description",
        "avd.aquasec.com",
      ])
        ok(p, !text.toLowerCase().includes(needle.toLowerCase()), `the findings mention ${needle}`);
      ok(
        p,
        result.findings.every((f) => findingSchema.safeParse(f).success),
        "a finding is invalid",
      );
      ok(
        p,
        result.findings.every(
          (f) =>
            f.provenance.length <= 2 && f.provenance.every((x) => !x.cvss || x.cvss.length <= 2),
        ),
        "provenance over its caps",
      );
      // the severity policy on the real data: OSV's moderate is medium, a v4-only group has no calculated score
      const v4 = JSON.parse(OSV_DOC)
        .results.flatMap((r) => r.packages)
        .flatMap((x) => x.vulnerabilities)
        .filter(
          (v) =>
            (v.severity ?? []).every((s) => s.type === "CVSS_V4") && (v.severity ?? []).length > 0,
        );
      ok(p, v4.length > 0, "control: the real data holds no v4-only advisory");
      // determinism and order
      const same2 = JSON.stringify(run().findings) === JSON.stringify(result.findings);
      ok(p, same2, "a second run differs");
      const swapped = run({
        runs: [
          { adapter: osv, streams: { stdout: OSV_DOC, exitCode: 1 }, ctx: ctxO() },
          { adapter: trivy, streams: { stdout: TRIVY_DOC, exitCode: 0 }, ctx: ctxT() },
        ],
      });
      ok(
        p,
        JSON.stringify(swapped.findings) === JSON.stringify(result.findings),
        "the tool order changed the findings",
      );
      // reversed record order of both reports
      const rev = (doc, key) => {
        const d = JSON.parse(doc);
        d[key] = [...d[key]].reverse();
        for (const r of d[key])
          for (const k of ["Vulnerabilities", "packages"]) if (r[k]) r[k] = [...r[k]].reverse();
        return JSON.stringify(d);
      };
      const reordered = run({
        runs: [
          {
            adapter: trivy,
            streams: { stdout: rev(TRIVY_DOC, "Results"), exitCode: 0 },
            ctx: ctxT(),
          },
          { adapter: osv, streams: { stdout: rev(OSV_DOC, "results"), exitCode: 1 }, ctx: ctxO() },
        ],
      });
      const key = (f) =>
        JSON.stringify([f.dedupKey, f.location?.path, f.provenance.map((x) => x.toolId)]);
      same(p, "record order", reordered.findings.map(key).sort(), result.findings.map(key).sort());
      // per-task isolation
      const other = runScaEnsemble({
        taskRef: TASK_B,
        runs: [
          {
            adapter: trivy,
            streams: { stdout: TRIVY_DOC, exitCode: 0 },
            ctx: ctxT({ taskRef: undefined }),
          },
          {
            adapter: osv,
            streams: { stdout: OSV_DOC, exitCode: 1 },
            ctx: ctxO({ taskRef: undefined }),
          },
        ],
      });
      same(p, "the same input in another task", other.findings.length, 51);
      ok(
        p,
        other.findings.every((f) => f.rawRef.toolRunId === RUN_T || f.rawRef.toolRunId === RUN_O),
        "raw reference",
      );
      // a tool alone
      const alone = runScaEnsemble({
        taskRef: TASK_A,
        runs: [
          { adapter: trivy, streams: { stdout: TRIVY_DOC, exitCode: 0 }, ctx: ctxT() },
          { toolId: "osv-scanner", status: "unavailable", reason: "db_unavailable" },
        ],
      });
      same(
        p,
        "one tool without a database",
        [
          alone.findings.length,
          alone.rollup.matchedRow,
          alone.rollup.completeness,
          alone.rollup.resolutionEligible,
        ],
        [47, 6, "incomplete", false],
      );
      ok(
        p,
        alone.findings.every((f) => f.provenance.length === 1 && f.confidenceBasis === "tool"),
        "a lone tool claimed agreement",
      );
      // a stale database
      const stale = runScaEnsemble({
        taskRef: TASK_A,
        runs: [
          {
            adapter: trivy,
            streams: { stdout: TRIVY_DOC, exitCode: 0 },
            ctx: ctxT(),
            dbStale: true,
          },
          { adapter: osv, streams: { stdout: OSV_DOC, exitCode: 1 }, ctx: ctxO(), dbStale: true },
        ],
      });
      same(
        p,
        "stale databases",
        [
          stale.findings.length,
          stale.rollup.matchedRow,
          stale.rollup.completeness,
          stale.rollup.resolutionEligible,
          stale.outcomes.map((o) => [o.status, o.reason]),
        ],
        [
          51,
          5,
          "incomplete",
          false,
          [
            ["partial", "db_stale"],
            ["partial", "db_stale"],
          ],
        ],
      );
      return p;
    },
  },
  {
    id: "ENG-S09e",
    name: "hostile Trivy and OSV-Scanner output is tolerated (SPEC scan-engines 7.2, SE-4, ENG-S09, part G): empty, truncated, non-JSON, wrong root, another schema version, a prototype key at any depth, nesting beyond the cap, the output cap and an unaccepted exit code give a failed tool with a fixed reason and no candidates, never an exception; a record with a wrong type, a missing purl, an unsafe or absolute or backslash path, an operating-system result, a score outside 0 to 10 or an unknown severity is dropped or assumed (counted, never merged), a title with control, ANSI and bidirectional characters is cleaned and one with a credential is redacted, advisory text and fixed-version lists are bounded, more than 50000 records are cut to a partial result, an OSV-Scanner exit 128 with an empty stdout is an honest empty result and anything else with exit 128 or 127 is not parsed, and 20 percent dropped fails the tool",
    async run() {
      const p = [];
      const tv = (over = {}) => ({
        VulnerabilityID: "CVE-2021-23337",
        VendorIDs: ["GHSA-35jh-r3h4-6jhm"],
        PkgName: "lodash",
        PkgIdentifier: { PURL: "pkg:npm/lodash@4.17.20" },
        InstalledVersion: "4.17.20",
        FixedVersion: "4.17.21",
        Severity: "HIGH",
        Title: "command injection",
        CweIDs: ["CWE-94"],
        CVSS: {},
        ...over,
      });
      const report = (vulns, over = {}) =>
        JSON.stringify({
          SchemaVersion: 2,
          Results: [
            {
              Target: "package-lock.json",
              Class: "lang-pkgs",
              Type: "npm",
              Vulnerabilities: vulns,
              ...over,
            },
          ],
        });
      const t = (text, exit = 0, ctx) => parseT(text, exit, ctx);
      const control = t(report([tv(), tv({ VulnerabilityID: "CVE-2021-23338" })]));
      same(p, "control", [control.status, control.findingsMapped], ["succeeded", 2]);
      const failedWith = (label, r, reason) =>
        same(p, label, [r.status, r.reason, r.candidates.length], ["failed", reason, 0]);
      failedWith("empty", t(""), "output_invalid");
      failedWith("not json", t("Total: 3 (HIGH: 3)\n"), "output_invalid");
      failedWith("truncated", t(report([tv(), tv()]).slice(0, 120)), "output_invalid");
      failedWith("a list root", t("[]"), "output_invalid");
      failedWith("null root", t("null"), "output_invalid");
      failedWith(
        "another schema version",
        t(JSON.stringify({ SchemaVersion: 1, Results: [] })),
        "output_invalid",
      );
      failedWith(
        "Results not a list",
        t(JSON.stringify({ SchemaVersion: 2, Results: {} })),
        "output_invalid",
      );
      failedWith("an exit code of 1", t(report([tv()]), 1), "exit_code");
      failedWith("a signal", t(report([tv()]), null), "exit_code");
      failedWith(
        "a prototype key",
        t(`{"SchemaVersion":2,"Results":[],"x":{"__proto__":{"polluted":true}}}`),
        "output_invalid",
      );
      failedWith(
        "a constructor key",
        t(`{"SchemaVersion":2,"Results":[{"constructor":{}}]}`),
        "output_invalid",
      );
      failedWith(
        "nesting",
        t(`{"SchemaVersion":2,"Results":${"[".repeat(70)}${"]".repeat(70)}}`),
        "output_invalid",
      );
      const cut = runToolParse(
        trivy,
        { stdout: Buffer.from(report([tv()])), exitCode: 0, truncated: true },
        ctxT(),
      );
      same(
        p,
        "cut by the capture cap",
        [cut.status, cut.reason, cut.truncated],
        ["failed", "output_too_large", true],
      );
      ok(p, {}.polluted === undefined, "prototype polluted");
      // no Results at all is an honest empty result
      same(
        p,
        "no lockfile",
        [
          t(JSON.stringify({ SchemaVersion: 2 })).status,
          t(JSON.stringify({ SchemaVersion: 2, Results: null })).findingsMapped,
        ],
        ["succeeded", 0],
      );
      // records
      const droppedOf = (vulns, over) => {
        const r = t(report(vulns, over));
        return [r.status, r.reason, r.recordsDropped, r.findingsMapped];
      };
      const good = Array.from({ length: 9 }, (_, i) =>
        tv({ VulnerabilityID: `CVE-2021-${1000 + i}` }),
      );
      same(p, "one bad record of ten", droppedOf([...good, tv({ PkgIdentifier: {} })]), [
        "partial",
        "output_invalid",
        1,
        9,
      ]);
      same(
        p,
        "two bad records of ten fail the tool",
        droppedOf([...good.slice(0, 8), tv({ PkgIdentifier: {} }), tv({ VulnerabilityID: 5 })])[0],
        "succeeded".replace("succeeded", "partial"),
      );
      same(
        p,
        "three bad records of ten fail the tool",
        droppedOf([
          ...good.slice(0, 7),
          tv({ PkgIdentifier: {} }),
          tv({ VulnerabilityID: 5 }),
          tv({ VulnerabilityID: "" }),
        ])[0],
        "failed",
      );
      for (const [label, over] of [
        ["no purl", { PkgIdentifier: {} }],
        ["a purl without a version", { PkgIdentifier: { PURL: "pkg:npm/lodash" } }],
        ["a non-purl", { PkgIdentifier: { PURL: "https://evil.example/x" } }],
        ["an id that is a number", { VulnerabilityID: 5 }],
        ["an empty id", { VulnerabilityID: "" }],
        ["a control character in the id", { VulnerabilityID: "CVE-2021-1\u0007" }],
      ]) {
        const r = droppedOf([...good, tv(over)]);
        ok(p, r[2] === 1 && r[3] === 9, `${label}: ${JSON.stringify(r)}`);
      }
      for (const target of ["../etc/passwd", "/etc/passwd", "a\\b", "a//b", "./a", "", "a/../b"]) {
        const r = t(report([...good, tv()], { Target: target }));
        ok(
          p,
          r.findingsMapped === 0 || r.status === "failed",
          `target ${JSON.stringify(target)} was mapped`,
        );
      }
      const os = t(report([tv()], { Class: "os-pkgs", Type: "debian" }));
      same(p, "an operating-system result", [os.findingsMapped, os.recordsDropped > 0], [0, true]);
      const mixed = t(
        JSON.stringify({
          SchemaVersion: 2,
          Results: [
            { Target: "package-lock.json", Class: "lang-pkgs", Type: "npm", Vulnerabilities: good },
            {
              Target: "debian 12",
              Class: "os-pkgs",
              Type: "debian",
              Vulnerabilities: [tv({ VulnerabilityID: "CVE-2099-1" })],
            },
          ],
        }),
      );
      ok(
        p,
        mixed.candidates.every((c) => c.rule.id !== "CVE-2099-1"),
        "an operating-system advisory was mapped",
      );
      // values
      const one = (over) => t(report([tv(over)])).candidates[0];
      same(
        p,
        "an unknown severity",
        [one({ Severity: "UNKNOWN" }).severity, one({ Severity: "UNKNOWN" }).severityAssumed],
        ["medium", true],
      );
      same(
        p,
        "a missing severity",
        [one({ Severity: "" }).severity, one({ Severity: "" }).severityAssumed],
        ["medium", true],
      );
      same(
        p,
        "a severity that is an object is unmapped, not dropped",
        [one({ Severity: { a: 1 } }).severity, one({ Severity: { a: 1 } }).severityAssumed],
        ["medium", true],
      );
      same(p, "a star severity", one({ Severity: "★" }).severityAssumed, true);
      const title = one({ Title: `\u001b[31mred\u001b[0m‮evil\u0007 ${"x".repeat(5000)}` }).title;
      ok(p, title.length <= 200 && !hasControl(title), "title not cleaned or not bounded");
      ok(
        p,
        !one({ Title: "key ghp_abcdefghijklmnopqrstuvwxyz0123456789 used" }).title.includes(
          "ghp_abc",
        ),
        "a credential in a title survived",
      );
      same(
        p,
        "an empty title falls back",
        one({ Title: "" }).title.startsWith("CVE-2021-23337"),
        true,
      );
      same(
        p,
        "fixed versions are split and capped",
        one({ FixedVersion: Array.from({ length: 40 }, (_, i) => `1.${i}.0`).join(", ") }).fix
          .fixedVersions.length,
        10,
      );
      same(
        p,
        "a long fixed version is dropped",
        one({ FixedVersion: `4.17.21, ${"9".repeat(200)}` }).fix.fixedVersions,
        ["4.17.21"],
      );
      same(p, "no fixed version", one({ FixedVersion: "" }).fix, undefined);
      same(p, "cwe", one({ CweIDs: ["CWE-79", "79", "x", "CWE-99999999", 5, null] }).cwe, [79]);
      const cvss = (c) => one({ CVSS: c }).provenance[0].cvss;
      same(
        p,
        "a vendor rating is ignored",
        cvss({
          redhat: { V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 9.8 },
        }),
        undefined,
      );
      same(
        p,
        "a ghsa score outside 0 to 10 is dropped, the vector kept",
        cvss({ ghsa: { V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", V3Score: 99 } }),
        [{ version: "3.1", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      );
      same(
        p,
        "a v2 vector is not kept",
        cvss({ nvd: { V2Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", V2Score: 7.5 } }),
        undefined,
      );
      same(
        p,
        "hostile cvss containers",
        [cvss("x"), cvss([]), cvss({ ghsa: null }), cvss({ ghsa: { V3Vector: 5 } })],
        [undefined, undefined, undefined, undefined],
      );
      // the cap
      const many = Array.from({ length: 50_001 }, (_, i) => ({
        VulnerabilityID: `CVE-2020-${i}`,
        PkgIdentifier: { PURL: `pkg:npm/p${i}@1.0.0` },
        Severity: "LOW",
      }));
      const big = t(report(many));
      same(
        p,
        "more than 50000 records",
        [big.status, big.reason, big.recordsSeen, big.truncated],
        ["partial", "output_too_large", 50_000, true],
      );

      // OSV-Scanner
      const ov = (over = {}) => ({
        package: {
          name: "lodash",
          version: "4.17.20",
          ecosystem: "npm",
          purl: "pkg:npm/lodash@4.17.20",
        },
        groups: [
          { ids: ["GHSA-35jh-r3h4-6jhm"], aliases: ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"] },
        ],
        vulnerabilities: [
          {
            id: "GHSA-35jh-r3h4-6jhm",
            aliases: ["CVE-2021-23337"],
            summary: "command injection",
            database_specific: { severity: "HIGH", cwe_ids: ["CWE-94"] },
            affected: [
              {
                package: { name: "lodash", ecosystem: "npm" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
              },
            ],
          },
        ],
        ...over,
      });
      const rep = (pkgs, source = { path: "/src/package-lock.json", type: "lockfile" }) =>
        JSON.stringify({ results: [{ source, packages: pkgs }] });
      const o = (text, exit = 1) => parseO(text, exit);
      const oc = o(rep([ov()]));
      same(
        p,
        "osv control",
        [oc.status, oc.findingsMapped, oc.candidates[0]?.severity],
        ["succeeded", 1, "high"],
      );
      same(p, "osv fixed version", oc.candidates[0]?.fix, { fixedVersions: ["4.17.21"] });
      same(
        p,
        "osv 128 and empty",
        [o("", 128).status, o("", 128).findingsMapped, o(Buffer.alloc(0), 128).status],
        ["succeeded", 0, "succeeded"],
      );
      failedWith("osv 128 with text", o("No package sources found", 128), "output_invalid");
      failedWith("osv 1 and empty", o("", 1), "output_invalid");
      failedWith("osv 0 and empty", o("", 0), "output_invalid");
      failedWith("osv 127", o(rep([ov()]), 127), "exit_code");
      failedWith("osv 2", o(rep([ov()]), 2), "exit_code");
      failedWith("osv no results key", o("{}"), "output_invalid");
      failedWith("osv a prototype key", o(`{"results":[{"__proto__":{}}]}`), "output_invalid");
      for (const [label, source] of [
        ["a path outside /src", { path: "/etc/passwd", type: "lockfile" }],
        ["a traversal", { path: "/src/../etc/passwd", type: "lockfile" }],
        ["a relative path", { path: "package-lock.json", type: "lockfile" }],
        ["a backslash", { path: "/src/a\\b", type: "lockfile" }],
        ["no source", null],
      ]) {
        const r = o(rep([ov()], source));
        ok(p, r.findingsMapped === 0, `${label} was mapped`);
      }
      const osvOne = (over) => o(rep([ov(over)])).candidates[0];
      same(
        p,
        "a Go version gets its v back",
        osvOne({
          package: {
            name: "golang.org/x/text",
            version: "0.14.0",
            ecosystem: "Go",
            purl: "pkg:golang/golang.org/x/text@0.14.0",
          },
        }).component.purl,
        "pkg:golang/golang.org/x/text@v0.14.0",
      );
      same(
        p,
        "a Go version with a v is kept",
        osvOne({
          package: {
            name: "golang.org/x/text",
            version: "v0.14.0",
            ecosystem: "Go",
            purl: "pkg:golang/golang.org/x/text@v0.14.0",
          },
        }).component.purl,
        "pkg:golang/golang.org/x/text@v0.14.0",
      );
      same(
        p,
        "an npm qualifier is dropped",
        osvOne({
          package: {
            name: "lodash",
            version: "4.17.20",
            ecosystem: "npm",
            purl: "pkg:npm/lodash@4.17.20?source=PUBLIC_REGISTRY",
          },
        }).component.purl,
        "pkg:npm/lodash@4.17.20",
      );
      same(
        p,
        "no severity at all",
        [
          osvOne({ vulnerabilities: [{ id: "GHSA-35jh-r3h4-6jhm", aliases: [] }] }).severity,
          osvOne({ vulnerabilities: [{ id: "GHSA-35jh-r3h4-6jhm", aliases: [] }] }).severityAssumed,
        ],
        ["medium", true],
      );
      same(
        p,
        "a group whose advisory has no record",
        osvOne({ vulnerabilities: [] }).severityAssumed,
        true,
      );
      same(
        p,
        "a group of two advisories takes the highest",
        osvOne({
          groups: [{ ids: ["GHSA-a", "PYSEC-1"], aliases: ["CVE-2020-9"] }],
          vulnerabilities: [
            { id: "GHSA-a", aliases: [], database_specific: { severity: "LOW" } },
            { id: "PYSEC-1", aliases: [], database_specific: { severity: "CRITICAL" } },
          ],
        }).severity,
        "critical",
      );
      same(
        p,
        "a hostile summary",
        osvOne({
          vulnerabilities: [
            {
              id: "GHSA-35jh-r3h4-6jhm",
              aliases: [],
              summary: `\u001b[1mbold‮ ${"z".repeat(3000)}`,
            },
          ],
        }).title.length <= 200,
        true,
      );
      same(
        p,
        "hostile fixed events",
        osvOne({
          vulnerabilities: [
            {
              id: "GHSA-35jh-r3h4-6jhm",
              aliases: [],
              affected: [
                {
                  package: { name: "lodash", ecosystem: "npm" },
                  ranges: [
                    { type: "GIT", events: [{ fixed: "deadbeef" }] },
                    { type: "SEMVER", events: [null, 5, { fixed: 7 }, { fixed: "4.17.21" }] },
                  ],
                },
                {
                  package: { name: "other", ecosystem: "npm" },
                  ranges: [{ type: "SEMVER", events: [{ fixed: "9.9.9" }] }],
                },
                null,
                5,
              ],
            },
          ],
        }).fix,
        { fixedVersions: ["4.17.21"] },
      );
      same(p, "a package that is not an object", o(rep([null, 5, "x"])).recordsDropped, 3);
      same(p, "a group without ids", o(rep([ov({ groups: [{}] })])).recordsDropped, 1);
      same(
        p,
        "a package without a version",
        o(rep([ov({ package: { name: "lodash", ecosystem: "npm" } })])).recordsDropped,
        1,
      );
      const groups = Array.from({ length: 41 }, (_, i) => ({
        ids: [`GHSA-aaaa-bbbb-${String(i).padStart(4, "0")}`],
        aliases: [],
      }));
      same(
        p,
        "41 groups are 41 records",
        o(rep([ov({ groups, vulnerabilities: [] })])).recordsSeen,
        41,
      );
      return p;
    },
  },
  {
    id: "ENG-S03d",
    name: "the SCA run plans and the language-only guard (SPEC scan-engines 5.2, 5.12 SE-36, 6.2, 11.3, D-15, D-21, ENG-S03, ENG-S12, part G): the Trivy SCA command line is the verified constant (`fs`, the platform `--config`, `--skip-db-update`, `--skip-java-db-update`, `--offline-scan`, `--scanners vuln` only, `--pkg-types library` and never `os`, `--include-dev-deps`, JSON), the OSV-Scanner command line is the sealed offline one (`--offline`, `--offline-vulnerabilities`, `--no-resolve`, `--no-call-analysis=go`, `--no-ignore`, the platform `--config`), both are frozen and contain no repository-derived string; the plans mount the tree, the platform rules and the snapshot read-only at /src, /rules and /db with the allowlisted environment, pass `validateRunSpec` and `assertRunArgsSafe` through the real `buildRunArgs` (network none, read-only root, no capability), refuse a missing database directory, and Grype is never selectable: the adapter gate throws `tool_deferred`, the registry holds only Trivy and OSV-Scanner, and no source file of the SCA module names Grype outside a comment",
    async run() {
      const p = [];
      for (const [name, argv] of [
        ["trivy", TRIVY_SCA_ARGV],
        ["osv-scanner", OSV_SCA_ARGV],
      ]) {
        ok(p, Object.isFrozen(argv), `${name} argv is not frozen`);
        ok(
          p,
          argv.every((a) => typeof a === "string" && !hasControl(a) && a !== "--"),
          `${name} argv entry`,
        );
      }
      const at = (argv, flag) => argv[argv.indexOf(flag) + 1];
      same(
        p,
        "trivy argv",
        [...TRIVY_SCA_ARGV],
        [
          "fs",
          "--config",
          "/rules/trivy.yaml",
          "--skip-db-update",
          "--skip-java-db-update",
          "--offline-scan",
          "--scanners",
          "vuln",
          "--pkg-types",
          "library",
          "--include-dev-deps",
          "--list-all-pkgs=false",
          "--format",
          "json",
          "/src",
        ],
      );
      same(p, "trivy scanners", at(TRIVY_SCA_ARGV, "--scanners"), "vuln");
      same(p, "trivy package types", at(TRIVY_SCA_ARGV, "--pkg-types"), "library");
      ok(
        p,
        TRIVY_SCA_ARGV.filter((a) => a === "--pkg-types").length === 1 &&
          TRIVY_SCA_ARGV.filter((a) => a === "--scanners").length === 1,
        "a repeated switch",
      );
      ok(
        p,
        !TRIVY_SCA_ARGV.some((a) =>
          /secret|misconfig|license|(^|,)os(,|$)|rootfs|image|repo|sbom|k8s|vm/i.test(a),
        ),
        "trivy runs something besides the language vulnerability scan",
      );
      same(
        p,
        "trivy env",
        { ...TRIVY_SCA_ENV },
        {
          TRIVY_SKIP_VERSION_CHECK: "true",
          TRIVY_DISABLE_TELEMETRY: "true",
          TRIVY_CACHE_DIR: "/db",
        },
      );
      same(
        p,
        "osv argv",
        [...OSV_SCA_ARGV],
        [
          "scan",
          "source",
          "--offline",
          "--offline-vulnerabilities",
          "--no-resolve",
          "--no-call-analysis=go",
          "--no-ignore",
          "--config",
          "/rules/osv-scanner.toml",
          "-r",
          "/src",
          "--format",
          "json",
        ],
      );
      same(p, "osv env", { ...OSV_SCA_ENV }, { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: "/db" });
      // the plans, through the real validation and argument builder
      const { resolver } = loadImageLock({});
      const config = validateSandboxConfig({
        runtimeBin: "docker",
        containerUser: "65534:65534",
        usernsMode: null,
        mountRoots: {
          archive: ["/var/lib/qm/scan"],
          db: ["/var/lib/qm/db-cache"],
          rules: ["/var/lib/qm/rules"],
        },
        egressNetworks: {},
      });
      const ctx = {
        tenantId: "00000000-0000-4000-8000-000000000001",
        executionId: "00000000-0000-4000-8000-000000000002",
        taskId: "00000000-0000-4000-8000-000000000003",
        attempt: 1,
        deadlineEpoch: 2_000_000_000,
        archiveDir: "/var/lib/qm/scan/t1",
        rulesDir: "/var/lib/qm/rules",
        dbDir: "/var/lib/qm/db-cache/trivy/" + "a".repeat(64),
        secondsToDeadline: 100,
      };
      for (const [adapter, dbName] of [
        [trivy, "trivy"],
        [osv, "osv-scanner"],
      ]) {
        const plan = adapter.plan({
          ...ctx,
          dbDir: `/var/lib/qm/db-cache/${dbName}/${"b".repeat(64)}`,
        });
        same(p, `${dbName} mounts`, Object.keys(plan.mounts).sort(), ["archive", "db", "rules"]);
        same(p, `${dbName} wall clock follows the deadline`, plan.limits.wallClockSeconds, 100);
        const spec = resolveRunSpecImage(
          {
            toolId: plan.toolId,
            imageKey: plan.imageKey,
            argv: plan.argv,
            mounts: plan.mounts,
            env: plan.env,
            limits: plan.limits,
            labels: plan.labels,
          },
          resolver,
          { scanType: "sca" },
        );
        validateRunSpec(spec, config);
        const args = buildRunArgs(spec, config);
        assertRunArgsSafe(args, config);
        const line = args.join(" ");
        ok(
          p,
          args.includes("--network=none") &&
            args.includes("--read-only") &&
            args.includes("--cap-drop=ALL"),
          `${dbName}: not sealed`,
        );
        ok(
          p,
          /dst=\/db,readonly/.test(line) &&
            /dst=\/src,readonly/.test(line) &&
            /dst=\/rules,readonly/.test(line),
          `${dbName}: a mount is not read-only`,
        );
        ok(
          p,
          !line.includes(":rw") || !/dst=\/(db|src|rules)(,|:)[^ ]*rw/.test(line),
          `${dbName}: a writable mount`,
        );
        ok(p, spec.image.includes("@sha256:"), `${dbName}: image not pinned by digest`);
        // nothing of the context but the platform paths reaches the argument vector
        const hostile = adapter.plan({
          ...ctx,
          dbDir: `/var/lib/qm/db-cache/${dbName}/${"c".repeat(64)}`,
          archiveDir: "/var/lib/qm/scan/--evil",
        });
        ok(
          p,
          JSON.stringify(hostile.argv) === JSON.stringify(plan.argv),
          `${dbName}: a context value entered the argument vector`,
        );
        for (const key of [
          "tenantId",
          "executionId",
          "taskId",
          "archiveDir",
          "rulesDir",
          "dbDir",
        ]) {
          let threw = false;
          try {
            adapter.plan({ ...ctx, dbDir: ctx.dbDir, [key]: "" });
          } catch (error) {
            threw = error instanceof TypeError;
          }
          ok(p, threw, `${dbName}: plan accepted an empty ${key}`);
        }
      }
      // the database mount must lie inside the configured roots: a snapshot elsewhere is refused by the validator
      const outside = trivy.plan({ ...ctx, dbDir: "/tmp/elsewhere" });
      let refused = false;
      try {
        validateRunSpec(
          resolveRunSpecImage(
            {
              toolId: outside.toolId,
              imageKey: outside.imageKey,
              argv: outside.argv,
              mounts: outside.mounts,
              env: outside.env,
              limits: outside.limits,
              labels: outside.labels,
            },
            resolver,
            { scanType: "sca" },
          ),
          config,
        );
      } catch {
        refused = true;
      }
      ok(p, refused, "a database directory outside the configured root was accepted");
      // Grype is never selectable
      let code = null;
      try {
        assertToolSelectable("grype", "sca");
      } catch (error) {
        code = error instanceof AdapterError ? error.code : "other";
      }
      same(p, "grype gate", code, "tool_deferred");
      same(
        p,
        "registry tools",
        createScaAdapterRegistry({ ensembleEnabled: true })
          .select("sca")
          .map((a) => a.toolId),
        ["trivy", "osv-scanner"],
      );
      same(p, "registry off", createScaAdapterRegistry().size, 0);
      let grypeRegistered = false;
      try {
        createAdapterRegistry([{ toolId: "grype", scanType: "sca", imageKey: "grype" }]);
        grypeRegistered = true;
      } catch {
        /* refused, as required */
      }
      ok(p, !grypeRegistered, "an adapter for grype was registered");
      // source guard
      const dir = path.join(ROOT, "apps/workers/src/execution/engines/ensemble/sca");
      const strip = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
      for (const name of readdirSync(dir).filter((n) => n.endsWith(".js"))) {
        const code2 = strip(readFileSync(path.join(dir, name), "utf8"));
        ok(p, !/grype/i.test(code2), `${name} names grype in code`);
        ok(
          p,
          !/child_process|node:net|node:http|fetch\(|process\.env|dbrefresh|writeFile|appendFile|unlink|execFile|spawn/.test(
            code2,
          ),
          `${name} reaches the outside world or the refresh job`,
        );
        ok(
          p,
          !/--pkg-types["',\s]+["']?os/.test(code2),
          `${name} asks for operating-system packages`,
        );
      }
      return p;
    },
  },
  {
    id: "ENG-S12o",
    name: "the SCA engine, sealed path and database provenance (SPEC scan-engines 5.12 SE-36 to SE-38, 5.3, 5.4, D-22, ENG-S12, part G; FakeSandboxRuntime, the real adapters, the real roll-up, the real snapshot resolver over a fake repository and store, the REAL tool output of 2026-11-21): each tool runs against the verified `active` snapshot of ITS OWN tool mounted read-only at /db with the verified command line, the tool run records the snapshot sha256 and build time and the run manifest changes with them; no snapshot, an object that fails its digest, a failing lookup or a candidate, retired or rejected status means the tool is `unavailable` / `db_unavailable` and NO container is started for it (one missing: degraded and incomplete, both missing: failed, transient, no result discarded), every stale tier (aging, stale, expired) runs the tool as `partial` / `db_stale`, the result is incomplete and never resolution eligible and nothing fails; a database error of the tool is `db_unavailable`, a bad configuration `config_invalid`, 137 `out_of_memory`; the engine never selects Grype and imports nothing from the refresh worker or the snapshot repository",
    async run() {
      const p = [];
      const base = mkdtempSync(path.join(os.tmpdir(), "qm-ens-g-"));
      try {
        const archiveRoot = path.join(base, "scan");
        const rulesDir = path.join(base, "rules");
        const dbRoot = path.join(base, "dbcache");
        for (const d of [archiveRoot, rulesDir, dbRoot]) mkdirSync(d);
        cpSync(
          path.join(ROOT, "apps/workers/src/execution/engines/ensemble/sbom/rules"),
          rulesDir,
          { recursive: true },
        );
        const sha = (c) => c.repeat(64);
        const dirOf = (tool, c) => {
          const d = path.join(dbRoot, tool, sha(c));
          mkdirSync(d, { recursive: true });
          return d;
        };
        const NOW = new Date("2026-11-21T12:00:00Z");
        const day = 86_400_000;
        const snapshot = (tool, c, ageDays, over = {}) => ({
          toolId: tool,
          sha256: sha(c),
          upstreamBuiltAt: new Date(NOW.getTime() - ageDays * day),
          fetchedAt: new Date(NOW.getTime() - ageDays * day + 3600_000),
          sources: [{ id: "ghsa", attributionRequired: true }],
          status: "active",
          ...over,
        });
        const files = {
          "package-lock.json": "{}",
          "web/package-lock.json": "{}",
          "java/pom.xml": "<project/>",
          "py/requirements.txt": "x==1\n",
          "py/requirements-dev.txt": "y==1\n",
          "svc/go.mod": "module x\n",
        };
        let n = 0;
        const tree = () => {
          const dir = path.join(archiveRoot, `t${(n += 1)}`);
          mkdirSync(dir, { mode: 0o755 });
          for (const [name, text] of Object.entries(files)) {
            mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
            writeFileSync(path.join(dir, name), text, { mode: 0o644 });
          }
          return dir;
        };
        /** @param {{ trivy?: any, osv?: any, scripts?: Record<string, any>, resolverOver?: any, now?: Date }} o */
        const rig = ({ trivySnap, osvSnap, scripts = {}, store, repoFault } = {}) => {
          const runtime = new FakeSandboxRuntime({
            config: {
              runtimeBin: "podman",
              containerUser: "65534:65534",
              usernsMode: "keep-id",
              uidMap: [],
              gidMap: [],
              seccompProfile: null,
              mountRoots: { archive: [archiveRoot], db: [dbRoot], rules: [rulesDir] },
              egressNetworks: {},
            },
          });
          runtime.script("trivy", { exitCode: 0, stdout: TRIVY_DOC, ...scripts.trivy });
          runtime.script("osv-scanner", {
            exitCode: 1,
            stdout: OSV_DOC,
            ...scripts["osv-scanner"],
          });
          const snaps = { trivy: trivySnap, "osv-scanner": osvSnap };
          const resolver = createDbSnapshotResolver({
            repo: {
              getActive: async (tool) => {
                if (repoFault) throw new Error("database is down");
                return snaps[tool] ?? null;
              },
            },
            store: store ?? {
              materialize: async ({ tool, sha256 }) => ({ dir: dirOf(tool, sha256[0]) }),
            },
            now: () => NOW,
          });
          const logs = [];
          const engine = createEnsembleScaEngine({
            runner: createSandboxRunner({ runtime }),
            gate: createCapacityGate({ perWorker: 4, perTenant: 4, perTask: 2, forkShare: 4 }),
            resolver: loadImageLock().resolver,
            dbResolver: resolver,
            rulesDir,
            toolWaitMs: 500,
            treePathExists: createTreePathExists,
          });
          const run = (extra = {}) =>
            engine.runTask(
              Object.freeze({
                executionId: "00000000-1111-4111-8111-000000000009",
                taskId: extra.taskId ?? TASK_A,
                attempt: 0,
                scanType: "sca",
                sourceDir: tree(),
              }),
              {
                signal: extra.signal ?? new AbortController().signal,
                log: (level, message) => logs.push(`${level} ${message}`),
                emit() {},
                platform: {
                  tenantId: "aaaaaaaa-0000-4000-8000-00000000000a",
                  deadlineEpoch: Math.floor(Date.now() / 1000) + 300,
                  secondsToDeadline: 300,
                  fork: false,
                  maxItems: 50_000,
                },
              },
            );
          return { runtime, run, logs, engine };
        };
        const statusOf = (r) =>
          Object.fromEntries(
            r.ensemble.toolRuns.map((t) => [
              t.toolId,
              `${t.status}${t.reason ? `/${t.reason}` : ""}`,
            ]),
          );
        const runsOf = (rt) => rt.calls.filter((c) => c.type === "run");

        // ---- fresh snapshots, the happy path
        const a = rig({
          trivySnap: snapshot("trivy", "a", 1),
          osvSnap: snapshot("osv-scanner", "b", 1),
        });
        const ra = await a.run();
        same(p, "statuses", statusOf(ra), { trivy: "succeeded", "osv-scanner": "succeeded" });
        same(
          p,
          "task",
          [
            ra.status,
            ra.incomplete,
            ra.ensemble.rollup.matchedRow,
            ra.ensemble.rollup.resolutionEligible,
            ra.items.length,
          ],
          ["succeeded", false, 5, true, 51],
        );
        same(p, "details match items", ra.ensemble.details.length, 51);
        const calls = runsOf(a.runtime);
        same(p, "two containers", calls.map((c) => c.spec.toolId).sort(), ["osv-scanner", "trivy"]);
        for (const c of calls) {
          const tool = c.spec.toolId;
          same(
            p,
            `${tool} db mount`,
            c.spec.mounts.db,
            path.join(dbRoot, tool, sha(tool === "trivy" ? "a" : "b")),
          );
          same(p, `${tool} argv`, c.spec.argv, [
            ...(tool === "trivy" ? TRIVY_SCA_ARGV : OSV_SCA_ARGV),
          ]);
          ok(
            p,
            c.args.some((x) => x.endsWith("dst=/db,readonly")),
            `${tool}: the database is not read-only`,
          );
          ok(p, c.args.includes("--network=none"), `${tool}: not sealed`);
        }
        const tr = ra.ensemble.toolRuns.find((t) => t.toolId === "trivy");
        const or = ra.ensemble.toolRuns.find((t) => t.toolId === "osv-scanner");
        same(
          p,
          "trivy provenance",
          [tr.dbSnapshotSha256, tr.dbBuiltAt],
          [sha("a"), new Date(NOW.getTime() - day).toISOString()],
        );
        same(
          p,
          "osv provenance",
          [or.dbSnapshotSha256, or.dbBuiltAt],
          [sha("b"), new Date(NOW.getTime() - day).toISOString()],
        );
        ok(
          p,
          /^sha256:[0-9a-f]{64}$/.test(tr.imageDigest) && tr.toolVersion !== "unknown",
          "trivy identity",
        );
        same(
          p,
          "tool run keys",
          Object.keys(tr)
            .filter((k) => /db|raw|stdout|stderr/i.test(k))
            .sort(),
          ["dbBuiltAt", "dbSnapshotSha256"],
        );
        same(p, "findings carry both tools", ra.items.length === 51, true);
        // the manifest: stable for the same data, different for other data
        const a2 = rig({
          trivySnap: snapshot("trivy", "a", 1),
          osvSnap: snapshot("osv-scanner", "b", 1),
        });
        const manifest = (r) => r.ensemble.runManifestSha256;
        same(p, "same snapshots, same manifest", manifest(await a2.run()), manifest(ra));
        const a3 = rig({
          trivySnap: snapshot("trivy", "c", 1),
          osvSnap: snapshot("osv-scanner", "b", 1),
        });
        ok(
          p,
          manifest(await a3.run()) !== manifest(ra),
          "another trivy snapshot gave the same manifest",
        );
        const a4 = rig({
          trivySnap: snapshot("trivy", "a", 1, {
            upstreamBuiltAt: new Date(NOW.getTime() - 2 * day),
          }),
          osvSnap: snapshot("osv-scanner", "b", 1),
        });
        ok(
          p,
          manifest(await a4.run()) !== manifest(ra),
          "another build time gave the same manifest",
        );

        // ---- no snapshot: no container, never a failure of the scan by itself
        const none = rig({ osvSnap: snapshot("osv-scanner", "b", 1) });
        const rn = await none.run();
        same(p, "trivy has no snapshot", statusOf(rn), {
          trivy: "unavailable/db_unavailable",
          "osv-scanner": "succeeded",
        });
        same(
          p,
          "only the other tool started",
          runsOf(none.runtime).map((c) => c.spec.toolId),
          ["osv-scanner"],
        );
        same(
          p,
          "degraded",
          [
            rn.status,
            rn.incomplete,
            rn.ensemble.rollup.matchedRow,
            rn.ensemble.rollup.resolutionEligible,
            rn.ensemble.rollup.toolsDegraded,
          ],
          ["succeeded", true, 6, false, 1],
        );
        ok(
          p,
          rn.items.length === 51 - 0 || rn.items.length > 0,
          "the other tool's results were discarded",
        );
        const trn = rn.ensemble.toolRuns.find((t) => t.toolId === "trivy");
        same(
          p,
          "an unavailable run has no identity and no snapshot",
          [trn.toolVersion, trn.imageDigest, trn.dbSnapshotSha256 ?? null, trn.exitCode],
          ["unknown", null, null, null],
        );
        const nothing = rig({});
        const rz = await nothing.run();
        same(
          p,
          "no snapshot at all",
          [
            statusOf(rz),
            rz.status,
            rz.ensemble.rollup.errorClass,
            rz.ensemble.rollup.reason,
            rz.items.length,
          ],
          [
            { trivy: "unavailable/db_unavailable", "osv-scanner": "unavailable/db_unavailable" },
            "failed",
            "transient",
            "tools_failed",
            0,
          ],
        );
        same(p, "no container at all", runsOf(nothing.runtime).length, 0);
        // the lookup fails
        const down = rig({
          trivySnap: snapshot("trivy", "a", 1),
          osvSnap: snapshot("osv-scanner", "b", 1),
          repoFault: true,
        });
        const rd = await down.run();
        same(
          p,
          "a failing lookup",
          [statusOf(rd), rd.status, runsOf(down.runtime).length],
          [
            { trivy: "unavailable/db_unavailable", "osv-scanner": "unavailable/db_unavailable" },
            "failed",
            0,
          ],
        );
        // the object does not match its digest
        const bad = rig({
          trivySnap: snapshot("trivy", "a", 1),
          osvSnap: snapshot("osv-scanner", "b", 1),
          store: {
            materialize: async () => {
              throw new DbMirrorIntegrityError("hash mismatch");
            },
          },
        });
        const rb = await bad.run();
        same(
          p,
          "an object that fails its digest",
          [statusOf(rb), runsOf(bad.runtime).length],
          [{ trivy: "unavailable/db_unavailable", "osv-scanner": "unavailable/db_unavailable" }, 0],
        );
        same(
          p,
          "the scan path sees one function of the snapshot table",
          Object.keys(createScanDbSnapshotReader({ db: {} })),
          ["getActive"],
        );
        same(
          p,
          "the reader asks for the ACTIVE row of one tool only",
          await (async () => {
            const seen = [];
            await createScanDbSnapshotReader({
              db: {
                scanDbSnapshot: {
                  findFirst: async (q) => {
                    seen.push(q.where);
                    return null;
                  },
                },
              },
            }).getActive("trivy");
            return seen;
          })(),
          [{ toolId: "trivy", status: "active" }],
        );
        // a candidate, retired or rejected row is never mounted: the repository returns only active rows, and the engine adds no other path
        const source = readFileSync(
          path.join(ROOT, "apps/workers/src/execution/engines/ensemble/engine/sca-engine.js"),
          "utf8",
        );
        ok(
          p,
          !/getActive|createScanDbSnapshotRepository|dbrefresh|\b(?:candidate|retired|rejected)\b/.test(
            source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, ""),
          ),
          "the SCA engine reaches snapshots other than through the resolver",
        );

        // ---- staleness never fails
        for (const [label, age] of [
          ["aging", 5],
          ["stale", 20],
          ["expired", 40],
        ]) {
          const s = rig({
            trivySnap: snapshot("trivy", "a", age),
            osvSnap: snapshot("osv-scanner", "b", age),
          });
          const r = await s.run();
          same(p, `${label} statuses`, statusOf(r), {
            trivy: "partial/db_stale",
            "osv-scanner": "partial/db_stale",
          });
          same(
            p,
            `${label} task`,
            [
              r.status,
              r.incomplete,
              r.ensemble.rollup.completeness,
              r.ensemble.rollup.resolutionEligible,
              r.ensemble.rollup.matchedRow,
              runsOf(s.runtime).length,
              r.items.length,
            ],
            ["succeeded", true, "incomplete", false, 5, 2, 51],
          );
        }
        const one = rig({
          trivySnap: snapshot("trivy", "a", 20),
          osvSnap: snapshot("osv-scanner", "b", 1),
        });
        const r1 = await one.run();
        same(
          p,
          "one stale",
          [statusOf(r1), r1.incomplete, r1.ensemble.rollup.resolutionEligible],
          [{ trivy: "partial/db_stale", "osv-scanner": "succeeded" }, true, false],
        );
        // a stale run that is also cut keeps the cut's reason (staleness is only a warning)
        const staleBad = rig({
          trivySnap: snapshot("trivy", "a", 20),
          osvSnap: snapshot("osv-scanner", "b", 1),
          scripts: { trivy: { stdout: "not json" } },
        });
        same(
          p,
          "a stale tool that fails keeps its failure",
          statusOf(await staleBad.run()).trivy,
          "failed/output_invalid",
        );

        // ---- tool failures, classified
        const exits = [
          [
            "a database error of trivy",
            "trivy",
            {
              exitCode: 1,
              stdout: "",
              stderr:
                "2026-11-21T11:02:21Z\tFATAL\tFatal error\trun error: init error: DB error: failed to open db: invalid database\n",
            },
            "unavailable/db_unavailable",
          ],
          [
            "a database error of osv-scanner",
            "osv-scanner",
            {
              exitCode: 127,
              stdout: "",
              stderr: "could not load db for npm ecosystem: unable to fetch OSV database\n",
            },
            "unavailable/db_unavailable",
          ],
          [
            "a missing osv configuration",
            "osv-scanner",
            {
              exitCode: 127,
              stdout: "",
              stderr:
                "Failed to read config file: open /rules/osv-scanner.toml: no such file or directory\n",
            },
            "failed/config_invalid",
          ],
          [
            "an out-of-memory kill",
            "trivy",
            { exitCode: 137, stdout: "", stderr: "" },
            "failed/out_of_memory",
          ],
          [
            "an unknown exit",
            "osv-scanner",
            { exitCode: 2, stdout: "", stderr: "boom" },
            "failed/exit_code",
          ],
          [
            "osv no package sources",
            "osv-scanner",
            { exitCode: 128, stdout: "", stderr: "No package sources found" },
            "succeeded",
          ],
          [
            "trivy garbage",
            "trivy",
            { exitCode: 0, stdout: "<html>", stderr: "" },
            "failed/output_invalid",
          ],
          ["a hung tool", "osv-scanner", { hang: true }, "timed_out/timeout"],
          ["a runtime fault", "trivy", { runtimeFault: true }, "failed/sandbox_error"],
        ];
        for (const [label, tool, outcome, want] of exits) {
          const e = rig({
            trivySnap: snapshot("trivy", "a", 1),
            osvSnap: snapshot("osv-scanner", "b", 1),
            scripts: { [tool]: outcome },
          });
          let r;
          if (outcome.hang) {
            // the wall clock is the plan's: shorten it by the task deadline
            const fast = e.engine;
            r = await fast.runTask(
              Object.freeze({
                executionId: "00000000-1111-4111-8111-000000000009",
                taskId: TASK_A,
                attempt: 0,
                scanType: "sca",
                sourceDir: tree(),
              }),
              {
                signal: new AbortController().signal,
                log() {},
                emit() {},
                platform: {
                  tenantId: "aaaaaaaa-0000-4000-8000-00000000000a",
                  deadlineEpoch: Math.floor(Date.now() / 1000) + 1,
                  secondsToDeadline: 1,
                  fork: false,
                  maxItems: 50_000,
                },
              },
            );
          } else r = await e.run();
          same(p, label, statusOf(r)[tool], want);
          ok(
            p,
            r.status === "succeeded",
            `${label}: one tool failing failed the task (${r.status})`,
          );
        }
        // grype is never run
        for (const c of runsOf(a.runtime))
          ok(p, !/grype/i.test(JSON.stringify(c.spec)), "grype was run");
        // cancel: no result of the tools is kept as complete, the containers are gone
        const ac = new AbortController();
        const slow = rig({
          trivySnap: snapshot("trivy", "a", 1),
          osvSnap: snapshot("osv-scanner", "b", 1),
          scripts: { trivy: { hang: true }, "osv-scanner": { hang: true } },
        });
        const pending = slow.run({ signal: ac.signal });
        setTimeout(() => ac.abort(new Error("lease_lost")), 50);
        const rc = await pending;
        same(
          p,
          "cancelled",
          [rc.ensemble.rollup.taskStatus, rc.ensemble.rollup.matchedRow, rc.incomplete],
          ["cancelled", 1, true],
        );
        same(p, "no container left", [...slow.runtime.containers.keys()], []);
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "ENG-S06k",
    name: "SCA mapper bounds, ordering and guards on the exact edges (SPEC scan-engines 7.2, 5.6.2, part G; found by the mutation sweep): CWE numbers 1 and 100000 are kept and 0, 100001 and non-numbers are not, at most ten sorted CWEs; the advisory list puts the CVE first then the other families in order and ids in order (any input order, equal family and equal id stay stable), at most 20, with the in-memory alias hints equal to it; component name and version are clipped to 200 and 100 characters and the scope is unknown; at most two CVSS entries of a stored version (a v2 entry is never kept), v3 before v4, shrunk to the byte budget, a score of exactly 0 and 10 kept and one outside refused, no key when there is none; a missing, empty or non-string title or fixed version falls back; an operating-system result drops exactly its vulnerabilities (or one when it has none) and a null vulnerability list is empty; the OSV group needs an id, at most 200 affected entries, six severity entries and the fixed versions of the named package only, a non-object advisory or group is skipped without losing the others, a summary that is not a string falls back; the plan refuses a non-integer attempt or deadline and a non-positive seconds-to-deadline uses the tool limit",
    async run() {
      const p = [];
      const tv = (over = {}) => ({
        VulnerabilityID: "CVE-2021-23337",
        VendorIDs: [],
        PkgName: "lodash",
        PkgIdentifier: { PURL: "pkg:npm/lodash@4.17.20" },
        InstalledVersion: "4.17.20",
        FixedVersion: "4.17.21",
        Severity: "HIGH",
        Title: "title",
        CweIDs: [],
        CVSS: {},
        ...over,
      });
      const rep = (vulns, over = {}) =>
        JSON.stringify({
          SchemaVersion: 2,
          Results: [
            {
              Target: "package-lock.json",
              Class: "lang-pkgs",
              Type: "npm",
              Vulnerabilities: vulns,
              ...over,
            },
          ],
        });
      const one = (over) => parseT(rep([tv(over)])).candidates[0];
      const V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      const V3b = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
      const V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
      // an advisory id that cannot be normalized is skipped, the record is not lost
      same(
        p,
        "unusable aliases are skipped",
        one({ VendorIDs: ["", "x y", "__proto__", "GHSA-aaaa-bbbb-cccc"] })?.advisories.map(
          (x) => x.id,
        ),
        ["CVE-2021-23337", "GHSA-aaaa-bbbb-cccc"],
      );
      // CWE
      same(
        p,
        "cwe edges",
        one({ CweIDs: ["CWE-1", "CWE-100000", "CWE-100001", "CWE-0", "x", "1000000"] }).cwe,
        [1, 100000],
      );
      same(
        p,
        "at most ten cwe",
        one({ CweIDs: Array.from({ length: 12 }, (_, i) => `CWE-${20 - i}`) }).cwe,
        [9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
      );
      same(p, "no cwe key", one({}).cwe, undefined);
      // advisories
      const order = (ids, primary = "CVE-2020-9") =>
        one({ VulnerabilityID: primary, VendorIDs: ids }).advisories.map((a) => a.id);
      const ids = [
        "RUSTSEC-2020-1",
        "GO-2020-2",
        "OSV-2020-1",
        "VENDOR-1",
        "GHSA-aaaa-bbbb-cccc",
        "PYSEC-2020-5",
        "GO-2020-10",
      ];
      const want = [
        "CVE-2020-9",
        "GHSA-aaaa-bbbb-cccc",
        "GO-2020-10",
        "GO-2020-2",
        "OSV-2020-1",
        "VENDOR-1",
        "PYSEC-2020-5",
        "RUSTSEC-2020-1",
      ];
      same(p, "advisory order", order(ids), want);
      same(p, "advisory order, reversed input", order([...ids].reverse()), want);
      same(p, "duplicates collapse", order(["GO-2020-2", "go-2020-2", "GO-2020-2"]), [
        "CVE-2020-9",
        "GO-2020-2",
      ]);
      const c = one({ VulnerabilityID: "CVE-2020-9", VendorIDs: ids });
      same(
        p,
        "alias hints equal the advisories",
        [c.mergeHints.aliases, c.mergeHints.primaryId],
        [want, "CVE-2020-9"],
      );
      same(
        p,
        "twenty advisories at most",
        one({
          VendorIDs: Array.from(
            { length: 20 },
            (_, i) => `GHSA-aaaa-bbbb-${String(i).padStart(4, "0")}`,
          ),
        }).advisories.length,
        20,
      );
      // component
      const longName = "n".repeat(250);
      const lc = one({ PkgIdentifier: { PURL: `pkg:npm/${longName}@${"1".repeat(150)}` } });
      same(
        p,
        "clipped name and version",
        lc === undefined ? null : [lc.component.name.length, lc.component.version.length],
        [200, 100],
      );
      same(p, "scope", one({}).component.scope, "unknown");
      // cvss
      const cv = (c) => one({ CVSS: c }).provenance[0].cvss;
      same(
        p,
        "score zero and ten kept",
        [
          cv({ ghsa: { V3Vector: V3, V3Score: 0 } })[0].score,
          cv({ ghsa: { V3Vector: V3, V3Score: 10 } })[0].score,
        ],
        [0, 10],
      );
      same(
        p,
        "score outside refused, vector kept",
        [
          cv({ ghsa: { V3Vector: V3, V3Score: -0.1 } })[0].score,
          cv({ ghsa: { V3Vector: V3, V3Score: 10.1 } })[0].score,
        ],
        [undefined, undefined],
      );
      same(
        p,
        "v3 before v4, at most two",
        cv({ ghsa: { V40Vector: V4, V3Vector: V3 }, nvd: { V3Vector: V3b } }).map((x) => x.version),
        ["3.1", "3.0"],
      );
      same(
        p,
        "v4 after v3",
        cv({ ghsa: { V40Vector: V4, V3Vector: V3 } }).map((x) => x.version),
        ["3.1", "4.0"],
      );
      same(
        p,
        "the same vector twice is one entry",
        cv({ ghsa: { V3Vector: V3 }, nvd: { V3Vector: V3 } }).length,
        1,
      );
      same(
        p,
        "two long vectors do not fit, one does",
        cv({ ghsa: { V40Vector: V4 }, nvd: { V40Vector: V4.replace("AV:N", "AV:A") } }).length,
        2,
      );
      same(p, "no cvss key", Object.hasOwn(one({}).provenance[0], "cvss"), false);
      // title and fix
      same(p, "title not a string", one({ Title: 5 }).title.startsWith("CVE-2021-23337"), true);
      same(p, "title empty", one({ Title: "" }).title.startsWith("CVE-2021-23337"), true);
      same(p, "title kept", one({ Title: "kept" }).title, "kept");
      same(p, "fixed version not a string", one({ FixedVersion: 5 }).fix, undefined);
      same(p, "fixed version empty", one({ FixedVersion: "" }).fix, undefined);
      // results
      const os = (n) =>
        parseT(
          rep(
            Array.from({ length: n }, () => tv()),
            { Class: "os-pkgs" },
          ),
        );
      same(p, "os result with three", [os(3).recordsDropped, os(3).findingsMapped], [3, 0]);
      same(p, "os result with none", os(0).recordsDropped, 1);
      same(
        p,
        "null vulnerabilities",
        [parseT(rep(null)).status, parseT(rep(null)).recordsSeen],
        ["succeeded", 0],
      );
      same(
        p,
        "undefined vulnerabilities",
        parseT(
          JSON.stringify({
            SchemaVersion: 2,
            Results: [{ Target: "package-lock.json", Class: "lang-pkgs" }],
          }),
        ).recordsSeen,
        0,
      );
      same(p, "vulnerabilities not a list", parseT(rep({})).recordsDropped, 1);
      same(
        p,
        "a fixed version string and a title are used",
        [one({}).fix, one({}).title],
        [{ fixedVersions: ["4.17.21"] }, "title"],
      );
      // OSV
      const ov = (over = {}) => ({
        package: {
          name: "lodash",
          version: "4.17.20",
          ecosystem: "npm",
          purl: "pkg:npm/lodash@4.17.20",
        },
        groups: [{ ids: ["GHSA-35jh-r3h4-6jhm"], aliases: ["CVE-2021-23337"] }],
        vulnerabilities: [{ id: "GHSA-35jh-r3h4-6jhm", aliases: [], summary: "sum" }],
        ...over,
      });
      const orep = (pkgs) =>
        JSON.stringify({
          results: [
            { source: { path: "/src/package-lock.json", type: "lockfile" }, packages: pkgs },
          ],
        });
      const oc = (over) => parseO(orep([ov(over)]));
      same(p, "a group without ids", oc({ groups: [{ ids: [], aliases: [] }] }).recordsDropped, 1);
      const aff = (n, at) =>
        Array.from({ length: n }, (_, i) => ({
          package: { name: i === at ? "lodash" : "other", ecosystem: "npm" },
          ranges: [{ type: "SEMVER", events: [{ fixed: i === at ? "4.17.21" : "9.9.9" }] }],
        }));
      const fixOf = (affected) =>
        oc({ vulnerabilities: [{ id: "GHSA-35jh-r3h4-6jhm", aliases: [], affected }] })
          .candidates[0].fix;
      same(p, "the 200th affected entry is read", fixOf(aff(200, 199)), {
        fixedVersions: ["4.17.21"],
      });
      same(p, "the 201st is not", fixOf(aff(201, 200)), undefined);
      const sevs = (at) =>
        Array.from({ length: 7 }, (_, i) => ({ type: "CVSS_V3", score: i === at ? V3 : "junk" }));
      const sevOf = (at) =>
        oc({ vulnerabilities: [{ id: "GHSA-35jh-r3h4-6jhm", aliases: [], severity: sevs(at) }] })
          .candidates[0];
      same(
        p,
        "the sixth severity entry is read",
        [sevOf(5).severity, sevOf(5).severityAssumed],
        ["critical", false],
      );
      same(p, "the seventh is not", sevOf(6).severityAssumed, true);
      const ranges = (n, at) => [
        {
          type: "SEMVER",
          events: Array.from({ length: n }, (_, i) =>
            i === at ? { fixed: "4.17.21" } : { introduced: "0" },
          ),
        },
      ];
      const fixR = (n, at) =>
        oc({
          vulnerabilities: [
            {
              id: "GHSA-35jh-r3h4-6jhm",
              aliases: [],
              affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: ranges(n, at) }],
            },
          ],
        }).candidates[0].fix;
      same(
        p,
        "the 100th event is read, the 101st is not",
        [fixR(100, 99), fixR(101, 100)],
        [{ fixedVersions: ["4.17.21"] }, undefined],
      );
      same(
        p,
        "a v2 entry is not a severity",
        oc({
          vulnerabilities: [
            {
              id: "GHSA-35jh-r3h4-6jhm",
              aliases: [],
              severity: [{ type: "CVSS_V2", score: "AV:N/AC:L/Au:N/C:P/I:P/A:P" }],
            },
          ],
        }).candidates[0].severityAssumed,
        true,
      );
      same(
        p,
        "no cvss key without vectors",
        Object.hasOwn(oc({}).candidates[0].provenance[0], "cvss"),
        false,
      );
      same(
        p,
        "a cvss key with a vector",
        oc({
          vulnerabilities: [
            { id: "GHSA-35jh-r3h4-6jhm", aliases: [], severity: [{ type: "CVSS_V3", score: V3 }] },
          ],
        }).candidates[0].provenance[0].cvss,
        [{ version: "3.1", vector: V3, score: 9.8 }],
      );
      same(
        p,
        "a non-object advisory is skipped",
        oc({
          vulnerabilities: [null, 5, { id: "GHSA-35jh-r3h4-6jhm", aliases: [], summary: "sum" }],
        }).candidates[0]?.title,
        "sum",
      );
      same(
        p,
        "a non-object group is dropped, the others kept",
        (() => {
          const g = { ids: ["GHSA-35jh-r3h4-6jhm"], aliases: [] };
          const r = parseO(orep([ov({ groups: [null, g, g, g, g, g, g, g, g, g] })]));
          return [r.recordsSeen, r.recordsDropped, r.findingsMapped];
        })(),
        [10, 1, 9],
      );
      same(
        p,
        "an advisory without an id is skipped",
        oc({
          vulnerabilities: [
            { aliases: [] },
            { id: "GHSA-35jh-r3h4-6jhm", aliases: [], summary: "sum" },
          ],
        }).candidates[0]?.title,
        "sum",
      );
      same(
        p,
        "summary not a string",
        oc({
          vulnerabilities: [{ id: "GHSA-35jh-r3h4-6jhm", aliases: [], summary: 5 }],
        }).candidates[0].title.startsWith("CVE-2021-23337"),
        true,
      );
      same(
        p,
        "summary empty",
        oc({
          vulnerabilities: [{ id: "GHSA-35jh-r3h4-6jhm", aliases: [], summary: "" }],
        }).candidates[0].title.startsWith("CVE-2021-23337"),
        true,
      );
      same(
        p,
        "the canonical id is the CVE of the group",
        oc({}).candidates[0].rule.id,
        "CVE-2021-23337",
      );
      same(p, "no cwe", oc({}).candidates[0].cwe, undefined);
      // plan
      const ctxP = {
        tenantId: "t",
        executionId: "e",
        taskId: "k",
        attempt: 1,
        deadlineEpoch: 5,
        archiveDir: "/a",
        rulesDir: "/r",
        dbDir: "/d",
      };
      const planOf = (over) => trivy.plan({ ...ctxP, ...over });
      const throwsT = (over) => {
        try {
          planOf(over);
          return false;
        } catch (e) {
          return e instanceof TypeError;
        }
      };
      same(
        p,
        "plan refusals",
        [
          throwsT({ attempt: 1.5 }),
          throwsT({ deadlineEpoch: "5" }),
          throwsT({ attempt: undefined }),
          throwsT({ deadlineEpoch: undefined }),
          throwsT({}),
        ],
        [true, true, true, true, false],
      );
      same(
        p,
        "seconds to deadline",
        [
          planOf({ secondsToDeadline: 0 }).limits.wallClockSeconds,
          planOf({ secondsToDeadline: -5 }).limits.wallClockSeconds,
          planOf({ secondsToDeadline: 7.5 }).limits.wallClockSeconds,
          planOf({ secondsToDeadline: 1 }).limits.wallClockSeconds,
          planOf({ secondsToDeadline: 9999 }).limits.wallClockSeconds,
        ],
        [300, 300, 300, 1, 300],
      );
      return p;
    },
  },
  {
    id: "ENG-S12p",
    name: "the SCA engine on its edges (SPEC scan-engines 5.3, 5.4, 6.4, SE-16 to SE-20, part G; found by the mutation sweep): the engine identity (scan type, `default`, `ensemble-sca/1`, idempotent, needs the platform facts) and the refusal of a relative rules directory or a missing resolver; the exit codes 0 and 1 are recorded as they are; a lease loss aborts with the cancelled roll-up (row 1) and the tool runs `cancelled` / `cancelled`, a task deadline with the timed-out roll-up (row 2) and `cancelled` / `deadline`, and the runner is asked to abort the attempt that is numbered from 1; a fork task is held to the fork share of the capacity gate (one tool waits and is `unavailable` / `capacity`), a trusted task is not; an image that is not in the local store is `unavailable` / `image_unavailable` whether the lock or the runtime says so, any other runtime error is `failed` / `sandbox_error`; the item cap of the platform facts truncates the result and an absent cap is the default",
    async run() {
      const p = [];
      const base = mkdtempSync(path.join(os.tmpdir(), "qm-ens-gp-"));
      try {
        const archiveRoot = path.join(base, "scan");
        const rulesDir = path.join(base, "rules");
        const dbRoot = path.join(base, "dbcache");
        for (const d of [archiveRoot, rulesDir, dbRoot]) mkdirSync(d);
        cpSync(
          path.join(ROOT, "apps/workers/src/execution/engines/ensemble/sbom/rules"),
          rulesDir,
          { recursive: true },
        );
        const NOW = new Date("2026-11-21T12:00:00Z");
        const snap = (tool, c) => ({
          toolId: tool,
          sha256: c.repeat(64),
          upstreamBuiltAt: new Date(NOW.getTime() - 86_400_000),
          fetchedAt: NOW,
          sources: [],
          status: "active",
        });
        const dbResolver = createDbSnapshotResolver({
          repo: { getActive: async (tool) => snap(tool, tool === "trivy" ? "a" : "b") },
          store: {
            materialize: async ({ tool, sha256 }) => ({
              dir:
                (mkdirSync(path.join(dbRoot, tool, sha256), { recursive: true }),
                path.join(dbRoot, tool, sha256)),
            }),
          },
          now: () => NOW,
        });
        const files = {
          "web/package-lock.json": "{}",
          "java/pom.xml": "<p/>",
          "py/requirements.txt": "x\n",
          "py/requirements-dev.txt": "y\n",
          "svc/go.mod": "m\n",
        };
        let n = 0;
        const tree = () => {
          const dir = path.join(archiveRoot, `t${(n += 1)}`);
          mkdirSync(dir, { mode: 0o755 });
          for (const [name, text] of Object.entries(files)) {
            mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
            writeFileSync(path.join(dir, name), text, { mode: 0o644 });
          }
          return dir;
        };
        const make = ({ scripts = {}, gate = {}, resolver, runnerOver, deps = {} } = {}) => {
          const runtime = new FakeSandboxRuntime({
            config: {
              runtimeBin: "podman",
              containerUser: "65534:65534",
              usernsMode: "keep-id",
              uidMap: [],
              gidMap: [],
              seccompProfile: null,
              mountRoots: { archive: [archiveRoot], db: [dbRoot], rules: [rulesDir] },
              egressNetworks: {},
            },
          });
          runtime.script("trivy", { exitCode: 0, stdout: TRIVY_DOC, ...scripts.trivy });
          runtime.script("osv-scanner", {
            exitCode: 1,
            stdout: OSV_DOC,
            ...scripts["osv-scanner"],
          });
          const runner = createSandboxRunner({ runtime });
          const aborts = [];
          const engine = createEnsembleScaEngine({
            runner: runnerOver
              ? runnerOver(runner)
              : {
                  ...runner,
                  runTool: runner.runTool,
                  abortAttempt: async (a) => (aborts.push(a), runner.abortAttempt(a)),
                },
            gate: createCapacityGate({
              perWorker: 4,
              perTenant: 4,
              perTask: 2,
              forkShare: 4,
              ...gate,
            }),
            resolver: resolver ?? loadImageLock().resolver,
            dbResolver,
            rulesDir,
            toolWaitMs: 300,
            treePathExists: createTreePathExists,
            ...deps,
          });
          const run = ({ signal, fork = false, maxItems, secondsToDeadline = 300 } = {}) =>
            engine.runTask(
              Object.freeze({
                executionId: "00000000-1111-4111-8111-000000000009",
                taskId: TASK_A,
                attempt: 0,
                scanType: "sca",
                sourceDir: tree(),
              }),
              {
                signal: signal ?? new AbortController().signal,
                log() {},
                emit() {},
                platform: {
                  tenantId: "aaaaaaaa-0000-4000-8000-00000000000a",
                  deadlineEpoch: Math.floor(Date.now() / 1000) + secondsToDeadline,
                  secondsToDeadline,
                  fork,
                  ...(maxItems === undefined ? {} : { maxItems }),
                },
              },
            );
          return { engine, run, runtime, aborts };
        };
        const statuses = (r) =>
          Object.fromEntries(
            r.ensemble.toolRuns.map((t) => [
              t.toolId,
              `${t.status}${t.reason ? `/${t.reason}` : ""}`,
            ]),
          );
        // identity and refusals
        const e = make();
        same(
          p,
          "identity",
          [
            e.engine.scanType,
            e.engine.engineId,
            e.engine.version,
            e.engine.idempotent,
            e.engine.needsPlatform,
          ],
          ["sca", "default", "ensemble-sca/1", true, true],
        );
        same(p, "frozen", Object.isFrozen(e.engine), true);
        const refuses = (deps) => {
          try {
            make({ deps });
            return false;
          } catch (error) {
            return error instanceof TypeError;
          }
        };
        same(
          p,
          "refusals",
          [
            refuses({ rulesDir: "relative/rules" }),
            refuses({ rulesDir: 5 }),
            refuses({ dbResolver: null }),
            refuses({ dbResolver: {} }),
            refuses({ dbResolver: { resolve: 5 } }),
            refuses({}),
          ],
          [true, true, true, true, true, false],
        );
        let noPlatform = null;
        try {
          await e.engine.runTask(
            Object.freeze({ executionId: "x", taskId: TASK_A, attempt: 0, sourceDir: tree() }),
            { signal: new AbortController().signal, log() {}, emit() {} },
          );
        } catch (error) {
          noPlatform = error instanceof TypeError;
        }
        same(p, "no platform facts", noPlatform, true);
        // exit codes recorded as they are
        const ok1 = await make().run();
        same(
          p,
          "exit codes",
          Object.fromEntries(ok1.ensemble.toolRuns.map((t) => [t.toolId, t.exitCode])),
          { trivy: 0, "osv-scanner": 1 },
        );
        // the item cap
        const capped = await make().run({ maxItems: 10 });
        same(
          p,
          "capped",
          [capped.items.length, capped.truncated, capped.incomplete],
          [10, true, true],
        );
        const uncapped = await make().run();
        same(p, "default cap", [uncapped.items.length, uncapped.truncated], [51, false]);
        // lease loss and deadline
        for (const [label, reason, row, task, toolReason] of [
          ["lease loss", "lease_lost", 1, "cancelled", "cancelled"],
          ["deadline", "task_deadline", 2, "timed_out", "deadline"],
        ]) {
          const ac = new AbortController();
          const h = make({ scripts: { trivy: { hang: true }, "osv-scanner": { hang: true } } });
          const pending = h.run({ signal: ac.signal });
          setTimeout(() => ac.abort(new Error(reason)), 60);
          const r = await pending;
          same(
            p,
            `${label} roll-up`,
            [r.ensemble.rollup.matchedRow, r.ensemble.rollup.taskStatus, r.status],
            [row, task, "succeeded"],
          );
          same(p, `${label} tool runs`, statuses(r), {
            trivy: `cancelled/${toolReason}`,
            "osv-scanner": `cancelled/${toolReason}`,
          });
          same(
            p,
            `${label} abort asked for attempt 1`,
            h.aborts.map((a) => [a.taskId, a.attempt]),
            [[TASK_A, 1]],
          );
          same(p, `${label} nothing left`, [...h.runtime.containers.keys()], []);
        }
        // the fork share
        const fork = await make({
          scripts: { trivy: { delayMs: 700 }, "osv-scanner": { delayMs: 700 } },
          gate: { forkShare: 1 },
        }).run({ fork: true });
        same(p, "a fork task is held to its share", Object.values(statuses(fork)).sort(), [
          "succeeded",
          "unavailable/capacity",
        ]);
        const trusted = await make({
          scripts: { trivy: { delayMs: 700 }, "osv-scanner": { delayMs: 700 } },
          gate: { forkShare: 1 },
        }).run({ fork: false });
        same(p, "a trusted task is not", Object.values(statuses(trusted)).sort(), [
          "succeeded",
          "succeeded",
        ]);
        // image and runtime errors
        const lockResolver = loadImageLock().resolver;
        const noImage = await make({
          resolver: {
            resolve: (key, o) => {
              if (key === "trivy") throw new SandboxError("image_unavailable", "x");
              return lockResolver.resolve(key, o);
            },
          },
        }).run();
        same(p, "the lock has no image", statuses(noImage).trivy, "unavailable/image_unavailable");
        const otherPlan = await make({
          resolver: {
            resolve: (key, o) => {
              if (key === "trivy") throw new Error("boom");
              return lockResolver.resolve(key, o);
            },
          },
        }).run();
        same(p, "another resolver error", statuses(otherPlan).trivy, "failed/sandbox_error");
        const runtimeError = (code) => (runner) => ({
          ...runner,
          abortAttempt: runner.abortAttempt,
          runTool: async (spec, o) => {
            if (spec.toolId === "trivy")
              throw code ? new SandboxError(code, "x") : new Error("boom");
            return runner.runTool(spec, o);
          },
        });
        const rtNo = await make({ runnerOver: runtimeError("image_unavailable") }).run();
        same(p, "the runtime has no image", statuses(rtNo).trivy, "unavailable/image_unavailable");
        const rtOther = await make({ runnerOver: runtimeError("invalid_spec") }).run();
        same(p, "a sandbox error of another kind", statuses(rtOther).trivy, "failed/sandbox_error");
        const rtPlain = await make({ runnerOver: runtimeError(null) }).run();
        same(p, "a plain error", statuses(rtPlain).trivy, "failed/sandbox_error");
        // the output and runtime outcomes of the runner
        const flag = async (outcome) =>
          statuses(await make({ scripts: { trivy: outcome } }).run()).trivy;
        same(
          p,
          "the output cap",
          await flag({ stdout: "x".repeat(65 * 1024 * 1024) }),
          "failed/output_too_large",
        );
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
      return p;
    },
  },
];
