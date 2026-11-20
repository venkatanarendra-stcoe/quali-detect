/* eslint-disable no-control-regex -- the checks assert that control characters are removed from untrusted text */
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { findRunArgsProblems, validateSandboxConfig } from "@qmentisai/infra";
import {
  ASSUMPTIONS,
  compareCapture,
  purlChangeTags,
  readManifest,
  safeText,
} from "../../../../workers/scripts/eng-l20/compare-lib.js";
import { canonicalPurl } from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import { compareDirectory } from "../../../../workers/scripts/eng-l20/compare.js";
import { SAMPLE_FILES, buildSampleTarGz } from "../../../../workers/scripts/eng-l20/sample-tree.js";
import {
  SYFT_ARGV,
  TRIVY_SBOM_ARGV,
} from "../../../../workers/src/execution/engines/ensemble/sbom/index.js";

/**
 * Scan engines, ENG-L20 tooling (ADR-008 area 18 hostile tool output containment, SPEC scan-engines 16.2 ENG-L20, 17.i-pre): the
 * offline comparison of captured real Syft and Trivy output with every assumption of the Part E adapters, and the capture tool's
 * Docker-free parts. No container, no network, no database. NOT proved: anything about real tool output (that is what the owner's
 * run produces); here only that the comparison is faithful, detects mismatches and is safe on hostile data.
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const SCRIPTS = path.join(ROOT, "apps/workers/scripts/eng-l20");
const SBOM_SRC = path.join(ROOT, "apps/workers/src/execution/engines/ensemble/sbom");
const CORE_ADAPTER = path.join(ROOT, "apps/workers/src/execution/engines/ensemble/core/adapter.js");
const FIX = path.join(ROOT, "apps/api/test/security/fixtures/scan-engines");
const LOCK = JSON.parse(
  readFileSync(
    path.join(ROOT, "apps/workers/src/execution/engines/ensemble/catalog/images.lock.json"),
    "utf8",
  ),
).images.map((e) => ({ key: e.key, digest: e.digest, version: e.version }));
const digestOf = (key) => LOCK.find((e) => e.key === key).digest;
const versionOf = (key) => LOCK.find((e) => e.key === key).version;

const ok = (problems, condition, message) => {
  if (!condition) problems.push(message);
};
const throwsCode = (fn) => {
  try {
    fn();
  } catch (e) {
    return e?.code ?? `non-coded ${e?.name}`;
  }
  return null;
};
const same = (problems, label, got, want) =>
  ok(
    problems,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
  );

const run = (id, tool, over = {}) => ({
  id,
  tool,
  purpose: id,
  exitCode: 0,
  wallMs: 900,
  timedOut: false,
  stdoutFile: `${id}.stdout`,
  stderrFile: `${id}.stderr`,
  ...over,
});

/** The capture of the hand-written SBOM fixtures as the owner's run would write it (in memory). */
export function fixtureCapture() {
  const files = new Map([
    ["syft-version.stdout", Buffer.from("syft 1.57.2\n")],
    ["trivy-version.stdout", Buffer.from("Version: 0.76.2\n")],
    ["syft-sealed.stdout", readFileSync(path.join(FIX, "sbom/syft-cyclonedx.json"))],
    ["trivy-sealed.stdout", readFileSync(path.join(FIX, "sbom/trivy-cyclonedx.json"))],
    ["syft-sealed.stderr", Buffer.alloc(0)],
    ["trivy-sealed.stderr", Buffer.alloc(0)],
  ]);
  const manifest = {
    manifestVersion: 1,
    images: {
      syft: { digest: digestOf("syft"), repoDigests: [`anchore/syft@${digestOf("syft")}`] },
      trivy: { digest: digestOf("trivy"), repoDigests: [`aquasec/trivy@${digestOf("trivy")}`] },
    },
    runs: [
      run("syft-version", "syft"),
      run("trivy-version", "trivy"),
      run("syft-sealed", "syft"),
      run("trivy-sealed", "trivy"),
    ],
  };
  return { manifest, files };
}

const compare = ({ manifest, files }, extra = {}) =>
  compareCapture({
    manifest,
    readOutput: (id, stream) => files.get(`${id}.${stream}`) ?? null,
    lock: { images: LOCK },
    ...extra,
  });
const statusOf = (report) => Object.fromEntries(report.checks.map((c) => [c.id, c.status]));
const mismatches = (report) =>
  report.checks
    .filter((c) => c.status === "MISMATCH")
    .map((c) => c.id)
    .sort();
const unknowns = (report) =>
  report.checks
    .filter((c) => c.status === "UNKNOWN")
    .map((c) => c.id)
    .sort();

const jsonOf = (cap, name) => JSON.parse(cap.files.get(name).toString("utf8"));
const setJson = (cap, name, value) => cap.files.set(name, Buffer.from(JSON.stringify(value)));
const clone = (cap) => ({
  manifest: structuredClone(cap.manifest),
  files: new Map([...cap.files].map(([k, v]) => [k, Buffer.from(v)])),
});
const runOf = (cap, id) => cap.manifest.runs.find((r) => r.id === id);
const libs = (doc) => doc.components.filter((c) => c.type === "library");

/** Each mutation breaks ONE assumption of an otherwise good capture; `expect` are the checks that must become MISMATCH. */
const MUTATIONS = [
  {
    name: "Syft location property renamed",
    expect: ["PATH-src-syft"],
    text: ["PATH-src-syft", "syft:loc:0:path"],
    apply(cap) {
      const d = jsonOf(cap, "syft-sealed.stdout");
      for (const c of d.components)
        for (const p of c.properties ?? []) p.name = p.name.replace("syft:location:", "syft:loc:");
      setJson(cap, "syft-sealed.stdout", d);
    },
  },
  {
    name: "Trivy dependency graph removed",
    expect: ["PATH-src-trivy", "PATH-graph-trivy"],
    apply(cap) {
      const d = jsonOf(cap, "trivy-sealed.stdout");
      delete d.dependencies;
      setJson(cap, "trivy-sealed.stdout", d);
    },
  },
  {
    name: "specVersion 2.0",
    expect: ["DOC-format-syft", "ADAPTER-syft"],
    collateral: ["COUNT-syft", "ENS-merge"],
    apply(cap) {
      const d = jsonOf(cap, "syft-sealed.stdout");
      d.specVersion = "2.0";
      setJson(cap, "syft-sealed.stdout", d);
    },
  },
  {
    name: "paths carry the container mount prefix",
    expect: ["PATH-form-syft"],
    apply(cap) {
      const d = jsonOf(cap, "syft-sealed.stdout");
      for (const c of d.components)
        for (const p of c.properties ?? [])
          if (/^syft:location:\d+:path$/.test(p.name)) p.value = `/src${p.value}`;
      setJson(cap, "syft-sealed.stdout", d);
    },
  },
  {
    name: "Trivy exits 2",
    expect: ["EXIT-trivy", "ADAPTER-trivy"],
    collateral: [
      "COUNT-trivy",
      "DB-trivy",
      "PURL-cross",
      "ENS-merge",
      "OQ5-pypi",
      "OQ5-golang",
      "OQ5-npm",
      "OQ5-maven",
    ],
    apply(cap) {
      runOf(cap, "trivy-sealed").exitCode = 2;
    },
  },
  {
    name: "Trivy purl for the same package differs",
    expect: ["PURL-cross", "OQ5-pypi"],
    collateral: ["ENS-merge"],
    apply(cap) {
      const d = jsonOf(cap, "trivy-sealed.stdout");
      for (const c of libs(d))
        if (c.purl.startsWith("pkg:pypi/")) {
          c.purl = `${c.purl}?distro=qm-mutation`;
        }
      setJson(cap, "trivy-sealed.stdout", d);
    },
  },
  {
    name: "image digest not the locked one",
    expect: ["IMG-syft"],
    apply(cap) {
      cap.manifest.images.syft.repoDigests = [`anchore/syft@sha256:${"0".repeat(64)}`];
    },
  },
  {
    name: "duplicate bom-ref",
    expect: ["DOC-bomref-syft"],
    apply(cap) {
      const d = jsonOf(cap, "syft-sealed.stdout");
      const l = libs(d);
      l[1]["bom-ref"] = l[0]["bom-ref"];
      setJson(cap, "syft-sealed.stdout", d);
    },
  },
  {
    name: "planted repository configuration changes the result",
    expect: ["CFG-repo-syft"],
    apply(cap) {
      const d = jsonOf(cap, "syft-sealed.stdout");
      d.components = d.components.filter((c) => c.type !== "library").concat(libs(d).slice(0, 2));
      cap.files.set("syft-planted.stdout", Buffer.from(JSON.stringify(d)));
      cap.files.set("syft-planted.stderr", Buffer.alloc(0));
      cap.manifest.runs.push(run("syft-planted", "syft"));
    },
  },
  {
    name: "reported version differs from the locked one",
    expect: ["VER-trivy"],
    apply(cap) {
      cap.files.set("trivy-version.stdout", Buffer.from("Version: 0.1.0\n"));
    },
  },
  {
    name: "document is SPDX, not CycloneDX",
    expect: ["DOC-format-trivy", "ADAPTER-trivy"],
    collateral: [
      "COUNT-trivy",
      "PURL-cross",
      "ENS-merge",
      "OQ5-pypi",
      "OQ5-golang",
      "OQ5-npm",
      "OQ5-maven",
      "DOC-bomref-trivy",
    ],
    apply(cap) {
      const d = jsonOf(cap, "trivy-sealed.stdout");
      d.bomFormat = "SPDX";
      setJson(cap, "trivy-sealed.stdout", d);
    },
  },
  {
    name: "run took more than half the wall clock",
    expect: [],
    unknown: ["TIME-syft"],
    apply(cap) {
      runOf(cap, "syft-sealed").wallMs = 100000;
    },
  },
  {
    name: "components list is empty",
    expect: ["DOC-components-syft"],
    collateral: [
      "PATH-src-syft",
      "PROP-foundby-syft",
      "PURL-cross",
      "ENS-merge",
      "OQ5-pypi",
      "OQ5-golang",
      "OQ5-npm",
      "OQ5-maven",
    ],
    apply(cap) {
      const d = jsonOf(cap, "syft-sealed.stdout");
      d.components = [];
      setJson(cap, "syft-sealed.stdout", d);
    },
  },
  {
    name: "component version differs from the purl version",
    expect: ["PURL-ver-syft"],
    apply(cap) {
      const d = jsonOf(cap, "syft-sealed.stdout");
      libs(d)[0].version = "9.9.9";
      setJson(cap, "syft-sealed.stdout", d);
    },
  },
  {
    name: "planted run fails",
    expect: ["CFG-repo-syft"],
    apply(cap) {
      cap.files.set("syft-planted.stdout", cap.files.get("syft-sealed.stdout"));
      cap.files.set("syft-planted.stderr", Buffer.alloc(0));
      cap.manifest.runs.push(run("syft-planted", "syft", { exitCode: 1 }));
    },
  },
  {
    name: "Trivy needs a database but a fallback works",
    expect: ["EXIT-trivy", "DB-trivy"],
    text: ["DB-trivy", "fallback trivy-fallback-skipdb worked"],
    apply(cap) {
      const sealed = runOf(cap, "trivy-sealed");
      sealed.exitCode = 1;
      cap.files.set("trivy-fallback-skipdb.stdout", cap.files.get("trivy-sealed.stdout"));
      cap.files.set("trivy-fallback-skipdb.stderr", Buffer.alloc(0));
      cap.manifest.runs.push(run("trivy-fallback-skipdb", "trivy"));
    },
    collateral: [],
  },
  {
    name: "run timed out",
    expect: ["EXIT-syft", "TIME-syft"],
    apply(cap) {
      Object.assign(runOf(cap, "syft-sealed"), { timedOut: true, wallMs: 181000 });
    },
  },
  {
    name: "a path escapes the tree",
    expect: ["PATH-form-trivy"],
    apply(cap) {
      const d = jsonOf(cap, "trivy-sealed.stdout");
      libs(d)[0].properties.push({
        name: "aquasecurity:trivy:FilePath",
        value: "../outside/package-lock.json",
      });
      setJson(cap, "trivy-sealed.stdout", d);
    },
  },
];

const baseReport = () => compare(fixtureCapture());

function runCli(args, options = {}) {
  const r = spawnSync(process.execPath, [path.join(SCRIPTS, "compare.js"), ...args], {
    encoding: "utf8",
    timeout: 60_000,
    ...options,
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function writeCapture(dir, cap) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, "manifest.json"), JSON.stringify(cap.manifest));
  for (const [name, bytes] of cap.files) writeFileSync(path.join(dir, name), bytes);
}

function treeHash(dir) {
  const h = createHash("sha256");
  const walk = (d) => {
    for (const f of readdirSync(d).sort()) {
      const p = path.join(d, f);
      const st = lstatSync(p);
      h.update(`${path.relative(dir, p)}:${st.mode}:${st.size}:${st.mtimeMs}\n`);
      if (st.isDirectory()) walk(p);
      else h.update(readFileSync(p));
    }
  };
  walk(dir);
  return h.digest("hex");
}

const listJs = (dir) =>
  readdirSync(dir).flatMap((f) => {
    const p = path.join(dir, f);
    return statSync(p).isDirectory() ? listJs(p) : p.endsWith(".js") ? [p] : [];
  });

export const ENG_L20_CHECKS = [
  {
    id: "ENG-S15a",
    name: "the ENG-L20 comparison reads the hand-written fixtures, the deliberately mismatched capture and a hostile capture correctly (SPEC scan-engines 16.2 ENG-L20, ADR-008 area 18): the good capture of the Syft and Trivy fixtures has no MISMATCH, decides its documents, locations, purls, scopes and the cross-tool merge as PASS and leaves exactly the experiments it lacks UNKNOWN; the report is identical on a second run and is a plain JSON value; the checked-in mismatched capture (specification 1.4 documents with renamed location properties, a container mount prefix on paths, a Go purl that differs between the tools by the v prefix, a deb distro qualifier that differs, duplicate and missing bom-refs, a missing dependency graph, a different image digest, a Trivy exit code of 1 after 400 seconds and a planted repository configuration that changed the result) reports exactly the pinned MISMATCH set and never PASS for those checks, so the comparison is not vacuous",
    async run() {
      const p = [];
      const base = baseReport();
      same(p, "good capture MISMATCH set", mismatches(base), []);
      same(p, "good capture UNKNOWN set", unknowns(base), [
        "CFG-keys-syft",
        "CFG-keys-trivy",
        "CFG-read-syft",
        "CFG-read-trivy",
        "CFG-repo-syft",
        "CFG-repo-trivy",
        "DOC-scope-trivy",
        "FLAG-syft",
        "FLAG-trivy",
        "OQ5-apk",
        "OQ5-deb",
        "OQ5-rpm",
        "PATH-exists-syft",
        "PATH-exists-trivy",
      ]);
      const s = statusOf(base);
      for (const id of [
        "IMG-syft",
        "IMG-trivy",
        "VER-syft",
        "VER-trivy",
        "EXIT-syft",
        "EXIT-trivy",
        "DOC-format-syft",
        "DOC-format-trivy",
        "DOC-purl-syft",
        "DOC-purl-trivy",
        "DOC-bomref-syft",
        "DOC-bomref-trivy",
        "PATH-src-syft",
        "PATH-src-trivy",
        "PATH-graph-trivy",
        "PATH-form-syft",
        "PATH-form-trivy",
        "PURL-norm-syft",
        "ADAPTER-syft",
        "ADAPTER-trivy",
        "PURL-cross",
        "OQ5-pypi",
        "OQ5-golang",
        "OQ5-npm",
        "OQ5-maven",
        "ENS-merge",
        "DOC-scope-syft",
        "COUNT-syft",
        "COUNT-trivy",
      ])
        ok(p, s[id] === "PASS", `${id} should PASS on the good capture, is ${s[id]}`);
      same(p, "verdict", [base.verdict, base.summary.mismatch], ["UNKNOWN", 0]);
      same(p, "second run identical", JSON.stringify(baseReport()), JSON.stringify(base));
      same(p, "report is plain JSON", JSON.parse(JSON.stringify(base)), base);
      ok(
        p,
        base.purlTable.some((r) => r.changes.includes("pypi-name-normalized")),
        "the purl table must show the PyPI normalization",
      );
      ok(
        p,
        base.purlTable.some((r) => r.changes.includes("golang-lowercased")),
        "the purl table must show the Go lower-casing",
      );

      // exact observations of the good capture (these pin the arithmetic and the wording of the evidence)
      const obs = (id) => base.checks.find((c) => c.id === id)?.observed;
      same(
        p,
        "PURL-norm-syft",
        obs("PURL-norm-syft"),
        "7 purls, 2 changed by normalization, 0 unparseable",
      );
      same(
        p,
        "PURL-norm-trivy",
        obs("PURL-norm-trivy"),
        "7 purls, 0 changed by normalization, 0 unparseable",
      );
      same(p, "COUNT-syft", obs("COUNT-syft"), "7 package components produce 7 records");
      same(p, "ADAPTER-trivy", obs("ADAPTER-trivy"), "7 records from 7 package components");
      same(p, "PROP-foundby-syft", obs("PROP-foundby-syft"), "7 components");
      same(p, "PROP-foundby-trivy", obs("PROP-foundby-trivy"), "not applicable to Trivy");
      same(
        p,
        "PATH-graph-trivy",
        obs("PATH-graph-trivy"),
        "7 lockfile applications cover all 7 libraries",
      );
      same(p, "PATH-form-syft", obs("PATH-form-syft"), '8 locations: {"leading-slash":8}');
      same(p, "PATH-form-trivy", obs("PATH-form-trivy"), '8 locations: {"bare-relative":8}');
      same(p, "versions", base.observations.versions, {
        syft: "syft 1.57.2",
        trivy: "Version: 0.76.2",
      });
      same(
        p,
        "tool version in the document",
        base.observations.documents.syft.toolVersionInDocument,
        "1.57.2",
      );
      same(p, "merge", base.observations.merge, { findings: 8, agreed: 6, singleTool: 2 });
      same(p, "example path", base.observations.documents.syft.examples[0], {
        raw: "/package-lock.json",
        form: "leading-slash",
        normalized: "package-lock.json",
      });
      same(p, "purl table rows of the good capture", base.purlTable.length, 2);
      ok(
        p,
        base.purlTable.every((r) => typeof r.after === "string"),
        "every purl row of the good capture has a normalized form",
      );
      ok(
        p,
        obs("OQ5-pypi").includes("rule is doing work") &&
          obs("OQ5-npm").includes("not needed for this data"),
        "the OQ-5 rows must say whether the rule matters",
      );
      // purl change tags (the explanation column)
      for (const [raw, want] of [
        ["pkg:npm/%40Babel/Core@v7.0.0", ["v-prefix-stripped", "npm-lowercased"]],
        ["pkg:pypi/Zope.Interface@5.5", ["pypi-name-normalized"]],
        ["pkg:golang/github.com/BurntSushi/toml@v1.3.2", ["golang-lowercased"]],
        ["pkg:deb/debian/curl@7?arch=amd64&package-id=x", ["qualifiers-dropped"]],
        ["pkg:npm/a@1#sub", ["subpath-dropped"]],
        ["pkg:maven/g/a@1?type=jar&classifier=x", ["encoding-or-order"]],
        ["pkg:npm/lodash@4.17.20", []],
        ["pkg:", ["unparseable"]],
      ])
        same(p, `purlChangeTags ${raw}`, purlChangeTags(raw, canonicalPurl(raw)), want);
      same(p, "safeText of a number", safeText(42), "42");
      same(p, "safeText of undefined", safeText(undefined), "");
      for (const bad of [
        null,
        { manifestVersion: 2, runs: [] },
        { manifestVersion: 1 },
        { manifestVersion: 1, runs: [{ id: "A B" }] },
      ])
        same(
          p,
          `unusable manifest ${JSON.stringify(bad)}`,
          throwsCode(() => readManifest(bad)),
          "manifest_invalid",
        );

      const dir = path.join(FIX, "eng-l20/mismatch");
      const bad = compareDirectory(dir);
      same(
        p,
        "mismatched capture MISMATCH set",
        mismatches(bad),
        [
          "ADAPTER-syft",
          "ADAPTER-trivy",
          "COUNT-trivy",
          "CFG-repo-syft",
          "DB-trivy",
          "DOC-bomref-syft",
          "DOC-bomref-trivy",
          "DOC-purl-syft",
          "DOC-scope-syft",
          "DOC-types-syft",
          "DUP-syft",
          "ENS-merge",
          "EXIT-trivy",
          "IMG-trivy",
          "OQ5-deb",
          "OQ5-golang",
          "PATH-form-syft",
          "PATH-form-trivy",
          "PATH-graph-trivy",
          "PROP-foundby-syft",
          "PURL-cross",
          "TIME-trivy",
          "VER-syft",
        ].sort(),
      );
      same(p, "mismatched verdict", bad.verdict, "MISMATCH");
      // not vacuous: the deliberate defects are named by the check that must catch them
      const bs = statusOf(bad);
      for (const id of [
        "PURL-cross",
        "OQ5-golang",
        "OQ5-deb",
        "EXIT-trivy",
        "IMG-trivy",
        "CFG-repo-syft",
        "PATH-form-syft",
        "DOC-bomref-trivy",
      ])
        ok(p, bs[id] === "MISMATCH", `${id} must report the deliberate defect`);
      const cross = bad.observations.cross.disagreements.map(
        (r) => `${r.syftCanonical} | ${r.trivyCanonical}`,
      );
      ok(
        p,
        cross.some((r) =>
          r.includes("burntsushi/toml@v1.3.2 | pkg:golang/github.com/burntsushi/toml@1.3.2"),
        ),
        "the Go v-prefix disagreement must be listed with both normalized purls",
      );
      ok(p, bad.purlTable.length > 0, "the mismatched capture must still produce a purl table");
      const imp = (id) => bad.checks.find((c) => c.id === id)?.impact;
      same(
        p,
        "impacts",
        [
          imp("DOC-bomref-trivy"),
          imp("DOC-bomref-syft"),
          imp("ADAPTER-trivy"),
          imp("ADAPTER-syft"),
          imp("EXIT-trivy"),
        ],
        ["breaks", "degraded", "breaks", "degraded", "breaks"],
      );
      ok(
        p,
        bad.checks
          .find((c) => c.id === "PATH-graph-trivy")
          .observed.includes("lockfile applications found by the adapter: 0"),
        "the missing graph must be explained",
      );
      ok(
        p,
        bad.checks.find((c) => c.id === "DUP-syft").observed.startsWith("1 repeated purl entry "),
        "one repeat is worded in the singular",
      );
      ok(
        p,
        bad.checks.find((c) => c.id === "DB-trivy").observed.includes("no fallback run"),
        "the missing fallback must be said",
      );
      ok(
        p,
        bad.checks.find((c) => c.id === "DOC-types-syft").observed.includes("type package"),
        "the unexpected purl-bearing type must be named",
      );
      return p;
    },
  },
  {
    id: "ENG-S15b",
    name: "the ENG-L20 comparison catches each single deliberate defect (mutate-style control, SPEC scan-engines 16.2 ENG-L20): starting from the good capture, thirteen one-defect mutations (location property renamed, dependency graph removed, specification 2.0, container mount prefix on paths, Trivy exit 2, a purl that differs between the tools, a different image digest, a duplicate bom-ref, a planted repository configuration that changes the result, a different reported version, an SPDX document, a timed-out run, a path that escapes the tree) each turn exactly the pinned checks into MISMATCH and nothing else beyond the declared collateral, and the unmutated capture stays free of MISMATCH, so a PASS means the assumption was really tested; a tree probe that lacks a reported path turns the path-exists check into MISMATCH while a tree that has them passes it",
    async run() {
      const p = [];
      for (const m of MUTATIONS) {
        const cap = clone(fixtureCapture());
        m.apply(cap);
        const report = compare(cap);
        const got = mismatches(report);
        for (const id of m.unknown ?? [])
          ok(p, unknowns(report).includes(id), `mutation "${m.name}": ${id} must be UNKNOWN`);
        if (m.text) {
          const c = report.checks.find((x) => x.id === m.text[0]);
          ok(
            p,
            c?.observed.includes(m.text[1]),
            `mutation "${m.name}": ${m.text[0]} must say "${m.text[1]}"`,
          );
        }
        const allowed = new Set([...m.expect, ...(m.collateral ?? [])]);
        for (const id of m.expect)
          ok(
            p,
            got.includes(id),
            `mutation "${m.name}": ${id} must be MISMATCH (got ${JSON.stringify(got)})`,
          );
        for (const id of got)
          ok(p, allowed.has(id), `mutation "${m.name}": unexpected MISMATCH ${id}`);
      }
      same(p, "unmutated control", mismatches(compare(fixtureCapture())), []);
      // ---- a capture with every experiment: all PASS; silent variants of the same experiments are UNKNOWN, never PASS
      const full = (exits) => {
        const cap = clone(fixtureCapture());
        for (const tool of ["syft", "trivy"]) {
          cap.files.set(`${tool}-planted.stdout`, cap.files.get(`${tool}-sealed.stdout`));
          cap.files.set(`${tool}-planted.stderr`, Buffer.from(""));
          cap.manifest.runs.push(run(`${tool}-planted`, tool));
          for (const [id, code] of [
            [`${tool}-config-missing`, exits],
            [`${tool}-config-unknown-key`, exits],
            [`${tool}-unknown-flag`, exits === 0 ? 0 : 2],
          ]) {
            cap.files.set(`${id}.stdout`, Buffer.from(""));
            cap.files.set(`${id}.stderr`, Buffer.from("unknown flag: --qm-no-such-flag\n"));
            cap.manifest.runs.push(run(id, tool, { exitCode: code }));
          }
        }
        return cap;
      };
      const loud = compare(full(1));
      for (const id of ["CFG-repo", "CFG-read", "CFG-keys", "FLAG"])
        for (const tool of ["syft", "trivy"])
          same(p, `${id}-${tool} with a loud tool`, statusOf(loud)[`${id}-${tool}`], "PASS");
      same(p, "no MISMATCH in the full capture", mismatches(loud), []);
      same(p, "flag stderr is an observation", loud.observations.stderr["syft-unknown-flag"].head, [
        "unknown flag: --qm-no-such-flag",
      ]);
      const silent = compare(full(0));
      for (const id of ["CFG-read", "CFG-keys", "FLAG"])
        for (const tool of ["syft", "trivy"])
          same(p, `${id}-${tool} with a silent tool`, statusOf(silent)[`${id}-${tool}`], "UNKNOWN");
      // missing evidence is UNKNOWN, a boundary is a MISMATCH
      const lacking = clone(fixtureCapture());
      lacking.manifest.runs = lacking.manifest.runs.filter((r) => !r.id.endsWith("-version"));
      delete lacking.manifest.images.trivy;
      lacking.manifest.images.syft.repoDigests = null;
      lacking.files.delete("syft-sealed.stdout");
      const lack = statusOf(compare(lacking));
      same(
        p,
        "missing evidence",
        [
          lack["VER-syft"],
          lack["VER-trivy"],
          lack["IMG-trivy"],
          lack["IMG-syft"],
          lack["DOC-parse-syft"],
          lack["PURL-cross"],
        ],
        ["UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"],
      );
      const edge = clone(fixtureCapture());
      runOf(edge, "syft-sealed").wallMs = 180000;
      same(p, "wall clock reached", statusOf(compare(edge))["TIME-syft"], "MISMATCH");
      const noRepo = clone(fixtureCapture());
      noRepo.manifest.images.syft.repoDigests = [];
      same(p, "empty RepoDigests", statusOf(compare(noRepo))["IMG-syft"], "UNKNOWN");
      const many = (n) => ({
        manifestVersion: 1,
        runs: Array.from({ length: n }, (_, i) => ({ id: `r${i}` })),
      });
      same(
        p,
        "64 runs are accepted",
        throwsCode(() => readManifest(many(64))),
        null,
      );
      same(
        p,
        "65 runs are refused",
        throwsCode(() => readManifest(many(65))),
        "manifest_invalid",
      );
      same(
        p,
        "file name must follow the run id",
        throwsCode(() =>
          readManifest({ manifestVersion: 1, runs: [{ id: "a", stdoutFile: "b.stdout" }] }),
        ),
        "manifest_invalid",
      );
      same(
        p,
        "stderr file name must follow the run id",
        throwsCode(() =>
          readManifest({ manifestVersion: 1, runs: [{ id: "a", stderrFile: "a.stdout" }] }),
        ),
        "manifest_invalid",
      );
      same(
        p,
        "right file names",
        throwsCode(() =>
          readManifest({
            manifestVersion: 1,
            runs: [{ id: "a", stdoutFile: "a.stdout", stderrFile: "a.stderr" }],
          }),
        ),
        null,
      );
      const exact = "word ".repeat(10).trim();
      ok(
        p,
        safeText(exact, exact.length) === exact,
        "safeText keeps a text of exactly the maximum",
      );
      // documents that are not objects never throw out of the comparison
      for (const text of ["5", "[]", "null", '"x"']) {
        const odd = clone(fixtureCapture());
        odd.files.set("syft-sealed.stdout", Buffer.from(text));
        same(p, `document ${text}`, statusOf(compare(odd))["DOC-format-syft"], "MISMATCH");
      }
      // CycloneDX 1.5 occurrences, hashes and licences
      const occ = clone(fixtureCapture());
      const occDoc = jsonOf(occ, "syft-sealed.stdout");
      for (const c of occDoc.components) {
        if (c.type !== "library") continue;
        c.properties = c.properties.filter((x) => !x.name.startsWith("syft:location"));
        c.evidence = { occurrences: [{ location: "./pkg/lock.json" }] };
      }
      libs(occDoc)[1].hashes = [];
      libs(occDoc)[1].licenses = [];
      libs(occDoc)[0].hashes = [{ alg: "SHA-1", content: "ab" }];
      libs(occDoc)[0].licenses = [{ license: { id: "MIT" } }];
      setJson(occ, "syft-sealed.stdout", occDoc);
      const occReport = compare(occ);
      same(
        p,
        "occurrences are a path source",
        [statusOf(occReport)["PATH-src-syft"], occReport.observations.documents.syft.pathForms],
        ["PASS", { "dot-slash": 7 }],
      );
      same(
        p,
        "hashes and licences are counted",
        [
          occReport.observations.documents.syft.hashes,
          occReport.observations.documents.syft.licences,
        ],
        [1, 1],
      );
      same(
        p,
        "observed text",
        occReport.checks.find((c) => c.id === "PATH-src-syft").observed,
        "syft:location=0, evidence.occurrences=7, trivy:FilePath=0, lockfile-graph libraries=0",
      );
      // an application without a purl is counted, one with a purl is a package
      const mis = compareDirectory(path.join(FIX, "eng-l20/mismatch"));
      same(
        p,
        "graph evidence",
        mis.checks.find((c) => c.id === "PATH-graph-trivy").observed,
        "dependencies: 1, lockfile applications found by the adapter: 0, applications without purl: 1",
      );
      // path-exists with a tree probe
      const none = compare(fixtureCapture(), { pathExists: () => false });
      ok(
        p,
        statusOf(none)["PATH-exists-syft"] === "MISMATCH",
        "a tree without the reported paths must be a MISMATCH",
      );
      const all = compare(fixtureCapture(), { pathExists: () => true });
      ok(
        p,
        statusOf(all)["PATH-exists-syft"] === "PASS" &&
          statusOf(all)["PATH-exists-trivy"] === "PASS",
        "a tree with every path must PASS",
      );
      return p;
    },
  },
  {
    id: "ENG-S15c",
    name: "the ENG-L20 comparison covers every assumption the adapters make and cannot drift from them (SPEC scan-engines 16.2 ENG-L20): each enumerated assumption literal still occurs in the SBOM adapter source and the adapter framework (location properties syft:location, syft:package:foundBy, evidence occurrences, aquasecurity:trivy:FilePath, the dependsOn graph, scope values, bom-ref, purl, component types), every check family of the comparison exists, the runbook names both locked image digests, the exact sealed Syft and Trivy argument vectors, the capture and compare commands, every experiment run id of the capture tool and the exit and wall-time evidence, and states the offline Trivy database fallback and that the pull is the only network step",
    async run() {
      const p = [];
      const source = [...listJs(SBOM_SRC), CORE_ADAPTER]
        .map((f) => readFileSync(f, "utf8"))
        .join("\n");
      for (const a of ASSUMPTIONS)
        ok(
          p,
          source.includes(a.literal),
          `assumption ${a.id}: "${a.literal}" no longer occurs in the SBOM adapter source`,
        );
      const lib = readFileSync(path.join(SCRIPTS, "compare-lib.js"), "utf8");
      for (const lit of [
        "syft:location",
        "syft:package:foundBy",
        "aquasecurity:trivy:FilePath",
        "occurrences",
        "dependsOn",
        "required",
        "optional",
        "excluded",
        "bom-ref",
      ])
        ok(p, lib.includes(lit), `the comparison does not mention ${lit}`);
      const runbook = readFileSync(
        path.join(ROOT, "docs/modules/scan-engines/ENG_L20_RUNBOOK.md"),
        "utf8",
      );
      for (const key of ["syft", "trivy"])
        ok(p, runbook.includes(digestOf(key)), `the runbook lacks the locked ${key} digest`);
      ok(
        p,
        runbook.includes(SYFT_ARGV.join(" ")),
        "the runbook lacks the sealed Syft argument vector",
      );
      ok(
        p,
        runbook.includes(TRIVY_SBOM_ARGV.join(" ")),
        "the runbook lacks the sealed Trivy argument vector",
      );
      const capture = readFileSync(path.join(SCRIPTS, "capture.js"), "utf8");
      const ids = [...capture.matchAll(/id: "([a-z0-9-]+)"/g)].map((m) => m[1]);
      ok(p, ids.length >= 12, `the capture tool lists too few runs (${ids.length})`);
      for (const id of ids)
        ok(p, runbook.includes(id), `the runbook does not explain the run ${id}`);
      for (const text of [
        "eng-l20/capture.js",
        "eng-l20/compare.js",
        "--skip-db-update",
        "--skip-java-db-update",
        "manifest.json",
        "only step that uses the network",
        "wall",
      ])
        ok(p, runbook.toLowerCase().includes(text.toLowerCase()), `the runbook lacks "${text}"`);
      // every check id family of the comparison belongs to a declared assumption area
      for (const prefix of [
        "IMG-",
        "VER-",
        "EXIT-",
        "TIME-",
        "ERR-",
        "DB-",
        "CFG-",
        "FLAG-",
        "DOC-",
        "PATH-",
        "PURL-",
        "OQ5-",
        "ENS-",
        "ADAPTER-",
        "DUP-",
        "COUNT-",
        "PROP-",
      ])
        ok(
          p,
          baseReport().checks.some((c) => c.id.startsWith(prefix)),
          `no check with the id prefix ${prefix}`,
        );
      const spec = readFileSync(path.join(ROOT, "docs/modules/scan-engines/SPEC.md"), "utf8");
      ok(
        p,
        /ENG-L20[^\n]*ENG_L20_RUNBOOK\.md/.test(spec),
        "SPEC 16.2 ENG-L20 must point at the runbook",
      );
      return p;
    },
  },
  {
    id: "ENG-S15d",
    name: "the ENG-L20 comparison is read-only, bounded, secret-free and executes nothing (SPEC scan-engines 11.1 T6, 14.1 ENG-S09, ADR-008 area 18): running the command line tool leaves the capture directory byte-identical (content, modes, sizes, times) and exits 0 for the good capture, 1 for the mismatched one and 2 for a missing manifest, a --json path inside the capture and a malformed manifest; a symbolic link in place of an output file, an output over the size cap, a document nested beyond the depth cap, a __proto__ key, a manifest with an unsafe file name and a manifest with a run id that is a path are refused with a fixed word and never followed or read; credential shapes planted in stderr, in a component property, in a path and in a version line never appear in the table or in the JSON report (secrets are redacted, property values are not reported); the comparison and its tool import no process, network, eval or dynamic import and call nothing with data from the capture",
    async run() {
      const p = [];
      const tmp = mkdtempSync(path.join(os.tmpdir(), "eng-l20-s15d-"));
      try {
        const canary = `ghp_${"Zq7".repeat(14)}`;
        const aws = "AKIAABCDEFGHIJKLMNOP";
        // ---- read-only and exit codes through the real command line tool
        const goodDir = path.join(tmp, "good");
        const good = fixtureCapture();
        good.files.set(
          "syft-sealed.stderr",
          Buffer.from(`warn Authorization: Bearer ${canary}\npassword=${aws}\n`),
        );
        const doc = JSON.parse(good.files.get("syft-sealed.stdout").toString("utf8"));
        doc.components[0].properties.push({ name: "secret:prop", value: canary });
        doc.components[0].properties.push({
          name: "syft:location:9:path",
          value: `/dir/${canary}/file`,
        });
        good.files.set("syft-sealed.stdout", Buffer.from(JSON.stringify(doc)));
        good.files.set("syft-version.stdout", Buffer.from(`syft 1.57.2 token=${canary}\n`));
        writeCapture(goodDir, good);
        const before = treeHash(goodDir);
        const reportPath = path.join(tmp, "report.json");
        const r1 = runCli([goodDir, "--json", reportPath]);
        same(p, "exit code, good capture", r1.status, 0);
        same(p, "capture directory untouched", treeHash(goodDir), before);
        const report = readFileSync(reportPath, "utf8");
        for (const [label, text] of [
          ["table", r1.stdout],
          ["report", report],
          ["stderr", r1.stderr],
        ]) {
          ok(
            p,
            !text.includes(canary) && !text.includes(canary.slice(4)),
            `${label} contains the planted GitHub token`,
          );
          ok(p, !text.includes(aws), `${label} contains the planted AWS key`);
        }
        ok(p, r1.stdout.includes("[redacted]"), "the redaction must be visible in the table");
        const r2 = runCli([path.join(FIX, "eng-l20/mismatch")]);
        same(p, "exit code, mismatched capture", r2.status, 1);
        ok(
          p,
          !r2.stdout.includes("ghp_Q9x"),
          "the mismatched capture's stderr token must not be printed",
        );
        same(p, "exit code, no manifest", runCli([path.join(tmp, "nothing")]).status, 2);
        same(
          p,
          "exit code, --json inside the capture",
          runCli([goodDir, "--json", path.join(goodDir, "r.json")]).status,
          2,
        );
        same(p, "capture still untouched", treeHash(goodDir), before);
        // ---- refusals
        const refuse = (label, mutate, wantCode) => {
          const dir = path.join(tmp, `refuse-${label}`);
          const cap = clone(fixtureCapture());
          mutate(cap, dir);
          writeCapture(dir, cap);
          let got = null;
          try {
            const r = compareDirectory(dir);
            const noted = r.observations.notes.find((n) => n.includes(wantCode));
            got = noted
              ? wantCode
              : r.checks.find((c) => c.id === "DOC-parse-syft")?.status === "MISMATCH"
                ? "doc_refused"
                : "accepted";
          } catch (e) {
            got = e?.code ?? `non-coded ${e?.name}`;
          }
          same(p, `refusal ${label}`, got, wantCode);
        };
        refuse(
          "symlink",
          (cap, dir) => {
            cap.files.delete("syft-sealed.stdout");
            mkdirSync(dir, { recursive: true });
            writeFileSync(path.join(tmp, "outside.json"), cap.files.get("trivy-sealed.stdout"));
            symlinkSync(path.join(tmp, "outside.json"), path.join(dir, "syft-sealed.stdout"));
          },
          "not_regular_file",
        );
        refuse(
          "oversize-manifest",
          (cap) => {
            cap.manifest.pad = "x".repeat(1024 * 1024 + 10);
          },
          "too_large",
        );
        refuse(
          "nested",
          (cap) => {
            cap.files.set(
              "syft-sealed.stdout",
              Buffer.from(`${"[".repeat(200)}${"]".repeat(200)}`),
            );
          },
          "doc_refused",
        );
        refuse(
          "proto",
          (cap) => {
            cap.files.set(
              "syft-sealed.stdout",
              Buffer.from(
                '{"bomFormat":"CycloneDX","specVersion":"1.6","__proto__":{"x":1},"components":[]}',
              ),
            );
          },
          "doc_refused",
        );
        refuse(
          "empty",
          (cap) => {
            cap.files.set("syft-sealed.stdout", Buffer.alloc(0));
          },
          "doc_refused",
        );
        refuse(
          "unsafe-id",
          (cap) => {
            cap.manifest.runs[0].id = "../../etc/passwd";
          },
          "manifest_invalid",
        );
        refuse(
          "unsafe-file",
          (cap) => {
            cap.manifest.runs[0].stdoutFile = "../../../etc/passwd";
          },
          "manifest_invalid",
        );
        refuse(
          "dup-id",
          (cap) => {
            cap.manifest.runs.push(cap.manifest.runs[0]);
          },
          "manifest_invalid",
        );
        const bomb = (n) =>
          Buffer.from(
            JSON.stringify({
              bomFormat: "CycloneDX",
              specVersion: "1.6",
              components: Array.from({ length: n }, (_, i) => ({
                type: "library",
                name: `n${i}`,
                purl: `pkg:npm/n${i}@1.0.0`,
              })),
            }),
          );
        const t0 = Date.now();
        const big = compare({
          ...fixtureCapture(),
          files: new Map([...fixtureCapture().files, ["syft-sealed.stdout", bomb(60000)]]),
        });
        ok(p, Date.now() - t0 < 30_000, "60000 components must be compared in bounded time");
        ok(
          p,
          big.checks.find((c) => c.id === "ADAPTER-syft")?.status === "MISMATCH",
          "60000 components exceed the record cap and must be reported",
        );
        ok(
          p,
          JSON.stringify(big).length < 200_000,
          "the report must stay small whatever the input size",
        );
        // ---- safeText
        ok(p, !safeText(`\u202e${canary}\u0007`).includes(canary), "safeText must redact");
        ok(
          p,
          !/[\u0001-\u001f\u202e]/.test(safeText("a\u0000b\u202ec")),
          "safeText must remove control and bidirectional characters",
        );
        ok(p, safeText("x".repeat(500), 50).length <= 50, "safeText must cut");
        // ---- source guard
        for (const f of ["compare-lib.js", "compare.js", "lock.js"]) {
          const src = readFileSync(path.join(SCRIPTS, f), "utf8")
            .replace(/\/\*[\s\S]*?\*\//g, "")
            .replace(/^\s*\/\/.*$/gm, "");
          for (const [name, re] of [
            ["child_process", /child_process/],
            ["net/http", /node:(net|http|https|dgram|dns|tls|worker_threads|vm)\b/],
            ["eval", /\beval\s*\(/],
            ["Function constructor", /\bnew Function\b|\bFunction\s*\(/],
            ["dynamic import", /\bimport\s*\(/],
            ["require", /\brequire\s*\(/],
            ["process.env", /process\.env/],
            [
              "write to the capture",
              /\b(unlinkSync|rmSync|renameSync|appendFileSync|chmodSync|mkdirSync|copyFileSync)\b/,
            ],
          ])
            ok(p, !re.test(src), `${f} uses ${name}`);
        }
        const cliSrc = readFileSync(path.join(SCRIPTS, "compare.js"), "utf8");
        ok(
          p,
          (cliSrc.match(/writeFileSync\(/g) ?? []).length === 1,
          "the comparison tool must write exactly one file, the --json report",
        );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "ENG-S15e",
    name: "the ENG-L20 capture tool prepares the tree the way production does and builds only sealed invocations, without Docker (SPEC scan-engines 6.2, 6.3, 16.2 ENG-L20): `prepare --sample` extracts the sample archive with the real extractor (directories 0755, files 0644, inside a private 0700 parent, no .git, the top directory stripped) and covers scoped npm, a mixed-case PyPI package with dot and underscore, an upper-case Go module, Maven, a Debian and an Alpine package database; the planted tree holds the three repository configuration files; `run --dry-run` prints one command per experiment, each of which passes the argument audit (network none, read-only, cap-drop ALL, no-new-privileges, numeric non-root user, tmpfs, read-only bind mounts, digest-pinned image, pull never), the sealed Syft and Trivy runs end with the exact argument vectors of the adapters, the unknown-flag and missing-config experiments differ from the sealed vector only in the stated way, and `images` prints the pull command of each locked digest; the tool never starts a container in this check",
    async run() {
      const p = [];
      const tmp = mkdtempSync(path.join(os.tmpdir(), "eng-l20-s15e-"));
      try {
        const work = path.join(tmp, "work");
        const cli = path.join(SCRIPTS, "capture.js");
        const exec = (...args) =>
          execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 60_000 });
        exec("prepare", "--work", work, "--sample");
        same(p, "work dir mode", statSync(work).mode & 0o777, 0o700);
        same(p, "trees dir mode", statSync(path.join(work, "trees")).mode & 0o777, 0o700);
        const walk = (d, rel = "") =>
          readdirSync(d).flatMap((f) => {
            const st = lstatSync(path.join(d, f));
            const r = rel ? `${rel}/${f}` : f;
            return st.isDirectory()
              ? [{ r, dir: true, mode: st.mode & 0o777 }, ...walk(path.join(d, f), r)]
              : [{ r, dir: false, mode: st.mode & 0o777, link: st.isSymbolicLink() }];
          });
        const clean = walk(path.join(work, "trees/clean"));
        for (const e of clean) {
          ok(p, !e.link, `${e.r} is a symbolic link`);
          ok(p, e.mode === (e.dir ? 0o755 : 0o644), `${e.r} has mode ${e.mode.toString(8)}`);
          ok(p, !e.r.split("/").includes(".git"), `${e.r} is inside .git`);
        }
        same(
          p,
          "files of the clean tree",
          clean
            .filter((e) => !e.dir)
            .map((e) => e.r)
            .sort(),
          Object.keys(SAMPLE_FILES).sort(),
        );
        ok(
          p,
          !existsSync(path.join(work, "trees/clean/eng-l20-sample-0000000")),
          "the top directory must be stripped",
        );
        const planted = walk(path.join(work, "trees/planted"))
          .filter((e) => !e.dir)
          .map((e) => e.r);
        for (const f of [".syft.yaml", "trivy.yaml", ".trivyignore"])
          ok(p, planted.includes(f), `planted tree lacks ${f}`);
        ok(
          p,
          !clean.some((e) => e.r === ".syft.yaml"),
          "the clean tree must not hold repository configuration",
        );
        const all = Object.values(SAMPLE_FILES).join("\n");
        for (const needle of [
          "@babel/core",
          "Django==",
          "zope.interface",
          "typing_extensions",
          "BurntSushi",
          "log4j-core",
          "Package: curl",
          "P:busybox",
        ])
          ok(p, all.includes(needle), `the sample tree lacks ${needle}`);
        ok(p, buildSampleTarGz().length > 100, "the sample archive is empty");
        ok(
          p,
          existsSync(path.join(work, "rules/syft.yaml")) &&
            existsSync(path.join(work, "rules/trivy.yaml")),
          "the platform rules must be copied",
        );
        ok(
          p,
          readFileSync(path.join(work, "rules/syft.yaml"), "utf8") ===
            readFileSync(path.join(SBOM_SRC, "rules/syft.yaml"), "utf8"),
          "the syft rules copy must equal the platform file",
        );
        // ---- dry run
        const dry = exec("run", "--work", work, "--dry-run");
        const blocks = dry
          .split(/^# /m)
          .filter(Boolean)
          .map((b) => {
            const [id, cmd] = b.trim().split("\n");
            return { id, argv: cmd.split(" ") };
          });
        const idsExpected = [
          "syft-version",
          "trivy-version",
          "syft-sealed",
          "trivy-sealed",
          "syft-planted",
          "trivy-planted",
          "syft-config-missing",
          "trivy-config-missing",
          "syft-config-unknown-key",
          "trivy-config-unknown-key",
          "syft-unknown-flag",
          "trivy-unknown-flag",
          "syft-nolock",
          "trivy-nolock",
          "syft-jar",
          "trivy-jar",
          "syft-oom",
          "trivy-oom",
          "trivy-vuln-nodb",
          "trivy-vuln-skipdb",
        ];
        same(
          p,
          "dry-run experiment ids",
          blocks.map((b) => b.id),
          idsExpected,
        );
        const config = validateSandboxConfig({
          runtimeBin: "docker",
          containerUser: "65534:65534",
          usernsMode: null,
          mountRoots: { archive: [path.join(work, "trees")], db: [], rules: [work] },
          egressNetworks: {},
        });
        for (const b of blocks) {
          ok(p, b.argv[0] === "docker" && b.argv[1] === "run", `${b.id}: not a docker run`);
          const args = b.argv.slice(1);
          const problems = findRunArgsProblems(args, config);
          ok(p, problems.length === 0, `${b.id}: audit problems ${JSON.stringify(problems)}`);
          for (const flag of [
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65534:65534",
            "--pull=never",
          ])
            ok(p, args.includes(flag), `${b.id}: missing ${flag}`);
          ok(
            p,
            args.filter((a) => a.startsWith("--mount=")).every((a) => a.endsWith(",readonly")),
            `${b.id}: a writable mount`,
          );
          ok(
            p,
            args.some((a) => a.startsWith("--tmpfs=/tmp:rw,noexec,nosuid,nodev")),
            `${b.id}: tmpfs`,
          );
          ok(
            p,
            args.some((a) => /@sha256:[0-9a-f]{64}$/.test(a)),
            `${b.id}: not digest pinned`,
          );
        }
        const tail = (id, n) => blocks.find((b) => b.id === id).argv.slice(-n);
        same(p, "syft sealed vector", tail("syft-sealed", SYFT_ARGV.length), [...SYFT_ARGV]);
        same(p, "trivy sealed vector", tail("trivy-sealed", TRIVY_SBOM_ARGV.length), [
          ...TRIVY_SBOM_ARGV,
        ]);
        same(p, "unknown flag adds one flag", tail("syft-unknown-flag", SYFT_ARGV.length + 1), [
          ...SYFT_ARGV,
          "--qm-no-such-flag",
        ]);
        ok(
          p,
          blocks.find((b) => b.id === "trivy-config-missing").argv.includes("/rules/missing.yaml"),
          "config-missing must name a missing file",
        );
        ok(
          p,
          blocks
            .find((b) => b.id === "syft-config-unknown-key")
            .argv.some((a) => a.includes("/rules-bad,dst=/rules")),
          "unknown-key must mount rules-bad",
        );
        ok(
          p,
          blocks
            .find((b) => b.id === "syft-planted")
            .argv.some((a) => a.includes("/trees/planted,dst=/src")),
          "planted must mount the planted tree",
        );
        const images = exec("images");
        for (const [key, repo] of [
          ["syft", "anchore/syft"],
          ["trivy", "aquasec/trivy"],
        ])
          ok(
            p,
            images.includes(`docker pull ${repo}@${digestOf(key)}`),
            `images must print the pull of ${key}`,
          );
        ok(
          p,
          versionOf("syft") === "1.57.2" && versionOf("trivy") === "0.76.2",
          "the locked versions changed: update the runbook and the fixtures",
        );
        // refusals of the tool
        const refused = spawnSync(process.execPath, [cli, "prepare", "--work", work, "--sample"], {
          encoding: "utf8",
        });
        ok(p, refused.status === 2, "prepare must refuse an existing directory");
        const noPrep = spawnSync(
          process.execPath,
          [cli, "run", "--work", path.join(tmp, "none"), "--out", path.join(tmp, "o")],
          { encoding: "utf8" },
        );
        ok(
          p,
          noPrep.status === 2 && !existsSync(path.join(tmp, "o")),
          "run must refuse an unprepared work directory and write nothing",
        );
        const src = readFileSync(cli, "utf8");
        ok(
          p,
          !/\bshell\s*:\s*true\b|\bexec\s*\(|execSync|spawnSync\(\s*`|sh -c|bash -c/.test(src),
          "the capture tool must not use a shell",
        );
        ok(
          p,
          !/process\.env\.[A-Z_]*TOKEN|GITHUB_TOKEN|Authorization/.test(src),
          "the capture tool must not handle tokens",
        );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return p;
    },
  },
];
