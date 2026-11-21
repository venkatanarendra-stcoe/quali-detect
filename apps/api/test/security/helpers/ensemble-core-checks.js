import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CONFIDENCES,
  DEFERRED_TOOL_IDS,
  detailExtraSchema,
  ENSEMBLE_RESULT_SCHEMA_VERSION,
  FINDING_LIMITS,
  jsonbTextBytes,
  ENSEMBLE_TOOL_IDS,
  EXCLUDED_TOOL_IDS,
  SEVERITIES,
  candidateSchema,
  findingSchema,
  highestSeverity,
  normalizeConfidence,
  normalizeSeverity,
  raiseConfidence,
  rollUpTask,
  severityFromCvssScore,
  severityOfSecretType,
  toolReasonClass,
} from "@qmentisai/shared";
import {
  ToolOutputError,
  canonicalAdvisory,
  canonicalPurl,
  createAdapterRegistry,
  createTaskFingerprinter,
  defineToolAdapter,
  detailRowBytes,
  findingToDetail,
  findingToItem,
  scrubDeep,
  mergeTaskCandidates,
  normalizeAdvisoryId,
  parseBoundedJson,
  recordsOf,
  runToolParse,
  sastRuleClass,
  toStorageRows,
} from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import { DIGEST, TASK_A, TASK_B, ctxFor, fakeAdapter, out } from "./ensemble-fakes.js";

/**
 * Scan engines, part D (ADR-008 area 18, SPEC scan-engines 14.1 ENG-S05, S06, S09, S11 and 16.1 part D): the adapter / mapper /
 * merger framework with FAKE adapters and scripted outputs. Pure functions only: no container, process, database, network or clock.
 * NOT proved: that a real tool's output has the shape of the fake records (parts E to I, ENG-L11), tool quality, rule content or the
 * exact severity tables and tolerances (out of scope by ADR-008; only the POLICY is asserted: unknown becomes medium with the
 * flag, the highest severity wins, SAST and secrets are never critical by default).
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const CORE_DIR = path.join(ROOT, "apps/workers/src/execution/engines/ensemble/core");
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const throwsCode = (fn) => {
  try {
    fn();
  } catch (e) {
    return e?.code ?? e?.reason ?? `non-coded ${e?.name}`;
  }
  return null;
};

const TRIVY = fakeAdapter("trivy", "sca");
const OSV = fakeAdapter("osv-scanner", "sca");
const OPENGREP = fakeAdapter("opengrep", "sast");
const BANDIT = fakeAdapter("bandit", "sast");
const GOSEC = fakeAdapter("gosec", "sast");
const GITLEAKS = fakeAdapter("gitleaks", "secrets");
const DETECT = fakeAdapter("detect-secrets", "secrets", { fingerprintField: "secret" });
const SYFT = fakeAdapter("syft", "sbom");
const TRIVY_SBOM = fakeAdapter("trivy", "sbom");

const parse = (adapter, records, task = TASK_A, ctx = {}, limits) =>
  runToolParse(adapter, out(records), ctxFor(task, ctx), limits);
const cands = (adapter, records, task = TASK_A, ctx = {}) => {
  const r = parse(adapter, records, task, ctx);
  if (r.candidates.length !== records.length)
    throw new Error(`fixture dropped records (${r.status}/${r.reason})`);
  return r.candidates;
};
const merge = (scanType, candidates, taskRef = TASK_A) =>
  mergeTaskCandidates({ taskRef, scanType, candidates }).findings;
const deepFreeze = (v) => {
  if (v && typeof v === "object" && !Object.isFrozen(v)) {
    Object.freeze(v);
    for (const x of Object.values(v)) deepFreeze(x);
  }
  return v;
};
const shuffle = (list, seed) => {
  const a = [...list];
  let s = seed;
  for (let i = a.length - 1; i > 0; i -= 1) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const j = s % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
};
const listJs = (dir) =>
  readdirSync(dir).flatMap((n) => {
    const full = path.join(dir, n);
    return statSync(full).isDirectory() ? listJs(full) : n.endsWith(".js") ? [full] : [];
  });

const LODASH = "pkg:npm/lodash@4.17.20";

export const ENSEMBLE_CORE_CHECKS = [
  {
    id: "ENG-S06a",
    name: "merging never crosses a boundary (SPEC scan-engines SE-10, SE-12, SE-15, ER-26, ADR-004, ENG-S06): the merger takes the candidates of ONE task and REFUSES (throws, never merges or silently drops) a candidate of another task, of another scan type or an invalid one; identical candidates of two tasks (so of two tenants, two pipelines or two executions) give separate findings in separate calls; two candidates of the SAME tool are never merged even with an equal key, different scan types are never merged, the union-find guard refuses to join two primary ids of one tool for one component; the merger keeps no module-level state (source guard), does not mutate its frozen input and gives identical output for any input order; a dedupKey is a merge key and is not an identity field of the finding",
    async run() {
      const p = [];
      const rec = {
        id: "CVE-2021-23337",
        aliases: ["GHSA-35jh-r3h4-6jhm"],
        purl: LODASH,
        severity: "HIGH",
      };
      const a = [
        ...cands(TRIVY, [rec], TASK_A),
        ...cands(OSV, [{ ...rec, id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"] }], TASK_A),
      ];
      // control: one task, two tools, one finding with two provenance entries
      const control = merge("sca", a);
      ok(
        p,
        control.length === 1 && control[0].provenance.length === 2,
        "control: two tools of one task did not merge",
      );
      // another task in the call
      const b = cands(
        OSV,
        [{ ...rec, id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"] }],
        TASK_B,
      );
      ok(
        p,
        throwsCode(() => merge("sca", [...a, ...b], TASK_A)) === "task_mismatch",
        "a candidate of another task was not refused",
      );
      ok(
        p,
        throwsCode(() => merge("sca", a, TASK_B)) === "task_mismatch",
        "the task reference of the call is not enforced",
      );
      // identical inputs in two tasks give two separate results
      const bFull = [...cands(TRIVY, [rec], TASK_B), ...b];
      const inA = merge("sca", a, TASK_A);
      const inB = merge("sca", bFull, TASK_B);
      ok(
        p,
        inA.length === 1 &&
          inB.length === 1 &&
          inA[0].provenance.length === 2 &&
          inB[0].provenance.length === 2,
        "two tasks did not produce two findings",
      );
      ok(
        p,
        inA[0].provenance.every(
          (x) => !inB[0].provenance.some((y) => y.rawRef.toolRunId === x.rawRef.toolRunId),
        ),
        "provenance leaked between tasks",
      );
      // scan types never mix
      const secret = cands(GITLEAKS, [
        {
          id: "aws",
          path: "a.env",
          line: 1,
          typeClass: "aws_access_key",
          secret: "AKIAABCDEFGHIJKLMNOP",
        },
      ]);
      const sast = cands(BANDIT, [
        { id: "B105", path: "a.env", line: 1, severity: "HIGH", cwe: [798] },
      ]);
      ok(
        p,
        throwsCode(() => merge("sast", [...sast, ...secret])) === "scan_type_mismatch",
        "a secret candidate entered a SAST merge",
      );
      ok(
        p,
        merge("sast", sast).length === 1 && merge("secrets", secret).length === 1,
        "control: the two scan types do not merge on their own",
      );
      ok(
        p,
        throwsCode(() => merge("sca", [{ ...a[0], title: "" }])) === "candidate_invalid",
        "an invalid candidate was accepted",
      );
      ok(
        p,
        throwsCode(() =>
          mergeTaskCandidates({ taskRef: TASK_A, scanType: "license", candidates: [] }),
        ) === "input_invalid",
        "an unknown scan type was accepted",
      );
      ok(
        p,
        throwsCode(() => mergeTaskCandidates({ taskRef: 5, scanType: "sca", candidates: [] })) ===
          "input_invalid",
        "a bad task reference was accepted",
      );
      ok(p, merge("sca", []).length === 0, "an empty task");
      // same tool is never merged
      const twice = merge("sca", [
        ...cands(TRIVY, [rec, { ...rec }], TASK_A),
        ...cands(OSV, [{ ...rec, id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"] }]),
      ]);
      ok(
        p,
        twice.length === 2,
        `two Trivy records of one advisory merged: ${twice.length} findings`,
      );
      ok(
        p,
        twice.every((f) => new Set(f.provenance.map((x) => x.toolId)).size === f.provenance.length),
        "a finding holds two entries of one tool",
      );
      ok(
        p,
        twice.filter((f) => f.provenance.length === 2).length === 1,
        "the other tool joined both or neither",
      );
      // the guard: osv names two primary ids of trivy as aliases
      const guarded = merge("sca", [
        ...cands(TRIVY, [
          { id: "CVE-2020-0001", aliases: ["GHSA-aaaa-aaaa-aaaa"], purl: LODASH, severity: "HIGH" },
          { id: "CVE-2020-0002", aliases: ["GHSA-bbbb-bbbb-bbbb"], purl: LODASH, severity: "LOW" },
        ]),
        ...cands(OSV, [
          {
            id: "GHSA-aaaa-aaaa-aaaa",
            aliases: ["CVE-2020-0001", "CVE-2020-0002"],
            purl: LODASH,
            severity: "MODERATE",
          },
        ]),
      ]);
      ok(p, guarded.length === 2, `the union-find guard failed: ${guarded.length} findings`);
      ok(
        p,
        guarded.every(
          (f) => new Set(f.provenance.map((x) => x.toolId)).size === f.provenance.length,
        ),
        "the guard let one tool in twice",
      );
      ok(
        p,
        guarded.filter((f) => f.provenance.length === 2).length === 1,
        "the guard did not keep exactly one merge",
      );
      // components with another version or another purl never merge
      const versions = merge("sca", [
        ...cands(TRIVY, [{ ...rec }]),
        ...cands(OSV, [
          { id: "CVE-2021-23337", purl: "pkg:npm/lodash@4.17.21" },
          { id: "CVE-2021-23337", purl: "pkg:npm/underscore@4.17.20" },
        ]),
      ]);
      ok(p, versions.length === 3, `different versions or packages merged: ${versions.length}`);
      // no module-level state and no mutation of the input, any order gives the same output
      for (const file of listJs(CORE_DIR)) {
        const src = readFileSync(file, "utf8");
        ok(p, !/^(let|var)\s/m.test(src), `${path.basename(file)}: a top-level mutable binding`);
        if (path.basename(file) === "merger.js")
          ok(
            p,
            !/^const\s+\w+\s*=\s*(new (Map|Set|WeakMap)|\[\]|\{\})/m.test(src),
            "merger.js: module-level state",
          );
      }
      const frozen = deepFreeze(structuredClone(a));
      const first = JSON.stringify(merge("sca", frozen));
      for (const seed of [1, 2, 3, 4, 5, 6, 7, 8])
        ok(
          p,
          JSON.stringify(merge("sca", shuffle(a, seed))) === first,
          `output depends on input order (seed ${seed})`,
        );
      ok(
        p,
        JSON.stringify(merge("sca", frozen)) === first,
        "a second call over the same input differs",
      );
      // a finding has no identity field and the schema refuses one
      const f = control[0];
      ok(
        p,
        !("id" in f) && !("identity" in f) && !("fingerprint" in f),
        "a finding carries an identity field",
      );
      ok(
        p,
        !findingSchema.safeParse({ ...f, identity: "x" }).success &&
          !findingSchema.safeParse({ ...f, fingerprint: "ab".repeat(16) }).success,
        "the schema accepts an identity or fingerprint field",
      );
      ok(
        p,
        f.dedupKey.startsWith("sca|") && f.dedupKey === `sca|${LODASH}|CVE-2021-23337`,
        `dedupKey ${f.dedupKey}`,
      );
      return p;
    },
  },
  {
    id: "ENG-S06b",
    name: "merge behaviour per scan type, policy properties only (SPEC scan-engines 5.6, 5.7, SE-13, SE-14, D-5, ENG-S06): SBOM folds one component per canonical purl with the union of locations, the strongest scope and info severity, and drops a versionless declaration when a versioned one exists in the same directory; SCA merges by canonical purl and a transitive alias intersection with the CVE-over-GHSA canonical id, unions fixed versions and CWE and never joins different versions or packages; SAST merges by rule class (curated CWE equivalence, tool-specific class when there is no CWE), file and line overlap or tolerance anchored at the first member, never chaining far lines; Secrets merge by file, line and type, a generic type folds into a specific one, different fingerprints stay apart, never critical; the highest severity wins, the assumed flag stays only when every candidate at the winning severity was assumed, two distinct tools raise confidence one step capped at high with basis multi_tool, a single tool keeps its basis, provenance has one entry per tool, SAST is never critical by default",
    async run() {
      const p = [];
      // ---- SBOM
      const syft = cands(SYFT, [
        { purl: "pkg:npm/lodash@4.17.20", path: "a/package-lock.json", scope: "dev" },
        { purl: "pkg:npm/express", path: "a/package.json" },
        { purl: "pkg:npm/express", path: "b/package.json" },
        { purl: "pkg:maven/org.Foo/Bar@1.0", path: "pom.xml" },
      ]);
      const trivySbom = cands(TRIVY_SBOM, [
        { purl: "pkg:npm/Lodash@v4.17.20", path: "a/package.json", scope: "prod" },
        { purl: "pkg:npm/express@4.18.0", path: "a/package-lock.json" },
        { purl: "pkg:maven/org.foo/bar@1.0", path: "pom.xml" },
      ]);
      const sbom = merge("sbom", [...syft, ...trivySbom]);
      const lodash = sbom.find((f) => f.component.name === "lodash");
      ok(
        p,
        lodash && lodash.provenance.length === 2 && lodash.component.scope === "prod",
        "SBOM: lodash did not fold with the strongest scope",
      );
      ok(
        p,
        lodash &&
          lodash.locations.length === 2 &&
          lodash.locationCount === 2 &&
          lodash.locations[0].path < lodash.locations[1].path,
        "SBOM: locations are not the sorted union",
      );
      ok(
        p,
        lodash &&
          lodash.severity === "info" &&
          lodash.kind === "component" &&
          lodash.confidenceBasis === "multi_tool",
        "SBOM: kind, severity or basis",
      );
      const express = sbom.filter((f) => f.component.name === "express");
      ok(
        p,
        express.length === 2 &&
          express.some((f) => f.component.version === "4.18.0") &&
          express.some((f) => !f.component.version),
        "SBOM: the declaration in directory a was not dropped or the one in b was lost",
      );
      ok(
        p,
        sbom.filter((f) => f.component.name.toLowerCase() === "bar").length === 2,
        "SBOM: maven names are case sensitive and must stay two components",
      );
      // ---- SCA
      const sca = merge("sca", [
        ...cands(TRIVY, [
          {
            id: "GHSA-35jh-r3h4-6jhm",
            aliases: ["CVE-2021-23337"],
            purl: LODASH,
            severity: "UNKNOWN",
            fixed: ["4.17.21"],
            cwe: [77, 94],
          },
        ]),
        ...cands(OSV, [
          {
            id: "cve-2021-23337",
            purl: LODASH,
            severity: "MODERATE",
            fixed: ["4.17.21", "4.18.0"],
            cwe: [77],
          },
        ]),
      ]);
      ok(p, sca.length === 1, `SCA: ${sca.length} findings`);
      ok(
        p,
        sca[0]?.rule.id === "CVE-2021-23337" &&
          sca[0].advisories[0].id === "CVE-2021-23337" &&
          sca[0].advisories.some((a) => a.id === "GHSA-35jh-r3h4-6jhm"),
        "SCA: canonical advisory is not CVE first",
      );
      ok(
        p,
        sca[0]?.severity === "medium" && sca[0].severityAssumed === false,
        "SCA: an unknown (assumed medium) and a real medium must give a confirmed medium",
      );
      ok(
        p,
        JSON.stringify(sca[0]?.fix?.fixedVersions) === '["4.17.21","4.18.0"]' &&
          JSON.stringify(sca[0]?.cwe) === "[77,94]",
        "SCA: fixed versions or CWE are not the sorted union",
      );
      const bothUnknown = merge("sca", [
        ...cands(TRIVY, [{ id: "CVE-1-1", purl: LODASH, severity: "UNKNOWN" }]),
        ...cands(OSV, [{ id: "CVE-1-1", purl: LODASH, severity: "weird" }]),
      ]);
      ok(
        p,
        bothUnknown[0].severity === "medium" && bothUnknown[0].severityAssumed === true,
        "SCA: unknown from every tool must stay medium with the unmapped flag",
      );
      const wins = merge("sca", [
        ...cands(TRIVY, [{ id: "CVE-9-9", purl: LODASH, severity: "UNKNOWN" }]),
        ...cands(OSV, [{ id: "CVE-9-9", purl: LODASH, severity: "LOW" }]),
      ]);
      ok(
        p,
        wins[0].severity === "medium" && wins[0].severityAssumed === true,
        "SCA: assumed medium must beat a real low and keep the flag",
      );
      const highest = merge("sca", [
        ...cands(TRIVY, [{ id: "CVE-8-8", purl: LODASH, severity: "CRITICAL" }]),
        ...cands(OSV, [{ id: "CVE-8-8", purl: LODASH, severity: "LOW" }]),
      ]);
      ok(
        p,
        highest[0].severity === "critical" &&
          highest[0].confidence === "high" &&
          highest[0].confidenceBasis === "multi_tool",
        "SCA: highest severity, confidence step or basis",
      );
      const apart = merge("sca", [
        ...cands(TRIVY, [{ id: "CVE-7-7", purl: LODASH, severity: "LOW" }]),
        ...cands(OSV, [{ id: "CVE-7-8", purl: LODASH, severity: "LOW" }]),
      ]);
      ok(p, apart.length === 2, "SCA: advisories with no common alias merged");
      const chain = merge("sca", [
        ...cands(TRIVY, [
          { id: "CVE-6-1", aliases: ["GHSA-1111-1111-1111"], purl: LODASH, severity: "LOW" },
        ]),
        ...cands(OSV, [
          { id: "GHSA-1111-1111-1111", aliases: ["PYSEC-2020-1"], purl: LODASH, severity: "LOW" },
        ]),
      ]);
      ok(
        p,
        chain.length === 1 && chain[0].rule.id === "CVE-6-1",
        "SCA: a shared alias did not merge",
      );
      ok(
        p,
        chain[0]?.confidence === "high",
        "SCA: a medium-confidence agreement by two tools must rise to high",
      );
      // ---- SAST
      const sast = (extra) => merge("sast", extra);
      const x = sast([
        ...cands(OPENGREP, [
          {
            id: "xss.rule",
            path: "src/a.js",
            line: 10,
            severity: "ERROR",
            cwe: [79],
            confidence: "HIGH",
          },
        ]),
        ...cands(BANDIT, [
          {
            id: "B703",
            path: "src/a.js",
            line: 12,
            severity: "MEDIUM",
            cwe: [80],
            confidence: "LOW",
          },
        ]),
      ]);
      ok(
        p,
        x.length === 1 &&
          x[0].location.startLine === 10 &&
          x[0].location.endLine === 12 &&
          x[0].severity === "high",
        "SAST: XSS siblings within the tolerance did not merge into one range at the highest severity",
      );
      ok(
        p,
        x[0]?.title === "xss.rule" && x[0].cwe.join() === "79,80" && x[0].kind === "code_issue",
        "SAST: title is not the highest-confidence tool's or CWE not the union",
      );
      ok(p, x[0]?.dedupKey === "sast|src/a.js|CWE-79|10", `SAST: dedupKey ${x[0]?.dedupKey}`);
      ok(
        p,
        sast([
          ...cands(OPENGREP, [
            { id: "r", path: "src/a.js", line: 10, severity: "ERROR", cwe: [79] },
          ]),
          ...cands(BANDIT, [{ id: "b", path: "src/a.js", line: 14, severity: "ERROR", cwe: [79] }]),
        ]).length === 2,
        "SAST: lines 4 apart merged",
      );
      ok(
        p,
        sast([
          ...cands(OPENGREP, [{ id: "r", path: "src/a.js", line: 10, severity: "ERROR" }]),
          ...cands(BANDIT, [{ id: "r", path: "src/a.js", line: 10, severity: "ERROR" }]),
        ]).length === 2,
        "SAST: candidates with no CWE merged across tools",
      );
      ok(
        p,
        sast([
          ...cands(OPENGREP, [
            { id: "r", path: "src/a.js", line: 10, severity: "ERROR", cwe: [79] },
          ]),
          ...cands(BANDIT, [{ id: "b", path: "src/b.js", line: 10, severity: "ERROR", cwe: [79] }]),
        ]).length === 2,
        "SAST: two files merged",
      );
      ok(
        p,
        sast([
          ...cands(OPENGREP, [
            { id: "r", path: "src/a.js", line: 10, severity: "ERROR", cwe: [79] },
          ]),
          ...cands(BANDIT, [{ id: "b", path: "src/a.js", line: 10, severity: "ERROR", cwe: [89] }]),
        ]).length === 2,
        "SAST: two rule classes merged",
      );
      const noChain = sast([
        ...cands(OPENGREP, [{ id: "r", path: "src/a.js", line: 10, severity: "ERROR", cwe: [79] }]),
        ...cands(BANDIT, [{ id: "b", path: "src/a.js", line: 13, severity: "ERROR", cwe: [79] }]),
        ...cands(GOSEC, [{ id: "g", path: "src/a.js", line: 16, severity: "ERROR", cwe: [79] }]),
      ]);
      ok(
        p,
        noChain.length === 2 &&
          noChain.some((f) => f.provenance.length === 2) &&
          noChain.some((f) => f.location.startLine === 16),
        `SAST: far lines chained (${noChain.length} findings)`,
      );
      ok(
        p,
        sast([
          ...cands(OPENGREP, [
            { id: "r", path: "src/a.js", line: 10, endLine: 30, severity: "ERROR", cwe: [79] },
          ]),
          ...cands(BANDIT, [{ id: "b", path: "src/a.js", line: 25, severity: "ERROR", cwe: [79] }]),
        ]).length === 1,
        "SAST: overlapping ranges did not merge",
      );
      ok(
        p,
        sast(
          cands(OPENGREP, [
            { id: "r", path: "a.js", line: 1, severity: "ERROR" },
            { id: "w", path: "a.js", line: 99, severity: "WARNING" },
            { id: "i", path: "a.js", line: 98, severity: "INFO" },
          ]),
        ).every((f) => f.severity !== "critical"),
        "SAST: a critical finding without a platform rule",
      );
      ok(
        p,
        sastRuleClass([89], "bandit", "x") === sastRuleClass([564], "opengrep", "y") &&
          sastRuleClass(undefined, "bandit", "B1") === "tool:bandit:B1",
        "SAST: rule class table",
      );
      // ---- Secrets
      const aws = {
        id: "aws",
        path: "src/config/prod.env",
        line: 12,
        typeClass: "aws_access_key",
        secret: "AKIAEXAMPLEEXAMPLE12",
        previewHint: "AKIA",
      };
      const s1 = merge("secrets", [
        ...cands(GITLEAKS, [aws]),
        ...cands(DETECT, [{ ...aws, id: "AWSKeyDetector" }]),
      ]);
      ok(
        p,
        s1.length === 1 &&
          s1[0].dedupKey === "secrets|src/config/prod.env|12|aws_access_key" &&
          s1[0].severity === "high" &&
          s1[0].confidenceBasis === "multi_tool",
        "Secrets: two tools on one location did not merge",
      );
      const s2 = merge("secrets", [
        ...cands(GITLEAKS, [{ ...aws, typeClass: "generic_api_key", secret: "x".repeat(20) }]),
        ...cands(DETECT, [aws]),
      ]);
      ok(
        p,
        s2.length === 1 && s2[0].dedupKey.endsWith("|aws_access_key"),
        "Secrets: a generic type did not fold into the specific one",
      );
      const s3 = merge("secrets", [
        ...cands(GITLEAKS, [aws]),
        ...cands(DETECT, [{ ...aws, typeClass: "jwt" }]),
      ]);
      ok(p, s3.length === 2, "Secrets: two specific types on one line merged");
      const s4 = merge("secrets", [
        ...cands(GITLEAKS, [aws]),
        ...cands(DETECT, [{ ...aws, line: 13 }]),
      ]);
      ok(p, s4.length === 2, "Secrets: lines 12 and 13 merged (tolerance is 0)");
      // fingerprints: detect-secrets fingerprints the value; the same value on one line merges, another value stays apart
      const fp = createTaskFingerprinter();
      const d1 = cands(DETECT, [aws], TASK_A, { fingerprinter: fp });
      const d2 = cands(DETECT, [aws], TASK_A, { fingerprinter: fp }).map((c) => ({
        ...c,
        provenance: [{ ...c.provenance[0], toolId: "gitleaks" }],
        rule: { ...c.rule, tool: "gitleaks" },
      }));
      ok(
        p,
        d1[0].mergeHints.fingerprint && /^[0-9a-f]{32}$/.test(d1[0].mergeHints.fingerprint),
        "Secrets: no in-task fingerprint",
      );
      ok(
        p,
        merge("secrets", [...d1, ...d2]).length === 1,
        "Secrets: equal fingerprints did not merge",
      );
      const other = cands(DETECT, [{ ...aws, secret: "AKIAOTHEROTHEROTHER12" }], TASK_A, {
        fingerprinter: fp,
      }).map((c) => ({
        ...c,
        provenance: [{ ...c.provenance[0], toolId: "gitleaks" }],
        rule: { ...c.rule, tool: "gitleaks" },
      }));
      ok(
        p,
        merge("secrets", [...d1, ...other]).length === 2,
        "Secrets: different fingerprints merged",
      );
      ok(
        p,
        createTaskFingerprinter()("v") !== createTaskFingerprinter()("v"),
        "Secrets: the fingerprint key is not per task",
      );
      ok(
        p,
        [...s1, ...s2, ...s3, ...s4].every(
          (f) =>
            f.severity !== "critical" &&
            !("mergeHints" in f) &&
            !JSON.stringify(f).includes("fingerprint"),
        ),
        "Secrets: critical severity or a fingerprint in a finding",
      );
      // ---- confidence and basis
      ok(
        p,
        JSON.stringify(CONFIDENCES.map(raiseConfidence)) === '["medium","high","high"]',
        "confidence step is not low to medium to high, capped",
      );
      const single = merge(
        "sca",
        cands(TRIVY, [{ id: "CVE-5-5", purl: LODASH, severity: "HIGH", confidence: "LOW" }]),
      );
      ok(
        p,
        single[0].confidence === "low" &&
          single[0].confidenceBasis === "tool" &&
          single[0].provenance.length === 1,
        "a single tool must keep its confidence and basis",
      );
      return p;
    },
  },
  {
    id: "ENG-S06c",
    name: "merge keys and normalization (SPEC scan-engines 5.6.1, 5.6.2, OQ-5, D-5): the purl parser canonicalizes the type, the npm / pypi / golang name rules, the v prefix only for npm and pypi (never golang), keeps the qualifiers classifier, type, arch and distro and drops repository_url, download_url, vcs_url, checksum and subpath, keeps maven case, sorts qualifiers, and refuses an over-long purl (501 characters), a control character, a missing type or name and an undecodable segment; advisory ids are normalized (CVE upper case, GHSA body lower case, ecosystem ids upper case, vendor ids as given, junk refused) and the canonical id priority is CVE, GHSA, ecosystem, OSV, other; the SAST equivalence table groups the siblings of the SPEC; keys are deterministic strings that start with the scan type",
    async run() {
      const p = [];
      const eq = (a, b, msg) =>
        ok(
          p,
          canonicalPurl(a)?.canonical === canonicalPurl(b)?.canonical && canonicalPurl(a) !== null,
          `${msg}: ${canonicalPurl(a)?.canonical} vs ${canonicalPurl(b)?.canonical}`,
        );
      const ne = (a, b, msg) =>
        ok(p, canonicalPurl(a)?.canonical !== canonicalPurl(b)?.canonical, msg);
      eq(
        "pkg:NPM/%40Angular/Core@v12.0.0",
        "pkg:npm/%40angular/core@12.0.0",
        "npm case and v prefix",
      );
      eq("pkg:pypi/Foo_Bar.Baz@1.0", "pkg:pypi/foo-bar-baz@1.0", "pypi name");
      ne(
        "pkg:golang/github.com/Foo/Bar@v1.0.0",
        "pkg:golang/github.com/foo/bar@1.0.0",
        "golang keeps the v prefix",
      );
      eq(
        "pkg:golang/github.com/Foo/Bar@v1.0.0",
        "pkg:golang/github.com/foo/bar@v1.0.0",
        "golang name is lower case",
      );
      ne("pkg:maven/org.Foo/Bar@1.0", "pkg:maven/org.foo/bar@1.0", "maven keeps case");
      eq(
        "pkg:maven/org.foo/bar@1.0?repository_url=https://x&download_url=y&checksum=z&vcs_url=v#sub/path",
        "pkg:maven/org.foo/bar@1.0",
        "dropped qualifiers and subpath",
      );
      ne(
        "pkg:maven/org.foo/bar@1.0?classifier=sources",
        "pkg:maven/org.foo/bar@1.0",
        "classifier is kept",
      );
      eq(
        "pkg:deb/debian/curl@7.0?distro=bookworm&arch=amd64",
        "pkg:deb/debian/curl@7.0?arch=amd64&distro=bookworm",
        "qualifiers are sorted",
      );
      ne(
        "pkg:deb/debian/curl@7.0?distro=bookworm",
        "pkg:deb/debian/curl@7.0?distro=bullseye",
        "distro is kept",
      );
      ok(
        p,
        canonicalPurl("pkg:npm/lodash").version === null &&
          canonicalPurl("pkg:npm/lodash").unversioned === "pkg:npm/lodash",
        "unversioned form",
      );
      for (const [label, bad] of [
        ["501 characters", `pkg:npm/${"a".repeat(493)}`],
        ["control character", "pkg:npm/lo\u0001dash@1"],
        ["no scheme", "npm/lodash@1"],
        ["no name", "pkg:npm/"],
        ["no type", "pkg:/lodash"],
        ["bad type", "pkg:1x/lodash"],
        ["undecodable", "pkg:npm/%E0%A4%A@1"],
        ["empty", ""],
        ["not a string", 5],
      ])
        ok(p, canonicalPurl(bad) === null, `purl accepted: ${label}`);
      ok(
        p,
        canonicalPurl(`pkg:npm/${"a".repeat(492)}`) !== null &&
          `pkg:npm/${"a".repeat(492)}`.length === 500,
        "a 500 character purl must be accepted",
      );
      const adv = (id) => normalizeAdvisoryId(id);
      ok(
        p,
        adv("cve-2021-23337")?.id === "CVE-2021-23337" &&
          adv("GHSA-35JH-R3H4-6JHM")?.id === "GHSA-35jh-r3h4-6jhm" &&
          adv("ghsa-35jh-r3h4-6jhm")?.id === "GHSA-35jh-r3h4-6jhm" &&
          adv("Ghsa-35Jh-R3h4-6jHm")?.id === "GHSA-35jh-r3h4-6jhm" &&
          adv("go-2021-0001")?.id === "GO-2021-0001",
        "advisory normalization",
      );
      ok(
        p,
        adv("pysec-2020-1")?.family === "PYSEC" &&
          adv("osv-2020-1")?.family === "OSV" &&
          adv("RHSA-2020:1234")?.id === "RHSA-2020:1234" &&
          adv("RHSA-2020:1234")?.family === "OTHER",
        "advisory families",
      );
      for (const bad of ["", " ", "a b", "x".repeat(61), "CVE-\n1", 5, null, "-CVE-1"])
        ok(p, adv(bad) === null, `advisory id accepted: ${JSON.stringify(bad)}`);
      const order = (ids) => canonicalAdvisory(ids.map(adv)).id;
      ok(
        p,
        order(["GHSA-aaaa-bbbb-cccc", "CVE-2020-1", "OSV-1"]) === "CVE-2020-1" &&
          order(["OSV-1", "GO-2020-1", "RHSA-1"]) === "GO-2020-1" &&
          order(["RHSA-1", "OSV-1"]) === "OSV-1" &&
          order(["GHSA-aaaa-bbbb-cccc", "GO-1"]) === "GHSA-aaaa-bbbb-cccc",
        "canonical advisory priority",
      );
      for (const g of [
        [77, 78, 88],
        [89, 564],
        [79, 80],
        [22, 23, 36],
        [259, 321, 798],
        [326, 327, 328],
        [330, 338],
      ])
        ok(
          p,
          new Set(g.map((c) => sastRuleClass([c], "t", "r"))).size === 1,
          `CWE group ${g} is not one class`,
        );
      ok(
        p,
        new Set(
          [77, 89, 79, 22, 259, 502, 918, 601, 326, 330].map((c) => sastRuleClass([c], "t", "r")),
        ).size === 10,
        "unrelated CWE groups share a class",
      );
      ok(p, sastRuleClass([999], "t", "r") === "CWE-999", "an unlisted CWE is its own class");
      return p;
    },
  },
  {
    id: "ENG-S09a",
    name: "hostile tool output is contained (SPEC scan-engines 7.2, SE-4, ENG-S09): truncated, malformed, empty, non-JSON, wrong-shape, deeply nested (10000 levels, refused before JSON.parse), huge (over the byte cap), node-flood and million-record outputs, __proto__ / constructor / prototype keys at any depth, ANSI and bidi and control characters, invalid severities, NaN and negative and non-integer line numbers, duplicate records and a mapper that throws all end in a fixed status and reason (partial or failed with output_invalid, output_too_large or exit_code), with bounded time, no exception escaping, Object.prototype untouched, titles stripped of control and ANSI and with bidi characters shown as visible \\uXXXX, over 20 percent dropped records fail the tool and a smaller share only makes it partial, an unaccepted exit code fails without trusting the output, an adapter cannot claim another tool, task or scan type",
    async run() {
      const p = [];
      const good = { id: "CVE-1-1", purl: LODASH, severity: "HIGH" };
      const run = (stdout, over = {}) =>
        runToolParse(TRIVY, { stdout, exitCode: 0, ...over }, ctxFor());
      const t0 = Date.now();
      ok(
        p,
        run(Buffer.from(JSON.stringify([good]))).status === "succeeded",
        "control: a good output failed",
      );
      for (const [label, raw, reason] of [
        ["empty", Buffer.alloc(0), "output_invalid"],
        ["not JSON", Buffer.from("this is not json"), "output_invalid"],
        ["truncated", Buffer.from(JSON.stringify([good, good]).slice(0, 40)), "output_invalid"],
        ["an object, not a list", Buffer.from('{"a":1}'), "output_invalid"],
        ["null", Buffer.from("null"), "output_invalid"],
        ["unbalanced", Buffer.from("]]]["), "output_invalid"],
        ["10000 levels", Buffer.from("[".repeat(10000) + "]".repeat(10000)), "output_invalid"],
        ["65 levels", Buffer.from("[".repeat(65) + "]".repeat(65)), "output_invalid"],
      ]) {
        const r = run(raw);
        ok(
          p,
          r.status === "failed" && r.reason === reason && r.candidates.length === 0,
          `${label}: ${r.status}/${r.reason}`,
        );
      }
      // 60 levels is inside the depth cap: the array of empty arrays is a list of records that the record schema drops
      ok(
        p,
        run(Buffer.from(`[${"[".repeat(59)}${"]".repeat(59)}]`)).status === "failed",
        "a nested but bounded list",
      );
      const huge = Buffer.alloc(1024 * 1024 + 1, 0x20);
      const small = runToolParse(TRIVY, { stdout: huge, exitCode: 0 }, ctxFor(), {
        maxBytes: 1024 * 1024,
      });
      ok(
        p,
        small.status === "failed" && small.reason === "output_too_large",
        `over the byte cap: ${small.status}/${small.reason}`,
      );
      const cut = run(Buffer.from(JSON.stringify([good])), { truncated: true });
      ok(
        p,
        cut.status === "failed" && cut.reason === "output_too_large",
        "stdout cut by the capture cap was trusted",
      );
      const nodes = runToolParse(
        TRIVY,
        {
          stdout: Buffer.from(JSON.stringify(Array.from({ length: 50 }, () => ({ a: [1, 2, 3] })))),
          exitCode: 0,
        },
        ctxFor(),
        { maxNodes: 40 },
      );
      ok(
        p,
        nodes.status === "failed" && nodes.reason === "output_too_large",
        `node flood: ${nodes.status}/${nodes.reason}`,
      );
      const bad = run(Buffer.from(JSON.stringify([good])), { exitCode: 2 });
      ok(
        p,
        bad.status === "failed" && bad.reason === "exit_code" && bad.candidates.length === 0,
        "an unaccepted exit code was parsed",
      );
      ok(
        p,
        runToolParse(TRIVY, { stdout: Buffer.from("[]"), exitCode: null }, ctxFor()).reason ===
          "exit_code",
        "a killed tool (null exit code) was accepted",
      );
      // prototype pollution
      for (const key of ["__proto__", "constructor", "prototype"]) {
        for (const text of [
          `[{"${key}":{"polluted":"yes"}}]`,
          `[{"id":"CVE-1-1","x":{"y":[{"${key}":1}]}}]`,
        ]) {
          const r = run(Buffer.from(text));
          ok(
            p,
            r.status === "failed" && r.reason === "output_invalid",
            `${key}: ${r.status}/${r.reason}`,
          );
        }
      }
      ok(
        p,
        {}.polluted === undefined &&
          Object.prototype.polluted === undefined &&
          {}.yes === undefined,
        "Object.prototype was polluted",
      );
      ok(
        p,
        throwsCode(() => parseBoundedJson('{"a":{"__proto__":{"x":1}}}')) === "output_invalid",
        "the parse kit let a __proto__ key through",
      );
      ok(
        p,
        throwsCode(() => parseBoundedJson('{"\\u005f_proto__":{"x":1}}')) === "output_invalid",
        "an escaped __proto__ key got through",
      );
      // per-record containment
      const records = [
        good,
        {
          ...good,
          id: "CVE-2-2",
          title: "\u001b[31mred\u001b[0m\u0007 and \u202eevil\u202c \u200bzero",
        },
        { ...good, id: "CVE-3-3", severity: "NOT-A-SEVERITY" },
        { ...good, id: "CVE-4-4", purl: "not a purl" },
        { ...good, id: "CVE-5-5", extra: { nested: "stripped" } },
        { id: 7 },
        "a string",
        null,
        [],
        { ...good, id: "CVE-6-6", line: Number.NaN },
        { ...good, id: "CVE-7-7", line: -5 },
        { ...good, id: "CVE-8-8", line: 1.5 },
        { ...good },
        { ...good },
      ];
      const r = runToolParse(
        TRIVY,
        {
          stdout: Buffer.from(
            JSON.stringify(records, (k, v) =>
              typeof v === "number" && Number.isNaN(v) ? "NaN" : v,
            ),
          ),
          exitCode: 0,
        },
        ctxFor(),
      );
      ok(
        p,
        r.status === "failed" && r.reason === "output_invalid",
        `a mostly-bad output must fail (${r.status}, dropped ${r.recordsDropped}/${r.recordsSeen})`,
      );
      const mixed = [
        good,
        {
          ...good,
          id: "CVE-2-2",
          title: "\u001b[31mred\u001b[0m\u0007 and \u202eevil\u202c \u200bzero",
        },
        { ...good, id: "CVE-3-3", severity: "NOT-A-SEVERITY" },
        { ...good, id: "CVE-5-5", extra: { nested: "stripped" } },
        ...Array.from({ length: 6 }, (_, i) => ({ ...good, id: `CVE-9-${i}` })),
        { id: 7 },
      ];
      const m = run(Buffer.from(JSON.stringify(mixed)));
      ok(
        p,
        m.status === "partial" &&
          m.reason === "output_invalid" &&
          m.recordsDropped === 1 &&
          m.recordsSeen === 11 &&
          m.findingsMapped === 10,
        `a minor share dropped: ${m.status}/${m.recordsDropped}/${m.recordsSeen}`,
      );
      const titled = m.candidates.find((c) => c.rule.id === "CVE-2-2");
      ok(
        p,
        titled &&
          // eslint-disable-next-line no-control-regex -- the point of the check
          !/[\u0000-\u001f\u007f-\u009f]/.test(titled.title) &&
          !titled.title.includes("\u202e") &&
          titled.title.includes("\\u202e") &&
          titled.title.includes("\\u200b") &&
          !titled.title.includes("[31m"),
        `title not contained: ${JSON.stringify(titled?.title)}`,
      );
      const assumed = m.candidates.find((c) => c.rule.id === "CVE-3-3");
      ok(
        p,
        assumed && assumed.severity === "medium" && assumed.severityAssumed === true,
        "an invalid severity must become medium with the flag",
      );
      ok(p, !JSON.stringify(m.candidates).includes("stripped"), "unknown keys were not stripped");
      ok(
        p,
        m.candidates.every(
          (c) => c.taskRef === TASK_A && c.provenance[0].toolId === "trivy" && c.scanType === "sca",
        ),
        "provenance, task or scan type is not set from trusted context",
      );
      // duplicates are kept as separate candidates (the tool said so), bounded by maxRecords
      const dup = run(Buffer.from(JSON.stringify(Array.from({ length: 5 }, () => good))));
      ok(p, dup.status === "succeeded" && dup.candidates.length === 5, "duplicate records");
      const many = runToolParse(
        TRIVY,
        {
          stdout: Buffer.from(
            JSON.stringify(Array.from({ length: 1000 }, (_, i) => ({ ...good, id: `CVE-0-${i}` }))),
          ),
          exitCode: 0,
        },
        ctxFor(),
        { maxRecords: 100 },
      );
      ok(
        p,
        many.status === "partial" &&
          many.reason === "output_too_large" &&
          many.truncated === true &&
          many.candidates.length === 100 &&
          many.recordsSeen === 100,
        `record cap: ${many.status}/${many.candidates.length}`,
      );
      const million = `[${Array.from({ length: 200 }, () => "{}").join(",")}]`;
      ok(
        p,
        runToolParse(TRIVY, { stdout: Buffer.from(million), exitCode: 0 }, ctxFor(), {
          maxRecords: 50,
        }).status === "failed",
        "a flood of empty records must fail the tool",
      );
      // the real default cap: a million tiny records stay bounded in time and memory
      const flood = Buffer.from(`[${Array.from({ length: 1_000_000 }, () => "1").join(",")}]`);
      const heap0 = process.memoryUsage().heapUsed;
      const t2 = Date.now();
      const floodRun = runToolParse(TRIVY, { stdout: flood, exitCode: 0 }, ctxFor());
      ok(
        p,
        floodRun.status === "failed" &&
          floodRun.recordsSeen === 100000 &&
          floodRun.candidates.length === 0,
        `a million records: ${floodRun.status}/${floodRun.recordsSeen}`,
      );
      ok(
        p,
        Date.now() - t2 < 20000 && process.memoryUsage().heapUsed - heap0 < 400 * 1024 * 1024,
        "a million records used too much time or memory",
      );
      ok(p, Date.now() - t0 < 60000, "hostile output took unbounded time");
      // a throwing mapper, a mapper claiming another tool
      const boom = fakeAdapter("trivy", "sca", {
        map: () => {
          throw new Error("boom");
        },
      });
      const b = runToolParse(boom, out([good, good, good, good, good]), ctxFor());
      ok(
        p,
        b.status === "failed" && b.reason === "output_invalid" && b.recordsDropped === 5,
        "a throwing mapper escaped or was trusted",
      );
      const liar = fakeAdapter("trivy", "sca", {
        map: (rec, ctx) => {
          const c = TRIVY.map(rec, ctx);
          return {
            ...c,
            scanType: "secrets",
            taskRef: TASK_B,
            provenance: [
              {
                ...c.provenance[0],
                toolId: "gitleaks",
                toolVersion: "evil",
                imageDigestShort: "none",
              },
            ],
            rule: { id: c.rule.id, tool: "gitleaks" },
          };
        },
      });
      const l = runToolParse(liar, out([good]), ctxFor());
      ok(
        p,
        l.status === "succeeded" &&
          l.candidates[0].taskRef === TASK_A &&
          l.candidates[0].scanType === "sca" &&
          l.candidates[0].provenance[0].toolId === "trivy" &&
          l.candidates[0].provenance[0].toolVersion === "fake-1.0.0" &&
          l.candidates[0].rule.tool === "trivy" &&
          l.candidates[0].provenance[0].imageDigestShort === `sha256:${DIGEST.slice(7, 15)}`,
        "a mapper set its own provenance, task or scan type",
      );
      const returnsNull = fakeAdapter("trivy", "sca", { map: () => null });
      ok(
        p,
        runToolParse(returnsNull, out([good]), ctxFor()).status === "failed",
        "a null mapper result was kept",
      );
      const parseBoom = fakeAdapter("trivy", "sca", {
        parse: () => {
          throw new ToolOutputError("output_too_large", "x");
        },
      });
      ok(
        p,
        runToolParse(parseBoom, out([good]), ctxFor()).reason === "output_too_large",
        "a parse failure lost its fixed reason",
      );
      const parseRaw = fakeAdapter("trivy", "sca", {
        parse: () => {
          throw new RangeError("secret text of the tool");
        },
      });
      const pr = runToolParse(parseRaw, out([good]), ctxFor());
      ok(
        p,
        pr.reason === "output_invalid" && !JSON.stringify(pr).includes("secret text"),
        "an unexpected parse error leaked text",
      );
      // tool-reported paths that do not exist in the tree are dropped
      const withPath = [
        { id: "b", path: "../../etc/passwd", line: 1, severity: "HIGH" },
        { id: "c", path: "/abs/x.js", line: 1, severity: "HIGH" },
        { id: "d", path: "src/gone.js", line: 1, severity: "HIGH" },
        { id: "e", path: "a\\b.js", line: 1, severity: "HIGH" },
        ...Array.from({ length: 36 }, (_, i) => ({
          id: `ok${i}`,
          path: "src/a.js",
          line: i + 1,
          severity: "HIGH",
        })),
      ];
      const pathRun = runToolParse(
        BANDIT,
        out(withPath),
        ctxFor(TASK_A, { pathExists: (rel) => rel === "src/a.js" }),
      );
      ok(
        p,
        pathRun.status === "partial" &&
          pathRun.recordsDropped === 4 &&
          pathRun.candidates.every((c) => c.location.path === "src/a.js"),
        `tool-reported paths: ${pathRun.status}/${pathRun.recordsDropped}`,
      );
      ok(p, {}.polluted === undefined, "Object.prototype was polluted at the end");
      return p;
    },
  },
  {
    id: "ENG-S09b",
    name: "the normalized finding contract is strict and versioned (SPEC scan-engines 7.2, D-11, ENG-S09, ER-26): unknown keys, a wrong schemaVersion, a kind that does not belong to the scan type, a dedupKey not starting with the scan type, a component finding that is not info, a critical secret, an unsafe path (absolute, .., backslash, control character, empty segment), an over-long title, more than 6 provenance entries, a provenance entry over 600 bytes, evidence over 8 KiB, a multi_tool basis with one tool, a candidate with two provenance entries and a non-https url are all refused; the Grype tool is refused as an adapter, as a provenance entry and as an image key, and so are the excluded tools; an adapter must have a matching image key and a legal scan type; the registry selects in tool order and refuses duplicates",
    async run() {
      const p = [];
      const [f] = merge("sca", [
        ...cands(TRIVY, [
          { id: "CVE-1-1", aliases: ["GHSA-aaaa-bbbb-cccc"], purl: LODASH, severity: "HIGH" },
        ]),
        ...cands(OSV, [
          { id: "GHSA-aaaa-bbbb-cccc", aliases: ["CVE-1-1"], purl: LODASH, severity: "LOW" },
        ]),
      ]);
      const [sec] = merge(
        "secrets",
        cands(GITLEAKS, [
          {
            id: "aws",
            path: "a.env",
            line: 3,
            typeClass: "aws_access_key",
            secret: "AKIAEXAMPLEEXAMPLE12",
          },
        ]),
      );
      const [one] = merge("sca", cands(TRIVY, [{ id: "CVE-2-2", purl: LODASH, severity: "HIGH" }]));
      ok(
        p,
        findingSchema.safeParse(f).success &&
          findingSchema.safeParse(sec).success &&
          findingSchema.safeParse(one).success,
        "control: valid findings were refused",
      );
      const refuse = (label, value, schema = findingSchema) =>
        ok(p, !schema.safeParse(value).success, `accepted: ${label}`);
      refuse("unknown key", { ...one, extra: 1 });
      refuse("schemaVersion 2", { ...one, schemaVersion: 2 });
      refuse("schemaVersion 0", { ...one, schemaVersion: 0 });
      refuse("kind of another scan type", { ...one, kind: "secret" });
      refuse("unknown scan type", { ...one, scanType: "license" });
      refuse("license kind", { ...one, kind: "license" });
      refuse("dedupKey of another type", { ...one, dedupKey: `sast|${LODASH}` });
      refuse("unknown severity", { ...one, severity: "severe" });
      refuse("critical secret", { ...sec, severity: "critical" });
      refuse("secret without a path", { ...sec, location: { startLine: 3 } });
      refuse("secret with a component", { ...sec, component: one.component });
      refuse("component with no component", { ...one, component: undefined });
      refuse("preview on a non-secret", { ...one, preview: "abcd" });
      refuse("preview of 5 characters", { ...sec, preview: "abcde" });
      refuse("vulnerability without advisory", { ...one, advisories: [] });
      refuse("title over 200", { ...one, title: "x".repeat(201) });
      refuse("empty title", { ...one, title: "" });
      refuse("control character in title", { ...one, title: "a\u0000b" });
      refuse("dedupKey over 600", { ...one, dedupKey: `sca|${"x".repeat(600)}` });
      for (const bad of [
        "/etc/passwd",
        "../x",
        "a/../b",
        "a\\b",
        "a//b",
        "./a",
        "a/./b",
        "a\u0000b",
        "",
        "x".repeat(1025),
      ])
        refuse(`path ${JSON.stringify(bad).slice(0, 20)}`, { ...one, location: { path: bad } });
      ok(
        p,
        findingSchema.safeParse({ ...one, location: { path: "x".repeat(1024) } }).success,
        "a 1024 character path must be accepted",
      );
      refuse("seven provenance entries", {
        ...f,
        provenance: Array.from({ length: 7 }, () => f.provenance[0]),
      });
      refuse("no provenance", { ...f, provenance: [] });
      refuse("provenance entry over 600 bytes", {
        ...one,
        provenance: [
          {
            ...one.provenance[0],
            ruleId: '"'.repeat(200),
            severityRaw: "s".repeat(60),
            toolVersion: "v".repeat(100),
          },
        ],
      });
      refuse("multi_tool with one tool", { ...one, confidenceBasis: "multi_tool" });
      refuse("tool basis with two tools", { ...f, confidenceBasis: "tool" });
      refuse("grype in provenance", {
        ...one,
        provenance: [{ ...one.provenance[0], toolId: "grype" }],
      });
      refuse("grype scale", {
        ...one,
        provenance: [{ ...one.provenance[0], severityScale: "grype" }],
      });
      refuse("rule tool grype", { ...one, rule: { ...one.rule, tool: "grype" } });
      refuse("evidence over 8 KiB", {
        ...sec,
        evidence: {
          kind: "line",
          snippet: "x".repeat(4096),
          language: "l".repeat(30),
          nodeKind: "n".repeat(30),
          truncated: false,
          startLine: 1,
          endLine: 2,
          focusStart: 1,
          focusEnd: 2,
        },
        extra: 1,
      });
      refuse("evidence with a secret key", { ...sec, evidence: { kind: "line", secret: "x" } });
      refuse("http url", { ...one, url: "http://github.com/x" });
      refuse("javascript url", { ...one, url: "javascript:alert(1)" });
      ok(
        p,
        findingSchema.safeParse({
          ...one,
          url: "https://github.com/o/r/blob/" + "a".repeat(40) + "/x",
        }).success,
        "an https url must be accepted",
      );
      refuse(
        "candidate with two provenance entries",
        { ...cands(TRIVY, [{ id: "CVE-3-3", purl: LODASH }])[0], provenance: f.provenance },
        candidateSchema,
      );
      refuse(
        "candidate without task",
        { ...cands(TRIVY, [{ id: "CVE-3-3", purl: LODASH }])[0], taskRef: undefined },
        candidateSchema,
      );
      refuse(
        "candidate with multi_tool",
        { ...cands(TRIVY, [{ id: "CVE-3-3", purl: LODASH }])[0], confidenceBasis: "multi_tool" },
        candidateSchema,
      );
      ok(
        p,
        JSON.stringify(ENSEMBLE_TOOL_IDS).includes("sbom-lite") &&
          !ENSEMBLE_TOOL_IDS.includes("grype") &&
          DEFERRED_TOOL_IDS.join() === "grype",
        "tool id lists",
      );
      // adapters
      const spec = (over = {}) => ({
        toolId: "trivy",
        scanType: "sca",
        imageKey: "trivy",
        plan: () => ({}),
        parse: () => [],
        recordSchema: TRIVY.recordSchema,
        map: () => null,
        ...over,
      });
      ok(
        p,
        throwsCode(() => defineToolAdapter(spec({ toolId: "grype", imageKey: "grype" }))) ===
          "tool_deferred",
        "Grype was accepted as an adapter",
      );
      ok(
        p,
        throwsCode(() => fakeAdapter("grype", "sca")) === "tool_deferred",
        "Grype was accepted by the fake factory",
      );
      for (const id of EXCLUDED_TOOL_IDS)
        ok(
          p,
          throwsCode(() => defineToolAdapter(spec({ toolId: id, imageKey: id }))) ===
            "tool_excluded",
          `the excluded tool ${id} was accepted`,
        );
      ok(
        p,
        throwsCode(() => defineToolAdapter(spec({ toolId: "mystery", imageKey: "mystery" }))) ===
          "tool_unknown",
        "an unknown tool was accepted",
      );
      ok(
        p,
        throwsCode(() => defineToolAdapter(spec({ imageKey: "grype" }))) === "adapter_invalid",
        "an image key other than the tool id was accepted",
      );
      ok(
        p,
        throwsCode(() => defineToolAdapter(spec({ scanType: "sast" }))) === "adapter_invalid",
        "Trivy was accepted for SAST",
      );
      ok(
        p,
        throwsCode(() => defineToolAdapter(spec({ scanType: "license" }))) === "adapter_invalid",
        "an unknown scan type was accepted",
      );
      ok(
        p,
        throwsCode(() =>
          defineToolAdapter(spec({ toolId: "sbom-lite", scanType: "sbom", imageKey: "sbom-lite" })),
        ) === "adapter_invalid",
        "sbom-lite must have no image",
      );
      ok(
        p,
        defineToolAdapter(spec({ toolId: "sbom-lite", scanType: "sbom", imageKey: null }))
          .imageKey === null,
        "sbom-lite without image must be accepted",
      );
      for (const name of ["plan", "parse", "map"])
        ok(
          p,
          throwsCode(() => defineToolAdapter(spec({ [name]: "x" }))) === "adapter_invalid",
          `${name} not a function was accepted`,
        );
      ok(
        p,
        throwsCode(() => defineToolAdapter(spec({ recordSchema: {} }))) === "adapter_invalid",
        "a non-Zod record schema was accepted",
      );
      ok(
        p,
        throwsCode(() => defineToolAdapter(spec({ acceptedExitCodes: [] }))) ===
          "adapter_invalid" &&
          throwsCode(() => defineToolAdapter(spec({ acceptedExitCodes: ["0"] }))) ===
            "adapter_invalid",
        "bad exit codes",
      );
      ok(
        p,
        throwsCode(() => defineToolAdapter(spec({ fingerprintField: "secret" }))) ===
          "adapter_invalid",
        "a fingerprint field outside secretFields was accepted",
      );
      ok(
        p,
        Object.isFrozen(TRIVY) && Object.isFrozen(TRIVY.acceptedExitCodes),
        "adapters must be frozen",
      );
      const reg = createAdapterRegistry([OSV, TRIVY, fakeAdapter("syft", "sbom")]);
      ok(
        p,
        reg
          .select("sca")
          .map((a) => a.toolId)
          .join() === "trivy,osv-scanner" &&
          reg.select("sbom").length === 1 &&
          reg.select("sast").length === 0,
        "registry selection and tool order",
      );
      ok(
        p,
        throwsCode(() => reg.register(TRIVY)) === "adapter_duplicate",
        "a duplicate adapter was accepted",
      );
      ok(
        p,
        throwsCode(() => reg.register(spec({ toolId: "grype", imageKey: "grype" }))) ===
          "tool_deferred",
        "the registry accepted Grype",
      );
      ok(
        p,
        reg.select("sca").every((a) => a.toolId !== "grype"),
        "Grype was selected",
      );
      return p;
    },
  },
  {
    id: "ENG-S05a",
    name: "secret values never reach a stored or transmitted structure (SPEC scan-engines 5.6.4, 7.2, D-5, ENG-S05, framework part): a canary secret value placed in every field of a hostile record (the secret, the match, the title, the rule id, the description, the path, a nested unknown key) leaves NO occurrence, in plain, base64, base64url, hex, URL-encoded or reversed form, in any candidate, merged finding, item, detail row or JSON of them (the secret fields are removed before the mapper runs); the stored preview is at most 4 characters and only for a value longer than 12, never otherwise; the value-length bucket is computed by the framework; the in-task fingerprint exists only in memory on a candidate, is a 32 hex character HMAC under a per-task key, and never appears in a finding, an item or a detail; credential-shaped text in any other field is redacted; a secret finding has no snippet unless supplied by the redacting layer; the canary also does not appear in the tool-run outcome counters",
    async run() {
      const p = [];
      const CANARY = "CanaryS3cretValue-ZX9q42pLmNo7";
      const SHORT = "pw12";
      const forms = (v) => {
        const b = Buffer.from(v);
        return [
          v,
          b.toString("base64"),
          b.toString("base64url"),
          b.toString("hex"),
          b.toString("hex").toUpperCase(),
          encodeURIComponent(v),
          Array.from(v).reverse().join(""),
        ];
      };
      const hostile = {
        id: `rule-${CANARY}`,
        title: `Found ${CANARY} in file and also ${Buffer.from(CANARY).toString("base64")}`,
        path: `src/${CANARY}.env`,
        line: 7,
        typeClass: "generic_api_key",
        previewHint: CANARY.slice(0, 4),
        secret: CANARY,
        match: `API_KEY=${CANARY}`,
        extra: { deep: CANARY },
      };
      const long = parse(GITLEAKS, [hostile]);
      ok(p, long.status === "succeeded" && long.candidates.length === 1, `control: ${long.status}`);
      const withFp = runToolParse(
        DETECT,
        out([
          {
            ...hostile,
            title: `x ${CANARY.split("").reverse().join("")} ${encodeURIComponent(CANARY)} ${Buffer.from(CANARY).toString("hex")} ${Buffer.from(CANARY).toString("base64url")}`,
          },
        ]),
        ctxFor(TASK_A, { fingerprinter: createTaskFingerprinter() }),
      );
      const all = [...long.candidates, ...withFp.candidates];
      const findings = merge("secrets", all);
      const rows = toStorageRows(findings, 100);
      const sweep = JSON.stringify({ all, findings, rows, long: { ...long, candidates: 0 } });
      for (const form of forms(CANARY))
        ok(
          p,
          !sweep.includes(form),
          `the canary survives as ${form.slice(0, 12)}... in a candidate, finding or row`,
        );
      ok(
        p,
        rows.items.length === findings.length &&
          rows.items.every((i) => i.data.preview === undefined || i.data.preview.length <= 4),
        "preview longer than 4",
      );
      ok(
        p,
        !/"(match|secret|Secret|value)"\s*:/.test(JSON.stringify(findings)),
        "a secret field name survives in a finding",
      );
      // preview only for a value longer than 12
      const longPrev = cands(GITLEAKS, [
        {
          id: "k",
          path: "a.env",
          line: 1,
          typeClass: "aws_access_key",
          secret: "AKIAEXAMPLEEXAMPLE12",
          previewHint: "AKIAEXAMPLE",
        },
      ])[0];
      const shortPrev = cands(GITLEAKS, [
        {
          id: "k",
          path: "a.env",
          line: 1,
          typeClass: "aws_access_key",
          secret: SHORT,
          previewHint: SHORT,
        },
      ])[0];
      const exact12 = cands(GITLEAKS, [
        {
          id: "k",
          path: "a.env",
          line: 1,
          typeClass: "aws_access_key",
          secret: "123456789012",
          previewHint: "1234",
        },
      ])[0];
      const exact13 = cands(GITLEAKS, [
        {
          id: "k",
          path: "a.env",
          line: 1,
          typeClass: "aws_access_key",
          secret: "1234567890123",
          previewHint: "1234",
        },
      ])[0];
      ok(
        p,
        longPrev.preview === "AKIA" &&
          shortPrev.preview === undefined &&
          exact12.preview === undefined &&
          exact13.preview === "1234",
        `preview rule: ${longPrev.preview}/${shortPrev.preview}/${exact12.preview}/${exact13.preview}`,
      );
      // D-5: nothing derived from a secret value is stored, not even its length (the bucket was dropped)
      ok(
        p,
        [longPrev, shortPrev, exact12, exact13].every(
          (c) => !("valueLengthBucket" in c) && JSON.stringify(c).includes("Bucket") === false,
        ),
        "a candidate carries a length bucket",
      );
      // fingerprint is memory only
      const fp = withFp.candidates[0].mergeHints?.fingerprint;
      ok(p, /^[0-9a-f]{32}$/.test(fp ?? ""), "no in-task fingerprint on the candidate");
      ok(
        p,
        !JSON.stringify({ findings, rows }).includes(fp ?? "never"),
        "the fingerprint reached a finding or row",
      );
      ok(p, !forms(CANARY).some((f) => (fp ?? "").includes(f)), "the fingerprint is the value");
      const f1 = createTaskFingerprinter();
      const f2 = createTaskFingerprinter();
      ok(
        p,
        f1(CANARY) === f1(CANARY) && f1(CANARY) !== f2(CANARY) && f1(CANARY).length === 32,
        "fingerprinter properties",
      );
      // credential shapes elsewhere are redacted
      const ghp = "ghp_abcdefghijklmnopqrstuvwx1234";
      const shaped = cands(OPENGREP, [
        {
          id: "r",
          path: "a.js",
          line: 1,
          severity: "ERROR",
          title: `token ${ghp} and AKIAIOSFODNN7EXAMPLE and Bearer abcdefghijklmnop12345`,
        },
      ])[0];
      ok(
        p,
        !shaped.title.includes(ghp) &&
          !shaped.title.includes("AKIAIOSFODNN7EXAMPLE") &&
          !shaped.title.includes("abcdefghijklmnop12345"),
        `credential shapes survive in a title: ${shaped.title}`,
      );
      // storage projection: the last gate
      ok(
        p,
        rows.details.every(
          (d) => !("extra" in d.extra) && !JSON.stringify(d).includes("fingerprint"),
        ),
        "detail rows carry a fingerprint",
      );
      const sneaky = { ...findings[0], title: `leak ${ghp}` };
      const gate = toStorageRows([sneaky], 10);
      ok(
        p,
        !JSON.stringify(gate).includes(ghp),
        "the storage gate let a credential-shaped title through",
      );
      ok(
        p,
        !forms(CANARY).some((f) => JSON.stringify(long.severityCounts).includes(f)),
        "counters carry the canary",
      );
      return p;
    },
  },
  {
    id: "ENG-S09c",
    name: "storage projection and the existing last gate (SPEC scan-engines 7.1, 7.3, 16.1 part D): merged findings become scan_result_items rows of the unchanged shape (4 KiB data) plus 1:1 detail rows that keep the SAME ordinals even when an invalid finding is dropped in the middle (a finding that passed the schema cannot be rejected by the normalizeItems gate, which stays as defence in depth); the cap marks the result truncated and writes no more rows; an invalid finding is dropped and counted and never reaches a row; a detail row stays under 16 KiB (evidence is shed first) and carries no credential shape; severity counts follow the stored items",
    async run() {
      const p = [];
      const secrets = merge(
        "secrets",
        cands(
          GITLEAKS,
          [1, 2, 3].map((n) => ({
            id: "k",
            path: `f${n}.env`,
            line: n,
            typeClass: "aws_access_key",
            secret: `AKIAEXAMPLEEXAMPLE${n}${n}`,
            previewHint: "AKIA",
          })),
        ),
      );
      const sca = merge(
        "sca",
        cands(TRIVY, [
          { id: "CVE-1-1", purl: LODASH, severity: "CRITICAL", fixed: ["4.17.21"] },
          { id: "CVE-1-2", purl: "pkg:npm/a@1", severity: "LOW" },
        ]),
      );
      const all = [...sca, ...secrets];
      const rows = toStorageRows(all, 100);
      ok(
        p,
        rows.items.length === 5 &&
          rows.details.length === 5 &&
          rows.truncated === false &&
          rows.dropped === 0,
        `rows ${rows.items.length}/${rows.details.length}`,
      );
      ok(
        p,
        rows.items[0].severity === "critical" &&
          rows.items[0].kind === "vulnerability" &&
          rows.items[0].componentPurl === LODASH &&
          rows.items[0].componentVersion === "4.17.20" &&
          rows.items[0].ruleId === "CVE-1-1",
        "item shape",
      );
      ok(
        p,
        rows.items
          .filter((i) => i.kind === "secret")
          .every((i) => i.data.preview === "AKIA" && Object.keys(i.data).length === 1),
        "secret item data",
      );
      ok(
        p,
        rows.details[0].dedupKey.startsWith("sca|") &&
          rows.details[0].schemaVersion === 1 &&
          rows.details[0].provenance.length === 1 &&
          rows.details[0].extra.fix.fixedVersions[0] === "4.17.21" &&
          rows.details[0].extra.component.name === "lodash",
        "detail shape",
      );
      ok(
        p,
        JSON.stringify(rows.severityCounts) ===
          '{"critical":1,"high":3,"medium":0,"low":1,"info":0}',
        `counts ${JSON.stringify(rows.severityCounts)}`,
      );
      const capped = toStorageRows(all, 3);
      ok(
        p,
        capped.items.length === 3 && capped.details.length === 3 && capped.truncated === true,
        "the cap",
      );
      const withBad = toStorageRows([all[0], { ...all[1], kind: "secret" }, all[2]], 100);
      ok(
        p,
        withBad.items.length === 2 && withBad.details.length === 2 && withBad.dropped === 1,
        "an invalid finding reached a row",
      );
      // alignment when a finding is dropped in the middle (here by the schema: a control-character title)
      const blank = { ...all[1], title: "\u0001\u0002" };
      const gated = toStorageRows([all[0], blank, all[2]], 100);
      ok(
        p,
        gated.items.length === gated.details.length && gated.items.length === 2,
        `items and details diverge: ${gated.items.length}/${gated.details.length}`,
      );
      ok(
        p,
        gated.details[1].dedupKey === all[2].dedupKey && gated.items[1].ruleId === all[2].rule.id,
        "details lost their ordinal",
      );
      const bigEvidence = {
        ...secrets[0],
        evidence: { kind: "line", snippet: "x".repeat(4000), truncated: false },
      };
      const big = toStorageRows([bigEvidence], 10);
      ok(
        p,
        big.details.length === 1 && Buffer.byteLength(JSON.stringify(big.details[0])) <= 16384,
        "detail over 16 KiB",
      );
      ok(p, toStorageRows([], 5).items.length === 0, "empty");
      return p;
    },
  },
  {
    id: "ENG-S11a",
    name: "roll-up of tool statuses matches table 5.4 (SPEC scan-engines 5.3, 5.4, D-6, ENG-S11): every row in order (cancel, deadline, nothing to scan, no applicable tool, all good, degraded, all failed), partial makes the result incomplete and not resolution eligible, a degraded task is succeeded with incomplete completeness, a toolsDegraded count and never resolution eligible, an all-failed task is failed with tools_failed and no result and is transient only when every failure reason is sandbox_error, image_unavailable or capacity, skipped tools are neutral, the task status unsupported is never produced and unknown statuses are refused",
    async run() {
      const p = [];
      const t = (toolId, status, reason = null) => ({ toolId, status, reason });
      const eq = (label, got, want) => {
        for (const [k, v] of Object.entries(want))
          if (JSON.stringify(got[k]) !== JSON.stringify(v))
            p.push(`${label}: ${k} = ${JSON.stringify(got[k])}, want ${JSON.stringify(v)}`);
      };
      eq("1 cancel", rollUpTask({ tools: [t("a", "succeeded")], cancelled: true }), {
        taskStatus: "cancelled",
        completeness: "incomplete",
        resolutionEligible: false,
        matchedRow: 1,
      });
      eq("1 beats 2", rollUpTask({ tools: [], cancelled: true, deadlineReached: true }), {
        taskStatus: "cancelled",
        matchedRow: 1,
      });
      eq(
        "2 deadline",
        rollUpTask({
          tools: [t("a", "succeeded"), t("b", "timed_out", "deadline")],
          deadlineReached: true,
        }),
        {
          taskStatus: "timed_out",
          completeness: "incomplete",
          resolutionEligible: false,
          matchedRow: 2,
        },
      );
      eq(
        "3 nothing to scan",
        rollUpTask({
          tools: [t("a", "skipped", "no_applicable_files")],
          relevantFilesExist: false,
        }),
        {
          taskStatus: "succeeded",
          completeness: "complete",
          coverageState: "nothing_to_scan",
          resolutionEligible: true,
          matchedRow: 3,
        },
      );
      eq("3 no tools at all", rollUpTask({ tools: [], relevantFilesExist: false }), {
        matchedRow: 3,
      });
      eq(
        "4 gap",
        rollUpTask({
          tools: [t("a", "skipped", "no_applicable_files")],
          relevantFilesExist: true,
          coverageGaps: ["haskell"],
        }),
        {
          taskStatus: "succeeded",
          completeness: "incomplete",
          coverageState: "language_gap",
          coverageGaps: ["haskell"],
          resolutionEligible: false,
          matchedRow: 4,
        },
      );
      eq("5 normal", rollUpTask({ tools: [t("a", "succeeded"), t("b", "succeeded")] }), {
        taskStatus: "succeeded",
        completeness: "complete",
        coverageState: "complete",
        toolsDegraded: 0,
        resolutionEligible: true,
        errorClass: null,
        matchedRow: 5,
      });
      eq(
        "5 with skipped",
        rollUpTask({ tools: [t("a", "succeeded"), t("b", "skipped", "no_applicable_files")] }),
        {
          taskStatus: "succeeded",
          completeness: "complete",
          resolutionEligible: true,
          matchedRow: 5,
        },
      );
      eq(
        "5 partial",
        rollUpTask({ tools: [t("a", "partial", "output_invalid"), t("b", "succeeded")] }),
        {
          taskStatus: "succeeded",
          completeness: "incomplete",
          coverageState: "partial",
          resolutionEligible: false,
          matchedRow: 5,
        },
      );
      eq("5 one partial alone", rollUpTask({ tools: [t("a", "partial", "output_too_large")] }), {
        taskStatus: "succeeded",
        completeness: "incomplete",
        resolutionEligible: false,
      });
      for (const bad of ["failed", "timed_out", "unavailable", "cancelled"])
        eq(
          `6 degraded by ${bad}`,
          rollUpTask({ tools: [t("a", "succeeded"), t("b", bad, "exit_code")] }),
          {
            taskStatus: "succeeded",
            reason: null,
            completeness: "incomplete",
            toolsDegraded: 1,
            coverageState: "degraded",
            resolutionEligible: false,
            matchedRow: 6,
          },
        );
      eq(
        "6 two broken",
        rollUpTask({
          tools: [
            t("a", "partial"),
            t("b", "failed", "exit_code"),
            t("c", "unavailable", "image_unavailable"),
          ],
        }),
        { toolsDegraded: 2, resolutionEligible: false, matchedRow: 6 },
      );
      eq(
        "7 all failed permanent",
        rollUpTask({
          tools: [t("a", "failed", "exit_code"), t("b", "unavailable", "db_unavailable")],
        }),
        {
          taskStatus: "failed",
          reason: "tools_failed",
          completeness: null,
          errorClass: "permanent",
          resolutionEligible: false,
          toolsDegraded: 2,
          matchedRow: 7,
        },
      );
      eq(
        "7 all transient",
        rollUpTask({
          tools: [
            t("a", "failed", "sandbox_error"),
            t("b", "unavailable", "image_unavailable"),
            t("c", "failed", "capacity"),
          ],
        }),
        { taskStatus: "failed", errorClass: "transient", matchedRow: 7 },
      );
      eq(
        "7 one permanent among transient",
        rollUpTask({ tools: [t("a", "failed", "sandbox_error"), t("b", "timed_out", "timeout")] }),
        { errorClass: "permanent" },
      );
      // owner decision 2026-11-20 (option A): a tool named in retryClassExcludes does not decide the class
      const lite = { retryClassExcludes: ["sbom-lite"] };
      eq(
        "7 transient container tools, permanent excluded inventory: transient",
        rollUpTask({
          tools: [
            t("syft", "failed", "sandbox_error"),
            t("trivy", "unavailable", "capacity"),
            t("sbom-lite", "failed", "output_invalid"),
          ],
          ...lite,
        }),
        { taskStatus: "failed", errorClass: "transient", toolsDegraded: 3, matchedRow: 7 },
      );
      eq(
        "7 the same without the exclusion is permanent (default unchanged)",
        rollUpTask({
          tools: [
            t("syft", "failed", "sandbox_error"),
            t("trivy", "unavailable", "capacity"),
            t("sbom-lite", "failed", "output_invalid"),
          ],
        }),
        { errorClass: "permanent" },
      );
      eq(
        "7 a permanent container failure stays permanent whatever is excluded",
        rollUpTask({
          tools: [
            t("syft", "failed", "sandbox_error"),
            t("trivy", "failed", "exit_code"),
            t("sbom-lite", "failed", "output_invalid"),
          ],
          ...lite,
        }),
        { errorClass: "permanent" },
      );
      eq(
        "7 only excluded tools failed: decided by them (nothing infrastructure-dependent failed)",
        rollUpTask({
          tools: [
            t("syft", "skipped", "no_applicable_files"),
            t("sbom-lite", "failed", "output_invalid"),
          ],
          ...lite,
        }),
        { taskStatus: "failed", errorClass: "permanent", toolsDegraded: 1 },
      );
      eq(
        "7 an excluded transient failure alone is transient",
        rollUpTask({ tools: [t("sbom-lite", "failed", "sandbox_error")], ...lite }),
        { errorClass: "transient" },
      );
      eq(
        "6 the exclusion changes nothing for a degraded task",
        rollUpTask({
          tools: [t("syft", "succeeded"), t("sbom-lite", "failed", "output_invalid")],
          ...lite,
        }),
        { taskStatus: "succeeded", toolsDegraded: 1, matchedRow: 6, resolutionEligible: false },
      );
      for (const bad of ["sbom-lite", [1], null])
        ok(
          p,
          throwsCode(() => rollUpTask({ tools: [], retryClassExcludes: bad })) !== null,
          `a bad retryClassExcludes ${JSON.stringify(bad)} is refused`,
        );
      eq(
        "7 skipped is neutral",
        rollUpTask({
          tools: [t("a", "skipped", "no_applicable_files"), t("b", "failed", "exit_code")],
        }),
        { taskStatus: "failed", matchedRow: 7 },
      );
      eq("7 no reason is permanent", rollUpTask({ tools: [t("a", "failed")] }), {
        errorClass: "permanent",
      });
      // owner decision 2026-11-19: failure classification
      eq(
        "7 db_unavailable alone is transient (infrastructure)",
        rollUpTask({
          tools: [t("a", "unavailable", "db_unavailable"), t("b", "unavailable", "db_unavailable")],
        }),
        { taskStatus: "failed", errorClass: "transient", matchedRow: 7 },
      );
      eq(
        "7 db_unavailable with a permanent failure is permanent",
        rollUpTask({
          tools: [t("a", "unavailable", "db_unavailable"), t("b", "failed", "killed")],
        }),
        { errorClass: "permanent" },
      );
      eq(
        "6 a persistent db_unavailable degrades, it does not discard the scan",
        rollUpTask({ tools: [t("a", "succeeded"), t("b", "unavailable", "db_unavailable")] }),
        {
          taskStatus: "succeeded",
          completeness: "incomplete",
          toolsDegraded: 1,
          resolutionEligible: false,
          matchedRow: 6,
        },
      );
      eq(
        "6 a killed tool is permanent for the run and shows as degraded",
        rollUpTask({ tools: [t("a", "succeeded"), t("b", "failed", "killed")] }),
        { taskStatus: "succeeded", completeness: "incomplete", toolsDegraded: 1, matchedRow: 6 },
      );
      eq(
        "7 killed alone is permanent (not auto-retried)",
        rollUpTask({ tools: [t("a", "failed", "killed")] }),
        { taskStatus: "failed", errorClass: "permanent" },
      );
      eq(
        "5 a stale database is a warning: the scan proceeds, incomplete, never eligible",
        rollUpTask({ tools: [t("a", "partial", "db_stale"), t("b", "succeeded")] }),
        {
          taskStatus: "succeeded",
          completeness: "incomplete",
          toolsDegraded: 0,
          resolutionEligible: false,
          matchedRow: 5,
        },
      );
      eq(
        "5 a stale database alone still produces a scan",
        rollUpTask({ tools: [t("a", "partial", "db_stale")] }),
        { taskStatus: "succeeded", completeness: "incomplete", matchedRow: 5 },
      );
      for (const status of [
        "failed",
        "timed_out",
        "unavailable",
        "skipped",
        "cancelled",
        "succeeded",
      ])
        ok(
          p,
          throwsCode(() => rollUpTask({ tools: [t("a", status, "db_stale")] })) !== null,
          `db_stale was accepted on a ${status} tool`,
        );
      eq(
        "reason classes",
        [
          "sandbox_error",
          "image_unavailable",
          "capacity",
          "db_unavailable",
          "db_stale",
          "killed",
          "timeout",
          "out_of_memory",
          "exit_code",
          "output_invalid",
          "output_too_large",
          "config_invalid",
          "no_applicable_files",
          "cancelled",
          "deadline",
          "nonsense",
          null,
          undefined,
        ].map(toolReasonClass),
        [
          "transient",
          "transient",
          "transient",
          "transient",
          "warning",
          "permanent",
          "permanent",
          "permanent",
          "permanent",
          "permanent",
          "permanent",
          "permanent",
          "permanent",
          "permanent",
          "permanent",
          "permanent",
          "permanent",
          "permanent",
        ],
      );
      // properties over all combinations of up to three tools
      const statuses = [
        "succeeded",
        "partial",
        "failed",
        "timed_out",
        "cancelled",
        "skipped",
        "unavailable",
      ];
      let combos = 0;
      for (const a of statuses)
        for (const b of statuses)
          for (const c of [...statuses, null]) {
            const tools = [t("a", a), t("b", b), ...(c ? [t("c", c)] : [])];
            const r = rollUpTask({ tools });
            combos += 1;
            if (r.taskStatus === "unsupported") p.push("unsupported produced");
            if (!["succeeded", "failed"].includes(r.taskStatus)) p.push(`status ${r.taskStatus}`);
            const anyOk = tools.some((x) => x.status === "succeeded" || x.status === "partial");
            const anyBroken = tools.some((x) =>
              ["failed", "timed_out", "cancelled", "unavailable"].includes(x.status),
            );
            if (
              anyOk &&
              anyBroken &&
              (r.taskStatus !== "succeeded" ||
                r.completeness !== "incomplete" ||
                r.resolutionEligible ||
                r.toolsDegraded < 1)
            )
              p.push(`degraded rule broken for ${JSON.stringify(tools.map((x) => x.status))}`);
            if (
              !anyOk &&
              anyBroken &&
              (r.taskStatus !== "failed" || r.reason !== "tools_failed" || r.resolutionEligible)
            )
              p.push(`all-failed rule broken for ${JSON.stringify(tools.map((x) => x.status))}`);
            if (tools.some((x) => x.status === "partial") && r.resolutionEligible)
              p.push("partial was resolution eligible");
            if (
              r.resolutionEligible &&
              (r.completeness !== "complete" || r.taskStatus !== "succeeded")
            )
              p.push("eligible without a complete success");
          }
      ok(p, combos === 7 * 7 * 8, `combinations ${combos}`);
      ok(
        p,
        throwsCode(() => rollUpTask({ tools: [{ toolId: "a", status: "unsupported" }] })) !== null,
        "an unknown status was accepted",
      );
      ok(
        p,
        (() => {
          try {
            rollUpTask({ tools: "x" });
          } catch {
            return true;
          }
          return false;
        })(),
        "non-array tools accepted",
      );
      return p;
    },
  },
  {
    id: "ENG-S11b",
    name: "severity and confidence policy (SPEC scan-engines 5.7, D-5, ENG-S11; tables are Recommended and out of the suite's scope, only the policy is asserted): every unknown, missing, mistyped or out-of-range raw value becomes medium with the assumed flag, never a thrown error and never a prototype property; known raw values map to the documented scale (Trivy, OSV with MODERATE, CVSS bands including the 0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0 and 10 boundaries, Opengrep ERROR/WARNING/INFO, Bandit and gosec HIGH/MEDIUM/LOW, SBOM info); a platform rule may set the Opengrep severity only to a known level; SAST and secrets are never critical by default; secrets are never critical whatever the type or confidence; highestSeverity is the maximum and info for an empty list",
    async run() {
      const p = [];
      const unmapped = (r) => r.severity === "medium" && r.assumed === true;
      for (const scale of ["trivy", "osv", "opengrep", "bandit", "gosec"])
        for (const raw of [
          undefined,
          null,
          "",
          "UNKNOWN",
          "nonsense",
          5,
          {},
          [],
          "__proto__",
          "constructor",
          "toString",
          "CRITICAL ",
          "Negligible",
        ])
          if (
            !(scale === "trivy" && raw === "CRITICAL ") &&
            !(scale === "osv" && raw === "CRITICAL ")
          )
            ok(
              p,
              unmapped(normalizeSeverity(scale, raw)) || ["CRITICAL "].includes(raw),
              `${scale} ${JSON.stringify(raw)} is not unmapped`,
            );
      const eq = (scale, raw, want, assumed = false) => {
        const r = normalizeSeverity(scale, raw);
        ok(
          p,
          r.severity === want && r.assumed === assumed,
          `${scale} ${JSON.stringify(raw)} gave ${r.severity}/${r.assumed}, want ${want}/${assumed}`,
        );
      };
      for (const [raw, want] of [
        ["CRITICAL", "critical"],
        ["high", "high"],
        [" Medium ", "medium"],
        ["LOW", "low"],
      ])
        eq("trivy", raw, want);
      eq("trivy", "UNKNOWN", "medium", true);
      eq("trivy", "CRITICAL ", "critical");
      for (const [raw, want] of [
        ["CRITICAL", "critical"],
        ["HIGH", "high"],
        ["MODERATE", "medium"],
        ["LOW", "low"],
      ])
        eq("osv", raw, want);
      for (const [score, want] of [
        [0, "info"],
        [0.1, "low"],
        [3.9, "low"],
        [4, "medium"],
        [6.9, "medium"],
        [7, "high"],
        [8.9, "high"],
        [9, "critical"],
        [10, "critical"],
      ])
        eq("cvss", score, want);
      for (const bad of [-0.1, 10.1, Number.NaN, Number.POSITIVE_INFINITY, "9.8", null, undefined])
        ok(p, unmapped(severityFromCvssScore(bad)), `cvss ${bad} is not unmapped`);
      eq("opengrep", "ERROR", "high");
      eq("opengrep", "WARNING", "medium");
      eq("opengrep", "INFO", "low");
      eq("bandit", "HIGH", "high");
      eq("gosec", "LOW", "low");
      eq("none", "anything", "info");
      ok(
        p,
        normalizeSeverity("opengrep", "INFO", { qmSeverity: "critical" }).severity === "critical" &&
          unmapped(normalizeSeverity("opengrep", "bogus", { qmSeverity: "catastrophic" })),
        "platform rule severity",
      );
      for (const raw of ["CRITICAL", "ERROR", "HIGH", "critical"])
        for (const scale of ["opengrep", "bandit", "gosec"])
          ok(
            p,
            normalizeSeverity(scale, raw).severity !== "critical",
            `${scale} ${raw} produced critical without a platform rule`,
          );
      const types = [
        "private_key",
        "aws_access_key",
        "gcp_service_account",
        "azure_storage_key",
        "github_token",
        "gitlab_token",
        "stripe_key",
        "slack_token",
        "jwt",
        "basic_auth_url",
        "password_assignment",
        "generic_api_key",
        "high_entropy_string",
        "other",
        "not_a_class",
        "__proto__",
        "constructor",
      ];
      for (const type of types)
        for (const conf of ["low", "medium", "high", undefined])
          ok(
            p,
            severityOfSecretType(type, conf).severity !== "critical",
            `secret ${type} is critical`,
          );
      ok(
        p,
        severityOfSecretType("aws_access_key").severity === "high" &&
          severityOfSecretType("jwt").severity === "medium" &&
          severityOfSecretType("generic_api_key", "low").severity === "low" &&
          severityOfSecretType("other", "high").severity === "medium",
        "secret table",
      );
      ok(
        p,
        unmapped(severityOfSecretType("constructor")) &&
          unmapped(severityOfSecretType("__proto__")),
        "a prototype name is a secret type",
      );
      ok(
        p,
        normalizeConfidence("HIGH") === "high" &&
          normalizeConfidence("low") === "low" &&
          normalizeConfidence("MEDIUM") === "medium" &&
          normalizeConfidence(undefined) === "medium" &&
          normalizeConfidence("constructor") === "medium",
        "confidence mapping",
      );
      ok(
        p,
        highestSeverity([]) === "info" &&
          highestSeverity(["low", "critical", "medium"]) === "critical" &&
          highestSeverity(["info", "low"]) === "low",
        "highestSeverity",
      );
      ok(p, SEVERITIES.length === 5, "severity scale");
      return p;
    },
  },
  {
    id: "ENG-S03b",
    name: "the ensemble core has no side effects (SPEC scan-engines SE-4, SE-5, SE-3, ENG-S03): the core framework directory and the shared scan-engine package import no process, network, file-system, database, SecretStore, GitHub, LLM or sandbox module and use no eval, Function constructor, dynamic import, fetch, Date.now, Math.random or process.env; the only I/O dependencies are the credential redaction and the existing normalizeItems gate; the framework is not imported by the scan worker (part K wires it, the rollout flag stays off) and the flag is still read by nothing",
    async run() {
      const p = [];
      const dirs = [CORE_DIR, path.join(ROOT, "packages/shared/src/scan-engines")];
      const FORBIDDEN_IMPORT =
        /from\s+["'](node:(child_process|net|http|https|http2|dgram|dns|tls|fs|fs\/promises|worker_threads|vm|cluster)|child_process|fs|net|http|https|@qmentisai\/db|@prisma\/client|ioredis|amqplib|socket\.io[^"']*)["']/;
      const FORBIDDEN_CALL =
        /\b(eval\s*\(|new Function\s*\(|import\s*\(|fetch\s*\(|Date\.now\s*\(|new Date\s*\(|Math\.random\s*\(|process\.env|process\.exit|execFile|spawn\s*\()/;
      for (const dir of dirs)
        for (const file of listJs(dir)) {
          const src = readFileSync(file, "utf8")
            .replace(/\/\*[\s\S]*?\*\//g, "")
            .replace(/^\s*\/\/.*$/gm, "");
          const name = path.relative(ROOT, file);
          ok(p, !FORBIDDEN_IMPORT.test(src), `${name}: a forbidden import`);
          ok(
            p,
            !FORBIDDEN_CALL.test(src),
            `${name}: a forbidden call (${FORBIDDEN_CALL.exec(src)?.[0]})`,
          );
          for (const m of src.matchAll(/from\s+["']([^"']+)["']/g))
            if (!m[1].startsWith("."))
              ok(
                p,
                ["zod", "@qmentisai/shared", "@qmentisai/infra", "node:crypto"].includes(m[1]),
                `${name}: unexpected dependency ${m[1]}`,
              );
          for (const m of src.matchAll(/from\s+["'](\.[^"']+)["']/g)) {
            const target = path.resolve(path.dirname(file), m[1]);
            ok(
              p,
              target.startsWith(dir) || target.endsWith("scan-handler.js"),
              `${name}: imports outside the core (${m[1]})`,
            );
          }
        }
      // part K core: the worker uses the framework only through the engine wiring and the changed-paths module (parse kit); the
      // rollout flag (its environment variable) is read by the configuration module only
      const worker = path.join(ROOT, "apps/workers/src");
      for (const file of listJs(worker)) {
        if (file.startsWith(CORE_DIR)) continue;
        const src = readFileSync(file, "utf8");
        ok(
          p,
          !/ensemble\/core/.test(src) || file.endsWith("execution/changed-paths.js"),
          `${path.relative(ROOT, file)}: imports the ensemble core outside the changed-paths module`,
        );
        if (!file.endsWith("config.js"))
          ok(
            p,
            !/SCAN_ENGINES_ENSEMBLE_ENABLED/.test(src),
            `${path.relative(ROOT, file)}: reads the rollout flag`,
          );
      }
      // only the existing last gate and the redaction are used from other packages
      const storage = readFileSync(path.join(CORE_DIR, "storage.js"), "utf8");
      ok(p, /normalizeItems/.test(storage), "storage.js does not use normalizeItems");
      return p;
    },
  },
  {
    id: "ENG-S06d",
    name: "exact values, order, ties and every size boundary of the framework (SPEC scan-engines SE-14, 5.6, 7.2, 7.3; mutation-sweep driven): the output order of findings is severity, path, line, component, rule; cross-tool grouping is decided in the documented sort order whatever the input order (all permutations), the SAST tolerance is anchored at the first member by line, touching ranges merge beyond the tolerance, a shared block id merges far lines and different ones do not, a generic secret type folds into a specific one in either order, two generic types stay apart, secrets in two files at one line stay apart, a fingerprint and a candidate without one merge, provenance and advisories are in tool and priority order, scope ties are decided by strength, the evidence, url and reference of any member are kept, the stats add up, absent optional parts are absent (not empty); the purl parser yields exact namespaces, names, versions and qualifiers per type and refuses encoded control characters; every cap of the finding schema, the parse kit (bytes, depth, nodes, records, drop ratio), the scrubber (value length, depth, length buckets) and the storage row is accepted at its limit and refused one past it; the JSON size measured by the application equals the text PostgreSQL prints for jsonb",
    async run() {
      const p = [];
      const eq = (label, got, want) =>
        ok(
          p,
          JSON.stringify(got) === JSON.stringify(want),
          `${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
        );
      const perms = (list) =>
        list.length <= 1
          ? [list]
          : list.flatMap((x, i) =>
              perms([...list.slice(0, i), ...list.slice(i + 1)]).map((rest) => [x, ...rest]),
            );
      const toolSets = (findings) =>
        findings.map((f) => f.provenance.map((x) => x.toolId).join("+")).sort();
      const withHints = (adapter, hints) =>
        fakeAdapter(adapter.toolId, adapter.scanType, {
          map: (r, c) => {
            const m = adapter.map(r, c);
            return { ...m, mergeHints: { ...m.mergeHints, ...hints(r) } };
          },
        });
      // ---- final order
      const ordered = merge(
        "sca",
        cands(TRIVY, [
          { id: "CVE-1-1", purl: "pkg:npm/b@1", severity: "LOW", path: "z/package-lock.json" },
          { id: "CVE-1-2", purl: "pkg:npm/a@1", severity: "LOW", path: "z/package-lock.json" },
          { id: "CVE-1-3", purl: "pkg:npm/a@1", severity: "LOW", path: "a/package-lock.json" },
          { id: "CVE-1-4", purl: "pkg:npm/a@1", severity: "CRITICAL", path: "z/package-lock.json" },
          { id: "CVE-1-0", purl: "pkg:npm/a@1", severity: "LOW", path: "z/package-lock.json" },
          { id: "CVE-1-5", purl: "pkg:npm/a@1", severity: "MEDIUM", path: "m/package-lock.json" },
        ]),
      );
      eq(
        "sca order",
        ordered.map((f) => f.rule.id),
        ["CVE-1-4", "CVE-1-5", "CVE-1-3", "CVE-1-0", "CVE-1-2", "CVE-1-1"],
      );
      const sastOrder = merge(
        "sast",
        cands(OPENGREP, [
          { id: "r", path: "b.js", line: 5, severity: "ERROR" },
          { id: "r", path: "a.js", line: 9, severity: "ERROR" },
          { id: "r", path: "a.js", line: 2, severity: "ERROR" },
          { id: "q", path: "a.js", line: 2, severity: "ERROR" },
          { id: "r", path: "a.js", line: 7, severity: "WARNING" },
        ]),
      );
      eq(
        "sast order",
        sastOrder.map(
          (f) => `${f.location.path}:${f.location.startLine}:${f.rule.id}:${f.severity}`,
        ),
        ["a.js:2:q:high", "a.js:2:r:high", "a.js:9:r:high", "b.js:5:r:high", "a.js:7:r:medium"],
      );
      const comp = merge(
        "sbom",
        cands(SYFT, [
          { purl: "pkg:npm/b@1", path: "x" },
          { purl: "pkg:npm/a@1", path: "x" },
          { purl: "pkg:npm/a@2", path: "x" },
        ]),
      );
      eq(
        "sbom order",
        comp.map((f) => f.component.purl),
        ["pkg:npm/a@1", "pkg:npm/a@2", "pkg:npm/b@1"],
      );
      // ---- the SAST grouping is decided in line order, whatever the input order
      const g10 = cands(GOSEC, [{ id: "g", path: "s.js", line: 10, severity: "ERROR", cwe: [79] }]);
      const b12 = cands(BANDIT, [
        { id: "b", path: "s.js", line: 12, severity: "ERROR", cwe: [79] },
      ]);
      const o14 = cands(OPENGREP, [
        { id: "o", path: "s.js", line: 14, severity: "ERROR", cwe: [79] },
      ]);
      for (const order of perms([g10[0], b12[0], o14[0]]))
        eq("sast anchor", toolSets(merge("sast", order)), ["opengrep", "bandit+gosec"].sort());
      const touch = [
        ...cands(OPENGREP, [
          { id: "o", path: "s.js", line: 10, endLine: 30, severity: "ERROR", cwe: [79] },
        ]),
        ...cands(BANDIT, [{ id: "b", path: "s.js", line: 30, severity: "ERROR", cwe: [79] }]),
      ];
      eq("touching ranges", merge("sast", touch).length, 1);
      eq("touching range", merge("sast", touch)[0].location, {
        path: "s.js",
        startLine: 10,
        endLine: 30,
      });
      eq("a single line has no end line", "endLine" in merge("sast", g10)[0].location, false);
      const farOne = [
        ...cands(
          withHints(OPENGREP, () => ({ blockId: "f1" })),
          [{ id: "o", path: "s.js", line: 10, severity: "ERROR", cwe: [79] }],
        ),
        ...cands(
          withHints(BANDIT, () => ({ blockId: "f1" })),
          [{ id: "b", path: "s.js", line: 60, severity: "ERROR", cwe: [79] }],
        ),
      ];
      const farTwo = [
        ...cands(
          withHints(OPENGREP, () => ({ blockId: "f1" })),
          [{ id: "o", path: "s.js", line: 10, severity: "ERROR", cwe: [79] }],
        ),
        ...cands(
          withHints(BANDIT, () => ({ blockId: "f2" })),
          [{ id: "b", path: "s.js", line: 60, severity: "ERROR", cwe: [79] }],
        ),
      ];
      eq("same block", merge("sast", farOne).length, 1);
      eq("different blocks", merge("sast", farTwo).length, 2);
      eq(
        "no block",
        merge("sast", [
          ...cands(OPENGREP, [{ id: "o", path: "s.js", line: 10, severity: "ERROR", cwe: [79] }]),
          ...cands(BANDIT, [{ id: "b", path: "s.js", line: 60, severity: "ERROR", cwe: [79] }]),
        ]).length,
        2,
      );
      const rich = fakeAdapter("bandit", "sast", {
        map: (r, c) => ({
          ...BANDIT.map(r, c),
          evidence: { kind: "window", snippet: "x = 1" },
          url: `https://github.com/o/r/blob/${"a".repeat(40)}/s.js`,
          scmRef: { provider: "github", repoFullName: "o/r", commitSha: "a".repeat(40) },
          scope: { kind: "targets", inScope: true },
        }),
      });
      const kept = merge("sast", [
        ...cands(OPENGREP, [
          { id: "o", path: "s.js", line: 10, severity: "ERROR", cwe: [79], confidence: "HIGH" },
        ]),
        ...cands(rich, [{ id: "b", path: "s.js", line: 11, severity: "ERROR", cwe: [79] }]),
      ])[0];
      ok(
        p,
        kept.evidence?.snippet === "x = 1" &&
          kept.url?.startsWith("https://github.com/o/r/blob/") &&
          kept.scmRef?.provider === "github" &&
          kept.scope?.kind === "targets" &&
          kept.scope.inScope === true,
        "evidence, url, scm reference or scope of a non-base member was lost",
      );
      const bareF = merge("sast", g10)[0];
      ok(
        p,
        !("evidence" in bareF) && !("url" in bareF) && !("scmRef" in bareF) && !("scope" in bareF),
        "absent optional parts must be absent",
      );
      ok(
        p,
        !(
          "cwe" in
          merge("sast", cands(OPENGREP, [{ id: "o", path: "s.js", line: 1, severity: "ERROR" }]))[0]
        ),
        "an empty cwe list must be absent",
      );
      eq(
        "one cwe",
        merge(
          "sast",
          cands(OPENGREP, [{ id: "o", path: "s.js", line: 1, severity: "ERROR", cwe: [79] }]),
        )[0].cwe,
        [79],
      );
      // titles by confidence, then tool order, whatever the input order
      const hi = cands(BANDIT, [
        { id: "b-rule", path: "t.js", line: 5, severity: "ERROR", cwe: [79], confidence: "HIGH" },
      ]);
      const lo = cands(OPENGREP, [
        { id: "o-rule", path: "t.js", line: 5, severity: "ERROR", cwe: [79], confidence: "LOW" },
      ]);
      for (const order of perms([hi[0], lo[0]]))
        eq("title by confidence", merge("sast", order)[0].title, "b-rule");
      const eqA = cands(BANDIT, [
        { id: "b-rule", path: "t.js", line: 5, severity: "ERROR", cwe: [79], confidence: "MEDIUM" },
      ]);
      const eqB = cands(OPENGREP, [
        { id: "o-rule", path: "t.js", line: 5, severity: "ERROR", cwe: [79], confidence: "MEDIUM" },
      ]);
      for (const order of perms([eqA[0], eqB[0]]))
        eq("title by tool order", merge("sast", order)[0].title, "o-rule");
      // ---- secrets grouping
      const sec = (adapter, over, ctx) =>
        cands(
          adapter,
          [
            {
              id: "r",
              path: "src/a.env",
              line: 4,
              typeClass: "jwt",
              secret: "ey.value.value.value",
              ...over,
            },
          ],
          TASK_A,
          ctx,
        );
      eq(
        "generic first, specific second",
        merge("secrets", [
          ...sec(GITLEAKS, { typeClass: "generic_api_key" }),
          ...sec(DETECT, { typeClass: "jwt" }),
        ]).map((f) => f.dedupKey),
        ["secrets|src/a.env|4|jwt"],
      );
      eq(
        "two generic types",
        merge("secrets", [
          ...sec(GITLEAKS, { typeClass: "generic_api_key" }),
          ...sec(DETECT, { typeClass: "high_entropy_string" }),
        ]).length,
        2,
      );
      eq(
        "two files, one line",
        merge("secrets", [...sec(GITLEAKS, { path: "a.env" }), ...sec(DETECT, { path: "b.env" })])
          .length,
        2,
      );
      const fp = createTaskFingerprinter();
      eq(
        "fingerprint with none",
        merge("secrets", [...sec(DETECT, {}, { fingerprinter: fp }), ...sec(GITLEAKS, {})]).length,
        1,
      );
      eq(
        "none with fingerprint",
        merge("secrets", [...sec(GITLEAKS, {}), ...sec(DETECT, {}, { fingerprinter: fp })]).length,
        1,
      );
      const noValue = fakeAdapter("gitleaks", "secrets");
      const bucketBase = cands(noValue, [
        { id: "r", path: "src/a.env", line: 4, typeClass: "jwt", confidence: "HIGH" },
      ]);
      const withBucket = merge("secrets", [
        ...bucketBase,
        ...sec(DETECT, { confidence: "LOW" }),
      ])[0];
      ok(
        p,
        !("valueLengthBucket" in bucketBase[0]) && !("valueLengthBucket" in withBucket),
        "a merged secret carries a length bucket",
      );
      const onlyBase = merge("secrets", bucketBase)[0];
      ok(p, !("preview" in onlyBase), "an absent preview must be absent");
      eq(
        "preview from a member",
        merge("secrets", [
          ...bucketBase,
          ...sec(DETECT, { previewHint: "eyJ0", secret: "x".repeat(20) }),
        ])[0].preview,
        "eyJ0",
      );
      // ---- SBOM details
      const noLoc = merge(
        "sbom",
        cands(
          fakeAdapter("syft", "sbom", {
            map: (r, c) => {
              const { location: _unused, ...rest } = SYFT.map(r, c);
              return rest;
            },
          }),
          [{ purl: "pkg:npm/a@1" }],
        ),
      )[0];
      ok(
        p,
        noLoc.locationCount === 0 && noLoc.locations.length === 0 && !("location" in noLoc),
        `a component without a location: ${noLoc.locationCount}`,
      );
      const scopes = (a, b) =>
        merge("sbom", [
          ...cands(SYFT, [{ purl: "pkg:npm/s@1", path: "p", scope: a }]),
          ...cands(TRIVY_SBOM, [{ purl: "pkg:npm/s@1", path: "q", scope: b }]),
        ])[0].component.scope;
      eq("scope optional vs dev", scopes("optional", "dev"), "dev");
      eq("scope dev vs optional", scopes("dev", "optional"), "dev");
      eq("scope peer vs dev", scopes("peer", "dev"), "dev");
      eq("scope unknown vs optional", scopes("unknown", "optional"), "optional");
      eq("scope unknown vs peer", scopes("unknown", "peer"), "peer");
      eq("scope prod vs dev", scopes("dev", "prod"), "prod");
      eq("scope none", scopes(undefined, undefined), undefined);
      ok(
        p,
        !("scope" in merge("sbom", cands(SYFT, [{ purl: "pkg:npm/s@1", path: "p" }]))[0].component),
        "a component without scope must have none",
      );
      const manyLoc = merge(
        "sbom",
        cands(
          fakeAdapter("syft", "sbom", {
            map: (r, c) => ({
              ...SYFT.map(r, c),
              locations: [
                { path: "b/x", startLine: 9 },
                { path: "a/x", startLine: 5 },
                { path: "a/x", startLine: 2 },
              ],
              locationCount: 3,
            }),
          }),
          [{ purl: "pkg:npm/m@1" }],
        ),
      )[0];
      eq(
        "locations order",
        manyLoc.locations.map((l) => `${l.path}:${l.startLine}`),
        ["a/x:2", "a/x:5", "b/x:9"],
      );
      const rootDecl = merge("sbom", [
        ...cands(SYFT, [{ purl: "pkg:npm/e", path: "package.json" }]),
        ...cands(TRIVY_SBOM, [{ purl: "pkg:npm/e@1.0.0", path: "package-lock.json" }]),
      ]);
      eq(
        "a declaration in the root directory",
        rootDecl.map((f) => f.component.version),
        ["1.0.0"],
      );
      const stats = mergeTaskCandidates({
        taskRef: TASK_A,
        scanType: "sbom",
        candidates: [
          ...cands(SYFT, [
            { purl: "pkg:npm/e", path: "package.json" },
            { purl: "pkg:npm/x@1", path: "p" },
          ]),
          ...cands(TRIVY_SBOM, [
            { purl: "pkg:npm/e@1.0.0", path: "package-lock.json" },
            { purl: "pkg:npm/x@1", path: "q" },
          ]),
        ],
      }).stats;
      eq("sbom stats", stats, { candidates: 4, findings: 2, merged: 1, redundantComponents: 1 });
      eq(
        "sca stats",
        mergeTaskCandidates({
          taskRef: TASK_A,
          scanType: "sca",
          candidates: cands(TRIVY, [{ id: "CVE-1-1", purl: LODASH }]),
        }).stats,
        { candidates: 1, findings: 1, merged: 0, redundantComponents: 0 },
      );
      // ---- SCA: provenance, advisories, the guard order
      const adv = merge("sca", [
        ...cands(TRIVY, [
          {
            id: "GHSA-bbbb-bbbb-bbbb",
            aliases: ["GHSA-aaaa-aaaa-aaaa", "PYSEC-2020-1", "CVE-2020-9"],
            purl: LODASH,
            severity: "HIGH",
          },
        ]),
        ...cands(OSV, [
          { id: "CVE-2020-9", aliases: ["GHSA-bbbb-bbbb-bbbb"], purl: LODASH, severity: "HIGH" },
        ]),
      ]);
      eq(
        "advisory order",
        adv[0].advisories.map((a) => a.id),
        ["CVE-2020-9", "GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb", "PYSEC-2020-1"],
      );
      eq(
        "provenance order",
        adv[0].provenance.map((x) => x.toolId),
        ["trivy", "osv-scanner"],
      );
      eq(
        "provenance rule ids",
        adv[0].provenance.map((x) => x.ruleId),
        ["GHSA-bbbb-bbbb-bbbb", "CVE-2020-9"],
      );
      const guardIn = [
        ...cands(TRIVY, [
          { id: "CVE-2020-0001", aliases: ["GHSA-aaaa-aaaa-aaaa"], purl: LODASH, severity: "HIGH" },
          { id: "CVE-2020-0002", aliases: ["GHSA-bbbb-bbbb-bbbb"], purl: LODASH, severity: "LOW" },
        ]),
        ...cands(OSV, [
          {
            id: "GHSA-aaaa-aaaa-aaaa",
            aliases: ["CVE-2020-0001", "CVE-2020-0002"],
            purl: LODASH,
            severity: "MODERATE",
          },
        ]),
      ];
      for (const order of perms(guardIn))
        eq(
          "guard keeps the first by sort order",
          merge("sca", order)
            .map((f) => `${f.provenance.map((x) => x.toolId).join("+")}:${f.rule.id}`)
            .sort(),
          ["trivy+osv-scanner:CVE-2020-0001", "trivy:CVE-2020-0002"].sort(),
        );
      // two Syft records of one component and one Trivy record: the Trivy record joins the first Syft record
      const syftTwo = cands(SYFT, [
        { purl: "pkg:npm/d@1", path: "one" },
        { purl: "pkg:npm/d@1", path: "two" },
      ]);
      const trivyOne = cands(TRIVY_SBOM, [{ purl: "pkg:npm/d@1", path: "three" }]);
      for (const order of perms([...syftTwo, ...trivyOne])) {
        const r = merge("sbom", order);
        const joined = r.find((f) => f.provenance.length === 2);
        ok(
          p,
          r.length === 2 &&
            joined &&
            joined.provenance.find((x) => x.toolId === "syft").rawRef.ordinal ===
              syftTwo[0].rawRef.ordinal,
          "the second tool did not join the first record of the other",
        );
      }
      // ---- purl exact values
      const pp = (s) => canonicalPurl(s);
      eq(
        "npm scope",
        [
          pp("pkg:npm/%40Angular/Core@v12.0.0").namespace,
          pp("pkg:npm/%40Angular/Core@v12.0.0").name,
          pp("pkg:npm/%40Angular/Core@v12.0.0").version,
        ],
        ["@angular", "core", "12.0.0"],
      );
      eq(
        "npm canonical",
        pp("pkg:npm/%40Angular/Core@v12.0.0").canonical,
        "pkg:npm/%40angular/core@12.0.0",
      );
      eq(
        "golang canonical",
        pp("pkg:golang/GitHub.com/Foo/Bar@v1").canonical,
        "pkg:golang/github.com/foo/bar@v1",
      );
      eq("golang namespace", pp("pkg:golang/GitHub.com/Foo/Bar@v1").namespace, "github.com/foo");
      eq("golang without namespace", pp("pkg:golang/Std@1").namespace, null);
      eq(
        "maven canonical",
        pp("pkg:maven/Org.Foo/Bar@1.0?classifier=Sources").canonical,
        "pkg:maven/Org.Foo/Bar@1.0?classifier=Sources",
      );
      eq(
        "deb qualifiers",
        pp("pkg:deb/debian/curl@7.0?distro=bookworm&arch=amd64").canonical,
        "pkg:deb/debian/curl@7.0?arch=amd64&distro=bookworm",
      );
      eq("one character type", pp("pkg:a/x@1")?.canonical, "pkg:a/x@1");
      eq("pypi canonical", pp("pkg:pypi/Foo_Bar.Baz@V1.0")?.canonical, "pkg:pypi/foo-bar-baz@V1.0");
      eq("pypi v prefix", pp("pkg:pypi/x@v1.0")?.version, "1.0");
      eq("empty version", pp("pkg:npm/x@")?.version, null);
      eq("blank version", pp("pkg:npm/x@%20")?.version, null);
      for (const [label, bad] of [
        ["encoded control in a name", "pkg:npm/lo%01dash@1"],
        ["encoded control in a version", "pkg:npm/a@1%0A2"],
        ["undecodable version", "pkg:npm/a@%E0%A4%A"],
        ["undecodable qualifier", "pkg:deb/x/y@1?arch=%E0%A4%A"],
        ["encoded control in a qualifier", "pkg:deb/x/y@1?arch=a%01b"],
      ])
        ok(p, pp(bad) === null, `purl accepted: ${label}`);
      ok(p, normalizeAdvisoryId("A")?.id === "A", "a one character advisory id");
      const top = (...ids) => canonicalAdvisory(ids.map(normalizeAdvisoryId)).id;
      ok(
        p,
        top("PYSEC-1", "OSV-1") === "PYSEC-1" &&
          top("RUSTSEC-1", "OSV-1") === "RUSTSEC-1" &&
          top("ALAS-1", "OSV-1") === "OSV-1" &&
          top("GO-1", "GHSA-aaaa") === "GHSA-aaaa",
        "advisory priority ties",
      );
      // ---- policy constants
      eq(
        "severity ties",
        [
          highestSeverity(["high", "critical"]),
          highestSeverity(["medium", "high"]),
          highestSeverity(["low", "medium"]),
          highestSeverity(["info", "low"]),
          highestSeverity(["critical", "high"]),
        ],
        ["critical", "high", "medium", "low", "critical"],
      );
      eq(
        "qm severity is confirmed",
        normalizeSeverity("opengrep", "INFO", { qmSeverity: "critical" }),
        { severity: "critical", assumed: false },
      );
      ok(
        p,
        severityOfSecretType("aws_access_key").assumed === false &&
          severityOfSecretType("generic_api_key", "low").assumed === false &&
          severityOfSecretType("jwt").assumed === false,
        "secret table is not assumed",
      );
      eq("result schema version", ENSEMBLE_RESULT_SCHEMA_VERSION, 2);
      eq("limits", FINDING_LIMITS, {
        dedupKey: 600,
        title: 200,
        ruleId: 200,
        path: 1024,
        purl: 500,
        provenanceEntries: 6,
        provenanceEntryBytes: 600,
        advisories: 20,
        cwe: 10,
        locations: 20,
        fixedVersions: 10,
        evidenceBytes: 8192,
        url: 2000,
        detailRowBytes: 16384,
        extraBytes: 16384,
      });
      // ---- roll-up details
      ok(
        p,
        rollUpTask({ tools: [{ toolId: "a", status: "skipped", reason: "no_applicable_files" }] })
          .matchedRow === 4,
        "relevant files are assumed by default",
      );
      ok(
        p,
        (() => {
          try {
            rollUpTask({ tools: null });
          } catch (e) {
            return e.message === "tools must be an array";
          }
          return false;
        })(),
        "the roll-up refuses non-array tools with its own message",
      );
      // ---- adapter contract details
      const bare = (over) => ({
        toolId: "trivy",
        scanType: "sca",
        imageKey: "trivy",
        plan: () => ({}),
        parse: () => [],
        recordSchema: TRIVY.recordSchema,
        map: () => null,
        ...over,
      });
      for (const bad of [null, undefined, 5, "x"])
        ok(
          p,
          throwsCode(() => defineToolAdapter(bad)) === "adapter_invalid",
          `adapter ${JSON.stringify(bad)}`,
        );
      ok(
        p,
        throwsCode(() => defineToolAdapter(bare({ secretFields: "abc" }))) === "adapter_invalid" &&
          throwsCode(() => defineToolAdapter(bare({ secretFields: [1] }))) === "adapter_invalid",
        "secretFields",
      );
      for (const bad of [0, -1, 1.5, "5", null])
        ok(
          p,
          throwsCode(() => defineToolAdapter(bare({ maxRecords: bad }))) === "adapter_invalid",
          `maxRecords ${JSON.stringify(bad)}`,
        );
      ok(p, defineToolAdapter(bare({ maxRecords: 1 })).maxRecords === 1, "maxRecords 1");
      // ---- parse kit exact messages, boundaries
      const msg = (fn) => {
        try {
          fn();
        } catch (e) {
          return `${e.reason}:${e.message}`;
        }
        return null;
      };
      eq(
        "empty",
        msg(() => parseBoundedJson("")),
        "output_invalid:empty output",
      );
      eq(
        "not json",
        msg(() => parseBoundedJson("{")),
        "output_invalid:not valid JSON",
      );
      eq(
        "unbalanced",
        msg(() => parseBoundedJson("]")),
        "output_invalid:unbalanced document",
      );
      eq(
        "too deep",
        msg(() => parseBoundedJson("[".repeat(65) + "]".repeat(65))),
        "output_invalid:nesting too deep",
      );
      eq(
        "deep enough",
        msg(() => parseBoundedJson("[".repeat(64) + "]".repeat(64))),
        null,
      );
      eq(
        "depth limit",
        msg(() => parseBoundedJson("[[[]]]", { maxDepth: 2 })),
        "output_invalid:nesting too deep",
      );
      eq(
        "depth limit ok",
        msg(() => parseBoundedJson("[[]]", { maxDepth: 2 })),
        null,
      );
      eq(
        "brackets in strings",
        msg(() =>
          parseBoundedJson(JSON.stringify({ a: "[".repeat(200), b: ["]".repeat(200)] }), {
            maxDepth: 3,
          }),
        ),
        null,
      );
      eq(
        "escaped quote in a string",
        msg(() => parseBoundedJson('{"a":"x\\"[[[[[[[[[","b":1}', { maxDepth: 2 })),
        null,
      );
      eq(
        "backslash at the end of a string",
        msg(() => parseBoundedJson('{"a":"x\\\\","b":[[[[[[]]]]]]}', { maxDepth: 7 })),
        null,
      );
      eq(
        "keys with brackets",
        msg(() => parseBoundedJson('{"[[[[":1}', { maxDepth: 2 })),
        null,
      );
      eq(
        "bytes at the limit",
        msg(() => parseBoundedJson("[1,2,3]", { maxBytes: 7 })),
        null,
      );
      eq(
        "bytes over the limit",
        msg(() => parseBoundedJson("[1,2,3]", { maxBytes: 6 })),
        "output_too_large:output too large",
      );
      eq(
        "the default byte cap",
        msg(() => parseBoundedJson(Buffer.alloc(64 * 1024 * 1024 + 1, 0x20))),
        "output_too_large:output too large",
      );
      eq(
        "the default byte cap, exactly",
        msg(() => parseBoundedJson(Buffer.alloc(64 * 1024 * 1024, 0x20))),
        "output_invalid:not valid JSON",
      );
      eq(
        "a BOM",
        parseBoundedJson(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("[1]")])),
        [1],
      );
      eq(
        "a primitive root",
        msg(() => parseBoundedJson("5", { maxNodes: 0 })),
        null,
      );
      eq(
        "nodes at the limit",
        msg(() => parseBoundedJson("[1,2,3,4,5]", { maxNodes: 6 })),
        null,
      );
      eq(
        "nodes over the limit",
        msg(() => parseBoundedJson("[1,2,3,4,5]", { maxNodes: 5 })),
        "output_too_large:too many nodes",
      );
      eq(
        "object nodes",
        msg(() => parseBoundedJson('{"a":{"b":{}}}', { maxNodes: 5 })),
        null,
      );
      eq(
        "object nodes over",
        msg(() => parseBoundedJson('{"a":{"b":{}}}', { maxNodes: 4 })),
        "output_too_large:too many nodes",
      );
      eq(
        "nested arrays count once",
        msg(() => parseBoundedJson("[[1],[2]]", { maxNodes: 7 })),
        null,
      );
      eq(
        "nested arrays count once, over",
        msg(() => parseBoundedJson("[[1],[2]]", { maxNodes: 6 })),
        "output_too_large:too many nodes",
      );
      eq(
        "forbidden key message",
        msg(() => parseBoundedJson('{"x":{"__proto__":1}}')),
        "output_invalid:forbidden key",
      );
      // ---- run-parse: exact results
      const failedZero = runToolParse(TRIVY, { stdout: Buffer.from("[]"), exitCode: 3 }, ctxFor());
      eq(
        "a failed run has zero counters",
        [
          failedZero.recordsSeen,
          failedZero.recordsDropped,
          failedZero.findingsMapped,
          failedZero.truncated,
          Object.values(failedZero.severityCounts).join(),
        ],
        [0, 0, 0, false, "0,0,0,0,0"],
      );
      eq(
        "a cut run is flagged truncated",
        runToolParse(TRIVY, { stdout: Buffer.from("[]"), exitCode: 0, truncated: true }, ctxFor())
          .truncated,
        true,
      );
      const notList = fakeAdapter("trivy", "sca", { parse: () => ({ not: "a list" }) });
      const notListRun = runToolParse(notList, out([]), ctxFor());
      eq(
        "a non-list parse result",
        [notListRun.status, notListRun.reason],
        ["failed", "output_invalid"],
      );
      const five = Array.from({ length: 5 }, (_, i) => ({
        id: `CVE-1-${i}`,
        purl: LODASH,
        severity: i < 3 ? "HIGH" : "LOW",
      }));
      const clean = parse(TRIVY, five);
      eq(
        "a clean run",
        [clean.status, clean.reason, clean.truncated, clean.severityCounts],
        ["succeeded", null, false, { critical: 0, high: 3, medium: 0, low: 2, info: 0 }],
      );
      const oneBad = parse(TRIVY, [...five.slice(0, 4), { id: 7 }]);
      eq(
        "exactly 20 percent dropped",
        [oneBad.status, oneBad.reason, oneBad.recordsDropped, oneBad.recordsSeen],
        ["partial", "output_invalid", 1, 5],
      );
      eq(
        "40 percent dropped",
        parse(TRIVY, [...five.slice(0, 3), { id: 7 }, { id: 8 }]).status,
        "failed",
      );
      const limit = runToolParse(TRIVY, out(five), ctxFor(), { maxRecords: 5 });
      eq(
        "exactly maxRecords",
        [limit.status, limit.truncated, limit.recordsSeen],
        ["succeeded", false, 5],
      );
      const over = runToolParse(TRIVY, out(five), ctxFor(), { maxRecords: 4 });
      eq(
        "one over maxRecords",
        [over.status, over.reason, over.truncated],
        ["partial", "output_too_large", true],
      );
      eq(
        "the adapter cap",
        runToolParse(fakeAdapter("trivy", "sca", { maxRecords: 3 }), out(five), ctxFor())
          .recordsSeen,
        3,
      );
      eq(
        "the adapter cap cannot raise the kit cap",
        runToolParse(fakeAdapter("trivy", "sca", { maxRecords: 1000 }), out(five), ctxFor(), {
          maxRecords: 2,
        }).recordsSeen,
        2,
      );
      const undef = parse(GITLEAKS, [
        {
          id: "the undefined rule",
          title: "undefined behaviour null",
          path: "a.env",
          line: 1,
          typeClass: "jwt",
        },
      ]);
      eq(
        "a record without a secret value",
        [undef.status, undef.candidates[0].title],
        ["succeeded", "undefined behaviour null"],
      );
      const emptySecret = parse(GITLEAKS, [
        { id: "r", title: "plain title", path: "a.env", line: 1, typeClass: "jwt", secret: "" },
      ]);
      eq("an empty secret value", emptySecret.candidates[0].title, "plain title");
      eq(
        "a one character value leaves no length trace",
        "valueLengthBucket" in
          parse(GITLEAKS, [{ id: "r", path: "a.env", line: 1, typeClass: "jwt", secret: "x" }])
            .candidates[0],
        false,
      );
      eq(
        "the schema refuses a length bucket key (strict, D-5)",
        findingSchema.safeParse({
          ...merge("secrets", sec(GITLEAKS, {}))[0],
          valueLengthBucket: "<=32",
        }).success,
        false,
      );
      eq(
        "a 4 character value is scrubbed",
        parse(GITLEAKS, [
          {
            id: "r",
            title: "has pw12 inside",
            path: "a.env",
            line: 1,
            typeClass: "jwt",
            secret: "pw12",
          },
        ]).candidates[0].title,
        "has [REDACTED] inside",
      );
      eq(
        "a 3 character value is not",
        parse(GITLEAKS, [
          {
            id: "r",
            title: "has abc inside",
            path: "a.env",
            line: 1,
            typeClass: "jwt",
            secret: "abc",
          },
        ]).candidates[0].title,
        "has abc inside",
      );
      eq(
        "a number as a secret value",
        parse(GITLEAKS, [
          {
            id: "r",
            title: "n 123456 n",
            path: "a.env",
            line: 1,
            typeClass: "jwt",
            secret: 123456,
          },
        ]).candidates[0].title,
        "n [REDACTED] n",
      );
      const sastWithSecret = fakeAdapter("bandit", "sast", {
        secretFields: ["secret"],
        fingerprintField: "secret",
      });
      const fpRun = runToolParse(
        sastWithSecret,
        out([{ id: "b", path: "a.js", line: 1, severity: "HIGH", secret: "some value 123" }]),
        ctxFor(TASK_A, { fingerprinter: createTaskFingerprinter() }),
      );
      ok(
        p,
        fpRun.status === "succeeded" && fpRun.candidates[0].mergeHints?.fingerprint === undefined,
        "a non-secret candidate received a fingerprint",
      );
      for (const value of ["x", 5, [], true])
        eq(
          `mapper returned ${JSON.stringify(value)}`,
          runToolParse(
            fakeAdapter("trivy", "sca", { map: () => value }),
            out([{ id: "CVE-1-1", purl: LODASH }]),
            ctxFor(),
          ).candidates.length,
          0,
        );
      // ---- scrubber details
      const nest = (n, leaf) => {
        let v = leaf;
        for (let i = 0; i < n; i += 1) v = { k: v };
        return v;
      };
      const nestArr = (n, leaf) => {
        let v = leaf;
        for (let i = 0; i < n; i += 1) v = [v];
        return v;
      };
      ok(
        p,
        throwsCode(() => scrubDeep(nest(8, "x"), [])) === null &&
          throwsCode(() => scrubDeep(nest(9, "x"), [])) !== null,
        "object depth boundary",
      );
      ok(
        p,
        throwsCode(() => scrubDeep(nestArr(8, "x"), [])) === null &&
          throwsCode(() => scrubDeep(nestArr(9, "x"), [])) !== null,
        "array depth boundary",
      );
      eq(
        "forbidden keys are dropped",
        Object.keys(
          scrubDeep(
            JSON.parse('{"__proto__":{"x":1},"constructor":1,"prototype":2,"ok":"fine"}'),
            [],
          ),
        ),
        ["ok"],
      );
      eq("OSC sequence", scrubDeep("a\u001b]0;evil title\u0007b", []), "ab");
      eq("OSC sequence ended by ST", scrubDeep("a\u001b]0;evil\u001b\\b", []), "ab");
      eq("ANSI sequence", scrubDeep("a\u001b[1;31mb\u001b[0m", []), "ab");
      eq("a path keeps its exact bytes", scrubDeep({ path: "a\u202eb" }, []), { path: "a\u202eb" });
      // ---- storage details
      const sbomF = merge("sbom", [
        ...cands(SYFT, [{ purl: "pkg:npm/s@1", path: "p" }]),
        ...cands(TRIVY_SBOM, [{ purl: "pkg:npm/s@1", path: "q" }]),
      ])[0];
      eq(
        "detail extra",
        [findingToDetail(sbomF).extra.locationCount, findingToDetail(sbomF).extra.ruleTool],
        [2, "syft"],
      );
      eq("default scope", findingToDetail(sbomF).scope, { kind: "full", inScope: true });
      // `extra` is validated at write time (owner decision 2026-11-19): strict, bounded, scrubbed
      const extraOk = findingToDetail(sbomF).extra;
      ok(p, detailExtraSchema.safeParse(extraOk).success, "control: a built extra is valid");
      for (const [label, bad] of [
        ["an unknown key", { ...extraOk, note: "x" }],
        ["a value length bucket key", { ...extraOk, valueLengthBucket: "<=16" }],
        ["a secret key", { ...extraOk, secret: "hunter2hunter2" }],
        ["a fingerprint key", { ...extraOk, fingerprint: "ab".repeat(16) }],
        ["a missing raw reference", { ...extraOk, rawRef: undefined }],
        ["an unknown tool", { ...extraOk, ruleTool: "grype" }],
        [
          "too many locations",
          { ...extraOk, locations: Array.from({ length: 21 }, () => ({ path: "a" })) },
        ],
        ["a traversal path", { ...extraOk, locations: [{ path: "../etc/passwd" }] }],
        ["a control character", { ...extraOk, ruleName: "a\u0000b" }],
        ["a long name", { ...extraOk, ruleName: "x".repeat(201) }],
        ["a string where an object belongs", { ...extraOk, fix: "x" }],
        [
          "too large",
          {
            ...extraOk,
            component: { ...extraOk.component, name: "x".repeat(200) },
            fix: { fixedVersions: Array.from({ length: 10 }, () => "y".repeat(100)) },
            ruleName: "z".repeat(200),
            locations: Array.from({ length: 20 }, (_, i) => ({ path: `${"d".repeat(1000)}/${i}` })),
          },
        ],
        ["an array", [extraOk]],
        ["a string", "x"],
        ["null", null],
        ["an empty object", {}],
      ])
        ok(p, !detailExtraSchema.safeParse(bad).success, `extra accepted ${label}`);
      // the size boundary of `extra`: exactly 16384 bytes of jsonb text is accepted, one more is not
      const sized = (lastLen) => ({
        ruleTool: "syft",
        rawRef: { toolRunId: randomUUID(), ordinal: 0 },
        locations: [
          ...Array.from({ length: 19 }, (_, i) => ({ path: `${"d".repeat(800)}/${i}` })),
          { path: "e".repeat(lastLen) },
        ],
      });
      let lastLen = 1;
      while (jsonbTextBytes(sized(lastLen)) < FINDING_LIMITS.extraBytes && lastLen < 1024)
        lastLen += 1;
      eq(
        "fixture: exactly the extra limit",
        jsonbTextBytes(sized(lastLen)),
        FINDING_LIMITS.extraBytes,
      );
      ok(
        p,
        detailExtraSchema.safeParse(sized(lastLen)).success,
        "extra of exactly 16384 bytes refused",
      );
      ok(
        p,
        !detailExtraSchema.safeParse(sized(lastLen + 1)).success,
        "extra of 16385 bytes accepted",
      );
      const prototypeExtra = JSON.parse(
        '{"ruleTool":"syft","rawRef":{"toolRunId":"' +
          randomUUID() +
          '","ordinal":0},"__proto__":{"x":1}}',
      );
      ok(p, !detailExtraSchema.safeParse(prototypeExtra).success, "extra accepted __proto__");
      const leaky = toStorageRows(
        [{ ...sbomF, rule: { ...sbomF.rule, name: "key ghp_abcdefghijklmnopqrstuv1234 here" } }],
        10,
      );
      ok(
        p,
        leaky.details.length === 1 &&
          !JSON.stringify(leaky.details[0].extra).includes("ghp_abcdefghij") &&
          detailExtraSchema.safeParse(leaky.details[0].extra).success,
        "a credential in extra was stored",
      );
      const secretF = merge("secrets", sec(GITLEAKS, {}))[0];
      eq(
        "secret item data",
        [
          findingToItem(secretF).data,
          findingToItem({ ...secretF, preview: undefined }).data,
          findingToItem(sbomF).data,
        ],
        [{ preview: secretF.preview }, {}, {}],
      );
      ok(
        p,
        !("preview" in findingToItem({ ...secretF, preview: undefined }).data),
        "an undefined preview key",
      );
      const badFinding = {
        ...merge("secrets", sec(GITLEAKS, { path: "x.env" }))[0],
        kind: "component",
      };
      const mixed = toStorageRows(
        [
          merge("secrets", sec(GITLEAKS, { path: "one.env" }))[0],
          badFinding,
          merge("secrets", sec(GITLEAKS, { path: "three.env" }))[0],
        ],
        10,
      );
      eq(
        "an invalid finding in the middle",
        [
          mixed.items.length,
          mixed.details.length,
          mixed.dropped,
          mixed.items[1].path,
          mixed.details[1].dedupKey,
        ],
        [2, 2, 1, "three.env", "secrets|three.env|4|jwt"],
      );
      const credF = {
        ...secretF,
        evidence: { kind: "line", snippet: "token ghp_abcdefghijklmnopqrstuvwxyz1234" },
      };
      const credRun = toStorageRows([credF, secretF], 10);
      // an excerpt that still looks like a credential is not stored but the finding is kept (part H); a credential anywhere else drops it
      eq(
        "a credential in the evidence",
        [credRun.items.length, credRun.dropped, credRun.details[0].evidence],
        [2, 0, null],
      );
      // the row size equals the database formula, evidence is shed first
      const sizeOf = (f) => detailRowBytes(findingToDetail(f));
      const evidenceFor = (target) => ({
        kind: "window",
        snippet: "x".repeat(target - jsonbTextBytes({ kind: "window", snippet: "" })),
      });
      const makeBulk = (len) => ({
        ...secretF,
        locations: Array.from({ length: 20 }, (_, i) => ({ path: `${"d".repeat(len)}/${i}` })),
        locationCount: 20,
      });
      let len = 100;
      while (sizeOf(makeBulk(len)) < FINDING_LIMITS.detailRowBytes - 3000) len += 10;
      const bulk = makeBulk(len);
      const bulkSize = sizeOf(bulk);
      const exact = { ...bulk, evidence: evidenceFor(FINDING_LIMITS.detailRowBytes - bulkSize) };
      ok(p, bulkSize < FINDING_LIMITS.detailRowBytes - 100, `fixture: bulk ${bulkSize}`);
      const small = { ...secretF, evidence: evidenceFor(2000) };
      eq(
        "a detail that fits keeps its evidence",
        toStorageRows([small], 5).details[0].evidence !== null,
        true,
      );
      const exactSize = sizeOf(exact);
      eq("fixture: exactly the row limit", exactSize, FINDING_LIMITS.detailRowBytes);
      eq(
        "exactly 16384 bytes keeps the evidence",
        toStorageRows([exact], 5).details[0].evidence !== null,
        true,
      );
      const plus = { ...bulk, evidence: evidenceFor(FINDING_LIMITS.detailRowBytes - bulkSize + 1) };
      eq(
        "one byte over sheds the evidence",
        [sizeOf(plus), toStorageRows([plus], 5).details[0].evidence],
        [FINDING_LIMITS.detailRowBytes + 1, null],
      );
      // ---- jsonb text size equals the database
      eq(
        "jsonb size",
        [
          jsonbTextBytes({ a: 1, b: [1, 2], c: "é", d: null, e: undefined }),
          jsonbTextBytes([]),
          jsonbTextBytes({}),
          jsonbTextBytes([[]]),
          jsonbTextBytes(true),
          jsonbTextBytes('a"b'),
        ],
        [Buffer.byteLength('{"a": 1, "b": [1, 2], "c": "é", "d": null}'), 2, 2, 4, 4, 6],
      );
      ok(p, throwsCode(() => jsonbTextBytes(nest(40, 1))) !== null, "jsonb size depth guard");
      // ---- schema caps: accepted at the limit, refused one past it
      const [base] = merge(
        "sca",
        cands(TRIVY, [{ id: "CVE-1-1", purl: LODASH, severity: "HIGH" }]),
      );
      const [secBase] = merge("secrets", sec(GITLEAKS, {}));
      const set = (obj, pathStr, value) => {
        const copy = structuredClone(obj);
        const keys = pathStr.split(".");
        let o = copy;
        for (const k of keys.slice(0, -1)) o = o[k];
        o[keys.at(-1)] = value;
        return copy;
      };
      const withParts = {
        ...base,
        provenance: [{ ...base.provenance[0], confidenceRaw: "c" }],
        rule: { ...base.rule, name: "n" },
        fix: { fixedVersions: ["1"] },
        scmRef: { provider: "github", repoFullName: "o/r", commitSha: "a".repeat(40) },
      };
      ok(p, findingSchema.safeParse(withParts).success, "control: the parts finding");
      for (const [where, max] of [
        ["provenance.0.toolVersion", 100],
        ["provenance.0.severityRaw", 60],
        ["provenance.0.confidenceRaw", 40],
        ["component.name", 200],
        ["component.version", 100],
        ["component.ecosystem", 40],
        ["rule.name", 200],
        ["rule.id", 200],
        ["title", 200],
        ["advisories.0.id", 60],
        ["advisories.0.family", 20],
        ["fix.fixedVersions.0", 100],
        ["scmRef.repoFullName", 200],
      ]) {
        ok(
          p,
          findingSchema.safeParse(set(withParts, where, "x".repeat(max))).success,
          `${where} at ${max} refused`,
        );
        ok(
          p,
          !findingSchema.safeParse(set(withParts, where, "x".repeat(max + 1))).success,
          `${where} over ${max} accepted`,
        );
      }
      ok(
        p,
        findingSchema.safeParse(set(withParts, "provenance.0.severityRaw", "")).success &&
          !findingSchema.safeParse(set(withParts, "provenance.0.toolVersion", "")).success,
        "empty severityRaw is allowed, an empty tool version is not",
      );
      ok(
        p,
        findingSchema.safeParse(set(withParts, "dedupKey", `sca|${"x".repeat(596)}`)).success &&
          !findingSchema.safeParse(set(withParts, "dedupKey", `sca|${"x".repeat(597)}`)).success,
        "dedupKey 600",
      );
      ok(
        p,
        findingSchema.safeParse(set(withParts, "component.purl", "x".repeat(500))).success &&
          !findingSchema.safeParse(set(withParts, "component.purl", "x".repeat(501))).success,
        "purl 500",
      );
      const advN = (n) =>
        Array.from({ length: n }, (_, i) => ({ id: `CVE-1-${i}`, family: "CVE" }));
      ok(
        p,
        findingSchema.safeParse({ ...withParts, advisories: advN(20) }).success &&
          !findingSchema.safeParse({ ...withParts, advisories: advN(21) }).success,
        "20 advisories",
      );
      const cweN = (n) => Array.from({ length: n }, (_, i) => i + 1);
      ok(
        p,
        findingSchema.safeParse({ ...withParts, cwe: cweN(10) }).success &&
          !findingSchema.safeParse({ ...withParts, cwe: cweN(11) }).success,
        "10 cwe",
      );
      ok(
        p,
        findingSchema.safeParse({ ...withParts, cwe: [1] }).success &&
          !findingSchema.safeParse({ ...withParts, cwe: [0] }).success &&
          findingSchema.safeParse({ ...withParts, cwe: [100000] }).success &&
          !findingSchema.safeParse({ ...withParts, cwe: [100001] }).success,
        "cwe range",
      );
      const locN = (n) => Array.from({ length: n }, (_, i) => ({ path: `p/${i}` }));
      ok(
        p,
        findingSchema.safeParse({ ...withParts, locations: locN(20), locationCount: 20 }).success &&
          !findingSchema.safeParse({ ...withParts, locations: locN(21), locationCount: 21 })
            .success,
        "20 locations",
      );
      ok(
        p,
        findingSchema.safeParse({ ...withParts, locationCount: 0 }).success &&
          !findingSchema.safeParse({ ...withParts, locationCount: -1 }).success,
        "locationCount",
      );
      const fixN = (n) => ({ fixedVersions: Array.from({ length: n }, (_, i) => String(i)) });
      ok(
        p,
        findingSchema.safeParse({ ...withParts, fix: fixN(10) }).success &&
          !findingSchema.safeParse({ ...withParts, fix: fixN(11) }).success,
        "10 fixed versions",
      );
      ok(
        p,
        findingSchema.safeParse({ ...withParts, url: `https://${"y".repeat(1992)}` }).success &&
          !findingSchema.safeParse({ ...withParts, url: `https://${"y".repeat(1993)}` }).success,
        "url 2000",
      );
      const sha = (s) => ({ ...withParts, scmRef: { ...withParts.scmRef, commitSha: s } });
      ok(
        p,
        !findingSchema.safeParse(sha("a".repeat(39))).success &&
          !findingSchema.safeParse(sha("a".repeat(41))).success &&
          findingSchema.safeParse(sha("0123456789abcdef0123456789abcdef01234567")).success,
        "commit sha",
      );
      const digest = (d) => ({
        ...withParts,
        provenance: [{ ...withParts.provenance[0], imageDigestShort: d }],
      });
      ok(
        p,
        findingSchema.safeParse(digest("sha256:0f0f0f0f")).success &&
          !findingSchema.safeParse(digest("sha256:0f0f0f0")).success &&
          !findingSchema.safeParse(digest("sha256:0f0f0f0f0")).success,
        "short digest",
      );
      const quoted = (n) => ({
        ...withParts.provenance[0],
        ruleId: '"'.repeat(n),
        confidenceRaw: undefined,
      });
      let q = 1;
      while (jsonbTextBytes(quoted(q + 1)) <= 600 && q < 200) q += 1;
      ok(
        p,
        jsonbTextBytes(quoted(q)) <= 600 &&
          jsonbTextBytes(quoted(q + 1)) > 600 &&
          findingSchema.safeParse({ ...withParts, provenance: [quoted(q)] }).success &&
          !findingSchema.safeParse({ ...withParts, provenance: [quoted(q + 1)] }).success,
        `provenance entry boundary ${jsonbTextBytes(quoted(q))}/${jsonbTextBytes(quoted(q + 1))}`,
      );
      ok(
        p,
        jsonbTextBytes(quoted(q)) === 600 || jsonbTextBytes(quoted(q)) === 599,
        `fixture: the boundary entry is ${jsonbTextBytes(quoted(q))} bytes`,
      );
      const multi = {
        ...withParts,
        confidenceBasis: "multi_tool",
        provenance: [
          withParts.provenance[0],
          { ...withParts.provenance[0], toolId: "osv-scanner" },
        ],
      };
      ok(p, findingSchema.safeParse(multi).success, "control: two tools");
      const evBig = {
        kind: "line",
        language: "l".repeat(30),
        nodeKind: "n".repeat(30),
        snippet: "x".repeat(4096),
        truncated: false,
        startLine: 1,
        endLine: 2,
        focusStart: 1,
        focusEnd: 2,
      };
      ok(
        p,
        findingSchema.safeParse({ ...secBase, evidence: evBig }).success &&
          !findingSchema.safeParse({
            ...secBase,
            evidence: { ...evBig, snippet: "x".repeat(4097) },
          }).success,
        "snippet 4096",
      );
      ok(
        p,
        !findingSchema.safeParse({ ...secBase, evidence: { ...evBig, language: "l".repeat(31) } })
          .success &&
          !findingSchema.safeParse({ ...secBase, evidence: { ...evBig, nodeKind: "n".repeat(31) } })
            .success,
        "evidence labels 30",
      );
      ok(
        p,
        findingSchema.safeParse({
          ...secBase,
          location: { ...secBase.location, startColumn: 1, endColumn: 1 },
        }).success &&
          !findingSchema.safeParse({
            ...secBase,
            location: { ...secBase.location, startColumn: 0 },
          }).success &&
          !findingSchema.safeParse({ ...secBase, location: { ...secBase.location, endColumn: 0 } })
            .success,
        "columns start at 1",
      );
      ok(
        p,
        !findingSchema.safeParse({ ...secBase, location: { path: "a.env", endLine: 3 } }).success &&
          !findingSchema.safeParse({
            ...secBase,
            location: { path: "a.env", startLine: 5, endLine: 3 },
          }).success &&
          findingSchema.safeParse({
            ...secBase,
            location: { path: "a.env", startLine: 3, endLine: 3 },
          }).success,
        "line range",
      );
      const sastBase = merge(
        "sast",
        cands(OPENGREP, [{ id: "o", path: "s.js", line: 1, severity: "ERROR" }]),
      )[0];
      ok(
        p,
        !findingSchema.safeParse({ ...sastBase, location: { path: "s.js" } }).success &&
          !findingSchema.safeParse({ ...secBase, location: { path: "a.env" } }).success,
        "a line is required for code issues and secrets",
      );
      ok(
        p,
        !findingSchema.safeParse({ ...withParts, rule: { ...withParts.rule, tool: "osv-scanner" } })
          .success,
        "the rule tool must be in the provenance",
      );
      ok(
        p,
        findingSchema.safeParse({ ...multi, rule: { ...multi.rule, tool: "osv-scanner" } }).success,
        "the rule tool may be any tool of the provenance",
      );
      const candOf = cands(TRIVY, [{ id: "CVE-1-1", purl: LODASH }])[0];
      for (const bad of [5, "", null, "x".repeat(1025)])
        ok(
          p,
          !candidateSchema.safeParse({ ...candOf, location: { path: bad } }).success,
          `path ${JSON.stringify(bad)}`,
        );
      const hints = (h) => candidateSchema.safeParse({ ...candOf, mergeHints: h }).success;
      ok(
        p,
        hints({ ruleClass: "r".repeat(200) }) &&
          !hints({ ruleClass: "r".repeat(201) }) &&
          hints({ primaryId: "p".repeat(80) }) &&
          !hints({ primaryId: "p".repeat(81) }) &&
          hints({ blockId: "b".repeat(80) }) &&
          !hints({ blockId: "b".repeat(81) }) &&
          hints({ aliases: Array.from({ length: 40 }, () => "a".repeat(80)) }) &&
          !hints({ aliases: Array.from({ length: 41 }, () => "a") }) &&
          !hints({ aliases: ["a".repeat(81)] }),
        "merge hint caps",
      );
      // ---- second sweep round: tie-breaks by raw reference, parse scanning, exact boundaries
      // two Trivy records for two advisories, in the order opposite to their keys; Osv overlaps both: the first by KEY order wins
      const rev = [
        ...cands(TRIVY, [
          { id: "CVE-2020-0002", aliases: ["GHSA-bbbb-bbbb-bbbb"], purl: LODASH, severity: "LOW" },
          { id: "CVE-2020-0001", aliases: ["GHSA-aaaa-aaaa-aaaa"], purl: LODASH, severity: "HIGH" },
        ]),
        ...cands(OSV, [
          {
            id: "GHSA-aaaa-aaaa-aaaa",
            aliases: ["CVE-2020-0001", "CVE-2020-0002"],
            purl: LODASH,
            severity: "MODERATE",
          },
        ]),
      ];
      for (const order of perms(rev))
        eq(
          "guard keeps the first by key order, records in reverse order",
          merge("sca", order)
            .map((f) => `${f.provenance.map((x) => x.toolId).join("+")}:${f.rule.id}`)
            .sort(),
          ["trivy+osv-scanner:CVE-2020-0001", "trivy:CVE-2020-0002"].sort(),
        );
      // two identical Trivy records and one Osv record: the Osv record joins the record with the lowest reference
      const dupT = cands(TRIVY, [
        { id: "CVE-3-3", purl: LODASH, severity: "HIGH" },
        { id: "CVE-3-3", purl: LODASH, severity: "HIGH" },
      ]);
      const oneO = cands(OSV, [{ id: "CVE-3-3", purl: LODASH, severity: "HIGH" }]);
      for (const order of perms([...dupT, ...oneO])) {
        const joined = merge("sca", order).find((f) => f.provenance.length === 2);
        eq(
          "sca duplicate reference order",
          joined.provenance.find((x) => x.toolId === "trivy").rawRef.ordinal,
          dupT[0].rawRef.ordinal,
        );
      }
      const dupB = cands(BANDIT, [
        { id: "b", path: "d.js", line: 5, severity: "HIGH", cwe: [79] },
        { id: "b", path: "d.js", line: 5, severity: "HIGH", cwe: [79] },
      ]);
      const oneG = cands(OPENGREP, [
        { id: "o", path: "d.js", line: 5, severity: "HIGH", cwe: [79] },
      ]);
      for (const order of perms([...dupB, ...oneG])) {
        const joined = merge("sast", order).find((f) => f.provenance.length === 2);
        eq(
          "sast duplicate reference order",
          joined.provenance.find((x) => x.toolId === "bandit").rawRef.ordinal,
          dupB[0].rawRef.ordinal,
        );
      }
      const dupL = sec(GITLEAKS, {}).concat(
        cands(GITLEAKS, [
          { id: "r", path: "src/a.env", line: 4, typeClass: "jwt", secret: "ey.value.value.value" },
        ]),
      );
      const oneD = sec(DETECT, {});
      for (const order of perms([...dupL, ...oneD])) {
        const joined = merge("secrets", order).find((f) => f.provenance.length === 2);
        eq(
          "secrets duplicate reference order",
          joined.provenance.find((x) => x.toolId === "gitleaks").rawRef.ordinal,
          Math.min(...dupL.map((c) => c.rawRef.ordinal)),
        );
      }
      // a scope on a non-base member, an unsorted location without a start line
      const scopedOther = merge("sbom", [
        ...cands(SYFT, [{ purl: "pkg:npm/z@1", path: "p" }]),
        ...cands(TRIVY_SBOM, [{ purl: "pkg:npm/z@1", path: "q", scope: "dev" }]),
      ])[0];
      eq("a scope only on the second member", scopedOther.component.scope, "dev");
      const mixedLoc = merge(
        "sbom",
        cands(
          fakeAdapter("syft", "sbom", {
            map: (r, c) => ({
              ...SYFT.map(r, c),
              locations: [{ path: "a/x", startLine: 1 }, { path: "a/x" }],
            }),
          }),
          [{ purl: "pkg:npm/m@1" }],
        ),
      )[0];
      eq(
        "a location without a line comes first",
        mixedLoc.locations.map((l) => l.startLine),
        [undefined, 1],
      );
      const locs3 = [{ path: "a/x", startLine: 1 }, { path: "a/x" }, { path: "a/x", startLine: 2 }];
      for (const order of perms(locs3))
        eq(
          "locations with and without a line, any order",
          merge(
            "sbom",
            cands(
              fakeAdapter("syft", "sbom", {
                map: (r, c) => ({ ...SYFT.map(r, c), locations: order }),
              }),
              [{ purl: "pkg:npm/m@1" }],
            ),
          )[0].locations.map((l) => l.startLine),
          [undefined, 1, 2],
        );
      const nestObj = (n) => {
        let v = 1;
        for (let i = 0; i < n; i += 1) v = { k: v };
        return v;
      };
      eq(
        "jsonb size, 32 objects deep",
        msg(() => jsonbTextBytes(nestObj(32))),
        null,
      );
      eq(
        "jsonb size, 33 objects deep",
        throwsCode(() => jsonbTextBytes(nestObj(33))) !== null,
        true,
      );
      // medium and high confidence: the higher one names the finding whatever the tool order
      const mid = cands(OPENGREP, [
        { id: "o-rule", path: "t.js", line: 5, severity: "ERROR", cwe: [79], confidence: "MEDIUM" },
      ]);
      const high = cands(BANDIT, [
        { id: "b-rule", path: "t.js", line: 5, severity: "ERROR", cwe: [79], confidence: "HIGH" },
      ]);
      for (const order of perms([mid[0], high[0]]))
        eq("medium versus high", merge("sast", order)[0].title, "b-rule");
      eq(
        "medium versus high, merged confidence",
        merge("sast", [mid[0], high[0]])[0].confidence,
        "high",
      );
      // ---- parse scanning: deep structure after strings
      const refused = (text, depth) => msg(() => parseBoundedJson(text, { maxDepth: depth }));
      eq(
        "deep after a plain string",
        refused('{"a":"xy","b":[[[[]]]]}', 3),
        "output_invalid:nesting too deep",
      );
      eq(
        "deep after an escaped quote",
        refused('{"a":"x\\"y","b":[[[[]]]]}', 3),
        "output_invalid:nesting too deep",
      );
      eq(
        "deep after an escaped backslash",
        refused('{"a":"x\\\\","b":[[[[]]]]}', 3),
        "output_invalid:nesting too deep",
      );
      eq(
        "deep after an escaped backslash and a quote",
        refused('{"a":"\\\\\\"","b":[[[[]]]]}', 3),
        "output_invalid:nesting too deep",
      );
      eq(
        "deep after two strings",
        refused('["a","b",[[[[]]]]]', 3),
        "output_invalid:nesting too deep",
      );
      eq(
        "records of a non-list",
        msg(() => recordsOf({ a: 1 })),
        "output_invalid:records are not a list",
      );
      eq(
        "records picked",
        recordsOf({ Results: [1, 2] }, (d) => d.Results),
        [1, 2],
      );
      // ---- exact boundaries of the JSON size measure and the schema
      const nestN = (n) => {
        let v = 1;
        for (let i = 0; i < n; i += 1) v = [v];
        return v;
      };
      eq(
        "jsonb size, 32 levels deep",
        msg(() => jsonbTextBytes(nestN(32))),
        null,
      );
      eq("jsonb size, 33 levels deep", throwsCode(() => jsonbTextBytes(nestN(33))) !== null, true);
      eq(
        "jsonb size of nested members",
        [jsonbTextBytes([[1, 2], [3]]), jsonbTextBytes({ a: { b: 1 } })],
        [Buffer.byteLength("[[1, 2], [3]]"), Buffer.byteLength('{"a": {"b": 1}}')],
      );
      const exactEntry = (target) => {
        const mk = (quotes, extra) => ({
          ...withParts.provenance[0],
          ruleId: '"'.repeat(quotes) + "x".repeat(extra),
          confidenceRaw: undefined,
        });
        for (let quotes = 0; quotes <= 200; quotes += 1)
          for (const extra of [0, 1]) {
            const e = mk(quotes, extra);
            if (jsonbTextBytes(e) === target && quotes + extra <= 200) return e;
          }
        return null;
      };
      const e600 = exactEntry(600);
      const e601 = exactEntry(601);
      ok(p, e600 && e601, "fixture: provenance entries of 600 and 601 bytes");
      ok(
        p,
        findingSchema.safeParse({ ...withParts, provenance: [e600] }).success &&
          !findingSchema.safeParse({ ...withParts, provenance: [e601] }).success,
        "provenance entry of exactly 600 / 601 bytes",
      );
      const exactEvidence = (target) => {
        for (let quotes = 0; quotes <= 4096; quotes += 1)
          for (const extra of [0, 1]) {
            if (quotes + extra > 4096) continue;
            const e = { kind: "line", snippet: '"'.repeat(quotes) + "x".repeat(extra) };
            if (jsonbTextBytes(e) === target) return e;
          }
        return null;
      };
      const ev8192 = exactEvidence(8192);
      const ev8193 = exactEvidence(8193);
      ok(p, ev8192 && ev8193, "fixture: evidence of 8192 and 8193 bytes");
      ok(
        p,
        findingSchema.safeParse({ ...secBase, evidence: ev8192 }).success &&
          !findingSchema.safeParse({ ...secBase, evidence: ev8193 }).success,
        "evidence of exactly 8192 / 8193 bytes",
      );
      return p;
    },
  },
];
