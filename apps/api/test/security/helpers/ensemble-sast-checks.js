import {
  cpSync,
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
import { COVERAGE_GAP_NAMES, findingSchema, rollUpTask } from "@qmentisai/shared";
import {
  FakeSandboxRuntime,
  SandboxError,
  assertRunArgsSafe,
  buildRunArgs,
  createCapacityGate,
  createImageResolver,
  createSandboxRunner,
  findCredentials,
  resolveRunSpecImage,
  validateRunSpec,
  validateSandboxConfig,
} from "@qmentisai/infra";
import {
  MergeBoundaryError,
  mergeTaskCandidates,
  runToolParse,
  toStorageRows,
} from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import { loadImageLock } from "../../../../workers/src/execution/engines/ensemble/catalog/index.js";
import { createEnsembleSastEngine } from "../../../../workers/src/execution/engines/ensemble/engine/sast-engine.js";
import { classifyToolExit } from "../../../../workers/src/execution/engines/ensemble/engine/tool-exit.js";
import { createTreePathExists } from "../../../../workers/src/execution/engines/ensemble/engine/tree-paths.js";
import {
  BANDIT_ARGV,
  BANDIT_FULL_TARGET,
  EVIDENCE_LIMITS,
  FORBIDDEN_REFERENCES,
  MAX_TARGETS,
  OPENGREP_ARGV,
  OPENGREP_ENV,
  OPENGREP_FULL_TARGET,
  RULE_PACK_LIMITS,
  SAST_TOOL_LIMITS,
  SUPPORTED_LANGUAGES,
  applicability,
  banditLines,
  buildEvidence,
  checkRulePack,
  createBanditAdapter,
  createOpengrepAdapter,
  createSastAdapterRegistry,
  filterToChanged,
  inventoryOf,
  isSafeTargetPath,
  languageOfFile,
  loadRulePack,
  planScope,
  rulePackDigest,
  scopedInventory,
  walkSourceTree,
} from "../../../../workers/src/execution/engines/ensemble/sast/index.js";
import { CONFIG_INPUT } from "./sandbox-checks.js";
import { TASK_A, TASK_B } from "./ensemble-fakes.js";

/**
 * Scan engines, part H (ADR-008 area 18, SPEC scan-engines 14.1 ENG-S03, S05, S06, S09, S11, S16 and 16.1 part H): the SAST ensemble
 * (Opengrep with the platform-owned rule pack, Bandit, the rule-class merge with line tolerance, language detection and the applicability
 * gate, the incremental scope, the SAST engine over a FakeSandboxRuntime). Pure functions and the fake runtime: no container, process
 * (except the tmp-directory fixtures), database or network. The mappers are proved against the REAL output captured on 2026-11-21
 * (`fixtures/scan-engines/sast/real`, Opengrep 2.0.0 and Bandit 1.9.4 over `fixtures/scan-engines/sast/tree`). Tool quality, rule content,
 * severity tables and tolerances stay out of ADR-008 scope; the policy properties (a repository file or comment never changes a result,
 * no secret value is stored, the pack is platform-owned and provenanced, the merge never crosses a task) are asserted.
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const ENGINE_DIR = path.join(ROOT, "apps/workers/src/execution/engines/ensemble");
const RULES_DIR = path.join(ENGINE_DIR, "sbom/rules");
const FIX = path.join(ROOT, "apps/api/test/security/fixtures/scan-engines/sast");
const real = (name) => readFileSync(path.join(FIX, "real", name));
const OG_TREE = real("opengrep-tree.json");
const OG_PLANTED = real("opengrep-planted.json");
const BD_TREE = real("bandit-tree.json");
const OG_HOSTILE = real("opengrep-hostile.json");
const BD_HOSTILE = real("bandit-hostile.json");

const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const same = (p, label, got, want) =>
  ok(
    p,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
  );
const hasControl = (t) => [...t].some((ch) => ch.charCodeAt(0) < 32 || ch === "‮");

const RUN_O = "00000000-0000-4000-8000-0000000000b1";
const RUN_B = "00000000-0000-4000-8000-0000000000b2";
const og = createOpengrepAdapter();
const bd = createBanditAdapter();
const ctxFor = (adapter, over = {}) => ({
  taskRef: TASK_A,
  toolRunId: adapter.toolId === "opengrep" ? RUN_O : RUN_B,
  toolVersion: adapter.toolId === "opengrep" ? "2.0.0" : "1.9.4",
  imageDigest: `sha256:${(adapter.toolId === "opengrep" ? "d4" : "e5").repeat(32)}`,
  ...over,
});
const asStreams = (doc, exitCode = 0) => ({
  stdout: Buffer.isBuffer(doc)
    ? doc
    : Buffer.from(typeof doc === "string" ? doc : JSON.stringify(doc)),
  exitCode,
});
const parseOg = (doc, over = {}, exit = 0) =>
  runToolParse(og, asStreams(doc, exit), ctxFor(og, over));
const parseBd = (doc, over = {}, exit = 1) =>
  runToolParse(bd, asStreams(doc, exit), ctxFor(bd, over));
const mergeAll = (candidates, taskRef = TASK_A) =>
  mergeTaskCandidates({ taskRef, scanType: "sast", candidates }).findings;

/** A minimal Opengrep report. `r`: { id, path, line, end, col, sev, cwe, conf, lines, message, category, value, extra }. */
const ogDoc = (rs, errors = []) => ({
  version: "2.0.0",
  results: rs.map((r) => ({
    check_id: r.id ?? "qm.python.sql-injection",
    path: `/src/${r.path ?? "a.py"}`,
    start: { line: r.line, col: r.col ?? 1, offset: 0 },
    end: { line: r.end ?? r.line, col: (r.col ?? 1) + 9, offset: 0 },
    extra: {
      message: r.message ?? "A finding.",
      severity: r.sev ?? "ERROR",
      metadata: {
        cwe: r.cwe === null ? [] : [`CWE-${r.cwe ?? 89}: Something`],
        confidence: r.conf ?? "HIGH",
        ...(r.category ? { category: r.category } : {}),
        ...(r.qm ? { qm_severity: r.qm } : {}),
      },
      lines: r.lines ?? "x = 1",
      metavars: r.value === undefined ? {} : { $VALUE: { abstract_content: r.value } },
      is_ignored: r.ignored ?? false,
      ...(r.extra ?? {}),
    },
  })),
  errors,
  paths: { scanned: [] },
});
/** A minimal Bandit report. `r`: { id, path, line, end, sev, conf, cwe (null: none), text, code }. */
const bdDoc = (rs, errors = []) => ({
  errors,
  generated_at: "2026-11-21T00:00:00Z",
  metrics: {},
  results: rs.map((r) => ({
    test_id: r.id ?? "B608",
    test_name: "hardcoded_sql_expressions",
    filename: `/src/${r.path ?? "a.py"}`,
    line_number: r.line,
    line_range:
      r.range ?? Array.from({ length: (r.end ?? r.line) - r.line + 1 }, (_, i) => r.line + i),
    col_offset: 4,
    end_col_offset: 20,
    issue_severity: r.sev ?? "MEDIUM",
    issue_confidence: r.conf ?? "HIGH",
    issue_text: r.text ?? "Bandit text.",
    issue_cwe: r.cwe === null ? undefined : { id: r.cwe ?? 89, link: "https://cwe.mitre.org/x" },
    code: r.code ?? `${r.line} x = 1\n`,
    more_info: "https://bandit.readthedocs.io/x",
  })),
});
const og1 = (r, task = TASK_A) =>
  runToolParse(og, asStreams(ogDoc([r])), ctxFor(og, { taskRef: task })).candidates;
const bd1 = (r, task = TASK_A) =>
  runToolParse(bd, asStreams(bdDoc([r]), 1), ctxFor(bd, { taskRef: task })).candidates;

const CANARIES = ["correct-horse-battery", "sk_live_abcdefghijklmnop", "hunter2-hunter2-hunter2"];

export const ENSEMBLE_SAST_CHECKS = [
  {
    id: "ENG-S06l",
    name: "SAST mapping and merge on REAL Opengrep and Bandit output (SPEC scan-engines 5.6.3, 5.7, 7.2, SE-12 to SE-14, 16.1 part H; the fixtures are the real reports of 2026-11-21 over the part H fixture tree: Opengrep 2.0.0 with the platform pack, Bandit 1.9.4): 26 Opengrep and 13 Bandit records all map (nothing dropped), they merge to 33 findings of which 6 carry both tools (the SQL injections of lines 13 and 14, the OS command injections of lines 15 and 16, the pickle load of line 18, the MD5 of line 20) with confidence high and the basis multi_tool, the rule id is the platform id without a path prefix, ERROR, WARNING and the Bandit levels map to high, medium and low, the CWE of both tools are joined (327 and 328 for MD5), the location has the start line and column the tool reported and a range only when the tool gave one, the evidence is the reported source line, a hard-coded credential finding has NO evidence and its value (and the values of the other two credential fixtures) appears nowhere in the findings or the storage rows, the `is_ignored` flag of Opengrep (planted nosemgrep comments) is never read: the planted report gives the same findings as the clean one, the output is identical for any order of the tools and records and for a second run, two tasks of one input stay separate, every finding is a valid finding and the storage rows carry no credential shape",
    async run() {
      const p = [];
      const t = (a, doc, exit) => runToolParse(a, asStreams(doc, exit), ctxFor(a));
      const o = t(og, OG_TREE, 0);
      const b = t(bd, BD_TREE, 1);
      same(
        p,
        "opengrep counts",
        [o.status, o.recordsSeen, o.recordsDropped, o.findingsMapped],
        ["succeeded", 26, 0, 26],
      );
      same(
        p,
        "bandit counts",
        [b.status, b.recordsSeen, b.recordsDropped, b.findingsMapped],
        ["succeeded", 13, 0, 13],
      );
      const findings = mergeAll([...o.candidates, ...b.candidates]);
      same(p, "merged count", findings.length, 33);
      for (const f of findings) {
        const parsed = findingSchema.safeParse(f);
        ok(p, parsed.success, `invalid finding ${f.dedupKey}`);
      }
      const both = findings.filter((f) => f.provenance.length > 1);
      same(
        p,
        "findings with both tools",
        both.map((f) => [f.location.path, f.location.startLine]).sort((a, c) => a[1] - c[1]),
        [
          ["svc/py/app.py", 13],
          ["svc/py/app.py", 14],
          ["svc/py/app.py", 15],
          ["svc/py/app.py", 16],
          ["svc/py/app.py", 18],
          ["svc/py/app.py", 20],
        ],
      );
      ok(
        p,
        both.every((f) => f.confidence === "high" && f.confidenceBasis === "multi_tool"),
        "both-tool findings are high and multi_tool",
      );
      same(
        p,
        "tool order of the provenance",
        both[0].provenance.map((x) => x.toolId),
        ["opengrep", "bandit"],
      );
      ok(
        p,
        findings.every((f) =>
          f.provenance.every(
            (x) => x.toolId !== "opengrep" || /^qm\.[a-z0-9]+\.[a-z0-9-]+$/.test(x.ruleId),
          ),
        ),
        "an Opengrep rule id still has a path prefix",
      );
      const at = (file, line, tool) =>
        findings.find(
          (f) =>
            f.location.path === file &&
            f.location.startLine === line &&
            f.provenance.some((x) => x.toolId === tool),
        );
      const md5 = at("svc/py/app.py", 20, "opengrep");
      same(p, "md5 cwe of both tools", md5.cwe, [327, 328]);
      same(
        p,
        "md5 rules",
        md5.provenance.map((x) => x.ruleId),
        ["qm.python.weak-hash", "B324"],
      );
      same(p, "md5 severity", [md5.severity, md5.severityAssumed], ["high", false]);
      const goSql = at("go/main.go", 16, "opengrep");
      same(
        p,
        "go sql",
        [
          goSql.severity,
          goSql.confidence,
          goSql.cwe,
          goSql.location.startColumn > 0,
          goSql.rule.id,
        ],
        ["high", "high", [89], true, "qm.go.sql-injection"],
      );
      ok(
        p,
        goSql.evidence?.snippet.includes("db.Query(fmt.Sprintf("),
        "the evidence is not the reported line",
      );
      same(
        p,
        "evidence kind",
        [goSql.evidence.kind, goSql.evidence.language, goSql.evidence.startLine],
        ["line", "go", 16],
      );
      same(p, "weak hash is medium", at("go/main.go", 18, "opengrep").severity, "medium");
      same(p, "bandit low", at("svc/py/app.py", 4, "bandit").severity, "low");
      same(p, "bandit medium", at("svc/py/app.py", 19, "bandit").severity, "medium");
      same(p, "eval rule confidence", at("web/app.js", 14, "opengrep").confidence, "medium");
      // a hard-coded credential: no evidence and no value anywhere
      const creds = findings.filter(
        (f) =>
          f.rule.id === "qm.go.hardcoded-credential" ||
          f.rule.id === "qm.js.hardcoded-credential" ||
          f.rule.id === "qm.python.hardcoded-credential",
      );
      same(p, "credential findings", creds.length, 3);
      ok(
        p,
        creds.every((f) => f.evidence === undefined || f.evidence === null),
        "a credential finding has evidence",
      );
      const rows = toStorageRows(findings, 50_000);
      same(
        p,
        "storage rows",
        [rows.items.length, rows.details.length, rows.dropped, rows.truncated],
        [33, 33, 0, false],
      );
      const everything = JSON.stringify([o.candidates, b.candidates, findings, rows]);
      for (const c of CANARIES)
        ok(p, !everything.includes(c), `the credential ${c.slice(0, 6)}... was stored`);
      ok(p, findCredentials(rows.details).length === 0, "a detail row carries a credential shape");
      ok(
        p,
        rows.details.some((d) => d.evidence?.snippet),
        "no detail row has evidence",
      );
      // the planted report (every line marked is_ignored by nosemgrep): the same findings
      const planted = t(og, OG_PLANTED, 0);
      ok(
        p,
        JSON.parse(OG_PLANTED).results.every((r) => r.extra.is_ignored === true),
        "the planted fixture is not marked ignored",
      );
      same(p, "planted counts", planted.findingsMapped, 26);
      const key = (list) =>
        JSON.stringify(
          list.map((f) => [f.dedupKey, f.severity, f.title, f.provenance.map((x) => x.ruleId)]),
        );
      same(
        p,
        "planted equals clean",
        key(mergeAll([...planted.candidates, ...b.candidates])),
        key(findings),
      );
      // order and repetition
      const shuffled = mergeAll([...b.candidates].reverse().concat([...o.candidates].reverse()));
      same(p, "order independent", key(shuffled), key(findings));
      same(
        p,
        "second run",
        key(mergeAll([...t(og, OG_TREE, 0).candidates, ...t(bd, BD_TREE, 1).candidates])),
        key(findings),
      );
      // two tasks stay separate
      const o2 = runToolParse(og, asStreams(OG_TREE), ctxFor(og, { taskRef: TASK_B }));
      same(p, "task B has its own findings", mergeAll(o2.candidates, TASK_B).length, 26);
      same(p, "task A unchanged", mergeAll(o.candidates).length, 26);
      let crossed = null;
      try {
        mergeAll([...o.candidates, ...o2.candidates]);
      } catch (e) {
        crossed = e instanceof MergeBoundaryError ? e.code : e?.name;
      }
      same(p, "candidates of two tasks", crossed, "task_mismatch");
      // each candidate points at its own tool run
      ok(
        p,
        o.candidates.every((c, i) => c.rawRef.toolRunId === RUN_O && c.rawRef.ordinal === i),
        "an Opengrep raw reference",
      );
      ok(
        p,
        b.candidates.every((c) => c.rawRef.toolRunId === RUN_B),
        "a Bandit raw reference",
      );
      return p;
    },
  },
  {
    id: "ENG-S06m",
    name: "SAST merge by rule class, file and line tolerance (SPEC scan-engines 5.6.3, SE-10 to SE-15, D-5, D-9, 16.1 part H; the REAL mappers over minimal reports): two candidates of DIFFERENT tools merge when the rule class (the CWE through the equivalence table) and the file are equal and their line ranges overlap or their start lines differ by at most the tolerance of 3 (3 merges, 4 does not), never when the file or the class differs, never when the tool is the same (two records of one tool stay two findings), and the tolerance is anchored at the FIRST member (a candidate 6 lines from the first never joins through a middle one); the sibling CWE of the table meet (328 and 327 of weak crypto, 77 and 78 and 88 of command injection, 89 and 564 of SQL injection) and CWE outside a group do not; a candidate with no CWE has the class `tool:<tool>:<rule>` and never merges across tools; the merged finding takes the HIGHEST severity, raises the confidence one step with the basis multi_tool, joins the CWE and the line range (a column that no longer sits on its line is dropped), keeps one provenance entry per tool, and its dedup key and order are the same for any input order; a merge key is NOT a finding identity: the same candidates in two tasks are two separate results and a candidate of another task is refused",
    async run() {
      const p = [];
      const one = (ogRec, bdRec) => mergeAll([...og1(ogRec), ...bd1(bdRec)]);
      const count = (ogRec, bdRec) => one(ogRec, bdRec).length;
      // tolerance
      same(p, "same line", count({ line: 10 }, { line: 10 }), 1);
      same(p, "3 lines apart merge", count({ line: 10 }, { line: 13 }), 1);
      same(p, "3 lines apart (other order) merge", count({ line: 13 }, { line: 10 }), 1);
      same(p, "4 lines apart do not", count({ line: 10 }, { line: 14 }), 2);
      same(p, "overlapping ranges merge", count({ line: 10, end: 30 }, { line: 20 }), 1);
      same(p, "range end touches", count({ line: 10, end: 20 }, { line: 20 }), 1);
      same(p, "range end one short, 4 apart", count({ line: 10, end: 11 }, { line: 15 }), 2);
      same(p, "another file", count({ line: 10, path: "a.py" }, { line: 10, path: "b.py" }), 2);
      same(p, "another class", count({ line: 10, cwe: 89 }, { line: 10, cwe: 79 }), 2);
      // sibling CWE of the equivalence table
      same(p, "weak crypto 328 and 327", count({ line: 5, cwe: 328 }, { line: 5, cwe: 327 }), 1);
      same(p, "weak crypto 326", count({ line: 5, cwe: 326 }, { line: 5, cwe: 328 }), 1);
      same(p, "command injection 78 and 77", count({ line: 5, cwe: 78 }, { line: 5, cwe: 77 }), 1);
      same(p, "command injection 88", count({ line: 5, cwe: 88 }, { line: 5, cwe: 78 }), 1);
      same(p, "sql 89 and 564", count({ line: 5, cwe: 564 }, { line: 5, cwe: 89 }), 1);
      same(p, "path traversal 22 and 23", count({ line: 5, cwe: 23 }, { line: 5, cwe: 22 }), 1);
      same(p, "credential 798 and 259", count({ line: 5, cwe: 259 }, { line: 5, cwe: 798 }), 1);
      same(p, "sql and command do not meet", count({ line: 5, cwe: 89 }, { line: 5, cwe: 78 }), 2);
      same(p, "eval 95 is its own class", count({ line: 5, cwe: 95 }, { line: 5, cwe: 94 }), 2);
      // no CWE: never across tools
      same(p, "no cwe on one side", count({ line: 5 }, { line: 5, cwe: null }), 2);
      same(p, "no cwe on both sides", count({ line: 5, cwe: null }, { line: 5, cwe: null }), 2);
      // same tool: never
      const sameTool = mergeAll([
        ...og1({ line: 5 }),
        ...og1({ line: 5, id: "qm.python.command-injection" }),
        ...og1({ line: 5 }),
      ]);
      same(p, "three Opengrep records of one line", sameTool.length, 3);
      const twoBandit = mergeAll([...bd1({ line: 7 }), ...bd1({ line: 7, id: "B602" })]);
      same(p, "two Bandit records of one line", twoBandit.length, 2);
      // anchored at the first member: no chaining of far lines
      const chain = mergeAll([...og1({ line: 10 }), ...bd1({ line: 13 }), ...bd1({ line: 16 })]);
      same(p, "chain: the far Bandit record stays alone", chain.length, 2);
      same(
        p,
        "chain: the middle one joined the first",
        chain.map((f) => [f.location.startLine, f.provenance.length]).sort(),
        [
          [10, 2],
          [16, 1],
        ],
      );
      // severity, confidence, range, provenance of a merged finding
      const m = one(
        { line: 10, end: 12, sev: "WARNING", conf: "LOW", col: 3 },
        { line: 11, end: 14, sev: "HIGH", conf: "LOW" },
      );
      same(p, "one finding", m.length, 1);
      const f = m[0];
      same(p, "highest severity wins", [f.severity, f.severityAssumed], ["high", false]);
      same(p, "confidence one step", [f.confidence, f.confidenceBasis], ["medium", "multi_tool"]);
      same(p, "range joined", [f.location.startLine, f.location.endLine], [10, 14]);
      ok(p, f.location.startColumn === 3, "the column of the first line was lost");
      ok(
        p,
        f.location.endColumn === undefined,
        "an end column that no longer sits on its end line was kept",
      );
      same(p, "dedup key", f.dedupKey, "sast|a.py|CWE-89|10");
      same(
        p,
        "one provenance entry per tool",
        f.provenance.map((x) => [x.toolId, x.ruleId, x.severityRaw, x.severityScale]),
        [
          ["opengrep", "qm.python.sql-injection", "WARNING", "opengrep"],
          ["bandit", "B608", "HIGH", "bandit"],
        ],
      );
      const unions = one({ line: 4, cwe: 78 }, { line: 4, cwe: 77, id: "B602" });
      same(p, "cwe joined", unions[0].cwe, [77, 78]);
      same(p, "the class of the group", unions[0].dedupKey, "sast|a.py|CWE-77|4");
      // an unmapped severity is assumed medium and a merge with a mapped one is not assumed
      const unmapped = one({ line: 4, sev: "NOPE" }, { line: 4, sev: "WEIRD" });
      same(
        p,
        "both unmapped",
        [unmapped[0].severity, unmapped[0].severityAssumed],
        ["medium", true],
      );
      const half = one({ line: 4, sev: "NOPE" }, { line: 4, sev: "MEDIUM" });
      same(p, "one mapped medium", [half[0].severity, half[0].severityAssumed], ["medium", false]);
      // a platform rule may set the severity itself, also critical
      const qm = one({ line: 4, sev: "WARNING", qm: "critical" }, { line: 400 });
      same(
        p,
        "qm_severity",
        qm.find((x) => x.provenance[0].toolId === "opengrep").severity,
        "critical",
      );
      // order independence
      const a = [...og1({ line: 10 }), ...og1({ line: 30, id: "qm.python.weak-hash", cwe: 328 })];
      const b = [...bd1({ line: 12 }), ...bd1({ line: 31, id: "B324", cwe: 327 })];
      const key = (list) =>
        JSON.stringify(list.map((x) => [x.dedupKey, x.provenance.map((y) => y.toolId)]));
      same(
        p,
        "order independent",
        key(mergeAll([...a, ...b])),
        key(mergeAll([...b.reverse(), ...a.reverse()])),
      );
      same(p, "two merged findings", mergeAll([...a, ...b]).length, 2);
      // a merge key is not an identity: two tasks, two results
      const t1 = mergeAll([...og1({ line: 5 }), ...bd1({ line: 5 })]);
      const t2 = mergeAll([...og1({ line: 5 }, TASK_B), ...bd1({ line: 5 }, TASK_B)], TASK_B);
      same(
        p,
        "both tasks give one finding with the same key",
        [t1.length, t2.length, t1[0].dedupKey === t2[0].dedupKey],
        [1, 1, true],
      );
      ok(p, t1[0].rawRef.toolRunId === t2[0].rawRef.toolRunId, "the runs of the fixture differ");
      let refused = null;
      try {
        mergeAll([...og1({ line: 5 }), ...bd1({ line: 5 }, TASK_B)]);
      } catch (e) {
        refused = e.code;
      }
      same(p, "another task's candidate", refused, "task_mismatch");
      return p;
    },
  },
  {
    id: "ENG-S09f",
    name: "hostile Opengrep and Bandit output is tolerated (SPEC scan-engines 7.2, SE-4, 11.2, ENG-S09, 16.1 part H): empty, truncated, non-JSON, a wrong root, a missing results list, a prototype key at any depth, nesting beyond the cap, the output cap and an unaccepted exit code (Opengrep 1 or 2, Bandit 2) give a failed tool with a fixed reason and no candidates, never an exception; Bandit exit 1 and Opengrep exit 0 are the accepted codes; a record whose path is outside the tree mount, relative, absolute elsewhere, with `..`, a backslash, a control character or bidirectional override, a rule id that is not a platform id (`rules.x`, a registry id, upper case, a path), a line that is zero, negative, fractional, a string or beyond the cap, an end before the start, a missing message or severity, a Bandit id that is not `B<digits>`, or a type error anywhere is dropped and counted (never merged, never stored), an unknown severity is assumed medium with the flag, a title with control, ANSI and bidirectional characters is cleaned and one with a credential is redacted, 20 percent dropped fails the tool and a smaller share makes it partial / output_invalid; files the tool reports in `errors` (a syntax error, a rule timeout, a Bandit `errors` entry) make a clean run partial with the reason output_invalid but never fail it, a hostile count of them is bounded; more than 50000 records are cut to a partial / output_too_large result; a tool-reported path that does not exist in the tree is dropped",
    async run() {
      const p = [];
      const fixedReasons = ["output_invalid", "output_too_large", "exit_code"];
      for (const [a, run, good] of [
        [og, parseOg, 0],
        [bd, parseBd, 1],
      ]) {
        const name = a.toolId;
        const failed = (stdout, exit = good, label = "") => {
          let r;
          try {
            r = runToolParse(a, { stdout, exitCode: exit }, ctxFor(a));
          } catch (e) {
            p.push(`${name} ${label}: threw ${e?.name}`);
            return;
          }
          ok(
            p,
            r.status === "failed" && fixedReasons.includes(r.reason) && r.candidates.length === 0,
            `${name} ${label}: ${r.status}/${r.reason}`,
          );
        };
        failed(Buffer.alloc(0), good, "empty");
        failed(Buffer.from('{"results": [{"check_id":'), good, "truncated");
        failed(Buffer.from("not json at all"), good, "not json");
        failed(Buffer.from("[1,2,3]"), good, "array root");
        failed(Buffer.from('{"errors": []}'), good, "no results");
        failed(Buffer.from('{"results": {}}'), good, "results is an object");
        failed(Buffer.from('{"results": [], "x": {"__proto__": {"a": 1}}}'), good, "prototype key");
        failed(Buffer.from('{"results": [], "constructor": 1}'), good, "constructor key");
        failed(Buffer.from(`{"results":${"[".repeat(200)}${"]".repeat(200)}}`), good, "nesting");
        failed(Buffer.from('{"results": []}'), 2, "exit 2");
        failed(Buffer.from('{"results": []}'), 7, "exit 7");
        failed(Buffer.from('{"results": []}'), 137, "exit 137");
        failed(Buffer.from('{"results": []}'), null, "no exit code");
        const cut = runToolParse(
          a,
          { stdout: Buffer.from('{"results": []}'), exitCode: good, truncated: true },
          ctxFor(a),
        );
        same(p, `${name} output cap`, [cut.status, cut.reason], ["failed", "output_too_large"]);
        const clean = run('{"results": [], "errors": []}');
        same(p, `${name} empty results`, [clean.status, clean.candidates.length], ["succeeded", 0]);
      }
      same(p, "Opengrep accepts only 0", [...og.acceptedExitCodes], [0]);
      same(p, "Bandit accepts 0 and 1", [...bd.acceptedExitCodes], [0, 1]);
      ok(
        p,
        parseOg(ogDoc([{ line: 1 }]), {}, 1).status === "failed",
        "Opengrep exit 1 was accepted",
      );
      ok(p, parseBd(bdDoc([{ line: 1 }]), {}, 2).status === "failed", "Bandit exit 2 was accepted");
      // records that must be dropped (one good record beside nine bad ones would fail the 20 percent rule, so test one at a time with many good)
      const goods = Array.from({ length: 20 }, (_, i) => ({ line: i + 1, path: "ok.py" }));
      const dropOg = (bad, label) => {
        const doc = ogDoc([...goods, bad.rec ?? { line: 1 }]);
        if (bad.edit) bad.edit(doc.results[20]);
        const r = parseOg(doc);
        same(
          p,
          `opengrep ${label}`,
          [r.status, r.recordsDropped, r.findingsMapped],
          ["partial", 1, 20],
        );
      };
      dropOg({ edit: (r) => (r.path = "/etc/passwd") }, "path outside the mount");
      dropOg({ edit: (r) => (r.path = "a.py") }, "relative path");
      dropOg({ edit: (r) => (r.path = "/src/../etc/passwd") }, "dot dot");
      dropOg({ edit: (r) => (r.path = "/src/a\\b.py") }, "backslash");
      dropOg({ edit: (r) => (r.path = "/src/a\nb.py") }, "newline in the path");
      dropOg({ edit: (r) => (r.path = "/src/") }, "empty path under the mount");
      dropOg({ edit: (r) => (r.check_id = "rules.qm-sast.qm.python.x") }, "path-prefixed rule id");
      dropOg(
        { edit: (r) => (r.check_id = "python.lang.security.audit.eval-detected") },
        "registry rule id",
      );
      dropOg({ edit: (r) => (r.check_id = "QM.python.x") }, "upper case rule id");
      dropOg({ edit: (r) => (r.check_id = "qm.python") }, "short rule id");
      dropOg({ edit: (r) => (r.check_id = 5) }, "numeric rule id");
      dropOg({ edit: (r) => (r.start.line = 0) }, "line 0");
      dropOg({ edit: (r) => (r.start.line = -3) }, "negative line");
      dropOg({ edit: (r) => (r.start.line = 1.5) }, "fractional line");
      dropOg({ edit: (r) => (r.start.line = "7") }, "string line");
      dropOg({ edit: (r) => (r.start.line = 10_000_001) }, "line beyond the cap");
      dropOg({ edit: (r) => ((r.start.line = 9), (r.end.line = 3)) }, "end before start");
      dropOg({ edit: (r) => (r.start.col = 0) }, "column 0");
      dropOg({ edit: (r) => (r.extra = null) }, "no extra");
      dropOg({ edit: (r) => (r.start = null) }, "no start");
      const dropBd = (edit, label) => {
        const doc = bdDoc([...goods, { line: 1 }]);
        edit(doc.results[20]);
        const r = parseBd(doc);
        same(
          p,
          `bandit ${label}`,
          [r.status, r.recordsDropped, r.findingsMapped],
          ["partial", 1, 20],
        );
      };
      dropBd((r) => (r.filename = "/etc/passwd"), "path outside the mount");
      dropBd((r) => (r.filename = "a.py"), "relative path");
      dropBd((r) => (r.filename = "/src/../x.py"), "dot dot");
      dropBd((r) => (r.test_id = "X123"), "not a Bandit id");
      dropBd((r) => (r.test_id = "B60"), "short Bandit id");
      dropBd((r) => (r.line_number = 0), "line 0");
      dropBd((r) => (r.line_number = "3"), "string line");
      dropBd((r) => (r.line_range = []), "empty line range");
      dropBd((r) => (r.issue_cwe = { id: 0 }), "cwe 0");
      // a null record, a wrong type of a record, a hostile errors member
      const mixed = parseOg({
        results: [...ogDoc(goods).results, null, 5, "x", [], { check_id: "qm.a.b" }],
        errors: [],
      });
      same(
        p,
        "non-object records",
        [mixed.status, mixed.recordsDropped, mixed.findingsMapped],
        ["partial", 5, 20],
      );
      const toomany = parseOg(
        ogDoc([...goods, ...Array.from({ length: 10 }, () => ({ line: 1, path: "/x" }))]),
      );
      same(
        p,
        "over 20 percent dropped",
        [toomany.status, toomany.reason],
        ["failed", "output_invalid"],
      );
      // a record without a severity or a message is kept (nothing is lost): severity assumed medium, the title falls back to the rule id
      const bare = parseOg(
        ogDoc([{ line: 1, path: "ok.py" }]).results.length
          ? {
              results: [
                {
                  ...ogDoc([{ line: 1, path: "ok.py" }]).results[0],
                  extra: { severity: 5, message: 5, metadata: 5 },
                },
              ],
            }
          : {},
      ).candidates;
      same(
        p,
        "an Opengrep record with wrong-typed extras",
        bare.map((c) => [c.severity, c.severityAssumed, c.title, c.confidence]),
        [["medium", true, "qm.python.sql-injection", "medium"]],
      );
      const bareB = bd1({ line: 1, text: 5 });
      same(
        p,
        "a Bandit record with a numeric text",
        bareB.map((c) => c.title),
        ["B608"],
      );
      // unknown severity: assumed medium
      same(
        p,
        "unknown opengrep severity",
        og1({ line: 1, sev: "SEVERE" }).map((c) => [c.severity, c.severityAssumed]),
        [["medium", true]],
      );
      same(
        p,
        "unknown bandit severity",
        bd1({ line: 1, sev: "UNDEFINED" }).map((c) => [c.severity, c.severityAssumed]),
        [["medium", true]],
      );
      // text containment
      const hostileText = og1({
        line: 1,
        message: "A\u001b[31mred\u001b[0m \u202eevil\u0000 text",
      })[0].title;
      ok(
        p,
        !hasControl(hostileText) && !hostileText.includes("\u001b"),
        `title not cleaned: ${JSON.stringify(hostileText)}`,
      );
      ok(p, hostileText.includes("\\u202e"), "a bidirectional override is not made visible");
      const withKey = og1({
        line: 1,
        message: "found AKIAIOSFODNN7EXAMPLE and password=hunter2hunter2 here",
      })[0].title;
      ok(
        p,
        !withKey.includes("AKIAIOSFODNN7EXAMPLE") && !withKey.includes("hunter2hunter2"),
        `credential in the title: ${withKey}`,
      );
      same(p, "title cap", og1({ line: 1, message: "x".repeat(5000) })[0].title.length, 200);
      same(p, "bandit title cap", bd1({ line: 1, text: "y".repeat(5000) })[0].title.length, 200);
      // errors: the files the tool could not process
      const withErrors = parseOg(
        ogDoc(goods, [{ code: 3, level: "warn", type: ["PartialParsing", []] }]),
      );
      same(
        p,
        "an error entry makes the run partial",
        [withErrors.status, withErrors.reason, withErrors.findingsMapped, withErrors.fileErrors],
        ["partial", "output_invalid", 20, 1],
      );
      const manyErrors = parseOg(
        ogDoc(
          goods,
          Array.from({ length: 5000 }, () => ({ level: "warn" })),
        ),
      );
      same(
        p,
        "5000 error entries stay one partial run",
        [manyErrors.status, manyErrors.fileErrors],
        ["partial", 5000],
      );
      const badErrors = parseOg({ ...ogDoc(goods), errors: "boom" });
      same(
        p,
        "errors that is not a list is no error",
        [badErrors.status, badErrors.fileErrors],
        ["succeeded", 0],
      );
      const bandErr = parseBd(
        bdDoc(
          [{ line: 1 }],
          [{ filename: "/src/x.py", reason: "syntax error while parsing AST from file" }],
        ),
      );
      same(
        p,
        "a Bandit errors entry makes the run partial",
        [bandErr.status, bandErr.reason, bandErr.findingsMapped],
        ["partial", "output_invalid", 1],
      );
      const hostile = parseOg(OG_HOSTILE);
      same(
        p,
        "the real hostile Opengrep report",
        [hostile.status, hostile.findingsMapped, hostile.fileErrors],
        ["partial", 1, 1],
      );
      const hostileB = parseBd(BD_HOSTILE);
      same(
        p,
        "the real hostile Bandit report",
        [hostileB.status, hostileB.findingsMapped, hostileB.fileErrors],
        ["partial", 2, 3],
      );
      // the record cap
      const wide = ogDoc(Array.from({ length: 50_001 }, () => ({ line: 1 })));
      const cutWide = parseOg(wide);
      same(
        p,
        "more than 50000 records",
        [cutWide.status, cutWide.reason, cutWide.recordsSeen, cutWide.truncated],
        ["partial", "output_too_large", 50_000, true],
      );
      // a path that is not in the tree is dropped by the tree filter
      const exists = (rel) => rel === "ok.py";
      const filtered = runToolParse(
        og,
        asStreams(
          ogDoc([...goods.map((g) => ({ ...g, line: g.line })), { line: 1, path: "ghost.py" }]),
        ),
        { ...ctxFor(og), pathExists: exists },
      );
      same(
        p,
        "a path that is not in the tree",
        [filtered.recordsDropped, filtered.findingsMapped],
        [1, 20],
      );
      return p;
    },
  },
  {
    id: "ENG-S05d",
    name: "SAST evidence snippets are bounded and no secret value is stored (SPEC scan-engines 5.13.2, 5.13.4, SE-40 to SE-43, D-5, ENG-S05, 16.1 part H): the snippet is the reported source lines only (Bandit's context lines are cut away), at most 10 lines, 300 characters a line (the cut marked), 4096 characters in all, `truncated` set when anything was cut, line breaks kept and every other control character, ANSI sequence and bidirectional character removed or made visible; a hard-coded credential finding (the Opengrep category and the Bandit tests B105, B106 and B107) has NO evidence at all, and the credential value of the matched variable (`$VALUE`) is removed from every string of the finding in its plain, base64, base64url, hex, URL-encoded and reversed forms, from the title, the rule text and a snippet of ANOTHER rule on the same line; the platform text redaction is applied to every snippet and title: a PEM private key block across lines, an Authorization header, a `password = value` pair, an AWS key id, a token and a credential in a URL never reach a stored string, and a snippet that still looks like a credential is not stored (the finding keeps its location); a canary secret planted in every field of a hostile record (path, message, lines, metavariable, rule name, Bandit text and code) appears nowhere in the candidates, the merged findings or the storage rows",
    async run() {
      const p = [];
      const long = "L".repeat(500);
      const lines = Array.from({ length: 14 }, (_, i) => `line ${i + 1}`).join("\n");
      const cut = buildEvidence({ lines, path: "a.py", startLine: 5, endLine: 18 });
      same(
        p,
        "ten lines at most",
        [cut.snippet.split("\n").length, cut.truncated, cut.startLine, cut.endLine],
        [10, true, 5, 14],
      );
      const exact = buildEvidence({
        lines: Array.from({ length: 10 }, () => "x").join("\n"),
        path: "a.py",
        startLine: 1,
        endLine: 10,
      });
      same(
        p,
        "exactly ten lines are not cut",
        [exact.snippet.split("\n").length, exact.truncated],
        [10, undefined],
      );
      const wide = buildEvidence({ lines: long, path: "a.py", startLine: 1, endLine: 1 });
      same(
        p,
        "a long line is cut with a marker",
        [wide.snippet.length, wide.snippet.endsWith("\u2026"), wide.truncated],
        [EVIDENCE_LIMITS.lineChars + 1, true, true],
      );
      const edge = buildEvidence({
        lines: "y".repeat(300),
        path: "a.py",
        startLine: 1,
        endLine: 1,
      });
      same(
        p,
        "exactly 300 characters are not cut",
        [edge.snippet.length, edge.truncated],
        [300, undefined],
      );
      same(
        p,
        "nothing to show",
        [
          buildEvidence({ lines: "", path: "a.py", startLine: 1, endLine: 1 }),
          buildEvidence({ lines: "  \n ", path: "a.py", startLine: 1, endLine: 1 }),
          buildEvidence({ lines: undefined, path: "a.py", startLine: 1, endLine: 1 }),
          buildEvidence({ lines: 5, path: "a.py", startLine: 1, endLine: 1 }),
        ],
        [null, null, null, null],
      );
      same(
        p,
        "single line has no end line",
        buildEvidence({ lines: "x\n", path: "a.js", startLine: 3, endLine: 3 }),
        { kind: "line", language: "javascript", startLine: 3, snippet: "x" },
      );
      same(
        p,
        "language of an unknown extension",
        buildEvidence({ lines: "x", path: "Makefile", startLine: 1, endLine: 1 }).language,
        undefined,
      );
      // through the real pipeline: control characters, newlines, caps
      const piped = (lines2, extra = {}) =>
        og1({ line: 1, end: 3, lines: lines2, ...extra })[0]?.evidence;
      same(
        p,
        "line breaks are kept",
        piped("a = 1\nb = 2\r\n\tc = 3").snippet,
        "a = 1\nb = 2\n  c = 3",
      );
      const dirty = piped("x\u0000y\u001b[31mz\u001b[0m \u202e w\u0007");
      ok(
        p,
        !hasControl(dirty.snippet) && !dirty.snippet.includes("\u001b"),
        `a control character survived: ${JSON.stringify(dirty.snippet)}`,
      );
      ok(p, dirty.snippet.includes("\\u202e"), "a bidirectional override was not made visible");
      const huge = piped(`${"w".repeat(299)}\n`.repeat(10) + "tail");
      ok(
        p,
        huge.snippet.length <= EVIDENCE_LIMITS.snippetChars &&
          huge.snippet.split("\n").length === 10,
        "the snippet exceeds the caps",
      );
      // Bandit: only the lines of the finding, never the context
      const code = "1 import os\n2 \n3 os.system(a)\n4 os.system(b)\n5 x = 1\n";
      same(
        p,
        "bandit lines inside the range",
        banditLines(code, 3, 4),
        "os.system(a)\nos.system(b)",
      );
      same(p, "bandit one line", banditLines(code, 3, 3), "os.system(a)");
      same(p, "bandit no match", banditLines(code, 9, 9), undefined);
      same(p, "bandit no code", banditLines(undefined, 1, 1), undefined);
      same(p, "a line number alone", banditLines("7\n", 7, 7), "");
      const banded = bd1({ line: 3, end: 4, code })[0];
      same(
        p,
        "bandit evidence",
        [
          banded.evidence.snippet,
          banded.evidence.startLine,
          banded.evidence.endLine,
          banded.evidence.language,
        ],
        ["os.system(a)\nos.system(b)", 3, 4, "python"],
      );
      // credential findings have no evidence, and the value is scrubbed from everything
      for (const value of CANARIES) {
        const f = og1({
          id: "qm.js.hardcoded-credential",
          category: "hardcoded-credential",
          line: 4,
          cwe: 798,
          lines: `const dbPassword = "${value}";`,
          value,
          message: `Hard-coded ${value} here`,
          path: "ok.js",
        });
        same(p, `credential ${value.slice(0, 4)} candidate`, f.length, 1);
        ok(p, f[0].evidence === undefined, "a credential finding has evidence");
        ok(
          p,
          !JSON.stringify(f).includes(value),
          `the value ${value.slice(0, 4)}... is in the candidate`,
        );
        for (const variant of [
          Buffer.from(value).toString("base64"),
          Buffer.from(value).toString("hex"),
          encodeURIComponent(value),
          [...value].reverse().join(""),
        ]) {
          const g = og1({
            id: "qm.js.hardcoded-credential",
            category: "hardcoded-credential",
            line: 4,
            cwe: 798,
            value,
            message: `v ${variant} v`,
            path: "ok.js",
          });
          ok(
            p,
            !JSON.stringify(g).includes(variant),
            `a form of the value was kept: ${variant.slice(0, 6)}`,
          );
        }
      }
      // the value is scrubbed from a SNIPPET of another rule on the same record
      const sneaky = og1({
        id: "qm.js.sql-injection",
        category: "hardcoded-credential",
        line: 1,
        value: "tok-1234567890",
        lines: "x = 'tok-1234567890'",
        cwe: 798,
      });
      same(p, "the credential category alone drops the snippet", sneaky[0].evidence, undefined);
      const other = og1({
        id: "qm.js.sql-injection",
        line: 1,
        value: "tok-1234567890",
        lines: "x = 'tok-1234567890'",
      });
      ok(
        p,
        other[0].evidence?.snippet.includes("tok-1234567890") === true ||
          other[0].evidence === undefined,
        "an unexpected evidence shape",
      );
      same(
        p,
        "bandit credential tests have no evidence",
        ["B105", "B106", "B107"].map(
          (id) =>
            bd1({
              id,
              line: 3,
              text: "Possible hardcoded password: 'abcdefghijk'",
              code: '3 password = "abcdefghijk"\n',
            })[0].evidence,
        ),
        [undefined, undefined, undefined],
      );
      same(
        p,
        "another bandit test has evidence",
        typeof bd1({ id: "B602", line: 3, code: "3 run(x)\n" })[0].evidence.snippet,
        "string",
      );
      // REAL Bandit output (2026-11-21): the text of B105, B106 and B107 QUOTES the secret value; none of the five values is stored
      const realCreds = runToolParse(bd, asStreams(real("bandit-credentials.json"), 1), ctxFor(bd));
      same(
        p,
        "real bandit credential records",
        [realCreds.status, realCreds.findingsMapped],
        ["succeeded", 5],
      );
      const realDump = JSON.stringify([
        realCreds,
        toStorageRows(mergeAll(realCreds.candidates), 100),
      ]);
      for (const v of [
        "hunter2-very-secret",
        "p4ss-default-val",
        "abc-def-ghijk",
        "tok_live_abcdefghijklmnop",
        "sk-abcdefghijklmnop",
      ])
        ok(p, !realDump.includes(v), `the real Bandit value ${v.slice(0, 6)}... was stored`);
      same(
        p,
        "real bandit credential titles",
        [...new Set(realCreds.candidates.map((c) => c.title))],
        ["Possible hardcoded password"],
      );
      ok(
        p,
        realCreds.candidates.every((c) => c.evidence === undefined),
        "a real Bandit credential finding has evidence",
      );
      // the platform redaction of snippets and titles
      const pem =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdef\nZm9vYmFyYmF6\n-----END RSA PRIVATE KEY-----";
      const sample = [
        ["a PEM block", pem, "MIIEowIBAAKCAQEA1234567890abcdef"],
        [
          "an Authorization header",
          'headers = {"Authorization": "Bearer abcdefghijklmnop1234"}\nAuthorization: Basic dXNlcjpwYXNzd29yZA==',
          "dXNlcjpwYXNzd29yZA==",
        ],
        [
          "a password pair",
          'db_password = "p4ssw0rd-very-secret"\npassword: hunter2hunter2',
          "hunter2hunter2",
        ],
        ["an AWS key id", "key = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"],
        [
          "a token",
          "t = ghp_abcdefghijklmnopqrstuvwxyz0123456789",
          "ghp_abcdefghijklmnopqrstuvwxyz",
        ],
        ["a URL credential", "u = https://user:s3cr3tpassw0rd@example.com/x", "s3cr3tpassw0rd"],
      ];
      for (const [label, text, needle] of sample) {
        const ev = piped(text, { id: "qm.js.sql-injection" });
        ok(
          p,
          ev === undefined || ev === null || !ev.snippet.includes(needle),
          `${label} reached the snippet`,
        );
        const title = og1({ line: 1, message: `see ${text.split("\n")[0]}` })[0].title;
        ok(p, !title.includes(needle), `${label} reached the title`);
      }
      const pemEv = piped(pem);
      ok(
        p,
        !JSON.stringify(pemEv ?? {}).includes("PRIVATE KEY-----\nMII"),
        "a PEM body stayed across lines",
      );
      // a snippet that still looks like a credential is not stored, the finding is
      const f1 = og1({ line: 1 })[0];
      const sneakyDetail = toStorageRows(
        [
          {
            ...mergeAll([f1])[0],
            evidence: {
              kind: "line",
              startLine: 1,
              snippet: "k = ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            },
          },
        ],
        10,
      );
      same(
        p,
        "an unredacted credential shape in the evidence",
        [sneakyDetail.items.length, sneakyDetail.dropped, sneakyDetail.details[0]?.evidence],
        [1, 0, null],
      );
      // the canary in every field of a hostile record
      const canary = "CANARY-secret-value-7788";
      const rec = {
        id: "qm.python.hardcoded-credential",
        category: "hardcoded-credential",
        path: `${canary}.py`,
        line: 2,
        cwe: 798,
        message: `msg ${canary}`,
        lines: `x = "${canary}"`,
        value: canary,
      };
      const hostileO = runToolParse(og, asStreams(ogDoc([rec])), {
        ...ctxFor(og),
        pathExists: () => true,
      });
      const hostileB = runToolParse(
        bd,
        asStreams(
          bdDoc([
            {
              id: "B105",
              path: "ok.py",
              line: 2,
              text: `Possible hardcoded password: '${canary}'`,
              code: `2 pw = "${canary}"\n`,
            },
          ]),
          1,
        ),
        ctxFor(bd),
      );
      same(
        p,
        "the bandit credential title is fixed",
        hostileB.candidates.map((c) => c.title),
        ["Possible hardcoded password"],
      );
      const stored = toStorageRows(mergeAll([...hostileO.candidates, ...hostileB.candidates]), 100);
      const dump = JSON.stringify([hostileO, hostileB, stored]);
      const pathless = dump.replaceAll(`${canary}.py`, "<path>");
      ok(p, !pathless.includes(canary), "the canary reached a candidate or a storage row");
      for (const form of [
        Buffer.from(canary).toString("base64"),
        Buffer.from(canary).toString("hex"),
        encodeURIComponent(canary),
        [...canary].reverse().join(""),
      ])
        ok(p, !pathless.includes(form), `a form of the canary reached a row: ${form.slice(0, 8)}`);
      return p;
    },
  },
  {
    id: "ENG-S03e",
    name: "the SAST tool invocations are sealed and contain nothing from the repository but validated targets (SPEC scan-engines 6.2, 11.3, SE-3, SE-27, 14.1 ENG-S01 and ENG-S03, OQ-16, 16.1 part H): the Opengrep and Bandit command lines are the constants documented in IMAGES.md section 8 (a drift guard reads the document), carry every flag the real runs proved essential (`--config /rules/qm-sast` as the ONLY configuration, `--disable-nosem`, `--no-git-ignore`, `--x-ignore-semgrepignore-files`, `--no-rewrite-rule-ids`, `--no-autofix`; `--ini /rules/empty.ini`, `--ignore-nosec`, `-c /rules/bandit.yaml`) and none that would weaken them (no `auto` or registry configuration, no `--metrics`, `--autofix`, `--enable-nosem`, `--use-git-ignore`, `--baseline-commit`, `--exclude`, `--include`, `--skip-invalid-configs`, `--sarif`), are frozen and free of control characters and `--`; the plans resolve (Opengrep through a mirror digest, the own build has none yet), pass RunSpec validation and the argument audit through the real `buildRunArgs` (network none, read-only root, no capability, tmpfs noexec, pull never, working directory /tmp, read-only mounts of the tree and the rules only, no database), the wall clock is capped by the task deadline; explicit targets travel ONLY in `paths` after `--` as `/src/<path>` (never in argv), a hostile target (a flag, an absolute path, `..`, a backslash, a control or bidirectional character, an empty or 1025-character path, 2001 targets, an empty list) is refused, a target with a space or a non-ASCII name is kept as one argument, the whole-tree target is left out of a targets run, no repository string is ever part of the constant argv, and gosec is never selectable by this module (no adapter, the registry holds Opengrep and Bandit only and only while the flag is on, no source file names it outside a comment)",
    async run() {
      const p = [];
      const images = readFileSync(path.join(ROOT, "docs/modules/scan-engines/IMAGES.md"), "utf8");
      const sealed = (tool) => new RegExp(`^${tool}: (.+)$`, "m").exec(images)?.[1];
      const ogLine = [...OPENGREP_ARGV, ...OPENGREP_FULL_TARGET].join(" ");
      const bdLine = [...BANDIT_ARGV, ...BANDIT_FULL_TARGET].join(" ");
      same(p, "IMAGES.md opengrep line", sealed("opengrep"), ogLine);
      same(p, "IMAGES.md bandit line", sealed("bandit"), bdLine);
      same(
        p,
        "opengrep argv",
        [...OPENGREP_ARGV],
        [
          "scan",
          "--config",
          "/rules/qm-sast",
          "--disable-nosem",
          "--no-git-ignore",
          "--x-ignore-semgrepignore-files",
          "--no-rewrite-rule-ids",
          "--json",
          "--quiet",
          "--timeout",
          "30",
          "--max-target-bytes",
          "1000000",
          "-j",
          "2",
          "--no-autofix",
          ...[
            "node_modules",
            "vendor",
            ".venv",
            "venv",
            "site-packages",
            "dist",
            "build",
            "target",
          ].flatMap((n) => ["--exclude", n]),
        ],
      );
      same(
        p,
        "bandit argv",
        [...BANDIT_ARGV],
        [
          "-f",
          "json",
          "-c",
          "/rules/bandit.yaml",
          "--ini",
          "/rules/empty.ini",
          "--ignore-nosec",
          "-q",
          "-x",
          "*/node_modules/*,*/vendor/*,*/.venv/*,*/venv/*,*/site-packages/*,*/dist/*,*/build/*,*/target/*",
        ],
      );
      same(
        p,
        "full targets",
        [[...OPENGREP_FULL_TARGET], [...BANDIT_FULL_TARGET]],
        [["/src"], ["-r", "/src"]],
      );
      same(
        p,
        "opengrep env",
        { ...OPENGREP_ENV },
        { SEMGREP_SEND_METRICS: "off", SEMGREP_ENABLE_VERSION_CHECK: "0" },
      );
      for (const [name, argv] of [
        ["opengrep", OPENGREP_ARGV],
        ["bandit", BANDIT_ARGV],
      ]) {
        ok(p, Object.isFrozen(argv), `${name} argv is not frozen`);
        ok(
          p,
          argv.every((a) => typeof a === "string" && !hasControl(a) && a !== "--"),
          `${name} argv entry`,
        );
      }
      ok(
        p,
        OPENGREP_ARGV.filter((a) => a === "--config").length === 1,
        "Opengrep has more than one configuration",
      );
      ok(
        p,
        OPENGREP_ARGV[OPENGREP_ARGV.indexOf("--config") + 1] === "/rules/qm-sast",
        "the Opengrep configuration is not the platform pack",
      );
      const forbidden =
        /^(--metrics|--autofix|-a|--enable-nosem|--use-git-ignore|--baseline-commit|--include|--skip-invalid-configs|--sarif|--error|--verbose|--debug|--dataflow-traces|--pro|--oss|--allow-rule-timeout-control|auto)\b/;
      ok(p, !OPENGREP_ARGV.some((a) => forbidden.test(a)), "Opengrep carries a forbidden flag");
      ok(
        p,
        !OPENGREP_ARGV.some((a) => /^p\/|semgrep\.dev|^https?:/.test(a)),
        "Opengrep names a registry pack or a URL",
      );
      ok(
        p,
        !BANDIT_ARGV.some((a) =>
          /^(--exit-zero|--baseline|-b|-s|--skip|-t|--tests|--profile|-p)$/.test(a),
        ),
        "Bandit skips or selects tests",
      );
      // plans through the real argument builder
      const config = validateSandboxConfig(CONFIG_INPUT);
      const lock = JSON.parse(
        readFileSync(path.join(ENGINE_DIR, "catalog/images.lock.json"), "utf8"),
      );
      const og0 = lock.images.find((i) => i.key === "opengrep");
      same(
        p,
        "the own build has no registry digest yet",
        [og0.repository, og0.digest, og0.flags.includes("local_build_requires_registry_digest")],
        [null, null, true],
      );
      const mirrored = JSON.parse(JSON.stringify(lock));
      const entry = mirrored.images.find((i) => i.key === "opengrep");
      entry.repository = "mirror.example/qm/opengrep";
      entry.digest = `sha256:${"d4".repeat(32)}`;
      entry.flags = entry.flags.filter((f) => f !== "local_build_requires_registry_digest");
      const resolver = createImageResolver(mirrored, { production: false });
      const ctx = (over = {}) => ({
        tenantId: "tenant-1",
        executionId: "exec-1",
        taskId: "11111111-aaaa-4aaa-8aaa-111111111111",
        attempt: 1,
        deadlineEpoch: 1790000000,
        archiveDir: "/tmp/qm-scan/tree-1",
        rulesDir: "/opt/qm/rules",
        ...over,
      });
      for (const adapter of [og, bd]) {
        const plan = adapter.plan(ctx());
        const spec = resolveRunSpecImage(plan, resolver, { scanType: "sast" });
        ok(p, /@sha256:[0-9a-f]{64}$/.test(spec.image), `${adapter.toolId}: image is not a digest`);
        const args = buildRunArgs(validateRunSpec(spec, config), config);
        assertRunArgsSafe(args, config);
        const joined = args.join("\n");
        for (const needle of [
          "--network=none",
          "--read-only",
          "--cap-drop=ALL",
          "--pull=never",
          "--workdir=/tmp",
          "--mount=type=bind,src=/tmp/qm-scan/tree-1,dst=/src,readonly",
          "--mount=type=bind,src=/opt/qm/rules,dst=/rules,readonly",
        ])
          ok(p, joined.includes(needle), `${adapter.toolId}: missing ${needle}`);
        ok(p, !joined.includes("dst=/db"), `${adapter.toolId}: mounts a database`);
        ok(
          p,
          args.filter((a) => a.startsWith("--mount=")).length === 2,
          `${adapter.toolId}: mount count`,
        );
        ok(
          p,
          !("paths" in plan) && !args.includes("--"),
          `${adapter.toolId}: a whole-tree plan passes paths`,
        );
        const afterImage = args.slice(args.indexOf(spec.image) + 1);
        same(
          p,
          `${adapter.toolId} whole-tree tail`,
          afterImage,
          adapter.toolId === "opengrep"
            ? [...OPENGREP_ARGV, "/src"]
            : [...BANDIT_ARGV, "-r", "/src"],
        );
        same(
          p,
          `${adapter.toolId} the plan is the same for any task`,
          JSON.stringify(
            adapter.plan(
              ctx({
                taskId: "22222222-bbbb-4bbb-8bbb-222222222222",
                archiveDir: "/tmp/qm-scan/tree-2",
              }),
            ).argv,
          ),
          JSON.stringify(plan.argv),
        );
        same(
          p,
          `${adapter.toolId} limits`,
          { ...plan.limits },
          { ...SAST_TOOL_LIMITS[adapter.toolId] },
        );
        same(
          p,
          `${adapter.toolId} wall clock capped by the deadline`,
          [
            adapter.plan(ctx({ secondsToDeadline: 7 })).limits.wallClockSeconds,
            adapter.plan(ctx({ secondsToDeadline: 99999 })).limits.wallClockSeconds,
            adapter.plan(ctx({ secondsToDeadline: 0 })).limits.wallClockSeconds,
          ],
          [
            7,
            SAST_TOOL_LIMITS[adapter.toolId].wallClockSeconds,
            SAST_TOOL_LIMITS[adapter.toolId].wallClockSeconds,
          ],
        );
        // targets
        const targets = [
          "web/app.js",
          "we ird/a b.js",
          "é/ü.py",
          "-rf",
          "$(touch x).js",
          ".hidden/x.py",
          "_x/y.go",
        ];
        const good = targets.filter(isSafeTargetPath);
        same(p, `${adapter.toolId} which targets are safe`, good, [
          "web/app.js",
          "we ird/a b.js",
          "é/ü.py",
          ".hidden/x.py",
          "_x/y.go",
        ]);
        const tplan = adapter.plan(ctx({ targets: good }));
        ok(
          p,
          !tplan.argv.some((a) => good.includes(a) || a === "/src" || a === "-r"),
          `${adapter.toolId}: a target or the whole tree is in argv`,
        );
        same(p, `${adapter.toolId} targets travel in paths`, tplan.paths, good);
        const targs = buildRunArgs(
          validateRunSpec(resolveRunSpecImage(tplan, resolver, { scanType: "sast" }), config),
          config,
        );
        const sep = targs.indexOf("--");
        same(
          p,
          `${adapter.toolId} the tail after --`,
          targs.slice(sep + 1),
          good.map((t) => `/src/${t}`),
        );
        ok(
          p,
          sep > targs.findIndex((a) => a.startsWith("--mount=")) &&
            targs.slice(0, sep).every((a) => !good.some((t) => a.includes(t))),
          `${adapter.toolId}: a target before --`,
        );
        for (const [label, bad] of [
          ["a flag", ["--config=evil"]],
          ["an absolute path", ["/etc/passwd"]],
          ["a dot dot", ["a/../../b.py"]],
          ["a backslash", ["a\\b.py"]],
          ["a newline", ["a\nb.py"]],
          ["a bidirectional override", ["a\u202eb.py"]],
          ["an empty path", [""]],
          ["a long path", ["a/".repeat(600) + "x.py"]],
          ["no target", []],
          ["a number", [5]],
          ["a hidden dot dot", ["a/./b.py"]],
          ["an empty segment", ["a//b.py"]],
        ]) {
          let e = null;
          try {
            adapter.plan(ctx({ targets: bad }));
          } catch (x) {
            e = x instanceof TypeError;
          }
          ok(p, e === true, `${adapter.toolId}: ${label} was accepted as a target`);
        }
        let notList = null;
        try {
          adapter.plan(ctx({ targets: "a.py" }));
        } catch (x) {
          notList = x instanceof TypeError;
        }
        ok(p, notList === true, `${adapter.toolId}: a string was accepted as the targets`);
        // the plan context
        for (const key of ["tenantId", "executionId", "taskId", "archiveDir", "rulesDir"]) {
          let e = null;
          try {
            adapter.plan(ctx({ [key]: "" }));
          } catch (x) {
            e = x instanceof TypeError;
          }
          ok(p, e === true, `${adapter.toolId}: an empty ${key} was accepted`);
        }
        let badAttempt = null;
        try {
          adapter.plan(ctx({ attempt: 1.5 }));
        } catch (x) {
          badAttempt = x instanceof TypeError;
        }
        ok(p, badAttempt === true, `${adapter.toolId}: a fractional attempt was accepted`);
      }
      same(
        p,
        "2000 targets pass the sandbox",
        buildRunArgs(
          validateRunSpec(
            resolveRunSpecImage(
              og.plan(ctx({ targets: Array.from({ length: 2000 }, (_, i) => `d/f${i}.js`) })),
              resolver,
              { scanType: "sast" },
            ),
            config,
          ),
          config,
        ).filter((a) => a.startsWith("/src/")).length,
        2000,
      );
      let tooMany = null;
      try {
        validateRunSpec(
          resolveRunSpecImage(
            og.plan(ctx({ targets: Array.from({ length: 2001 }, (_, i) => `d/f${i}.js`) })),
            resolver,
            { scanType: "sast" },
          ),
          config,
        );
      } catch (x) {
        tooMany = x instanceof SandboxError;
      }
      ok(p, tooMany === true, "2001 targets were accepted by the sandbox");
      same(p, "MAX_TARGETS is the sandbox ceiling", MAX_TARGETS, 2000);
      // gosec is held
      const reg = createSastAdapterRegistry({ ensembleEnabled: true });
      same(
        p,
        "registry with the flag",
        reg.select("sast").map((a) => a.toolId),
        ["opengrep", "bandit"],
      );
      same(
        p,
        "registry without the flag",
        [
          createSastAdapterRegistry().size,
          createSastAdapterRegistry({ ensembleEnabled: "true" }).size,
          createSastAdapterRegistry({ ensembleEnabled: 1 }).size,
        ],
        [0, 0, 0],
      );
      const sastDir = path.join(ENGINE_DIR, "sast");
      const sources = [
        ...readdirSync(sastDir)
          .filter((f) => f.endsWith(".js"))
          .map((f) => path.join(sastDir, f)),
        path.join(ENGINE_DIR, "engine/sast-engine.js"),
      ];
      for (const file of sources) {
        const code = readFileSync(file, "utf8");
        const lines = code.split("\n").filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l));
        ok(
          p,
          !lines.some((l) => /gosec/i.test(l)),
          `${path.basename(file)} names gosec outside a comment`,
        );
        ok(
          p,
          !/(?<![.\w])(execFile|execSync|exec|spawn|spawnSync|fork)\s*\(|child_process/.test(
            lines.join("\n"),
          ),
          `${path.basename(file)} starts a process`,
        );
        ok(
          p,
          !/node:(net|http|https|dgram|dns|tls|child_process)|process\.env|fetch\(/.test(
            lines.join("\n"),
          ),
          `${path.basename(file)} touches the network, a process or the environment`,
        );
      }
      return p;
    },
  },
  {
    id: "ENG-S03f",
    name: "the SAST rule pack is platform-owned and provenanced, and a registry or third-party pack is never referenced (SPEC scan-engines D-16, OQ-25, 5.2, 11.3, SE-45, 16.1 part H): every file of the shipped pack (`qm-sast/*.yml` of the platform rules directory) starts with the pack, provenance (platform-owned, original) and licence (platform-owned) header, every rule has a platform id (`qm.<language>.<name>`), a message, a severity of ERROR, WARNING or INFO, languages, the `qm_pack` metadata, at least one CWE and a confidence, and covers the classes of the owner decision (SQL injection, command injection, eval of untrusted input, insecure deserialization, path traversal, weak crypto, hard-coded credentials) for JavaScript and TypeScript, Python and Go (eval and deserialization where the language has them); a copy of the pack with a missing header line, a missing or foreign provenance or licence line, a duplicate or foreign rule id, a missing message, severity, languages, metadata, CWE or confidence, an unknown severity, a wrong file name, a registry pack (`p/ci`), `semgrep.dev`, a URL, `config: auto`, the Semgrep Rules License, a Commons Clause text, a `license:` key or an empty pack is refused with a named problem, the loader refuses a pack directory with a foreign file or subdirectory, an oversized file or a missing directory, the engine refuses to start with a broken pack and loads the shipped one, the digest of the pack changes with any byte and not with the order of reading, the run manifest of a SAST result carries the pack digest, and no other rule file exists anywhere in the platform rules directory",
    async run() {
      const p = [];
      const dir = path.join(RULES_DIR, "qm-sast");
      const names = readdirSync(dir).sort();
      same(p, "the shipped files", names, ["qm-go.yml", "qm-javascript.yml", "qm-python.yml"]);
      const files = names.map((name) => ({
        name,
        text: readFileSync(path.join(dir, name), "utf8"),
      }));
      same(p, "the shipped pack has no problem", checkRulePack(files), []);
      const loaded = loadRulePack(RULES_DIR);
      same(
        p,
        "the loader reads the same files",
        loaded.files.map((f) => f.name),
        names,
      );
      ok(
        p,
        /^[0-9a-f]{64}$/.test(loaded.digest) && loaded.digest === rulePackDigest(files),
        "the pack digest",
      );
      // every rule of the pack, by language and class
      const ids = files.flatMap((f) =>
        [...f.text.matchAll(/^ {2}- id: (\S+)$/gm)].map((m) => m[1]),
      );
      ok(p, ids.length >= 18 && ids.length <= 40, `a starter pack is small (${ids.length} rules)`);
      for (const [lang, classes] of [
        [
          "js",
          [
            "sql-injection",
            "command-injection",
            "eval-dynamic-code",
            "insecure-deserialization",
            "path-traversal",
            "weak-hash",
            "weak-cipher",
            "hardcoded-credential",
          ],
        ],
        [
          "python",
          [
            "sql-injection",
            "command-injection",
            "eval-exec-dynamic",
            "insecure-deserialization",
            "path-traversal",
            "weak-hash",
            "weak-cipher",
            "hardcoded-credential",
          ],
        ],
        [
          "go",
          [
            "sql-injection",
            "command-injection",
            "insecure-deserialization",
            "path-traversal",
            "weak-hash",
            "weak-cipher",
            "hardcoded-credential",
          ],
        ],
      ])
        for (const c of classes)
          ok(p, ids.includes(`qm.${lang}.${c}`), `the pack lacks qm.${lang}.${c}`);
      ok(p, new Set(ids).size === ids.length, "duplicate rule ids in the shipped pack");
      for (const f of files) {
        ok(
          p,
          /^# QM-RULE-PROVENANCE: platform-owned; original work/m.test(
            f.text.split("\n").slice(0, 12).join("\n"),
          ),
          `${f.name}: provenance line`,
        );
        ok(
          p,
          !FORBIDDEN_REFERENCES.some(([, re]) =>
            re.test(
              f.text
                .split("\n")
                .filter((l) => !l.trimStart().startsWith("#"))
                .join("\n"),
            ),
          ),
          `${f.name}: a forbidden reference`,
        );
      }
      // mutated copies are refused
      const first = files[0];
      const problemsOf = (mutate) =>
        checkRulePack([{ ...first, text: mutate(first.text) }, ...files.slice(1)]);
      const refused = (label, mutate, word) => {
        const found = problemsOf(mutate);
        ok(
          p,
          found.length > 0 && (word === undefined || found.some((x) => x.includes(word))),
          `${label}: ${JSON.stringify(found.slice(0, 2))}`,
        );
      };
      refused(
        "no pack header",
        (t) => t.replace(/^# QM-RULE-PACK: qm-sast\n/m, ""),
        "no pack header",
      );
      refused(
        "no provenance",
        (t) => t.replace(/^# QM-RULE-PROVENANCE:.*$/m, "# nothing"),
        "no provenance header",
      );
      refused(
        "foreign provenance",
        (t) => t.replace("QM-RULE-PROVENANCE: platform-owned", "QM-RULE-PROVENANCE: community"),
        "no provenance header",
      );
      refused(
        "no licence",
        (t) => t.replace(/^# QM-RULE-LICENCE:.*$/m, "# nothing"),
        "no licence header",
      );
      refused(
        "foreign licence",
        (t) => t.replace("QM-RULE-LICENCE: platform-owned", "QM-RULE-LICENCE: MIT"),
        "no licence header",
      );
      refused(
        "header below the first lines",
        (t) => `${"# filler\n".repeat(13)}${t}`,
        "no pack header",
      );
      refused("no rules list", (t) => t.replace(/^rules:\s*$/m, "other:"), "no rules list");
      refused(
        "a foreign rule id",
        (t) => t.replace("- id: qm.", "- id: python.lang.security."),
        "not qm.",
      );
      refused("an upper case rule id", (t) => t.replace("- id: qm.", "- id: QM."), "not qm.");
      refused("a duplicate id", (t) => t + t.slice(t.indexOf("  - id: ")), "duplicate id");
      refused("no message", (t) => t.replace(/^ {4}message: /m, "    msg: "), "no message");
      refused(
        "an unknown severity",
        (t) => t.replace(/^ {4}severity: \w+/m, "    severity: CRITICAL"),
        "severity",
      );
      refused("no severity", (t) => t.replace(/^ {4}severity: .*$/m, ""), "severity");
      refused("no languages", (t) => t.replace(/^ {4}languages: .*$/m, ""), "no languages");
      refused("no qm_pack", (t) => t.replace(/^ {6}qm_pack: .*$/m, ""), "qm_pack");
      refused(
        "another pack",
        (t) => t.replace(/^ {6}qm_pack: .*$/m, "      qm_pack: other"),
        "qm_pack",
      );
      refused("no cwe", (t) => t.replace(/^ {6}cwe: .*$/m, ""), "CWE");
      refused("a bad cwe", (t) => t.replace(/^ {6}cwe: .*$/m, '      cwe: ["89"]'), "CWE");
      refused("no confidence", (t) => t.replace(/^ {6}confidence: .*$/m, ""), "confidence");
      refused(
        "a bad confidence",
        (t) => t.replace(/^ {6}confidence: HIGH/m, "      confidence: SURE"),
        "confidence",
      );
      refused(
        "a registry pack",
        (t) => t.replace("rules:\n", "rules:\n  - include: p/ci\n"),
        "registry pack",
      );
      refused("semgrep.dev", (t) => `${t}\n    source: semgrep.dev/r/x\n`, "semgrep.dev");
      refused(
        "the word registry in code",
        (t) => t.replace("message: ", "message: from the registry: "),
        "registry",
      );
      refused("a URL", (t) => t.replace("message: ", "message: see https://example.com "), "a URL");
      refused("config auto", (t) => `${t}\n# x\nconfig: auto\n`, "config: auto");
      refused(
        "the Semgrep Rules License",
        (t) => `${t}\n    license: Semgrep Rules License v1.0\n`,
        "licen",
      );
      refused("a Commons Clause text", (t) => `${t}\n    note: Commons Clause\n`, "commons clause");
      refused("a license key", (t) => `${t}\n    license: MIT\n`, "licence key");
      refused("r2c", (t) => `${t}\n    note: r2c\n`, "r2c");
      ok(
        p,
        checkRulePack([]).length > 0 && checkRulePack(null).length > 0,
        "an empty pack was accepted",
      );
      ok(
        p,
        checkRulePack([{ name: "qm-x.yml", text: "" }]).length > 0,
        "an empty file was accepted",
      );
      ok(
        p,
        checkRulePack([{ ...first, name: "rules.yml" }]).some((x) => x.includes("qm-<name>.yml")),
        "a foreign file name was accepted",
      );
      ok(
        p,
        checkRulePack([{ ...first, name: "qm-Upper.yml" }]).length > 0,
        "an upper case file name was accepted",
      );
      ok(
        p,
        checkRulePack([
          {
            name: "qm-a.yml",
            text: "# QM-RULE-PACK: qm-sast\n# QM-RULE-PROVENANCE: platform-owned\n# QM-RULE-LICENCE: platform-owned\nrules:\n",
          },
        ]).some((x) => x.includes("no rule")),
        "a pack of no rule was accepted",
      );
      ok(
        p,
        checkRulePack(
          Array.from({ length: RULE_PACK_LIMITS.files + 1 }, (_, i) => ({
            name: `qm-f${i}.yml`,
            text: first.text,
          })),
        ).some((x) => x.includes("too many files")),
        "too many files were accepted",
      );
      // the comments that state the provenance may name what is NOT used
      ok(
        p,
        /registry/i.test(first.text) && problemsOf((t) => t).length === 0,
        "a provenance comment that names the registry was refused",
      );
      // digest
      same(
        p,
        "the digest ignores the order of reading",
        rulePackDigest([...files].reverse()),
        loaded.digest,
      );
      ok(
        p,
        rulePackDigest([{ ...first, text: `${first.text} ` }, ...files.slice(1)]) !== loaded.digest,
        "the digest ignores a byte",
      );
      ok(
        p,
        rulePackDigest([{ ...first, name: "qm-other.yml" }, ...files.slice(1)]) !== loaded.digest,
        "the digest ignores a file name",
      );
      // the loader
      const tmp = mkdtempSync(path.join(os.tmpdir(), "qm-sast-pack-"));
      try {
        const fresh = (name) => {
          const d = path.join(tmp, name);
          mkdirSync(path.join(d, "qm-sast"), { recursive: true });
          for (const f of files) writeFileSync(path.join(d, "qm-sast", f.name), f.text);
          return d;
        };
        const refuses = (dirPath) => {
          try {
            loadRulePack(dirPath);
            return false;
          } catch (e) {
            return (
              e instanceof Error &&
              /not valid/.test(e.message) &&
              !/hunter|password/i.test(e.message)
            );
          }
        };
        same(p, "a copy loads", loadRulePack(fresh("ok")).digest, loaded.digest);
        const foreign = fresh("foreign");
        writeFileSync(path.join(foreign, "qm-sast", "notes.txt"), "x");
        ok(p, refuses(foreign), "a foreign file in the pack directory was accepted");
        const sub = fresh("sub");
        mkdirSync(path.join(sub, "qm-sast", "extra"));
        ok(p, refuses(sub), "a subdirectory in the pack directory was accepted");
        const big = fresh("big");
        writeFileSync(
          path.join(big, "qm-sast", "qm-big.yml"),
          `${first.text}\n# ${"x".repeat(RULE_PACK_LIMITS.bytesPerFile)}\n`,
        );
        ok(p, refuses(big), "an oversized file was accepted");
        const link = fresh("link");
        symlinkSync("/etc/hostname", path.join(link, "qm-sast", "qm-link.yml"));
        ok(p, refuses(link), "a symbolic link in the pack directory was accepted");
        const missing = path.join(tmp, "missing");
        mkdirSync(missing);
        ok(p, refuses(missing), "a missing pack directory was accepted");
        const empty = path.join(tmp, "empty");
        mkdirSync(path.join(empty, "qm-sast"), { recursive: true });
        ok(p, refuses(empty), "an empty pack directory was accepted");
        let relative = null;
        try {
          loadRulePack("relative/rules");
        } catch (e) {
          relative = e instanceof TypeError;
        }
        ok(p, relative === true, "a relative rules directory was accepted");
        // the engine
        const rules = path.join(tmp, "engine-rules");
        cpSync(RULES_DIR, rules, { recursive: true });
        const engineOver = (dirPath) =>
          createEnsembleSastEngine({ runner: {}, gate: {}, resolver: {}, rulesDir: dirPath });
        same(p, "the engine loads the shipped pack", Object.isFrozen(engineOver(rules)), true);
        writeFileSync(
          path.join(rules, "qm-sast", "qm-python.yml"),
          files[2].text.replace("- id: qm.python.", "- id: py.lang."),
        );
        let refusedEngine = null;
        try {
          engineOver(rules);
        } catch (e) {
          refusedEngine = /not valid/.test(String(e.message));
        }
        ok(p, refusedEngine === true, "the engine started with a broken pack");
        // no other rule file anywhere in the platform rules directory
        const rootFiles = readdirSync(RULES_DIR).sort();
        same(p, "the platform rules directory", rootFiles, [
          "bandit.yaml",
          "canary.cdx.json",
          "empty.ini",
          "gitleaks.toml",
          "osv-scanner.toml",
          "qm-sast",
          "syft.yaml",
          "trivy.yaml",
        ]);
        ok(
          p,
          statSync(path.join(RULES_DIR, "qm-sast")).isDirectory(),
          "the pack is not a directory",
        );
        const sastText =
          readFileSync(path.join(RULES_DIR, "bandit.yaml"), "utf8") +
          readFileSync(path.join(RULES_DIR, "empty.ini"), "utf8");
        ok(
          p,
          !/^\s*(skips|exclude|tests|exclude_dirs)\s*[:=]/m.test(sastText),
          "the Bandit platform configuration skips or excludes something",
        );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "ENG-S11e",
    name: "language detection and the applicability gate of the SAST scan type (SPEC scan-engines 5.4 rows 3 and 4, 5.5 SE-7 to SE-9, OQ-17, D-24 (c), 16.1 part H): the language of a file is a pure function of its NAME (the extension, case-insensitive; a dot file, a file with no extension and an unknown extension have none; never the content), the supported languages are JavaScript, TypeScript, Python and Go and every other known source language is a coverage GAP named with a platform word of the shared list; a tool is applicable when the tree has a file of a language it covers (Opengrep: the four, Bandit: Python), otherwise it is recorded skipped / no_applicable_files and never started; a tree with no source file of any known language is nothing to scan (row 3: complete, zero findings), a tree with source files and no applicable tool is a language gap (row 4: incomplete, the gaps named, never resolution eligible), a mixed tree names the languages no tool covers; the bounded walk lists regular files only (a symbolic link, a FIFO or a directory is never followed or listed), sorts, honours its entry, path and depth caps and marks a cut inventory truncated, and a truncated inventory never claims absence: every tool is applicable and no gap is claimed; hostile names (control characters, bidirectional characters, spaces, a million-entry cap) never throw",
    async run() {
      const p = [];
      same(
        p,
        "extensions",
        [
          "a.js",
          "a.JSX",
          "a.mjs",
          "a.cjs",
          "a.ts",
          "a.tsx",
          "a.mts",
          "a.cts",
          "a.py",
          "a.go",
          "a.PY",
          "dir/b.Go",
        ].map(languageOfFile),
        [
          "javascript",
          "javascript",
          "javascript",
          "javascript",
          "typescript",
          "typescript",
          "typescript",
          "typescript",
          "python",
          "go",
          "python",
          "go",
        ],
      );
      same(
        p,
        "no language",
        ["Makefile", ".js", "a.", "README.md", "a.js.bak", "a.txt", "x/.py", "a.json", ""].map(
          languageOfFile,
        ),
        [null, null, null, null, null, null, null, null, null],
      );
      same(
        p,
        "gap languages",
        [
          "A.java",
          "a.kt",
          "a.c",
          "a.h",
          "a.cc",
          "a.cpp",
          "a.cs",
          "a.php",
          "a.rb",
          "a.rs",
          "a.swift",
          "a.scala",
          "a.sh",
          "a.hs",
          "a.lua",
          "a.dart",
          "a.ex",
        ].map(languageOfFile),
        [
          "java",
          "kotlin",
          "c",
          "c",
          "cpp",
          "cpp",
          "csharp",
          "php",
          "ruby",
          "rust",
          "swift",
          "scala",
          "shell",
          "haskell",
          "lua",
          "dart",
          "elixir",
        ],
      );
      same(p, "supported", [...SUPPORTED_LANGUAGES], ["javascript", "typescript", "python", "go"]);
      // the content is never read: a file named .txt with Python content has no language
      const inv = inventoryOf([
        "a/b.py",
        "a/c.py",
        "web/x.ts",
        "svc/Main.java",
        "svc/Other.java",
        "z.rs",
        "readme.md",
      ]);
      same(p, "inventory counts", inv.counts, { python: 2, typescript: 1, java: 2, rust: 1 });
      same(p, "inventory paths", inv.paths.python, ["a/b.py", "a/c.py"]);
      const app = applicability(inv);
      same(p, "applicable", app.applicable, { opengrep: true, bandit: true });
      same(
        p,
        "gaps",
        [app.gaps, app.relevantFilesExist, app.languages],
        [["java", "rust"], true, { typescript: 1, python: 2 }],
      );
      ok(
        p,
        app.gaps.every((g) => COVERAGE_GAP_NAMES.includes(g)),
        "a gap word outside the platform list",
      );
      for (const lang of new Set(Object.values({ x: "javascript" })))
        ok(p, COVERAGE_GAP_NAMES.includes(lang), "a supported language is not a platform word");
      // per-tool applicability
      same(p, "only JavaScript", applicability(inventoryOf(["a.js"])).applicable, {
        opengrep: true,
        bandit: false,
      });
      same(p, "only Go", applicability(inventoryOf(["a.go"])).applicable, {
        opengrep: true,
        bandit: false,
      });
      same(p, "only Python", applicability(inventoryOf(["a.py"])).applicable, {
        opengrep: true,
        bandit: true,
      });
      // row 3: nothing to scan; row 4: a language gap
      const none = applicability(inventoryOf(["README.md", "Dockerfile", "data.json", "img.png"]));
      same(
        p,
        "no source file",
        [none.applicable, none.relevantFilesExist, none.gaps],
        [{ opengrep: false, bandit: false }, false, []],
      );
      const javaOnly = applicability(inventoryOf(["src/A.java", "src/B.java"]));
      same(
        p,
        "only Java",
        [javaOnly.applicable, javaOnly.relevantFilesExist, javaOnly.gaps],
        [{ opengrep: false, bandit: false }, true, ["java"]],
      );
      const skip = (a) => ({ toolId: a, status: "skipped", reason: "no_applicable_files" });
      const r3 = rollUpTask({
        tools: [skip("opengrep"), skip("bandit")],
        relevantFilesExist: none.relevantFilesExist,
        coverageGaps: none.gaps,
      });
      same(
        p,
        "row 3",
        [r3.matchedRow, r3.taskStatus, r3.completeness, r3.coverageState, r3.resolutionEligible],
        [3, "succeeded", "complete", "nothing_to_scan", true],
      );
      const r4 = rollUpTask({
        tools: [skip("opengrep"), skip("bandit")],
        relevantFilesExist: javaOnly.relevantFilesExist,
        coverageGaps: javaOnly.gaps,
      });
      same(
        p,
        "row 4",
        [
          r4.matchedRow,
          r4.taskStatus,
          r4.completeness,
          r4.coverageState,
          r4.coverageGaps,
          r4.resolutionEligible,
        ],
        [4, "succeeded", "incomplete", "language_gap", ["java"], false],
      );
      // a truncated inventory proves nothing
      const trunc = applicability({ counts: {}, paths: {}, truncated: true });
      same(
        p,
        "truncated: everything applies, nothing is claimed",
        [trunc.applicable, trunc.relevantFilesExist, trunc.gaps],
        [{ opengrep: true, bandit: true }, true, []],
      );
      const capped = inventoryOf(["a.py", "b.py", "c.py"], { maxPaths: 2 });
      same(
        p,
        "the path cap marks the inventory truncated",
        [capped.truncated, capped.counts.python, capped.paths.python.length],
        [true, 3, 2],
      );
      // the walk
      const tmp = mkdtempSync(path.join(os.tmpdir(), "qm-sast-walk-"));
      try {
        const put = (rel, text = "x") => {
          mkdirSync(path.dirname(path.join(tmp, rel)), { recursive: true });
          writeFileSync(path.join(tmp, rel), text);
        };
        put("b/z.py");
        put("a/y.js");
        put("a/x.ts");
        put("deep/one/two/three/w.go");
        put("we ird/a b.py");
        put("notes.txt", "import os\nos.system('x')");
        put("Main.java");
        put("a\u202eb.py");
        symlinkSync("/etc", path.join(tmp, "linkdir"));
        symlinkSync("/etc/hostname", path.join(tmp, "link.py"));
        mkdirSync(path.join(tmp, "empty"));
        const walked = await walkSourceTree(tmp);
        same(p, "walk counts", walked.counts, {
          go: 1,
          java: 1,
          javascript: 1,
          python: 3,
          typescript: 1,
        });
        same(p, "walk paths in order", walked.paths.python, [
          "a\u202eb.py",
          "b/z.py",
          "we ird/a b.py",
        ]);
        ok(p, walked.truncated === false, "the walk is truncated");
        ok(p, !JSON.stringify(walked).includes("link"), "a symbolic link was listed");
        same(p, "walk is repeatable", await walkSourceTree(tmp), walked);
        // the entry cap on its exact edge: the tree has 14 entries (directories and files); 14 are listed, 13 are not
        const entriesAll = await walkSourceTree(tmp, { maxEntries: 1000 });
        ok(p, entriesAll.truncated === false, "the walk with room was truncated");
        let total = 0;
        const countEntries = (d) => {
          for (const e of readdirSync(d, { withFileTypes: true })) {
            total += 1;
            if (e.isDirectory()) countEntries(path.join(d, e.name));
          }
        };
        countEntries(tmp);
        ok(
          p,
          (await walkSourceTree(tmp, { maxEntries: total })).truncated === false,
          "an exact entry cap truncated the walk",
        );
        ok(
          p,
          (await walkSourceTree(tmp, { maxEntries: total - 1 })).truncated === true,
          "one entry over the cap did not mark the walk",
        );
        const small = await walkSourceTree(tmp, { maxEntries: 3 });
        ok(p, small.truncated === true, "the entry cap did not mark the walk");
        ok(
          p,
          (await walkSourceTree(tmp, { maxDepth: 4 })).truncated === false,
          "an exact depth cap truncated the walk",
        );
        ok(
          p,
          (await walkSourceTree(tmp, { maxDepth: 3 })).truncated === true,
          "one level over the depth cap did not mark the walk",
        );
        const shallow = await walkSourceTree(tmp, { maxDepth: 1 });
        ok(
          p,
          shallow.truncated === true && !shallow.paths.go,
          "the depth cap did not stop the walk",
        );
        const few = await walkSourceTree(tmp, { maxPaths: 2 });
        ok(
          p,
          few.truncated === true && Object.values(few.paths).flat().length === 2,
          "the path cap did not hold",
        );
        let rel = null;
        try {
          await walkSourceTree("relative");
        } catch (e) {
          rel = e instanceof TypeError;
        }
        ok(p, rel === true, "a relative root was accepted");
        const missing = await walkSourceTree(path.join(tmp, "nothing-here"));
        same(
          p,
          "a missing root is a truncated, empty inventory",
          [missing.truncated, missing.counts],
          [true, {}],
        );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "ENG-S11g",
    name: "incremental scope of the SAST tools (SPEC scan-engines 5.9 SE-22 to SE-24, SE-27, D-7, 16.1 part H): without a COMPLETE changed-path list (a full scan, a truncated, unavailable or not recorded list) the scope is full and nothing is filtered (fail closed to full, SE-23); with a complete list the tool receives as explicit targets only the changed files of its languages that exist in the tree, sorted and valid (Opengrep: JavaScript, TypeScript, Python and Go, Bandit: Python), at most 2000, and a deleted or renamed file is counted and never a target; more than 2000 targets, a changed file of the tree whose name cannot be a target, or an inventory that is not the whole tree widens the run to the WHOLE tree with the filter (`full_filtered`) so no changed file is skipped; the one filter keeps the merged findings whose path is in the changed list (SE-24: merge first, filter after) and counts the others, a finding with no path is kept, a full run filters nothing; the target rules refuse a flag, a leading hyphen, an absolute path, `..`, a control, bidirectional or zero-width character and a path over 1024 characters; the inventory restricted to the changed files decides applicability and gaps of an incremental run, and a truncated inventory stays truncated",
    async run() {
      const p = [];
      const inv = inventoryOf([
        "web/app.js",
        "web/render.ts",
        "svc/py/app.py",
        "svc/py/util.py",
        "go/main.go",
        "svc/Main.java",
        "lib/c.c",
        "docs/readme.md",
      ]);
      const complete = (paths) => ({ status: "complete", paths });
      // fail closed to full
      for (const [label, cp] of [
        ["null", null],
        ["undefined", undefined],
        ["not recorded", { status: "not_recorded", paths: [] }],
        ["truncated", { status: "truncated", paths: [] }],
        ["unavailable", { status: "unavailable", paths: ["web/app.js"] }],
        [
          "a complete status with paths that is not a list",
          { status: "complete", paths: "web/app.js" },
        ],
        ["a truncated status that carries a list", { status: "truncated", paths: ["web/app.js"] }],
      ]) {
        const sc = planScope(cp, inv);
        same(
          p,
          `${label}: full`,
          [sc.kind, sc.changed, sc.targets, sc.targetsDropped],
          ["full", null, {}, 0],
        );
      }
      // targets
      const sc = planScope(
        complete([
          "svc/py/util.py",
          "web/app.js",
          "svc/Main.java",
          "docs/readme.md",
          "gone/deleted.py",
          "web/app.js",
          "go/main.go",
        ]),
        inv,
      );
      same(p, "targets kind", sc.kind, "targets");
      same(p, "opengrep targets", sc.targets.opengrep, [
        "go/main.go",
        "svc/py/util.py",
        "web/app.js",
      ]);
      same(p, "bandit targets", sc.targets.bandit, ["svc/py/util.py"]);
      same(p, "a deleted file is counted once per tool, never a target", sc.targetsDropped, 2);
      same(p, "the changed set", [...sc.changed].sort(), [
        "docs/readme.md",
        "go/main.go",
        "gone/deleted.py",
        "svc/Main.java",
        "svc/py/util.py",
        "web/app.js",
      ]);
      const none = planScope(complete([]), inv);
      same(
        p,
        "an empty list: targets, no file",
        [none.kind, none.targets.opengrep, none.targets.bandit],
        ["targets", [], []],
      );
      const onlyJs = planScope(complete(["web/app.js"]), inv);
      same(
        p,
        "only JavaScript changed",
        [onlyJs.targets.opengrep, onlyJs.targets.bandit],
        [["web/app.js"], []],
      );
      // widening
      const big = inventoryOf(Array.from({ length: 2002 }, (_, i) => `d/f${i}.js`));
      const allChanged = Array.from({ length: 2002 }, (_, i) => `d/f${i}.js`);
      same(
        p,
        "2001 targets widen",
        [planScope(complete(allChanged), big).kind, planScope(complete(allChanged), big).targets],
        ["full_filtered", {}],
      );
      const exact = inventoryOf(Array.from({ length: 2000 }, (_, i) => `d/f${i}.js`));
      same(
        p,
        "2000 targets stay targets",
        [
          planScope(complete(allChanged.slice(0, 2000)), exact).kind,
          planScope(complete(allChanged.slice(0, 2000)), exact).targets.opengrep.length,
        ],
        ["targets", 2000],
      );
      const odd = inventoryOf(["web/app.js", "web/a\u202eb.js", "web/-x.js"]);
      const widened = planScope(complete(["web/app.js", "web/a\u202eb.js"]), odd);
      same(
        p,
        "a changed file with an unusable name widens the run",
        [widened.kind, widened.targets],
        ["full_filtered", {}],
      );
      const hyphen = planScope(complete(["web/-x.js"]), odd);
      same(
        p,
        "a name that starts a segment with a hyphen is a valid target",
        hyphen.kind,
        "targets",
      );
      const leading = inventoryOf(["-rf.js"]);
      same(
        p,
        "a leading hyphen widens the run",
        planScope(complete(["-rf.js"]), leading).kind,
        "full_filtered",
      );
      const trunc = planScope(complete(["web/app.js"]), { counts: {}, paths: {}, truncated: true });
      same(
        p,
        "a truncated inventory widens the run",
        [trunc.kind, [...trunc.changed]],
        ["full_filtered", ["web/app.js"]],
      );
      // the filter
      const f = (path2) => ({ location: { path: path2, startLine: 1 }, dedupKey: path2 });
      const findings = [f("a.py"), f("b.py"), f("c/d.js"), { dedupKey: "no-path" }];
      const kept = filterToChanged(findings, new Set(["a.py", "c/d.js"]));
      same(
        p,
        "filter keeps the changed",
        [kept.kept.map((x) => x.dedupKey), kept.dropped],
        [["a.py", "c/d.js", "no-path"], 1],
      );
      same(
        p,
        "a full run filters nothing",
        [filterToChanged(findings, null).kept.length, filterToChanged(findings, null).dropped],
        [4, 0],
      );
      same(
        p,
        "an empty changed set keeps only a finding with no path",
        filterToChanged(findings, new Set()).kept.map((x) => x.dedupKey),
        ["no-path"],
      );
      // target rules
      same(
        p,
        "target rules",
        [
          "a.py",
          "-a.py",
          "/a.py",
          "a/../b.py",
          "a\\b.py",
          "a\nb.py",
          "a\u200bb.py",
          "a\u2028b.py",
          "a/b/",
          "",
          ".hidden",
          "_x",
          "9.py",
          "a".repeat(1024),
          "a".repeat(1025),
          5,
          null,
        ].map(isSafeTargetPath),
        [
          true,
          false,
          false,
          false,
          false,
          false,
          false,
          false,
          false,
          false,
          true,
          true,
          true,
          true,
          false,
          false,
          false,
        ],
      );
      // an incremental inventory
      const scoped = scopedInventory(inv, new Set(["svc/py/app.py", "svc/Main.java", "gone.py"]));
      same(p, "scoped counts", scoped.counts, { python: 1, java: 1 });
      same(p, "scoped paths", scoped.paths, { python: ["svc/py/app.py"], java: ["svc/Main.java"] });
      ok(p, scopedInventory(inv, null) === inv, "a full run changed the inventory");
      const tr = { counts: { python: 1 }, paths: { python: ["a.py"] }, truncated: true };
      ok(p, scopedInventory(tr, new Set(["b.py"])) === tr, "a truncated inventory was narrowed");
      same(
        p,
        "nothing changed of a supported language",
        applicability(scopedInventory(inv, new Set(["docs/readme.md"]))).relevantFilesExist,
        false,
      );
      same(
        p,
        "only a Java file changed",
        applicability(scopedInventory(inv, new Set(["svc/Main.java"]))).gaps,
        ["java"],
      );
      return p;
    },
  },
  {
    id: "ENG-S16f",
    name: "the SAST engine over a FakeSandboxRuntime (SPEC scan-engines 5.3, 5.4, 5.5, 5.9, 6.1, 6.4, SE-16 to SE-24, 14.1 ENG-S11 and ENG-S16, 16.1 part H; the real adapters, the real roll-up, the real merger and the REAL tool output of 2026-11-21): the engine identity (`sast`, `default`, `ensemble-sast/1`, idempotent, needs the platform facts) and the refusal of a relative rules directory; both tools run with the sealed command lines over a whole tree and give the 33 merged findings of the real fixtures, the roll-up row 5, complete, with the pack digest as the configuration digest of Opengrep and in the run manifest (a changed rule changes the manifest); a tree with no source file is nothing to scan (row 3: both tools skipped / no_applicable_files, NO container started, complete, zero items), a tree of Java only a language gap (row 4: incomplete, gap java), a tree of JavaScript only skips Bandit and starts only Opengrep, a mixed tree names its gap and is incomplete; an incremental scan with a complete changed list runs the tools with explicit targets after `--` (`/src/...`), records the scope, keeps only the findings of the changed files (the filter is applied once to the merged findings, also when the tool was narrowed), widens to the whole tree with the filter for more than 2000 changed files or a changed file with a name that cannot be a target, and ignores a truncated or unavailable list; planted repository configuration and hostile file names never change the command line (the whole run is the same constants whatever the tree), an unknown extension is not a language; every exit class is a fixed word (Opengrep exit 2 is `exit_code`, 7 and 8 `config_invalid`, Bandit exit 2 with the unreadable-configuration text `config_invalid`, 137 `out_of_memory`, the accepted codes never classified), a failed tool degrades the result (row 6, incomplete), both failed fail the task (row 7), an Opengrep image that is not in the lock or the store (the own build before it is mirrored) is unavailable / image_unavailable and the task is degraded, a file the tool could not process makes its run partial / output_invalid, a lease loss and a deadline abort with rows 1 and 2 and the runner is asked to abort the attempt numbered from 1, the item cap truncates the result",
    async run() {
      const p = [];
      const base = mkdtempSync(path.join(os.tmpdir(), "qm-ens-h-"));
      try {
        const archiveRoot = path.join(base, "scan");
        const rulesDir = path.join(base, "rules");
        mkdirSync(archiveRoot);
        cpSync(RULES_DIR, rulesDir, { recursive: true });
        const lock = JSON.parse(
          readFileSync(path.join(ENGINE_DIR, "catalog/images.lock.json"), "utf8"),
        );
        const entry = lock.images.find((i) => i.key === "opengrep");
        entry.repository = "mirror.example/qm/opengrep";
        entry.digest = `sha256:${"d4".repeat(32)}`;
        entry.flags = entry.flags.filter((f) => f !== "local_build_requires_registry_digest");
        const mirrored = createImageResolver(lock, { production: false });
        let n = 0;
        const tree = (files) => {
          const dir = path.join(archiveRoot, `t${(n += 1)}`);
          mkdirSync(dir, { mode: 0o755 });
          if (files === "fixture") {
            cpSync(path.join(FIX, "tree"), dir, { recursive: true });
            return dir;
          }
          for (const [name, text] of Object.entries(files)) {
            mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
            writeFileSync(path.join(dir, name), text);
          }
          return dir;
        };
        const make = ({
          scripts = {},
          gate = {},
          resolver,
          runnerOver,
          deps = {},
          rules = rulesDir,
        } = {}) => {
          const runtime = new FakeSandboxRuntime({
            config: {
              runtimeBin: "podman",
              containerUser: "65534:65534",
              usernsMode: "keep-id",
              uidMap: [],
              gidMap: [],
              seccompProfile: null,
              mountRoots: { archive: [archiveRoot], db: [], rules: [rules] },
              egressNetworks: {},
            },
          });
          runtime.script("opengrep", { exitCode: 0, stdout: OG_TREE, ...scripts.opengrep });
          runtime.script("bandit", { exitCode: 1, stdout: BD_TREE, ...scripts.bandit });
          const runner = createSandboxRunner({ runtime });
          const aborts = [];
          const engine = createEnsembleSastEngine({
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
            resolver: resolver ?? mirrored,
            rulesDir: rules,
            toolWaitMs: 300,
            treePathExists: createTreePathExists,
            ...deps,
          });
          const run = ({
            files = "fixture",
            signal,
            changedPaths,
            maxItems,
            secondsToDeadline = 300,
          } = {}) => {
            const dir = typeof files === "string" && files !== "fixture" ? files : tree(files);
            return engine.runTask(
              Object.freeze({
                executionId: "00000000-1111-4111-8111-000000000009",
                taskId: TASK_A,
                attempt: 0,
                scanType: "sast",
                sourceDir: dir,
              }),
              {
                signal: signal ?? new AbortController().signal,
                log() {},
                emit() {},
                platform: {
                  tenantId: "aaaaaaaa-0000-4000-8000-00000000000a",
                  deadlineEpoch: Math.floor(Date.now() / 1000) + secondsToDeadline,
                  secondsToDeadline,
                  ...(changedPaths === undefined ? {} : { changedPaths }),
                  ...(maxItems === undefined ? {} : { maxItems }),
                },
              },
            );
          };
          return { engine, run, runtime, aborts };
        };
        const statuses = (r) =>
          Object.fromEntries(
            r.ensemble.toolRuns.map((t) => [
              t.toolId,
              `${t.status}${t.reason ? `/${t.reason}` : ""}`,
            ]),
          );
        const runs = (h) => h.runtime.calls.filter((c) => c.type === "run");
        const tail = (call) => call.args.slice(call.args.indexOf(call.spec.image) + 1);
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
            Object.isFrozen(e.engine),
          ],
          ["sast", "default", "ensemble-sast/1", true, true, true],
        );
        let relative = null;
        try {
          make({ deps: { rulesDir: "relative/rules" } });
        } catch (x) {
          relative = x instanceof TypeError;
        }
        ok(p, relative === true, "a relative rules directory was accepted");
        let noPlatform = null;
        try {
          await e.engine.runTask(
            Object.freeze({
              executionId: "x",
              taskId: TASK_A,
              attempt: 0,
              sourceDir: tree("fixture"),
            }),
            { signal: new AbortController().signal, log() {}, emit() {} },
          );
        } catch (x) {
          noPlatform = x instanceof TypeError;
        }
        ok(p, noPlatform === true, "the engine ran without the platform facts");
        // a whole-tree run
        const full = await e.run();
        same(p, "full: statuses", statuses(full), { opengrep: "succeeded", bandit: "succeeded" });
        same(
          p,
          "full: result",
          [
            full.status,
            full.items.length,
            full.truncated,
            full.incomplete,
            full.ensemble.rollup.matchedRow,
            full.ensemble.coverage.state,
            full.ensemble.scope.kind,
          ],
          ["succeeded", 33, false, false, 5, "complete", "full"],
        );
        const calls = runs(e);
        same(p, "full: both containers started", calls.map((c) => c.spec.toolId).sort(), [
          "bandit",
          "opengrep",
        ]);
        same(
          p,
          "full: the sealed Opengrep line",
          tail(calls.find((c) => c.spec.toolId === "opengrep")),
          [...OPENGREP_ARGV, "/src"],
        );
        same(
          p,
          "full: the sealed Bandit line",
          tail(calls.find((c) => c.spec.toolId === "bandit")),
          [...BANDIT_ARGV, "-r", "/src"],
        );
        same(
          p,
          "full: no `--`",
          calls.some((c) => c.args.includes("--")),
          false,
        );
        same(
          p,
          "full: the tool run records",
          full.ensemble.toolRuns.map((t) => [
            t.toolId,
            t.scope,
            t.findingsMapped,
            t.recordsDropped,
            t.exitCode,
          ]),
          [
            ["opengrep", { kind: "full", paths: 0 }, 26, 0, 0],
            ["bandit", { kind: "full", paths: 0 }, 13, 0, 1],
          ],
        );
        same(
          p,
          "full: every finding states its scope",
          [...new Set(full.ensemble.details.map((d) => JSON.stringify(d.scope)))],
          ['{"kind":"full","inScope":true}'],
        );
        const pack = loadRulePack(rulesDir);
        same(
          p,
          "the configuration digest of Opengrep is the pack digest",
          full.ensemble.toolRuns.find((t) => t.toolId === "opengrep").configDigest,
          pack.digest,
        );
        ok(p, /^[0-9a-f]{64}$/.test(full.ensemble.runManifestSha256), "the run manifest");
        same(
          p,
          "the manifest is repeatable",
          (await e.run()).ensemble.runManifestSha256,
          full.ensemble.runManifestSha256,
        );
        // a changed rule changes the manifest
        const rules2 = path.join(base, "rules2");
        cpSync(RULES_DIR, rules2, { recursive: true });
        const jsFile = path.join(rules2, "qm-sast", "qm-javascript.yml");
        writeFileSync(jsFile, `${readFileSync(jsFile, "utf8")}\n# a comment\n`);
        const e2 = make({ rules: rules2 });
        ok(
          p,
          (await e2.run()).ensemble.runManifestSha256 !== full.ensemble.runManifestSha256,
          "a changed rule file did not change the manifest",
        );
        // the items are valid findings of the SAST scan type
        ok(
          p,
          full.items.every((i) => i.kind === "code_issue" && i.path && i.startLine >= 1),
          "an item is not a code issue with a location",
        );
        same(p, "detail rows follow the items", full.ensemble.details.length, full.items.length);
        // applicability: row 3, row 4, partial applicability, mixed
        const row3 = make();
        const r3 = await row3.run({
          files: { "README.md": "hello", "data.json": "{}", Dockerfile: "FROM x" },
        });
        same(
          p,
          "row 3",
          [
            r3.status,
            r3.items.length,
            r3.incomplete,
            r3.ensemble.rollup.matchedRow,
            r3.ensemble.coverage.state,
            r3.ensemble.coverage.coverageGaps,
            statuses(r3),
          ],
          [
            "succeeded",
            0,
            false,
            3,
            "nothing_to_scan",
            [],
            { opengrep: "skipped/no_applicable_files", bandit: "skipped/no_applicable_files" },
          ],
        );
        same(p, "row 3 starts no container", runs(row3).length, 0);
        same(p, "row 3 is eligible for resolution", r3.ensemble.rollup.resolutionEligible, true);
        ok(
          p,
          r3.ensemble.toolRuns.every(
            (t) => t.imageDigest === null && t.toolVersion === "unknown" && t.exitCode === null,
          ),
          "a skipped tool run carries a container fact",
        );
        const row4 = make();
        const r4 = await row4.run({
          files: { "src/Main.java": "class A {}", "lib/x.c": "int x;" },
        });
        same(
          p,
          "row 4",
          [
            r4.items.length,
            r4.incomplete,
            r4.ensemble.rollup.matchedRow,
            r4.ensemble.coverage.state,
            r4.ensemble.coverage.coverageGaps,
            r4.ensemble.rollup.resolutionEligible,
          ],
          [0, true, 4, "language_gap", ["c", "java"], false],
        );
        same(p, "row 4 starts no container", runs(row4).length, 0);
        const jsOnly = make({
          scripts: {
            opengrep: {
              stdout: JSON.stringify(
                ogDoc([{ id: "qm.js.sql-injection", path: "a.js", line: 2, cwe: 89 }]),
              ),
            },
          },
        });
        const rj = await jsOnly.run({ files: { "a.js": "x\nx\nx" } });
        same(
          p,
          "javascript only",
          [
            statuses(rj),
            runs(jsOnly).map((c) => c.spec.toolId),
            rj.items.length,
            rj.ensemble.rollup.matchedRow,
            rj.incomplete,
          ],
          [
            { opengrep: "succeeded", bandit: "skipped/no_applicable_files" },
            ["opengrep"],
            1,
            5,
            false,
          ],
        );
        const mixed = make({
          scripts: {
            opengrep: { stdout: JSON.stringify(ogDoc([{ path: "a.py", line: 1 }])) },
            bandit: { stdout: JSON.stringify(bdDoc([{ path: "a.py", line: 1 }])) },
          },
        });
        const rm = await mixed.run({ files: { "a.py": "x", "svc/Main.java": "class A {}" } });
        same(
          p,
          "a mixed tree",
          [
            rm.status,
            rm.items.length,
            rm.incomplete,
            rm.ensemble.rollup.matchedRow,
            rm.ensemble.coverage.state,
            rm.ensemble.coverage.coverageGaps,
            rm.ensemble.rollup.resolutionEligible,
          ],
          ["succeeded", 1, true, 5, "language_gap", ["java"], true],
        );
        // scope: targets
        const sc = make();
        const changed = {
          status: "complete",
          paths: ["svc/py/app.py", "docs/readme.md", "gone/deleted.py"],
        };
        const rt = await sc.run({ changedPaths: changed });
        const tcalls = runs(sc);
        same(
          p,
          "targets: the Opengrep tail",
          tail(tcalls.find((c) => c.spec.toolId === "opengrep")),
          [...OPENGREP_ARGV, "--", "/src/svc/py/app.py"],
        );
        same(p, "targets: the Bandit tail", tail(tcalls.find((c) => c.spec.toolId === "bandit")), [
          ...BANDIT_ARGV,
          "--",
          "/src/svc/py/app.py",
        ]);
        ok(
          p,
          !tcalls.some((c) => tail(c).includes("/src") || tail(c).includes("-r")),
          "a targets run still names the whole tree",
        );
        same(
          p,
          "targets: the scope of the runs",
          rt.ensemble.toolRuns.map((t) => [t.toolId, t.scope]),
          [
            ["opengrep", { kind: "targets", paths: 1 }],
            ["bandit", { kind: "targets", paths: 1 }],
          ],
        );
        ok(
          p,
          rt.items.length > 0 && rt.items.every((i) => i.path === "svc/py/app.py"),
          "a finding outside the changed files was kept",
        );
        same(
          p,
          "targets: the filter dropped the other files of the (unscoped) fake output",
          [
            rt.ensemble.scope.kind,
            rt.ensemble.scope.outOfScopeDropped > 0,
            rt.ensemble.scope.targetsDropped,
          ],
          ["targets", true, 2],
        );
        same(
          p,
          "targets: every finding states its scope",
          [...new Set(rt.ensemble.details.map((d) => JSON.stringify(d.scope)))],
          ['{"kind":"targets","inScope":true}'],
        );
        same(
          p,
          "targets: the changed paths status is recorded",
          rt.ensemble.changedPathsStatus,
          "complete",
        );
        // scope: only a Go file changed -> Bandit has no target and is skipped
        const goOnly = make();
        const rg = await goOnly.run({
          changedPaths: { status: "complete", paths: ["go/main.go"] },
        });
        same(
          p,
          "targets: Bandit has nothing to scan",
          [statuses(rg), runs(goOnly).map((c) => c.spec.toolId)],
          [{ opengrep: "succeeded", bandit: "skipped/no_applicable_files" }, ["opengrep"]],
        );
        same(
          p,
          "targets: only the changed file",
          [...new Set(rg.items.map((i) => i.path))],
          ["go/main.go"],
        );
        // no relevant changed file: nothing to scan
        const noRel = make();
        const rn = await noRel.run({ changedPaths: { status: "complete", paths: ["README.md"] } });
        same(
          p,
          "an incremental scan with no source change",
          [rn.ensemble.rollup.matchedRow, rn.items.length, runs(noRel).length],
          [3, 0, 0],
        );
        // scope: widening
        const many = Object.fromEntries(
          Array.from({ length: 2002 }, (_, i) => [`d/f${i}.js`, "x"]),
        );
        const wide = make({
          scripts: {
            opengrep: {
              stdout: JSON.stringify(
                ogDoc([
                  { id: "qm.js.sql-injection", path: "d/f7.js", line: 1, cwe: 89 },
                  { id: "qm.js.sql-injection", path: "d/f8.js", line: 1, cwe: 89 },
                ]),
              ),
            },
          },
        });
        const rw = await wide.run({
          files: many,
          changedPaths: {
            status: "complete",
            paths: Object.keys(many).filter((k) => k !== "d/f8.js"),
          },
        });
        same(
          p,
          "2001 changed files: the whole tree, filtered",
          [
            rw.ensemble.scope.kind,
            tail(runs(wide).find((c) => c.spec.toolId === "opengrep")).slice(-1),
            rw.items.length,
          ],
          ["full_filtered", ["/src"], 1],
        );
        same(
          p,
          "widened runs record the scope",
          rw.ensemble.toolRuns.find((t) => t.toolId === "opengrep").scope.kind,
          "full_filtered",
        );
        const odd = make({
          scripts: {
            opengrep: {
              stdout: JSON.stringify(
                ogDoc([
                  { id: "qm.js.sql-injection", path: "-rf.js", line: 1, cwe: 89 },
                  { id: "qm.js.sql-injection", path: "ok.js", line: 1, cwe: 89 },
                ]),
              ),
            },
          },
        });
        const ro = await odd.run({
          files: { "-rf.js": "x", "ok.js": "x" },
          changedPaths: { status: "complete", paths: ["-rf.js"] },
        });
        same(
          p,
          "a changed file with a hostile name: the whole tree, filtered, the name in no argument",
          [
            ro.ensemble.scope.kind,
            ro.items.map((i) => i.path),
            runs(odd).some((c) => c.args.some((a) => a.includes("-rf.js"))),
          ],
          ["full_filtered", ["-rf.js"], false],
        );
        for (const status of ["truncated", "unavailable", "not_recorded"]) {
          const h = make();
          const rr = await h.run({ changedPaths: { status, paths: ["go/main.go"] } });
          same(
            p,
            `${status}: full and unfiltered`,
            [rr.ensemble.scope.kind, rr.items.length, rr.ensemble.changedPathsStatus],
            ["full", 33, status],
          );
        }
        // planted repository content never changes the command line
        const planted = make();
        await planted.run({
          files: {
            ".semgrepignore": "*\n",
            ".gitignore": "*\n",
            ".bandit": "[bandit]\nskips=B602\n",
            "setup.cfg": "[bandit]\n",
            "a.py": "# nosec nosemgrep\nx=1\n",
            "--config=evil.py": "x",
            "$(id).js": "x",
          },
        });
        const clean = make();
        await clean.run({ files: { "a.py": "x=1\n" } });
        same(
          p,
          "the command lines do not depend on the tree",
          runs(planted).map((c) => tail(c)),
          runs(clean).map((c) => tail(c)),
        );
        ok(
          p,
          !runs(planted).some((c) => c.args.some((a) => /evil|\$\(id\)/.test(a))),
          "a repository name reached an argument",
        );
        // exit classes
        const reason = async (tool, outcome) =>
          statuses(await make({ scripts: { [tool]: outcome } }).run())[tool];
        same(
          p,
          "Opengrep exit 2",
          await reason("opengrep", { exitCode: 2, stdout: "" }),
          "failed/exit_code",
        );
        same(
          p,
          "Opengrep exit 7",
          await reason("opengrep", { exitCode: 7, stdout: "" }),
          "failed/config_invalid",
        );
        same(
          p,
          "Opengrep exit 8",
          await reason("opengrep", { exitCode: 8, stdout: "" }),
          "failed/config_invalid",
        );
        same(
          p,
          "Opengrep exit 1",
          await reason("opengrep", { exitCode: 1, stdout: "" }),
          "failed/exit_code",
        );
        same(
          p,
          "Opengrep 137",
          await reason("opengrep", { exitCode: 137, stdout: "" }),
          "failed/out_of_memory",
        );
        same(
          p,
          "Bandit exit 2",
          await reason("bandit", { exitCode: 2, stdout: "", stderr: "usage: bandit" }),
          "failed/exit_code",
        );
        same(
          p,
          "Bandit unreadable config",
          await reason("bandit", {
            exitCode: 2,
            stdout: "",
            stderr: "[main]\tERROR\t/rules/bandit.yaml : Could not read config file.",
          }),
          "failed/config_invalid",
        );
        same(
          p,
          "Bandit 137",
          await reason("bandit", { exitCode: 137, stdout: "" }),
          "failed/out_of_memory",
        );
        same(
          p,
          "Bandit exit 0 is accepted",
          await reason("bandit", { exitCode: 0, stdout: JSON.stringify(bdDoc([])) }),
          "succeeded",
        );
        same(
          p,
          "classify: accepted codes",
          [
            classifyToolExit({ exitCode: 0, role: "sast", toolId: "opengrep" }),
            classifyToolExit({ exitCode: 1, accepted: [0, 1], role: "sast", toolId: "bandit" }),
          ],
          [null, null],
        );
        same(
          p,
          "classify: 7 is only Opengrep's in the SAST role",
          [
            classifyToolExit({ exitCode: 7, role: "sast", toolId: "bandit" }),
            classifyToolExit({ exitCode: 7, role: "sca", toolId: "opengrep" }),
            classifyToolExit({ exitCode: 7, role: "sast", toolId: "opengrep" }),
          ],
          ["exit_code", "exit_code", "config_invalid"],
        );
        // degraded and failed
        const one = await make({ scripts: { bandit: { exitCode: 2, stdout: "" } } }).run();
        same(
          p,
          "one tool failed: degraded",
          [
            one.status,
            one.incomplete,
            one.ensemble.rollup.matchedRow,
            one.ensemble.rollup.toolsDegraded,
            one.ensemble.coverage.state,
            one.items.length,
          ],
          ["succeeded", true, 6, 1, "degraded", 26],
        );
        const both = await make({
          scripts: { bandit: { exitCode: 2, stdout: "" }, opengrep: { exitCode: 2, stdout: "" } },
        }).run();
        same(
          p,
          "both failed: failed",
          [
            both.status,
            both.ensemble.rollup.matchedRow,
            both.ensemble.rollup.reason,
            both.ensemble.rollup.errorClass,
            both.items.length,
          ],
          ["failed", 7, "tools_failed", "permanent", 0],
        );
        // the own build before it is mirrored
        const unmirrored = make({ resolver: loadImageLock().resolver });
        const ru = await unmirrored.run();
        same(
          p,
          "the unmirrored own build",
          [
            statuses(ru),
            ru.ensemble.rollup.matchedRow,
            ru.incomplete,
            runs(unmirrored).map((c) => c.spec.toolId),
          ],
          [{ opengrep: "unavailable/image_unavailable", bandit: "succeeded" }, 6, true, ["bandit"]],
        );
        // files the tool could not process
        const errs = await make({
          scripts: {
            opengrep: {
              stdout: JSON.stringify(
                ogDoc(
                  [{ id: "qm.go.sql-injection", path: "go/main.go", line: 16, cwe: 89 }],
                  [{ level: "warn", type: "PartialParsing" }],
                ),
              ),
            },
          },
        }).run();
        same(
          p,
          "a file error: partial",
          [statuses(errs).opengrep, errs.incomplete, errs.ensemble.rollup.matchedRow],
          ["partial/output_invalid", true, 5],
        );
        // abort
        for (const [label, why, row, task, toolReason] of [
          ["lease loss", "lease_lost", 1, "cancelled", "cancelled"],
          ["deadline", "task_deadline", 2, "timed_out", "deadline"],
        ]) {
          const ac = new AbortController();
          const h = make({ scripts: { opengrep: { hang: true }, bandit: { hang: true } } });
          const pending = h.run({ signal: ac.signal });
          setTimeout(() => ac.abort(new Error(why)), 80);
          const r = await pending;
          same(
            p,
            `${label}: roll-up`,
            [r.ensemble.rollup.matchedRow, r.ensemble.rollup.taskStatus, r.status],
            [row, task, "succeeded"],
          );
          same(p, `${label}: tool runs`, statuses(r), {
            opengrep: `cancelled/${toolReason}`,
            bandit: `cancelled/${toolReason}`,
          });
          same(
            p,
            `${label}: abort asked for attempt 1`,
            h.aborts.map((a) => [a.taskId, a.attempt]),
            [[TASK_A, 1]],
          );
          same(p, `${label}: nothing left`, [...h.runtime.containers.keys()], []);
        }
        // the item cap
        const capped = await make().run({ maxItems: 10 });
        same(
          p,
          "capped",
          [capped.items.length, capped.truncated, capped.incomplete],
          [10, true, true],
        );
        // image errors of the runtime
        const rtErr = await make({
          runnerOver: (runner) => ({
            ...runner,
            abortAttempt: runner.abortAttempt,
            runTool: async (spec, o) => {
              if (spec.toolId === "bandit") throw new SandboxError("image_unavailable", "x");
              return runner.runTool(spec, o);
            },
          }),
        }).run();
        same(
          p,
          "the runtime has no Bandit image",
          statuses(rtErr).bandit,
          "unavailable/image_unavailable",
        );
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
      return p;
    },
  },
];
