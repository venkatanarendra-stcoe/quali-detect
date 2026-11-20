import { readFileSync } from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import {
  MergeBoundaryError,
  mergeTaskCandidates,
  mergeTaskCandidatesAsync,
  runSync,
  runToolParse,
  runToolParseAsync,
  runYielding,
  sortYielding,
  toStorageRows,
  toStorageRowsAsync,
} from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import { TASK_A, ctxFor, fakeAdapter, out } from "./ensemble-fakes.js";

/**
 * Scan engines, part K core, owner decision of 2026-11-20 (ADR-008 area 18, SPEC scan-engines 17.i and 17.j): the CPU-heavy steps of the
 * ensemble path (parse of the records, merge, storage rows) must give the event loop a turn every few milliseconds, because the lease
 * heartbeat of the scan handler is a timer on the SAME loop and a merge of 50000 candidates took about 24 seconds when it ran in one go.
 * Pure functions and a timer only: no container, process, database or network. NOT proved: throughput (ENG-L10 decides tuning), a single
 * native call (one `JSON.parse` inside `adapter.parse`) which cannot be sliced, and anything about real tool output.
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const ENSEMBLE = path.join(ROOT, "apps/workers/src/execution/engines/ensemble");
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const same = (p, label, got, want) =>
  ok(
    p,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)?.slice(0, 300)}, want ${JSON.stringify(want)?.slice(0, 300)}`,
  );

/**
 * The longest tolerated gap between two ticks of a 200 ms timer while the heavy steps run (milliseconds). The unit of work between two
 * event-loop turns is one time slice (8 ms) plus the largest single item (tens of milliseconds at 25000 open groups), so a healthy run
 * shows 200 to 300 ms; 1000 ms leaves 700 ms for a slow, shared CI machine and garbage collection, and is still ten times below the
 * heartbeat (10 s default) and sixty times below the lease TTL (60 s default). The unyielded merge blocks for tens of seconds, so the
 * bound cannot pass by accident.
 */
export const MAX_TICK_GAP_MS = 1000;
const TICK_MS = 200;

/** A deterministic pseudo-random sequence (a fixed seed: the checks must not depend on the clock). */
const lcg = (seed) => {
  let s = seed;
  return (n) => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s % n;
  };
};

/** Records of a fake adapter whose keys overlap between two tools, so the merge has real work (cross-tool groups, redundant components). */
function records(scanType, tool, n, seed) {
  const rnd = lcg(seed);
  const list = [];
  for (let i = 0; i < n; i += 1) {
    const k = rnd(Math.max(1, Math.floor(n * 0.7)));
    if (scanType === "sbom")
      list.push({
        purl: `pkg:npm/p${k}${rnd(9) === 0 ? "" : `@1.${rnd(3)}.0`}`,
        path: `d${rnd(7)}/package-lock.json`,
        scope: ["prod", "dev", "optional"][rnd(3)],
      });
    else if (scanType === "sca")
      list.push({
        id: `CVE-2024-${1000 + k}`,
        aliases: rnd(2) === 0 ? [`GHSA-${k}xxx-aaaa-bbbb`] : [],
        purl: `pkg:npm/p${rnd(Math.max(1, Math.floor(n / 4)))}@1.${rnd(3)}.0`,
        severity: ["low", "medium", "high", "critical"][rnd(4)],
        fixed: rnd(2) === 0 ? ["1.9.9"] : undefined,
      });
    else if (scanType === "sast")
      list.push({
        id: `rule.${rnd(5)}`,
        path: `src/f${rnd(Math.max(1, Math.floor(n / 6)))}.js`,
        line: 1 + rnd(400),
        endLine: rnd(2) === 0 ? 1 + rnd(400) + 400 : undefined,
        cwe: [[79, 89, 22][rnd(3)]],
        severity: ["low", "medium", "high"][rnd(3)],
      });
    else
      list.push({
        id: `secret.${rnd(4)}`,
        path: `cfg/f${rnd(Math.max(1, Math.floor(n / 5)))}.env`,
        line: 1 + rnd(30),
        typeClass: ["github_token", "aws_access_key", "generic_api_key"][rnd(3)],
        secret: `value-${k}-${rnd(1000)}-xxxxxxxxxxxxxxxx`,
        confidence: ["low", "medium", "high"][rnd(3)],
      });
  }
  return list;
}

const TOOLS = {
  sbom: ["syft", "trivy"],
  sca: ["trivy", "osv-scanner"],
  sast: ["opengrep", "bandit"],
  secrets: ["gitleaks", "detect-secrets"],
};

/** Candidates of both tools of a scan type, parsed by the real framework. */
function candidatesFor(scanType, n, seed = 7) {
  const all = [];
  for (const [i, tool] of TOOLS[scanType].entries()) {
    const adapter = fakeAdapter(tool, scanType, { maxRecords: 100_000 });
    const parsed = runToolParse(adapter, out(records(scanType, tool, n, seed + i)), ctxFor(TASK_A));
    all.push(...parsed.candidates);
  }
  return all;
}

/** A timer that ticks every 200 ms; `stop()` returns the longest gap between the markers (start, every tick, end) and the tick count. */
function gapMeter() {
  const marks = [performance.now()];
  const timer = setInterval(() => marks.push(performance.now()), TICK_MS);
  return {
    stop() {
      clearInterval(timer);
      marks.push(performance.now());
      let max = 0;
      for (let i = 1; i < marks.length; i += 1) max = Math.max(max, marks[i] - marks[i - 1]);
      return {
        maxGap: Math.round(max),
        ticks: marks.length - 2,
        elapsed: Math.round(marks.at(-1) - marks[0]),
      };
    },
  };
}

/** Candidates of an SBOM with `unique` components seen by two tools: the cheapest way to 50000 candidates that merge pairwise. */
function bigSbom(unique) {
  const tools = [
    { id: "syft", run: "22222222-1111-4111-8111-111111111111" },
    { id: "trivy", run: "33333333-1111-4111-8111-111111111111" },
  ];
  const all = [];
  for (const tool of tools)
    for (let i = 0; i < unique; i += 1) {
      const purl = `pkg:npm/pkg${i}@1.0.${i % 97}`;
      const rawRef = { toolRunId: tool.run, ordinal: i };
      all.push({
        schemaVersion: 1,
        scanType: "sbom",
        kind: "component",
        dedupKey: `sbom|${purl}`,
        title: `pkg${i}@1.0.${i % 97}`,
        severity: "info",
        severityAssumed: false,
        confidence: "medium",
        confidenceBasis: "tool",
        rule: { id: "component", tool: tool.id },
        location: { path: `d${i % 50}/package-lock.json` },
        component: { purl, name: `pkg${i}`, version: `1.0.${i % 97}`, ecosystem: "npm" },
        locations: [{ path: `d${i % 50}/package-lock.json` }],
        locationCount: 1,
        rawRef,
        provenance: [
          {
            toolId: tool.id,
            toolVersion: "1",
            imageDigestShort: "none",
            severityRaw: "",
            severityScale: "none",
            rawRef,
          },
        ],
        taskRef: TASK_A,
      });
    }
  return all;
}

/**
 * The scanner of the source guard (ENG-S17b). The comments, strings and template texts of the source are blanked first (a `yield` in a
 * comment or a string counts for nothing), then every `for` / `while` statement is located with its body. A loop is accepted only when
 * its body contains a `yield` (the checkpoint), or the line of the loop or the line above carries `// bounded: <reason>` (a short list
 * with a stated bound). An array-iteration call (`map`, `filter`, `reduce`, ...) on a variable named like a large collection needs the
 * same marker, because a callback cannot yield. `await` is deliberately NOT accepted as a yield point: awaiting a settled promise
 * never lets a timer run.
 * @param {string} source
 * @returns {{ problems: { line: number, kind: string, text: string }[], loops: number, yielding: number }}
 */
export function findUnyieldedLoops(source) {
  const BIG =
    /^(candidates|valid|kept|sorted|classed|findings|ordered|records|components|items|details|groups|parsed|settled|rows|raw|all)$/;
  const METHODS = [
    "map",
    "filter",
    "flatMap",
    "forEach",
    "reduce",
    "sort",
    "some",
    "every",
    "find",
    "flat",
    "findIndex",
  ];
  const out = source.split("");
  const n = source.length;
  const fill = (a, b) => {
    for (let k = a; k < b; k += 1) if (out[k] !== "\n") out[k] = " ";
  };
  let i = 0;
  while (i < n) {
    const c = source[i];
    const d = source[i + 1];
    if (c === "/" && d === "/") {
      let j = i;
      while (j < n && source[j] !== "\n") j += 1;
      fill(i, j);
      i = j;
    } else if (c === "/" && d === "*") {
      const e = source.indexOf("*/", i + 2);
      const j = e < 0 ? n : e + 2;
      fill(i, j);
      i = j;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && source[j] !== c && source[j] !== "\n") {
        if (source[j] === "\\") j += 1;
        j += 1;
      }
      fill(i + 1, j);
      i = j + 1;
    } else if (c === "`") {
      let j = i + 1;
      while (j < n && source[j] !== "`") {
        if (source[j] === "\\") j += 1;
        j += 1;
      }
      fill(i + 1, j);
      i = j + 1;
    } else i += 1;
  }
  const code = out.join("");
  const lines = source.split("\n");
  const matching = (open, openCh, closeCh) => {
    let depth = 0;
    for (let k = open; k < code.length; k += 1) {
      if (code[k] === openCh) depth += 1;
      else if (code[k] === closeCh) {
        depth -= 1;
        if (depth === 0) return k;
      }
    }
    return -1;
  };
  const lineOf = (pos) => source.slice(0, pos).split("\n").length;
  const marked = (line) =>
    /\/\/\s*bounded:\s*\S/.test(lines[line - 1] ?? "") ||
    /^\s*\/\/\s*bounded:\s*\S/.test(lines[line - 2] ?? "");
  const problems = [];
  let loops = 0;
  let yielding = 0;
  const loopRe = /\b(for|while)\s*(await\s*)?\(/g;
  let m;
  while ((m = loopRe.exec(code))) {
    const close = matching(m.index + m[0].length - 1, "(", ")");
    let k = close + 1;
    while (/\s/.test(code[k])) k += 1;
    let end;
    if (code[k] === "{") end = matching(k, "{", "}");
    else {
      end = code.indexOf(";", k);
      if (end < 0) end = code.length;
    }
    loops += 1;
    if (/\byield\b/.test(code.slice(close + 1, end + 1))) {
      yielding += 1;
      continue;
    }
    const line = lineOf(m.index);
    if (!marked(line)) problems.push({ line, kind: "loop", text: lines[line - 1].trim() });
  }
  const methodRe = new RegExp(
    `([A-Za-z_$][\\w$]*)\\s*(?:\\?\\.|\\.)(${METHODS.join("|")})\\s*\\(`,
    "g",
  );
  while ((m = methodRe.exec(code))) {
    if (!BIG.test(m[1])) continue;
    const line = lineOf(m.index);
    if (!marked(line)) problems.push({ line, kind: `.${m[2]}()`, text: lines[line - 1].trim() });
  }
  return { problems, loops, yielding };
}

/** The files of the ensemble path that loop over candidates, components, findings or records (ENG-S17b). */
export const GUARDED_FILES = [
  "core/merger.js",
  "core/storage.js",
  "core/run-parse.js",
  "engine/engine.js",
];

/** The cheap part of ENG-S17a: sort, driver, determinism against the synchronous reference, identical refusals (also used by the mutation sweep). */
export async function yieldEquivalenceProblems() {
  const p = [];
  // ---- the stable sort equals the native one
  for (const size of [0, 1, 2, 255, 256, 257, 511, 512, 513, 1000, 5000]) {
    const rnd = lcg(size + 1);
    const items = Array.from({ length: size }, (_, i) => ({
      k: rnd(Math.max(1, size >> 2)),
      i,
    }));
    const native = [...items].sort((a, b) => a.k - b.k);
    const mine = runSync(sortYielding(items, (a, b) => a.k - b.k));
    ok(
      p,
      mine.length === native.length && mine.every((x, i) => x === native[i]),
      `sort of ${size} items differs from the native stable sort`,
    );
  }
  // ---- the driver
  {
    const events = [];
    let clock = 0;
    function* work() {
      for (let i = 0; i < 6; i += 1) {
        events.push(`w${i}`);
        yield;
      }
      return "done";
    }
    // every clock read advances 5 ms, the slice is 8 ms: the loop gets a turn after every second checkpoint at most
    const realImmediate = globalThis.setImmediate;
    let turns = 0;
    globalThis.setImmediate = (fn, ...args) => {
      turns += 1;
      return realImmediate(fn, ...args);
    };
    let result;
    try {
      result = await runYielding(work(), { sliceMs: 8, now: () => (clock += 5) });
      same(p, "driver result", result, "done");
      same(p, "driver order", events, ["w0", "w1", "w2", "w3", "w4", "w5"]);
      // the first read is at 5 ms, a turn is due every second checkpoint: 6 checkpoints give 3 turns
      same(p, "event-loop turns of a slice of 8 ms at 5 ms per clock read", turns, 3);
      turns = 0;
      await runYielding(work(), { sliceMs: Infinity, now: () => 0 });
      same(p, "a driver with an unlimited slice gives no turn", turns, 0);
      turns = 0;
      await runYielding(work(), { sliceMs: 0, now: () => 0 });
      ok(p, turns >= 6, `a zero slice gives a turn at every checkpoint (${turns})`);
    } finally {
      globalThis.setImmediate = realImmediate;
    }
    // a throwing generator rejects, the synchronous driver throws
    function* boom() {
      yield;
      throw new MergeBoundaryError("input_invalid", "x");
    }
    let code = null;
    try {
      await runYielding(boom());
    } catch (e) {
      code = e.code;
    }
    same(p, "the async driver rejects with the error of the generator", code, "input_invalid");
  }
  // ---- yielding changes nothing: every scan type, a turn at every checkpoint
  for (const scanType of ["sbom", "sca", "sast", "secrets"]) {
    const candidates = candidatesFor(scanType, 700);
    const input = { taskRef: TASK_A, scanType, candidates };
    const reference = mergeTaskCandidates(input);
    ok(p, reference.findings.length > 0, `${scanType}: nothing to merge`);
    ok(
      p,
      reference.stats.merged > 0,
      `${scanType}: the fixture merged nothing (vacuous determinism check)`,
    );
    for (const options of [undefined, { sliceMs: 0 }]) {
      const got = await mergeTaskCandidatesAsync(input, options);
      ok(
        p,
        JSON.stringify(got) === JSON.stringify(reference),
        `${scanType}: the async merge (${JSON.stringify(options)}) differs from the synchronous reference`,
      );
      ok(p, Object.isFrozen(got.findings[0]), `${scanType}: findings must be frozen`);
    }
    const rowsRef = toStorageRows(reference.findings, 1_000_000);
    ok(p, rowsRef.items.length > 0, `${scanType}: no storage rows`);
    const rowsAsync = await toStorageRowsAsync(reference.findings, 1_000_000, { sliceMs: 0 });
    ok(
      p,
      JSON.stringify(rowsAsync) === JSON.stringify(rowsRef),
      `${scanType}: the async storage projection differs`,
    );
    const capped = await toStorageRowsAsync(reference.findings, 3, { sliceMs: 0 });
    same(p, `${scanType}: the cap`, [capped.items.length, capped.truncated], [3, true]);
    same(
      p,
      `${scanType}: the capped result equals the synchronous one`,
      capped,
      toStorageRows(reference.findings, 3),
    );
    // the parse
    const adapter = fakeAdapter(TOOLS[scanType][0], scanType, { maxRecords: 100_000 });
    const stream = out(records(scanType, TOOLS[scanType][0], 300, 11));
    const ctx = ctxFor(TASK_A, { toolRunId: "44444444-1111-4111-8111-111111111111" });
    const parseRef = runToolParse(adapter, stream, ctx);
    const parseAsync = await runToolParseAsync(adapter, stream, ctx, {}, { sliceMs: 0 });
    ok(
      p,
      parseRef.candidates.length > 0 && JSON.stringify(parseAsync) === JSON.stringify(parseRef),
      `${scanType}: the async parse differs from the synchronous one`,
    );
  }
  // ---- refusals are identical
  for (const bad of [
    { taskRef: TASK_A, scanType: "license", candidates: [] },
    { taskRef: 5, scanType: "sca", candidates: [] },
    { taskRef: TASK_A, scanType: "sca", candidates: [{ nope: 1 }] },
    {
      taskRef: "22222222-2222-4222-8222-222222222222",
      scanType: "sbom",
      candidates: candidatesFor("sbom", 3),
    },
    { taskRef: TASK_A, scanType: "sca", candidates: candidatesFor("sbom", 3) },
  ]) {
    const codeOf = async (fn) => {
      try {
        await fn();
      } catch (e) {
        return e instanceof MergeBoundaryError ? e.code : `other ${e?.name}`;
      }
      return null;
    };
    const sync = await codeOf(() => mergeTaskCandidates(bad));
    const async = await codeOf(() => mergeTaskCandidatesAsync(bad));
    ok(p, sync !== null && sync === async, `refusal differs: sync ${sync}, async ${async}`);
  }
  return p;
}

/** The timed part of ENG-S17a: the longest event-loop gap while 50000 candidates are merged, stored and parsed. */
export async function eventLoopGapProblems() {
  const p = [];
  // ---- the event loop is never blocked for long: merge, storage rows and parse
  {
    const candidates = bigSbom(25_000);
    ok(p, candidates.length === 50_000, "the fixture must hold 50000 candidates");
    const meter = gapMeter();
    const merged = await mergeTaskCandidatesAsync({
      taskRef: TASK_A,
      scanType: "sbom",
      candidates,
    });
    const mergeGap = meter.stop();
    same(
      p,
      "50000 candidates, 25000 components seen by two tools",
      [merged.stats.candidates, merged.stats.findings, merged.stats.merged],
      [50_000, 25_000, 25_000],
    );
    ok(
      p,
      mergeGap.maxGap < MAX_TICK_GAP_MS && mergeGap.ticks >= 3,
      `merge of 50000 candidates: longest gap ${mergeGap.maxGap} ms over ${mergeGap.ticks} ticks in ${mergeGap.elapsed} ms (bound ${MAX_TICK_GAP_MS})`,
    );
    const storage = gapMeter();
    const rows = await toStorageRowsAsync(merged.findings, 50_000);
    const storageGap = storage.stop();
    ok(p, rows.items.length === 25_000, `storage rows ${rows.items.length}`);
    ok(
      p,
      storageGap.maxGap < MAX_TICK_GAP_MS && storageGap.ticks >= 3,
      `storage of 25000 findings: longest gap ${storageGap.maxGap} ms over ${storageGap.ticks} ticks in ${storageGap.elapsed} ms (bound ${MAX_TICK_GAP_MS})`,
    );
    const adapter = fakeAdapter("syft", "sbom", { maxRecords: 100_000 });
    const stream = out(records("sbom", "syft", 10_000, 5));
    const parse = gapMeter();
    const parsed = await runToolParseAsync(adapter, stream, ctxFor(TASK_A));
    const parseGap = parse.stop();
    ok(p, parsed.candidates.length === 10_000, `parsed ${parsed.candidates.length}`);
    ok(
      p,
      parseGap.maxGap < MAX_TICK_GAP_MS && parseGap.ticks >= 1,
      `parse of 10000 records: longest gap ${parseGap.maxGap} ms over ${parseGap.ticks} ticks in ${parseGap.elapsed} ms (bound ${MAX_TICK_GAP_MS})`,
    );
    if (process.env.SECURITY_REPORT_GAPS)
      console.log(
        `[ENG-S17a] merge ${JSON.stringify(mergeGap)} storage ${JSON.stringify(storageGap)} parse ${JSON.stringify(parseGap)}`,
      );
  }
  return p;
}

export const ENSEMBLE_YIELD_CHECKS = [
  {
    id: "ENG-S17a",
    name: "the heavy steps of the ensemble path never block the event loop long enough to starve the lease heartbeat, and yielding changes no result (SPEC scan-engines 17.i, 17.j, SE-14, Executions ER-27 and EXEC-028, owner decision 2026-11-20; timer and pure functions only, no container, database or network): a merge of 50000 SBOM candidates (25000 components seen by two tools) runs while a 200 ms timer ticks and the longest gap between two ticks (including the start and the end) stays below 1000 ms, ten times below the 10 s heartbeat; the storage projection of the 25000 findings and the per-record parse of 10000 records stay below the same bound; the async merge, the async parse and the async storage projection return exactly what their synchronous reference returns for every scan type (SBOM, SCA, SAST, secrets), also when the loop is given a turn at EVERY checkpoint, and an invalid or foreign candidate is refused with the same code by both; the checkpointed stable sort equals the native stable sort for ties and for every run boundary; the driver gives the loop a turn only when a slice is used up and never reorders work",
    async run() {
      return [...(await yieldEquivalenceProblems()), ...(await eventLoopGapProblems())];
    },
  },
  {
    id: "ENG-S17b",
    name: "no loop over candidates, components, findings or records in the ensemble path runs without a yield point, and the worker path uses the yielding forms (SPEC scan-engines 17.i, 17.j, owner decision 2026-11-20; source guard): in the merger, the storage projection, the record parse and the engine every for or while statement contains a yield or carries a stated bound (a bounded: comment), and an array-iteration call on a collection named like a large one carries the same marker; the guard is not vacuous (it sees the loops and the yields of each file), ignores a yield written in a comment or a string, does not take an await for a yield point, and is shown to FAIL on mutated sources: a new unmarked loop, a new map over candidates, a removed yield (every sole yield of every guarded file, one at a time), the marker removed from a bounded loop; the engine awaits the async merge, storage projection and parse and calls none of their synchronous forms, and the scan handler awaits the engine while its heartbeat timer is created before the call and cleared only afterwards",
    async run() {
      const p = [];
      const sources = Object.fromEntries(
        GUARDED_FILES.map((f) => [f, readFileSync(path.join(ENSEMBLE, f), "utf8")]),
      );
      for (const [file, source] of Object.entries(sources)) {
        const r = findUnyieldedLoops(source);
        same(p, `${file}: unguarded loops`, r.problems, []);
        ok(p, r.loops >= 1, `${file}: the guard saw no loop (vacuous)`);
      }
      const merger = findUnyieldedLoops(sources["core/merger.js"]);
      ok(
        p,
        merger.loops >= 20 && merger.yielding >= 15,
        `merger: ${merger.loops} loops, ${merger.yielding} yielding`,
      );
      for (const f of ["core/storage.js", "core/run-parse.js"])
        ok(p, findUnyieldedLoops(sources[f]).yielding >= 1, `${f}: no yielding loop`);
      // ---- mutations of the guard's input must be caught
      const merger0 = sources["core/merger.js"];
      const flagged = (src) => findUnyieldedLoops(src).problems.length;
      ok(
        p,
        flagged(`${merger0}\nfor (const c of candidates) total += 1;\n`) === 1,
        "a new unmarked loop is not flagged",
      );
      ok(
        p,
        flagged(`${merger0}\nwhile (x) {\n  y();\n}\n`) === 1,
        "a new unmarked while loop is not flagged",
      );
      ok(
        p,
        flagged(`${merger0}\nconst q = candidates.map((c) => c.id);\n`) === 1,
        "a new map over candidates is not flagged",
      );
      ok(
        p,
        flagged(`${merger0}\nconst q = findings.reduce((a, c) => a + 1, 0);\n`) === 1,
        "a new reduce over findings is not flagged",
      );
      ok(
        p,
        flagged(`${merger0}\nconst q = tools.map((c) => c.id);\n`) === 0,
        "a small collection must not be flagged",
      );
      ok(
        p,
        flagged(
          `${merger0}\n// bounded: three tools\nfor (const c of candidates) total += 1;\n`,
        ) === 0,
        "the marker does not suppress",
      );
      ok(
        p,
        flagged(
          `${merger0}\nfor (const c of candidates) {\n  // yield; yield\n  total += "yield";\n}\n`,
        ) === 1,
        "a yield in a comment or a string counts",
      );
      ok(
        p,
        flagged(`${merger0}\nfor (const c of candidates) {\n  await Promise.resolve();\n}\n`) === 1,
        "an await counts as a yield point",
      );
      ok(
        p,
        flagged(`${merger0}\nfor (const c of candidates) {\n  yield;\n}\n`) === 0,
        "a loop with a yield is wrongly flagged",
      );
      ok(
        p,
        flagged(`${merger0}\nfor (let i = 0; i < n; i += 1) yield;\n`) === 0,
        "a one-statement loop with a yield is wrongly flagged",
      );
      const unmarked = merger0.replace(/\/\/ bounded:[^\n]*\n/, "");
      ok(p, flagged(unmarked) >= 1, "removing a bounded: marker is not flagged");
      // every sole yield of every guarded file, one at a time
      let soleYields = 0;
      let caught = 0;
      for (const [file, source] of Object.entries(sources)) {
        const re = /^[ \t]*yield;[ \t]*$/gm;
        let m;
        while ((m = re.exec(source))) {
          const mutated = source.slice(0, m.index) + source.slice(m.index + m[0].length);
          const before = findUnyieldedLoops(source);
          const after = findUnyieldedLoops(mutated);
          // the loop count is unchanged; a yield that was the only one of its loop must now be a problem
          if (after.yielding < before.yielding) {
            soleYields += 1;
            if (after.problems.length > 0) caught += 1;
            else p.push(`${file}: removing the yield at offset ${m.index} was not flagged`);
          }
        }
      }
      ok(
        p,
        soleYields >= 12 && caught === soleYields,
        `sole yields ${soleYields}, caught ${caught}`,
      );
      // ---- the worker path
      const engine = sources["engine/engine.js"].replace(/\/\/[^\n]*/g, "");
      for (const used of ["mergeTaskCandidatesAsync(", "toStorageRowsAsync(", "runToolParseAsync("])
        ok(p, engine.includes(`await ${used}`), `the engine must await ${used}`);
      for (const banned of [/\bmergeTaskCandidates\(/, /\btoStorageRows\(/, /\brunToolParse\(/])
        ok(p, !banned.test(engine), `the engine must not call the synchronous ${banned}`);
      const handler = readFileSync(
        path.join(ROOT, "apps/workers/src/execution/scan-handler.js"),
        "utf8",
      ).replace(/\/\/[^\n]*/g, "");
      const beat = handler.indexOf("const beat = setInterval(");
      const run = handler.indexOf("await adapter.runTask(");
      const clear = handler.indexOf("clearInterval(beat)");
      ok(p, beat > 0 && run > beat, "the heartbeat timer must exist before the engine runs");
      ok(p, clear > run, "the heartbeat timer must be cleared only after the engine returned");
      ok(
        p,
        !/\brunSync\(/.test(handler) &&
          !/Sync\(/.test(
            sources["engine/engine.js"].replace(/\/\/[^\n]*/g, "").replace(/readFileSync/g, ""),
          ),
        "a synchronous driver or call in the handler or the engine",
      );
      return p;
    },
  },
];
