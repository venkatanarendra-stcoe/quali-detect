/**
 * Deterministic mutation sweep of the scan-engine functions (SPEC scan-engines 14.1 and 16.1 part M, the method of Executions 17.ag).
 *
 * It applies ONE operator mutation at a time to a source file, IN MEMORY (a module loader hook, `mutation-hook.js`; the working tree is
 * never written), and runs the fast Docker-free, database-free security checks that execute the mutated line (`mutation-worker.js`).
 * A mutant is KILLED when a check fails, TIMEOUT when the run does not end in time (an infinite loop is a kill by the clock, reported
 * apart), SURVIVED when every covering check stays green, INVALID when the mutated source does not compile. Which checks cover which
 * line comes from V8 coverage of each check run alone (`map`), so a survivor is proved against every check that touches its line.
 *
 * Usage (from apps/api):
 *   node scripts/mutation-sweep.js map     [--map-file F]                       build the check coverage map
 *   node scripts/mutation-sweep.js list                                          count candidate mutants per file
 *   node scripts/mutation-sweep.js run     [--map-file F] [--out F] [--per-file N] [--only SUBSTR] [--jobs N] [--seed N]
 *   node scripts/mutation-sweep.js report  [--out F]                             markdown of the survivors grouped by file
 *   node scripts/mutation-sweep.js one --file F --line N [--operator OP] [--only REGEX]
 *                                                                                re-runs every mutant of ONE line against the Docker-free checks
 *                                                                                (or the check ids matching REGEX): the triage tool (MUTATION_BACKLOG.md 4)
 * Deterministic: the same sources and seed give the same mutants. Operators: === and !==, && and ||, comparison boundaries, true and
 * false, a removed negation in a condition, an integer literal plus one, startsWith and endsWith, every and some, min and max, a removed
 * array element line (flag lists), a removed statement call, a removed continue, break or return.
 */
import { spawn } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
  existsSync,
  appendFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const apiDir = path.resolve(here, "..");
const repoRoot = path.resolve(here, "../../..");

/** The new scan-engine code (part M scope). Directories are walked for `.js`; plain files are taken as they are. */
const SCAN_ENGINE_TARGETS = [
  "packages/shared/src/scan-engines",
  "packages/infra/src/sandbox",
  "packages/infra/src/archive",
  "packages/infra/src/dbmirror",
  "apps/workers/src/execution/engines/ensemble",
  "apps/workers/src/dbrefresh",
];

/**
 * The code the sweep mutates. `MUTATION_TARGETS` (comma separated repository-relative files or directories) replaces the scan-engine list,
 * so the same tooling sweeps another module (Findings part F: `MUTATION_GROUP=findings` selects the matching checks in the worker).
 */
export const TARGETS = process.env.MUTATION_TARGETS
  ? process.env.MUTATION_TARGETS.split(",").filter(Boolean)
  : SCAN_ENGINE_TARGETS;

const args = process.argv.slice(2);
const command = args[0] ?? "run";
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : args[i + 1];
};
const SCRATCH = process.env.MUTATION_SCRATCH ?? path.join(os.tmpdir(), "qm-mutation");
mkdirSync(SCRATCH, { recursive: true });
const MAP_FILE = opt("map-file", path.join(SCRATCH, "coverage-map.json"));
const OUT_FILE = opt("out", path.join(SCRATCH, "results.jsonl"));

/** @param {string} dir */
function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) {
      if (
        name === "node_modules" ||
        name === "fixtures" ||
        name === "rules" ||
        name === "extractor-image"
      )
        continue;
      out.push(...walk(full));
    } else if (name.endsWith(".js")) out.push(full);
  }
  return out;
}
const targetFiles = () =>
  TARGETS.flatMap((t) => {
    const full = path.join(repoRoot, t);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });

// ---- seeded generator (mulberry32) ------------------------------------------------------------------------------------------
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---- code mask: 1 where a character is code (not a comment, string, template text or regex literal) ----------------------------
/** @param {string} src @returns {Uint8Array} */
export function codeMask(src) {
  const mask = new Uint8Array(src.length);
  let i = 0;
  let lastSignificant = "";
  const regexAllowedAfter = new Set([
    "",
    "(",
    ",",
    "=",
    ":",
    "[",
    "!",
    "&",
    "|",
    "?",
    "{",
    "}",
    ";",
    "+",
    "-",
    "*",
    "%",
    "<",
    ">",
    "~",
    "^",
  ]);
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (c === "/" && n === "/") {
      while (i < src.length && src[i] !== "\n") i += 1;
      continue;
    }
    if (c === "/" && n === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i += 1;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'") {
      i += 1;
      while (i < src.length && src[i] !== c && src[i] !== "\n") i += src[i] === "\\" ? 2 : 1;
      i += 1;
      lastSignificant = "x";
      continue;
    }
    if (c === "`") {
      i += 1;
      let depth = 0;
      while (i < src.length) {
        if (src[i] === "\\") {
          i += 2;
          continue;
        }
        if (depth === 0 && src[i] === "`") break;
        if (src[i] === "$" && src[i + 1] === "{") {
          depth += 1;
          i += 2;
          continue;
        }
        if (depth > 0 && src[i] === "}") depth -= 1;
        i += 1;
      }
      i += 1;
      lastSignificant = "x";
      continue;
    }
    if (c === "/" && regexAllowedAfter.has(lastSignificant)) {
      i += 1;
      let inClass = false;
      while (i < src.length && src[i] !== "\n") {
        if (src[i] === "\\") i += 2;
        else if (src[i] === "[") ((inClass = true), (i += 1));
        else if (src[i] === "]") ((inClass = false), (i += 1));
        else if (src[i] === "/" && !inClass) break;
        else i += 1;
      }
      i += 1;
      while (/[a-z]/.test(src[i] ?? "")) i += 1;
      lastSignificant = "x";
      continue;
    }
    mask[i] = 1;
    if (!/\s/.test(c)) lastSignificant = /[\w$)\]]/.test(c) ? "x" : c;
    i += 1;
  }
  return mask;
}

const inCode = (mask, from, to) => {
  for (let k = from; k < to; k += 1) if (!mask[k]) return false;
  return true;
};

/**
 * Candidate mutations of one source: `{ offset, length, replacement, operator }` (the text between offset and offset+length is replaced).
 * @param {string} src
 */
export function candidatesOf(src) {
  const mask = codeMask(src);
  const out = [];
  const lineStart = [0];
  for (let k = 0; k < src.length; k += 1) if (src[k] === "\n") lineStart.push(k + 1);
  const lineOf = (offset) => {
    let lo = 0;
    let hi = lineStart.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStart[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  const add = (operator, re, replace) => {
    for (const m of src.matchAll(re)) {
      const text = m[1] ?? m[0];
      const at = m[1] !== undefined ? m.index + m[0].indexOf(m[1]) : m.index;
      if (!inCode(mask, at, at + text.length)) continue;
      const r = replace(text, m);
      if (r === null || r === text) continue;
      out.push({ operator, offset: at, length: text.length, replacement: r, line: lineOf(at) });
    }
  };
  add("eq", /(===|!==)/g, (t) => (t === "===" ? "!==" : "==="));
  add("logic", /(?<![&|])(&&|\|\|)(?![=|&])/g, (t) => (t === "&&" ? "||" : "&&"));
  add("bound", /(?<![<>=!\-+*/%&|^?])(>=|<=)(?!=)/g, (t) => (t === ">=" ? ">" : "<"));
  add("bound", /(?<![<>=!\-+*/%&|^?])(>|<)(?![<>=])/g, (t) => (t === ">" ? ">=" : "<="));
  add("bool", /\b(true|false)\b/g, (t) => (t === "true" ? "false" : "true"));
  add("negation", /\bif \((!)(?!=)/g, () => "");
  add("negation", /(?:&&|\|\|) (!)(?!=)/g, () => "");
  add("int", /(?<![\w.$])([1-9]\d{0,8})(?![\w.])/g, (t) => String(Number(t) + 1));
  add("string-method", /\.(startsWith|endsWith)\(/g, (t) =>
    t === "startsWith" ? "endsWith" : "startsWith",
  );
  add("quantifier", /\.(every|some)\(/g, (t) => (t === "every" ? "some" : "every"));
  add("minmax", /Math\.(min|max)\(/g, (t) => (t === "min" ? "max" : "min"));
  // a removed array element line (flag lists, allowlists): a line that is only a string literal and a comma
  for (const m of src.matchAll(
    /^([ \t]*(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'),[ \t]*)\r?$/gm,
  )) {
    const prevEnd = src.lastIndexOf("\n", m.index - 2);
    const prev = src.slice(prevEnd + 1, m.index).trimEnd();
    if (!/[[,]$/.test(prev)) continue;
    out.push({
      operator: "drop-element",
      offset: m.index,
      length: m[0].length,
      replacement: "",
      line: lineOf(m.index),
    });
  }
  // a removed statement call (a line that is one call ending with `);`)
  for (const m of src.matchAll(/^([ \t]+(?:await )?[A-Za-z_$][\w$.]*\([^\n]*\);)[ \t]*$/gm)) {
    const first = m.index + m[0].search(/\S/);
    if (!mask[first]) continue;
    if (/^\s*(return|throw|const|let|var|export|import)\b/.test(m[1])) continue;
    out.push({
      operator: "drop-call",
      offset: first,
      length: m[1].trim().length,
      replacement: ";",
      line: lineOf(first),
    });
  }
  for (const m of src.matchAll(/^[ \t]+(continue|break);[ \t]*$/gm)) {
    const first = m.index + m[0].search(/\S/);
    if (mask[first])
      out.push({
        operator: "drop-jump",
        offset: first,
        length: m[1].length + 1,
        replacement: ";",
        line: lineOf(first),
      });
  }
  for (const m of src.matchAll(/^[ \t]+(return [^\n;]+;)[ \t]*$/gm)) {
    const first = m.index + m[0].search(/\S/);
    if (!mask[first]) continue;
    const t = m[1];
    if (/^return (true|false);$/.test(t)) continue; // covered by the bool operator
    out.push({
      operator: "return-undefined",
      offset: first,
      length: t.length,
      replacement: "return undefined;",
      line: lineOf(first),
    });
  }
  out.sort((a, b) => a.offset - b.offset || a.operator.localeCompare(b.operator));
  return out;
}

const workerEnvBase = () => ({
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  MUTATION_SCRATCH: SCRATCH,
  ...(process.env.MUTATION_GROUP ? { MUTATION_GROUP: process.env.MUTATION_GROUP } : {}),
});

/** Runs the worker once; resolves `{ code, json, timedOut, ms }`. */
function runWorker({ env = {}, timeoutMs = 600_000, hook = false }) {
  return new Promise((resolve) => {
    const started = Date.now();
    const argv = [
      ...(hook ? ["--import", path.join(here, "mutation-register.js")] : []),
      path.join(here, "mutation-worker.js"),
    ];
    const child = spawn(process.execPath, argv, {
      cwd: apiDir,
      env: { ...workerEnvBase(), ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", () => {});
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ code: null, json: null, timedOut: true, ms: Date.now() - started });
    }, timeoutMs);
    child.on("exit", (code) => {
      clearTimeout(timer);
      const line = stdout
        .trim()
        .split("\n")
        .filter((l) => l.startsWith("{"))
        .pop();
      let json = null;
      try {
        json = line ? JSON.parse(line) : null;
      } catch {
        /* a garbled line is a crash */
      }
      resolve({ code, json, timedOut: false, ms: Date.now() - started });
    });
  });
}

async function pool(items, jobs, fn) {
  let next = 0;
  const workers = Array.from({ length: jobs }, async () => {
    while (next < items.length) {
      const mine = next;
      next += 1;
      await fn(items[mine], mine);
    }
  });
  await Promise.all(workers);
}

// ---- coverage map -----------------------------------------------------------------------------------------------------------
async function buildMap() {
  const listed = await runWorker({ env: { MUTATION_LIST: "1" } });
  const ids = listed.json.ids;
  const files = new Set(targetFiles().map((f) => pathToFileURL(f).href));
  const map = { checks: {} };
  const jobs = Number(opt("jobs", 8));
  await pool(ids, jobs, async (id) => {
    const dir = mkdtempSync(path.join(SCRATCH, "cov-"));
    const r = await runWorker({ env: { MUTATION_ONLY: `^${id}$`, NODE_V8_COVERAGE: dir } });
    const perFile = {};
    for (const name of readdirSync(dir)) {
      const cov = JSON.parse(readFileSync(path.join(dir, name), "utf8"));
      for (const script of cov.result) {
        if (!files.has(script.url)) continue;
        const ranges = [];
        for (const fn of script.functions)
          for (const range of fn.ranges)
            ranges.push([range.startOffset, range.endOffset, range.count]);
        perFile[fileURLToPath(script.url)] = ranges;
      }
    }
    rmSync(dir, { recursive: true, force: true });
    map.checks[id] = { ms: r.ms, ok: r.json?.ok === true, files: perFile };
    process.stdout.write(`${r.json?.ok ? "." : "F"}`);
  });
  writeFileSync(MAP_FILE, JSON.stringify(map));
  const bad = Object.entries(map.checks)
    .filter(([, v]) => !v.ok)
    .map(([k]) => k);
  console.log(`\nmap: ${ids.length} checks, ${bad.length} not green alone ${bad.join(" ")}`);
}

/** The checks whose coverage includes this offset; module-level offsets (the innermost range is the whole module) take every check that loaded the file. */
function coveringChecks(map, file, offset, srcLength) {
  const out = [];
  for (const [id, info] of Object.entries(map.checks)) {
    const ranges = info.files[file];
    if (!ranges) continue;
    let best = null;
    for (const r of ranges) {
      if (r[0] <= offset && offset < r[1] && (best === null || r[1] - r[0] <= best[1] - best[0]))
        best = r;
    }
    if (best === null) continue;
    const moduleLevel = best[0] === 0 && best[1] >= srcLength - 1;
    if (best[2] > 0 || moduleLevel) out.push({ id, ms: info.ms, moduleLevel });
  }
  return out;
}

// ---- run --------------------------------------------------------------------------------------------------------------------
function syntaxOk(source) {
  // a module compiles when `node --check` accepts it; written to a temp file next to nothing (ESM syntax, .mjs)
  const tmp = path.join(SCRATCH, `check-${process.pid}-${Math.random().toString(36).slice(2)}.mjs`);
  writeFileSync(tmp, source);
  return new Promise((resolve) => {
    const c = spawn(process.execPath, ["--check", tmp], { stdio: "ignore" });
    c.on("exit", (code) => {
      rmSync(tmp, { force: true });
      resolve(code === 0);
    });
  });
}

async function run() {
  if (!existsSync(MAP_FILE)) throw new Error(`no coverage map at ${MAP_FILE}; run "map" first`);
  const map = JSON.parse(readFileSync(MAP_FILE, "utf8"));
  const seed = Number(opt("seed", 20261122));
  const perFile = Number(opt("per-file", 12));
  const only = opt("only", "");
  const jobs = Number(opt("jobs", 8));
  const random = rng(seed);
  const mutants = [];
  // `--resume`: keep the results file and skip the files that already have results (a second pass with other caps for the rest)
  const resume = args.includes("--resume");
  const idPrefix = opt("id-prefix", "M");
  const doneFiles = new Set(
    resume && existsSync(OUT_FILE)
      ? readFileSync(OUT_FILE, "utf8")
          .trim()
          .split("\n")
          .filter(Boolean)
          .map((l) => JSON.parse(l).file)
      : [],
  );
  for (const file of targetFiles()) {
    const rel = path.relative(repoRoot, file);
    if (only && !rel.includes(only)) continue;
    if (doneFiles.has(rel)) continue;
    const src = readFileSync(file, "utf8");
    const allCands = candidatesOf(src);
    const cands = allCands.filter(
      (c) => coveringChecks(map, file, c.offset, src.length).length > 0,
    );
    // the uncovered ones are survivors by definition (no check runs the line): sample a few so they appear in the backlog
    const uncoveredCands = allCands.filter((c) => !cands.includes(c));
    const pick = (list, n) => {
      const copy = [...list];
      for (let k = copy.length - 1; k > 0; k -= 1) {
        const j = Math.floor(random() * (k + 1));
        [copy[k], copy[j]] = [copy[j], copy[k]];
      }
      return copy.slice(0, n).sort((a, b) => a.offset - b.offset);
    };
    // spread over the operators: take round-robin by operator so one operator does not take the whole share
    // module-level mutants (a constant, an exported table) are covered by every check that loads the file, so a survivor costs a full run:
    // at most `--module-level` of them per file
    const moduleLevelMax = Number(opt("module-level", 10));
    let moduleLevel = 0;
    const byOp = new Map();
    for (const c of pick(cands, cands.length)) {
      const isModule = coveringChecks(map, file, c.offset, src.length).some((x) => x.moduleLevel);
      if (isModule && (moduleLevel += 1) > moduleLevelMax) continue;
      byOp.set(c.operator, [...(byOp.get(c.operator) ?? []), c]);
    }
    const chosen = [];
    const queues = [...byOp.values()].map((l) => pick(l, l.length));
    while (chosen.length < perFile && queues.some((q) => q.length))
      for (const q of queues) if (q.length && chosen.length < perFile) chosen.push(q.shift());
    for (const c of chosen) mutants.push({ file, rel, src, ...c, covered: true });
    for (const c of pick(uncoveredCands, Math.min(2, uncoveredCands.length)))
      mutants.push({ file, rel, src, ...c, covered: false });
  }
  console.log(
    `mutants: ${mutants.length} (seed ${seed}, up to ${perFile} covered per file, jobs ${jobs})`,
  );
  const killersByFile = new Map();
  let done = 0;
  const tally = { killed: 0, survived: 0, timeout: 0, invalid: 0, uncovered: 0 };
  if (!resume) writeFileSync(OUT_FILE, "");
  await pool(mutants, jobs, async (m, index) => {
    const mutated = m.src.slice(0, m.offset) + m.replacement + m.src.slice(m.offset + m.length);
    const id = `${idPrefix}${String(index + 1).padStart(4, "0")}`;
    const record = {
      id,
      file: m.rel,
      line: m.line,
      operator: m.operator,
      before: m.src.slice(m.offset, m.offset + m.length).slice(0, 90),
      after: m.replacement.slice(0, 90),
      lineText: m.src.split("\n")[m.line - 1].trim().slice(0, 140),
    };
    if (!m.covered) {
      record.result = "survived";
      record.note = "no check executes this line";
      tally.survived += 1;
      tally.uncovered += 1;
    } else if (!(await syntaxOk(mutated, m.file))) {
      record.result = "invalid";
      tally.invalid += 1;
    } else {
      const covering = coveringChecks(map, m.file, m.offset, m.src.length);
      const killers = killersByFile.get(m.file) ?? new Set();
      covering.sort((a, b) => Number(killers.has(b.id)) - Number(killers.has(a.id)) || a.ms - b.ms);
      const sourceFile = path.join(SCRATCH, `mutant-${id}.js`);
      writeFileSync(sourceFile, mutated);
      const total = covering.reduce((s, c) => s + c.ms, 0);
      const r = await runWorker({
        hook: true,
        timeoutMs: Math.min(240_000, 30_000 + total * 1.2),
        env: {
          MUTANT_FILE: m.file,
          MUTANT_SOURCE_FILE: sourceFile,
          MUTATION_ONLY: `^(${covering.map((c) => c.id).join("|")})$`,
          MUTATION_ORDER: covering.map((c) => c.id).join(","),
        },
      });
      rmSync(sourceFile, { force: true });
      record.checks = covering.length;
      record.ms = r.ms;
      if (r.timedOut) {
        record.result = "timeout";
        tally.timeout += 1;
      } else if (r.json?.ok === true) {
        record.result = "survived";
        tally.survived += 1;
      } else {
        record.result = "killed";
        record.killedBy = r.json?.failed ?? `crash (exit ${r.code})`;
        tally.killed += 1;
        if (r.json?.failed) {
          killers.add(r.json.failed);
          killersByFile.set(m.file, killers);
        }
      }
    }
    appendFileSync(OUT_FILE, `${JSON.stringify(record)}\n`);
    done += 1;
    if (done % 25 === 0 || done === mutants.length)
      console.log(
        `[${done}/${mutants.length}] killed ${tally.killed} survived ${tally.survived} (uncovered ${tally.uncovered}) timeout ${tally.timeout} invalid ${tally.invalid}`,
      );
  });
  console.log(JSON.stringify(tally));
}

// ---- http: the SBOM download route and its data function, run against the real suite (in place, one at a time) -----------------------
/** Windows of the sources of the repository SBOM download (SPEC scan-engines 17.r): `[file, first marker, last marker]`. */
const HTTP_WINDOWS = [
  ["apps/api/src/modules/repositories/mappers/index.js", "export function sbomFileName", "\n}\n"],
  [
    "apps/api/src/modules/repositories/services/index.js",
    "async sbom(actor, repo",
    "async update(actor, repo",
  ],
  [
    "apps/api/src/modules/repositories/controllers/index.js",
    "sbom: async (request, reply)",
    "update: async",
  ],
  ["apps/api/src/modules/repositories/schemas/index.js", "export const sbomQuerySchema", "\n"],
  ["packages/db/src/executions/artifacts.js", "async findLatestSbomDocument(", "async head("],
];
/** Hand-written mutants of the route and schema declarations (no operator reaches a string argument): `[file, find, replace, label]`. */
const HTTP_MANUAL = [
  [
    "apps/api/src/modules/repositories/schemas/index.js",
    "pipelineId: z.string().uuid().optional() }).strict()",
    "pipelineId: z.string().uuid().optional() })",
    "sbom query not strict",
  ],
  [
    "apps/api/src/modules/repositories/schemas/index.js",
    "pipelineId: z.string().uuid().optional()",
    "pipelineId: z.string().optional()",
    "sbom pipelineId not a uuid",
  ],
  [
    "apps/api/src/modules/repositories/routes/index.js",
    '"/repositories/:repositoryId/sbom",\n      {\n        config,\n        rateLimit: "read",\n        preHandler: onRepository("repository.view"),',
    '"/repositories/:repositoryId/sbom",\n      {\n        config,\n        rateLimit: "read",',
    "sbom route without its permission",
  ],
  [
    "apps/api/src/modules/repositories/routes/index.js",
    '"/repositories/:repositoryId/sbom",\n      {\n        config,\n        rateLimit: "read",',
    '"/repositories/:repositoryId/sbom",\n      {\n        config,',
    "sbom route without rate limit",
  ],
  [
    "apps/api/src/modules/repositories/controllers/index.js",
    '"Cache-Control": "private, no-store"',
    '"Cache-Control": "public"',
    "sbom cache header public",
  ],
  [
    "apps/api/src/modules/repositories/controllers/index.js",
    '"X-Content-Type-Options": "nosniff",',
    "",
    "sbom nosniff removed",
  ],
];

async function http() {
  const { execFileSync } = await import("node:child_process");
  const jobs = [];
  for (const [rel, startMark, endMark] of HTTP_WINDOWS) {
    const file = path.join(repoRoot, rel);
    const src = readFileSync(file, "utf8");
    const from = src.indexOf(startMark);
    const to = src.indexOf(endMark, from + startMark.length);
    if (from === -1 || to === -1) throw new Error(`window not found in ${rel}`);
    for (const c of candidatesOf(src))
      if (c.offset >= from && c.offset < to) jobs.push({ file, rel, src, ...c });
  }
  for (const [rel, find, replace, label] of HTTP_MANUAL) {
    const file = path.join(repoRoot, rel);
    const src = readFileSync(file, "utf8");
    const at = src.indexOf(find);
    if (at === -1) throw new Error(`manual mutant not found: ${label}`);
    jobs.push({
      file,
      rel,
      src,
      offset: at,
      length: find.length,
      replacement: replace,
      operator: "manual",
      line: src.slice(0, at).split("\n").length,
      label,
    });
  }
  const limit = opt("limit", "");
  const include = opt("only", "");
  const exclude = opt("exclude", "");
  const filtered = jobs.filter(
    (j) => (!include || j.rel.includes(include)) && (!exclude || !j.rel.includes(exclude)),
  );
  const list = limit ? filtered.slice(0, Number(limit)) : filtered;
  console.log(`http mutants: ${list.length}`);
  writeFileSync(OUT_FILE, "");
  const tally = {};
  let n = 0;
  /** the one file that is mutated right now, restored on any exit (the working tree is never left mutated) */
  let active = null;
  const restore = () => {
    if (active) writeFileSync(active.file, active.src);
    active = null;
  };
  process.on("exit", restore);
  for (const signal of ["SIGINT", "SIGTERM"])
    process.on(signal, () => {
      restore();
      process.exit(130);
    });
  for (const m of list) {
    n += 1;
    const mutated = m.src.slice(0, m.offset) + m.replacement + m.src.slice(m.offset + m.length);
    const record = {
      id: `H${String(n).padStart(3, "0")}`,
      file: m.rel,
      line: m.line,
      operator: m.operator,
      before: (m.label ?? m.src.slice(m.offset, m.offset + m.length)).slice(0, 90),
      after: m.replacement.slice(0, 90),
      lineText: m.src.split("\n")[m.line - 1].trim().slice(0, 140),
    };
    if (!(await syntaxOk(mutated, m.file))) {
      record.result = "invalid";
    } else {
      active = { file: m.file, src: m.src };
      writeFileSync(m.file, mutated);
      try {
        execFileSync(process.execPath, [path.join(here, "security-suite.js")], {
          cwd: apiDir,
          env: { ...process.env, SECURITY_SUITE_ONLY: "ENG-S08i|DAL-317" },
          stdio: "ignore",
          timeout: 240_000,
        });
        record.result = "survived";
      } catch (error) {
        record.result = error.status === 2 ? "invalid" : error.signal ? "timeout" : "killed";
      } finally {
        restore();
      }
    }
    tally[record.result] = (tally[record.result] ?? 0) + 1;
    appendFileSync(OUT_FILE, `${JSON.stringify(record)}\n`);
    console.log(`${record.id} ${record.result} ${record.file}:${record.line} ${record.operator}`);
  }
  console.log(JSON.stringify(tally));
}

/**
 * `rerun --files SUBSTR --filter PATTERN --out RESULTS`: the survivors of the Docker-free pass whose file is covered by checks that need the
 * database or the HTTP API are applied again IN PLACE, one at a time, against the real suite filtered by PATTERN (`SECURITY_SUITE_ONLY`).
 * The outcome is appended to `RESULTS.rerun.jsonl`; `report` reads it and reclassifies a killed survivor.
 */
async function rerun() {
  const { execFileSync } = await import("node:child_process");
  const files = opt("files", "");
  const filter = opt("filter", "ENG-S12");
  const rows = readFileSync(OUT_FILE, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const todo = rows.filter((r) => r.result === "survived" && r.file.includes(files));
  const out = `${OUT_FILE}.rerun.jsonl`;
  console.log(`rerun: ${todo.length} survivors against ${filter}`);
  let active = null;
  const restore = () => {
    if (active) writeFileSync(active.file, active.src);
    active = null;
  };
  process.on("exit", restore);
  for (const signal of ["SIGINT", "SIGTERM"])
    process.on(signal, () => {
      restore();
      process.exit(130);
    });
  for (const rec of todo) {
    const file = path.join(repoRoot, rec.file);
    const src = readFileSync(file, "utf8");
    const c = candidatesOf(src).find(
      (x) =>
        x.line === rec.line &&
        x.operator === rec.operator &&
        src.slice(x.offset, x.offset + x.length).slice(0, 90) === rec.before,
    );
    let result = "not_found";
    if (c) {
      const mutated = src.slice(0, c.offset) + c.replacement + src.slice(c.offset + c.length);
      if (!(await syntaxOk(mutated, file))) result = "invalid";
      else {
        active = { file, src };
        writeFileSync(file, mutated);
        try {
          execFileSync(process.execPath, [path.join(here, "security-suite.js")], {
            cwd: apiDir,
            env: { ...process.env, SECURITY_SUITE_ONLY: filter },
            stdio: "ignore",
            timeout: 300_000,
          });
          result = "survived";
        } catch (error) {
          result = error.status === 2 ? "invalid" : error.signal ? "timeout" : "killed";
        } finally {
          restore();
        }
      }
    }
    appendFileSync(
      out,
      `${JSON.stringify({ id: rec.id, file: rec.file, line: rec.line, result, filter })}\n`,
    );
    console.log(`${rec.id} ${result} ${rec.file}:${rec.line}`);
  }
}

/**
 * `dbsweep --files SUBSTR --filter PATTERN --count N`: a sample of mutants of files whose checks need the database (the DB refresh worker),
 * applied IN PLACE one at a time against the real suite filtered by PATTERN. Appended to the results file with ids `D0001`.
 */
async function dbsweep() {
  const { execFileSync } = await import("node:child_process");
  const filter = opt("filter", "ENG-S12");
  const count = Number(opt("count", 25));
  const random = rng(Number(opt("seed", 20261122)));
  const todo = [];
  for (const file of targetFiles()) {
    const rel = path.relative(repoRoot, file);
    if (!rel.includes(opt("files", "dbrefresh/refresh"))) continue;
    const src = readFileSync(file, "utf8");
    const all = candidatesOf(src);
    const picked = [...all]
      .sort(() => random() - 0.5)
      .slice(0, count)
      .sort((a, b) => a.offset - b.offset);
    for (const c of picked) todo.push({ file, rel, src, ...c });
  }
  console.log(`dbsweep: ${todo.length} mutants against ${filter}`);
  let active = null;
  const restore = () => {
    if (active) writeFileSync(active.file, active.src);
    active = null;
  };
  process.on("exit", restore);
  for (const signal of ["SIGINT", "SIGTERM"])
    process.on(signal, () => {
      restore();
      process.exit(130);
    });
  let n = 0;
  for (const m of todo) {
    n += 1;
    const mutated = m.src.slice(0, m.offset) + m.replacement + m.src.slice(m.offset + m.length);
    const record = {
      id: `D${String(n).padStart(4, "0")}`,
      file: m.rel,
      line: m.line,
      operator: m.operator,
      before: m.src.slice(m.offset, m.offset + m.length).slice(0, 90),
      after: m.replacement.slice(0, 90),
      lineText: m.src.split("\n")[m.line - 1].trim().slice(0, 140),
    };
    if (!(await syntaxOk(mutated, m.file))) record.result = "invalid";
    else {
      active = { file: m.file, src: m.src };
      writeFileSync(m.file, mutated);
      try {
        execFileSync(process.execPath, [path.join(here, "security-suite.js")], {
          cwd: apiDir,
          env: { ...process.env, SECURITY_SUITE_ONLY: filter },
          stdio: "ignore",
          timeout: 300_000,
        });
        record.result = "survived";
      } catch (error) {
        record.result = error.status === 2 ? "invalid" : error.signal ? "timeout" : "killed";
        if (record.result === "killed") record.killedBy = `database checks ${filter}`;
      } finally {
        restore();
      }
    }
    appendFileSync(OUT_FILE, `${JSON.stringify(record)}\n`);
    console.log(`${record.id} ${record.result} ${record.file}:${record.line} ${record.operator}`);
  }
}

/**
 * `confirm --by ID,ID --out RESULTS`: kills attributed to a check that is sensitive to machine load (capacity timers, event loop slices,
 * heap and time guards) are run AGAIN one at a time with the whole covering list, so a kill that only came from a loaded machine is
 * found. The outcome is appended to `RESULTS.confirm.jsonl` (`confirmed` or `not_confirmed` plus the check that now fails).
 */
async function confirm() {
  const by = new Set(
    opt(
      "by",
      "ENG-S14a,ENG-S14b,ENG-S17a,ENG-S17b,ENG-S17c,ENG-S02a,ENG-S09d,ENG-S10a,ENG-S10b,ENG-S10c",
    ).split(","),
  );
  const map = JSON.parse(readFileSync(MAP_FILE, "utf8"));
  const rows = readFileSync(OUT_FILE, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const todo = rows.filter((r) => r.result === "killed" && by.has(r.killedBy));
  const out = `${OUT_FILE}.confirm.jsonl`;
  console.log(`confirm: ${todo.length} kills attributed to ${[...by].join(" ")}`);
  const jobs = Number(opt("jobs", 2));
  await pool(todo, jobs, async (rec) => {
    const file = path.join(repoRoot, rec.file);
    const src = readFileSync(file, "utf8");
    const c = candidatesOf(src).find(
      (x) =>
        x.line === rec.line &&
        x.operator === rec.operator &&
        src.slice(x.offset, x.offset + x.length).slice(0, 90) === rec.before,
    );
    let result = "not_found";
    let failed = null;
    if (c) {
      const sourceFile = path.join(SCRATCH, `confirm-${rec.id}.js`);
      writeFileSync(
        sourceFile,
        src.slice(0, c.offset) + c.replacement + src.slice(c.offset + c.length),
      );
      const covering = coveringChecks(map, file, c.offset, src.length).map((x) => x.id);
      const r = await runWorker({
        hook: true,
        timeoutMs: 400_000,
        env: {
          MUTANT_FILE: file,
          MUTANT_SOURCE_FILE: sourceFile,
          MUTATION_ONLY: `^(${covering.join("|")})$`,
          MUTATION_ORDER: [rec.killedBy, ...covering].join(","),
        },
      });
      rmSync(sourceFile, { force: true });
      result = r.timedOut || r.json?.ok === false ? "confirmed" : "not_confirmed";
      failed = r.json?.failed ?? (r.timedOut ? "timeout" : null);
    }
    appendFileSync(
      out,
      `${JSON.stringify({ id: rec.id, file: rec.file, line: rec.line, was: rec.killedBy, result, failed })}\n`,
    );
    console.log(`${rec.id} ${result} (was ${rec.killedBy}, now ${failed})`);
  });
}

function report() {
  const rows = readFileSync(OUT_FILE, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const rerunFile = `${OUT_FILE}.rerun.jsonl`;
  if (existsSync(rerunFile)) {
    const reran = new Map(
      readFileSync(rerunFile, "utf8")
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((l) => [JSON.parse(l).id, JSON.parse(l)]),
    );
    for (const r of rows) {
      const x = reran.get(r.id);
      if (x && x.result === "killed")
        ((r.result = "killed"), (r.killedBy = `database checks ${x.filter}`));
    }
  }
  // survivors killed AFTER the sweep by checks added in part M (each one re-run with the hook and verified): `[file suffix, line, operator, check]`
  const ADDED_KILLS = [
    ["sandbox/build-run-args.js", 160, "drop-call", "ENG-S01c"],
    ["sandbox/config.js", 41, "drop-element", "ENG-S01c"],
    ["sandbox/config.js", 42, "drop-element", "ENG-S01c"],
    ["sandbox/cli-runtime.js", 139, "drop-call", "ENG-S03l"],
    ["dbmirror/sources.js", 38, "drop-element", "ENG-S07d"],
    ["dbmirror/sources.js", 39, "drop-element", "ENG-S07d"],
    ["dbmirror/sources.js", 40, "drop-element", "ENG-S07d"],
    ["archive/tree.js", 40, "logic", "ENG-S07d"],
    ["sast/plan.js", 58, "quantifier", "ENG-S03m"],
    ["evidence/permalink.js", 100, "string-method", "ENG-S13f"],
    ["evidence/mask.js", 47, "logic", "ENG-S13f"],
    ["evidence/mask.js", 47, "bound", "ENG-S13f"],
    ["evidence/mask.js", 47, "bool", "ENG-S13f"],
    ["evidence/mask.js", 48, "bool", "ENG-S13f"],
    ["evidence/mask.js", 52, "return-undefined", "ENG-S13f"],
  ];
  for (const r of rows)
    if (r.result === "survived") {
      const hit = ADDED_KILLS.find(
        ([f, l, o]) => r.file.endsWith(f) && r.line === l && r.operator === o,
      );
      if (hit)
        ((r.result = "killed"),
          (r.killedBy = `${hit[3]} (added in part M after the sweep)`),
          (r.addedKill = true));
    }
  const confirmFile = `${OUT_FILE}.confirm.jsonl`;
  if (existsSync(confirmFile)) {
    for (const l of readFileSync(confirmFile, "utf8").trim().split("\n").filter(Boolean)) {
      const x = JSON.parse(l);
      const r = rows.find((y) => y.id === x.id);
      if (r && x.result === "not_confirmed")
        ((r.result = "survived"), (r.note = "killed only under load (not confirmed serially)"));
    }
  }
  const byFile = new Map();
  for (const r of rows) byFile.set(r.file, [...(byFile.get(r.file) ?? []), r]);
  const lines = [];
  const total = {};
  for (const r of rows) total[r.result] = (total[r.result] ?? 0) + 1;
  lines.push(
    `<!-- totals: ${JSON.stringify(total)}, added kills ${rows.filter((r) => r.addedKill).length} -->`,
    "",
  );
  lines.push(
    "| File | Mutants | Killed | Survived | Timeout | Invalid |",
    "|---|---|---|---|---|---|",
  );
  for (const [file, list] of [...byFile].sort()) {
    const n = (res) => list.filter((r) => r.result === res).length;
    lines.push(
      `| \`${file}\` | ${list.length} | ${n("killed")} | ${n("survived")} | ${n("timeout")} | ${n("invalid")} |`,
    );
  }
  lines.push("");
  for (const [file, list] of [...byFile].sort()) {
    const count = (res) => list.filter((r) => r.result === res).length;
    const survivors = list.filter((r) => r.result === "survived").sort((a, b) => a.line - b.line);
    lines.push(
      `### ${file}`,
      "",
      `killed ${count("killed")}, survived ${survivors.length}, timeout ${count("timeout")}, invalid ${count("invalid")}`,
      "",
    );
    for (const s of survivors)
      lines.push(
        `- \`${s.id}\` line ${s.line} ${s.operator}${s.note ? " (not executed by any Docker-free check)" : ""}: \`${s.before.replace(/`/g, "'")}\` -> \`${s.after.replace(/`/g, "'") || "(removed)"}\` in \`${s.lineText.replace(/`/g, "'")}\``,
      );
    lines.push("");
  }
  console.log(lines.join("\n"));
}

/**
 * Triage helper (MUTATION_BACKLOG.md section 4): applies, one at a time and IN MEMORY, every mutant of one source line and prints the
 * verdict of each against the Docker-free checks (all of them, or the check ids matching `--only`). The working tree is never written.
 */
async function one() {
  const file = path.resolve(repoRoot, opt("file", ""));
  const line = Number(opt("line", "0"));
  const operator = opt("operator", null);
  const only = opt("only", null);
  const src = readFileSync(file, "utf8");
  const wanted = candidatesOf(src).filter(
    (c) => c.line === line && (operator === null || c.operator === operator),
  );
  if (wanted.length === 0) console.log("no mutant on that line");
  for (const [i, c] of wanted.entries()) {
    const mutated = src.slice(0, c.offset) + c.replacement + src.slice(c.offset + c.length);
    const before = src.slice(c.offset, c.offset + c.length).trim();
    const label = `${i} ${c.operator} \`${before}\` -> \`${c.replacement.trim() || "(removed)"}\``;
    if (!(await syntaxOk(mutated))) {
      console.log(`${label}: invalid`);
      continue;
    }
    const sourceFile = path.join(SCRATCH, `one-${process.pid}-${i}.js`);
    writeFileSync(sourceFile, mutated);
    const r = await runWorker({
      hook: true,
      env: {
        MUTANT_FILE: file,
        MUTANT_SOURCE_FILE: sourceFile,
        ...(only ? { MUTATION_ONLY: only } : {}),
      },
    });
    rmSync(sourceFile, { force: true });
    console.log(
      `${label}: ${r.timedOut ? "timeout" : r.json?.ok === true ? "SURVIVED" : `killed by ${r.json?.failed ?? "a crash"}`}`,
    );
  }
}

if (command === "map") await buildMap();
else if (command === "list") {
  let total = 0;
  for (const file of targetFiles()) {
    const n = candidatesOf(readFileSync(file, "utf8")).length;
    total += n;
    console.log(`${String(n).padStart(5)} ${path.relative(repoRoot, file)}`);
  }
  console.log(`${total} candidates in ${targetFiles().length} files`);
} else if (command === "run") await run();
else if (command === "http") await http();
else if (command === "rerun") await rerun();
else if (command === "confirm") await confirm();
else if (command === "dbsweep") await dbsweep();
else if (command === "report") report();
else if (command === "one") await one();
else throw new Error(`unknown command ${command}`);
