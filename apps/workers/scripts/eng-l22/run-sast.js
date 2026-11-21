/**
 * ENG-L22 live SAST run (docs/modules/scan-engines/ENG_L22_RUNBOOK.md). RUN BY THE OWNER on a Docker machine; nothing in the security
 * suite or the build runs it. It takes an extracted tree, runs the SEALED SAST command lines of the two adapters (Opengrep with the platform
 * rule pack, Bandit) through the REAL `buildRunArgs` (so the sandbox flags are the production ones), and prints what the real adapters, the
 * real merger and the real roll-up make of the output. It also runs three experiments on the same tree: (1) hostile repository
 * configuration and inline suppressions planted (`.semgrepignore`, `.gitignore`, `.semgrep.yml`, `.opengrep/`, `.bandit`, `setup.cfg`,
 * `pyproject.toml`, `nosemgrep` and `nosec` comments: the findings must NOT change), (2) explicit file targets of the changed files
 * (SPEC 5.9: the findings of those files must equal the full run's findings in the same files), (3) the elapsed time of each tool.
 *
 *   node run-sast.js --work <dir> --tree <dir> [--runtime docker|podman] [--opengrep-local <repo@sha256:digest>]
 *
 * `--work` must be under /tmp (the sandbox policy forbids home paths) and `--tree` must be inside it. No network is used by the tools
 * (`--network=none`); the script itself never uses the network, reads no token and prints no environment. The Opengrep image is
 * OWN-BUILT (SPEC D-14) and has no registry digest until it is pushed to the mirror registry: on a development machine pass the
 * locally built image by its digest reference with `--opengrep-local` (for example `qm-spike-opengrep@sha256:<image id>`, which
 * the containerd image store accepts); this affects THIS script only, never the worker.
 */
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildRunArgs,
  createImageResolver,
  resolveRunSpecImage,
  validateSandboxConfig,
} from "@qmentisai/infra";
import {
  applicability,
  createBanditAdapter,
  createOpengrepAdapter,
  runSastEnsemble,
  walkSourceTree,
} from "../../src/execution/engines/ensemble/sast/index.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RULES_SRC = path.resolve(HERE, "../../src/execution/engines/ensemble/sbom/rules");
const LOCK = path.resolve(HERE, "../../src/execution/engines/ensemble/catalog/images.lock.json");
const STDOUT_CAP = 64 * 1024 * 1024;
const TASK = "00000000-0000-4000-8000-0000000000f1";

const die = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(2);
};

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (!argv[i].startsWith("--")) die(`unexpected argument ${argv[i]}`);
    out[argv[i].slice(2)] = argv[i + 1];
    i += 1;
  }
  return out;
}

const within = (parent, child) => child === parent || child.startsWith(`${parent}/`);

function runOne(runtime, args, outDir, id, wallSeconds) {
  return new Promise((resolve) => {
    const started = Date.now();
    const chunks = [];
    const errs = [];
    let bytes = 0;
    const child = spawn(runtime, args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env.PATH },
    });
    const timer = setTimeout(() => child.kill("SIGKILL"), wallSeconds * 1000);
    child.stdout.on("data", (c) => {
      bytes += c.length;
      if (bytes <= STDOUT_CAP) chunks.push(c);
    });
    child.stderr.on("data", (c) => errs.push(c));
    child.on("close", (code) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(chunks);
      writeFileSync(path.join(outDir, `${id}.stdout`), stdout, { mode: 0o600 });
      writeFileSync(path.join(outDir, `${id}.stderr`), Buffer.concat(errs), { mode: 0o600 });
      resolve({ exitCode: code, wallMs: Date.now() - started, stdout });
    });
  });
}

/** Runs both tools over `tree` (whole tree, or `targets` for an incremental run) and returns the pure ensemble result. */
async function scan({ runtime, tree, rulesDir, outDir, config, resolver, label, targets }) {
  const inventory = await walkSourceTree(tree);
  const app = applicability(inventory);
  const runs = [];
  const timing = {};
  for (const adapter of [createOpengrepAdapter(), createBanditAdapter()]) {
    if (!app.applicable[adapter.toolId]) {
      runs.push({ toolId: adapter.toolId, status: "skipped", reason: "no_applicable_files" });
      continue;
    }
    const mine = targets?.[adapter.toolId];
    if (mine && mine.length === 0) {
      runs.push({ toolId: adapter.toolId, status: "skipped", reason: "no_applicable_files" });
      continue;
    }
    const plan = adapter.plan({
      tenantId: "00000000-0000-4000-8000-0000000000f2",
      executionId: "00000000-0000-4000-8000-0000000000f3",
      taskId: `${TASK.slice(0, -2)}${label.length.toString(16).padStart(2, "0")}`,
      attempt: 1,
      deadlineEpoch: Math.floor(Date.now() / 1000) + 900,
      archiveDir: tree,
      rulesDir,
      ...(mine ? { targets: mine } : {}),
    });
    const spec = resolveRunSpecImage(
      {
        toolId: plan.toolId,
        imageKey: plan.imageKey,
        argv: plan.argv,
        ...(plan.paths ? { paths: plan.paths } : {}),
        mounts: plan.mounts,
        env: plan.env,
        limits: plan.limits,
        labels: plan.labels,
      },
      resolver,
      { scanType: "sast" },
    );
    const args = buildRunArgs(spec, config);
    process.stdout.write(`running ${label}/${adapter.toolId} ... `);
    const r = await runOne(
      runtime,
      args,
      outDir,
      `${label}-${adapter.toolId}`,
      plan.limits.wallClockSeconds,
    );
    process.stdout.write(`exit ${r.exitCode} in ${r.wallMs} ms\n`);
    timing[adapter.toolId] = r.wallMs;
    runs.push({
      adapter,
      streams: { stdout: r.stdout, exitCode: r.exitCode },
      ctx: {
        toolRunId: `00000000-0000-4000-8000-0000000000${adapter.toolId === "opengrep" ? "a1" : "a2"}`,
        toolVersion: "live",
        imageDigest: spec.image.slice(spec.image.indexOf("@") + 1),
      },
    });
  }
  const result = runSastEnsemble({
    taskRef: TASK,
    runs,
    relevantFilesExist: app.relevantFilesExist,
    coverageGaps: app.gaps,
  });
  return { ...result, timing, languages: app.languages, gaps: app.gaps };
}

const summary = (label, result) => {
  process.stdout.write(`\n== ${label}\n`);
  for (const o of result.outcomes)
    process.stdout.write(
      `   ${o.toolId.padEnd(10)} ${o.status}${o.reason ? `/${o.reason}` : ""}  records ${o.recordsSeen ?? 0}, dropped ${o.recordsDropped ?? 0}, findings ${o.findingsMapped ?? 0}, file errors ${o.fileErrors ?? 0}\n`,
    );
  const both = result.findings.filter((f) => f.provenance.length > 1).length;
  process.stdout.write(
    `   languages ${JSON.stringify(result.languages)} gaps ${JSON.stringify(result.gaps)}\n   merged findings ${result.findings.length} (both tools ${both}, one tool ${result.findings.length - both}); roll-up row ${result.rollup.matchedRow}, ${result.rollup.completeness}\n`,
  );
  const sev = {};
  for (const f of result.findings) sev[f.severity] = (sev[f.severity] ?? 0) + 1;
  process.stdout.write(
    `   severities ${JSON.stringify(sev)}; time ${JSON.stringify(result.timing)}\n`,
  );
};

/** Plants hostile repository configuration and inline suppressions in a copy of the tree. */
function plant(dest) {
  const w = (name, text) => {
    mkdirSync(path.dirname(path.join(dest, name)), { recursive: true });
    writeFileSync(path.join(dest, name), text);
  };
  w(".semgrepignore", "*\n");
  w(".gitignore", "*\n");
  w(".semgrep.yml", "rules: []\n");
  w(".opengrep/rules.yml", "rules: []\n");
  w(".semgrep/rules.yml", "rules: []\n");
  w("semgrep.yml", "rules: []\n");
  w(".gitattributes", "* -diff\n");
  w(
    ".bandit",
    "[bandit]\nskips = B101,B102,B103,B104,B105,B106,B107,B108,B110,B112,B201,B301,B302,B303,B304,B305,B306,B307,B308,B310,B311,B312,B313,B314,B315,B316,B317,B318,B319,B320,B321,B323,B324,B325,B401,B402,B403,B404,B405,B406,B407,B408,B409,B410,B411,B412,B413,B501,B502,B503,B504,B505,B506,B507,B601,B602,B603,B604,B605,B606,B607,B608,B609,B610,B611,B701,B702,B703\n",
  );
  w("setup.cfg", "[bandit]\nskips = B602,B605,B608\n");
  w("pyproject.toml", '[tool.bandit]\nskips = ["B602","B605","B608"]\n');
  w("bandit.yaml", "skips: [B602, B605, B608]\n");
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name !== ".git") walk(p);
      } else if (/\.(js|jsx|ts|tsx|mjs|cjs|py|go)$/.test(e.name)) {
        const mark = e.name.endsWith(".py") ? "# nosec nosemgrep" : "// nosemgrep";
        const lines = readFileSync(p, "utf8").split("\n");
        writeFileSync(
          p,
          lines
            .map((l) => (l.trim() === "" || l.includes("nosemgrep") ? l : `${l}  ${mark}`))
            .join("\n"),
        );
      }
    }
  };
  walk(dest);
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  for (const k of ["work", "tree"]) if (!o[k]) die(`--${k} is required`);
  const work = path.resolve(o.work);
  if (!work.startsWith("/tmp/")) die("--work must be a directory under /tmp");
  const tree = path.resolve(o.tree);
  if (!within(work, tree) || !existsSync(tree))
    die("--tree must be an existing directory inside --work");
  const runtime = o.runtime ?? "docker";
  const rulesDir = path.join(work, "rules");
  mkdirSync(rulesDir, { recursive: true, mode: 0o755 });
  cpSync(RULES_SRC, rulesDir, { recursive: true });
  const outDir = path.join(work, "out-sast");
  mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const config = validateSandboxConfig({
    runtimeBin: runtime,
    containerUser: "65534:65534",
    usernsMode: null,
    mountRoots: { archive: [work], db: [work], rules: [work] },
    egressNetworks: {},
  });
  const lock = JSON.parse(readFileSync(LOCK, "utf8"));
  if (o["opengrep-local"]) {
    const m = /^([a-z0-9._/-]+)@(sha256:[0-9a-f]{64})$/.exec(o["opengrep-local"]);
    if (!m) die("--opengrep-local must be <repository>@sha256:<64 hex>");
    const entry = lock.images.find((i) => i.key === "opengrep");
    entry.repository = m[1];
    entry.digest = m[2];
    entry.flags = entry.flags.filter((f) => f !== "local_build_requires_registry_digest");
  }
  const resolver = createImageResolver(lock, { production: false });
  const common = { runtime, rulesDir, outDir, config, resolver };

  const clean = await scan({ ...common, tree, label: "clean" });
  summary("clean tree (whole tree)", clean);

  const planted = path.join(work, "trees-planted");
  cpSync(tree, planted, { recursive: true });
  plant(planted);
  const hostile = await scan({ ...common, tree: planted, label: "planted" });
  summary("planted configuration and suppressions (must equal the clean tree)", hostile);

  // explicit targets: the changed files of the tree that have at least one finding
  const first = [...new Set(clean.findings.map((f) => f.location.path))].slice(0, 2).sort();
  const targets = {
    opengrep: first,
    bandit: first.filter((p) => p.endsWith(".py")),
  };
  const scoped = await scan({ ...common, tree, label: "targets", targets });
  summary(`explicit targets (${first.join(", ")})`, scoped);

  const key = (r) =>
    JSON.stringify(r.findings.map((f) => [f.dedupKey, f.location?.path, f.severity]).sort());
  const inFiles = (r) => ({
    ...r,
    findings: r.findings.filter((f) => first.includes(f.location.path)),
  });
  const checks = [
    [
      "clean: Opengrep succeeded",
      clean.outcomes.find((x) => x.toolId === "opengrep")?.status !== "failed",
    ],
    ["clean: nothing dropped", clean.outcomes.every((x) => (x.recordsDropped ?? 0) === 0)],
    ["planted: the same findings as the clean tree", key(clean) === key(hostile)],
    [
      "targets: the same findings as the full run in those files",
      key(scoped) === key(inFiles(clean)),
    ],
  ];
  process.stdout.write("\n");
  let bad = 0;
  for (const [name, passed] of checks) {
    process.stdout.write(`${passed ? "PASS" : "FAIL"}  ${name}\n`);
    if (!passed) bad += 1;
  }
  writeFileSync(
    path.join(outDir, "summary.json"),
    JSON.stringify(
      { clean: clean.stats, planted: hostile.stats, targets: scoped.stats, checks },
      null,
      2,
    ),
  );
  process.exit(bad === 0 ? 0 : 1);
}

main().catch((error) => die(`failed: ${error?.message ?? error}`));
