/**
 * ENG-L21 live SCA run (docs/modules/scan-engines/ENG_L21_RUNBOOK.md). RUN BY THE OWNER on a Docker machine; nothing in the security
 * suite or the build runs it. It takes an extracted tree and the two vulnerability database directories (the layout the Part F mirror
 * materializes: `trivy/db/trivy.db` + `metadata.json`, `osv-scanner/osv-scalibr/<npm|PyPI|Go|Maven>/all.zip`), runs the SEALED SCA
 * command lines of the two adapters through the REAL `buildRunArgs` (so the sandbox flags are the production ones) and prints what the
 * real adapters, the real merger and the real roll-up make of the output. It also runs the planted-configuration experiment (the same
 * tree plus a hostile `.trivyignore`, `trivy.yaml` and `osv-scanner.toml`: the findings must not change).
 *
 *   node run-sca.js --work <dir> --tree <dir> --trivy-db <dir> --osv-db <dir> [--runtime docker|podman]
 *
 * `--work` must be under /tmp (the sandbox policy forbids home paths); `--tree`, `--trivy-db` and `--osv-db` must be inside it. No network
 * is used by the tools (`--network=none`); the script itself never uses the network, reads no token and prints no environment.
 */
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildRunArgs, resolveRunSpecImage, validateSandboxConfig } from "@qmentisai/infra";
import { loadImageLock } from "../../src/execution/engines/ensemble/catalog/index.js";
import { runScaEnsemble } from "../../src/execution/engines/ensemble/sca/index.js";
import {
  createOsvScannerAdapter,
  createTrivyScaAdapter,
} from "../../src/execution/engines/ensemble/sca/index.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RULES_SRC = path.resolve(HERE, "../../src/execution/engines/ensemble/sbom/rules");
const STDOUT_CAP = 64 * 1024 * 1024;
const TASK = "00000000-0000-4000-8000-0000000000e1";

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

async function scan({ runtime, tree, trivyDb, osvDb, rulesDir, outDir, label, config, resolver }) {
  const adapters = [
    { adapter: createTrivyScaAdapter(), db: trivyDb },
    { adapter: createOsvScannerAdapter(), db: osvDb },
  ];
  const runs = [];
  for (const { adapter, db } of adapters) {
    const plan = adapter.plan({
      tenantId: "00000000-0000-4000-8000-0000000000e2",
      executionId: "00000000-0000-4000-8000-0000000000e3",
      taskId: `${TASK.slice(0, -2)}${label === "clean" ? "e1" : "e4"}`,
      attempt: 1,
      deadlineEpoch: Math.floor(Date.now() / 1000) + 600,
      archiveDir: tree,
      rulesDir,
      dbDir: db,
    });
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
    const version = spec.image.slice(spec.image.indexOf("@") + 1);
    runs.push({
      adapter,
      streams: { stdout: r.stdout, exitCode: r.exitCode },
      ctx: {
        toolRunId: `00000000-0000-4000-8000-0000000000${adapter.toolId === "trivy" ? "a1" : "a2"}`,
        toolVersion: "live",
        imageDigest: version,
      },
      wallMs: r.wallMs,
    });
  }
  return runScaEnsemble({ taskRef: TASK, runs });
}

const summary = (label, result) => {
  process.stdout.write(`\n== ${label}\n`);
  for (const o of result.outcomes)
    process.stdout.write(
      `   ${o.toolId.padEnd(12)} ${o.status}${o.reason ? `/${o.reason}` : ""}  records ${o.recordsSeen}, dropped ${o.recordsDropped}, findings ${o.findingsMapped}\n`,
    );
  const both = result.findings.filter((f) => f.provenance.length > 1).length;
  process.stdout.write(
    `   merged findings ${result.findings.length} (both tools ${both}, one tool ${result.findings.length - both}); roll-up row ${result.rollup.matchedRow}, ${result.rollup.completeness}, eligible ${result.rollup.resolutionEligible}\n`,
  );
  const sev = {};
  for (const f of result.findings) sev[f.severity] = (sev[f.severity] ?? 0) + 1;
  process.stdout.write(
    `   severities ${JSON.stringify(sev)}; assumed ${result.findings.filter((f) => f.severityAssumed).length}\n`,
  );
};

async function main() {
  const o = parseArgs(process.argv.slice(2));
  for (const k of ["work", "tree", "trivy-db", "osv-db"]) if (!o[k]) die(`--${k} is required`);
  const work = path.resolve(o.work);
  if (!work.startsWith("/tmp/")) die("--work must be a directory under /tmp");
  const tree = path.resolve(o.tree);
  const trivyDb = path.resolve(o["trivy-db"]);
  const osvDb = path.resolve(o["osv-db"]);
  for (const [name, dir] of [
    ["tree", tree],
    ["trivy-db", trivyDb],
    ["osv-db", osvDb],
  ])
    if (!within(work, dir) || !existsSync(dir))
      die(`--${name} must be an existing directory inside --work`);
  if (!existsSync(path.join(trivyDb, "db", "trivy.db"))) die("--trivy-db must contain db/trivy.db");
  for (const eco of ["npm", "PyPI", "Go", "Maven"])
    if (!existsSync(path.join(osvDb, "osv-scalibr", eco, "all.zip")))
      die(`--osv-db must contain osv-scalibr/${eco}/all.zip`);
  const runtime = o.runtime ?? "docker";
  const rulesDir = path.join(work, "rules");
  mkdirSync(rulesDir, { recursive: true, mode: 0o755 });
  for (const f of readdirSync(RULES_SRC)) cpSync(path.join(RULES_SRC, f), path.join(rulesDir, f));
  const outDir = path.join(work, "out-sca");
  mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const config = validateSandboxConfig({
    runtimeBin: runtime,
    containerUser: "65534:65534",
    usernsMode: null,
    mountRoots: { archive: [work], db: [work], rules: [work] },
    egressNetworks: {},
  });
  const { resolver } = loadImageLock({});
  const common = { runtime, trivyDb, osvDb, rulesDir, outDir, config, resolver };
  const clean = await scan({ ...common, tree, label: "clean" });
  summary("clean tree", clean);
  // the planted-configuration experiment: the same tree plus hostile repository configuration
  const planted = path.join(work, "trees-planted");
  cpSync(tree, planted, { recursive: true });
  const ids = [...new Set(clean.findings.flatMap((f) => f.advisories.map((a) => a.id)))];
  writeFileSync(path.join(planted, ".trivyignore"), `${ids.join("\n")}\n`);
  writeFileSync(path.join(planted, "trivy.yaml"), "scan:\n  skip-dirs:\n    - '**'\n");
  writeFileSync(
    path.join(planted, "osv-scanner.toml"),
    `${ids.map((id) => `[[IgnoredVulns]]\nid = "${id}"\nreason = "planted"\n`).join("\n")}`,
  );
  const hostile = await scan({ ...common, tree: planted, label: "planted" });
  summary("planted configuration (must equal the clean tree)", hostile);
  const key = (r) =>
    JSON.stringify(r.findings.map((f) => [f.dedupKey, f.location?.path, f.severity]).sort());
  const checks = [
    ["clean: Trivy exit 0", clean.outcomes[0].status !== "failed"],
    ["clean: OSV-Scanner exit 0, 1 or 128", clean.outcomes[1].status !== "failed"],
    ["clean: nothing dropped", clean.outcomes.every((x) => x.recordsDropped === 0)],
    [
      "clean: the two tools agree on most findings",
      clean.findings.filter((f) => f.provenance.length > 1).length >= clean.findings.length / 2 ||
        clean.findings.length === 0,
    ],
    ["planted: the same findings as the clean tree", key(clean) === key(hostile)],
    ["clean: the roll-up is row 5", clean.rollup.matchedRow === 5],
  ];
  process.stdout.write("\n");
  let bad = 0;
  for (const [name, passed] of checks) {
    process.stdout.write(`${passed ? "PASS" : "FAIL"}  ${name}\n`);
    if (!passed) bad += 1;
  }
  writeFileSync(
    path.join(outDir, "summary.json"),
    JSON.stringify({ clean: clean.stats, planted: hostile.stats, checks }, null, 2),
  );
  process.exit(bad === 0 ? 0 : 1);
}

main().catch((error) => die(`failed: ${error?.message ?? error}`));
