/**
 * ENG-L23 live Secrets run (docs/modules/scan-engines/ENG_L23_RUNBOOK.md). RUN BY THE OWNER on a Docker machine; nothing in the security
 * suite or the build runs it. It builds the fixture tree of FAKE secrets (`apps/api/test/security/fixtures/scan-engines/secrets/tree-builder.js`,
 * every value assembled at run time and obviously fake), runs the SEALED command lines of the two adapters (Gitleaks, detect-secrets) through the
 * REAL `buildRunArgs` (so the sandbox flags are the production ones), and prints what the real adapters, the real merger and the real roll-up
 * make of the output. Experiments on the same tree: (1) hostile repository configuration planted (`.gitleaks.toml` allowing everything,
 * `.gitleaksignore` with every fingerprint, `.secrets.baseline`, `.gitignore`, ...) with the platform extraction deny list applied: the
 * findings must NOT change; (2) the same tree WITHOUT the deny list, to show what a root `.gitleaksignore` does (informational); (3) explicit
 * file targets for detect-secrets; (4) the CANARY: no fake value (in any encoding the platform scrubs) appears in the findings, the storage rows
 * or the serialized tool statuses the engine would store.
 *
 *   node run-secrets.js --work <dir> [--runtime docker|podman] [--detect-secrets-local <repo@sha256:digest>] [--save <dir>]
 *
 * `--work` must be under /tmp (the sandbox policy forbids home paths). No network is used by the tools (`--network=none`); the script itself
 * never uses the network, reads no token and prints no environment and NO secret value (only paths, rules, lines and counts). The detect-secrets
 * image is OWN-BUILT (SPEC D-14) and has no registry digest until it is pushed to the mirror registry: on a development machine pass the locally
 * built image by its digest reference with `--detect-secrets-local` (this affects THIS script only, never the worker). `--save <dir>` writes
 * the real tool outputs (`gitleaks-*.json`, `detect-secrets-*.json`) for the suite's fixtures.
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
import { toStorageRows } from "../../src/execution/engines/ensemble/core/index.js";
import { filterToChanged } from "../../src/execution/engines/ensemble/sast/scope.js";
import { secretVariants } from "../../src/execution/engines/ensemble/core/scrub.js";
import {
  createDetectSecretsAdapter,
  createGitleaksAdapter,
  isSecretsToolControlPath,
  planSecretsScope,
  runSecretsEnsemble,
  scopedFileInventory,
  secretsApplicability,
  walkAllFiles,
} from "../../src/execution/engines/ensemble/secrets/index.js";
import {
  FAKE,
  plantedConfigFiles,
  secretsTreeFiles,
  writeTree,
} from "../../../api/test/security/fixtures/scan-engines/secrets/tree-builder.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RULES_SRC = path.resolve(HERE, "../../src/execution/engines/ensemble/sbom/rules");
const LOCK = path.resolve(HERE, "../../src/execution/engines/ensemble/catalog/images.lock.json");
const STDOUT_CAP = 32 * 1024 * 1024;
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

/** Copies a tree the way the extractor would: files matching `deny` are never copied. */
function copyTree(from, to, deny) {
  cpSync(from, to, {
    recursive: true,
    filter: (src) => !deny || !isSecretsToolControlPath(path.relative(from, src)),
  });
}

/** Runs both tools over `tree` (whole tree, or `targets` for detect-secrets) and returns the pure ensemble result. */
async function scan({ runtime, tree, rulesDir, outDir, config, resolver, label, changed }) {
  const inventory = await walkAllFiles(tree);
  const scope = planSecretsScope(
    changed ? { status: "complete", paths: changed } : null,
    inventory,
  );
  const app = secretsApplicability(scopedFileInventory(inventory, scope.changed));
  const runs = [];
  const timing = {};
  for (const adapter of [createGitleaksAdapter(), createDetectSecretsAdapter()]) {
    const targets = scope.targets[adapter.toolId] ?? null;
    const plan = adapter.plan({
      tenantId: "00000000-0000-4000-8000-0000000000e2",
      executionId: "00000000-0000-4000-8000-0000000000e3",
      taskId: `${TASK.slice(0, -2)}${label.length.toString(16).padStart(2, "0")}`,
      attempt: 1,
      deadlineEpoch: Math.floor(Date.now() / 1000) + 900,
      archiveDir: tree,
      rulesDir,
      ...(targets ? { targets } : {}),
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
      { scanType: "secrets" },
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
        toolRunId: `00000000-0000-4000-8000-0000000000${adapter.toolId === "gitleaks" ? "a1" : "a2"}`,
        toolVersion: "live",
        imageDigest: spec.image.slice(spec.image.indexOf("@") + 1),
      },
    });
  }
  const result = runSecretsEnsemble({
    taskRef: TASK,
    runs,
    relevantFilesExist: app.relevantFilesExist,
  });
  // SE-24: merge first, filter after, once (the engine does the same)
  return {
    ...result,
    findings: filterToChanged(result.findings, scope.changed).kept,
    timing,
    runs,
  };
}

const summary = (label, result) => {
  process.stdout.write(`\n== ${label}\n`);
  for (const o of result.outcomes)
    process.stdout.write(
      `   ${o.toolId.padEnd(15)} ${o.status}${o.reason ? `/${o.reason}` : ""}  records ${o.recordsSeen ?? 0}, dropped ${o.recordsDropped ?? 0}, findings ${o.findingsMapped ?? 0}\n`,
    );
  const both = result.findings.filter((f) => f.provenance.length > 1).length;
  process.stdout.write(
    `   merged findings ${result.findings.length} (both tools ${both}, one tool ${result.findings.length - both}); roll-up row ${result.rollup.matchedRow}, ${result.rollup.completeness}\n`,
  );
  const sev = {};
  for (const f of result.findings) sev[f.severity] = (sev[f.severity] ?? 0) + 1;
  process.stdout.write(
    `   severities ${JSON.stringify(sev)}; time ${JSON.stringify(result.timing)}\n`,
  );
};

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (!o.work) die("--work is required");
  const work = path.resolve(o.work);
  if (!work.startsWith("/tmp/")) die("--work must be a directory under /tmp");
  mkdirSync(work, { recursive: true, mode: 0o755 });
  const runtime = o.runtime ?? "docker";
  const rulesDir = path.join(work, "rules");
  mkdirSync(rulesDir, { recursive: true, mode: 0o755 });
  cpSync(RULES_SRC, rulesDir, { recursive: true });
  const outDir = path.join(work, "out-secrets");
  mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const config = validateSandboxConfig({
    runtimeBin: runtime,
    containerUser: "65534:65534",
    usernsMode: null,
    mountRoots: { archive: [work], db: [work], rules: [work] },
    egressNetworks: {},
  });
  const lock = JSON.parse(readFileSync(LOCK, "utf8"));
  if (o["detect-secrets-local"]) {
    const m = /^([a-z0-9._/-]+)@(sha256:[0-9a-f]{64})$/.exec(o["detect-secrets-local"]);
    if (!m) die("--detect-secrets-local must be <repository>@sha256:<64 hex>");
    const entry = lock.images.find((i) => i.key === "detect-secrets");
    entry.repository = m[1];
    entry.digest = m[2];
    entry.flags = entry.flags.filter((f) => f !== "local_build_requires_registry_digest");
  }
  const resolver = createImageResolver(lock, { production: false });
  const common = { runtime, rulesDir, outDir, config, resolver };

  const tree = path.join(work, "tree");
  writeTree(tree, secretsTreeFiles());
  const clean = await scan({ ...common, tree, label: "clean" });
  summary("clean tree (whole tree)", clean);

  // the fingerprints Gitleaks itself reports, planted as a `.gitleaksignore` (absolute and relative form)
  const gl = clean.runs.find((r) => r.adapter.toolId === "gitleaks");
  const fps = JSON.parse(gl.streams.stdout.toString("utf8")).flatMap((x) => [
    x.Fingerprint,
    x.Fingerprint.replace("/src/", ""),
  ]);
  const planted = path.join(work, "tree-planted");
  copyTree(tree, planted, false);
  writeTree(planted, plantedConfigFiles(fps));
  // the extraction deny list is applied the way the scan handler applies it
  const denied = path.join(work, "tree-planted-denied");
  copyTree(planted, denied, true);
  const hostile = await scan({ ...common, tree: denied, label: "planted" });
  summary(
    "planted configuration, extraction deny list applied (must equal the clean tree)",
    hostile,
  );
  const bare = await scan({ ...common, tree: planted, label: "planted-nodeny" });
  summary(
    "planted configuration WITHOUT the deny list (informational: a root .gitleaksignore)",
    bare,
  );

  const targets = ["web/app.js", "svc/db.py"];
  const scoped = await scan({ ...common, tree, label: "targets", changed: targets });
  summary(
    `incremental (${targets.join(", ")}): detect-secrets targets, Gitleaks full then filtered`,
    scoped,
  );

  // the canary: no fake value, in any form the platform scrubs, reaches anything the engine stores
  const stored = JSON.stringify([
    clean.findings,
    toStorageRows(clean.findings, 50_000),
    clean.outcomes,
  ]);
  const leaked = Object.entries(FAKE)
    .filter(([, v]) => secretVariants(v).some((variant) => stored.includes(variant)))
    .map(([name]) => name);

  const key = (r) =>
    JSON.stringify(r.findings.map((f) => [f.dedupKey, f.location?.path, f.severity]).sort());
  const inFiles = (r) => ({
    ...r,
    findings: r.findings.filter((f) => targets.includes(f.location.path)),
  });
  const checks = [
    ["clean: both tools succeeded", clean.outcomes.every((x) => x.status === "succeeded")],
    ["clean: nothing dropped", clean.outcomes.every((x) => (x.recordsDropped ?? 0) === 0)],
    [
      "clean: findings in node_modules (nothing is excluded)",
      clean.findings.some((f) => f.location.path.startsWith("node_modules/")),
    ],
    ["planted + deny list: the same findings as the clean tree", key(clean) === key(hostile)],
    [
      "incremental: the same findings as the full run in those files",
      key(scoped) === key(inFiles(clean)),
    ],
    [
      `canary: no fake value in findings, rows or statuses (${leaked.join(",") || "none"})`,
      leaked.length === 0,
    ],
  ];
  process.stdout.write("\n");
  let bad = 0;
  for (const [name, passed] of checks) {
    process.stdout.write(`${passed ? "PASS" : "FAIL"}  ${name}\n`);
    if (!passed) bad += 1;
  }
  if (o.save) {
    const save = path.resolve(o.save);
    mkdirSync(save, { recursive: true });
    for (const [label, name] of [
      ["clean", "tree"],
      ["planted", "planted"],
      ["planted-nodeny", "planted-nodeny"],
    ])
      for (const tool of ["gitleaks", "detect-secrets"])
        cpSync(
          path.join(outDir, `${label}-${tool}.stdout`),
          path.join(save, `${tool}-${name}.json`),
        );
  }
  writeFileSync(
    path.join(outDir, "summary.json"),
    JSON.stringify(
      { clean: clean.stats, planted: hostile.stats, targets: scoped.stats, checks },
      null,
      2,
    ),
  );
  const existing = readdirSync(outDir).length;
  process.stdout.write(`\n${existing} output files in ${outDir}\n`);
  process.exit(bad === 0 && existsSync(outDir) ? 0 : 1);
}

main().catch((error) => die(`failed: ${error?.message ?? error}`));
