/**
 * ENG-L20 capture tool (docs/modules/scan-engines/ENG_L20_RUNBOOK.md). RUN BY THE OWNER on a Docker machine; nothing in the
 * security suite or the build runs it. It prepares an extracted tree the way the production extractor does, runs the sealed
 * Syft and Trivy command lines (the argument vector comes from the REAL `buildRunArgs`, so the sandbox flags are the production
 * ones) plus the configuration-acceptance experiments, and writes the outputs and a manifest to an output directory that
 * `compare.js` reads offline.
 *
 *   node capture.js images [--check] [--runtime docker|podman]
 *   node capture.js prepare --work <dir> (--sample | --tarball <file.tar.gz>)
 *   node capture.js run --work <dir> --out <dir> [--runtime docker|podman] [--dry-run]
 *
 * The only network use in the whole procedure is `docker pull` of the two pinned images (printed by `images`, run by the owner).
 * This script never uses the network, never reads a token and never prints environment variables.
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  createReadStream,
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildRunArgs,
  extractTarGz,
  resolveRunSpecImage,
  validateSandboxConfig,
} from "@qmentisai/infra";
import { loadImageLock } from "../../src/execution/engines/ensemble/catalog/index.js";
import { createSyftAdapter } from "../../src/execution/engines/ensemble/sbom/syft.js";
import { createTrivySbomAdapter } from "../../src/execution/engines/ensemble/sbom/trivy-sbom.js";
import { buildSampleTarGz } from "./sample-tree.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RULES_SRC = path.resolve(HERE, "../../src/execution/engines/ensemble/sbom/rules");
const LOCK_PATH = path.resolve(
  HERE,
  "../../src/execution/engines/ensemble/catalog/images.lock.json",
);
const MANIFEST_VERSION = 1;
const STDERR_CAP = 4 * 1024 * 1024;

const die = (message, code = 2) => {
  process.stderr.write(`${message}\n`);
  process.exit(code);
};

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    if (!arg.startsWith("--")) die(`unexpected argument: ${arg}`);
    const key = arg.slice(2);
    if (["sample", "check", "dry-run"].includes(key)) options[key] = true;
    else {
      const value = rest[(i += 1)];
      if (value === undefined) die(`--${key} needs a value`);
      options[key] = value;
    }
  }
  return { command, options };
}

const readLock = () => JSON.parse(readFileSync(LOCK_PATH, "utf8"));
const lockEntry = (key) => readLock().images.find((e) => e.key === key);

function runtimeOf(options) {
  const runtime = options.runtime ?? "docker";
  if (!["docker", "podman"].includes(runtime)) die("--runtime must be docker or podman");
  return runtime;
}

function quote(arg) {
  return /^[A-Za-z0-9_./:=,@+%-]+$/.test(arg) ? arg : `'${arg.replaceAll("'", "'\\''")}'`;
}

// ---- images -------------------------------------------------------------------------------------------------------------

function cmdImages(options) {
  const runtime = runtimeOf(options);
  const entries = ["syft", "trivy"].map((key) => ({ key, ...lockEntry(key) }));
  if (!options.check) {
    process.stdout.write(
      "# Run these once (the ONLY step that uses the network), then run: images --check\n",
    );
    for (const e of entries) process.stdout.write(`${runtime} pull ${e.repository}@${e.digest}\n`);
    return;
  }
  let bad = 0;
  for (const e of entries) {
    const ref = `${e.repository}@${e.digest}`;
    const r = spawnSync(runtime, ["image", "inspect", "--format", "{{json .RepoDigests}}", ref], {
      encoding: "utf8",
    });
    if (r.status !== 0) {
      bad += 1;
      process.stdout.write(
        `MISSING   ${e.key}: ${ref} is not in the local image store (pull it)\n`,
      );
      continue;
    }
    const digests = r.stdout.trim();
    const present = digests.includes(e.digest);
    process.stdout.write(
      `${present ? "OK       " : "UNKNOWN  "} ${e.key}: ${ref} inspect RepoDigests=${digests}\n`,
    );
  }
  if (bad > 0) process.exit(1);
}

// ---- prepare ------------------------------------------------------------------------------------------------------------

const PLANTED = {
  ".syft.yaml": "# planted repository configuration: must never be read\nexclude:\n  - '**'\n",
  "trivy.yaml":
    "# planted repository configuration: must never be read\nscan:\n  skip-dirs:\n    - '**'\n",
  ".trivyignore": "# planted: must never be read\nCVE-0000-0000\n",
};
const BAD_RULES = {
  "syft.yaml": "check-for-app-update: false\nqm-no-such-key: true\n",
  "trivy.yaml": "debug: false\nqm-no-such-key: true\n",
};

async function extractInto(tarball, destDir) {
  return extractTarGz(createReadStream(tarball), { destDir });
}

function writeRules(dir, files) {
  mkdirSync(dir, { mode: 0o755 });
  for (const [name, text] of Object.entries(files))
    writeFileSync(path.join(dir, name), text, { mode: 0o644 });
}

async function cmdPrepare(options) {
  const work = options.work;
  if (!work || !path.isAbsolute(work))
    die("--work needs an absolute directory that does not exist yet");
  if (!options.sample && !options.tarball) die("give --sample or --tarball <file.tar.gz>");
  if (existsSync(work)) die(`${work} exists; give a new directory`);
  mkdirSync(work, { mode: 0o700 });
  const trees = path.join(work, "trees");
  mkdirSync(trees, { mode: 0o700 }); // the extractor requires a private parent
  let tarball = options.tarball;
  if (options.sample) {
    tarball = path.join(work, "sample.tar.gz");
    writeFileSync(tarball, buildSampleTarGz(), { mode: 0o600 });
  }
  const clean = await extractInto(tarball, path.join(trees, "clean"));
  const planted = await extractInto(tarball, path.join(trees, "planted"));
  for (const [name, text] of Object.entries(PLANTED))
    writeFileSync(path.join(trees, "planted", name), text, { mode: 0o644 });
  const rulesDir = path.join(work, "rules");
  mkdirSync(rulesDir, { mode: 0o755 });
  for (const f of ["syft.yaml", "trivy.yaml"])
    writeFileSync(path.join(rulesDir, f), readFileSync(path.join(RULES_SRC, f)), { mode: 0o644 });
  writeRules(path.join(work, "rules-bad"), BAD_RULES);
  const info = {
    prepareVersion: 1,
    source: options.sample ? "sample" : "tarball",
    clean: {
      files: clean.files,
      entries: clean.entries,
      bytes: clean.bytes,
      gitDenied: clean.gitDenied ?? 0,
    },
    planted: { files: planted.files, plantedFiles: Object.keys(PLANTED) },
  };
  writeFileSync(path.join(work, "prepare.json"), `${JSON.stringify(info, null, 2)}\n`, {
    mode: 0o600,
  });
  process.stdout.write(`prepared ${work}\n${JSON.stringify(info)}\n`);
}

// ---- run ----------------------------------------------------------------------------------------------------------------

const ADAPTERS = { syft: createSyftAdapter(), trivy: createTrivySbomAdapter() };

/** The experiments. `sealed` ones use the adapter's own plan unchanged. */
function experiments() {
  const sealed = (tool) => ADAPTERS[tool];
  const flag = "--qm-no-such-flag";
  return [
    { id: "syft-version", tool: "syft", purpose: "version", argv: ["--version"] },
    { id: "trivy-version", tool: "trivy", purpose: "version", argv: ["--version"] },
    {
      id: "syft-sealed",
      tool: "syft",
      purpose: "sealed",
      argv: [...sealed("syft").plan(dummyCtx()).argv],
    },
    {
      id: "trivy-sealed",
      tool: "trivy",
      purpose: "sealed",
      argv: [...sealed("trivy").plan(dummyCtx()).argv],
    },
    {
      id: "syft-planted",
      tool: "syft",
      purpose: "planted-repo-config",
      tree: "planted",
      argv: [...sealed("syft").plan(dummyCtx()).argv],
    },
    {
      id: "trivy-planted",
      tool: "trivy",
      purpose: "planted-repo-config",
      tree: "planted",
      argv: [...sealed("trivy").plan(dummyCtx()).argv],
    },
    {
      id: "syft-config-missing",
      tool: "syft",
      purpose: "config-missing",
      argv: ["-c", "/rules/missing.yaml", "dir:/src", "-o", "cyclonedx-json"],
    },
    {
      id: "trivy-config-missing",
      tool: "trivy",
      purpose: "config-missing",
      argv: [
        "fs",
        "--config",
        "/rules/missing.yaml",
        "--scanners",
        "license",
        "--format",
        "cyclonedx",
        "/src",
      ],
    },
    {
      id: "syft-config-unknown-key",
      tool: "syft",
      purpose: "config-unknown-key",
      rules: "rules-bad",
      argv: [...sealed("syft").plan(dummyCtx()).argv],
    },
    {
      id: "trivy-config-unknown-key",
      tool: "trivy",
      purpose: "config-unknown-key",
      rules: "rules-bad",
      argv: [...sealed("trivy").plan(dummyCtx()).argv],
    },
    {
      id: "syft-unknown-flag",
      tool: "syft",
      purpose: "unknown-flag",
      argv: [...sealed("syft").plan(dummyCtx()).argv, flag],
    },
    {
      id: "trivy-unknown-flag",
      tool: "trivy",
      purpose: "unknown-flag",
      argv: [...sealed("trivy").plan(dummyCtx()).argv, flag],
    },
  ];
}

const dummyCtx = () => ({
  tenantId: "eng-l20",
  executionId: "eng-l20",
  taskId: "eng-l20",
  attempt: 1,
  deadlineEpoch: 1,
  archiveDir: "/tmp/x",
  rulesDir: "/tmp/x",
});

function specFor(exp, work, attempt, resolver) {
  const base = ADAPTERS[exp.tool].plan({
    ...dummyCtx(),
    taskId: "eng-l20",
    attempt,
    deadlineEpoch: Math.floor(Date.now() / 1000) + 3600,
    archiveDir: path.join(work, "trees", exp.tree ?? "clean"),
    rulesDir: path.join(work, exp.rules ?? "rules"),
  });
  return resolveRunSpecImage({ ...base, argv: exp.argv }, resolver, { scanType: "sbom" });
}

function sandboxConfig(runtimeBin, work) {
  return validateSandboxConfig({
    runtimeBin,
    containerUser: "65534:65534",
    usernsMode: null,
    mountRoots: { archive: [path.join(work, "trees")], db: [], rules: [work] },
    egressNetworks: {},
  });
}

function execute(runtime, args, outDir, id, wallSeconds, stdoutCap) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    const stdoutFile = `${id}.stdout`;
    const stderrFile = `${id}.stderr`;
    const out = createWriteStream(path.join(outDir, stdoutFile), { mode: 0o600 });
    const err = createWriteStream(path.join(outDir, stderrFile), { mode: 0o600 });
    const hashOut = createHash("sha256");
    let outBytes = 0;
    let errBytes = 0;
    let timedOut = false;
    let truncated = false;
    const child = spawn(runtime, args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env.PATH },
    });
    const name = args.find((a) => a.startsWith("--name="))?.slice(7);
    const killer = setTimeout(
      () => {
        timedOut = true;
        if (name) spawnSync(runtime, ["kill", name], { stdio: "ignore" });
        child.kill("SIGKILL");
      },
      (wallSeconds + 15) * 1000,
    );
    child.stdout.on("data", (chunk) => {
      if (outBytes + chunk.length > stdoutCap) {
        truncated = true;
        if (name) spawnSync(runtime, ["kill", name], { stdio: "ignore" });
        return;
      }
      outBytes += chunk.length;
      hashOut.update(chunk);
      out.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      if (errBytes + chunk.length > STDERR_CAP) return;
      errBytes += chunk.length;
      err.write(chunk);
    });
    child.on("close", (code, signal) => {
      clearTimeout(killer);
      out.end();
      err.end();
      resolve({
        exitCode: code,
        signal,
        wallMs: Number((process.hrtime.bigint() - started) / 1_000_000n),
        timedOut,
        stdoutTruncated: truncated,
        stdoutFile,
        stdoutBytes: outBytes,
        stdoutSha256: hashOut.digest("hex"),
        stderrFile,
        stderrBytes: errBytes,
      });
    });
    child.on("error", () => {
      clearTimeout(killer);
      out.end();
      err.end();
      resolve({
        exitCode: null,
        signal: null,
        wallMs: 0,
        timedOut,
        stdoutTruncated: truncated,
        stdoutFile,
        stdoutBytes: outBytes,
        stdoutSha256: "",
        stderrFile,
        stderrBytes: errBytes,
        spawnError: true,
      });
    });
  });
}

async function cmdRun(options) {
  const work = options.work;
  const outDir = options.out;
  if (!work || !path.isAbsolute(work) || !existsSync(path.join(work, "prepare.json")))
    die("--work must be a directory made by `prepare`");
  if (!options["dry-run"] && (!outDir || !path.isAbsolute(outDir) || existsSync(outDir)))
    die("--out needs an absolute directory that does not exist yet");
  const runtime = runtimeOf(options);
  const { resolver } = loadImageLock();
  const config = sandboxConfig(runtime, work);
  const plan = experiments().map((exp, i) => {
    const spec = specFor(exp, work, i + 1, resolver);
    return { exp, spec, args: buildRunArgs(spec, config) };
  });
  if (options["dry-run"]) {
    for (const p of plan)
      process.stdout.write(`# ${p.exp.id}\n${runtime} ${p.args.map(quote).join(" ")}\n`);
    return;
  }
  mkdirSync(outDir, { mode: 0o700 });
  const runs = [];
  let failedBefore = false;
  for (const p of plan) {
    process.stdout.write(`running ${p.exp.id} ... `);
    const result = await execute(
      runtime,
      p.args,
      outDir,
      p.exp.id,
      p.spec.limits.wallClockSeconds,
      p.spec.limits.stdoutBytes,
    );
    process.stdout.write(`exit ${result.exitCode} in ${result.wallMs} ms\n`);
    runs.push({
      id: p.exp.id,
      tool: p.exp.tool,
      purpose: p.exp.purpose,
      tree: p.exp.tree ?? "clean",
      rules: p.exp.rules ?? "rules",
      toolArgv: p.exp.argv,
      runArgs: [...p.args],
      ...result,
    });
    if (p.exp.id === "trivy-sealed" && result.exitCode !== 0 && !failedBefore) {
      // Trivy may want a database or a Java DB even for the licence scanner: record the failure (the evidence), then try the documented fallbacks
      failedBefore = true;
      for (const [suffix, extra] of [
        ["skipdb", ["--skip-db-update", "--skip-java-db-update"]],
        ["offline", ["--offline-scan", "--skip-db-update", "--skip-java-db-update"]],
      ]) {
        const exp = {
          id: `trivy-fallback-${suffix}`,
          tool: "trivy",
          purpose: `fallback-${suffix}`,
          argv: [...p.exp.argv.slice(0, -1), ...extra, p.exp.argv.at(-1)],
        };
        const spec = specFor(exp, work, 50 + runs.length, resolver);
        const args = buildRunArgs(spec, config);
        process.stdout.write(`running ${exp.id} ... `);
        const r = await execute(
          runtime,
          args,
          outDir,
          exp.id,
          spec.limits.wallClockSeconds,
          spec.limits.stdoutBytes,
        );
        process.stdout.write(`exit ${r.exitCode} in ${r.wallMs} ms\n`);
        runs.push({
          id: exp.id,
          tool: "trivy",
          purpose: exp.purpose,
          tree: "clean",
          rules: "rules",
          toolArgv: exp.argv,
          runArgs: [...args],
          ...r,
        });
      }
    }
  }
  const images = {};
  for (const key of ["syft", "trivy"]) {
    const e = lockEntry(key);
    const ref = `${e.repository}@${e.digest}`;
    const r = spawnSync(runtime, ["image", "inspect", "--format", "{{json .RepoDigests}}", ref], {
      encoding: "utf8",
    });
    let repoDigests = null;
    try {
      repoDigests = r.status === 0 ? JSON.parse(r.stdout) : null;
    } catch {
      repoDigests = null;
    }
    images[key] = { reference: ref, digest: e.digest, repoDigests };
  }
  const v = spawnSync(runtime, ["version", "--format", "{{.Server.Version}}"], {
    encoding: "utf8",
  });
  const manifest = {
    manifestVersion: MANIFEST_VERSION,
    runtime,
    runtimeServerVersion: v.status === 0 ? v.stdout.trim().slice(0, 40) : null,
    host: { platform: process.platform, arch: process.arch, node: process.version },
    prepare: JSON.parse(readFileSync(path.join(work, "prepare.json"), "utf8")),
    images,
    runs,
  };
  writeFileSync(path.join(outDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, {
    mode: 0o600,
  });
  process.stdout.write(
    `wrote ${outDir} (${readdirSync(outDir).length} files, manifest.json last)\n`,
  );
}

const { command, options } = parseArgs(process.argv.slice(2));
if (command === "images") cmdImages(options);
else if (command === "prepare") await cmdPrepare(options);
else if (command === "run") await cmdRun(options);
else
  die(
    "usage: capture.js images [--check] | prepare --work <dir> (--sample|--tarball f) | run --work <dir> --out <dir> [--dry-run]",
  );
