/**
 * ENG-J live evidence run (docs/modules/scan-engines/SPEC.md 17.z). RUN BY THE OWNER (or the part J author) on a Docker machine; nothing in the
 * security suite or the build runs it. It runs the REAL Secrets engine and the REAL SAST engine of the ensemble through the REAL CLI sandbox
 * runtime (the production `buildRunArgs` flags, `--network=none`, read-only mounts) over the fixture trees, with the block extractor image
 * for the enclosing blocks, and prints what the engines STORE for evidence: the masked previews of the secret findings, the blocks and
 * windows of the code findings and the provider links. It also runs the CANARY: no fake secret value (in any form the platform scrubs) and no
 * SHA-1 of one may appear anywhere in the stored rows, the detail rows or the task log lines; and every stored secret preview holds the mask.
 *
 *   node run-evidence.js --work <dir> [--runtime docker|podman] [--detect-secrets-local <repo@sha256:id>]
 *        [--opengrep-local <repo@sha256:id>] [--extractor-local <repo@sha256:id>]
 *
 * `--work` must be under /tmp. The own-built images (detect-secrets, Opengrep, block extractor) have no registry digest until they are pushed
 * to the mirror registry (a pre-production task): pass the local image by `repo@sha256:<image id>` (this affects THIS script only).
 * The script never uses the network, reads no token and prints no secret value.
 */
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createCapacityGate,
  createCliSandboxRuntime,
  createImageResolver,
  createSandboxRunner,
} from "@qmentisai/infra";
import { secretVariants } from "../../src/execution/engines/ensemble/core/scrub.js";
import { createEnsembleSastEngine } from "../../src/execution/engines/ensemble/engine/sast-engine.js";
import { createEnsembleSecretsEngine } from "../../src/execution/engines/ensemble/engine/secrets-engine.js";
import { createTreePathExists } from "../../src/execution/engines/ensemble/engine/tree-paths.js";
import {
  FAKE,
  secretsTreeFiles,
  writeTree,
} from "../../../api/test/security/fixtures/scan-engines/secrets/tree-builder.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RULES_SRC = path.resolve(HERE, "../../src/execution/engines/ensemble/sbom/rules");
const SAST_TREE = path.resolve(HERE, "../../../api/test/security/fixtures/scan-engines/sast/tree");
const LOCK = path.resolve(HERE, "../../src/execution/engines/ensemble/catalog/images.lock.json");
const COMMIT = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c";

const die = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(2);
};
const out = (text) => process.stdout.write(`${text}\n`);

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith("--")) die(`unexpected argument ${argv[i]}`);
    o[argv[i].slice(2)] = argv[i + 1];
  }
  return o;
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (!o.work) die("--work is required");
  const work = path.resolve(o.work);
  if (!work.startsWith("/tmp/")) die("--work must be a directory under /tmp");
  const runtimeBin = o.runtime ?? "docker";
  const rulesDir = path.join(work, "rules");
  mkdirSync(rulesDir, { recursive: true, mode: 0o755 });
  cpSync(RULES_SRC, rulesDir, { recursive: true });
  const secretsTree = path.join(work, "tree-secrets");
  mkdirSync(secretsTree, { recursive: true, mode: 0o755 });
  writeTree(secretsTree, secretsTreeFiles());
  const sastTree = path.join(work, "tree-sast");
  cpSync(SAST_TREE, sastTree, { recursive: true });

  const lock = JSON.parse(readFileSync(LOCK, "utf8"));
  for (const [flag, key] of [
    ["detect-secrets-local", "detect-secrets"],
    ["opengrep-local", "opengrep"],
    ["extractor-local", "block-extractor"],
  ]) {
    if (!o[flag]) continue;
    const m = /^([a-z0-9._/-]+)@(sha256:[0-9a-f]{64})$/.exec(o[flag]);
    if (!m) die(`--${flag} must be <repository>@sha256:<64 hex>`);
    const entry = lock.images.find((i) => i.key === key);
    entry.repository = m[1];
    entry.digest = m[2];
    entry.flags = entry.flags.filter((f) => f !== "local_build_requires_registry_digest");
  }
  const resolver = createImageResolver(lock, { production: false });
  const runtime = createCliSandboxRuntime({
    config: {
      runtimeBin,
      containerUser: "65534:65534",
      usernsMode: null,
      mountRoots: { archive: [work], db: [work], rules: [work] },
      egressNetworks: {},
    },
  });
  const deps = {
    runner: createSandboxRunner({ runtime }),
    gate: createCapacityGate({ perWorker: 4, perTenant: 4, perTask: 2, forkShare: 4 }),
    resolver,
    rulesDir,
    toolWaitMs: 120_000,
    treePathExists: createTreePathExists,
  };
  const logs = [];
  const run = async (engine, sourceDir, scanType, n) =>
    engine.runTask(
      Object.freeze({
        executionId: "00000000-1111-4111-8111-0000000000a1",
        taskId: `00000000-2222-4222-8222-0000000000b${n}`,
        attempt: 0,
        scanType,
        sourceDir,
      }),
      {
        signal: new AbortController().signal,
        log: (level, message) => logs.push(`${level} ${message}`),
        emit() {},
        platform: {
          tenantId: "00000000-3333-4333-8333-0000000000c1",
          deadlineEpoch: Math.floor(Date.now() / 1000) + 900,
          secondsToDeadline: 900,
          scm: { provider: "github", fullName: "acme/app", commitSha: COMMIT },
        },
      },
    );

  const secrets = await run(createEnsembleSecretsEngine(deps), secretsTree, "secrets", 1);
  out(`\n== Secrets: ${secrets.items.length} findings, status ${secrets.status}`);
  out(
    `   tools ${JSON.stringify(secrets.ensemble.toolRuns.map((r) => `${r.toolId}:${r.status}`))}`,
  );
  out(`   coverage ${JSON.stringify(secrets.ensemble.coverage)}`);
  secrets.items.forEach((item, i) => {
    const d = secrets.ensemble.details[i];
    out(`-- ${item.path}:${item.startLine} ${item.ruleId} ${d.url ?? "(no link)"}`);
    out(d.evidence ? d.evidence.snippet : "(no evidence)");
  });

  const sast = await run(createEnsembleSastEngine(deps), sastTree, "sast", 2);
  out(`\n== SAST: ${sast.items.length} findings, status ${sast.status}`);
  out(`   tools ${JSON.stringify(sast.ensemble.toolRuns.map((r) => `${r.toolId}:${r.status}`))}`);
  sast.items.forEach((item, i) => {
    const d = sast.ensemble.details[i];
    const e = d.evidence;
    out(
      `-- ${item.path}:${item.startLine} ${item.ruleId} ${d.url ?? "(no link)"}\n   evidence ${
        e
          ? `${e.kind}${e.nodeKind ? `/${e.nodeKind}` : ""} lines ${e.startLine}-${e.endLine} focus ${e.focusStart}-${e.focusEnd}${e.truncated ? " truncated" : ""}`
          : "none"
      }`,
    );
  });
  // a SAST excerpt can hold a hard-coded credential in its own line: show what is stored for those (SE-43)
  sast.items.forEach((item, i) => {
    if (/hardcoded|B10[5-7]/i.test(item.ruleId) && sast.ensemble.details[i].evidence)
      out(
        `-- stored excerpt of ${item.path}:${item.startLine} (${item.ruleId})\n${sast.ensemble.details[i].evidence.snippet}`,
      );
  });
  out(`   log: ${logs.filter((l) => /evidence/i.test(l)).join(" | ")}`);

  // the canary: no value, no SHA-1 of a value anywhere that would be stored or logged
  const variants = Object.values(FAKE).flatMap((v) => secretVariants(v));
  const sha1s = Object.values(FAKE).map((v) => createHash("sha1").update(v).digest("hex"));
  const everything = JSON.stringify([secrets, sast, logs]);
  const checks = [
    ["no fake value in any stored row or log", variants.every((v) => !everything.includes(v))],
    ["no SHA-1 of a fake value", sha1s.every((h) => !everything.includes(h))],
    [
      "every secret preview holds the mask",
      secrets.ensemble.details.every(
        (d) => d.evidence === null || /\[REDACTED:[a-z_]+\]/.test(d.evidence.snippet),
      ),
    ],
    [
      "every secret finding of the fixture tree has a preview",
      secrets.ensemble.details.filter((d) => d.evidence !== null).length === secrets.items.length,
    ],
    [
      "the secrets coverage names the Gitleaks allowlist gap",
      secrets.ensemble.coverage.notes?.includes("gitleaks_default_allowlist") === true,
    ],
    ["code findings have evidence", sast.ensemble.details.some((d) => d.evidence)],
    [
      "code findings carry a commit-pinned link",
      sast.ensemble.details.every((d) => d.url?.includes(COMMIT)),
    ],
  ];
  let bad = 0;
  for (const [name, passed] of checks) {
    out(`${passed ? "PASS" : "FAIL"}  ${name}`);
    if (!passed) bad += 1;
  }
  process.exit(bad === 0 ? 0 : 1);
}

main().catch((error) => die(`failed: ${error?.message ?? error}`));
