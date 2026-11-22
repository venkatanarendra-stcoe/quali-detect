import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildRunArgs, resolveRunSpecImage, validateSandboxConfig } from "@qmentisai/infra";
import { loadImageLock } from "../../../../workers/src/execution/engines/ensemble/catalog/index.js";
import {
  SECRETS_TOOL_CONTROL_FILES,
  createGitleaksAdapter,
  isSecretsToolControlPath,
} from "../../../../workers/src/execution/engines/ensemble/secrets/index.js";

/**
 * Scan engines, part M gap fillers (ADR-008 area 18, SPEC scan-engines 14.1, 16.1 part M, the coverage matrix of
 * `docs/modules/scan-engines/MUTATION_BACKLOG.md`): two properties earlier parts proved only indirectly.
 * - `ENG-S03j` (Docker-free): the Gitleaks file size cap `--max-target-megabytes 5` in the ARGUMENT VECTOR the sandbox is given,
 *   with a negative control (the inspection function rejects each mutated copy).
 * - `ENG-S03i` (database, real orchestrator and scan handler): the Secrets extraction deny list composes with `exclusions.paths`
 *   at the scan handler, at any depth, whatever the user's patterns are.
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const RULES_DIR = path.join(ROOT, "apps/workers/src/execution/engines/ensemble/sbom/rules");
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const same = (p, label, got, want) =>
  ok(
    p,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
  );

const FLAG = "--max-target-megabytes";
/**
 * Inspection of the arguments AFTER the image name: the size cap flag exactly once, as its own argument followed by the value 5,
 * before the scan target, in no `=` form.
 * @param {readonly string[]} tail
 * @returns {string[]} the problems found (empty when the cap is sealed)
 */
export function sizeCapProblems(tail) {
  const problems = [];
  const at = tail.indexOf(FLAG);
  if (at === -1) problems.push("the size cap flag is missing");
  if (tail.filter((a) => a === FLAG).length > 1) problems.push("the size cap flag is repeated");
  if (tail.some((a) => a.startsWith(`${FLAG}=`))) problems.push("the size cap uses the = form");
  if (at !== -1 && tail[at + 1] !== "5")
    problems.push(`the size cap value is ${JSON.stringify(tail[at + 1])}, not 5`);
  if (at !== -1 && tail.indexOf("/src") !== -1 && at > tail.indexOf("/src"))
    problems.push("the size cap comes after the scan target");
  return problems;
}

const ENSEMBLE_DIR = path.join(ROOT, "apps/workers/src/execution/engines/ensemble");
/** @param {string} dir @returns {string[]} */
const jsFilesOf = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) return name === "extractor-image" ? [] : jsFilesOf(full);
    return name.endsWith(".js") ? [full] : [];
  });
const FORBIDDEN_IMPORT =
  /from\s+["'](node:(child_process|net|http|https|http2|dgram|dns|tls|worker_threads|vm|cluster|inspector)|child_process|net|http|https|dns|tls|vm|worker_threads|undici|axios|node-fetch|ws|socket\.io[^"']*)["']/;
const FORBIDDEN_CALL =
  /\b(eval\s*\(|new Function\s*\(|fetch\s*\(|process\.env|XMLHttpRequest)|(?<![.\w$])(?:execFile|spawn|exec)\s*\(/;
const FORBIDDEN_NAME =
  /\b(SecretStore|createSecrets|createGitHubClient|GitHubClient|createLlm\w*|LlmProvider|ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_APP_\w+)\b/;
/**
 * The side effect guard of one ensemble source file (SE-5): returns the problems found in its code (comments removed).
 * @param {string} name @param {string} source
 */
export function sideEffectProblems(name, source) {
  const src = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  const problems = [];
  if (FORBIDDEN_IMPORT.test(src)) problems.push(`${name}: a network, process or thread import`);
  if (FORBIDDEN_CALL.test(src))
    problems.push(`${name}: a forbidden call (${FORBIDDEN_CALL.exec(src)?.[0]})`);
  if (FORBIDDEN_NAME.test(src))
    problems.push(`${name}: a SecretStore, GitHub or LLM name (${FORBIDDEN_NAME.exec(src)?.[0]})`);
  if (/@qmentisai\/db/.test(src) && !name.endsWith("engine/wiring.js"))
    problems.push(`${name}: a database import outside the engine wiring`);
  return problems;
}

export const ENSEMBLE_GUARD_CHECKS = [
  {
    id: "ENG-S03j",
    name: "the Gitleaks file size cap is in the argument vector the sandbox is given, with a negative control (SPEC scan-engines 11.3, 14.1 ENG-S03; part M gap): the arguments after the image of the REAL run specification of the Gitleaks plan hold --max-target-megabytes 5 exactly once, before /src, as separate arguments and no other size flag; the inspection function reports a problem for each of seven mutated copies (flag removed, value removed, value 0, value 500, flag repeated, = form, flag after the target), so the check cannot pass vacuously",
    async run() {
      const p = [];
      const tmp = mkdtempSync(path.join(os.tmpdir(), "qm-ens-m-"));
      try {
        const archiveDir = path.join(tmp, "tree");
        mkdirSync(archiveDir);
        const rulesDir = path.join(tmp, "rules");
        cpSync(RULES_DIR, rulesDir, { recursive: true });
        const cfg = validateSandboxConfig({
          runtimeBin: "podman",
          containerUser: "65534:65534",
          usernsMode: "keep-id",
          mountRoots: { archive: [tmp], db: [], rules: [rulesDir] },
          egressNetworks: {},
        });
        const plan = createGitleaksAdapter().plan({
          tenantId: "t",
          executionId: "e",
          taskId: "k",
          attempt: 1,
          deadlineEpoch: 1,
          archiveDir,
          rulesDir,
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
          loadImageLock().resolver,
          { scanType: "secrets" },
        );
        const args = buildRunArgs(spec, cfg);
        const tail = args.slice(args.indexOf(spec.image) + 1);
        same(p, "the real argument vector", sizeCapProblems(tail), []);
        same(p, "the flag count", tail.filter((a) => a === FLAG).length, 1);
        same(p, "the value", tail[tail.indexOf(FLAG) + 1], "5");
        // the runtime's own arguments before the image carry no size flag
        ok(
          p,
          !args.slice(0, args.indexOf(spec.image)).some((a) => a.includes("max-target")),
          "a size flag sits before the image",
        );
        const at = tail.indexOf(FLAG);
        const without = (i, n) => [...tail.slice(0, i), ...tail.slice(i + n)];
        const mutants = {
          "flag removed": without(at, 2),
          "value removed": without(at + 1, 1),
          "value 0": tail.map((a, i) => (i === at + 1 ? "0" : a)),
          "value 500": tail.map((a, i) => (i === at + 1 ? "500" : a)),
          "flag repeated": [...tail.slice(0, at + 2), FLAG, "5", ...tail.slice(at + 2)],
          "= form": [...tail.slice(0, at), `${FLAG}=5`, ...tail.slice(at + 2)],
          "flag after the target": [...without(at, 2), FLAG, "5"],
        };
        for (const [label, mutated] of Object.entries(mutants))
          ok(
            p,
            sizeCapProblems(mutated).length > 0,
            `negative control: "${label}" was not detected`,
          );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "ENG-S03k",
    name: "the whole ensemble directory has no network, process, SecretStore, GitHub or LLM access (SPEC scan-engines SE-5, SE-3, 14.1 ENG-S03; part M gap, the core was guarded by ENG-S03b only): no file under ensemble/** (the adapters, engines, catalog, evidence and database resolver included; the extractor image sources run inside the container and are not part of the worker) imports a network, child process, thread or VM module, calls fetch, eval, new Function, exec, execFile or spawn, reads process.env, names a SecretStore, GitHub client or LLM provider, or imports the database package outside the engine wiring; the guard function reports each of ten planted violations (negative control) and nothing on a clean source",
    async run() {
      const p = [];
      const files = jsFilesOf(ENSEMBLE_DIR);
      ok(p, files.length > 40, `only ${files.length} files were scanned`);
      for (const file of files) {
        const problems = sideEffectProblems(path.relative(ROOT, file), readFileSync(file, "utf8"));
        for (const x of problems) p.push(x);
      }
      const plant = (line) =>
        sideEffectProblems("ensemble/sca/x.js", `import z from "zod";\n${line}\n`);
      same(p, "a clean source", plant("export const a = 1;"), []);
      for (const line of [
        'import { request } from "node:https";',
        'import net from "node:net";',
        'import { execFile } from "node:child_process";',
        "const r = await fetch(url);",
        "const x = process.env.HOME;",
        "eval(code);",
        "const f = new Function(code);",
        "const s = new SecretStore();",
        "const g = createGitHubClient({});",
        'import { getDbClient } from "@qmentisai/db";',
      ])
        ok(p, plant(line).length > 0, `negative control: ${line} was not reported`);
      ok(
        p,
        sideEffectProblems(
          "apps/workers/src/execution/engines/ensemble/engine/wiring.js",
          'import { x } from "@qmentisai/db";\n',
        ).length === 0,
        "the engine wiring may import the database package",
      );
      // a commented-out violation is not code
      same(p, "comments are ignored", plant("// fetch(url) process.env"), []);
      return p;
    },
  },
];

/** Files seen by the Secrets engine and by another engine for ONE archive and ONE exclusion list, through the real scan handler. */
const ENTRIES = [
  { name: "README.md", content: "# repo\n" },
  { name: "src", dir: true },
  { name: "src/keep.js", content: "console.log(1)\n" },
  { name: ".gitignore", content: "node_modules\n" },
  { name: ".gitleaksignore", content: "fp\n" },
  { name: ".gitleaks.toml", content: "[allowlist]\n" },
  { name: ".secrets.baseline", content: "{}\n" },
  { name: "a", dir: true },
  { name: "a/b", dir: true },
  { name: "a/b/.gitleaksignore", content: "fp\n" },
  { name: "a/b/.secrets.baseline", content: "{}\n" },
  { name: "a/b/c.js", content: "1\n" },
  { name: "deep", dir: true },
  { name: "deep/er", dir: true },
  { name: "deep/er/x", dir: true },
  { name: "deep/er/x/.gitleaks.toml", content: "[allowlist]\n" },
  { name: "deep/er/x/ok.txt", content: "ok\n" },
  { name: "vendor", dir: true },
  { name: "vendor/lib.js", content: "2\n" },
  { name: "vendor/.gitleaksignore", content: "fp\n" },
  { name: "decoy", dir: true },
  { name: "decoy/gitleaksignore", content: "not the name\n" },
  { name: "decoy/.gitleaksignore.bak", content: "not the name\n" },
];
const DENIED = [
  ".gitleaksignore",
  ".gitleaks.toml",
  ".secrets.baseline",
  "a/b/.gitleaksignore",
  "a/b/.secrets.baseline",
  "deep/er/x/.gitleaks.toml",
  "vendor/.gitleaksignore",
];

export const ENSEMBLE_DENY_WORLD_CHECKS = [
  {
    id: "ENG-S03i",
    name: "the Secrets extraction deny list composes with exclusions.paths at the scan handler (SPEC scan-engines 11.3 layer 2, SE-3, 14.1 ENG-S03 and S07; part M gap, real orchestrator, scan handler, archive store and database): with the Secrets engine's deny list the tree the engine receives has no .gitleaksignore, .gitleaks.toml or .secrets.baseline at the root or at any depth (also inside a user-excluded directory, and with a user pattern that excludes everything else), the user's exclusions still apply next to it (an excluded directory and a glob are absent), look-alike names (gitleaksignore, .gitleaksignore.bak) and ordinary dotfiles stay, and an engine of another scan type in the same execution receives every one of those files (the deny list is the Secrets engine's alone; control); the deny list is the three names of the engine, so a predicate that stops denying one name or depth is caught",
    async run(w) {
      const p = [];
      same(
        p,
        "the deny list names",
        [...SECRETS_TOOL_CONTROL_FILES],
        [".gitleaksignore", ".gitleaks.toml", ".secrets.baseline"],
      );
      for (const path_ of DENIED)
        ok(p, isSecretsToolControlPath(path_), `the predicate does not deny ${path_}`);
      for (const [label, config] of [
        ["no user exclusions", w.config1()],
        ["a directory and a glob", w.config1({ exclusions: { paths: ["a/b", "*.md"] } })],
        ["vendor excluded", w.config1({ exclusions: { paths: ["vendor/**"] } })],
        ["everything excluded", w.config1({ exclusions: { paths: ["**"] } })],
      ]) {
        const registry = w.registry();
        // the Secrets engine of the suite carries the real platform deny list; the other three scan types have none
        registry.register({
          ...registry.get("secrets", "default"),
          extractionDeny: isSecretsToolControlPath,
        });
        const tree = await w.tree(`deny-${label.split(" ")[0]}`, { config });
        const execution = await w.execution(tree, { commitSha: w.sha(), entries: ENTRIES });
        const scan = w.scanHandler({}, undefined, registry);
        await w.run(tree, execution, { scan });
        const seen = w.fileTrees.filter((t) => t.executionId === execution.id);
        const filesOf = (type) =>
          (seen.find((t) => t.scanType === type)?.files ?? []).map((f) => f.path).sort();
        const secrets = filesOf("secrets");
        const sast = filesOf("sast");
        ok(p, seen.length === 4, `${label}: ${seen.length} scans received the tree`);
        for (const denied of DENIED)
          ok(p, !secrets.includes(denied), `${label}: the Secrets engine received ${denied}`);
        if (label === "everything excluded") {
          same(p, `${label}: secrets tree`, secrets, []);
          continue;
        }
        const userExcluded =
          label === "a directory and a glob"
            ? (f) => f.startsWith("a/b/") || f.endsWith(".md")
            : label === "vendor excluded"
              ? (f) => f.startsWith("vendor/")
              : () => false;
        const expected = ENTRIES.filter((e) => !e.dir)
          .map((e) => e.name)
          .filter((f) => !userExcluded(f) && !isSecretsToolControlPath(f))
          .sort();
        same(p, `${label}: secrets tree`, secrets, expected);
        for (const keep of [
          "src/keep.js",
          ".gitignore",
          "decoy/gitleaksignore",
          "decoy/.gitleaksignore.bak",
        ])
          ok(
            p,
            secrets.includes(keep) === !userExcluded(keep),
            `${label}: ${keep} wrongly kept or dropped`,
          );
        // control: the other scan type sees every denied file the user did not exclude
        for (const denied of DENIED)
          ok(
            p,
            sast.includes(denied) === !userExcluded(denied),
            `${label}: control, the other engine ${sast.includes(denied) ? "received" : "lacked"} ${denied}`,
          );
      }
      return p;
    },
  },
];
