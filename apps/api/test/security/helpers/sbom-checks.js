import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { findCredentials } from "@qmentisai/infra";
import { aggregateTaskOutcome, isResolutionEligible } from "@qmentisai/shared";
import { EngineError } from "../../../../workers/src/execution/engines.js";
import { inventoryArchive } from "../../../../workers/src/execution/engines/sbom/index.js";
import { engineRegistry } from "../../../../workers/src/execution/registry.js";
import { SBOM_LIMITS } from "../../../../workers/src/execution/engines/sbom/limits.js";

/**
 * SBOM engine and unsupported-task checks (ADR-008, docs/modules/executions/SPEC.md §17.ab): the built-in SBOM engine is the
 * only registered engine; a scan type without an engine becomes an `unsupported` task that never blocks the run. The REAL
 * orchestrator, scan handler, ownership verifier, outbox and SBOM engine run against the disposable database and the local GitHub
 * stub (production registry shape: `w.sbomRegistry()`); the repository content is hostile data. Black box about outcomes: rows,
 * statuses, messages. Every denial has a control (the legitimate path works) so no check passes vacuously.
 */

const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const TOKEN_SHAPES =
  /ghs_stub_|ghu_stub_|BEGIN (RSA )?PRIVATE KEY|authorization|secretRef|Bearer /i;
const SENTINEL = "sentinel-env-secret-value-0451";
const byCodeUnit = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

const scansOf = (types) => ({
  sbom: { enabled: types.includes("sbom") },
  sca: { enabled: types.includes("sca") },
  sast: { enabled: types.includes("sast") },
  secrets: { enabled: types.includes("secrets") },
});
const configOf = (w, types) => w.config1({ scans: scansOf(types) });

const PACKAGE_JSON = JSON.stringify({
  name: "app",
  version: "1.0.0",
  scripts: { preinstall: "node evil.js", postinstall: "node evil.js" },
  dependencies: { "left-pad": "^1.3.0", "@scope/util": "2.0.0" },
  devDependencies: { jest: "^29.0.0" },
});
const PACKAGE_LOCK = JSON.stringify({
  name: "app",
  lockfileVersion: 3,
  packages: {
    "": { name: "app" },
    "node_modules/left-pad": { version: "1.3.0" },
    "node_modules/@scope/util": { version: "2.0.0" },
    "node_modules/jest": { version: "29.7.0", dev: true },
    "node_modules/a/node_modules/left-pad": { version: "1.3.0" },
    "node_modules/b/node_modules/left-pad": { version: "1.3.0" },
  },
});
const GOOD_ENTRIES = [
  { name: "README.md", content: "# app\n" },
  { name: "package.json", content: PACKAGE_JSON },
  { name: "package-lock.json", content: PACKAGE_LOCK },
];

/** Claims and runs one execution end to end with ONLY the SBOM engine registered (the production registry shape). */
async function sbomRun(w, tree, execution, { over = {}, inventory } = {}) {
  const engines = w.sbomRegistry({ inventory });
  const orch = w.orchestrator(over, { engines });
  const scan = w.scanHandler(over, undefined, engines);
  return w.run(tree, execution, { orch, scan });
}

async function scenarioOf(w, label, types, { entries = GOOD_ENTRIES, over, inventory, fork } = {}) {
  const tree = await w.tree(label, { config: configOf(w, types) });
  const execution = fork
    ? await w.fork(tree, { entries, concurrencyGroup: label })
    : await w.execution(tree, { entries });
  const result = await sbomRun(w, tree, execution, { over, inventory });
  return {
    tree,
    execution,
    ...result,
    completed: await w.completed(tree, execution),
    tasks: await w.taskRows(execution),
    items: await w.db.scanResultItem.findMany({
      where: { tenantId: tree.tenant.id, executionId: execution.id },
      orderBy: { ordinal: "asc" },
    }),
  };
}

const state = (s) => `${s.row.status}/${s.row.statusReason}`;
const sorted = (rows) =>
  [...rows].sort((a, b) =>
    byCodeUnit(
      `${a.path}\u0000${a.data.ecosystem}\u0000${a.data.name}\u0000${a.componentVersion ?? ""}`,
      `${b.path}\u0000${b.data.ecosystem}\u0000${b.data.name}\u0000${b.componentVersion ?? ""}`,
    ),
  );

export const SBOM_CHECKS = [
  {
    id: "EXE-046",
    name: "the SBOM engine receives ONLY the archive: the object handed to the inventory function has exactly the key sourceDir (frozen), the scan context has only the documented credential-free keys, in a trusted and in an untrusted_fork run; no token, secret reference, Authorization text or environment value (a sentinel secret in the process environment) reaches an input, an item, a row or a log line; the engine source reads no environment, starts no process, opens no socket and evaluates nothing",
    async run(w) {
      const p = [];
      process.env.QM_SBOM_SENTINEL = SENTINEL;
      const fromInputs = w.sbomSpy.inputs.length;
      const fromContexts = w.sbomSpy.contexts.length;
      const logsBefore = w.logs.length;
      let trusted;
      let fork;
      try {
        trusted = await scenarioOf(w, "sbomIn1", ["sbom"]);
        fork = await scenarioOf(w, "sbomIn2", ["sbom"], { fork: true });
      } finally {
        delete process.env.QM_SBOM_SENTINEL;
      }
      const inputs = w.sbomSpy.inputs.slice(fromInputs);
      const contexts = w.sbomSpy.contexts.slice(fromContexts);
      ok(
        p,
        inputs.length === 2 && contexts.length === 2,
        `control: the engine ran ${inputs.length} times for two executions`,
      );
      ok(p, state(trusted) === "succeeded/null", `control: trusted run ${state(trusted)}`);
      ok(p, state(fork) === "succeeded/null", `control: fork run ${state(fork)}`);
      ok(
        p,
        trusted.items.length === 6 && fork.items.length === 6,
        `control: the engine reported ${trusted.items.length}/${fork.items.length} components, not 6`,
      );
      for (const input of inputs) {
        ok(
          p,
          Object.keys(input).join() === "sourceDir" && Object.isFrozen(input),
          `the inventory input is not exactly { sourceDir } (keys: ${Object.keys(input)})`,
        );
        ok(p, findCredentials(input).length === 0, "the inventory input carries a credential");
      }
      const allowed = new Set([
        "executionId",
        "taskId",
        "attempt",
        "scanType",
        "engine",
        "severityThreshold",
        "trust",
        "deadlineSeconds",
        "sourceDir",
      ]);
      for (const context of contexts) {
        const extra = Object.keys(context).filter((k) => !allowed.has(k));
        ok(p, extra.length === 0, `the scan context has undocumented keys: ${extra}`);
        ok(p, findCredentials(context).length === 0, "the scan context carries a credential");
      }
      ok(
        p,
        contexts
          .map((c) => c.trust)
          .sort()
          .join() === "trusted,untrusted_fork",
        `the contexts did not carry both trust levels (${contexts.map((c) => c.trust)})`,
      );
      const text = [
        JSON.stringify(inputs),
        JSON.stringify(contexts),
        await w.dump(trusted.tree),
        await w.dump(fork.tree),
        w.logs.slice(logsBefore).join("\n"),
      ].join("\n");
      ok(p, !text.includes(SENTINEL), "an environment secret reached the engine, a row or a log");
      ok(p, !TOKEN_SHAPES.test(text), "a token-shaped value reached the engine, a row or a log");
      // the production registry holds the SBOM engine and nothing else (SPEC §17.ab): SCA, SAST and secrets stay unsupported
      ok(
        p,
        engineRegistry.size === 1 &&
          engineRegistry.has("sbom", "default") &&
          ["sca", "sast", "secrets"].every((type) => !engineRegistry.has(type, "default")),
        `the production registry holds ${engineRegistry.size} engines, not exactly the SBOM engine`,
      );
      ok(
        p,
        engineRegistry.get("sbom", "default")?.idempotent === true,
        "the production SBOM engine is not declared idempotent",
      );
      // static guard: the engine's source has no way to read the environment, start a process, reach the network or evaluate text
      const dir = new URL("../../../../workers/src/execution/engines/sbom/", import.meta.url);
      const FORBIDDEN =
        /process\.env|child_process|node:net|node:http|node:https|node:dns|node:dgram|node:tls|node:vm|worker_threads|\bfetch\s*\(|\beval\s*\(|new\s+Function|\bimport\s*\(|\brequire\s*\(|\bspawn\s*\(|\bexecSync\s*\(|\bexecFile\s*\(/;
      let scanned = 0;
      for (const file of ["index.js", "parsers.js", "limits.js"]) {
        const source = await readFile(new URL(file, dir), "utf8");
        scanned += 1;
        const hit = FORBIDDEN.exec(source.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, ""));
        ok(p, !hit, `${file} contains ${hit?.[0]}`);
      }
      ok(p, scanned === 3, "control: the source guard did not read the engine files");
      return p;
    },
  },
  {
    id: "EXE-047",
    name: "an enabled scan type without a registered engine becomes an unsupported task (reason engine_not_registered, no attempt, no result, no queue message) and never fails the run: SBOM only -> succeeded; SBOM + SCA -> partial (tasks_unsupported), SBOM + SCA + SAST + secrets -> partial with three unsupported tasks; every enabled type unsupported -> failed (tasks_unsupported) before anything is fetched with the quota unit given back exactly once; a failing SBOM task next to an unsupported one stays failed (unsupported counts as no success); no task is ever failed for being unsupported; one history row and one status hint per unsupported task; the outcome table agrees",
    async run(w) {
      const p = [];
      const only = await scenarioOf(w, "unsOnly", ["sbom"]);
      const withSca = await scenarioOf(w, "unsSca", ["sbom", "sca"]);
      const all = await scenarioOf(w, "unsAll", ["sbom", "sca", "sast", "secrets"]);
      const none = await scenarioOf(w, "unsNone", ["sca"]);
      const broken = await scenarioOf(w, "unsBroken", ["sbom", "sca"], {
        inventory: async () => {
          throw new EngineError("engine_rejected_input", "permanent");
        },
      });
      const full = await (async () => {
        // control: with a registry that has every engine the same configuration is a full success (nothing is unsupported by default)
        const tree = await w.tree("unsFull", { config: configOf(w, ["sbom", "sca"]) });
        const execution = await w.execution(tree);
        const result = await w.run(tree, execution);
        return { tree, execution, ...result, tasks: await w.taskRows(execution) };
      })();
      ok(p, state(only) === "succeeded/null", `SBOM only: ${state(only)}`);
      ok(p, state(withSca) === "partial/tasks_unsupported", `SBOM + SCA: ${state(withSca)}`);
      ok(p, state(all) === "partial/tasks_unsupported", `all four: ${state(all)}`);
      ok(p, state(none) === "failed/tasks_unsupported", `SCA only: ${state(none)}`);
      ok(
        p,
        state(broken) === "failed/tasks_failed",
        `SBOM failing + SCA unsupported: ${state(broken)}`,
      );
      ok(p, state(full) === "succeeded/null", `control: both engines registered: ${state(full)}`);
      const statusOf = (s, type) => s.tasks.find((t) => t.scanType === type)?.status;
      ok(
        p,
        statusOf(only, "sbom") === "succeeded" &&
          statusOf(withSca, "sbom") === "succeeded" &&
          statusOf(withSca, "sca") === "unsupported" &&
          statusOf(broken, "sbom") === "failed",
        "the task statuses are not sbom succeeded / sca unsupported",
      );
      ok(
        p,
        all.tasks.filter((t) => t.status === "unsupported").length === 3 &&
          all.tasks.find((t) => t.scanType === "sbom").status === "succeeded",
        "four enabled types: not three unsupported next to a succeeded SBOM task",
      );
      ok(
        p,
        none.tasks.length === 1 && none.tasks[0].status === "unsupported",
        "SCA only: not exactly one unsupported task",
      );
      for (const s of [only, withSca, all, none, broken]) {
        for (const t of s.tasks.filter((x) => x.status === "unsupported")) {
          ok(
            p,
            t.statusReason === "engine_not_registered" &&
              t.attempt === 0 &&
              t.statusRev === 1 &&
              t.finishedAt &&
              !t.startedAt &&
              !t.queuedAt &&
              t.leaseOwner === null,
            `${t.scanType}: an unsupported task row is not (reason engine_not_registered, attempt 0, never queued or started)`,
          );
        }
        ok(
          p,
          s.tasks.every((t) => t.status !== "failed" || t.statusReason !== "engine_not_registered"),
          "a task was failed for being unsupported",
        );
        ok(p, s.completed.length === 1, `${state(s)}: ${s.completed.length} completed events`);
        const unsupportedIds = new Set(
          s.tasks.filter((t) => t.status === "unsupported").map((t) => t.id),
        );
        // no attempt, no result, no queue message, no task event of a running kind for an unsupported task
        const attempts = await w.db.scanTaskAttempt.count({
          where: { executionId: s.execution.id, scanTaskId: { in: [...unsupportedIds] } },
        });
        const results = await w.db.scanResult.count({
          where: { executionId: s.execution.id, scanTaskId: { in: [...unsupportedIds] } },
        });
        ok(
          p,
          attempts === 0 && results === 0,
          `${state(s)}: an unsupported task has attempts or results`,
        );
        const requested = (await w.outbox(s.tree, { type: "scan.task.requested" })).filter(
          (m) => m.payload.executionId === s.execution.id,
        );
        ok(
          p,
          requested.every((m) => !unsupportedIds.has(m.payload.taskId ?? m.taskId)),
          `${state(s)}: a scan queue message names an unsupported task`,
        );
        const requestedTypes = requested.map((m) => m.payload.payload.scanType).sort();
        const expectedTypes = s.tasks
          .filter((t) => t.status !== "unsupported")
          .map((t) => t.scanType)
          .sort();
        ok(
          p,
          requestedTypes.join() === expectedTypes.join(),
          `${state(s)}: scan queue messages for ${requestedTypes} instead of ${expectedTypes}`,
        );
        const history = (await w.events(s.execution, { type: "task_unsupported" })).map(
          (e) => e.details.scanType,
        );
        ok(
          p,
          history.sort().join() ===
            s.tasks
              .filter((t) => t.status === "unsupported")
              .map((t) => t.scanType)
              .sort()
              .join(),
          `${state(s)}: the history rows ${history} do not match the unsupported tasks`,
        );
        const hints = (await w.outbox(s.tree, { type: "scan.task.status_changed" })).filter(
          (m) =>
            m.payload.executionId === s.execution.id && m.payload.payload.status === "unsupported",
        );
        ok(
          p,
          hints.length === unsupportedIds.size,
          `${state(s)}: ${hints.length} unsupported status hints for ${unsupportedIds.size} tasks`,
        );
      }
      // events and eligibility
      const eligible = (s) => s.completed[0]?.payload.payload.resolutionEligible;
      ok(
        p,
        eligible(only) === true,
        "control: the clean SBOM-only trusted full run is not eligible",
      );
      ok(
        p,
        eligible(withSca) === false && eligible(all) === false && eligible(none) === false,
        "a run with an unsupported task is resolution eligible",
      );
      ok(
        p,
        withSca.completed[0].payload.payload.tasks.filter((t) => t.status === "unsupported")
          .length === 1,
        "the completed event does not list the unsupported task",
      );
      // quota: the SBOM+SCA run consumed its unit and kept it; the run where nothing could run gave it back exactly once
      for (const [label, s, released] of [
        ["SBOM + SCA", withSca, false],
        ["SBOM only", only, false],
        ["SCA only", none, true],
      ]) {
        const row = await w.row(s.execution);
        ok(
          p,
          Boolean(row.quotaReleasedAt) === released,
          `${label}: quota release is ${Boolean(row.quotaReleasedAt)}, expected ${released}`,
        );
      }
      const noneRow = await w.row(none.execution);
      ok(
        p,
        noneRow.commitSha &&
          (await w.sourceCalls()).tarballs.every((t) => t.sha !== noneRow.commitSha),
        "SCA only: the archive was fetched although nothing could run",
      );
      ok(
        p,
        (await w.events(none.execution, { type: "transition" })).filter(
          (e) => e.toStatus === "failed",
        ).length === 1,
        "SCA only: not exactly one transition to failed",
      );
      // the pure outcome table, written out independently of the code under test
      const row = (...statuses) => statuses.map((status) => ({ status }));
      for (const [tasks, status, reason] of [
        [row("succeeded"), "succeeded", null],
        [row("succeeded", "succeeded"), "succeeded", null],
        [row("succeeded", "unsupported"), "partial", "tasks_unsupported"],
        [row("succeeded", "unsupported", "unsupported"), "partial", "tasks_unsupported"],
        [row("succeeded", "failed", "unsupported"), "partial", "tasks_incomplete"],
        [row("succeeded", "timed_out"), "partial", "tasks_incomplete"],
        [row("unsupported"), "failed", "tasks_unsupported"],
        [row("unsupported", "unsupported"), "failed", "tasks_unsupported"],
        [row("failed", "unsupported"), "failed", "tasks_failed"],
        [row("failed"), "failed", "tasks_failed"],
        [[], "failed", "tasks_failed"],
      ]) {
        const got = aggregateTaskOutcome(tasks);
        ok(
          p,
          got.status === status && got.reason === reason,
          `outcome of [${tasks.map((t) => t.status)}] is ${got.status}/${got.reason}, expected ${status}/${reason}`,
        );
      }
      const base = { scanKind: "full", trust: "trusted", enabledScanTypes: ["sbom", "sca"] };
      const done = (scanType, status) => ({
        scanType,
        status,
        completeness: "complete",
        truncated: false,
      });
      ok(
        p,
        isResolutionEligible({
          ...base,
          status: "succeeded",
          tasks: [done("sbom", "succeeded"), done("sca", "succeeded")],
        }) === true &&
          isResolutionEligible({
            ...base,
            status: "partial",
            tasks: [done("sbom", "succeeded"), done("sca", "unsupported")],
          }) === false &&
          isResolutionEligible({
            ...base,
            status: "succeeded",
            tasks: [done("sbom", "succeeded"), done("sca", "unsupported")],
          }) === false,
        "resolution eligibility treats an unsupported task as complete",
      );
      return p;
    },
  },
  {
    id: "EXE-048",
    name: "a fork pull request SBOM run (untrusted_fork) carries no credentials anywhere and goes to scan-untrusted only: fetched with a contents:read token restricted to one repository through the base repository, the redirect followed WITHOUT Authorization; no outbox payload, event row, log line, audit entry, result, item, task, execution row, scan context or inventory input contains an installation token, private key marker, Authorization header, secretRef or a URL with credentials; an unsupported SCA task of the same fork run is never queued; the completed event is not resolution eligible",
    async run(w) {
      const p = [];
      const logsBefore = w.logs.length;
      const fromContexts = w.sbomSpy.contexts.length;
      const fromInputs = w.sbomSpy.inputs.length;
      const sbomOnly = await scenarioOf(w, "sbomForkA", ["sbom"], { fork: true });
      const withSca = await scenarioOf(w, "sbomForkB", ["sbom", "sca"], { fork: true });
      const trusted = await scenarioOf(w, "sbomForkT", ["sbom"]);
      const calls = await w.sourceCalls();
      const tokens = calls.minted.map((m) => m.token);
      ok(p, tokens.length >= 3, "control: the stub minted no installation tokens");
      for (const s of [sbomOnly, withSca]) {
        const forkTarballs = calls.tarballs.filter((t) => t.sha === s.execution.commitSha);
        ok(
          p,
          forkTarballs.length >= 1 &&
            forkTarballs.every(
              (t) =>
                t.scoped &&
                t.permissions?.contents === "read" &&
                Object.keys(t.permissions).length === 1,
            ),
          "control: the fork archive was not fetched with a token restricted to contents:read",
        );
        ok(
          p,
          calls.minted.some(
            (m) => m.repositories?.length === 1 && m.repositories[0] === s.tree.repoName,
          ),
          "control: the token was not restricted to the one repository",
        );
      }
      ok(
        p,
        calls.codeload.length >= 3 && calls.codeload.every((c) => c.hasAuthorization === false),
        "the redirect target received an Authorization header",
      );
      ok(p, state(sbomOnly) === "succeeded/null", `fork SBOM only: ${state(sbomOnly)}`);
      ok(p, state(withSca) === "partial/tasks_unsupported", `fork SBOM + SCA: ${state(withSca)}`);
      ok(p, state(trusted) === "succeeded/null", `control: trusted SBOM run: ${state(trusted)}`);
      for (const s of [sbomOnly, withSca]) {
        const queues = (await w.outbox(s.tree, { type: "scan.task.requested" })).filter(
          (m) => m.payload.executionId === s.execution.id,
        );
        ok(
          p,
          queues.length === 1 && queues.every((m) => m.queue === "scan-untrusted"),
          `fork tasks went to ${queues.map((m) => m.queue)} (${queues.length} messages)`,
        );
        ok(
          p,
          s.completed[0]?.payload.payload.resolutionEligible === false,
          "a fork execution was resolution eligible",
        );
      }
      const trustedQueues = (await w.outbox(trusted.tree, { type: "scan.task.requested" })).filter(
        (m) => m.payload.executionId === trusted.execution.id,
      );
      ok(
        p,
        trustedQueues.length === 1 && trustedQueues.every((m) => m.queue === "scan"),
        "control: the trusted SBOM task did not go to the scan queue",
      );
      const contexts = w.sbomSpy.contexts.slice(fromContexts);
      const inputs = w.sbomSpy.inputs.slice(fromInputs);
      ok(
        p,
        contexts.length === 3 &&
          findCredentials(contexts).length === 0 &&
          findCredentials(inputs).length === 0 &&
          contexts.filter((c) => c.trust === "untrusted_fork").length === 2,
        "the scan contexts or inventory inputs carry credentials, or the fork trust did not reach the engine",
      );
      for (const [label, tree] of [
        ["fork tenant A", sbomOnly.tree],
        ["fork tenant B", withSca.tree],
        ["trusted tenant", trusted.tree],
      ]) {
        const text = (await w.dump(tree)) + w.logs.slice(logsBefore).join("\n");
        for (const token of tokens)
          ok(p, !text.includes(token), `${label}: an installation token value is stored or logged`);
        ok(p, !TOKEN_SHAPES.test(text), `${label}: a credential-shaped value is stored or logged`);
        ok(p, !/https?:\/\/[^\s"']*@/.test(text), `${label}: a URL with credentials is stored`);
      }
      return p;
    },
  },
  {
    id: "EXE-049",
    name: "hostile repository content is only data: a package.json with lifecycle scripts next to an evil.js, a setup.py, conftest.py, build.rs and a .yarnrc.yml pointing at a script, a malformed lockfile, a 5000-level nested JSON file, a lockfile over the per-file cap that would yield tens of thousands of components, a binary yarn.lock, a pom.xml with an external entity, a requirements.txt line over the line cap, a symbolic link to a host file and keys named __proto__ and constructor: nothing is executed (the marker file is never written), the run still succeeds with an incomplete result, each bad file is a logged warning code (never content), the oversized file contributes no component, valid files are still reported, nothing leaks the host file or pollutes Object.prototype; the engine core, given tiny limits, caps files, bytes, depth and components (truncated), ignores a symlinked lockfile, and lets an abort through",
    async run(w) {
      const p = [];
      const marker = path.join(w.tmp, `pwned-${Date.now()}`);
      const evil = `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed");\n`;
      let big = '{"lockfileVersion":3,"packages":{"":{"name":"huge"}';
      for (let i = 0; big.length < 6 * 1024 * 1024; i += 1)
        big += `,"node_modules/huge-${i.toString(36)}-${(i * 7919).toString(16)}":{"version":"1.${i}.0"}`;
      big += "}}";
      ok(
        p,
        big.length > SBOM_LIMITS.maxFileBytes,
        "control: the oversized fixture is not over the cap",
      );
      const entries = [
        { name: "README.md", content: "# hostile\n" },
        { name: "package.json", content: PACKAGE_JSON.replace("app", "hostile") },
        { name: "evil.js", content: evil },
        { name: "setup.py", content: `open(${JSON.stringify(marker)}, "w").write("x")\n` },
        { name: "conftest.py", content: `open(${JSON.stringify(marker)}, "w").write("x")\n` },
        {
          name: "build.rs",
          content: `fn main() { std::fs::write(${JSON.stringify(marker)}, "x").unwrap(); }\n`,
        },
        { name: ".yarnrc.yml", content: "yarnPath: ./evil.js\n" },
        { name: "a", dir: true },
        { name: "a/package-lock.json", content: '{"lockfileVersion":3,"packages":{' },
        { name: "b", dir: true },
        { name: "b/package-lock.json", content: `{"a":`.repeat(5000) + "1" + "}".repeat(5000) },
        { name: "c", dir: true },
        { name: "c/package-lock.json", content: big },
        { name: "d", dir: true },
        { name: "d/yarn.lock", content: "\u0000\u0001\u0002 binary \u0003\nnot a lockfile\n" },
        { name: "e", dir: true },
        {
          name: "e/pom.xml",
          content:
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><project><dependencies><dependency><groupId>&xxe;</groupId><artifactId>x</artifactId><version>1</version></dependency></dependencies></project>',
        },
        { name: "f", dir: true },
        {
          name: "f/package.json",
          content:
            '{"dependencies":{"__proto__":"1.0.0","constructor":"2.0.0","toString":"3.0.0"},"__proto__":{"polluted":"yes"}}',
        },
        { name: "g", dir: true },
        { name: "g/requirements.txt", content: `requests==2.0.1\n${"x".repeat(5000)}==1\n` },
        { name: "h", dir: true },
        { name: "h/package.json", content: '{"dependencies":{"real-dep":"1.2.3"}}' },
        { name: "link", dir: true },
        { name: "link/package-lock.json", symlink: "/etc/passwd" },
        { name: "go.mod", symlink: "/etc/hostname" },
      ];
      const logsBefore = w.logs.length;
      const over = {
        EXECUTION_ARCHIVE_MAX_FILE_BYTES: String(16 * 1024 * 1024),
        EXECUTION_ARCHIVE_MAX_RATIO: "10000",
      };
      const s = await scenarioOf(w, "sbomHostile", ["sbom"], { entries, over });
      ok(p, state(s) === "succeeded/null", `the hostile archive ended ${state(s)}`);
      ok(
        p,
        s.tasks.length === 1 && s.tasks[0].status === "succeeded",
        `the SBOM task is ${s.tasks.map((t) => t.status)}`,
      );
      let executed = true;
      try {
        await stat(marker);
      } catch {
        executed = false;
      }
      ok(p, !executed, "repository code was executed (the marker file exists)");
      ok(p, s.completed.length === 1, "not exactly one completed event");
      const result = (
        await w.db.scanResult.findMany({ where: { executionId: s.execution.id } })
      )[0];
      ok(
        p,
        result?.completeness === "incomplete" && result.truncated === false,
        `the result is ${result?.completeness}/truncated ${result?.truncated}, not incomplete without truncation`,
      );
      ok(
        p,
        s.completed[0].payload.payload.resolutionEligible === false,
        "an incomplete SBOM result was resolution eligible",
      );
      const logs = w.logs.slice(logsBefore).join("\n");
      for (const [file, code] of [
        ["a/package-lock.json", "invalid_json"],
        ["b/package-lock.json", "too_deeply_nested"],
        ["c/package-lock.json", "file_too_large"],
        ["d/yarn.lock", "unexpected_structure"],
        ["g/requirements.txt", "line_too_long"],
      ])
        ok(p, logs.includes(`${file}: ${code}`), `no warning ${code} for ${file}`);
      const paths = new Set(s.items.map((i) => i.path));
      ok(p, !paths.has("c/package-lock.json"), "the oversized lockfile was parsed");
      ok(
        p,
        paths.has("h/package.json") &&
          s.items.some((i) => i.data.name === "real-dep" && i.data.scope === "prod"),
        "control: a valid file next to the hostile ones was not reported",
      );
      ok(
        p,
        paths.has("package.json") && s.items.filter((i) => i.path === "package.json").length === 3,
        "control: the root package.json (with lifecycle scripts) was not read as data",
      );
      ok(
        p,
        !paths.has("link/package-lock.json") && !paths.has("go.mod"),
        "a symbolic link was read",
      );
      const names = s.items.filter((i) => i.path === "f/package.json").map((i) => i.data.name);
      ok(
        p,
        ["__proto__", "constructor", "toString"].every((n) => names.includes(n)),
        `keys named like prototype members were lost (${names})`,
      );
      ok(
        p,
        {}.polluted === undefined &&
          Object.getPrototypeOf({}) === Object.prototype &&
          {}.toString === Object.prototype.toString,
        "Object.prototype was changed",
      );
      const text = (await w.dump(s.tree)) + logs;
      ok(p, !/root:[^\s]*:0:0/.test(text), "a host file's content reached a row or a log");
      ok(p, !text.includes("executed"), "executed repository output reached a row or a log");

      // the shipped limits themselves are bounded (the injected tiny limits below prove the enforcement, these prove the defaults)
      ok(
        p,
        Object.isFrozen(SBOM_LIMITS) &&
          SBOM_LIMITS.maxFileBytes <= 8 * 1024 * 1024 &&
          SBOM_LIMITS.maxTotalBytes <= 64 * 1024 * 1024 &&
          SBOM_LIMITS.maxFiles <= 1000 &&
          SBOM_LIMITS.maxDirectories <= 50000 &&
          SBOM_LIMITS.maxDepth <= 64 &&
          SBOM_LIMITS.maxComponents <= 100000 &&
          SBOM_LIMITS.maxJsonDepth <= 256 &&
          SBOM_LIMITS.maxLineLength <= 16384 &&
          SBOM_LIMITS.maxNameLength <= 500 &&
          SBOM_LIMITS.maxVersionLength <= 200,
        "a shipped SBOM limit is missing or unbounded",
      );
      // the engine core with tiny limits, in process, on a private directory
      const dir = await mkdtemp(path.join(os.tmpdir(), "qm-sbom-core-"));
      try {
        const outside = path.join(dir, "outside");
        const root = path.join(dir, "root");
        await mkdir(outside, { recursive: true });
        await mkdir(root, { recursive: true });
        await writeFile(
          path.join(outside, "package.json"),
          '{"dependencies":{"symlinked-dep":"1.0.0"}}',
        );
        await symlink(path.join(outside, "package.json"), path.join(root, "package.json"));
        for (const d of ["x", "y", "z"]) {
          await mkdir(path.join(root, d));
          await writeFile(
            path.join(root, d, "package.json"),
            JSON.stringify({ dependencies: { [`dep-${d}-1`]: "1", [`dep-${d}-2`]: "2" } }),
          );
        }
        await mkdir(path.join(root, "deep", "deeper", "deepest"), { recursive: true });
        await writeFile(path.join(root, "deep", "deeper", "deepest", "package.json"), "{}");
        await mkdir(path.join(root, "node_modules", "skipped"), { recursive: true });
        await writeFile(
          path.join(root, "node_modules", "skipped", "package.json"),
          '{"dependencies":{"in-node-modules":"1"}}',
        );
        const run = async (limits, signal = new AbortController().signal) => {
          const emitted = [];
          const logLines = [];
          const out = await inventoryArchive(
            { sourceDir: root },
            {
              signal,
              emit: (item) => emitted.push(item),
              log: (_l, m) => logLines.push(m),
              limits: { ...SBOM_LIMITS, ...limits },
            },
          );
          return { out, emitted, logLines };
        };
        const base = await run({});
        ok(
          p,
          base.emitted.length === 6 &&
            base.out.incomplete === false &&
            base.out.truncated === false &&
            !base.emitted.some((i) => /symlinked-dep|in-node-modules/.test(i.title)),
          `control: the core reported ${base.emitted.length} components (symlink and node_modules must be skipped)`,
        );
        const cappedComponents = await run({ maxComponents: 4 });
        ok(
          p,
          cappedComponents.emitted.length === 4 &&
            cappedComponents.out.truncated === true &&
            cappedComponents.out.incomplete === true,
          `the component cap was not enforced (${cappedComponents.emitted.length}, truncated ${cappedComponents.out.truncated})`,
        );
        const cappedFiles = await run({ maxFiles: 2 });
        ok(
          p,
          cappedFiles.emitted.length === 2 &&
            cappedFiles.out.incomplete === true &&
            cappedFiles.logLines.some((l) => l.includes("too_many_files")),
          "the file cap was not enforced",
        );
        const cappedBytes = await run({ maxTotalBytes: 100 });
        ok(
          p,
          cappedBytes.out.incomplete === true &&
            cappedBytes.emitted.length < base.emitted.length &&
            cappedBytes.logLines.some((l) => l.includes("total_bytes_exceeded")),
          "the total byte cap was not enforced",
        );
        const cappedFile = await run({ maxFileBytes: 20 });
        ok(
          p,
          cappedFile.emitted.length === 0 &&
            cappedFile.logLines.some((l) => l.includes("file_too_large")),
          "the per-file byte cap was not enforced",
        );
        const shallow = await run({ maxDepth: 1 });
        ok(
          p,
          shallow.out.incomplete === true && shallow.logLines.some((l) => l.includes("walk_limit")),
          "the depth cap was not enforced",
        );
        const again = await run({});
        ok(
          p,
          JSON.stringify(again.emitted) === JSON.stringify(base.emitted),
          "two runs on the same tree differ (not deterministic)",
        );
        const aborted = new AbortController();
        aborted.abort(new Error("task_deadline"));
        let abortSeen = false;
        try {
          await run({}, aborted.signal);
        } catch (error) {
          abortSeen = error?.message === "task_deadline";
        }
        ok(p, abortSeen, "an aborted signal did not stop the inventory");
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "EXE-050",
    name: "SBOM output is sorted, de-duplicated and tenant-scoped: the same archive in two tenants yields the same items in the order (source file, ecosystem, name, version) with a package that appears under three node_modules paths of one lockfile reported once and a production use winning over a dev use of the same version; every result and item row carries its own tenant and execution, the other tenant cannot read them through the result repository, and each tenant's items hold only that tenant's repository content",
    async run(w) {
      const p = [];
      const lock = JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": {},
          "node_modules/zeta": { version: "1.0.0", dev: true },
          "node_modules/alpha": { version: "2.0.0" },
          "node_modules/x/node_modules/zeta": { version: "1.0.0" },
          "node_modules/y/node_modules/zeta": { version: "1.0.0", dev: true },
          "node_modules/Beta": { version: "1.0.0" },
        },
      });
      const marked = (name) => [
        { name: "package-lock.json", content: lock },
        { name: "package.json", content: JSON.stringify({ dependencies: { [name]: "1.0.0" } }) },
        {
          name: "go.mod",
          content: `module m\nrequire github.com/z/z v1.0.0\nrequire github.com/a/a v1.0.0\n`,
        },
      ];
      const one = await scenarioOf(w, "sbomOrd1", ["sbom"], { entries: marked("only-in-one") });
      const two = await scenarioOf(w, "sbomOrd2", ["sbom"], { entries: marked("only-in-two") });
      ok(
        p,
        state(one) === "succeeded/null" && state(two) === "succeeded/null",
        "control: the runs did not succeed",
      );
      const strip = (s) =>
        s.items
          .filter((i) => i.path !== "package.json")
          .map((i) => ({
            ...i,
            id: undefined,
            tenantId: undefined,
            executionId: undefined,
            scanResultId: undefined,
            createdAt: undefined,
          }));
      ok(
        p,
        JSON.stringify(strip(one)) === JSON.stringify(strip(two)),
        "two tenants' identical lockfile and go.mod produced different items",
      );
      const locked = one.items.filter((i) => i.path === "package-lock.json");
      ok(
        p,
        locked.length === 3 &&
          locked.filter((i) => i.data.name === "zeta").length === 1 &&
          locked.find((i) => i.data.name === "zeta")?.data.scope === "prod",
        `de-duplication: ${locked.map((i) => `${i.data.name}@${i.componentVersion}/${i.data.scope}`)} (zeta once, production wins)`,
      );
      const order = (s) => s.items.map((i) => i.id).join();
      ok(
        p,
        order(one) ===
          sorted(one.items)
            .map((i) => i.id)
            .join(),
        "the items are not in (source file, ecosystem, name, version) order",
      );
      ok(
        p,
        one.items.map((i) => i.ordinal).join() === one.items.map((_i, n) => n).join(),
        "the ordinals are not 0..n-1",
      );
      // tenant scoping
      for (const [label, s, other] of [
        ["one", one, two],
        ["two", two, one],
      ]) {
        ok(
          p,
          s.items.length > 0 &&
            s.items.every(
              (i) => i.tenantId === s.tree.tenant.id && i.executionId === s.execution.id,
            ),
          `${label}: an item row carries another tenant or execution`,
        );
        const results = await w.db.scanResult.findMany({ where: { executionId: s.execution.id } });
        ok(
          p,
          results.length === 1 && results[0].tenantId === s.tree.tenant.id,
          `${label}: the result row is not the tenant's`,
        );
        const crossResults = await w.tasks.listResults({
          tenantId: other.tree.tenant.id,
          executionId: s.execution.id,
        });
        const crossItems = await w.db.scanResultItem.count({
          where: { tenantId: other.tree.tenant.id, executionId: s.execution.id },
        });
        ok(
          p,
          crossResults.length === 0 && crossItems === 0,
          `${label}: the other tenant can read the result or items`,
        );
        const text = JSON.stringify(s.items);
        ok(
          p,
          text.includes(`only-in-${label}`) &&
            !text.includes(`only-in-${label === "one" ? "two" : "one"}`),
          `${label}: the items do not hold exactly that tenant's repository content`,
        );
      }
      return p;
    },
  },
];
