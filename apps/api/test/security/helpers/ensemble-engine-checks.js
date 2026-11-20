import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createExecutionArtifactRepository, createScanDecisionRepository } from "@qmentisai/db";
import {
  FakeSandboxRuntime,
  SandboxError,
  createCapacityGate,
  createJanitor,
  createPostgresArtifactStore,
  createSandboxRunner,
  findCredentials,
} from "@qmentisai/infra";
import { TOOL_REASONS } from "@qmentisai/shared";
import { ConfigError, loadWorkerConfig } from "../../../../workers/src/config.js";
import {
  CHANGED_PATHS_MAX,
  CHANGED_PATHS_NAME,
  buildChangedPaths,
  readChangedPaths,
  writeChangedPaths,
} from "../../../../workers/src/execution/changed-paths.js";
import { decideScans } from "../../../../workers/src/execution/decision/decide.js";
import { decideFloor } from "../../../../workers/src/execution/decision/floor.js";
import { createEngineRegistry } from "../../../../workers/src/execution/engines.js";
import { loadImageLock } from "../../../../workers/src/execution/engines/ensemble/catalog/index.js";
import {
  createEnsembleSbomEngine,
  redactedSbomDocument,
} from "../../../../workers/src/execution/engines/ensemble/engine/engine.js";
import { runManifestSha256 } from "../../../../workers/src/execution/engines/ensemble/engine/run-manifest.js";
import { buildEnsembleEngine } from "../../../../workers/src/execution/engines/ensemble/engine/wiring.js";
import { buildEngineRegistry, engineRegistry } from "../../../../workers/src/execution/registry.js";

/**
 * Scan engines, part K core (ADR-008 area 18, SPEC scan-engines 14.1 ENG-S04, S05, S06, S10, S11, S14, 16.1 part K, 17.i): the
 * ensemble SBOM engine, its capacity, cancellation and roll-up behaviour, the changed-paths contract and the rollout flag, all with
 * the FAKE sandbox runtime and the hand-written fixtures (no container, no process, no network, no database). NOT proved: anything
 * about real tool output or a real runtime (ENG-L20, ENG-L05, ENG-L12); the engine is exercised only with the Part E adapters
 * unchanged and with no path filter (both HELD, SPEC 17.i).
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const WORKERS = path.join(ROOT, "apps/workers/src");
const ENGINE_DIR = path.join(WORKERS, "execution/engines/ensemble/engine");
const RULES = path.join(WORKERS, "execution/engines/ensemble/sbom/rules");
const FIX = path.join(ROOT, "apps/api/test/security/fixtures/scan-engines/sbom");
const SYFT_DOC = readFileSync(path.join(FIX, "syft-cyclonedx.json"), "utf8");
const TRIVY_DOC = readFileSync(path.join(FIX, "trivy-cyclonedx.json"), "utf8");
const TENANT_A = "aaaaaaaa-0000-4000-8000-00000000000a";
const TENANT_B = "bbbbbbbb-0000-4000-8000-00000000000b";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const same = (p, label, got, want) =>
  ok(
    p,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
  );
const uuid = (n, tail = "0") =>
  `${String(n).padStart(8, "0")}-1111-4111-8111-${tail.padStart(12, "0")}`;

const TREE_FILES = {
  "package.json": JSON.stringify({
    name: "app",
    version: "1.0.0",
    dependencies: { lodash: "4.17.20" },
  }),
  "package-lock.json": JSON.stringify({
    name: "app",
    lockfileVersion: 3,
    packages: { "": { name: "app" }, "node_modules/lodash": { version: "4.17.20" } },
  }),
};

/** A disposable environment: tree root, rules directory, fake runtime, runner, gate, engine. */
export function makeEnv({ gate = {}, toolWaitMs = 500, inventory, scripts } = {}) {
  const base = mkdtempSync(path.join(os.tmpdir(), "qm-ens-s10-"));
  const archiveRoot = path.join(base, "scan");
  const rulesDir = path.join(base, "rules");
  mkdirSync(archiveRoot);
  cpSync(RULES, rulesDir, { recursive: true });
  const runtime = new FakeSandboxRuntime({
    config: {
      runtimeBin: "podman",
      containerUser: "65534:65534",
      usernsMode: "keep-id",
      uidMap: [],
      gidMap: [],
      seccompProfile: null,
      mountRoots: { archive: [archiveRoot], db: [], rules: [rulesDir] },
      egressNetworks: {},
    },
  });
  runtime.script("syft", { exitCode: 0, stdout: SYFT_DOC, ...scripts?.syft });
  runtime.script("trivy", { exitCode: 0, stdout: TRIVY_DOC, ...scripts?.trivy });
  const runner = createSandboxRunner({ runtime });
  const gateOf = createCapacityGate({
    perWorker: 4,
    perTenant: 4,
    perTask: 2,
    forkShare: 4,
    ...gate,
  });
  const { resolver } = loadImageLock();
  const engine = createEnsembleSbomEngine({
    runner,
    gate: gateOf,
    resolver,
    rulesDir,
    toolWaitMs,
    inventory,
  });
  let n = 0;
  const tree = (files = TREE_FILES) => {
    const dir = path.join(archiveRoot, `t${(n += 1)}`);
    mkdirSync(dir, { mode: 0o755 });
    for (const [name, text] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      writeFileSync(path.join(dir, name), text, { mode: 0o644 });
    }
    return dir;
  };
  const logs = [];
  /** Runs one task attempt; resolves with the engine's return value. */
  const run = ({
    tenantId = TENANT_A,
    taskId = uuid(1),
    attempt = 0,
    secondsToDeadline = 120,
    fork = false,
    signal,
    files,
  } = {}) =>
    engine.runTask(
      Object.freeze({
        executionId: uuid(9),
        taskId,
        attempt,
        scanType: "sbom",
        sourceDir: tree(files),
      }),
      {
        signal: signal ?? new AbortController().signal,
        log: (level, message) => logs.push(`${level} ${message}`),
        emit() {},
        platform: {
          tenantId,
          deadlineEpoch: Math.floor(Date.now() / 1000) + secondsToDeadline,
          secondsToDeadline,
          fork,
          maxItems: 50_000,
        },
      },
    );
  return {
    base,
    runtime,
    runner,
    gate: gateOf,
    engine,
    run,
    logs,
    tree,
    rulesDir,
    cleanup: () => rmSync(base, { recursive: true, force: true }),
  };
}

const statusOf = (r) =>
  Object.fromEntries(
    r.ensemble.toolRuns.map((t) => [t.toolId, `${t.status}${t.reason ? `/${t.reason}` : ""}`]),
  );
const runs = (r) => Object.fromEntries(r.ensemble.toolRuns.map((t) => [t.toolId, t]));

/** The database CHECK of `scan_tool_runs` (migration 20261119120000), restated: what a record may hold. */
const TOOL_RUN_KEYS = [
  "id",
  "toolId",
  "toolVersion",
  "imageDigest",
  "configDigest",
  "status",
  "reason",
  "exitCode",
  "scope",
  "limits",
  "capacityWaitMs",
  "startedAt",
  "finishedAt",
  "durationMs",
  "recordsSeen",
  "recordsDropped",
  "findingsMapped",
  "severityCounts",
  "truncated",
];
export function toolRunProblems(r) {
  const bad = [];
  const need = (c, m) => c || bad.push(`${r.toolId}: ${m}`);
  need(
    Object.keys(r).every((k) => TOOL_RUN_KEYS.includes(k)),
    `unexpected keys ${Object.keys(r).filter((k) => !TOOL_RUN_KEYS.includes(k))}`,
  );
  need(["sbom-lite", "syft", "trivy"].includes(r.toolId), "tool id");
  need(
    typeof r.toolVersion === "string" && r.toolVersion.length >= 1 && r.toolVersion.length <= 100,
    "tool version",
  );
  need(r.imageDigest === null || /^sha256:[0-9a-f]{64}$/.test(r.imageDigest), "image digest");
  need(
    r.imageDigest !== null ||
      r.toolId === "sbom-lite" ||
      ["skipped", "unavailable"].includes(r.status),
    "digest missing",
  );
  need(/^[0-9a-f]{64}$/.test(r.configDigest), "config digest");
  need(
    ["succeeded", "partial", "failed", "timed_out", "cancelled", "skipped", "unavailable"].includes(
      r.status,
    ),
    "status",
  );
  need(
    r.reason === null || r.reason === undefined || TOOL_REASONS.includes(r.reason),
    "reason word",
  );
  need(r.status !== "succeeded" || !r.reason, "succeeded with a reason");
  need(
    !["failed", "timed_out", "unavailable", "skipped"].includes(r.status) || Boolean(r.reason),
    "failure without a reason",
  );
  need(
    r.exitCode === null || (Number.isInteger(r.exitCode) && r.exitCode >= 0 && r.exitCode <= 255),
    "exit code",
  );
  need(
    Date.parse(r.finishedAt) >= Date.parse(r.startedAt) &&
      r.durationMs >= 0 &&
      r.capacityWaitMs >= 0,
    "timing",
  );
  const seen = r.recordsSeen ?? 0;
  need((r.recordsDropped ?? 0) <= seen && (r.findingsMapped ?? 0) <= seen, "counters");
  need(findCredentials(r).length === 0, "credential shape");
  return bad;
}

const FIXED = { syftFindings: 8 };

export const ENSEMBLE_ENGINE_CHECKS = [
  {
    id: "ENG-S10c",
    name: "cancellation, deadline, tool timeout and crash leave no orphan container through the ensemble engine (SPEC scan-engines 6.4, 14.1 ENG-S10, part K core; fake runtime): a user cancel and a task deadline arriving while both tools run end every run, kill AND remove every container of the attempt exactly once and leave none, the tools are cancelled with the reason cancelled or deadline and the roll-up is row 1 (cancelled) or row 2 (timed out); a tool that hits its wall clock is timed_out / timeout, its container is removed, its output is never parsed, the other tools keep their findings and the task is the degraded row 6; a runtime fault is failed / sandbox_error with nothing left behind; after a simulated crash of the runner the janitor removes the labelled containers whose attempt is no longer running, keeps the ones of a running attempt and never touches an unlabelled container; the janitor started by the wiring sweeps at once and stops when told to",
    async run() {
      const p = [];
      // ---- user cancel and deadline while both container tools hang
      for (const [reason, tool, row, task] of [
        ["user_cancelled", "cancelled", 1, "cancelled"],
        ["task_deadline", "deadline", 2, "timed_out"],
      ]) {
        const env = makeEnv({ scripts: { syft: { hang: true }, trivy: { hang: true } } });
        try {
          const ac = new AbortController();
          const done = env.run({ signal: ac.signal });
          await sleep(60);
          ok(
            p,
            env.runtime.containers.size === 2,
            `${reason}: two containers must be running (${env.runtime.containers.size})`,
          );
          const names = [...env.runtime.containers.keys()];
          ac.abort(new Error(reason));
          const r = await Promise.race([done, sleep(4000).then(() => null)]);
          ok(p, r !== null, `${reason}: the engine did not return after the abort`);
          if (!r) continue;
          same(p, `${reason} containers left`, env.runtime.containers.size, 0);
          for (const n of names) {
            same(p, `${reason} kill count of ${n}`, env.runtime.killCount(n), 1);
            same(p, `${reason} remove count of ${n}`, env.runtime.removeCount(n), 1);
          }
          const st = statusOf(r);
          same(
            p,
            `${reason} container tools`,
            [st.syft, st.trivy],
            [`cancelled/${tool}`, `cancelled/${tool}`],
          );
          same(
            p,
            `${reason} roll-up row`,
            [r.ensemble.rollup.matchedRow, r.ensemble.rollup.taskStatus],
            [row, task],
          );
          ok(
            p,
            r.ensemble.toolRuns.every((t) => toolRunProblems(t).length === 0),
            `${reason}: a tool run record is malformed`,
          );
        } finally {
          env.cleanup();
        }
      }
      // ---- the tool wall clock (the task seconds cap it): the hanging tool is timed_out, the other keeps its findings
      {
        const env = makeEnv({ scripts: { syft: { hang: true } } });
        try {
          const r = await env.run({ secondsToDeadline: 1 });
          const st = statusOf(r);
          same(
            p,
            "timeout tool statuses",
            [st.syft, st.trivy, st["sbom-lite"]],
            ["timed_out/timeout", "succeeded", "succeeded"],
          );
          same(
            p,
            "timeout roll-up",
            [
              r.ensemble.rollup.matchedRow,
              r.ensemble.rollup.completeness,
              r.ensemble.rollup.toolsDegraded,
            ],
            [6, "incomplete", 1],
          );
          same(p, "timeout containers", env.runtime.containers.size, 0);
          ok(
            p,
            r.items.length > 0 && r.ensemble.document === null,
            "findings of the other tools are kept and a timed-out tool has no document",
          );
          ok(
            p,
            r.incomplete === true && r.status === "succeeded",
            "a degraded task is succeeded and incomplete",
          );
        } finally {
          env.cleanup();
        }
      }
      // ---- a runtime fault
      {
        const env = makeEnv({ scripts: { syft: { runtimeFault: true } } });
        try {
          const r = await env.run();
          same(p, "runtime fault", statusOf(r).syft, "failed/sandbox_error");
          same(p, "runtime fault leaves nothing", env.runtime.containers.size, 0);
          ok(p, r.status === "succeeded", "one failed tool does not fail the task");
        } finally {
          env.cleanup();
        }
      }
      // ---- a runner that throws: the capacity unit is given back and nothing is left
      {
        const env = makeEnv();
        try {
          env.runtime.run = async () => {
            throw new Error("runtime exploded");
          };
          const r = await env.run();
          same(
            p,
            "thrown runner error",
            [statusOf(r).syft, statusOf(r).trivy],
            ["failed/sandbox_error", "failed/sandbox_error"],
          );
          same(
            p,
            "the gate is drained after a thrown error",
            [env.gate.snapshot().worker, env.gate.snapshot().tasks],
            [0, 0],
          );
          env.runtime.run = async () => {
            throw new SandboxError("image_unavailable", "gone", ["image_unavailable"]);
          };
          const r2 = await env.run();
          same(
            p,
            "image gone at run time",
            [statusOf(r2).syft, env.gate.snapshot().worker],
            ["unavailable/image_unavailable", 0],
          );
        } finally {
          env.cleanup();
        }
      }
      // ---- an image that cannot be resolved (never started), and a relative rules directory is refused
      {
        const env = makeEnv();
        try {
          const { resolver } = loadImageLock();
          const picky = {
            ...resolver,
            resolve: (key, o) => {
              if (key === "trivy")
                throw new SandboxError("image_unavailable", "no", ["no_registry_digest"]);
              return resolver.resolve(key, o);
            },
          };
          const engine = createEnsembleSbomEngine({
            runner: env.runner,
            gate: env.gate,
            resolver: picky,
            rulesDir: env.rulesDir,
            toolWaitMs: 200,
          });
          const r = await engine.runTask(
            Object.freeze({
              executionId: uuid(9),
              taskId: uuid(4),
              attempt: 0,
              scanType: "sbom",
              sourceDir: env.tree(),
            }),
            {
              signal: new AbortController().signal,
              log() {},
              emit() {},
              platform: {
                tenantId: TENANT_A,
                deadlineEpoch: Math.floor(Date.now() / 1000) + 100,
                secondsToDeadline: 100,
                maxItems: 1000,
              },
            },
          );
          same(
            p,
            "unresolvable image",
            [statusOf(r).trivy, runs(r).trivy.imageDigest, runs(r).trivy.toolVersion],
            ["unavailable/image_unavailable", null, "unknown"],
          );
          const only = (ids) =>
            runManifestSha256({
              ensembleVersion: "1",
              tools: r.ensemble.toolRuns
                .filter((t) => ids.includes(t.toolId))
                .map((t) => ({
                  toolId: t.toolId,
                  toolVersion: t.toolVersion,
                  imageDigest: t.imageDigest,
                  configDigest: t.configDigest,
                })),
            });
          same(
            p,
            "the manifest names only the tools that could be resolved",
            r.ensemble.runManifestSha256,
            only(["syft", "sbom-lite"]),
          );
          for (const bad of ["relative/rules", "", 5, null]) {
            let threw = false;
            try {
              createEnsembleSbomEngine({
                runner: env.runner,
                gate: env.gate,
                resolver,
                rulesDir: bad,
              });
            } catch (e) {
              threw = e instanceof TypeError;
            }
            ok(p, threw, `rulesDir ${JSON.stringify(bad)} must be refused`);
          }
          let noPlatform = null;
          try {
            await env.engine.runTask(
              Object.freeze({
                executionId: uuid(9),
                taskId: uuid(4),
                attempt: 0,
                scanType: "sbom",
                sourceDir: env.tree(),
              }),
              { signal: new AbortController().signal, log() {}, emit() {} },
            );
          } catch (e) {
            noPlatform = e instanceof TypeError;
          }
          same(p, "no platform facts", noPlatform, true);
          for (const [code, want] of [
            [300, null],
            [256, null],
            [255, 255],
            [1, 1],
            [-1, null],
          ]) {
            const oddEnv = makeEnv({ scripts: { trivy: { exitCode: code } } });
            try {
              const odd = await oddEnv.run();
              same(
                p,
                `exit code ${code}`,
                [statusOf(odd).trivy, runs(odd).trivy.exitCode],
                ["failed/exit_code", want],
              );
            } finally {
              oddEnv.cleanup();
            }
          }
        } finally {
          env.cleanup();
        }
      }
      // ---- the in-process inventory: truncated and incomplete are partial, an abort cancels it with the right reason
      for (const [label, ret, want] of [
        [
          "truncated",
          { truncated: true, incomplete: false, summary: {} },
          "partial/output_too_large",
        ],
        [
          "incomplete",
          { truncated: false, incomplete: true, summary: {} },
          "partial/output_invalid",
        ],
        ["clean", { truncated: false, incomplete: false, summary: {} }, "succeeded"],
      ]) {
        const env = makeEnv({
          inventory: async (_i, hooks) => {
            hooks.emit({ path: "package-lock.json", componentPurl: "pkg:npm/lodash@4.17.20" });
            return ret;
          },
        });
        try {
          const r = await env.run();
          same(
            p,
            `inventory ${label}`,
            [statusOf(r)["sbom-lite"], runs(r)["sbom-lite"].truncated],
            [want, label === "truncated"],
          );
          same(
            p,
            `inventory ${label} roll-up`,
            r.ensemble.rollup.completeness,
            label === "clean" ? "complete" : "incomplete",
          );
        } finally {
          env.cleanup();
        }
      }
      for (const [reason, want] of [
        ["user_cancelled", "cancelled/cancelled"],
        ["task_deadline", "cancelled/deadline"],
      ]) {
        const ac = new AbortController();
        const env = makeEnv({
          inventory: async () => {
            ac.abort(new Error(reason));
            return { truncated: false, incomplete: false, summary: {} };
          },
        });
        try {
          const r = await env.run({ signal: ac.signal });
          same(p, `inventory abort ${reason}`, statusOf(r)["sbom-lite"], want);
        } finally {
          env.cleanup();
        }
      }
      // ---- a straggler of this attempt that the runner never started is removed by the abort (labels are 1-based)
      {
        const env = makeEnv({ scripts: { syft: { hang: true }, trivy: { hang: true } } });
        try {
          const ac = new AbortController();
          const done = env.run({ signal: ac.signal, taskId: uuid(6), attempt: 2 });
          await sleep(60);
          const label = (attempt) => ({
            "qm.scan": "1",
            "qm.tenant": TENANT_A,
            "qm.execution": uuid(9),
            "qm.task": uuid(6),
            "qm.tool": "syft",
            "qm.attempt": String(attempt),
            "qm.deadline": String(Math.floor(Date.now() / 1000) + 600),
          });
          env.runtime.seed("straggler-now", label(3));
          env.runtime.seed("straggler-other-attempt", label(2));
          ac.abort(new Error("user_cancelled"));
          await Promise.race([done, sleep(3000)]);
          ok(
            p,
            !env.runtime.containers.has("straggler-now"),
            "the abort left a straggler of this attempt",
          );
          ok(
            p,
            env.runtime.containers.has("straggler-other-attempt"),
            "the abort removed a container of another attempt",
          );
          ok(
            p,
            env.runtime.calls
              .filter((c) => c.type === "run")
              .every((c) => c.spec.labels.attempt === 3),
            "containers carry the 1-based attempt",
          );
        } finally {
          env.cleanup();
        }
      }
      // ---- crash of the runner process: only the janitor can end the containers
      {
        const env = makeEnv({ scripts: { syft: { hang: true }, trivy: { hang: true } } });
        try {
          const ac = new AbortController();
          const done = env.run({ signal: ac.signal, taskId: uuid(2) });
          await sleep(60);
          env.runtime.forgetRunnerState();
          env.runtime.seed("unrelated", { app: "other" });
          const running = new Set();
          const janitor = createJanitor({
            runtime: env.runtime,
            isAttemptRunning: async ({ taskId }) => running.has(taskId),
          });
          running.add(uuid(2));
          let sweep = await janitor.sweep();
          same(p, "janitor keeps a running attempt", [sweep.removed.length, sweep.kept], [0, 2]);
          running.clear();
          sweep = await janitor.sweep();
          same(p, "janitor removes the orphans", sweep.removed.length, 2);
          ok(
            p,
            env.runtime.containers.has("unrelated"),
            "the janitor touched an unlabelled container",
          );
          ac.abort(new Error("user_cancelled"));
          await Promise.race([done, sleep(3000)]);
        } finally {
          env.cleanup();
        }
      }
      // ---- the janitor started by the wiring
      {
        const env = makeEnv();
        try {
          const queries = [];
          const db = { $queryRaw: async (...args) => (queries.push(args.length), []) };
          const config = {
            scanEngines: {
              sandbox: {
                runtimeBin: "podman",
                containerUser: "65534:65534",
                usernsMode: "keep-id",
                uidMap: [],
                gidMap: [],
                seccompProfile: null,
              },
              archiveRoot: path.join(env.base, "scan"),
              rulesDir: env.rulesDir,
              maxContainers: 4,
              maxContainersPerTenant: 2,
              untrustedCapacityShare: 50,
              toolParallelism: 2,
              waitSeconds: 1,
              janitorSeconds: 0.05,
              production: false,
            },
          };
          env.runtime.seed("orphan", {
            "qm.scan": "1",
            "qm.tenant": TENANT_A,
            "qm.execution": uuid(9),
            "qm.task": uuid(5),
            "qm.tool": "syft",
            "qm.attempt": "1",
            "qm.deadline": String(Math.floor(Date.now() / 1000) + 600),
          });
          const slow = buildEnsembleEngine({
            config: { scanEngines: { ...config.scanEngines, janitorSeconds: 30 } },
            db,
            runtime: env.runtime,
            logger: undefined,
          });
          const stopSlow = slow.startJanitor();
          await sleep(120);
          ok(
            p,
            !env.runtime.containers.has("orphan"),
            "the janitor did not sweep at once (a 30 second interval)",
          );
          same(p, "one sweep so far", env.runtime.calls.filter((c) => c.type === "list").length, 1);
          stopSlow();
          env.runtime.seed("orphan", {
            "qm.scan": "1",
            "qm.tenant": TENANT_A,
            "qm.execution": uuid(9),
            "qm.task": uuid(5),
            "qm.tool": "syft",
            "qm.attempt": "1",
            "qm.deadline": String(Math.floor(Date.now() / 1000) + 600),
          });
          const built = buildEnsembleEngine({
            config,
            db,
            runtime: env.runtime,
            logger: undefined,
          });
          const stop = built.startJanitor();
          await sleep(250);
          ok(
            p,
            !env.runtime.containers.has("orphan"),
            "the started janitor did not remove the orphan of a task that is not running",
          );
          const lists = env.runtime.calls.filter((c) => c.type === "list").length;
          ok(p, lists >= 2, `the janitor must sweep at start and again (${lists})`);
          stop();
          const after = env.runtime.calls.filter((c) => c.type === "list").length;
          await sleep(200);
          same(
            p,
            "no sweep after stop",
            env.runtime.calls.filter((c) => c.type === "list").length,
            after,
          );
          ok(p, typeof built.engine.runTask === "function", "the wiring returns the engine");
        } finally {
          env.cleanup();
        }
      }
      return p;
    },
  },
  {
    id: "ENG-S14b",
    name: "the ensemble engine respects the capacity limits and reports a tool that waits too long as unavailable / capacity (SPEC scan-engines 5.8 SE-16 to SE-20, 14.1 ENG-S14, part K core; fake runtime): with a worker limit of one container two concurrent tasks never run two containers at once and both complete; with a per-tenant limit of one a tenant's two tasks never overlap while another tenant's task runs beside them; with a fork share of one two fork tasks never overlap while a trusted task is not held up by them; per task at most the configured number of tools run at once; a tool that cannot get capacity within the wait is unavailable with the reason capacity (transient) and the inventory tool still produces the result (row 6), and all container tools unavailable plus a failing inventory is row 7 failed / tools_failed (permanent: the inventory's output_invalid is a permanent reason, so the transient class of table 5.4 needs every tool, including the always-present inventory, to fail transiently)",
    async run() {
      const p = [];
      const track = (runtime) => {
        const state = {
          now: 0,
          max: 0,
          byTenant: new Map(),
          maxTenant: new Map(),
          fork: 0,
          maxFork: 0,
        };
        const orig = runtime.run.bind(runtime);
        runtime.run = async (spec, opts) => {
          state.now += 1;
          state.max = Math.max(state.max, state.now);
          const t = spec.labels.tenantId;
          const cur = (state.byTenant.get(t) ?? 0) + 1;
          state.byTenant.set(t, cur);
          state.maxTenant.set(t, Math.max(state.maxTenant.get(t) ?? 0, cur));
          try {
            return await orig(spec, opts);
          } finally {
            state.now -= 1;
            state.byTenant.set(t, state.byTenant.get(t) - 1);
          }
        };
        return state;
      };
      // worker limit 1
      {
        const env = makeEnv({
          gate: { perWorker: 1 },
          toolWaitMs: 5000,
          scripts: { syft: { delayMs: 60 }, trivy: { delayMs: 60 } },
        });
        try {
          const s = track(env.runtime);
          const results = await Promise.all([
            env.run({ taskId: uuid(1), tenantId: TENANT_A }),
            env.run({ taskId: uuid(2), tenantId: TENANT_B }),
          ]);
          same(p, "worker limit: max concurrent containers", s.max, 1);
          ok(
            p,
            results.every(
              (r) => statusOf(r).syft === "succeeded" && statusOf(r).trivy === "succeeded",
            ),
            "worker limit: every tool must complete",
          );
          same(p, "the gate is drained", env.gate.snapshot().worker, 0);
        } finally {
          env.cleanup();
        }
      }
      // tenant limit 1: tenant A's two tasks never overlap, tenant B runs beside
      {
        const env = makeEnv({
          gate: { perWorker: 4, perTenant: 1, perTask: 2 },
          toolWaitMs: 5000,
          scripts: { syft: { delayMs: 60 }, trivy: { delayMs: 60 } },
        });
        try {
          const s = track(env.runtime);
          await Promise.all([
            env.run({ taskId: uuid(1), tenantId: TENANT_A }),
            env.run({ taskId: uuid(2), tenantId: TENANT_A }),
            env.run({ taskId: uuid(3), tenantId: TENANT_B }),
          ]);
          same(p, "tenant limit: tenant A", s.maxTenant.get(TENANT_A), 1);
          ok(p, s.max >= 2, `tenant limit: another tenant must run beside (max ${s.max})`);
        } finally {
          env.cleanup();
        }
      }
      // fork share 1
      {
        const env = makeEnv({
          gate: { perWorker: 4, perTenant: 4, perTask: 2, forkShare: 1 },
          toolWaitMs: 5000,
          scripts: { syft: { delayMs: 80 }, trivy: { delayMs: 80 } },
        });
        try {
          let forks = 0;
          let maxForks = 0;
          const orig = env.runtime.run.bind(env.runtime);
          env.runtime.run = async (spec, opts) => {
            const isFork = spec.labels.taskId.startsWith("00000015");
            if (isFork) maxForks = Math.max(maxForks, (forks += 1));
            try {
              return await orig(spec, opts);
            } finally {
              if (isFork) forks -= 1;
            }
          };
          const t0 = Date.now();
          const [, , trusted] = await Promise.all([
            env.run({ taskId: uuid(15), fork: true, tenantId: TENANT_A }),
            env.run({ taskId: uuid(15, "1"), fork: true, tenantId: TENANT_B }),
            env.run({ taskId: uuid(3), fork: false, tenantId: TENANT_B }),
          ]);
          same(p, "fork share", maxForks, 1);
          ok(
            p,
            statusOf(trusted).syft === "succeeded" && Date.now() - t0 < 3000,
            "a trusted task is not held up by forks",
          );
        } finally {
          env.cleanup();
        }
      }
      // per task parallelism 1: the two tools of one task run one after the other
      {
        const env = makeEnv({
          gate: { perWorker: 4, perTenant: 4, perTask: 1 },
          toolWaitMs: 5000,
          scripts: { syft: { delayMs: 50 }, trivy: { delayMs: 50 } },
        });
        try {
          const s = track(env.runtime);
          await env.run();
          same(p, "per task limit", s.max, 1);
        } finally {
          env.cleanup();
        }
      }
      // waiting too long: capacity, transient; the inventory tool still answers (row 6)
      {
        const env = makeEnv({
          gate: { perWorker: 1 },
          toolWaitMs: 40,
          scripts: { syft: { delayMs: 400 }, trivy: { delayMs: 400 } },
        });
        try {
          const [a, b] = await Promise.all([
            env.run({ taskId: uuid(1), tenantId: TENANT_A }),
            env.run({ taskId: uuid(2), tenantId: TENANT_B }),
          ]);
          const unavailable = [a, b]
            .flatMap((r) => r.ensemble.toolRuns)
            .filter((t) => t.status === "unavailable");
          ok(
            p,
            unavailable.length >= 2 &&
              unavailable.every((t) => t.reason === "capacity" && t.capacityWaitMs >= 30),
            "waiting tools must be unavailable / capacity with their wait recorded",
          );
          const loser = [a, b].find((r) =>
            r.ensemble.toolRuns.some((t) => t.status === "unavailable"),
          );
          same(
            p,
            "capacity roll-up",
            [
              loser.status,
              loser.ensemble.rollup.matchedRow,
              loser.ensemble.rollup.toolsDegraded >= 1,
            ],
            ["succeeded", 6, true],
          );
          ok(
            p,
            loser.ensemble.toolRuns.every((t) => toolRunProblems(t).length === 0),
            "records of a capacity wait must satisfy the table checks",
          );
        } finally {
          env.cleanup();
        }
      }
      // every container tool unavailable (capacity) and the inventory fails: row 7, transient
      {
        const env = makeEnv({
          gate: { perWorker: 1 },
          toolWaitMs: 30,
          scripts: { syft: { delayMs: 500 }, trivy: { delayMs: 500 } },
          inventory: async () => {
            throw new Error("inventory broken");
          },
        });
        try {
          const hold = await env.gate.acquire(
            { tenantId: TENANT_B, taskId: uuid(8) },
            { timeoutMs: 100 },
          );
          const r = await env.run({ taskId: uuid(1) });
          hold();
          same(
            p,
            "all tools failed (capacity: transient; the failed inventory does not decide the class, D-23 (1))",
            [
              r.status,
              r.ensemble.rollup.taskStatus,
              r.ensemble.rollup.reason,
              r.ensemble.rollup.errorClass,
              r.ensemble.rollup.matchedRow,
            ],
            ["failed", "failed", "tools_failed", "transient", 7],
          );
          same(
            p,
            "reasons",
            [statusOf(r).syft, statusOf(r).trivy, statusOf(r)["sbom-lite"]],
            ["unavailable/capacity", "unavailable/capacity", "failed/output_invalid"],
          );
        } finally {
          env.cleanup();
        }
      }
      return p;
    },
  },
  {
    id: "ENG-S11c",
    name: "the ensemble engine rolls tool statuses up exactly as table 5.4 says and records reproducible, database-shaped tool runs (SPEC scan-engines 5.3, 5.4, 5.10 SE-25, SE-26, 7.3, 14.1 ENG-S11, part K core; fake runtime, Part E adapters unchanged): all tools succeeded is row 5 complete with the coverage state complete, the engine version ensemble-sbom/1 and a run manifest of 64 hex; one tool exiting non-zero is row 6 (succeeded, incomplete, toolsDegraded 1, never resolution eligible) with its reason exit_code; both container tools failing with the inventory alive is still row 6; all three failing is row 7 failed / tools_failed whose class is permanent when any reason is (exit_code, output_invalid); an unparseable document fails that tool (output_invalid) and an oversize one is output_too_large; every tool run record has exactly the table columns, fixed reason words, a digest of the locked image, a configuration digest of the mounted rules, durations that add up and no credential shape; the manifest is the same for the same tools and differs when an image digest or configuration changes; the canonical document is the Syft document and only when Syft succeeded or was partial and the document fits 16 MiB",
    async run() {
      const p = [];
      const lock = JSON.parse(
        readFileSync(
          path.join(WORKERS, "execution/engines/ensemble/catalog/images.lock.json"),
          "utf8",
        ),
      ).images;
      const digestOf = (key) => lock.find((e) => e.key === key).digest;
      const shape = (r) => r.ensemble.toolRuns.flatMap(toolRunProblems);
      // all succeeded
      {
        const env = makeEnv();
        try {
          const r = await env.run();
          const st = statusOf(r);
          same(
            p,
            "all ok statuses",
            [st.syft, st.trivy, st["sbom-lite"]],
            ["succeeded", "succeeded", "succeeded"],
          );
          const ro = r.ensemble.rollup;
          same(
            p,
            "row 5",
            [ro.matchedRow, ro.taskStatus, ro.completeness, ro.toolsDegraded, ro.coverageState],
            [5, "succeeded", "complete", 0, "complete"],
          );
          same(p, "problems", shape(r), []);
          same(p, "coverage", r.ensemble.coverage, {
            state: "complete",
            coverageGaps: [],
            toolsDegraded: 0,
            tools: [
              { toolId: "syft", status: "succeeded" },
              { toolId: "trivy", status: "succeeded" },
              { toolId: "sbom-lite", status: "succeeded" },
            ],
          });
          ok(p, /^[0-9a-f]{64}$/.test(r.ensemble.runManifestSha256), "run manifest");
          same(p, "engine version", env.engine.version, "ensemble-sbom/1");
          same(
            p,
            "engine identity",
            [
              env.engine.scanType,
              env.engine.engineId,
              env.engine.needsPlatform,
              env.engine.idempotent,
            ],
            ["sbom", "default", true, true],
          );
          const t = runs(r);
          same(
            p,
            "locked digests",
            [t.syft.imageDigest, t.trivy.imageDigest, t["sbom-lite"].imageDigest],
            [digestOf("syft"), digestOf("trivy"), null],
          );
          same(
            p,
            "locked versions",
            [t.syft.toolVersion, t.trivy.toolVersion],
            [
              lock.find((e) => e.key === "syft").version,
              lock.find((e) => e.key === "trivy").version,
            ],
          );
          const rules = (f) =>
            createHash("sha256")
              .update(readFileSync(path.join(RULES, f)))
              .digest("hex");
          same(
            p,
            "config digests",
            [t.syft.configDigest, t.trivy.configDigest],
            [rules("syft.yaml"), rules("trivy.yaml")],
          );
          ok(
            p,
            r.items.length === FIXED.syftFindings && r.ensemble.details.length === r.items.length,
            `items ${r.items.length}, details ${r.ensemble.details.length}`,
          );
          ok(
            p,
            r.ensemble.details.every((d) => d.provenance.length >= 1) &&
              r.ensemble.details.some((d) => d.provenance.length === 3),
            "provenance entries per tool and a finding confirmed by all three",
          );
          ok(
            p,
            r.ensemble.document?.toolId === "syft" &&
              r.ensemble.document.bytes.toString("utf8") === SYFT_DOC,
            "the canonical document is the Syft document, byte for byte",
          );
          same(
            p,
            "exit codes",
            [t.syft.exitCode, t.trivy.exitCode, t["sbom-lite"].exitCode ?? null],
            [0, 0, null],
          );
          ok(
            p,
            t.syft.limits.cpus === 1 && t.syft.limits.wallClockSeconds === 120,
            "applied limits are recorded and capped by the task seconds",
          );
          ok(
            p,
            t.syft.scope.kind === "full" && t.syft.scope.paths === 0,
            "every tool scans the whole tree (narrowing is held)",
          );
        } finally {
          env.cleanup();
        }
      }
      // determinism and manifest sensitivity
      {
        const a = makeEnv();
        const b = makeEnv();
        try {
          const [ra, rb] = [await a.run(), await b.run()];
          same(
            p,
            "same tools, same manifest",
            ra.ensemble.runManifestSha256,
            rb.ensemble.runManifestSha256,
          );
          same(p, "same findings", ra.items, rb.items);
          writeFileSync(
            path.join(b.rulesDir, "syft.yaml"),
            `${readFileSync(path.join(RULES, "syft.yaml"), "utf8")}# changed\n`,
          );
          const c = makeEnv();
          writeFileSync(path.join(c.rulesDir, "syft.yaml"), "check-for-app-update: true\n");
          cpSync(c.rulesDir, b.rulesDir, { recursive: true });
          c.cleanup();
          const tools = [
            {
              toolId: "syft",
              toolVersion: "1",
              imageDigest: digestOf("syft"),
              configDigest: "a".repeat(64),
            },
          ];
          const m = (over) =>
            runManifestSha256({ ensembleVersion: "1", tools: [{ ...tools[0], ...over }] });
          ok(p, m({}) === m({}), "manifest is deterministic");
          for (const over of [
            { imageDigest: digestOf("trivy") },
            { configDigest: "b".repeat(64) },
            { toolVersion: "2" },
            { rulepackDigest: "c".repeat(64) },
            { dbSnapshotSha256: "d".repeat(64) },
          ])
            ok(p, m(over) !== m({}), `manifest ignores ${Object.keys(over)}`);
          ok(
            p,
            runManifestSha256({ ensembleVersion: "2", tools }) !== m({}),
            "manifest ignores the ensemble version",
          );
          for (const key of ["dbBuiltAt", "dbSnapshotSha256", "imageDigest", "rulepackDigest"])
            ok(
              p,
              m({ [key]: "" }) !== m({ [key]: null }),
              `manifest treats an empty ${key} like an absent one`,
            );
          ok(
            p,
            runManifestSha256({
              ensembleVersion: "1",
              tools: [tools[0], { ...tools[0], toolId: "trivy" }],
            }) ===
              runManifestSha256({
                ensembleVersion: "1",
                tools: [{ ...tools[0], toolId: "trivy" }, tools[0]],
              }),
            "manifest depends on tool order",
          );
        } finally {
          a.cleanup();
          b.cleanup();
        }
      }
      // one tool fails with an exit code: row 6
      {
        const env = makeEnv({ scripts: { trivy: { exitCode: 2 } } });
        try {
          const r = await env.run();
          same(p, "exit code failure", statusOf(r).trivy, "failed/exit_code");
          const ro = r.ensemble.rollup;
          same(
            p,
            "row 6",
            [
              ro.matchedRow,
              ro.taskStatus,
              ro.completeness,
              ro.toolsDegraded,
              ro.resolutionEligible,
              ro.coverageState,
            ],
            [6, "succeeded", "incomplete", 1, false, "degraded"],
          );
          same(p, "run exit code", runs(r).trivy.exitCode, 2);
          same(p, "problems", shape(r), []);
          ok(
            p,
            r.incomplete === true && r.items.length > 0,
            "an incomplete result keeps what the other tools found",
          );
        } finally {
          env.cleanup();
        }
      }
      // both container tools fail, the inventory lives
      {
        const env = makeEnv({ scripts: { syft: { runtimeFault: true }, trivy: { exitCode: 1 } } });
        try {
          const r = await env.run();
          same(
            p,
            "container tools down",
            [
              r.ensemble.rollup.matchedRow,
              r.ensemble.rollup.taskStatus,
              r.ensemble.rollup.toolsDegraded,
            ],
            [6, "succeeded", 2],
          );
          ok(
            p,
            r.ensemble.document === null && r.items.length > 0,
            "no Syft document without Syft, findings from the inventory",
          );
        } finally {
          env.cleanup();
        }
      }
      // everything fails: row 7, class by reason
      const failing = async (scripts, inventory) => {
        const env = makeEnv({
          scripts,
          inventory:
            inventory ??
            (async () => {
              throw new Error("x");
            }),
        });
        try {
          const r = await env.run();
          return {
            status: r.status,
            ro: r.ensemble.rollup,
            st: statusOf(r),
            shape: shape(r),
            items: r.items.length,
          };
        } finally {
          env.cleanup();
        }
      };
      const sandboxDown = await failing({
        syft: { runtimeFault: true },
        trivy: { runtimeFault: true },
      });
      same(
        p,
        "row 7 with a failed inventory",
        [
          sandboxDown.status,
          sandboxDown.ro.matchedRow,
          sandboxDown.ro.reason,
          sandboxDown.ro.errorClass,
          sandboxDown.ro.completeness,
        ],
        ["failed", 7, "tools_failed", "transient", null],
      );
      // owner decision 2026-11-20 (option A): the inventory's permanent failure word does NOT decide the retry class; the container
      // tools do. It still counts as a failed tool (toolsDegraded 3) and is recorded with its own reason.
      same(p, "all three tools count as failed", sandboxDown.ro.toolsDegraded, 3);
      ok(
        p,
        sandboxDown.st["sbom-lite"] === "failed/output_invalid",
        "the failed inventory is output_invalid",
      );
      same(
        p,
        "container tools transient, inventory permanent: the class is transient",
        [sandboxDown.st.syft, sandboxDown.st.trivy],
        ["failed/sandbox_error", "failed/sandbox_error"],
      );
      const mixed = await failing({ syft: { runtimeFault: true }, trivy: { exitCode: 4 } });
      same(
        p,
        "one transient and one permanent container tool: permanent",
        [mixed.ro.errorClass, mixed.st.syft, mixed.st.trivy],
        ["permanent", "failed/sandbox_error", "failed/exit_code"],
      );
      const permanent = await failing({ syft: { exitCode: 3 }, trivy: { exitCode: 4 } });
      same(
        p,
        "row 7 permanent",
        [permanent.ro.errorClass, permanent.st.syft, permanent.st.trivy],
        ["permanent", "failed/exit_code", "failed/exit_code"],
      );
      // a document that is not JSON, and an oversize one
      {
        const env = makeEnv({
          scripts: {
            syft: { stdout: "not json at all" },
            trivy: { stdout: "x".repeat(70 * 1024 * 1024) },
          },
        });
        try {
          const r = await env.run();
          const st = statusOf(r);
          same(
            p,
            "hostile documents",
            [st.syft, st.trivy],
            ["failed/output_invalid", "failed/output_too_large"],
          );
          ok(
            p,
            r.ensemble.document === null &&
              r.ensemble.toolRuns.every((t) => toolRunProblems(t).length === 0),
            "no document from a failed Syft, valid records",
          );
        } finally {
          env.cleanup();
        }
      }
      // the document ceiling is exact: 16 MiB is stored, one byte more is not
      for (const [extra, want] of [
        [0, true],
        [1, false],
      ]) {
        const base = JSON.parse(SYFT_DOC);
        base.pad = "";
        const head = Buffer.byteLength(JSON.stringify(base));
        const fitted = JSON.stringify({
          ...base,
          pad: "p".repeat(16 * 1024 * 1024 - head + extra),
        });
        same(p, `fixture size ${extra}`, Buffer.byteLength(fitted), 16 * 1024 * 1024 + extra);
        const env = makeEnv({ scripts: { syft: { stdout: fitted } } });
        try {
          const r = await env.run();
          same(
            p,
            `document of ${16 * 1024 * 1024 + extra} bytes`,
            r.ensemble.document !== null,
            want,
          );
        } finally {
          env.cleanup();
        }
      }
      // the document ceiling: a Syft document above 16 MiB is parsed (it is within the parse caps) but never stored
      {
        const big = JSON.stringify({ ...JSON.parse(SYFT_DOC), pad: "p".repeat(17 * 1024 * 1024) });
        const env = makeEnv({ scripts: { syft: { stdout: big } } });
        try {
          const r = await env.run();
          same(
            p,
            "big Syft document",
            [statusOf(r).syft, r.ensemble.document],
            ["succeeded", null],
          );
          ok(p, r.items.length > 0, "a big document does not cost the findings");
        } finally {
          env.cleanup();
        }
      }
      return p;
    },
  },
  {
    id: "ENG-S06g",
    name: "ensemble results never cross a task, tenant or pipeline in the worker path (SPEC scan-engines 5.6, SE-12, 14.1 ENG-S06, part K core; fake runtime): two tasks of two tenants run concurrently on the SAME engine instance with different tool outputs, and each result holds only its own components, its own tool run ids (the raw reference of every detail row names a tool run of that task), its own run manifest inputs and no component of the other; a component only task A reports never appears for task B, in either order and under concurrency; the engine, the wiring, the run manifest and the changed-paths module hold no module-level mutable state (no let or var, no map, set or array at module level), read no environment, and the engine imports no process, file-system write or network module",
    async run() {
      const p = [];
      const only = (name, version) => ({
        "bom-ref": `x-${name}`,
        type: "library",
        name,
        version,
        purl: `pkg:npm/${name}@${version}`,
        properties: [{ name: "syft:location:0:path", value: "/package-lock.json" }],
      });
      const docWith = (extra) => {
        const d = JSON.parse(SYFT_DOC);
        d.components.push(extra);
        return JSON.stringify(d);
      };
      const env = makeEnv({ gate: { perWorker: 8, perTenant: 8, perTask: 2 } });
      try {
        const outputs = new Map([
          [uuid(1), docWith(only("only-in-task-a", "1.0.0"))],
          [uuid(2), docWith(only("only-in-task-b", "2.0.0"))],
        ]);
        env.runtime.scriptBy((spec) =>
          spec.toolId === "syft"
            ? { exitCode: 0, stdout: outputs.get(spec.labels.taskId), delayMs: 20 }
            : undefined,
        );
        const [a, b] = await Promise.all([
          env.run({ taskId: uuid(1), tenantId: TENANT_A }),
          env.run({ taskId: uuid(2), tenantId: TENANT_B }),
        ]);
        const purls = (r) => r.items.map((i) => i.componentPurl);
        ok(
          p,
          purls(a).includes("pkg:npm/only-in-task-a@1.0.0") &&
            !purls(a).includes("pkg:npm/only-in-task-b@2.0.0"),
          "task A holds its own component and none of B's",
        );
        ok(
          p,
          purls(b).includes("pkg:npm/only-in-task-b@2.0.0") &&
            !purls(b).includes("pkg:npm/only-in-task-a@1.0.0"),
          "task B holds its own component and none of A's",
        );
        for (const [label, r] of [
          ["A", a],
          ["B", b],
        ]) {
          const ids = new Set(r.ensemble.toolRuns.map((t) => t.id));
          ok(p, ids.size === 3, `${label}: three distinct tool run ids`);
          ok(
            p,
            r.ensemble.details.every(
              (d) =>
                ids.has(d.extra.rawRef.toolRunId) &&
                d.provenance.every((x) => ids.has(x.rawRef.toolRunId)),
            ),
            `${label}: a detail row points at a tool run of another task`,
          );
        }
        const idsA = new Set(a.ensemble.toolRuns.map((t) => t.id));
        ok(
          p,
          b.ensemble.toolRuns.every((t) => !idsA.has(t.id)),
          "tool run ids are never shared between tasks",
        );
        // reversed order, sequential
        const b2 = await env.run({ taskId: uuid(2), tenantId: TENANT_B });
        const a2 = await env.run({ taskId: uuid(1), tenantId: TENANT_A });
        same(p, "a second run of B has the same components", purls(b2), purls(b));
        same(p, "a second run of A has the same components", purls(a2), purls(a));
        // the labels of the containers carry the right tenant and task
        const runsSeen = env.runtime.calls.filter(
          (c) => c.type === "run" && c.spec.toolId === "syft",
        );
        ok(
          p,
          runsSeen.every(
            (c) => (c.spec.labels.taskId === uuid(1)) === (c.spec.labels.tenantId === TENANT_A),
          ),
          "a container label mixes tenant and task",
        );
      } finally {
        env.cleanup();
      }
      // source guards
      const files = [
        ...readdirSync(ENGINE_DIR).map((f) => path.join(ENGINE_DIR, f)),
        path.join(WORKERS, "execution/changed-paths.js"),
      ];
      for (const file of files) {
        const src = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
        const name = path.relative(ROOT, file);
        ok(p, !/^(let|var)\s/m.test(src), `${name}: a module-level let or var`);
        ok(
          p,
          !/^(const|export const) [A-Za-z_]+ = (new (Map|Set|WeakMap)\(|\[)/m.test(src),
          `${name}: a mutable collection at module level`,
        );
        ok(p, !/process\.env|process\.argv/.test(src), `${name}: reads the process environment`);
        ok(
          p,
          !/child_process|node:net|node:http|node:https|node:dgram|node:dns|node:tls|\bfetch\(/.test(
            src,
          ),
          `${name}: imports a process or network module`,
        );
        ok(
          p,
          !/\b(writeFile|writeFileSync|appendFile|rmSync|unlinkSync|mkdirSync)\b/.test(src),
          `${name}: writes the file system`,
        );
        ok(p, !/\beval\s*\(|new Function|\bimport\s*\(/.test(src), `${name}: dynamic code`);
      }
      return p;
    },
  },
  {
    id: "ENG-S05b",
    name: "no secret reaches a tool run record, the coverage, the manifest, the log or a stored row of the ensemble engine (SPEC scan-engines 5.3, 7.3, 11, 14.1 ENG-S05, part K core; fake runtime): canary secrets planted in the stdout and stderr of both tools (property values, a cataloger name, component fields, metadata, an error line), in a file name of the tree and in the tool's exit text never appear, in plain, base64, hex, URL-encoded or reversed form, in any tool run record, the coverage statement, the run manifest, the roll-up, the items, the detail rows or the lines the engine logs; a tool run record has exactly the table columns and fixed reason words (no stdout, stderr or message text), the engine never logs tool output, and a credential-shaped cataloger name is redacted before it is stored",
    async run() {
      const p = [];
      const secret = "ghp_Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7Zq7";
      const variants = [
        secret,
        Buffer.from(secret).toString("base64"),
        Buffer.from(secret).toString("hex"),
        encodeURIComponent(secret),
        [...secret].reverse().join(""),
      ];
      const d = JSON.parse(SYFT_DOC);
      d.metadata.properties.push({ name: "qm:secret", value: secret });
      for (const c of d.components) {
        c.properties = [
          ...(c.properties ?? []),
          { name: "qm:secret", value: secret },
          { name: "syft:package:foundBy", value: secret },
        ];
      }
      const t = JSON.parse(TRIVY_DOC);
      for (const c of t.components)
        c.properties = [...(c.properties ?? []), { name: "qm:secret", value: secret }];
      const env = makeEnv({
        scripts: {
          syft: {
            stdout: JSON.stringify(d),
            stderr: `warn token=${secret}\nAuthorization: Bearer ${secret}\n`,
          },
          trivy: { stdout: JSON.stringify(t), stderr: `fatal ${secret}\n` },
        },
      });
      try {
        const r = await env.run({ files: { ...TREE_FILES, [`config-${secret}.txt`]: "x" } });
        const sinks = JSON.stringify({
          runs: r.ensemble.toolRuns,
          coverage: r.ensemble.coverage,
          manifest: r.ensemble.runManifestSha256,
          rollup: r.ensemble.rollup,
          items: r.items,
          details: r.ensemble.details,
          logs: env.logs,
        });
        for (const v of variants)
          ok(p, !sinks.includes(v), `a secret form (${v.slice(0, 8)}...) reached a sink`);
        ok(
          p,
          r.ensemble.toolRuns.every((x) =>
            Object.keys(x).every((k) => !/^(stdout|stderr|message|output|text|log)/i.test(k)),
          ),
          "a tool run record carries tool text",
        );
        ok(
          p,
          r.ensemble.toolRuns.every((x) => toolRunProblems(x).length === 0),
          "a tool run record is malformed",
        );
        ok(
          p,
          findCredentials({
            runs: r.ensemble.toolRuns,
            coverage: r.ensemble.coverage,
            details: r.ensemble.details,
            items: r.items,
          }).length === 0,
          "a credential shape in a stored row",
        );
        const lite = r.ensemble.toolRuns.find((x) => x.toolId === "sbom-lite");
        same(
          p,
          "reasons are fixed words",
          r.ensemble.toolRuns.every((x) => x.reason === null || TOOL_REASONS.includes(x.reason)),
          true,
        );
        void lite;
        ok(
          p,
          r.ensemble.details.every((x) =>
            x.provenance.every((e) => e.ruleId === undefined || !/ghp_/.test(e.ruleId)),
          ),
          "a credential-shaped cataloger name was kept",
        );
      } finally {
        env.cleanup();
      }
      return p;
    },
  },
  {
    id: "ENG-S16a",
    name: "the changed-paths artifact contract fails closed and is tenant scoped (SPEC scan-engines 5.9 SE-22 to SE-24, owner decision D-7, part K core): a full run records nothing; a complete diff is stored sorted and de-duplicated with renamed files named by both paths; more than 3000 paths, a list over 512 KiB, an unsafe path (traversal, absolute, control, backslash), a truncated diff and an unavailable diff give NO list and the statuses truncated or unavailable; credential-shaped path text is redacted; a failed write is unavailable and never throws; the reader returns the list only for a complete status, the fixed artifact name and a valid document (strict schema, total equal to the paths, safe paths, bounded size and depth), and every damaged, oversize, foreign, missing or tampered case is unavailable with an empty list, never a partial one; the store is keyed by tenant and execution so another tenant or execution reads nothing; with no decision, or a decision from before the column, the reader says not_recorded",
    async run() {
      const p = [];
      const store = () => {
        const objects = new Map();
        return {
          objects,
          async put(ref, content, options) {
            const key = `${ref.tenantId}/${ref.executionId}/${ref.name}`;
            if (options?.ifAbsent && objects.has(key)) return { created: false };
            if (Buffer.byteLength(content) > (options?.maxBytes ?? Infinity))
              throw new Error("too large");
            objects.set(key, Buffer.from(content));
            return { created: true };
          },
          open(ref) {
            const key = `${ref.tenantId}/${ref.executionId}/${ref.name}`;
            if (!objects.has(key)) throw Object.assign(new Error("none"), { code: "ENOENT" });
            return (async function* () {
              yield objects.get(key);
            })();
          },
        };
      };
      const files = (list) =>
        list.map((f) => (typeof f === "string" ? { path: f, previousPath: null } : f));
      const built = (diffStatus, list) => buildChangedPaths({ diffStatus, files: files(list) });
      same(p, "full run", built("not_needed", []), { status: null });
      same(p, "truncated diff", built("truncated", []), { status: "truncated", document: null });
      same(p, "unavailable diff", built("unavailable", []), {
        status: "unavailable",
        document: null,
      });
      same(p, "unknown status", built("weird", []), { status: "unavailable", document: null });
      same(p, "not an array", buildChangedPaths({ diffStatus: "complete", files: null }), {
        status: "unavailable",
        document: null,
      });
      const good = built("complete", [
        "b/x.js",
        "a/y.js",
        "b/x.js",
        { path: "new/name.js", previousPath: "old/name.js" },
      ]);
      same(p, "complete", good, {
        status: "complete",
        document: {
          schemaVersion: 1,
          total: 4,
          paths: ["a/y.js", "b/x.js", "new/name.js", "old/name.js"],
        },
      });
      same(p, "empty complete list", built("complete", []), {
        status: "complete",
        document: { schemaVersion: 1, total: 0, paths: [] },
      });
      const many = Array.from({ length: CHANGED_PATHS_MAX + 1 }, (_, i) => `src/f${i}.js`);
      same(p, "over the cap", built("complete", many).status, "truncated");
      same(
        p,
        "exactly the cap",
        built("complete", many.slice(0, CHANGED_PATHS_MAX)).status,
        "complete",
      );
      same(
        p,
        "over the byte cap",
        built(
          "complete",
          Array.from({ length: 700 }, (_, i) => `${"d".repeat(1000)}/${i}.js`),
        ).status,
        "truncated",
      );
      for (const bad of ["../x", "/abs", "a//b", "a\\b", "a/./b", "a\u0000b", "a/../b", ""])
        same(
          p,
          `unsafe path ${JSON.stringify(bad)}`,
          built("complete", ["ok.js", bad]).status,
          "truncated",
        );
      same(p, "non-string path", built("complete", [{ path: 5 }]).status, "truncated");
      // the byte cap is exact (512 KiB of JSON): the document that fits is complete, one byte more is not; the reader agrees
      const CAP = 512 * 1024;
      const sized = (extra) => {
        const list = [];
        const doc = () =>
          JSON.stringify({ schemaVersion: 1, total: list.length, paths: [...list].sort() });
        for (let i = 0; ; i += 1) {
          list.push(`src/${"mod-".repeat(50)}${String(i).padStart(4, "0")}.js`);
          if (Buffer.byteLength(doc()) > CAP - 600) break;
        }
        const deficit = CAP + extra - Buffer.byteLength(doc());
        // the filler is made of short segments (a long unbroken token would be redacted)
        list[list.length - 1] =
          `${list[list.length - 1].slice(0, -3)}${"ab/".repeat(Math.floor(deficit / 3))}${"a".repeat(deficit % 3)}.js`;
        return Buffer.byteLength(doc()) === CAP + extra ? list : null;
      };
      const exact = sized(0);
      ok(
        p,
        exact !== null &&
          buildChangedPaths({ diffStatus: "complete", files: exact.map((x) => ({ path: x })) })
            .status === "complete",
        "a list of exactly 512 KiB is complete",
      );
      const over = sized(1);
      ok(
        p,
        over !== null &&
          buildChangedPaths({ diffStatus: "complete", files: over.map((x) => ({ path: x })) })
            .status === "truncated",
        "a list of 512 KiB plus a byte is truncated",
      );
      const readCap = async (extra) => {
        const t = store();
        const doc = JSON.stringify({
          schemaVersion: 1,
          total: exact.length,
          paths: [...exact].sort(),
        });
        t.objects.set(
          `${TENANT_A}/${uuid(9)}/${CHANGED_PATHS_NAME}`,
          Buffer.from(doc + " ".repeat(extra)),
        );
        return (
          await readChangedPaths({
            artifacts: t,
            tenantId: TENANT_A,
            executionId: uuid(9),
            decision: { changedPathsRef: CHANGED_PATHS_NAME, changedPathsStatus: "complete" },
          })
        ).status;
      };
      same(p, "reader at the byte cap", await readCap(0), "complete");
      same(p, "reader one byte over the byte cap", await readCap(1), "unavailable");
      const redacted = built("complete", [`src/${"ghp_"}${"A1b2".repeat(6)}.txt`]);
      ok(
        p,
        redacted.status !== "complete" || !JSON.stringify(redacted).includes("A1b2A1b2"),
        "a credential-shaped path was kept",
      );
      // write
      const s = store();
      const ref = { tenantId: TENANT_A, executionId: uuid(9) };
      same(
        p,
        "write full",
        await writeChangedPaths({ artifacts: s, ...ref, built: built("not_needed", []) }),
        { ref: null, status: null },
      );
      same(
        p,
        "write truncated",
        await writeChangedPaths({ artifacts: s, ...ref, built: built("truncated", []) }),
        { ref: null, status: "truncated" },
      );
      same(p, "nothing written", s.objects.size, 0);
      same(p, "write complete", await writeChangedPaths({ artifacts: s, ...ref, built: good }), {
        ref: CHANGED_PATHS_NAME,
        status: "complete",
      });
      same(
        p,
        "write again keeps the first",
        await writeChangedPaths({ artifacts: s, ...ref, built: built("complete", ["other.js"]) }),
        { ref: CHANGED_PATHS_NAME, status: "complete" },
      );
      same(
        p,
        "a failing store",
        await writeChangedPaths({
          artifacts: {
            put: async () => {
              throw new Error("db down");
            },
          },
          ...ref,
          built: good,
        }),
        { ref: null, status: "unavailable" },
      );
      // read
      const decision = { changedPathsRef: CHANGED_PATHS_NAME, changedPathsStatus: "complete" };
      same(p, "read", await readChangedPaths({ artifacts: s, ...ref, decision }), {
        status: "complete",
        paths: ["a/y.js", "b/x.js", "new/name.js", "old/name.js"],
      });
      same(p, "no decision", await readChangedPaths({ artifacts: s, ...ref, decision: null }), {
        status: "not_recorded",
        paths: [],
      });
      same(
        p,
        "decision from before the column",
        await readChangedPaths({ artifacts: s, ...ref, decision: {} }),
        { status: "not_recorded", paths: [] },
      );
      same(
        p,
        "truncated decision",
        await readChangedPaths({
          artifacts: s,
          ...ref,
          decision: { changedPathsStatus: "truncated", changedPathsRef: null },
        }),
        { status: "truncated", paths: [] },
      );
      same(
        p,
        "unavailable decision",
        await readChangedPaths({
          artifacts: s,
          ...ref,
          decision: { changedPathsStatus: "unavailable" },
        }),
        { status: "unavailable", paths: [] },
      );
      same(
        p,
        "garbage status",
        await readChangedPaths({ artifacts: s, ...ref, decision: { changedPathsStatus: "x" } }),
        { status: "unavailable", paths: [] },
      );
      same(
        p,
        "foreign tenant",
        await readChangedPaths({
          artifacts: s,
          tenantId: TENANT_B,
          executionId: ref.executionId,
          decision,
        }),
        { status: "unavailable", paths: [] },
      );
      same(
        p,
        "foreign execution",
        await readChangedPaths({
          artifacts: s,
          tenantId: TENANT_A,
          executionId: uuid(7),
          decision,
        }),
        { status: "unavailable", paths: [] },
      );
      same(
        p,
        "a ref that is not the fixed name",
        await readChangedPaths({
          artifacts: s,
          ...ref,
          decision: { changedPathsStatus: "complete", changedPathsRef: "other.json" },
        }),
        { status: "unavailable", paths: [] },
      );
      same(p, "no store", await readChangedPaths({ artifacts: null, ...ref, decision }), {
        status: "unavailable",
        paths: [],
      });
      const tamper = async (label, body) => {
        const t = store();
        t.objects.set(
          `${ref.tenantId}/${ref.executionId}/${CHANGED_PATHS_NAME}`,
          Buffer.from(typeof body === "string" ? body : JSON.stringify(body)),
        );
        same(p, `tampered: ${label}`, await readChangedPaths({ artifacts: t, ...ref, decision }), {
          status: "unavailable",
          paths: [],
        });
      };
      await tamper("not JSON", "{nope");
      await tamper("wrong version", { schemaVersion: 2, total: 0, paths: [] });
      await tamper("total differs", { schemaVersion: 1, total: 2, paths: ["a.js"] });
      await tamper("unknown key", { schemaVersion: 1, total: 0, paths: [], extra: 1 });
      await tamper("unsafe path", { schemaVersion: 1, total: 1, paths: ["../x"] });
      await tamper("paths not a list", { schemaVersion: 1, total: 0, paths: "x" });
      await tamper("too many paths", { schemaVersion: 1, total: 3001, paths: many });
      await tamper("prototype key", '{"schemaVersion":1,"total":0,"paths":[],"__proto__":{"x":1}}');
      await tamper("deep", `${"[".repeat(100)}${"]".repeat(100)}`);
      await tamper(
        "oversize",
        `{"schemaVersion":1,"total":0,"paths":[],"pad":"${"x".repeat(600 * 1024)}"}`,
      );
      await tamper("array", []);
      return p;
    },
  },
  {
    id: "ENG-S16b",
    name: "with the rollout flag off nothing changes and with it on only the scan worker's registry changes (SPEC scan-engines 5.10 SE-25, SE-28, D-12, part K core): the registry builder always holds the built-in SBOM engine as sbom/default and replaces it with the ensemble engine ONLY for a strictly true flag (false, absent, the string true, 1 and any other value keep the built-in engine and never call the factory), a missing factory with the flag on is refused, there is no fallback from the ensemble to the built-in engine at run time, the module-level registry is the built-in engine only and declares no platform need, the worker configuration defaults the flag to false, requires an absolute archive root and rules directory (outside the forbidden host paths) and consistent capacity limits only while the flag is on, rejects anything but true or false and never echoes a value, and the rollout environment variable is read in the configuration module only; the ensemble modules are imported by the engine wiring, the scan worker entry and the changed-paths module only",
    async run() {
      const p = [];
      const legacy = engineRegistry.get("sbom", "default");
      ok(
        p,
        legacy &&
          legacy.needsPlatform === undefined &&
          !String(legacy.version).startsWith("ensemble-"),
        "the module-level registry must hold the built-in engine",
      );
      same(p, "module-level registry size", engineRegistry.size, 1);
      let calls = 0;
      const factory = () => {
        calls += 1;
        return {
          scanType: "sbom",
          engineId: "default",
          version: "ensemble-sbom/test",
          runTask() {},
          needsPlatform: true,
        };
      };
      for (const flag of [false, undefined, "true", 1, "yes", null, {}]) {
        const reg = buildEngineRegistry({ ensembleEnabled: flag, createEnsembleEngine: factory });
        same(
          p,
          `flag ${JSON.stringify(flag)}`,
          [reg.get("sbom", "default").version === legacy.version, reg.size],
          [true, 1],
        );
      }
      same(p, "the factory was never called while off", calls, 0);
      const on = buildEngineRegistry({ ensembleEnabled: true, createEnsembleEngine: factory });
      same(
        p,
        "flag true",
        [on.get("sbom", "default").version, on.size, calls],
        ["ensemble-sbom/test", 1, 1],
      );
      try {
        buildEngineRegistry({ ensembleEnabled: true });
        p.push("the flag on without a factory was accepted");
      } catch (e) {
        ok(p, e instanceof TypeError, "a missing factory is a TypeError");
      }
      same(
        p,
        "the built-in engine is still registered when off",
        buildEngineRegistry().has("sbom", "sca"),
        false,
      );
      // configuration
      const base = {
        RABBITMQ_URL: "amqp://localhost",
        DATABASE_URL: "postgres://localhost/qm_test",
      };
      const off = loadWorkerConfig(base).scanEngines;
      same(
        p,
        "defaults",
        [
          off.ensembleEnabled,
          off.archiveRoot,
          off.rulesDir,
          off.toolParallelism,
          off.maxContainers,
          off.maxContainersPerTenant,
          off.untrustedCapacityShare,
          off.waitSeconds,
          off.janitorSeconds,
        ],
        [false, null, null, 2, 4, 2, 50, 120, 60],
      );
      const dir = mkdtempSync(path.join(os.tmpdir(), "qm-ens-cfg-"));
      try {
        const good = {
          ...base,
          SCAN_ENGINES_ENSEMBLE_ENABLED: "true",
          SANDBOX_ARCHIVE_ROOT: path.join(dir, "scan"),
          SANDBOX_RULES_DIR: path.join(dir, "rules"),
        };
        const on2 = loadWorkerConfig(good).scanEngines;
        same(
          p,
          "flag on",
          [on2.ensembleEnabled, on2.archiveRoot, on2.rulesDir],
          [true, good.SANDBOX_ARCHIVE_ROOT, good.SANDBOX_RULES_DIR],
        );
        for (const [label, over] of [
          ["no archive root", { SANDBOX_ARCHIVE_ROOT: undefined }],
          ["no rules dir", { SANDBOX_RULES_DIR: undefined }],
          ["relative root", { SANDBOX_ARCHIVE_ROOT: "scan" }],
          ["root under /etc", { SANDBOX_ARCHIVE_ROOT: "/etc/qm" }],
          ["root under /home", { SANDBOX_RULES_DIR: "/home/x/rules" }],
          [
            "tenant limit above the worker limit",
            { SCAN_RUNNER_MAX_CONTAINERS: "1", SCAN_RUNNER_MAX_CONTAINERS_PER_TENANT: "2" },
          ],
          ["flag yes", { SCAN_ENGINES_ENSEMBLE_ENABLED: "yes" }],
        ]) {
          try {
            loadWorkerConfig({ ...good, ...over });
            p.push(`${label}: accepted`);
          } catch (e) {
            ok(p, e instanceof ConfigError, `${label}: not a ConfigError`);
            const text = String(e.message);
            for (const v of Object.values(over).filter(
              (x) => typeof x === "string" && x.length > 3,
            ))
              ok(p, !text.includes(v), `${label}: the message echoes a value`);
          }
        }
        same(
          p,
          "production is derived from NODE_ENV",
          [
            loadWorkerConfig({ ...good, NODE_ENV: "production" }).scanEngines.production,
            on2.production,
          ],
          [true, false],
        );
        try {
          loadWorkerConfig({ ...good, SANDBOX_ARCHIVE_ROOT: "scan" });
        } catch (e) {
          ok(
            p,
            e.problems.some(
              (x) =>
                x.variable === "SANDBOX_ARCHIVE_ROOT" &&
                x.message ===
                  "an absolute path is required while SCAN_ENGINES_ENSEMBLE_ENABLED=true",
            ),
            "the message names the flag and the rule",
          );
        }
        same(
          p,
          "an empty value is kept, not turned into null",
          [
            loadWorkerConfig({ ...base, SANDBOX_ARCHIVE_ROOT: "", SANDBOX_RULES_DIR: "" })
              .scanEngines.archiveRoot,
            loadWorkerConfig({ ...base, SANDBOX_RULES_DIR: "" }).scanEngines.rulesDir,
          ],
          ["", ""],
        );
        // off: the extra settings are ignored, nothing is required
        const ignored = loadWorkerConfig({ ...base, SANDBOX_ARCHIVE_ROOT: "relative" }).scanEngines;
        same(p, "off ignores the roots", ignored.ensembleEnabled, false);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
      // the flag is read in the configuration only; the ensemble is imported by the wiring only
      const listJs = (d) =>
        readdirSync(d).flatMap((f) => {
          const x = path.join(d, f);
          return statSync(x).isDirectory() ? listJs(x) : x.endsWith(".js") ? [x] : [];
        });
      for (const file of listJs(WORKERS)) {
        const src = readFileSync(file, "utf8");
        const rel = path.relative(ROOT, file);
        if (!file.endsWith("config.js") && !file.includes("/ensemble/core/"))
          ok(
            p,
            !/SCAN_ENGINES_ENSEMBLE_ENABLED/.test(src),
            `${rel}: reads the rollout environment variable`,
          );
        if (file.includes("/ensemble/")) continue;
        if (
          /engines\/ensemble\/(engine|sbom|core)/.test(src) ||
          /ensemble\/engine\/wiring/.test(src)
        )
          ok(
            p,
            /scan\/index\.js$|execution\/changed-paths\.js$|execution\/scan-handler\.js$/.test(
              file,
            ) || file.endsWith("registry.js"),
            `${rel}: imports the ensemble outside the allowed modules`,
          );
      }
      const scanIndex = readFileSync(path.join(WORKERS, "scan/index.js"), "utf8");
      ok(
        p,
        /ensembleEnabled/.test(scanIndex) && /engineRegistry/.test(scanIndex),
        "the scan worker keeps the module-level registry for the flag off",
      );
      return p;
    },
  },
  {
    id: "ENG-S05c",
    name: "the stored SBOM document is the REDACTED copy, still valid JSON, and a document the redaction would break is not stored (SPEC scan-engines D-22 (4), 17.i, owner decision 2026-11-20 option A; fake runtime, Part E adapters unchanged): a credential-shaped value in a package field or a property of the Syft document is masked in the document the engine hands over (the planted token appears nowhere in it, nor in the log, the tool runs, the detail rows or the items), the document parses as JSON and keeps its components; a clean document is handed over byte for byte and flagged as not redacted; a document whose text the redaction turns into something that is not a JSON object (a line that carries an Authorization header, which the redaction replaces up to the end of the line, closing quotes included) is NOT stored (fail closed): the document is null, the log says so, no secret is logged, and the task is NOT failed (succeeded, the findings of the other tools and of the inventory kept, row 5); the redaction is the one of the artifact store (a hostile redaction that returns plain text, an array or an empty text is refused with a fixed note, a text that is not JSON to begin with is refused too); the helper stores nothing and never throws for a hostile document",
    async run() {
      const p = [];
      const token = "ghp_Wk9Wk9Wk9Wk9Wk9Wk9Wk9Wk9Wk9Wk9Wk9";
      const withProperty = (value) => {
        const doc = JSON.parse(SYFT_DOC);
        doc.components[0].properties.push({ name: "qm:note", value });
        doc.components[1].description = `built with ${value}`;
        return doc;
      };
      // a token in a package field and in a property
      {
        const env = makeEnv({ scripts: { syft: { stdout: JSON.stringify(withProperty(token)) } } });
        try {
          const r = await env.run();
          const d = r.ensemble.document;
          ok(p, d?.toolId === "syft", "a redacted document is still stored");
          if (d) {
            const text = d.bytes.toString("utf8");
            ok(p, !text.includes(token), "the planted token is in the stored document");
            ok(
              p,
              text.includes("[REDACTED]") && d.redacted === true,
              "the token is masked, not dropped",
            );
            let parsed = null;
            try {
              parsed = JSON.parse(text);
            } catch {
              p.push("the redacted document is not valid JSON");
            }
            ok(
              p,
              parsed?.bomFormat === "CycloneDX" &&
                parsed.components.length === JSON.parse(SYFT_DOC).components.length,
              "the redacted document lost components",
            );
          }
          const everything = JSON.stringify([
            r.items,
            r.ensemble.details,
            r.ensemble.toolRuns,
            env.logs,
          ]);
          ok(
            p,
            !everything.includes(token),
            "the planted token reached an item, a detail row, a tool run or the log",
          );
          same(p, "task", [r.status, r.ensemble.rollup.matchedRow], ["succeeded", 5]);
        } finally {
          env.cleanup();
        }
      }
      // a clean document is untouched
      {
        const env = makeEnv();
        try {
          const r = await env.run();
          ok(
            p,
            r.ensemble.document?.redacted === false &&
              r.ensemble.document.bytes.toString("utf8") === SYFT_DOC,
            "a clean document must be handed over byte for byte and flagged as not redacted",
          );
        } finally {
          env.cleanup();
        }
      }
      // a document the redaction would break: not stored, not a failure
      {
        const header = "Authorization: Bearer abcdefghijklmnop1234";
        const env = makeEnv({
          scripts: { syft: { stdout: JSON.stringify(withProperty(header), null, 2) } },
        });
        try {
          const r = await env.run();
          same(p, "no document", r.ensemble.document, null);
          ok(
            p,
            env.logs.some((l) =>
              /^warn The SBOM document was not stored \(redaction_broke_document\)/.test(l),
            ),
            `the log must say why: ${JSON.stringify(env.logs)}`,
          );
          ok(
            p,
            !env.logs.join("\n").includes("abcdefghijklmnop1234"),
            "the header value was logged",
          );
          same(
            p,
            "the task is not failed",
            [
              r.status,
              r.ensemble.rollup.matchedRow,
              r.ensemble.rollup.taskStatus,
              statusOf(r).syft,
            ],
            ["succeeded", 5, "succeeded", "succeeded"],
          );
          ok(p, r.items.length === FIXED.syftFindings, `the findings are kept (${r.items.length})`);
        } finally {
          env.cleanup();
        }
      }
      // the helper itself
      const hostile = (stdout, redact) => redactedSbomDocument(stdout, redact);
      same(
        p,
        "plain text",
        hostile('{"a":1}', () => "[REDACTED]"),
        {
          ok: false,
          note: "redaction_broke_document",
        },
      );
      same(
        p,
        "an array",
        hostile('{"a":1}', () => "[1,2]"),
        {
          ok: false,
          note: "redaction_broke_document",
        },
      );
      for (const scalar of ["null", "5", '"text"', "true"])
        same(
          p,
          `a JSON scalar ${scalar}`,
          hostile('{"a":1}', () => scalar),
          {
            ok: false,
            note: "redaction_broke_document",
          },
        );
      same(
        p,
        "an empty text",
        hostile('{"a":1}', () => ""),
        {
          ok: false,
          note: "redaction_broke_document",
        },
      );
      same(
        p,
        "not JSON to begin with",
        hostile("not json", (t) => t),
        {
          ok: false,
          note: "document_not_json",
        },
      );
      const fine = hostile(Buffer.from('{"a":"x"}'), (t) => t);
      same(
        p,
        "an unchanged text",
        [fine.ok, fine.redacted, fine.bytes?.toString()],
        [true, false, '{"a":"x"}'],
      );
      const masked = hostile('{"a":"x"}', () => '{"a":"[REDACTED]"}');
      same(
        p,
        "a masked text",
        [masked.ok, masked.redacted, masked.bytes?.toString()],
        [true, true, '{"a":"[REDACTED]"}'],
      );
      let threw = false;
      try {
        hostile("\u0000{", undefined);
      } catch {
        threw = true;
      }
      ok(p, !threw, "the helper threw for a hostile document");
      return p;
    },
  },
];

// =====================================================================================================================
// World checks: the REAL orchestrator, scan handler and database with the ensemble engine over the FAKE runtime (part K core)
// =====================================================================================================================

const MANIFEST_AND_CODE = [
  { filename: "package.json", status: "modified", additions: 1, deletions: 0 },
  { filename: "src/a.js", status: "modified", additions: 2, deletions: 1 },
];
const ENTRIES = [
  { name: "README.md", content: "# app\n" },
  { name: "package.json", content: TREE_FILES["package.json"] },
  { name: "package-lock.json", content: TREE_FILES["package-lock.json"] },
];
const SBOM_ONLY = {
  sbom: { enabled: true },
  sca: { enabled: false },
  sast: { enabled: false },
  secrets: { enabled: false },
};

/** An ensemble engine over the fake runtime whose trees live where the scan handler of the world extracts them. */
function worldEngine(w, { scripts, inventory, gate = {}, wrap } = {}) {
  const rulesDir = mkdtempSync(path.join(os.tmpdir(), "qm-ens-rules-"));
  cpSync(RULES, rulesDir, { recursive: true });
  const runtime = new FakeSandboxRuntime({
    config: {
      runtimeBin: "podman",
      containerUser: "65534:65534",
      usernsMode: "keep-id",
      uidMap: [],
      gidMap: [],
      seccompProfile: null,
      mountRoots: { archive: [w.scanTmp], db: [], rules: [rulesDir] },
      egressNetworks: {},
    },
  });
  runtime.script("syft", { exitCode: 0, stdout: SYFT_DOC, ...scripts?.syft });
  runtime.script("trivy", { exitCode: 0, stdout: TRIVY_DOC, ...scripts?.trivy });
  const { resolver } = loadImageLock();
  const real = createEnsembleSbomEngine({
    runner: createSandboxRunner({ runtime }),
    gate: createCapacityGate({ perWorker: 4, perTenant: 4, perTask: 2, forkShare: 4, ...gate }),
    resolver,
    rulesDir,
    toolWaitMs: 2000,
    inventory,
  });
  const seen = [];
  const engine = {
    ...real,
    runTask: (ctx, hooks) => (
      seen.push(hooks.platform ?? null),
      wrap ? wrap(real, ctx, hooks) : real.runTask(ctx, hooks)
    ),
  };
  return {
    engine,
    runtime,
    seen,
    rulesDir,
    cleanup: () => rmSync(rulesDir, { recursive: true, force: true }),
  };
}

async function incrementalSbom(w, label, { files = MANIFEST_AND_CODE, config, over } = {}) {
  const tree = await w.tree(label, { config: config ?? w.config1({ scans: SBOM_ONLY }) });
  const base = w.sha();
  const head = w.sha();
  await w.stub("/__control/compare", { fullName: tree.fullName, base, head, files });
  const execution = await w.execution(tree, {
    commitSha: head,
    baseSha: base,
    scanKind: "incremental",
    scanKindReason: "push",
    entries: ENTRIES,
    ...over,
  });
  return { tree, execution };
}

async function rowsOf(w, tree, execution) {
  const where = { tenantId: tree.tenant.id, executionId: execution.id };
  const tasks = await w.db.scanTask.findMany({ where, orderBy: { ordinal: "asc" } });
  return {
    tasks,
    decision: await w.db.scanDecision.findFirst({ where }),
    results: await w.db.scanResult.findMany({ where }),
    items: await w.db.scanResultItem.findMany({ where: { ...where }, orderBy: { ordinal: "asc" } }),
    details: await w.db
      .$queryRaw`SELECT item_ordinal AS "ordinal", provenance, extra FROM scan_result_item_details WHERE tenant_id = ${tree.tenant.id}::uuid AND execution_id = ${execution.id}::uuid ORDER BY item_ordinal`,
    toolRuns: await w.db
      .$queryRaw`SELECT id::text AS id, tool_id AS "toolId", attempt, status, reason, image_digest AS "imageDigest", config_digest AS "configDigest", exit_code AS "exitCode", tenant_id::text AS "tenantId" FROM scan_tool_runs WHERE tenant_id = ${tree.tenant.id}::uuid AND execution_id = ${execution.id}::uuid ORDER BY attempt, tool_id`,
    artifacts: await w.db
      .$queryRaw`SELECT name, artifact_class AS "artifactClass", media_type AS "mediaType", size_bytes AS "size", content FROM execution_artifacts WHERE tenant_id = ${tree.tenant.id}::uuid AND execution_id = ${execution.id}::uuid ORDER BY name`,
    row: await w.row(execution),
  };
}

export const ENSEMBLE_WORLD_CHECKS = [
  {
    id: "ENG-S16c",
    name: "the ensemble engine in the real worker path: result, tool runs, detail rows, the canonical SBOM document and the changed-paths artifact (SPEC scan-engines 5.9, 6.1, 7.3, D-7, D-22, 14.1 ENG-S08 and ENG-S10, part K core; real orchestrator, scan handler and database, fake runtime, Part E adapters unchanged): with the flag on an incremental execution stores the changed-paths artifact and records its name and status on the decision, the scan handler reads it back by tenant and execution and hands it, with the tenant and the trust, to the engine only; the task result is schema version 2 with the engine version ensemble-sbom/1, the coverage statement and a run manifest hash, the items have one detail row each whose provenance and raw reference point at tool runs of THIS task, three tool run rows exist with the locked image digests, the configuration digests of the mounted rules, exit codes and fixed reasons, ONE sbom_document artifact holds the Syft document (a planted credential in it is redacted, a failing artifact store never fails the scan, a document stored once per attempt), a tool run is written only for the running attempt (a second finish writes nothing); a task deadline with hanging tools ends the task timed_out with its tool runs recorded cancelled / deadline, an incomplete result of the finished tools and no container left; all tools failing ends the task failed / tools_failed with the tool runs recorded and no result; with the flag OFF the same execution has NULL changed-path columns, no artifact, a schema version 1 result, no tool run and the engine receives exactly the three hooks of before",
    async run(w) {
      const p = [];
      const cleanups = [];
      const credential = "ghp_Wk9Wk9Wk9Wk9Wk9Wk9Wk9Wk9Wk9Wk9Wk9";
      try {
        const pg = createPostgresArtifactStore({
          repository: createExecutionArtifactRepository({ db: w.db }),
        });
        const over = (rulesDir) => ({
          SCAN_ENGINES_ENSEMBLE_ENABLED: "true",
          SANDBOX_ARCHIVE_ROOT: w.scanTmp,
          SANDBOX_RULES_DIR: rulesDir,
        });
        // ---- flag on
        const doc = JSON.parse(SYFT_DOC);
        doc.metadata.properties.push({ name: "qm:secret", value: credential });
        const probes = [];
        const env = worldEngine(w, {
          scripts: { syft: { stdout: JSON.stringify(doc) } },
          wrap: async (real, ctx, hooks) => {
            const q = (tenantId) =>
              w.tasks.isAttemptRunning({
                tenantId,
                executionId: ctx.executionId,
                taskId: ctx.taskId,
                attempt: ctx.attempt,
              });
            probes.push([await q(hooks.platform.tenantId), await q(TENANT_B)]);
            return real.runTask(ctx, hooks);
          },
        });
        cleanups.push(env.cleanup);
        const engines = buildEngineRegistry({
          ensembleEnabled: true,
          createEnsembleEngine: () => env.engine,
        });
        const x = await incrementalSbom(w, "ensOn");
        const orch = w.orchestrator(over(env.rulesDir), { engines, artifacts: pg });
        const scan = w.scanHandler(over(env.rulesDir), undefined, engines, { artifacts: pg });
        await w.run(x.tree, x.execution, { orch, scan });
        const on = await rowsOf(w, x.tree, x.execution);
        same(
          p,
          "task and execution",
          [on.tasks.map((t) => `${t.scanType}/${t.status}`), on.row.status],
          [["sbom/succeeded"], "succeeded"],
        );
        same(
          p,
          "decision columns",
          [on.decision?.changedPathsStatus, on.decision?.changedPathsRef],
          ["complete", CHANGED_PATHS_NAME],
        );
        const cp = on.artifacts.find((a) => a.name === CHANGED_PATHS_NAME);
        ok(
          p,
          cp && cp.artifactClass === "standard",
          "the changed-paths artifact must exist (standard class)",
        );
        if (cp)
          same(p, "changed paths content", JSON.parse(Buffer.from(cp.content).toString("utf8")), {
            schemaVersion: 1,
            total: 2,
            paths: ["package.json", "src/a.js"],
          });
        same(
          p,
          "platform handed to the engine",
          [
            env.seen.length,
            env.seen[0]?.tenantId === x.tree.tenant.id,
            env.seen[0]?.fork,
            env.seen[0]?.changedPaths,
          ],
          [1, true, false, { status: "complete", paths: ["package.json", "src/a.js"] }],
        );
        const result = on.results[0];
        ok(
          p,
          result &&
            result.schemaVersion === 2 &&
            result.engineVersion === "ensemble-sbom/1" &&
            result.engineId === "default",
          `result identity ${JSON.stringify({ v: result?.schemaVersion, e: result?.engineVersion })}`,
        );
        ok(p, /^[0-9a-f]{64}$/.test(result?.runManifestSha256 ?? ""), "run manifest hash");
        same(
          p,
          "coverage",
          [result?.coverage?.state, result?.coverage?.toolsDegraded, result?.completeness],
          ["complete", 0, "complete"],
        );
        ok(
          p,
          on.items.length === FIXED.syftFindings && on.details.length === on.items.length,
          `items ${on.items.length} / details ${on.details.length}`,
        );
        same(
          p,
          "tool runs",
          on.toolRuns.map((t) => [t.toolId, t.status, t.reason, t.attempt]),
          [
            ["sbom-lite", "succeeded", null, 0],
            ["syft", "succeeded", null, 0],
            ["trivy", "succeeded", null, 0],
          ],
        );
        const lock = JSON.parse(
          readFileSync(
            path.join(WORKERS, "execution/engines/ensemble/catalog/images.lock.json"),
            "utf8",
          ),
        ).images;
        same(
          p,
          "image digests",
          on.toolRuns.map((t) => t.imageDigest),
          [
            null,
            lock.find((e) => e.key === "syft").digest,
            lock.find((e) => e.key === "trivy").digest,
          ],
        );
        ok(
          p,
          on.toolRuns.every(
            (t) => /^[0-9a-f]{64}$/.test(t.configDigest) && t.tenantId === x.tree.tenant.id,
          ),
          "tool runs carry configuration digests and the tenant of the task",
        );
        const ids = new Set(on.toolRuns.map((t) => t.id));
        ok(
          p,
          on.details.every((d) => ids.has(d.extra.rawRef.toolRunId)),
          "a detail row's raw reference must be a tool run row of this task",
        );
        const docs = on.artifacts.filter((a) => a.artifactClass === "sbom_document");
        same(p, "one sbom_document", docs.length, 1);
        if (docs[0]) {
          ok(
            p,
            /^sbom-[0-9a-f]{32}-a0\.cdx\.json$/.test(docs[0].name),
            `document name ${docs[0].name}`,
          );
          ok(
            p,
            !Buffer.from(docs[0].content).toString("utf8").includes(credential),
            "the stored document holds the planted credential",
          );
          ok(p, docs[0].size <= 16 * 1024 * 1024, "document ceiling");
        }
        ok(
          p,
          !JSON.stringify(on.toolRuns).includes(credential) &&
            !JSON.stringify(on.details).includes(credential),
          "a planted credential reached a tool run or detail row",
        );
        same(p, "no container left", env.runtime.containers.size, 0);
        same(p, "the janitor's question while the task runs (own tenant, foreign tenant)", probes, [
          [true, false],
        ]);
        // a tool run is written only for the running attempt
        const again = await w.tasks.finishTask({
          tenantId: x.tree.tenant.id,
          taskId: on.tasks[0].id,
          attempt: 0,
          status: "succeeded",
          result: {
            engineId: "default",
            engineVersion: "x",
            completeness: "complete",
            truncated: false,
            severityCounts: {},
            items: [],
          },
          toolRuns: [
            {
              toolId: "syft",
              toolVersion: "1",
              imageDigest: lock.find((e) => e.key === "syft").digest,
              configDigest: "a".repeat(64),
              status: "succeeded",
              startedAt: new Date().toISOString(),
              finishedAt: new Date().toISOString(),
              durationMs: 0,
              scope: {},
              severityCounts: {},
              limits: {},
            },
          ],
        });
        same(
          p,
          "a finished attempt writes nothing",
          [again.finished, (await rowsOf(w, x.tree, x.execution)).toolRuns.length],
          [false, 3],
        );
        // ---- the decision columns and their CHECK (migration 20261120100000): each wrong combination is refused by the database
        const decisionRepo = createScanDecisionRepository({ db: w.db });
        const decisionOf = (diffStatus) => ({
          diff: {
            source: diffStatus === "unavailable" ? "unavailable" : "github_compare",
            status: diffStatus,
            changedTotal: diffStatus === "complete" ? 1 : 0,
            summary: {},
          },
          secretsRule: "any_change",
          floor: [{ scanType: "sbom", ruleIds: ["manifest"] }],
          agent: {
            status: "not_configured",
            provider: null,
            model: null,
            additions: [],
            summary: null,
            usage: null,
          },
          finalTypes: ["sbom"],
          notSelected: [],
        });
        const tryInsert = async (label, diffStatus, changedPaths) => {
          const c = await incrementalSbom(w, `cols${label}`);
          await w.repo.claimQueued({
            tenantId: c.tree.tenant.id,
            executionId: c.execution.id,
            workerId: "cols",
            leaseTtlSeconds: 60,
            deadlineSeconds: 600,
            staleThresholdSeconds: 36 * 3600,
          });
          try {
            await w.db.$transaction((tx) =>
              decisionRepo.insertDecision(
                {
                  tenantId: c.tree.tenant.id,
                  executionId: c.execution.id,
                  leaseEpoch: 1,
                  decision: decisionOf(diffStatus),
                  changedPaths,
                },
                tx,
              ),
            );
            const row = await w.db.scanDecision.findFirst({
              where: { tenantId: c.tree.tenant.id, executionId: c.execution.id },
            });
            return `accepted ${row.changedPathsStatus}/${row.changedPathsRef}`;
          } catch (e) {
            return /scan_decisions_changed_paths_check/.test(String(e?.message))
              ? "check"
              : `error ${String(e?.message).slice(0, 80)}`;
          }
        };
        same(
          p,
          "complete with the fixed name",
          await tryInsert("ok", "complete", { status: "complete", ref: CHANGED_PATHS_NAME }),
          `accepted complete/${CHANGED_PATHS_NAME}`,
        );
        same(
          p,
          "truncated without a ref",
          await tryInsert("trunc", "truncated", { status: "truncated", ref: null }),
          "accepted truncated/null",
        );
        same(
          p,
          "unavailable without a ref",
          await tryInsert("unav", "unavailable", { status: "unavailable", ref: null }),
          "accepted unavailable/null",
        );
        same(
          p,
          "nothing recorded",
          await tryInsert("none", "complete", undefined),
          "accepted null/null",
        );
        same(
          p,
          "complete with another name",
          await tryInsert("name", "complete", { status: "complete", ref: "other.json" }),
          "check",
        );
        same(
          p,
          "complete with no name",
          await tryInsert("noname", "complete", { status: "complete", ref: null }),
          "check",
        );
        same(
          p,
          "complete over a truncated diff",
          await tryInsert("diff", "truncated", { status: "complete", ref: CHANGED_PATHS_NAME }),
          "check",
        );
        same(
          p,
          "truncated with a name",
          await tryInsert("tname", "truncated", { status: "truncated", ref: CHANGED_PATHS_NAME }),
          "check",
        );
        same(
          p,
          "an unknown status",
          await tryInsert("junk", "complete", { status: "weird", ref: null }),
          "check",
        );
        const def = await w.db
          .$queryRaw`SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conname = 'scan_decisions_changed_paths_check'`;
        const text = String(def[0]?.def ?? "");
        ok(
          p,
          (text.match(/changed_paths_status IS NOT NULL/g) ?? []).length === 2 &&
            /changed_paths_ref IS NOT NULL/.test(text),
          "the CHECK must be null-safe (a CHECK that evaluates to NULL passes)",
        );
        // the janitor's question: only the running attempt of this tenant's task (1-based label minus one)
        const taskId = on.tasks[0].id;
        const q = (over) =>
          w.tasks.isAttemptRunning({
            tenantId: x.tree.tenant.id,
            executionId: x.execution.id,
            taskId,
            attempt: 0,
            ...over,
          });
        same(p, "a finished task is not running", await q({}), false);
        same(
          p,
          "a malformed id never reaches the database",
          [
            await q({ taskId: "x" }),
            await q({ attempt: -1 }),
            await q({ attempt: 1.5 }),
            await q({ tenantId: "../" }),
          ],
          [false, false, false, false],
        );
        // ---- the artifact store fails: the scan is not affected
        const failing = {
          ...pg,
          put: async (ref, content, options) =>
            options?.artifactClass === "sbom_document"
              ? Promise.reject(new Error("store down"))
              : pg.put(ref, content, options),
        };
        const env2 = worldEngine(w);
        cleanups.push(env2.cleanup);
        const engines2 = buildEngineRegistry({
          ensembleEnabled: true,
          createEnsembleEngine: () => env2.engine,
        });
        const y = await incrementalSbom(w, "ensStoreDown");
        await w.run(y.tree, y.execution, {
          orch: w.orchestrator(over(env2.rulesDir), { engines: engines2, artifacts: pg }),
          scan: w.scanHandler(over(env2.rulesDir), undefined, engines2, { artifacts: failing }),
        });
        const down = await rowsOf(w, y.tree, y.execution);
        same(
          p,
          "store down",
          [
            down.tasks[0].status,
            down.artifacts.filter((a) => a.artifactClass === "sbom_document").length,
            down.results.length,
          ],
          ["succeeded", 0, 1],
        );
        // ---- every tool fails: row 7, tool runs recorded, no result
        const env3 = worldEngine(w, {
          scripts: { syft: { exitCode: 3 }, trivy: { exitCode: 4 } },
          inventory: async () => {
            throw new Error("broken");
          },
        });
        cleanups.push(env3.cleanup);
        const engines3 = buildEngineRegistry({
          ensembleEnabled: true,
          createEnsembleEngine: () => env3.engine,
        });
        const z = await incrementalSbom(w, "ensAllFail");
        await w.run(z.tree, z.execution, {
          orch: w.orchestrator(over(env3.rulesDir), { engines: engines3, artifacts: pg }),
          scan: w.scanHandler(over(env3.rulesDir), undefined, engines3, { artifacts: pg }),
        });
        const dead = await rowsOf(w, z.tree, z.execution);
        same(
          p,
          "all tools failed",
          [dead.tasks[0].status, dead.tasks[0].statusReason, dead.results.length, dead.row.status],
          ["failed", "tools_failed", 0, "failed"],
        );
        same(
          p,
          "failed tool runs",
          dead.toolRuns.map((t) => `${t.toolId}/${t.status}/${t.reason}`),
          ["sbom-lite/failed/output_invalid", "syft/failed/exit_code", "trivy/failed/exit_code"],
        );
        same(
          p,
          "no document of a failed run",
          dead.artifacts.filter((a) => a.artifactClass === "sbom_document").length,
          0,
        );
        // ---- the task deadline with hanging tools: timed_out, tool runs cancelled / deadline, partial result
        const env4 = worldEngine(w, { scripts: { syft: { hang: true }, trivy: { hang: true } } });
        cleanups.push(env4.cleanup);
        const engines4 = buildEngineRegistry({
          ensembleEnabled: true,
          createEnsembleEngine: () => env4.engine,
        });
        const slow = await incrementalSbom(w, "ensDeadline", {
          config: w.config1({
            scans: SBOM_ONLY,
            execution: { timeoutSeconds: 60, scanTaskTimeoutSeconds: 1 },
          }),
        });
        await w.run(slow.tree, slow.execution, {
          orch: w.orchestrator(over(env4.rulesDir), { engines: engines4, artifacts: pg }),
          scan: w.scanHandler(over(env4.rulesDir), undefined, engines4, { artifacts: pg }),
        });
        const late = await rowsOf(w, slow.tree, slow.execution);
        same(
          p,
          "deadline task",
          [late.tasks[0].status, late.tasks[0].statusReason],
          ["timed_out", "task_deadline"],
        );
        same(
          p,
          "deadline tool runs",
          late.toolRuns
            .map((t) => `${t.toolId}/${t.status}/${t.reason}`)
            .filter((s) => !s.startsWith("sbom-lite")),
          ["syft/cancelled/deadline", "trivy/cancelled/deadline"],
        );
        ok(
          p,
          late.results.length === 1 &&
            late.results[0].completeness === "incomplete" &&
            late.results[0].schemaVersion === 2,
          "a timed-out ensemble task keeps an incomplete schema 2 result of the finished tools",
        );
        same(p, "deadline: no container left", env4.runtime.containers.size, 0);
        // ---- a fork run: the platform facts say so (the fork share of the capacity gate keys on it), a FULL run records nothing
        const envFork = worldEngine(w);
        cleanups.push(envFork.cleanup);
        const enginesFork = buildEngineRegistry({
          ensembleEnabled: true,
          createEnsembleEngine: () => envFork.engine,
        });
        const forkTree = await w.tree("ensFork", { config: w.config1({ scans: SBOM_ONLY }) });
        const forkExec = await w.fork(forkTree, {
          scanKind: "full",
          scanKindReason: "first_run",
          entries: ENTRIES,
          concurrencyGroup: "ensFork",
        });
        await w.run(forkTree, forkExec, {
          orch: w.orchestrator(over(envFork.rulesDir), { engines: enginesFork, artifacts: pg }),
          scan: w.scanHandler(over(envFork.rulesDir), undefined, enginesFork, { artifacts: pg }),
        });
        const forked = await rowsOf(w, forkTree, forkExec);
        same(
          p,
          "fork platform facts",
          [envFork.seen.length, envFork.seen[0]?.fork, envFork.seen[0]?.changedPaths?.status],
          [1, true, "not_recorded"],
        );
        same(
          p,
          "a full run records no changed paths",
          [
            forked.decision?.changedPathsStatus ?? null,
            forked.artifacts.filter((a) => a.name === CHANGED_PATHS_NAME).length,
            forked.tasks[0]?.status,
          ],
          [null, 0, "succeeded"],
        );
        // ---- no artifact store while the flag is on: the decision says unavailable and the scan runs over the whole tree
        const envNo = worldEngine(w);
        cleanups.push(envNo.cleanup);
        const enginesNo = buildEngineRegistry({
          ensembleEnabled: true,
          createEnsembleEngine: () => envNo.engine,
        });
        const nn = await incrementalSbom(w, "ensNoStore");
        await w.run(nn.tree, nn.execution, {
          orch: w.orchestrator(over(envNo.rulesDir), { engines: enginesNo }),
          scan: w.scanHandler(over(envNo.rulesDir), undefined, enginesNo),
        });
        const noStore = await rowsOf(w, nn.tree, nn.execution);
        same(
          p,
          "no store",
          [
            noStore.decision?.changedPathsStatus,
            noStore.decision?.changedPathsRef,
            envNo.seen[0]?.changedPaths,
            noStore.tasks[0]?.status,
          ],
          ["unavailable", null, { status: "unavailable", paths: [] }, "succeeded"],
        );
        // ---- a transient row 7 (every tool failed transiently) is retried and the failed attempt keeps its tool runs
        let retried = 0;
        const envRetry = worldEngine(w, {
          wrap: async (real, ctx, hooks) => {
            const r = await real.runTask(ctx, hooks);
            if (ctx.attempt !== 0) return r;
            retried += 1;
            return {
              ...r,
              status: "failed",
              items: [],
              ensemble: {
                ...r.ensemble,
                rollup: {
                  ...r.ensemble.rollup,
                  taskStatus: "failed",
                  reason: "tools_failed",
                  errorClass: "transient",
                  completeness: null,
                },
              },
            };
          },
        });
        cleanups.push(envRetry.cleanup);
        const enginesRetry = buildEngineRegistry({
          ensembleEnabled: true,
          createEnsembleEngine: () => envRetry.engine,
        });
        const rr = await incrementalSbom(w, "ensRetry");
        await w.run(rr.tree, rr.execution, {
          orch: w.orchestrator(over(envRetry.rulesDir), { engines: enginesRetry, artifacts: pg }),
          scan: w.scanHandler(over(envRetry.rulesDir), undefined, enginesRetry, { artifacts: pg }),
        });
        const retry = await rowsOf(w, rr.tree, rr.execution);
        same(
          p,
          "retried task",
          [retried, retry.tasks[0]?.status, retry.tasks[0]?.attempt, retry.results.length],
          [1, "succeeded", 1, 1],
        );
        same(
          p,
          "tool runs of both attempts",
          retry.toolRuns.map((t) => `${t.attempt}/${t.toolId}/${t.status}`),
          [
            "0/sbom-lite/succeeded",
            "0/syft/succeeded",
            "0/trivy/succeeded",
            "1/sbom-lite/succeeded",
            "1/syft/succeeded",
            "1/trivy/succeeded",
          ],
        );
        same(
          p,
          "one document per attempt that produced one",
          retry.artifacts
            .filter((a) => a.artifactClass === "sbom_document")
            .map((a) => /-a(\d+)\.cdx\.json$/.exec(a.name)?.[1]),
          ["1"],
        );
        // ---- the decision functions return exactly what they did unless the changed files are asked for
        const github = {
          listChangedFiles: async () => ({
            status: "complete",
            source: "github_compare",
            files: [
              { path: "a.js", previousPath: null, status: "modified", additions: 1, deletions: 0 },
            ],
          }),
        };
        const floorInput = {
          execution: {
            scanKind: "incremental",
            triggerType: "push",
            baseSha: "a".repeat(40),
            commitSha: "b".repeat(40),
          },
          repository: { fullName: "o/r", externalInstallationId: "1" },
          github,
          config: {
            scanDecision: {
              secretsRule: "any_change",
              maxChangedFiles: 3000,
              maxPages: 30,
              samplePaths: 20,
            },
          },
          enabledTypes: ["sbom"],
          exclusions: null,
        };
        same(
          p,
          "decideFloor default shape",
          "changedFiles" in (await decideFloor(floorInput)),
          false,
        );
        same(
          p,
          "decideFloor on request",
          (await decideFloor({ ...floorInput, collectChangedFiles: true })).changedFiles?.map(
            (f) => f.path,
          ),
          ["a.js"],
        );
        const decideInput = {
          ...floorInput,
          tenantId: x.tree.tenant.id,
          runtime: null,
          exclusions: null,
        };
        same(
          p,
          "decideScans default shape",
          "changedFiles" in
            (await decideScans({
              ...decideInput,
              config: {
                ...floorInput.config,
                scanDecision: {
                  ...floorInput.config.scanDecision,
                  agentTimeoutSeconds: 3,
                  maxTurns: 1,
                  contextPaths: 0,
                },
              },
            })),
          false,
        );
        // ---- flag OFF: the same execution is exactly the old path
        const legacyHooks = [];
        const off = buildEngineRegistry({ ensembleEnabled: false });
        const legacy = off.get("sbom", "default");
        const spy = createEngineRegistry();
        spy.register({
          ...legacy,
          runTask: (ctx, hooks) => (
            legacyHooks.push(Object.keys(hooks).sort()),
            legacy.runTask(ctx, hooks)
          ),
        });
        const o = await incrementalSbom(w, "ensOff");
        await w.run(o.tree, o.execution, {
          orch: w.orchestrator({}, { engines: spy }),
          scan: w.scanHandler({}, undefined, spy),
        });
        const old = await rowsOf(w, o.tree, o.execution);
        same(
          p,
          "flag off decision",
          [old.decision?.changedPathsStatus ?? null, old.decision?.changedPathsRef ?? null],
          [null, null],
        );
        same(p, "flag off artifacts", old.artifacts.length, 0);
        same(
          p,
          "flag off result",
          [
            old.results[0]?.schemaVersion,
            old.results[0]?.coverage ?? null,
            old.results[0]?.runManifestSha256 ?? null,
            old.toolRuns.length,
            old.details.length,
          ],
          [1, null, null, 0, 0],
        );
        same(p, "flag off hooks", legacyHooks, [["emit", "log", "signal"]]);
        same(
          p,
          "flag off task",
          [old.tasks[0].status, old.results[0].engineVersion === legacy.version],
          ["succeeded", true],
        );
      } finally {
        for (const c of cleanups) c();
      }
      return p;
    },
  },
  {
    id: "ENG-S17c",
    name: "a large ensemble result never starves the lease heartbeat of the real scan handler (SPEC scan-engines 17.i, 17.j, Executions ER-27 and EXEC-028 false-reclaim rule, owner decision 2026-11-20; real orchestrator, scan handler and database, fake runtime, Part E adapters unchanged): two container tools report the same 8000 components, so parsing, the merge and the storage rows are heavy work of several seconds on the worker's event loop; the handler runs with a heartbeat of 1 second and its timer renews the task lease through the database during all of it: the heartbeat column of the task row advances repeatedly while the engine works (at least three distinct renewals), no gap between two renewals (the first being the claim) nor between the last renewal and the end of the engine exceeds 2.5 times the heartbeat, which is far below the lease TTL, and the task still finishes succeeded with the item cap applied after the full merge (the database write of a large result is not what this proves)",
    async run(w) {
      const p = [];
      const cleanups = [];
      try {
        const doc = JSON.parse(SYFT_DOC);
        const count = 8000;
        doc.components = Array.from({ length: count }, (_, i) => ({
          "bom-ref": `r${i}`,
          type: "library",
          name: `pkg${i}`,
          version: `1.0.${i % 97}`,
          purl: `pkg:npm/pkg${i}@1.0.${i % 97}`,
          properties: [{ name: "syft:location:0:path", value: `/d${i % 50}/package-lock.json` }],
        }));
        const big = JSON.stringify(doc);
        const beats = new Set();
        let engineMs = 0;
        let lastBeatAtEnd = 0;
        const env = worldEngine(w, {
          scripts: { syft: { stdout: big }, trivy: { stdout: big } },
          wrap: async (real, ctx, hooks) => {
            const read = async () => {
              const rows = await w.db.$queryRaw`
                SELECT (extract(epoch from heartbeat_at) * 1000)::float8 AS "beat", (extract(epoch from clock_timestamp()) * 1000)::float8 AS "now"
                FROM scan_tasks WHERE id = ${ctx.taskId}::uuid AND tenant_id = ${hooks.platform.tenantId}::uuid`;
              if (rows[0]) beats.add(Math.round(rows[0].beat));
              return rows[0];
            };
            await read();
            const poll = setInterval(() => void read().catch(() => {}), 150);
            const started = Date.now();
            try {
              return await real.runTask(ctx, hooks);
            } finally {
              engineMs = Date.now() - started;
              clearInterval(poll);
              const last = await read();
              lastBeatAtEnd = last ? last.now - last.beat : Infinity;
            }
          },
        });
        cleanups.push(env.cleanup);
        const over = (rulesDir) => ({
          SCAN_ENGINES_ENSEMBLE_ENABLED: "true",
          SANDBOX_ARCHIVE_ROOT: w.scanTmp,
          SANDBOX_RULES_DIR: rulesDir,
        });
        const engines = buildEngineRegistry({
          ensembleEnabled: true,
          createEnsembleEngine: () => env.engine,
        });
        const pg = createPostgresArtifactStore({
          repository: createExecutionArtifactRepository({ db: w.db }),
        });
        const x = await incrementalSbom(w, "ensBeat");
        const orch = w.orchestrator(over(env.rulesDir), { engines, artifacts: pg });
        const scan = w.scanHandler(
          {
            ...over(env.rulesDir),
            EXECUTION_HEARTBEAT_SECONDS: "1",
            // the parse and the merge see all 8000 components; only 500 rows are written (the database write is not what this proves)
            EXECUTION_MAX_RESULT_ITEMS_PER_TASK: "500",
          },
          undefined,
          engines,
          { artifacts: pg },
        );
        await w.run(x.tree, x.execution, { orch, scan });
        const on = await rowsOf(w, x.tree, x.execution);
        same(
          p,
          "task",
          on.tasks.map((t) => `${t.scanType}/${t.status}`),
          ["sbom/succeeded"],
        );
        same(
          p,
          "the 500 row cap of the storage step applies after the full merge",
          [on.items.length, on.results[0]?.truncated],
          [500, true],
        );
        const times = [...beats].sort((a, b) => a - b);
        ok(
          p,
          times.length >= 4,
          `${times.length} distinct heartbeat values over ${engineMs} ms of engine work: the engine ran too briefly to prove anything, or the heartbeat did not advance`,
        );
        let gap = 0;
        for (let i = 1; i < times.length; i += 1) gap = Math.max(gap, times[i] - times[i - 1]);
        ok(
          p,
          gap <= 2500,
          `the longest gap between two lease renewals was ${gap} ms (heartbeat 1000 ms)`,
        );
        ok(
          p,
          lastBeatAtEnd <= 2500,
          `the last lease renewal was ${Math.round(lastBeatAtEnd)} ms before the engine returned`,
        );
        if (process.env.SECURITY_REPORT_GAPS)
          console.log(
            `[ENG-S17c] engine ${engineMs} ms, ${times.length} renewals, longest gap ${gap} ms, last renewal ${Math.round(lastBeatAtEnd)} ms before the end`,
          );
      } finally {
        for (const c of cleanups) c();
      }
      return p;
    },
  },
];
