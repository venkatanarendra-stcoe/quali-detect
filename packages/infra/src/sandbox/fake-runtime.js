import { buildRunArgs } from "./build-run-args.js";
import { validateSandboxConfig } from "./config.js";
import { LABEL_KEYS } from "./policy.js";
import { containerNameOf } from "./run-spec.js";

/**
 * An in-memory SandboxRuntime for the Docker-free security suite and for unit-style use (SPEC 14.1). It starts no process and no
 * container. It runs the REAL `buildRunArgs` for every run (so the recorded argv is exactly what a CLI runtime would execute),
 * records every call, keeps a container state table with labels (so the janitor and the kill-then-remove rule can be asserted),
 * and plays scripted outcomes.
 *
 * A script is chosen per tool id (`script(toolId, outcome)`) or by a function (`scriptBy(fn)`); an outcome is
 * `{ exitCode, stdout, stderr, delayMs, hang, runtimeFault, huge }`. `hang: true` never finishes by itself: only `kill`, an abort
 * signal or the wall clock ends it.
 *
 * @param {{ config: unknown, now?: () => number }} options
 */
export class FakeSandboxRuntime {
  constructor({ config, now = Date.now }) {
    this.config = validateSandboxConfig(config);
    this.now = now;
    /** @type {Array<{ type: string, name?: string, spec?: any, args?: readonly string[], labels?: any }>} */
    this.calls = [];
    /** @type {Map<string, { name: string, labels: Record<string,string>, state: "running" | "exited", args: readonly string[], endRun: ((why: string) => void) | null }>} */
    this.containers = new Map();
    this.scripts = new Map();
    this.scriptFn = null;
    this.healthResult = { ok: true, runtime: this.config.runtimeBin, rootless: null, reason: null };
  }

  /** @param {string} toolId @param {object} outcome */
  script(toolId, outcome) {
    this.scripts.set(toolId, outcome);
    return this;
  }

  /** @param {(spec: any) => object | undefined} fn */
  scriptBy(fn) {
    this.scriptFn = fn;
    return this;
  }

  /** Marks a crash of the runner process: the containers stay in the runtime and only the janitor (or a later kill) ends them. */
  forgetRunnerState() {
    this.calls.push({ type: "crash" });
  }

  /** Adds a container that was not started through this runtime (labelled or not), for janitor tests. */
  seed(name, labels, state = "running") {
    this.containers.set(name, { name, labels: { ...labels }, state, args: [], endRun: null });
  }

  killCount(name) {
    return this.calls.filter((c) => c.type === "kill" && c.name === name).length;
  }

  removeCount(name) {
    return this.calls.filter((c) => c.type === "remove" && c.name === name).length;
  }

  async run(spec, { signal } = {}) {
    const args = buildRunArgs(spec, this.config);
    const name = containerNameOf(spec);
    this.calls.push({ type: "run", name, spec, args });
    const labels = {
      [LABEL_KEYS.scan]: "1",
      [LABEL_KEYS.tenant]: spec.labels.tenantId,
      [LABEL_KEYS.execution]: spec.labels.executionId,
      [LABEL_KEYS.task]: spec.labels.taskId,
      [LABEL_KEYS.tool]: spec.toolId,
      [LABEL_KEYS.attempt]: String(spec.labels.attempt),
      [LABEL_KEYS.deadline]: String(spec.labels.deadlineEpoch),
    };
    const outcome = this.scriptFn?.(spec) ??
      this.scripts.get(spec.toolId) ?? { exitCode: 0, stdout: "", stderr: "" };
    const started = this.now();
    const result = (over) => ({
      containerName: name,
      status: "exited",
      exitCode: 0,
      stdout: "",
      stderr: "",
      stdoutTruncated: false,
      stderrTruncated: false,
      timedOut: false,
      aborted: false,
      durationMs: this.now() - started,
      cleanupFailed: false,
      ...over,
    });
    if (outcome.runtimeFault) return result({ status: "runtime_error", exitCode: 125 });
    if (signal?.aborted) return result({ status: "aborted", exitCode: null, aborted: true });
    const container = { name, labels, state: "running", args, endRun: null };
    this.containers.set(name, container);
    return await new Promise((resolve) => {
      let timer;
      const finish = (why) => {
        clearTimeout(timer);
        clearTimeout(wall);
        signal?.removeEventListener("abort", onAbort);
        container.endRun = null;
        if (why === "natural") {
          container.state = "exited";
          this.containers.delete(name); // --rm
          const cap = spec.limits.stdoutBytes;
          const out = String(outcome.stdout ?? "");
          if (Buffer.byteLength(out) > cap) {
            // the output cap makes the runtime kill and remove the container
            this.calls.push({ type: "kill", name }, { type: "remove", name });
            return resolve(result({ status: "output_limit", exitCode: null }));
          }
          return resolve(
            result({
              exitCode: outcome.exitCode ?? 0,
              stdout: out,
              stderr: String(outcome.stderr ?? ""),
            }),
          );
        }
        // killed: discard output (SPEC 6.4). An abort signal or the wall clock makes the runtime itself kill and remove; a kill
        // issued by a caller is recorded by `kill()` and the caller removes
        if (why !== "kill") this.calls.push({ type: "kill", name }, { type: "remove", name });
        this.containers.delete(name); // --rm removes a killed container
        resolve(
          result({
            status: why === "timeout" ? "timed_out" : "aborted",
            exitCode: null,
            timedOut: why === "timeout",
            aborted: why !== "timeout",
          }),
        );
      };
      const onAbort = () => finish("abort");
      container.endRun = (why) => finish(why);
      signal?.addEventListener("abort", onAbort, { once: true });
      const wall = setTimeout(() => finish("timeout"), spec.limits.wallClockSeconds * 1000);
      if (!outcome.hang) timer = setTimeout(() => finish("natural"), outcome.delayMs ?? 0);
    });
  }

  async kill(name) {
    this.calls.push({ type: "kill", name });
    const c = this.containers.get(name);
    if (!c) return;
    c.state = "exited";
    c.endRun?.("kill"); // a run in flight ends as aborted
  }

  async remove(name) {
    this.calls.push({ type: "remove", name });
    this.containers.get(name)?.endRun?.("kill"); // rm -f also stops a running container
    this.containers.delete(name);
  }

  async health() {
    this.calls.push({ type: "health" });
    return this.healthResult;
  }

  async listByLabel(labels) {
    this.calls.push({ type: "list", labels });
    return [...this.containers.values()]
      .filter((c) => Object.entries(labels).every(([k, v]) => c.labels[k] === v))
      .map((c) => ({ name: c.name, id: null, labels: { ...c.labels }, state: c.state }));
  }
}
