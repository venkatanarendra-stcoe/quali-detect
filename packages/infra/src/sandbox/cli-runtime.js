import { execFile as nodeExecFile } from "node:child_process";
import { buildRunArgs } from "./build-run-args.js";
import { validateSandboxConfig } from "./config.js";
import { SANDBOX_ERROR_CODES, SandboxError } from "./errors.js";
import { CONTAINER_NAME_PATTERN, LABEL_KEYS } from "./policy.js";
import { containerNameOf, validateRunSpec } from "./run-spec.js";

/**
 * Environment variables handed to the runtime CLIENT process (not to the container). An explicit allowlist: nothing else of the
 * worker's environment (tokens, database URLs, LLM keys) ever reaches a child. `DOCKER_HOST` / `CONTAINER_HOST` may name a
 * rootless daemon's own socket for the client; the socket is never mounted into a container (the mount validator refuses it).
 */
export const CLI_ENV_ALLOWLIST = Object.freeze([
  "PATH",
  "HOME",
  "XDG_RUNTIME_DIR",
  "DOCKER_HOST",
  "CONTAINER_HOST",
  "DBUS_SESSION_BUS_ADDRESS",
  "TMPDIR",
  "LANG",
]);

const NO_SUCH =
  /no such (container|object)|not found|is not running|already in progress|no container with/i;

/**
 * Creates a SandboxRuntime that drives a Docker-compatible CLI (`docker` or `podman`, chosen by configuration) through `execFile`
 * (an argument array, never a shell).
 *
 * UNVERIFIED (cloud sandbox: no runtime, no user namespaces): that the generated flags are accepted and applied by a real runtime
 * (ENG-L01), rootless operation and uid mapping (ENG-L02, ENG-L18), the `inspect` format used by `listByLabel`, exit codes of
 * runtime faults (125) for Podman, and `health` parsing.
 *
 * @param {{
 *   config: unknown,
 *   execFile?: typeof nodeExecFile,
 *   env?: Record<string, string | undefined>,
 *   now?: () => number
 * }} options `execFile` and `env` are injectable for tests (no process is started by the tests)
 * @returns {import("./runtime.js").SandboxRuntime}
 */
export function createCliSandboxRuntime({
  config: rawConfig,
  execFile = nodeExecFile,
  env = process.env,
  now = Date.now,
}) {
  const config = validateSandboxConfig(rawConfig);
  const bin = config.runtimeBin;
  const cliEnv = Object.freeze(
    Object.fromEntries(
      CLI_ENV_ALLOWLIST.filter((k) => typeof env[k] === "string").map((k) => [k, env[k]]),
    ),
  );

  /**
   * One CLI call. Resolves `{ code, stdout, stderr, truncated, spawnError }`; never rejects.
   * @param {string[]} args
   * @param {{ maxBuffer: number, timeoutMs?: number, stdin?: string, onChild?: (child: any) => void }} o
   */
  function call(args, { maxBuffer, timeoutMs, stdin, onChild }) {
    return new Promise((resolve) => {
      let child;
      try {
        child = execFile(
          bin,
          args,
          {
            encoding: "buffer",
            maxBuffer,
            timeout: timeoutMs,
            env: cliEnv,
            windowsHide: true,
            shell: false,
          },
          (err, stdout, stderr) => {
            const out = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout ?? "");
            const errBuf = Buffer.isBuffer(stderr) ? stderr : Buffer.from(stderr ?? "");
            const truncated = err?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER";
            const spawnError = err && typeof err.code === "string" && !truncated ? err.code : null;
            const code = err ? (typeof err.code === "number" ? err.code : null) : 0;
            resolve({
              code,
              stdout: out,
              stderr: errBuf,
              truncated,
              spawnError,
              killedSignal: err?.signal ?? null,
            });
          },
        );
      } catch {
        resolve({
          code: null,
          stdout: Buffer.alloc(0),
          stderr: Buffer.alloc(0),
          truncated: false,
          spawnError: "EXEC",
          killedSignal: null,
        });
        return;
      }
      onChild?.(child);
      try {
        child.stdin?.on?.("error", () => {});
        child.stdin?.end(stdin);
      } catch {
        /* the client exited before reading stdin */
      }
    });
  }

  const assertName = (name) => {
    if (typeof name !== "string" || !CONTAINER_NAME_PATTERN.test(name))
      throw new SandboxError(SANDBOX_ERROR_CODES.invalidSpec, "container name is malformed", [
        "containerName",
      ]);
  };

  async function manage(args) {
    const r = await call(args, { maxBuffer: 65536, timeoutMs: config.cliTimeoutMs });
    if (r.spawnError === "ENOENT")
      throw new SandboxError(
        SANDBOX_ERROR_CODES.runtimeUnavailable,
        "container runtime binary not found",
      );
    if (r.code === 0 || NO_SUCH.test(r.stderr.toString("utf8"))) return;
    throw new SandboxError(SANDBOX_ERROR_CODES.runtimeError, `runtime ${args[0]} failed`);
  }

  const runtime = {
    async kill(name) {
      assertName(name);
      await manage(["kill", name]);
    },

    async remove(name) {
      assertName(name);
      await manage(["rm", "-f", name]);
    },

    async health() {
      const r = await call(["info"], { maxBuffer: 262144, timeoutMs: config.cliTimeoutMs });
      if (r.spawnError === "ENOENT")
        return { ok: false, runtime: bin, rootless: null, reason: "binary_not_found" };
      if (r.code !== 0) return { ok: false, runtime: bin, rootless: null, reason: "info_failed" };
      const text = r.stdout.toString("utf8");
      // best effort and UNVERIFIED: Podman prints "rootless: true|false"; Docker lists "rootless" among its security options
      const podman = /^\s*rootless:\s*(true|false)\s*$/im.exec(text);
      const rootless = podman
        ? podman[1] === "true"
        : /(^|\s|name=)rootless\s*$/im.test(text)
          ? true
          : null;
      return { ok: true, runtime: bin, rootless, reason: null };
    },

    async listByLabel(labels) {
      const filters = Object.entries(labels).map(([k, v]) => {
        if (!/^qm\.[a-z]+$/.test(k) || !/^[A-Za-z0-9._-]{1,64}$/.test(String(v)))
          throw new SandboxError(SANDBOX_ERROR_CODES.invalidSpec, "label filter is malformed", [
            "labels",
          ]);
        return `--filter=label=${k}=${v}`;
      });
      if (filters.length === 0)
        throw new SandboxError(
          SANDBOX_ERROR_CODES.invalidSpec,
          "at least one label filter is required",
          ["labels"],
        );
      const ps = await call(["ps", "-a", "-q", "--no-trunc", ...filters], {
        maxBuffer: 1048576,
        timeoutMs: config.cliTimeoutMs,
      });
      if (ps.spawnError === "ENOENT")
        throw new SandboxError(
          SANDBOX_ERROR_CODES.runtimeUnavailable,
          "container runtime binary not found",
        );
      if (ps.code !== 0)
        throw new SandboxError(SANDBOX_ERROR_CODES.runtimeError, "runtime ps failed");
      const ids = ps.stdout
        .toString("utf8")
        .split("\n")
        .map((x) => x.trim())
        .filter((x) => /^[0-9a-f]{12,64}$/.test(x));
      if (ids.length === 0) return [];
      const format =
        '--format={"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"state":{{json .State.Status}}}';
      const inspect = await call(["inspect", format, ...ids], {
        maxBuffer: 4194304,
        timeoutMs: config.cliTimeoutMs,
      });
      if (inspect.code !== 0)
        throw new SandboxError(SANDBOX_ERROR_CODES.runtimeError, "runtime inspect failed");
      return parseInspectLines(inspect.stdout.toString("utf8"));
    },

    async run(rawSpec, { signal } = {}) {
      const spec = validateRunSpec(rawSpec, config);
      const args = buildRunArgs(spec, config);
      const name = containerNameOf(spec);
      const started = now();
      const stdoutCap = spec.limits.stdoutBytes;
      let cause = null; // "timed_out" | "aborted"
      let child;
      const stop = async (why) => {
        if (cause) return;
        cause = why;
        // SPEC 6.4: kill, then remove; the CLI client exits when its container dies
        await runtime.kill(name).catch(() => {});
        await runtime.remove(name).catch(() => {});
        setTimeout(() => child?.kill?.("SIGKILL"), config.killGraceMs).unref?.();
      };
      const onAbort = () => void stop("aborted");
      if (signal?.aborted) {
        return {
          containerName: name,
          status: "aborted",
          exitCode: null,
          stdout: "",
          stderr: "",
          stdoutTruncated: false,
          stderrTruncated: false,
          timedOut: false,
          aborted: true,
          durationMs: 0,
          cleanupFailed: false,
        };
      }
      signal?.addEventListener("abort", onAbort, { once: true });
      const timer = setTimeout(() => void stop("timed_out"), spec.limits.wallClockSeconds * 1000);
      const r = await call([...args], {
        maxBuffer: Math.max(stdoutCap, config.stderrBytes),
        stdin: spec.stdin,
        onChild: (c) => {
          child = c;
        },
      });
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      let cleanupFailed = false;
      if (r.truncated && !cause) {
        // the client was stopped by the output cap; the container may still run
        cause = "output_limit";
        await runtime.kill(name).catch(() => (cleanupFailed = true));
        await runtime.remove(name).catch(() => (cleanupFailed = true));
      }
      // an abort that fired before the daemon created the container made the first kill a no-op: remove again now that the client is gone
      if (cause === "aborted" || cause === "timed_out")
        await runtime.remove(name).catch(() => (cleanupFailed = true));
      if (r.spawnError === "ENOENT")
        throw new SandboxError(
          SANDBOX_ERROR_CODES.runtimeUnavailable,
          "container runtime binary not found",
        );
      const killed = cause !== null;
      const stdoutText = r.stdout.subarray(0, stdoutCap).toString("utf8");
      const stderrText = r.stderr.subarray(0, config.stderrBytes).toString("utf8");
      const fault = !killed && (r.code === 125 || (r.code === null && r.spawnError !== null));
      return {
        containerName: name,
        status:
          cause === "timed_out"
            ? "timed_out"
            : cause === "aborted"
              ? "aborted"
              : cause === "output_limit"
                ? "output_limit"
                : fault
                  ? "runtime_error"
                  : "exited",
        exitCode: killed ? null : r.code,
        stdout: killed ? "" : stdoutText,
        stderr: killed ? "" : stderrText,
        stdoutTruncated: r.stdout.length > stdoutCap || r.truncated,
        stderrTruncated: r.stderr.length > config.stderrBytes,
        timedOut: cause === "timed_out",
        aborted: cause === "aborted",
        durationMs: now() - started,
        cleanupFailed,
      };
    },
  };
  return Object.freeze(runtime);
}

/**
 * Parses the one-JSON-object-per-line output of `inspect --format` (see `listByLabel`). Tolerant: malformed lines are skipped;
 * only containers carrying the `qm.scan=1` label are returned (the janitor never sees anything else).
 * @param {string} text
 * @returns {import("./runtime.js").ListedContainer[]}
 */
export function parseInspectLines(text) {
  const out = [];
  for (const line of String(text).split("\n")) {
    if (!line.trim()) continue;
    let o;
    try {
      o = JSON.parse(line);
    } catch {
      continue;
    }
    if (!o || typeof o !== "object" || typeof o.name !== "string") continue;
    const labels =
      o.labels && typeof o.labels === "object" && !Array.isArray(o.labels) ? o.labels : {};
    if (labels[LABEL_KEYS.scan] !== "1") continue;
    const name = o.name.replace(/^\//, "");
    if (!CONTAINER_NAME_PATTERN.test(name)) continue;
    out.push({
      name,
      id: typeof o.id === "string" ? o.id : null,
      labels: Object.fromEntries(Object.entries(labels).filter(([, v]) => typeof v === "string")),
      state: typeof o.state === "string" ? o.state : "unknown",
    });
  }
  return out;
}
