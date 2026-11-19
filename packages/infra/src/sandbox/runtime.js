/**
 * The SandboxRuntime interface (SPEC 6, ADR-014 decision 1): the ONLY way the platform starts, stops and lists scan containers.
 * Drivers: `createCliSandboxRuntime` (a Docker-compatible CLI via execFile, never a shell, never the runtime socket mounted into
 * anything) and `FakeSandboxRuntime` (tests, no container). A production scan-runner service is a later driver behind the same
 * interface. No driver may assume a rootful runtime (SPEC D-20).
 *
 * @typedef {{
 *   containerName: string,
 *   status: "exited" | "timed_out" | "aborted" | "output_limit" | "runtime_error",
 *   exitCode: number | null,
 *   stdout: string, stderr: string,
 *   stdoutTruncated: boolean, stderrTruncated: boolean,
 *   timedOut: boolean, aborted: boolean,
 *   durationMs: number,
 *   cleanupFailed: boolean
 * }} RunResult
 * `stdout` and `stderr` are decoded as UTF-8 (invalid sequences replaced) and capped (`limits.stdoutBytes`, configured stderr cap).
 * A killed run (`timed_out`, `aborted`, `output_limit`) never returns output that should be parsed (SPEC 6.4: discard).
 *
 * @typedef {{ name: string, id: string | null, labels: Record<string, string>, state: string }} ListedContainer
 *
 * @typedef {{ ok: boolean, runtime: string, rootless: boolean | null, reason: string | null }} RuntimeHealth
 *
 * @typedef {{
 *   run(spec: import("./run-spec.js").RunSpec, options?: { signal?: AbortSignal }): Promise<RunResult>,
 *   kill(containerName: string): Promise<void>,
 *   remove(containerName: string): Promise<void>,
 *   health(): Promise<RuntimeHealth>,
 *   listByLabel(labels: Record<string, string>): Promise<ListedContainer[]>
 * }} SandboxRuntime
 * `kill` and `remove` are idempotent: a container that no longer exists is not an error.
 */

export const RUN_STATUSES = Object.freeze([
  "exited",
  "timed_out",
  "aborted",
  "output_limit",
  "runtime_error",
]);
