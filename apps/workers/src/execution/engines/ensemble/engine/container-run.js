import { SandboxError, resolveRunSpecImage } from "@qmentisai/infra";
import { classifyToolExit } from "./tool-exit.js";

/**
 * One container tool of an ensemble engine, from capacity to the classified result (docs/modules/scan-engines/SPEC.md 5.3, 6.1, 6.4,
 * SE-16 to SE-20): plan from platform data, resolve the digest-pinned image, wait for capacity, run through the `SandboxRunner`, and
 * classify the outcome into the FIXED statuses and reasons. Shared by the SBOM, SCA and SAST engines, which differ only in
 * the scan type of the image catalog lookup, the configuration digests and the extra plan input (the SCA database directory, the SAST explicit targets). It never
 * throws for a tool-originated problem and never returns tool text: the stderr is read only to choose a fixed word.
 *
 * @param {{
 *   runner: { runTool: Function },
 *   gate: { acquire: Function },
 *   resolver: { resolve: Function },
 *   scanType: "sbom" | "sca" | "sast",
 *   rulesDir: string,
 *   configDigests: Record<string, string>,
 *   toolWaitMs: number,
 *   now: () => number,
 *   newId: () => string,
 * }} deps
 */
export function createContainerToolRunner({
  runner,
  gate,
  resolver,
  scanType,
  rulesDir,
  configDigests,
  toolWaitMs,
  now,
  newId,
}) {
  /** The timing columns of a tool run: ISO instants and the duration (never negative). */
  const stamp = (startedMs) => {
    const end = Math.max(now(), startedMs);
    return {
      startedAt: new Date(startedMs).toISOString(),
      finishedAt: new Date(end).toISOString(),
      durationMs: end - startedMs,
    };
  };
  /** An exit code the database accepts (0 to 255), or null. */
  const exitOf = (code) => (Number.isInteger(code) && code >= 0 && code <= 255 ? code : null);

  /**
   * @param {Readonly<any>} adapter a tool adapter
   * @param {{ platform: any, context: any, signal: AbortSignal }} ctx
   * @param {{ dbDir?: string, dbProvenance?: { dbSnapshotSha256?: string, dbBuiltAt?: string }, targets?: string[], scope?: { kind: string, paths: number } }} [extra] SCA only: the verified snapshot directory and what the record keeps of it; SAST only: the explicit targets and the scope the record keeps
   */
  return async function runContainerTool(adapter, ctx, extra = {}) {
    const { platform, context, signal } = ctx;
    const startedAt = now();
    const record = {
      id: newId(),
      toolId: adapter.toolId,
      toolVersion: "unknown",
      imageDigest: null,
      configDigest: configDigests[adapter.toolId],
      status: "failed",
      reason: "sandbox_error",
      exitCode: null,
      scope: extra.scope ?? { kind: "full", paths: 0 },
      limits: {},
      capacityWaitMs: 0,
      ...(extra.dbProvenance ?? {}),
    };
    const finish = (over, streams = null) => ({
      record: { ...record, ...over, ...stamp(startedAt) },
      streams,
    });
    const abortReason = () =>
      signal.aborted && String(signal.reason?.message) === "task_deadline"
        ? "deadline"
        : "cancelled";
    let spec;
    try {
      const plan = adapter.plan({
        tenantId: platform.tenantId,
        executionId: context.executionId,
        taskId: context.taskId,
        // the container's attempt number is 1-based (RunSpec labels.attempt >= 1); the task's attempt column is 0-based
        attempt: context.attempt + 1,
        deadlineEpoch: platform.deadlineEpoch,
        secondsToDeadline: platform.secondsToDeadline,
        archiveDir: context.sourceDir,
        rulesDir,
        ...(extra.dbDir ? { dbDir: extra.dbDir } : {}),
        ...(extra.targets ? { targets: extra.targets } : {}),
      });
      spec = resolveRunSpecImage(
        {
          toolId: plan.toolId,
          imageKey: plan.imageKey,
          argv: plan.argv,
          mounts: plan.mounts,
          ...(plan.paths ? { paths: plan.paths } : {}),
          env: plan.env,
          limits: plan.limits,
          labels: plan.labels,
        },
        resolver,
        { scanType },
      );
      const entry = resolver.resolve(plan.imageKey, { scanType });
      record.toolVersion = entry.version;
      record.imageDigest = spec.image.slice(spec.image.indexOf("@") + 1);
      record.limits = { ...plan.limits };
    } catch (error) {
      if (
        error instanceof SandboxError &&
        ["image_unavailable", "tool_deferred"].includes(error.code)
      )
        return finish({ status: "unavailable", reason: "image_unavailable" });
      return finish({ status: "failed", reason: "sandbox_error" });
    }
    const waitStarted = now();
    let release;
    try {
      release = await gate.acquire(
        { tenantId: platform.tenantId, taskId: context.taskId, fork: platform.fork === true },
        { timeoutMs: toolWaitMs, signal },
      );
    } catch {
      const capacityWaitMs = now() - waitStarted;
      return signal.aborted
        ? finish({ status: "cancelled", reason: abortReason(), capacityWaitMs })
        : finish({ status: "unavailable", reason: "capacity", capacityWaitMs });
    }
    record.capacityWaitMs = now() - waitStarted;
    let result;
    try {
      result = await runner.runTool(spec, { signal });
    } catch (error) {
      release();
      if (error instanceof SandboxError && error.code === "image_unavailable")
        return finish({ status: "unavailable", reason: "image_unavailable" });
      return signal.aborted
        ? finish({ status: "cancelled", reason: abortReason() })
        : finish({ status: "failed", reason: "sandbox_error" });
    }
    release();
    const common = { exitCode: exitOf(result.exitCode) };
    if (result.status === "timed_out" || result.timedOut)
      return finish({ ...common, status: "timed_out", reason: "timeout" });
    if (result.status === "aborted" || result.aborted)
      return finish({ ...common, status: "cancelled", reason: abortReason() });
    if (result.status === "output_limit")
      return finish({ ...common, status: "failed", reason: "output_too_large" });
    if (result.status === "runtime_error")
      return finish({ ...common, status: "failed", reason: "sandbox_error" });
    // an exit code the adapter does not accept: one fixed word, the output is never parsed (the stderr only chooses the word)
    const exitReason = classifyToolExit({
      exitCode: result.exitCode,
      stderr: result.stderr,
      accepted: adapter.acceptedExitCodes,
      role: scanType,
      toolId: adapter.toolId,
    });
    if (exitReason === "db_unavailable")
      return finish({ ...common, status: "unavailable", reason: "db_unavailable" });
    if (exitReason !== null) return finish({ ...common, status: "failed", reason: exitReason });
    return finish(
      { ...common, status: "succeeded", reason: null },
      {
        stdout: result.stdout,
        exitCode: result.exitCode,
        truncated: result.stdoutTruncated === true,
      },
    );
  };
}
