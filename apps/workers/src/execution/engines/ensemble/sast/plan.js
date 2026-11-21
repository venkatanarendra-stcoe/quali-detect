import { isSafeTargetPath } from "./scope.js";

/**
 * The run plan of a SAST tool (docs/modules/scan-engines/SPEC.md 5.8, 5.9 SE-27, 6.2, 11.3, SE-2, SE-3). Built from PLATFORM data only:
 * the trusted task identity, the mount sources (the extracted tree, the platform rule pack and tool configuration), the limits. The
 * argument vector is a constant per tool; a repository-derived string enters ONLY as an explicit target, validated by
 * {@link isSafeTargetPath}, in the `paths` field that the runner places after `--` under the archive mount. The image is a catalog
 * KEY. Nothing here starts anything.
 */

const MiB = 1024 * 1024;

/** Per-tool container limits (SPEC 5.8 Recommended; calibrated by ENG-L22 on the owner's machine). */
export const SAST_TOOL_LIMITS = Object.freeze({
  opengrep: Object.freeze({
    cpus: 2,
    memoryMiB: 3072,
    pids: 512,
    wallClockSeconds: 600,
    stdoutBytes: 64 * MiB,
    tmpfsMiB: 512,
  }),
  bandit: Object.freeze({
    cpus: 1,
    memoryMiB: 1024,
    pids: 128,
    wallClockSeconds: 240,
    stdoutBytes: 32 * MiB,
    tmpfsMiB: 256,
  }),
});

/**
 * @typedef {object} SastPlanContext
 * @property {string} tenantId @property {string} executionId @property {string} taskId @property {number} attempt
 * @property {number} deadlineEpoch the task deadline (epoch seconds), written to the janitor label
 * @property {string} archiveDir host directory of the extracted tree (mounted read-only at /src)
 * @property {string} rulesDir host directory of the platform rule pack and tool configuration (mounted read-only at /rules)
 * @property {number} [secondsToDeadline] caps the wall clock (`min(tool limit, task seconds left)`, SPEC 5.8)
 * @property {string[]} [targets] explicit relative file targets (an incremental run); absent: the whole tree (`/src`)
 */

/**
 * @param {{ toolId: string, imageKey: string, argv: readonly string[], fullTarget: readonly string[], env: Record<string, string>, limits: Readonly<Record<string, number>> }} tool
 * `fullTarget` is the argument that names the whole tree (`["/src"]` for Opengrep, `["-r", "/src"]` for Bandit); it is omitted in a targets run
 * @param {SastPlanContext} ctx
 */
export function planSastTool(tool, ctx) {
  for (const key of ["tenantId", "executionId", "taskId", "archiveDir", "rulesDir"])
    if (typeof ctx?.[key] !== "string" || ctx[key].length === 0)
      throw new TypeError(`plan context needs ${key}`);
  if (!Number.isInteger(ctx.attempt) || !Number.isInteger(ctx.deadlineEpoch))
    throw new TypeError("plan context needs an integer attempt and deadlineEpoch");
  if (ctx.targets !== undefined) {
    if (
      !Array.isArray(ctx.targets) ||
      ctx.targets.length === 0 ||
      !ctx.targets.every(isSafeTargetPath)
    )
      throw new TypeError("targets must be a non-empty list of safe relative paths");
  }
  const wall =
    Number.isInteger(ctx.secondsToDeadline) && ctx.secondsToDeadline > 0
      ? Math.min(tool.limits.wallClockSeconds, ctx.secondsToDeadline)
      : tool.limits.wallClockSeconds;
  return {
    toolId: tool.toolId,
    imageKey: tool.imageKey,
    argv: [...tool.argv, ...(ctx.targets === undefined ? tool.fullTarget : [])],
    ...(ctx.targets === undefined ? {} : { paths: [...ctx.targets] }),
    mounts: { archive: ctx.archiveDir, rules: ctx.rulesDir },
    env: { ...tool.env },
    limits: { ...tool.limits, wallClockSeconds: wall },
    labels: {
      tenantId: ctx.tenantId,
      executionId: ctx.executionId,
      taskId: ctx.taskId,
      attempt: ctx.attempt,
      deadlineEpoch: ctx.deadlineEpoch,
    },
  };
}
