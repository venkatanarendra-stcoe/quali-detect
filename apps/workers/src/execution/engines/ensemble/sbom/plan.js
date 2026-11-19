/**
 * The run plan of an SBOM tool (docs/modules/scan-engines/SPEC.md 5.8, 6.2, 11.3, SE-2, SE-3). A plan is built from PLATFORM data only
 * (the trusted task identity, the two mount sources, the limits) and contains NO repository-derived string: the argument vector is
 * a constant per tool, the image is a catalog KEY that part B resolves to a digest, the environment holds the tool's offline
 * switches, and the working directory (`/tmp`) is fixed by `buildRunArgs`. Nothing here starts anything.
 */

const MiB = 1024 * 1024;

/** Per-tool container limits (SPEC 5.8, Recommended; to be calibrated by ENG-L10). */
export const SBOM_TOOL_LIMITS = Object.freeze({
  syft: Object.freeze({
    cpus: 1,
    memoryMiB: 1024,
    pids: 128,
    wallClockSeconds: 180,
    stdoutBytes: 64 * MiB,
    tmpfsMiB: 512,
  }),
  trivy: Object.freeze({
    cpus: 2,
    memoryMiB: 2048,
    pids: 256,
    wallClockSeconds: 300,
    stdoutBytes: 64 * MiB,
    tmpfsMiB: 512,
  }),
});

/**
 * @typedef {object} SbomPlanContext
 * @property {string} tenantId @property {string} executionId @property {string} taskId @property {number} attempt
 * @property {number} deadlineEpoch the task deadline (epoch seconds), written to the janitor label
 * @property {string} archiveDir host directory of the extracted tree (mounted read-only at /src)
 * @property {string} rulesDir host directory of the platform-owned tool configuration (mounted read-only at /rules)
 * @property {number} [secondsToDeadline] caps the wall clock (`min(tool limit, task seconds left)`, SPEC 5.8)
 */

/**
 * @param {{ toolId: string, imageKey: string, argv: readonly string[], env: Record<string, string>, limits: Readonly<Record<string, number>> }} tool
 * @param {SbomPlanContext} ctx
 */
export function planSbomTool(tool, ctx) {
  for (const key of ["tenantId", "executionId", "taskId", "archiveDir", "rulesDir"])
    if (typeof ctx?.[key] !== "string" || ctx[key].length === 0)
      throw new TypeError(`plan context needs ${key}`);
  if (!Number.isInteger(ctx.attempt) || !Number.isInteger(ctx.deadlineEpoch))
    throw new TypeError("plan context needs an integer attempt and deadlineEpoch");
  const wall =
    Number.isInteger(ctx.secondsToDeadline) && ctx.secondsToDeadline > 0
      ? Math.min(tool.limits.wallClockSeconds, ctx.secondsToDeadline)
      : tool.limits.wallClockSeconds;
  return {
    toolId: tool.toolId,
    imageKey: tool.imageKey,
    argv: [...tool.argv],
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
