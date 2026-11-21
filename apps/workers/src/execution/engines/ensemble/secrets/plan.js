import { planSastTool } from "../sast/plan.js";

/**
 * The run plan of a Secrets tool (docs/modules/scan-engines/SPEC.md 5.8, 5.9, 6.2, 11.3). The same construction as the SAST plan: platform data
 * only, a constant argument vector per tool, a repository-derived string only as an explicit, validated target after `--` (detect-secrets
 * only; Gitleaks always scans the whole tree and the findings are filtered afterwards, SPEC 5.9). The image is a catalog KEY.
 */

const MiB = 1024 * 1024;

/** Per-tool container limits (SPEC 5.8 Recommended; calibrated by ENG-L23 on the owner's machine). */
export const SECRETS_TOOL_LIMITS = Object.freeze({
  gitleaks: Object.freeze({
    cpus: 1,
    memoryMiB: 1024,
    pids: 128,
    wallClockSeconds: 300,
    stdoutBytes: 32 * MiB,
    tmpfsMiB: 128,
  }),
  "detect-secrets": Object.freeze({
    cpus: 1,
    memoryMiB: 1024,
    pids: 128,
    wallClockSeconds: 300,
    stdoutBytes: 32 * MiB,
    tmpfsMiB: 128,
  }),
});

/**
 * @param {{ toolId: string, imageKey: string, argv: readonly string[], fullTarget: readonly string[], env: Record<string, string>, limits: Readonly<Record<string, number>> }} tool
 * @param {import("../sast/plan.js").SastPlanContext} ctx `rulesDir` is the platform configuration directory (`/rules`)
 */
export function planSecretsTool(tool, ctx) {
  return planSastTool(tool, ctx);
}
