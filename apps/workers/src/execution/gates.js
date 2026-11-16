import { createHash } from "node:crypto";
import { EntitlementError, QUOTA_KEYS } from "@qmentisai/db";
import { PIPELINE_SCAN_TYPES, SCAN_TASK_ORDER, canonicalJson } from "@qmentisai/shared";
import { CONFIG_SCHEMA } from "../pipeline/execution-request.js";

/** Recomputes the canonical hash of a stored configuration version (SPEC §5.7: SHA-256 over `{ schemaVersion, config }`). */
export const hashStoredConfig = (config) =>
  createHash("sha256")
    .update(canonicalJson({ schemaVersion: config?.schemaVersion, config }))
    .digest("hex");

/** The enabled scan types of a validated configuration, in the fixed catalog order (ER-11). */
export const enabledScanTypes = (cfg) =>
  SCAN_TASK_ORDER.filter(
    (type) => PIPELINE_SCAN_TYPES.includes(type) && cfg.scans?.[type]?.enabled,
  );

/**
 * The re-validation gates of a claim (docs/modules/executions/SPEC.md §6.2, EXEC-005, B2), evaluated in the order of the spec,
 * FROM THE DATABASE (never from a message), inside the claim transaction under the pipeline advisory lock. Returns a decision:
 * - `{ decision: "cancel", reason }`: the execution can never run (the queued row is cancelled, quota released once);
 * - `{ decision: "defer", reason }`: leave it `queued` and try again next tick (suspended tenant, limits);
 * - `{ decision: "invalid", reason, config? }`: the snapshot cannot be trusted: claim, then fail the execution;
 * - `{ decision: "go", cfg, repository, pipeline }`.
 * @param {{ entitlements: { assertEntitlement: Function }, staleThresholdSeconds: number }} deps
 * @param {any} tx The claim transaction client.
 * @param {{ id: string, tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, configVersionId: string, configHash: string }} exec the row, re-read by tenant and id
 */
export async function evaluateGates({ entitlements, staleThresholdSeconds }, tx, exec) {
  const { tenantId } = exec;
  // 1. never start a stale run (ER-32): evaluated first, with the database clock
  const [age] = await tx.$queryRaw`
    SELECT (requested_at < now() - make_interval(secs => ${staleThresholdSeconds}::double precision)) AS stale
    FROM executions WHERE id = ${exec.id}::uuid AND tenant_id = ${tenantId}::uuid`;
  if (age?.stale) return { decision: "cancel", reason: "queue_expired" };
  // 2. tenant lifecycle: a suspended tenant may be restored, so its rows stay queued
  const tenant = await tx.tenant.findUnique({ where: { id: tenantId }, select: { status: true } });
  if (tenant?.status === "suspended") return { decision: "defer", reason: "tenant_suspended" };
  if (!tenant || !["active", "trial"].includes(tenant.status))
    return { decision: "cancel", reason: "tenant_inactive" };
  // 3. workspace in the tenant and active
  const workspace = await tx.workspace.findFirst({
    where: { id: exec.workspaceId, tenantId },
    select: { status: true },
  });
  if (workspace?.status !== "active") return { decision: "cancel", reason: "workspace_archived" };
  // 4/5. repository by tenant and id, in the workspace, active and enabled
  const repository = await tx.repository.findFirst({
    where: { id: exec.repositoryId, tenantId, workspaceId: exec.workspaceId },
    select: {
      id: true,
      fullName: true,
      status: true,
      enabled: true,
      link: {
        select: {
          status: true,
          installation: { select: { externalInstallationId: true, status: true } },
        },
      },
    },
  });
  if (!repository || repository.status !== "active")
    return { decision: "cancel", reason: "repository_inactive" };
  if (!repository.enabled) return { decision: "cancel", reason: "repository_disabled" };
  // 6/7. pipeline in the chain, not deleted, enabled
  const pipeline = await tx.pipeline.findFirst({
    where: {
      id: exec.pipelineId,
      tenantId,
      workspaceId: exec.workspaceId,
      repositoryId: exec.repositoryId,
    },
    select: { id: true, enabled: true, deletedAt: true },
  });
  if (!pipeline || pipeline.deletedAt) return { decision: "cancel", reason: "pipeline_deleted" };
  if (!pipeline.enabled) return { decision: "cancel", reason: "pipeline_disabled" };
  // 8. entitlement (no new consumption: the unit was taken when the request was created)
  try {
    await entitlements.assertEntitlement({ tenantId, key: QUOTA_KEYS.SCANS_MONTHLY }, tx);
  } catch (error) {
    if (error instanceof EntitlementError)
      return { decision: "cancel", reason: "entitlement_required" };
    throw error;
  }
  // snapshot, loaded before the limits so a broken snapshot is failed rather than left to age out
  const version = await tx.pipelineConfigVersion.findFirst({
    where: { id: exec.configVersionId, tenantId, pipelineId: exec.pipelineId },
    select: { config: true, configHash: true, schemaVersion: true },
  });
  if (
    !version ||
    version.configHash !== exec.configHash ||
    hashStoredConfig(version.config) !== exec.configHash
  )
    return { decision: "invalid", reason: "config_snapshot_mismatch" };
  const parsed = CONFIG_SCHEMA.safeParse(version.config);
  if (!parsed.success || version.schemaVersion !== 1)
    return { decision: "invalid", reason: "config_invalid" };
  const cfg = parsed.data;
  // 9. concurrency: the pipeline's maxActive (platform and tenant limits are Open, OD)
  const active = await tx.execution.count({
    where: { tenantId, pipelineId: exec.pipelineId, status: { in: ["preparing", "running"] } },
  });
  if (active >= (cfg.execution?.concurrency?.maxActive ?? 1))
    return { decision: "defer", reason: "limit_reached" };
  // SPEC §17.ab (amends EQ-7a/EXEC-026): a scan type without a registered engine no longer defers the claim; its task is created
  // `unsupported` (engine_not_registered) and the execution runs the types that do have an engine.
  return { decision: "go", cfg, repository, pipeline };
}
