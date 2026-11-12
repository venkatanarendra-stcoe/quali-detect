/**
 * The derived effective state of a pipeline (SPEC §5.2, PIPE-019, owner decision C5): the stored `enabled` flag is the
 * user's intent and is never flipped; whether a pipeline can fire is computed from the current state of its tenant, workspace
 * and repository. Pure, shared by the API (display, manual-run gate, dry-run) and the worker (event routing, schedules).
 */

const USABLE_TENANT = ["active", "trial"];

/**
 * @param {{
 *   tenantStatus?: string | null,
 *   workspaceStatus: string,
 *   repositoryStatus: string,
 *   repositoryEnabled: boolean,
 *   pipelineEnabled: boolean,
 *   pipelineDeletedAt?: Date | string | null,
 * }} input `tenantStatus` is optional: omit it when the caller already runs inside a usable tenant
 * @returns {"running_normally" | "disabled" | "repository_disabled" | "repository_unavailable" | "repository_disconnected" | "workspace_archived" | "tenant_unavailable" | "deleted"}
 */
export function computeEffectiveState({
  tenantStatus,
  workspaceStatus,
  repositoryStatus,
  repositoryEnabled,
  pipelineEnabled,
  pipelineDeletedAt = null,
}) {
  if (pipelineDeletedAt) return "deleted";
  if (tenantStatus && !USABLE_TENANT.includes(tenantStatus)) return "tenant_unavailable";
  if (!pipelineEnabled) return "disabled";
  if (workspaceStatus !== "active") return "workspace_archived";
  if (repositoryStatus === "disconnected") return "repository_disconnected";
  if (repositoryStatus === "unavailable") return "repository_unavailable";
  if (repositoryStatus !== "active") return "repository_unavailable";
  if (!repositoryEnabled) return "repository_disabled";
  return "running_normally";
}

/**
 * The trigger decision reason (SPEC §7.8) a blocked effective state is recorded with, or null when it can fire.
 * @param {string} state
 * @returns {"pipeline_disabled" | "repository_inactive" | "repository_disabled" | "workspace_archived" | "tenant_unavailable" | null}
 */
export function gateReasonOf(state) {
  switch (state) {
    case "running_normally":
      return null;
    case "disabled":
    case "deleted":
      return "pipeline_disabled";
    case "repository_disabled":
      return "repository_disabled";
    case "repository_unavailable":
    case "repository_disconnected":
      return "repository_inactive";
    case "workspace_archived":
      return "workspace_archived";
    default:
      return "tenant_unavailable";
  }
}

/**
 * Why a MANUAL run is refused for this state (SPEC §5.6: `pipeline_disabled`, `repository_not_active`, plus
 * `workspace_archived`), or null when the state allows it.
 * @param {string} state
 * @returns {"pipeline_disabled" | "repository_not_active" | "workspace_archived" | null}
 */
export function manualRunBlockOf(state) {
  switch (state) {
    case "running_normally":
      return null;
    case "workspace_archived":
      return "workspace_archived";
    case "repository_disabled":
    case "repository_unavailable":
    case "repository_disconnected":
      return "repository_not_active";
    default:
      return "pipeline_disabled";
  }
}
