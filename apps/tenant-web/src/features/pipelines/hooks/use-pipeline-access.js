import { manualRunBlockOf } from "@qmentisai/shared";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";

const RUN_DENIED = "You don't have permission to run pipelines in this workspace.";
const RUN_BLOCKS = Object.freeze({
  pipeline_disabled: "Enable the pipeline to run it.",
  repository_not_active: "The repository must be active to run the pipeline.",
  workspace_archived: "The workspace is archived, so nothing can run in it.",
});

/**
 * What the caller may do with one pipeline, from the central engine (never a role name). Usability only; the API
 * enforces every request. `runReason` is null when Run now is available, else the sentence for the disabled control;
 * `canRun` is false for a deleted pipeline (the control is then hidden).
 * @param {{ workspaceId: string, effectiveState: string, deletedAt?: string | null }} pipeline
 */
export function usePipelineAccess(pipeline) {
  const can = useCan();
  const scope = { type: "workspace", workspaceId: pipeline.workspaceId };
  const deleted = Boolean(pipeline.deletedAt);
  const mayRun = can("execution.run", scope);
  const block = manualRunBlockOf(pipeline.effectiveState);
  return {
    deleted,
    canManage: !deleted && can("pipeline.manage", scope),
    canDelete: !deleted && can("pipeline.delete", scope),
    canRunPermission: mayRun,
    showRun: !deleted,
    runReason: !mayRun ? RUN_DENIED : block ? RUN_BLOCKS[block] : null,
    canForkPolicy: can("pipeline.manage_fork_policy", scope),
    canCancel: !deleted && can("execution.cancel", scope),
    canViewExecutions: can("execution.view", scope),
  };
}
