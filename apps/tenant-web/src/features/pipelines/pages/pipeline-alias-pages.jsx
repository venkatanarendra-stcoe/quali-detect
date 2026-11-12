import { Navigate, useLocation, useParams, useSearchParams } from "react-router";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { useRepository } from "@/features/repositories/hooks/use-repositories.js";
import { useWorkspaceStore } from "@/features/workspaces/stores/workspace-store.js";
import { usePipeline } from "../hooks/use-pipelines.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Wireframe routes (`/pipelines`, `/pipelines/new`, `/pipelines/:id`, `/pipelines/:id/edit`) redirect to the workspace-nested
 * URL (SCREENS §2). The workspace comes from the pipeline (or the repository for `new`) after a read: a pipeline that is
 * hidden or missing stays the same 404 page.
 * @param {{ kind: "list" | "new" | "detail" | "edit" }} props
 */
export function PipelineAliasRedirect({ kind }) {
  const { pipelineId } = useParams();
  const [params] = useSearchParams();
  const { search } = useLocation();
  const permissions = usePermissions();
  const tenantId = useTenantId();
  const last = useWorkspaceStore((s) => s.lastWorkspaceByTenant[tenantId]);
  const repositoryId = kind === "new" ? (params.get("repository") ?? "") : "";
  const needsPipeline = kind === "detail" || kind === "edit";
  const pipeline = usePipeline(pipelineId ?? "", {
    enabled: needsPipeline && UUID.test(pipelineId ?? ""),
  });
  const repository = useRepository(UUID.test(repositoryId) ? repositoryId : "");

  if (needsPipeline) {
    if (!UUID.test(pipelineId ?? "")) return <NotFoundState />;
    if (pipeline.isPending) return <LoadingState label="Opening pipeline" rows={2} />;
    if (pipeline.isError)
      return <QueryErrorState error={pipeline.error} onRetry={pipeline.refetch} />;
    const suffix = kind === "edit" ? "/edit" : "";
    return (
      <Navigate
        to={`/workspaces/${pipeline.data.workspaceId}/pipelines/${pipeline.data.id}${suffix}`}
        replace
      />
    );
  }
  if (kind === "new" && UUID.test(repositoryId)) {
    if (repository.isPending) return <LoadingState label="Opening wizard" rows={2} />;
    if (repository.isError)
      return <QueryErrorState error={repository.error} onRetry={repository.refetch} />;
    return (
      <Navigate to={`/workspaces/${repository.data.workspaceId}/pipelines/new${search}`} replace />
    );
  }
  const target = permissions.workspaces.find((w) => w.id === last) ?? permissions.workspaces[0];
  if (!target) return <Navigate to="/" replace />;
  return (
    <Navigate to={`/workspaces/${target.id}/pipelines${kind === "new" ? "/new" : ""}`} replace />
  );
}
