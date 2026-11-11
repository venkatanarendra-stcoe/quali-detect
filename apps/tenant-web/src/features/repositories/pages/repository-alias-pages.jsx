import { Navigate, useParams, useSearchParams } from "react-router";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import { useRepository } from "../hooks/use-repositories.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Alias `/repositories/connect?workspace=<id>` -> the canonical wizard route. */
export function ConnectAliasRedirect() {
  const [params] = useSearchParams();
  const workspaceId = params.get("workspace") ?? "";
  if (!UUID.test(workspaceId)) return <Navigate to="/repositories" replace />;
  return <Navigate to={`/workspaces/${workspaceId}/repositories/connect`} replace />;
}

/** Alias `/repositories/:repositoryId` -> the canonical detail route (the workspace comes from the repository itself). */
export function RepositoryAliasRedirect() {
  const { repositoryId } = useParams();
  const query = useRepository(UUID.test(repositoryId ?? "") ? repositoryId : "");
  if (!UUID.test(repositoryId ?? "")) return <NotFoundState />;
  if (query.isPending) return <LoadingState label="Opening repository" rows={2} />;
  if (query.isError) return <QueryErrorState error={query.error} onRetry={query.refetch} />;
  return (
    <Navigate to={`/workspaces/${query.data.workspaceId}/repositories/${query.data.id}`} replace />
  );
}
