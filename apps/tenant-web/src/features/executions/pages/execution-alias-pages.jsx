import { useQuery } from "@tanstack/react-query";
import { Navigate, useLocation, useParams } from "react-router";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { useWorkspaceStore } from "@/features/workspaces/stores/workspace-store.js";
import { executionsService } from "../services/executions-service.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Wireframe routes `/executions` and `/executions/:executionId` redirect to the workspace-nested URL (SCREENS §2). The
 * workspace of a detail link comes from the execution after a read: a hidden, other-tenant or missing one stays the same 404.
 * @param {{ kind: "list" | "detail" }} props
 */
export function ExecutionAliasRedirect({ kind }) {
  const { executionId } = useParams();
  const { search } = useLocation();
  const permissions = usePermissions();
  const tenantId = useTenantId();
  const last = useWorkspaceStore((s) => s.lastWorkspaceByTenant[tenantId]);
  const valid = kind === "detail" && UUID.test(executionId ?? "");
  const execution = useQuery({
    queryKey: ["tenant", tenantId, "execution-alias", executionId],
    queryFn: ({ signal }) => executionsService.get(executionId, { signal }),
    enabled: valid,
    retry: false,
  });
  if (kind === "detail") {
    if (!valid) return <NotFoundState />;
    if (execution.isPending) return <LoadingState label="Opening execution" rows={2} />;
    if (execution.isError)
      return <QueryErrorState error={execution.error} onRetry={execution.refetch} />;
    return (
      <Navigate
        to={`/workspaces/${execution.data.workspaceId}/executions/${execution.data.id}${search}`}
        replace
      />
    );
  }
  const target = permissions.workspaces.find((w) => w.id === last) ?? permissions.workspaces[0];
  if (!target) return <Navigate to="/" replace />;
  return <Navigate to={`/workspaces/${target.id}/executions${search}`} replace />;
}
