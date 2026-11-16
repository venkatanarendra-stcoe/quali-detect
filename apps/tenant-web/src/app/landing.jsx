import { Navigate } from "react-router";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { useLanding } from "@/features/account/index.js";
import { usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { useWorkspaceStore } from "@/features/workspaces/stores/workspace-store.js";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { ShieldOff } from "lucide-react";

/**
 * `/` (also the post-login landing): asks the server where to go (`GET /me/landing`, decided at request time from the
 * caller's current permissions): the saved default workspace while it is still accessible, else the Organization Overview
 * (holders of `dashboard.view`), else the first accessible workspace, else a "no access" state. The server never reveals a
 * workspace the caller cannot see; this component only follows what it is told.
 */
export function LandingRedirect() {
  const tenantId = useTenantId();
  const landing = useLanding(tenantId);
  if (landing.isPending) return <LoadingState rows={2} label="Opening your workspace" />;
  if (landing.isError) return <QueryErrorState error={landing.error} onRetry={landing.refetch} />;
  const { target, workspaceId } = landing.data;
  if (target === "workspace")
    return <Navigate to={`/workspaces/${workspaceId}/dashboard`} replace />;
  if (target === "overview") return <Navigate to="/overview" replace />;
  return (
    <EmptyState
      icon={ShieldOff}
      title="No access yet"
      description="You are a member of this organization but have no workspace access. Ask an administrator to assign you a role."
    />
  );
}

/** Legacy `/repositories`: the repositories page of the last or first accessible workspace. */
export function LegacyRepositoriesRedirect() {
  const permissions = usePermissions();
  const tenantId = useTenantId();
  const last = useWorkspaceStore((s) => s.lastWorkspaceByTenant[tenantId]);
  const target = permissions.workspaces.find((w) => w.id === last) ?? permissions.workspaces[0];
  if (!target) return <Navigate to="/" replace />;
  return <Navigate to={`/workspaces/${target.id}/repositories`} replace />;
}
