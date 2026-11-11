import { Navigate } from "react-router";
import { canInAnyWorkspace, can } from "@qmentisai/shared";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { useWorkspaceStore } from "@/features/workspaces/stores/workspace-store.js";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { ShieldOff } from "lucide-react";

/** `/`: the organization overview when permitted, else the workspaces list, else a "no access" state. */
export function LandingRedirect() {
  const permissions = usePermissions();
  if (can(permissions, "dashboard.view")) return <Navigate to="/overview" replace />;
  if (canInAnyWorkspace(permissions, "workspace.view"))
    return <Navigate to="/workspaces" replace />;
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
