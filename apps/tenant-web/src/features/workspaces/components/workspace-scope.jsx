import { useEffect } from "react";
import { Outlet, useParams } from "react-router";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { useWorkspaceStore } from "../stores/workspace-store.js";

/**
 * Wraps `/workspaces/:workspaceId/*`. A workspace that is not in the user's visible set answers with the SAME 404 page as
 * one that does not exist. Pages are remounted per workspace (`key`), and cache keys include the workspace id, so data of
 * the previous workspace is never shown.
 */
export function WorkspaceScope() {
  const { workspaceId } = useParams();
  const tenantId = useTenantId();
  const permissions = usePermissions();
  const rememberWorkspace = useWorkspaceStore((s) => s.rememberWorkspace);
  const visible = permissions.workspaces.some((w) => w.id === workspaceId);

  useEffect(() => {
    if (visible && tenantId) rememberWorkspace(tenantId, workspaceId);
  }, [visible, tenantId, workspaceId, rememberWorkspace]);

  if (!visible) return <NotFoundState />;
  return <Outlet key={workspaceId} />;
}
