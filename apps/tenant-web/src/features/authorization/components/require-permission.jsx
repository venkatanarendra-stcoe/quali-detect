import { canInAnyWorkspace, can } from "@qmentisai/shared";
import { useParams } from "react-router";
import { UnauthorizedState } from "@/components/states/unauthorized-state.jsx";
import { usePermissions } from "../hooks/use-permissions.js";

/**
 * Route guard: renders the page only when the permission is held, otherwise the 403 state (the page is visible to the
 * user's workspace but not permitted). `scope`: "tenant" (default), "workspace" (workspace of the URL) or "anyWorkspace".
 * Workspaces the user cannot see never reach this guard: `WorkspaceScope` answers 404 first.
 * @param {{ permission: string, scope?: "tenant" | "workspace" | "anyWorkspace", children: any }} props
 */
export function RequirePermission({ permission, scope = "tenant", children }) {
  const permissions = usePermissions();
  const { workspaceId } = useParams();
  let allowed = false;
  if (scope === "tenant") allowed = can(permissions, permission);
  else if (scope === "anyWorkspace") allowed = canInAnyWorkspace(permissions, permission);
  else if (workspaceId) allowed = can(permissions, permission, { type: "workspace", workspaceId });
  return allowed ? children : <UnauthorizedState />;
}
