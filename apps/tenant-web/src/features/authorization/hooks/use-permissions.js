import { can, canInAnyWorkspace, getPermission } from "@qmentisai/shared";
import { useNavContext } from "@/hooks/use-nav-context.js";
import { useSession } from "@/features/auth/hooks/use-session.js";

const NONE = Object.freeze({ tenant: [], allWorkspaces: [], workspaces: [] });

/** Effective permissions of the signed-in user in the active tenant (from `GET /me`). */
export function usePermissions() {
  const { me } = useSession();
  return me?.permissions ?? NONE;
}

/**
 * `(permissionKey, scope?) => boolean` over the central engine. Without `scope` it is derived from the key: tenant keys
 * at tenant scope, workspace keys in the workspace of the current URL (false outside a workspace). Usability only; the
 * backend enforces every request.
 */
export function useCan() {
  const permissions = usePermissions();
  const { workspaceId } = useNavContext();
  return (permissionKey, scope) => {
    const keyScope = getPermission(permissionKey)?.scope;
    if (scope) return can(permissions, permissionKey, scope);
    if (keyScope === "tenant") return can(permissions, permissionKey);
    if (keyScope === "workspace") {
      return workspaceId
        ? can(permissions, permissionKey, { type: "workspace", workspaceId })
        : canInAnyWorkspace(permissions, permissionKey);
    }
    return false;
  };
}

/** The workspace of the current URL from the permission set (null when outside a workspace or not visible). */
export function useActiveWorkspace() {
  const permissions = usePermissions();
  const { workspaceId } = useNavContext();
  return workspaceId ? (permissions.workspaces.find((w) => w.id === workspaceId) ?? null) : null;
}
