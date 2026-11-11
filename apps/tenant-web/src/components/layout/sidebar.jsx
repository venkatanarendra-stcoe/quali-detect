import { ArrowLeft, Shield } from "lucide-react";
import { useMemo } from "react";
import { Link, useLocation } from "react-router";
import { ORG_NAV_GROUPS, WORKSPACE_NAV_GROUPS, evaluateNavigation } from "@qmentisai/shared";
import { isRouteAvailable } from "@/app/routes.jsx";
import { useSession } from "@/features/auth/hooks/use-session.js";
import { usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { useNavContext } from "@/hooks/use-nav-context.js";
import { cn } from "@/lib/cn.js";
import { GROUP_LABELS, NAV_ITEMS } from "./nav.js";
import { WorkspaceSwitcher } from "./workspace-switcher.jsx";

const isActive = (pathname, paths) =>
  paths.some((p) => pathname === p || pathname.startsWith(`${p}/`));

/**
 * Sidebar (240 px). Organization layout outside a workspace, Workspace layout inside one. The items come from
 * `evaluateNavigation` (implemented && permitted && route exists); empty groups are not rendered. No account area here:
 * the account menu lives in the top bar only.
 */
export function Sidebar({ onNavigate }) {
  const { layout, workspaceId } = useNavContext();
  const { me } = useSession();
  const permissions = usePermissions();
  const { pathname } = useLocation();

  const groups = useMemo(
    () =>
      evaluateNavigation(layout === "workspace" ? WORKSPACE_NAV_GROUPS : ORG_NAV_GROUPS, {
        permissions,
        workspaceId,
        isRouteAvailable,
      }),
    [layout, permissions, workspaceId],
  );
  const canListWorkspaces = useMemo(
    () =>
      evaluateNavigation(ORG_NAV_GROUPS, { permissions, isRouteAvailable }).some((g) =>
        g.items.some((i) => i.id === "workspaces"),
      ),
    [permissions],
  );

  return (
    <nav
      aria-label="Main navigation"
      className="flex h-full w-60 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground"
    >
      <div className="flex h-12 items-center gap-2 border-b border-sidebar-border px-4">
        <Shield aria-hidden="true" className="size-5 text-foreground" strokeWidth={1.75} />
        <Link to="/" className="text-sm font-semibold text-foreground" onClick={onNavigate}>
          QmentisAI
        </Link>
      </div>

      <div className="border-b border-sidebar-border px-3 py-3">
        {layout === "workspace" ? (
          <div className="space-y-2">
            <Link
              to={canListWorkspaces ? "/workspaces" : "/"}
              onClick={onNavigate}
              className="flex items-center gap-1.5 rounded-sm px-1 text-xs text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft aria-hidden="true" className="size-3.5" /> All workspaces
            </Link>
            <WorkspaceSwitcher onNavigate={onNavigate} />
          </div>
        ) : (
          <p className="truncate px-1 text-xs text-muted-foreground" title={me.tenant.name}>
            {me.tenant.name}
          </p>
        )}
      </div>

      <div className="flex-1 overflow-y-auto px-3 py-3">
        {groups.length === 0 ? (
          <p className="px-1 text-xs text-muted-foreground">No pages are available to you here.</p>
        ) : (
          groups.map((group) => (
            <section key={group.id} aria-labelledby={`nav-${group.id}`} className="mb-4">
              <h2
                id={`nav-${group.id}`}
                className="mb-1 px-2 text-xs font-medium text-subtle-foreground"
              >
                {GROUP_LABELS[group.id]}
              </h2>
              <ul className="space-y-0.5">
                {group.items.map((item) => {
                  const def = NAV_ITEMS[item.id];
                  const active = isActive(pathname, def.matches(workspaceId));
                  const Icon = def.icon;
                  return (
                    <li key={item.id}>
                      <Link
                        to={def.to(workspaceId)}
                        onClick={onNavigate}
                        aria-current={active ? "page" : undefined}
                        className={cn(
                          "relative flex h-8 items-center gap-2.5 rounded-sm px-2 text-sm transition-colors",
                          active
                            ? "bg-sidebar-active font-medium text-sidebar-active-foreground before:absolute before:inset-y-1 before:left-0 before:w-0.5 before:rounded-full before:bg-primary"
                            : "hover:bg-accent hover:text-foreground",
                        )}
                      >
                        <Icon
                          aria-hidden="true"
                          className={cn(
                            "size-4 shrink-0",
                            active ? "text-sidebar-active-foreground" : "text-muted-foreground",
                          )}
                          strokeWidth={1.75}
                        />
                        <span className="truncate">{def.label}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </section>
          ))
        )}
      </div>
    </nav>
  );
}
