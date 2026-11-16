import { ArrowLeft, LogOut, Shield } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useLocation } from "react-router";
import { ORG_NAV_GROUPS, WORKSPACE_NAV_GROUPS, evaluateNavigation } from "@qmentisai/shared";
import { isRouteAvailable } from "@/app/routes.jsx";
import { useAuthActions } from "@/features/auth/hooks/use-auth-actions.js";
import { useSession } from "@/features/auth/hooks/use-session.js";
import { usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { useNavContext } from "@/hooks/use-nav-context.js";
import { cn } from "@/lib/cn.js";
import { GROUP_LABELS, NAV_ITEMS } from "./nav.js";
import { NotificationsItem } from "./notifications.jsx";
import { WorkspaceSwitcher } from "./workspace-switcher.jsx";

const isActive = (pathname, paths) =>
  paths.some((p) => pathname === p || pathname.startsWith(`${p}/`));

/**
 * Sidebar (240 px), the only app chrome (the top bar was removed by owner decision, 2026-11-16). Top to bottom: logo,
 * the organization (and, inside a workspace, "All workspaces" + the workspace switcher), then the navigation. The last
 * group ("You"; defined in `@qmentisai/shared`, no permission) is Account, Settings, Notifications (an action item: it
 * opens the drawer and carries the unread badge) and Sign out as its last row. Nothing notification-related sits above
 * the navigation (owner decision 2026-11-17). There is no search / command palette
 * trigger (removed 2026-11-16) and no bottom-pinned account block. Organization layout outside a workspace, Workspace
 * layout inside one. The items come from `evaluateNavigation` (implemented && permitted && route exists); empty groups
 * are not rendered.
 */
export function Sidebar({ onNavigate }) {
  const { layout, workspaceId } = useNavContext();
  const { me } = useSession();
  const permissions = usePermissions();
  const { pathname } = useLocation();
  const { logout } = useAuthActions();
  const [notificationsOpen, setNotificationsOpen] = useState(false);

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

  const rowClass =
    "flex h-8 w-full items-center gap-2.5 rounded-sm px-2 text-sm outline-none transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring";

  return (
    <nav
      aria-label="Main navigation"
      className="flex h-full w-60 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground"
    >
      <div className="flex h-12 items-center gap-2 border-b border-sidebar-border px-4">
        <Shield aria-hidden="true" className="size-5 text-foreground" strokeWidth={1.75} />
        <Link
          to="/"
          className="rounded-sm text-sm font-semibold text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring"
          onClick={onNavigate}
        >
          QmentisAI
        </Link>
      </div>

      <div className="space-y-3 border-b border-sidebar-border px-3 py-3">
        <p className="truncate px-1 text-xs text-muted-foreground" title={me.tenant.name}>
          {me.tenant.name}
        </p>
        {layout === "workspace" ? (
          <div className="space-y-2">
            <Link
              to={canListWorkspaces ? "/workspaces" : "/"}
              onClick={onNavigate}
              className="flex items-center gap-1.5 rounded-sm px-1 text-xs text-muted-foreground outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
            >
              <ArrowLeft aria-hidden="true" className="size-3.5" /> All workspaces
            </Link>
            <WorkspaceSwitcher onNavigate={onNavigate} />
          </div>
        ) : null}
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
                  if (def.action === "notifications")
                    return (
                      <li key={item.id}>
                        <NotificationsItem
                          open={notificationsOpen}
                          onOpenChange={setNotificationsOpen}
                          itemClassName={rowClass}
                        />
                      </li>
                    );
                  const active = isActive(pathname, def.matches(workspaceId));
                  const Icon = def.icon;
                  return (
                    <li key={item.id}>
                      <Link
                        to={def.to(workspaceId)}
                        onClick={onNavigate}
                        aria-current={active ? "page" : undefined}
                        className={cn(
                          "relative flex h-8 items-center gap-2.5 rounded-sm px-2 text-sm outline-none transition-colors focus-visible:ring-2 focus-visible:ring-ring",
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
                {group.id === "account" ? (
                  <li>
                    <button
                      type="button"
                      onClick={() => logout.mutate()}
                      disabled={logout.isPending}
                      className={cn(rowClass, "disabled:opacity-60")}
                    >
                      <LogOut
                        aria-hidden="true"
                        className="size-4 shrink-0 text-muted-foreground"
                        strokeWidth={1.75}
                      />
                      <span className="truncate">Sign out</span>
                    </button>
                  </li>
                ) : null}
              </ul>
            </section>
          ))
        )}
      </div>
    </nav>
  );
}
