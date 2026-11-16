import { LogOut, Shield } from "lucide-react";
import { useScrollActivity } from "@qmentisai/ui";
import { useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router";
import { evaluatePlatformNavigation } from "@qmentisai/shared/platform";
import { isRouteAvailable } from "@/app/routes.jsx";
import { useAuthActions } from "@/features/auth/hooks/use-auth-actions.js";
import { usePlatformPermissions } from "@/features/authorization/hooks/use-platform-permissions.js";
import { cn } from "@/lib/cn.js";
import { GROUP_LABELS, NAV_ITEMS } from "./nav.js";
import { NotificationsItem } from "./notifications.jsx";
import { SystemStatus } from "./system-status.jsx";

const isActive = (pathname, to) => pathname === to || pathname.startsWith(`${to}/`);

/**
 * Dark sidebar (dark in light mode too), the only app chrome besides the environment strip (the top bar was removed by
 * owner decision, 2026-11-16). Top to bottom: "QmentisAI Platform" logo, the navigation from
 * `evaluatePlatformNavigation` with the user's `platform.*` permissions (empty groups are not rendered), and the
 * system-status indicator. The last group ("You", no permission) is Account, Settings, Notifications (an action item:
 * opens the drawer, unread badge) and Sign out as its last row (owner decision 2026-11-17). No search / command palette trigger (removed 2026-11-16), no
 * bottom-pinned account block, no workspace switcher.
 */
export function Sidebar({ onNavigate }) {
  const permissions = usePlatformPermissions();
  const { pathname } = useLocation();
  const scrollRef = useRef(null);
  const { logout } = useAuthActions();
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  useScrollActivity(scrollRef);
  const groups = useMemo(
    () => evaluatePlatformNavigation({ permissions, isRouteAvailable }),
    [permissions],
  );
  return (
    <nav
      aria-label="Main navigation"
      className="flex h-full w-60 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground"
    >
      <div className="flex h-12 items-center gap-2 border-b border-sidebar-border px-4">
        <Shield aria-hidden="true" className="size-5 text-sidebar-strong" strokeWidth={1.75} />
        <Link
          to="/"
          onClick={onNavigate}
          className="rounded-sm text-sm font-semibold text-sidebar-strong outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          QmentisAI Platform
        </Link>
      </div>
      <div
        ref={scrollRef}
        className="qm-scroll qm-scroll-dark min-h-0 flex-1 overflow-y-auto px-3 py-3"
      >
        {groups.length === 0 ? (
          <p className="px-1 text-xs text-sidebar-muted">No pages are available to your role.</p>
        ) : (
          groups.map((group) => (
            <section key={group.id} aria-labelledby={`nav-${group.id}`} className="mb-4">
              <h2
                id={`nav-${group.id}`}
                className="mb-1 px-2 text-xs font-medium text-sidebar-muted"
              >
                {GROUP_LABELS[group.id]}
              </h2>
              <ul className="space-y-0.5">
                {group.items.map((entry) => {
                  const def = NAV_ITEMS[entry.id];
                  if (def.action === "notifications")
                    return (
                      <li key={entry.id}>
                        <NotificationsItem
                          open={notificationsOpen}
                          onOpenChange={setNotificationsOpen}
                        />
                      </li>
                    );
                  const active = isActive(pathname, def.to);
                  const Icon = def.icon;
                  return (
                    <li key={entry.id}>
                      <Link
                        to={def.to}
                        onClick={onNavigate}
                        aria-current={active ? "page" : undefined}
                        className={cn(
                          "relative flex h-8 items-center gap-2.5 rounded-sm px-2 text-sm outline-none transition-colors focus-visible:ring-2 focus-visible:ring-ring",
                          active
                            ? "bg-sidebar-active font-medium text-sidebar-active-foreground before:absolute before:inset-y-1 before:left-0 before:w-0.5 before:rounded-full before:bg-sidebar-indicator"
                            : "hover:bg-sidebar-hover hover:text-sidebar-strong",
                        )}
                      >
                        <Icon aria-hidden="true" className="size-4 shrink-0" strokeWidth={1.75} />
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
                      className="flex h-8 w-full items-center gap-2.5 rounded-sm px-2 text-sm outline-none transition-colors hover:bg-sidebar-hover hover:text-sidebar-strong focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60"
                    >
                      <LogOut aria-hidden="true" className="size-4 shrink-0" strokeWidth={1.75} />
                      <span className="truncate">Sign out</span>
                    </button>
                  </li>
                ) : null}
              </ul>
            </section>
          ))
        )}
      </div>
      <div className="border-t border-sidebar-border p-2">
        <SystemStatus />
      </div>
    </nav>
  );
}
