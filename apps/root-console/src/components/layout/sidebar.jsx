import { Search, Shield } from "lucide-react";
import { useScrollActivity } from "@qmentisai/ui";
import { useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router";
import { evaluatePlatformNavigation } from "@qmentisai/shared/platform";
import { isRouteAvailable } from "@/app/routes.jsx";
import { usePlatformPermissions } from "@/features/authorization/hooks/use-platform-permissions.js";
import { cn } from "@/lib/cn.js";
import { AccountMenu } from "./account-menu.jsx";
import { CommandPalette } from "./command-palette.jsx";
import { GROUP_LABELS, NAV_ITEMS } from "./nav.js";
import { NotificationsItem } from "./notifications.jsx";
import { SystemStatus } from "./system-status.jsx";

const isActive = (pathname, to) => pathname === to || pathname.startsWith(`${to}/`);

/**
 * Dark sidebar (dark in light mode too), the only app chrome besides the environment strip (the top bar was removed by
 * owner decision, 2026-11-16). Top to bottom: "QmentisAI Platform" logo, search / command palette trigger (⌘K),
 * Notifications with its unread badge, the navigation from `evaluatePlatformNavigation` with the user's `platform.*`
 * permissions (empty groups are not rendered), the system-status indicator, and the account area pinned at the bottom.
 * No workspace switcher.
 */
export function Sidebar({ onNavigate }) {
  const permissions = usePlatformPermissions();
  const { pathname } = useLocation();
  const scrollRef = useRef(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const searchRef = useRef(null);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  useScrollActivity(scrollRef);
  const groups = useMemo(
    () => evaluatePlatformNavigation({ permissions, isRouteAvailable }),
    [permissions],
  );
  const paletteEntries = useMemo(
    () => [
      ...groups.flatMap((group) =>
        group.items.map((entry) => ({
          id: entry.id,
          label: NAV_ITEMS[entry.id].label,
          group: GROUP_LABELS[group.id],
          to: NAV_ITEMS[entry.id].to,
        })),
      ),
      { id: "account", label: "Account", group: "You", to: "/account" },
      { id: "settings-account", label: "Settings", group: "You", to: "/account/settings" },
    ],
    [groups],
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
      <div className="space-y-1 border-b border-sidebar-border px-3 py-3">
        <button
          ref={searchRef}
          type="button"
          aria-haspopup="dialog"
          aria-keyshortcuts="Control+K Meta+K"
          onClick={() => setPaletteOpen(true)}
          className="flex h-8 w-full items-center gap-2 rounded-sm border border-sidebar-border bg-sidebar-hover px-2 text-sm text-sidebar-muted outline-none hover:text-sidebar-strong focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Search aria-hidden="true" className="size-4 shrink-0" />
          <span className="flex-1 truncate text-left">Search or jump to…</span>
          <kbd className="rounded-sm border border-sidebar-border px-1 font-sans text-[11px]">
            ⌘K
          </kbd>
        </button>
        <NotificationsItem open={notificationsOpen} onOpenChange={setNotificationsOpen} />
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
              </ul>
            </section>
          ))
        )}
      </div>
      <div className="space-y-2 border-t border-sidebar-border p-2">
        <SystemStatus />
        <AccountMenu onNavigate={onNavigate} />
      </div>
      <CommandPalette
        entries={paletteEntries}
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onNavigate={onNavigate}
        returnFocusRef={searchRef}
      />
    </nav>
  );
}
