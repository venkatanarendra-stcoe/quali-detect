import { Shield } from "lucide-react";
import { useScrollActivity } from "@qmentisai/ui";
import { useMemo, useRef } from "react";
import { Link, useLocation } from "react-router";
import { evaluatePlatformNavigation } from "@qmentisai/shared/platform";
import { isRouteAvailable } from "@/app/routes.jsx";
import { usePlatformPermissions } from "@/features/authorization/hooks/use-platform-permissions.js";
import { cn } from "@/lib/cn.js";
import { GROUP_LABELS, NAV_ITEMS } from "./nav.js";

const isActive = (pathname, to) => pathname === to || pathname.startsWith(`${to}/`);

/**
 * Dark sidebar (dark in light mode too). Items come from `evaluatePlatformNavigation` with the user's `platform.*`
 * permissions; empty groups are not rendered. Header: "QmentisAI Platform". No workspace switcher, no account area.
 */
export function Sidebar({ onNavigate }) {
  const permissions = usePlatformPermissions();
  const { pathname } = useLocation();
  const scrollRef = useRef(null);
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
        <Link to="/" onClick={onNavigate} className="text-sm font-semibold text-sidebar-strong">
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
                  const active = isActive(pathname, def.to);
                  const Icon = def.icon;
                  return (
                    <li key={entry.id}>
                      <Link
                        to={def.to}
                        onClick={onNavigate}
                        aria-current={active ? "page" : undefined}
                        className={cn(
                          "relative flex h-8 items-center gap-2.5 rounded-sm px-2 text-sm transition-colors",
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
    </nav>
  );
}
