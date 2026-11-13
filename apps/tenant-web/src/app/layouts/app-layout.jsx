import { useEffect } from "react";
import { Outlet, useLocation } from "react-router";
import { useUiStore } from "@/app/stores/ui-store.js";
import { ErrorBoundary } from "@/components/states/error-boundary.jsx";
import { Sidebar } from "@/components/layout/sidebar.jsx";
import { Topbar } from "@/components/layout/topbar.jsx";
import { useNavContext } from "@/hooks/use-nav-context.js";
import { cn } from "@/lib/cn.js";

/**
 * Application shell. `useNavContext` picks the Organization layout (T-00a) or the Workspace layout (T-00b) from the URL;
 * the sidebar and top bar follow. On small screens the sidebar is a drawer.
 */
export function AppLayout() {
  const { layout } = useNavContext();
  const { pathname } = useLocation();
  const open = useUiStore((s) => s.mobileNavOpen);
  const setOpen = useUiStore((s) => s.setMobileNavOpen);

  useEffect(() => {
    setOpen(false);
  }, [pathname, setOpen]);

  return (
    <div className="relative flex h-dvh overflow-hidden bg-background" data-layout={layout}>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-sm focus:bg-primary focus:px-3 focus:py-1.5 focus:text-primary-foreground"
      >
        Skip to content
      </a>
      {open ? (
        <div
          className="fixed inset-0 z-30 bg-black/50 md:hidden"
          aria-hidden="true"
          onClick={() => setOpen(false)}
        />
      ) : null}
      <div
        className={cn(
          "fixed inset-y-0 left-0 z-40 transition-transform md:sticky md:top-0 md:h-screen md:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <Sidebar onNavigate={() => setOpen(false)} />
      </div>
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main id="main" className="qm-scroll min-h-0 flex-1 overflow-y-auto p-6">
          <ErrorBoundary key={pathname}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
