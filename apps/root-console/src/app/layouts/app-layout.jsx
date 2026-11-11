import { useEffect } from "react";
import { Outlet, useLocation } from "react-router";
import { useUiStore } from "@/app/stores/ui-store.js";
import { EnvironmentStrip } from "@/components/layout/environment-strip.jsx";
import { Sidebar } from "@/components/layout/sidebar.jsx";
import { Topbar } from "@/components/layout/topbar.jsx";
import { ErrorBoundary } from "@/components/states/error-boundary.jsx";
import { cn } from "@/lib/cn.js";

/**
 * Root Console shell: environment strip on top, dark sidebar, top bar with the PLATFORM chip, page area. A tenant
 * drill-in banner (`SupportAccessBanner`) belongs directly under the top bar once support-access grants exist.
 */
export function AppLayout() {
  const { pathname } = useLocation();
  const open = useUiStore((s) => s.mobileNavOpen);
  const setOpen = useUiStore((s) => s.setMobileNavOpen);
  useEffect(() => {
    setOpen(false);
  }, [pathname, setOpen]);
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-8 focus:left-2 focus:z-50 focus:rounded-sm focus:bg-primary focus:px-3 focus:py-1.5 focus:text-primary-foreground"
      >
        Skip to content
      </a>
      <EnvironmentStrip />
      <div className="flex flex-1">
        {open ? (
          <div
            className="fixed inset-0 z-30 bg-black/50 md:hidden"
            aria-hidden="true"
            onClick={() => setOpen(false)}
          />
        ) : null}
        <div
          className={cn(
            "fixed inset-y-0 left-0 z-40 pt-6 transition-transform md:sticky md:top-6 md:h-[calc(100vh-1.5rem)] md:self-start md:translate-x-0 md:pt-0",
            open ? "translate-x-0" : "-translate-x-full",
          )}
        >
          <Sidebar onNavigate={() => setOpen(false)} />
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <main id="main" className="flex-1 p-6">
            <ErrorBoundary key={pathname}>
              <Outlet />
            </ErrorBoundary>
          </main>
        </div>
      </div>
    </div>
  );
}
