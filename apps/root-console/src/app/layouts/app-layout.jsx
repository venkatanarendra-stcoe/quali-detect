import { useEffect, useRef } from "react";
import { Outlet, useLocation } from "react-router";
import { useUiStore } from "@/app/stores/ui-store.js";
import { EnvironmentStrip } from "@/components/layout/environment-strip.jsx";
import { Sidebar } from "@/components/layout/sidebar.jsx";
import { Menu, Shield } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { ErrorBoundary } from "@/components/states/error-boundary.jsx";
import { cn } from "@/lib/cn.js";

/**
 * Root Console shell: environment strip on top (kept: a safety feature), dark sidebar carrying logo, search,
 * notifications, system status and the account area, page area. There is no top bar (owner decision 2026-11-16). A
 * tenant drill-in banner (`SupportAccessBanner`) belongs directly above `main` once support-access grants exist.
 * The shell is `h-dvh overflow-hidden`: neither it nor the document scrolls. Pages render in `AppPageLayout`
 * (offset 4.5rem = 1.5rem environment strip + 3rem page padding; below `md` the shell sets `--app-shell-extra` for the
 * 3rem menu strip that opens the drawer); `main` only scrolls as a fallback for whole-page states (403, 404, error).
 */
export function AppLayout() {
  const { pathname } = useLocation();
  const open = useUiStore((s) => s.mobileNavOpen);
  const setOpen = useUiStore((s) => s.setMobileNavOpen);
  const menuButtonRef = useRef(null);
  const drawerRef = useRef(null);
  // Opening the drawer (below md only) moves focus into it, so Tab and Escape start from the navigation.
  useEffect(() => {
    if (open) drawerRef.current?.querySelector("a, button")?.focus();
  }, [open]);
  // Drawer (below md): Escape from inside the drawer closes it and returns focus to the menu button. Events from
  // portaled popovers (account menu, palette) are not DOM descendants, so their own Escape handling is untouched.
  const closeOnEscape = (event) => {
    if (event.key !== "Escape" || !event.currentTarget.contains(event.target)) return;
    setOpen(false);
    menuButtonRef.current?.focus();
  };

  useEffect(() => {
    setOpen(false);
  }, [pathname, setOpen]);

  return (
    <div className="flex h-dvh flex-col overflow-hidden bg-background">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-8 focus:left-2 focus:z-50 focus:rounded-sm focus:bg-primary focus:px-3 focus:py-1.5 focus:text-primary-foreground"
      >
        Skip to content
      </a>
      <EnvironmentStrip />
      <div className="flex min-h-0 flex-1 flex-col [--app-shell-extra:3rem] md:flex-row md:[--app-shell-extra:0rem]">
        <header className="flex h-12 shrink-0 items-center gap-2 border-b border-border bg-background px-3 md:hidden">
          <Button
            variant="ghost"
            size="icon"
            ref={menuButtonRef}
            aria-label="Open navigation"
            aria-expanded={open}
            onClick={() => setOpen(true)}
          >
            <Menu aria-hidden="true" />
          </Button>
          <Shield aria-hidden="true" className="size-5" strokeWidth={1.75} />
          <span className="text-sm font-semibold">QmentisAI Platform</span>
        </header>
        {open ? (
          <div
            className="fixed inset-0 z-30 bg-black/50 md:hidden"
            aria-hidden="true"
            onClick={() => setOpen(false)}
          />
        ) : null}
        {/* Escape handler on a container (not an interactive control): keyboard users close the drawer from inside it. */}
        {/* eslint-disable-next-line jsx-a11y/no-static-element-interactions */}
        <div
          ref={drawerRef}
          onKeyDown={closeOnEscape}
          className={cn(
            "fixed inset-y-0 left-0 z-40 pt-6 transition-transform md:static md:h-full md:translate-x-0 md:pt-0",
            open ? "translate-x-0" : "-translate-x-full max-md:invisible",
          )}
        >
          <Sidebar onNavigate={() => setOpen(false)} />
        </div>
        <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          <main id="main" className="qm-scroll min-h-0 flex-1 overflow-y-auto p-6">
            <ErrorBoundary key={pathname}>
              <Outlet />
            </ErrorBoundary>
          </main>
        </div>
      </div>
    </div>
  );
}
