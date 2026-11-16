import { useEffect, useRef } from "react";
import { Outlet, useLocation } from "react-router";
import { useUiStore } from "@/app/stores/ui-store.js";
import { ErrorBoundary } from "@/components/states/error-boundary.jsx";
import { Sidebar } from "@/components/layout/sidebar.jsx";
import { Menu, Shield } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { useNavContext } from "@/hooks/use-nav-context.js";
import { cn } from "@/lib/cn.js";

/**
 * Application shell. `useNavContext` picks the Organization layout (T-00a) or the Workspace layout (T-00b) from the URL;
 * the sidebar follows. There is no top bar (owner decision 2026-11-16): the sidebar carries logo, search, notifications
 * and the account area, and `main` fills the full height. Below `md` the sidebar is a drawer opened from a slim 3rem
 * strip (menu button + logo); `--app-shell-extra` tells `AppPageLayout`/`WizardLayout` to subtract that strip.
 */
export function AppLayout() {
  const { layout } = useNavContext();
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
    <div
      className="relative flex h-dvh flex-col overflow-hidden bg-background md:flex-row [--app-shell-extra:3rem] md:[--app-shell-extra:0rem]"
      data-layout={layout}
    >
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-sm focus:bg-primary focus:px-3 focus:py-1.5 focus:text-primary-foreground"
      >
        Skip to content
      </a>
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
        <span className="text-sm font-semibold">QmentisAI</span>
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
          "fixed inset-y-0 left-0 z-40 transition-transform md:sticky md:top-0 md:h-screen md:translate-x-0",
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
  );
}
