import { Menu } from "lucide-react";
import { useLocation } from "react-router";
import { useUiStore } from "@/app/stores/ui-store.js";
import { Button } from "@/components/ui/button.jsx";
import { AccountMenu } from "./account-menu.jsx";
import { NAV_ITEMS } from "./nav.js";

/** Top bar (48 px): persistent "PLATFORM" chip, the current page, and the account menu. No workspace switcher. */
export function Topbar() {
  const setMobileNavOpen = useUiStore((s) => s.setMobileNavOpen);
  const { pathname } = useLocation();
  const current = Object.values(NAV_ITEMS).find(
    (i) => pathname === i.to || pathname.startsWith(`${i.to}/`),
  );
  return (
    <header className="relative z-20 flex h-12 shrink-0 items-center justify-between gap-3 border-b border-border bg-background px-4">
      <div className="flex min-w-0 items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          aria-label="Open navigation"
          onClick={() => setMobileNavOpen(true)}
        >
          <Menu aria-hidden="true" />
        </Button>
        <span className="rounded-sm border border-border-strong px-1.5 py-0.5 text-[11px] font-semibold tracking-wider text-muted-foreground">
          PLATFORM
        </span>
        {current ? <p className="truncate text-sm text-muted-foreground">{current.label}</p> : null}
      </div>
      <AccountMenu />
    </header>
  );
}
