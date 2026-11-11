import { Menu } from "lucide-react";
import { useUiStore } from "@/app/stores/ui-store.js";
import { Button } from "@/components/ui/button.jsx";
import { useSession } from "@/features/auth/hooks/use-session.js";
import { useActiveWorkspace } from "@/features/authorization/hooks/use-permissions.js";
import { AccountMenu } from "./account-menu.jsx";

/** Top bar (48 px): where you are, and the account menu. */
export function Topbar() {
  const { me } = useSession();
  const workspace = useActiveWorkspace();
  const setMobileNavOpen = useUiStore((s) => s.setMobileNavOpen);
  return (
    <header className="sticky top-0 z-20 flex h-12 shrink-0 items-center justify-between gap-3 border-b border-border bg-background px-4">
      <div className="flex min-w-0 items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          aria-label="Open navigation"
          onClick={() => setMobileNavOpen(true)}
        >
          <Menu aria-hidden="true" />
        </Button>
        <p className="truncate text-sm text-muted-foreground">
          {me.tenant.name}
          {workspace ? (
            <span>
              {" "}
              / <span className="text-foreground">{workspace.name}</span>
            </span>
          ) : null}
        </p>
      </div>
      <AccountMenu />
    </header>
  );
}
