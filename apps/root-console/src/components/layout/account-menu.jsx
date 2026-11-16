import { ChevronsUpDown, LogOut, Settings, UserRound } from "lucide-react";
import { useNavigate } from "react-router";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.jsx";
import { useAuthActions } from "@/features/auth/hooks/use-auth-actions.js";
import { usePlatformSession } from "@/features/auth/hooks/use-platform-session.js";

const initials = (name) =>
  name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join("");

/**
 * Account area pinned at the bottom of the (dark) sidebar (owner decision 2026-11-16, replaces the top-bar account
 * menu): avatar + name open a menu (Escape closes, focus returns to the trigger) with Account, Settings (Appearance:
 * theme only, Root Console has no accent picker) and Sign out.
 * @param {{ onNavigate?: () => void }} props
 */
export function AccountMenu({ onNavigate }) {
  const { me } = usePlatformSession();
  const { logout } = useAuthActions();
  const navigate = useNavigate();
  const go = (to) => () => {
    navigate(to);
    onNavigate?.();
  };
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={`Account menu for ${me.platformUser.name}`}
          className="flex w-full items-center gap-2.5 rounded-sm p-1.5 text-left outline-none hover:bg-sidebar-hover focus-visible:ring-2 focus-visible:ring-ring data-[state=open]:bg-sidebar-hover"
        >
          <span
            aria-hidden="true"
            className="flex size-8 shrink-0 items-center justify-center rounded-sm bg-sidebar-active text-xs font-semibold text-sidebar-active-foreground"
          >
            {initials(me.platformUser.name)}
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-medium text-sidebar-strong">
              {me.platformUser.name}
            </span>
            <span className="block truncate text-xs text-sidebar-muted">{me.role.name}</span>
          </span>
          <ChevronsUpDown aria-hidden="true" className="size-4 shrink-0 text-sidebar-muted" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align="start" className="w-60">
        <DropdownMenuLabel className="space-y-0.5">
          <span className="block text-sm font-medium text-foreground">{me.platformUser.name}</span>
          <span className="block truncate font-normal">{me.platformUser.email}</span>
          <span className="block truncate font-normal">Platform role: {me.role.name}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={go("/account")}>
          <UserRound aria-hidden="true" />
          Account
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={go("/account/settings")}>
          <Settings aria-hidden="true" />
          Settings
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => logout.mutate()}>
          <LogOut aria-hidden="true" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
