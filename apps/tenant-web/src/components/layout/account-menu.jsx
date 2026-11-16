import { useQuery } from "@tanstack/react-query";
import { Building2, ChevronsUpDown, LogOut, Settings, UserRound } from "lucide-react";
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
import { authService } from "@/features/auth/services/auth-service.js";
import { useSession } from "@/features/auth/hooks/use-session.js";

const initials = (name) =>
  name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join("");

/**
 * Account area pinned at the bottom of the sidebar (owner decision 2026-11-16, replaces the top-bar account menu):
 * avatar + name open a menu (Radix `menu`: focus moves in, arrows/typeahead, Escape closes, focus returns to the
 * trigger) with Account, Settings (Appearance and Preferences) and Sign out, plus Switch organization when the user
 * belongs to more than one. No permission is needed: these are the user's own pages.
 * @param {{ onNavigate?: () => void }} props
 */
export function AccountMenu({ onNavigate }) {
  const { me } = useSession();
  const navigate = useNavigate();
  const { logout } = useAuthActions();
  const tenants = useQuery({
    queryKey: ["account", "tenants"],
    queryFn: ({ signal }) => authService.listTenants({ signal }),
    staleTime: 60_000,
  });
  const canSwitchOrganization = (tenants.data?.length ?? 0) > 1;
  const go = (to) => () => {
    navigate(to);
    onNavigate?.();
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={`Account menu for ${me.user.name}`}
          className="flex w-full items-center gap-2.5 rounded-sm p-1.5 text-left outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring data-[state=open]:bg-accent"
        >
          <span
            aria-hidden="true"
            className="flex size-8 shrink-0 items-center justify-center rounded-sm bg-secondary text-xs font-semibold"
          >
            {initials(me.user.name)}
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-medium text-foreground">
              {me.user.name}
            </span>
            <span className="block truncate text-xs text-muted-foreground">{me.user.email}</span>
          </span>
          <ChevronsUpDown aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align="start" className="w-60">
        <DropdownMenuLabel className="space-y-0.5">
          <span className="block text-sm font-medium text-foreground">{me.user.name}</span>
          <span className="block truncate font-normal">{me.user.email}</span>
          <span className="block truncate font-normal">Organization: {me.tenant.name}</span>
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
        {canSwitchOrganization ? (
          <DropdownMenuItem onSelect={() => navigate("/select-tenant")}>
            <Building2 aria-hidden="true" />
            Switch organization
          </DropdownMenuItem>
        ) : null}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => logout.mutate()}>
          <LogOut aria-hidden="true" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
