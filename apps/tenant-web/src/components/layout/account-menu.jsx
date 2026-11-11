import { useQuery } from "@tanstack/react-query";
import { Building2, LogOut, Monitor, Moon, Sun } from "lucide-react";
import { useNavigate } from "react-router";
import { useUiStore } from "@/app/stores/ui-store.js";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
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

/** The only account control in the app (top bar): identity, organization switch, theme, sign out. */
export function AccountMenu() {
  const { me } = useSession();
  const navigate = useNavigate();
  const { logout } = useAuthActions();
  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);
  const tenants = useQuery({
    queryKey: ["account", "tenants"],
    queryFn: ({ signal }) => authService.listTenants({ signal }),
    staleTime: 60_000,
  });
  const canSwitchOrganization = (tenants.data?.length ?? 0) > 1;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label="Account menu"
          className="flex size-8 items-center justify-center rounded-sm bg-secondary text-xs font-semibold outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
        >
          {initials(me.user.name)}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel className="space-y-0.5">
          <span className="block text-sm font-medium text-foreground">{me.user.name}</span>
          <span className="block truncate font-normal">{me.user.email}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Organization: {me.tenant.name}</DropdownMenuLabel>
        {canSwitchOrganization ? (
          <DropdownMenuItem onSelect={() => navigate("/select-tenant")}>
            <Building2 aria-hidden="true" />
            Switch organization
          </DropdownMenuItem>
        ) : null}
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Theme</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={theme} onValueChange={setTheme}>
          <DropdownMenuRadioItem value="light">
            <Sun aria-hidden="true" />
            Light
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark">
            <Moon aria-hidden="true" />
            Dark
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="system">
            <Monitor aria-hidden="true" />
            System
          </DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => logout.mutate()}>
          <LogOut aria-hidden="true" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
