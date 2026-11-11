import { ChevronsUpDown } from "lucide-react";
import { useLocation, useNavigate } from "react-router";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.jsx";
import {
  useActiveWorkspace,
  usePermissions,
} from "@/features/authorization/hooks/use-permissions.js";
import { resolveSwitchTarget } from "./nav.js";

/**
 * Workspace switcher (T-00b): a dropdown of the workspaces the user can access when there is more than one, a static
 * label otherwise. Switching keeps the current section when it is allowed in the target workspace, else opens the
 * target Dashboard.
 */
export function WorkspaceSwitcher({ onNavigate }) {
  const permissions = usePermissions();
  const active = useActiveWorkspace();
  const navigate = useNavigate();
  const { pathname, search } = useLocation();
  if (!active) return null;

  if (permissions.workspaces.length <= 1) {
    return (
      <div
        className="flex h-8 items-center rounded-sm border border-border px-2 text-sm font-medium"
        aria-label={`Workspace: ${active.name}`}
      >
        <span className="truncate">{active.name}</span>
      </div>
    );
  }
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          aria-label={`Workspace: ${active.name}. Switch workspace`}
          className="flex h-8 w-full items-center justify-between gap-2 rounded-sm border border-border-strong bg-secondary px-2 text-sm font-medium outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
        >
          <span className="truncate">{active.name}</span>
          <ChevronsUpDown aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-56">
        <DropdownMenuRadioGroup
          value={active.id}
          onValueChange={(targetId) => {
            if (targetId === active.id) return;
            navigate(
              resolveSwitchTarget({ pathname, search, permissions, targetWorkspaceId: targetId }),
            );
            onNavigate?.();
          }}
        >
          {permissions.workspaces.map((ws) => (
            <DropdownMenuRadioItem key={ws.id} value={ws.id}>
              <span className="truncate">{ws.name}</span>
              {ws.status === "archived" ? (
                <span className="ml-auto text-xs text-muted-foreground">Archived</span>
              ) : null}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
