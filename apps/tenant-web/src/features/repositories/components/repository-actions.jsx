import { MoreHorizontal } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import {
  useDisableRepository,
  useDisconnectRepository,
  useEnableRepository,
  useSyncRepository,
} from "../hooks/use-repositories.js";

/**
 * Actions of one repository (list row menu and detail header). Each is shown only when the caller holds the permission in
 * the repository's workspace; the backend decides regardless. Disconnect needs the full name typed.
 */
export function useRepositoryActions(repository, { onDisconnected } = {}) {
  const can = useCan();
  const scope = { type: "workspace", workspaceId: repository.workspaceId };
  const sync = useSyncRepository();
  const enable = useEnableRepository();
  const disable = useDisableRepository();
  const disconnect = useDisconnectRepository();
  const live = repository.status !== "disconnected";
  return {
    canSync: live && can("repository.sync", scope),
    canToggle: live && can("repository.toggle", scope),
    canDisconnect: live && can("repository.disconnect", scope),
    canUpdate: live && can("repository.update", scope),
    sync: () =>
      sync.mutate(repository.id, {
        onSuccess: () => toast.success("Sync queued"),
        onError: (e) => toast.error(e.message ?? "Could not queue the sync"),
      }),
    syncing: sync.isPending,
    toggle: () =>
      (repository.enabled ? disable : enable).mutate(repository.id, {
        onSuccess: () =>
          toast.success(repository.enabled ? "Repository disabled" : "Repository enabled"),
        onError: (e) => toast.error(e.message ?? "Could not change the repository"),
      }),
    disconnect,
    onDisconnected,
  };
}

export function RepositoryRowActions({ repository }) {
  const navigate = useNavigate();
  const actions = useRepositoryActions(repository);
  const [confirming, setConfirming] = useState(false);
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" aria-label={`Actions for ${repository.fullName}`}>
            <MoreHorizontal aria-hidden="true" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-52">
          <DropdownMenuItem
            onSelect={() =>
              navigate(`/workspaces/${repository.workspaceId}/repositories/${repository.id}`)
            }
          >
            Open
          </DropdownMenuItem>
          {actions.canSync ? (
            <DropdownMenuItem onSelect={actions.sync}>Sync now</DropdownMenuItem>
          ) : null}
          {actions.canToggle ? (
            <DropdownMenuItem onSelect={actions.toggle}>
              {repository.enabled ? "Disable" : "Enable"}
            </DropdownMenuItem>
          ) : null}
          {actions.canDisconnect ? (
            <DropdownMenuItem onSelect={() => setConfirming(true)}>Disconnect…</DropdownMenuItem>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      <DisconnectDialog
        repository={repository}
        open={confirming}
        onOpenChange={setConfirming}
        disconnect={actions.disconnect}
      />
    </>
  );
}

/** Typed-confirmation dialog shared by the list and the detail page. */
export function DisconnectDialog({ repository, open, onOpenChange, disconnect, onDone }) {
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        if (!next) disconnect.reset();
      }}
      title="Disconnect this repository?"
      description="Its pipelines stop and GitHub events are ignored. History, findings and audit entries are kept, and connecting the repository again restores it."
      confirmLabel="Disconnect"
      destructive
      confirmText={repository.fullName}
      pending={disconnect.isPending}
      error={disconnect.error}
      onConfirm={({ confirm }) =>
        disconnect.mutate(
          { repositoryId: repository.id, confirm },
          {
            onSuccess: () => {
              onOpenChange(false);
              toast.success(`${repository.fullName} disconnected`);
              onDone?.();
            },
          },
        )
      }
    />
  );
}
