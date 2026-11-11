import { Plug } from "lucide-react";
import { useParams } from "react-router";
import { toast } from "sonner";
import { LinkButton } from "@/components/common/link-button.jsx";
import { PageHeader } from "@/components/common/page-header.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { describeError } from "@/lib/api/index.js";
import { LinkHealth } from "../components/link-health.jsx";
import { useSetWorkspaceRouting, useWorkspaceLinks } from "../hooks/use-integrations.js";

/**
 * T-42 Workspace integrations: routing only. The list holds the linked accounts the organization allows this workspace to
 * use; with workspace_integration.manage the workspace can switch each one off or on for itself. Linking, unlinking and the
 * organization-wide scope stay on the GitHub integration page (integration.view / integration.manage).
 */
export function WorkspaceIntegrationsPage() {
  const { workspaceId } = useParams();
  const can = useCan();
  const canManage = can("workspace_integration.manage");
  const links = useWorkspaceLinks(workspaceId);
  const routing = useSetWorkspaceRouting(workspaceId);
  return (
    <>
      <PageHeader
        title="Integrations"
        description="GitHub accounts this workspace can connect repositories from."
        actions={
          can("integration.view") ? (
            <LinkButton to="/integrations/github" variant="secondary">
              Organization GitHub settings
            </LinkButton>
          ) : null
        }
      />
      {links.isPending ? <LoadingState label="Loading integrations" rows={3} /> : null}
      {links.isError ? <QueryErrorState error={links.error} onRetry={links.refetch} /> : null}
      {routing.error ? (
        <p role="alert" className="mb-3 text-sm text-status-danger">
          {describeError(routing.error)}
        </p>
      ) : null}
      {links.data && links.data.length === 0 ? (
        <EmptyState
          icon={Plug}
          title="No GitHub account available"
          description="No linked GitHub account is allowed for this workspace. An organization administrator links accounts and chooses which workspaces may use them."
        />
      ) : null}
      {links.data && links.data.length > 0 ? (
        <ul className="divide-y divide-border rounded-md border border-border bg-card">
          {links.data.map((link) => (
            <li
              key={link.id}
              className="flex flex-wrap items-center justify-between gap-3 px-3 py-3 text-sm"
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs">{link.account.login}</span>
                <LinkHealth status={link.health} />
              </div>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={link.enabled}
                  disabled={!canManage || routing.isPending}
                  onChange={() =>
                    routing.mutate(
                      { linkId: link.id, enabled: !link.enabled },
                      {
                        onSuccess: () =>
                          toast.success(
                            link.enabled
                              ? "Turned off for this workspace"
                              : "Turned on for this workspace",
                          ),
                      },
                    )
                  }
                />
                Use in this workspace
              </label>
            </li>
          ))}
        </ul>
      ) : null}
      {!canManage && links.data?.length ? (
        <p className="mt-3 text-xs text-muted-foreground">
          You can see these settings but need the workspace_integration.manage permission to change
          them.
        </p>
      ) : null}
    </>
  );
}
