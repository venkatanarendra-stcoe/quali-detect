import { Plug } from "lucide-react";
import { useParams } from "react-router";
import { toast } from "sonner";
import { PageHeader } from "@/components/common/page-header.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { LinkButton } from "@/components/common/link-button.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { describeError } from "@/lib/api/index.js";
import { LinkHealth } from "../components/link-health.jsx";
import { useInstallations, useSetScope } from "../hooks/use-integrations.js";

/**
 * T-42 Workspace integrations: which linked accounts this workspace may use. Reading needs integration.view; the toggle
 * rewrites the link's workspace scope, so it needs integration.manage (the API enforces it). An empty scope means every
 * workspace; switching one workspace off while the scope is empty first scopes the link to the other workspaces.
 */
export function WorkspaceIntegrationsPage() {
  const { workspaceId } = useParams();
  const can = useCan();
  const canManage = can("integration.manage");
  const installations = useInstallations();
  const setScope = useSetScope();
  const links = (installations.data ?? []).filter((l) => l.status === "linked");
  return (
    <>
      <PageHeader
        title="Integrations"
        description="GitHub accounts available to this workspace."
        actions={
          can("integration.view") ? (
            <LinkButton to="/integrations/github" variant="secondary">
              Manage on GitHub page
            </LinkButton>
          ) : null
        }
      />
      {installations.isPending ? <LoadingState label="Loading integrations" rows={3} /> : null}
      {installations.isError ? (
        <QueryErrorState error={installations.error} onRetry={installations.refetch} />
      ) : null}
      {setScope.error ? (
        <p role="alert" className="mb-3 text-sm text-status-danger">
          {describeError(setScope.error)}
        </p>
      ) : null}
      {installations.data && links.length === 0 ? (
        <EmptyState
          icon={Plug}
          title="No GitHub account linked"
          description="An organization administrator can link a GitHub account on the GitHub integration page."
        />
      ) : null}
      {links.length > 0 ? (
        <ul className="divide-y divide-border rounded-md border border-border bg-card">
          {links.map((link) => {
            const allowed =
              link.workspaceScope.length === 0 || link.workspaceScope.includes(workspaceId);
            const toggle = () => {
              // Empty scope = everyone: turning this workspace off needs the explicit list of the others.
              const others = link.workspaceScope.filter((id) => id !== workspaceId);
              const next = allowed ? others : [...link.workspaceScope, workspaceId];
              if (allowed && link.workspaceScope.length === 0) {
                toast.error(
                  "This account is available to every workspace. Choose the allowed workspaces on the GitHub integration page.",
                );
                return;
              }
              setScope.mutate(
                { linkId: link.id, workspaceIds: next },
                { onSuccess: () => toast.success("Scope saved") },
              );
            };
            return (
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
                    checked={allowed}
                    disabled={!canManage || setScope.isPending}
                    onChange={toggle}
                  />
                  Available in this workspace
                </label>
              </li>
            );
          })}
        </ul>
      ) : null}
    </>
  );
}
