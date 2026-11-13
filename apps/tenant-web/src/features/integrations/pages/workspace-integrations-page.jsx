import { Plug } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router";
import { PageHeader } from "@/components/common/page-header.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { LinkChoiceDialog } from "../components/link-choice-dialog.jsx";
import { WorkspaceLinkCard } from "../components/workspace-link-card.jsx";
import {
  useDiscoverInstallations,
  useStartLinking,
  useWorkspaceIntegrations,
} from "../hooks/use-integrations.js";
import { linkHint } from "../services/link-hint.js";
import { LINKING_DISABLED_MESSAGE, linkErrorMessage } from "../services/link-errors.js";

/**
 * T-42 Workspace integrations: where GitHub is connected. With workspace_integration.manage the workspace links a GitHub
 * account (the workspace id is kept as a hint for the global setup/callback pages), tests, unlinks and edits the repository
 * allow-list of each link. workspace_integration.view holders see the same page read-only with the reason.
 */
export function WorkspaceIntegrationsPage() {
  const { workspaceId } = useParams();
  const can = useCan();
  const canManage = can("workspace_integration.manage");
  const overview = useWorkspaceIntegrations(workspaceId);
  const start = useStartLinking();
  const discover = useDiscoverInstallations();
  const [choosing, setChoosing] = useState(false);
  const data = overview.data;
  const links = data?.items.filter((l) => l.status !== "unlinked") ?? [];
  const previous = data?.items.filter((l) => l.status === "unlinked") ?? [];
  let linkReason = null;
  if (!canManage)
    linkReason = "You need the workspace_integration.manage permission in this workspace.";
  else if (data && !data.linkingEnabled) linkReason = LINKING_DISABLED_MESSAGE;
  const startLinking = () => {
    linkHint.write(workspaceId);
    start.mutate(workspaceId, {
      onSuccess: ({ installUrl }) => window.location.assign(installUrl),
    });
  };
  // "Use an existing installation": GitHub lists the installations the user administers on the callback page.
  const chooseExisting = () => {
    linkHint.write(workspaceId);
    discover.mutate(workspaceId, {
      onSuccess: ({ authorizeUrl }) => window.location.assign(authorizeUrl),
    });
  };
  const linkError = start.error ?? discover.error;
  return (
    <>
      <PageHeader
        title="Integrations"
        description="GitHub accounts linked to this workspace and the repositories it may connect."
        actions={
          data && data.configured ? (
            <DisabledWithReason reason={linkReason}>
              <Button
                onClick={() => setChoosing(true)}
                disabled={start.isPending || discover.isPending}
              >
                <Plug aria-hidden="true" />
                Link a GitHub account
              </Button>
            </DisabledWithReason>
          ) : null
        }
      />
      <LinkChoiceDialog
        open={choosing}
        onOpenChange={setChoosing}
        onInstall={() => {
          setChoosing(false);
          startLinking();
        }}
        onUseExisting={() => {
          setChoosing(false);
          chooseExisting();
        }}
      />
      {linkError ? (
        <p role="alert" className="mb-3 text-sm text-status-danger">
          {linkErrorMessage(linkError)}
        </p>
      ) : null}
      {data && data.configured && linkReason && canManage ? (
        <p role="status" className="mb-3 text-sm text-muted-foreground">
          {linkReason}
        </p>
      ) : null}
      {overview.isPending ? <LoadingState label="Loading integrations" rows={3} /> : null}
      {overview.isError ? (
        <QueryErrorState error={overview.error} onRetry={overview.refetch} />
      ) : null}
      {data && !data.configured ? (
        <EmptyState
          icon={Plug}
          title="GitHub is not configured"
          description="The GitHub App is not set up on this platform. Ask your platform administrator."
        />
      ) : null}
      {data && data.configured && links.length === 0 ? (
        <EmptyState
          icon={Plug}
          title="No GitHub account linked"
          description={
            canManage
              ? "Link a GitHub organization or personal account to connect repositories. You must be an owner of the organization."
              : "Ask a workspace administrator to link a GitHub account."
          }
        />
      ) : null}
      {links.length > 0 ? (
        <div className="space-y-4">
          {!canManage ? (
            <p role="status" className="text-sm text-muted-foreground">
              You can see these settings but need the workspace_integration.manage permission to
              change them.
            </p>
          ) : null}
          {links.map((link) => (
            <WorkspaceLinkCard
              key={link.id}
              workspaceId={workspaceId}
              link={link}
              canManage={canManage}
            />
          ))}
        </div>
      ) : null}
      {previous.length > 0 ? (
        <p className="mt-4 text-sm text-muted-foreground">
          Previously linked: {previous.map((l) => l.account.login).join(", ")}. Linking one of these
          accounts again restores its repositories.
        </p>
      ) : null}
    </>
  );
}
