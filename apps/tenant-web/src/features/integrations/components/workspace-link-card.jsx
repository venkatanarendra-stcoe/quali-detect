import { ChevronDown, ChevronUp, RefreshCw } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent } from "@/components/ui/card.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { describeError } from "@/lib/api/index.js";
import { useRefreshLink, useUnlinkWorkspaceLink } from "../hooks/use-integrations.js";
import { AllowListEditor } from "./allow-list-editor.jsx";
import { LinkHealth } from "./link-health.jsx";

const MANAGE_REASON = "You need the workspace_integration.manage permission in this workspace.";
const when = (value) =>
  value
    ? new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
    : "No events yet";

/** One GitHub account linked to the workspace: health, counts, Test connection, Unlink and the allow-list editor. */
export function WorkspaceLinkCard({ workspaceId, link, canManage }) {
  const refresh = useRefreshLink(workspaceId);
  const unlink = useUnlinkWorkspaceLink(workspaceId);
  const [unlinking, setUnlinking] = useState(false);
  const [editing, setEditing] = useState(false);
  const reason = canManage ? null : MANAGE_REASON;
  return (
    <Card>
      <CardContent className="space-y-4 pt-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold">
              <span className="font-mono">{link.account.login}</span>
            </h2>
            <LinkHealth status={link.health} />
            <Badge>
              {link.account.type === "organization" ? "Organization" : "Personal account"}
            </Badge>
          </div>
          <div className="flex flex-wrap gap-2">
            <DisabledWithReason reason={reason}>
              <Button
                variant="secondary"
                disabled={refresh.isPending}
                onClick={() =>
                  refresh.mutate(link.id, { onSuccess: () => toast.success("Connection checked") })
                }
              >
                <RefreshCw aria-hidden="true" />
                Test connection
              </Button>
            </DisabledWithReason>
            <DisabledWithReason reason={reason}>
              <Button variant="outline" onClick={() => setUnlinking(true)}>
                Unlink
              </Button>
            </DisabledWithReason>
          </div>
        </div>
        {refresh.error ? (
          <p role="alert" className="text-sm text-status-danger">
            {describeError(refresh.error)}
          </p>
        ) : null}
        {link.health === "degraded" ? (
          <p
            role="status"
            className="rounded-md border border-border-strong bg-secondary p-3 text-sm"
          >
            {link.unavailableRepositoryCount} repositories are unavailable. Open the repositories
            page and sync them, or check the access on GitHub.
          </p>
        ) : null}
        {link.health === "suspended" || link.health === "revoked" ? (
          <p
            role="status"
            className="rounded-md border border-border-strong bg-secondary p-3 text-sm"
          >
            {link.health === "suspended"
              ? "GitHub reports this installation as suspended. Repositories are paused until it is unsuspended."
              : "The App was uninstalled from this GitHub account. Install it again on GitHub and link it to restore the repositories."}
          </p>
        ) : null}
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm lg:grid-cols-4">
          <div>
            <dt className="text-muted-foreground">Repository access</dt>
            <dd>
              {link.repositorySelection === "all" ? "All repositories" : "Selected repositories"}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Connected repositories</dt>
            <dd>
              {link.repositoryCount}
              {link.unavailableRepositoryCount > 0
                ? ` (${link.unavailableRepositoryCount} unavailable)`
                : ""}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Allowed repositories</dt>
            <dd>{link.allowListCount}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Last event</dt>
            <dd>{when(link.lastEventAt)}</dd>
          </div>
        </dl>
        <div>
          <Button
            variant="secondary"
            aria-expanded={editing}
            aria-controls={`allow-list-${link.id}`}
            onClick={() => setEditing((v) => !v)}
          >
            {editing ? <ChevronUp aria-hidden="true" /> : <ChevronDown aria-hidden="true" />}
            {canManage ? "Edit allowed repositories" : "View allowed repositories"}
          </Button>
        </div>
        {editing ? (
          <section
            id={`allow-list-${link.id}`}
            aria-label={`Allowed repositories of ${link.account.login}`}
          >
            <p className="mb-3 text-xs text-muted-foreground">
              Only allowed repositories can be connected to this workspace. A repository can be
              allowed in one workspace at a time.
            </p>
            <AllowListEditor workspaceId={workspaceId} link={link} canManage={canManage} />
          </section>
        ) : null}
        <ConfirmDialog
          open={unlinking}
          onOpenChange={(open) => {
            setUnlinking(open);
            if (!open) unlink.reset();
          }}
          title="Unlink this GitHub account from the workspace?"
          description="Only this workspace's repositories from this account become disconnected (nothing is deleted) and their pipelines stop. Other workspaces using the account are not affected. History, findings and audit entries are kept; linking the account again restores the repositories."
          confirmLabel="Unlink account"
          destructive
          confirmText={link.account.login}
          pending={unlink.isPending}
          error={unlink.error}
          onConfirm={({ confirm }) =>
            unlink.mutate(
              { linkId: link.id, confirm },
              {
                onSuccess: (r) => {
                  setUnlinking(false);
                  toast.success(
                    `Unlinked; ${r.repositoriesDisconnected} repositories disconnected`,
                  );
                },
              },
            )
          }
        />
      </CardContent>
    </Card>
  );
}
