import { ExternalLink, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { toast } from "sonner";
import { PageHeader } from "@/components/common/page-header.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { AddPipelineButton, RepositoryPipelinesTab } from "@/features/pipelines/index.js";
import { describeError } from "@/lib/api/index.js";
import { DisconnectDialog, useRepositoryActions } from "../components/repository-actions.jsx";
import { RepositoryHealth } from "../components/repository-health.jsx";
import {
  useBranches,
  usePullRequests,
  useRepository,
  useUpdateRepository,
} from "../hooks/use-repositories.js";

const when = (value) =>
  value
    ? new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
    : "—";

function Live({ query, empty, children }) {
  if (query.isPending) return <LoadingState rows={3} />;
  if (query.isError) return <QueryErrorState error={query.error} onRetry={query.refetch} />;
  if (query.data.items.length === 0) return <EmptyState title={empty} />;
  return children(query.data.items);
}

function Branches({ id }) {
  const branches = useBranches(id);
  return (
    <Live query={branches} empty="No branches">
      {(items) => (
        <ul className="divide-y divide-border rounded-md border border-border text-sm">
          {items.map((b) => (
            <li key={b.name} className="flex items-center justify-between px-3 py-2">
              <span className="font-mono text-xs">{b.name}</span>
              <span className="text-xs text-muted-foreground">
                {b.protected ? "Protected" : ""}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Live>
  );
}
function PullRequests({ id }) {
  const pulls = usePullRequests(id);
  return (
    <Live query={pulls} empty="No open pull requests">
      {(items) => (
        <ul className="divide-y divide-border rounded-md border border-border text-sm">
          {items.map((p) => (
            <li key={p.number} className="px-3 py-2">
              <span className="font-mono text-xs">#{p.number}</span> {p.title}
              <div className="text-xs text-muted-foreground">
                {p.headRef} → {p.baseRef}
                {p.draft ? " · draft" : ""}
                {p.isFork ? " · from a fork" : ""}
                {p.authorLogin ? ` · ${p.authorLogin}` : ""}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Live>
  );
}

function Settings({ repository, canUpdate }) {
  const update = useUpdateRepository(repository.id);
  const [displayName, setDisplayName] = useState(repository.displayName ?? "");
  const [description, setDescription] = useState(repository.description ?? "");
  const save = (event) => {
    event.preventDefault();
    update.mutate(
      { displayName: displayName.trim() || null, description: description.trim() || null },
      { onSuccess: () => toast.success("Repository updated") },
    );
  };
  return (
    <form onSubmit={save} className="max-w-lg space-y-3">
      <div className="space-y-1.5">
        <label htmlFor="display-name" className="text-sm font-medium">
          Display name
        </label>
        <Input
          id="display-name"
          value={displayName}
          maxLength={100}
          disabled={!canUpdate}
          onChange={(e) => setDisplayName(e.target.value)}
        />
      </div>
      <div className="space-y-1.5">
        <label htmlFor="description" className="text-sm font-medium">
          Description
        </label>
        <Textarea
          id="description"
          value={description}
          maxLength={500}
          disabled={!canUpdate}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>
      {update.error ? (
        <p role="alert" className="text-sm text-status-danger">
          {describeError(update.error)}
        </p>
      ) : null}
      <DisabledWithReason reason={canUpdate ? null : "You need the repository.update permission."}>
        <Button type="submit" disabled={update.isPending}>
          Save changes
        </Button>
      </DisabledWithReason>
    </form>
  );
}

function Detail({ repository }) {
  const navigate = useNavigate();
  const can = useCan();
  const actions = useRepositoryActions(repository);
  const [confirming, setConfirming] = useState(false);
  const [params, setParams] = useSearchParams();
  const live = repository.status !== "disconnected";
  const seesPipelines = can("pipeline.view", {
    type: "workspace",
    workspaceId: repository.workspaceId,
  });
  const requestedTab = params.get("tab");
  const tab =
    ["overview", "pipelines", "branches", "pulls", "webhooks", "settings"].includes(requestedTab) &&
    (requestedTab !== "pipelines" || seesPipelines)
      ? requestedTab
      : "overview";
  const setTab = (value) =>
    setParams(value === "overview" ? {} : { tab: value }, { replace: true });
  return (
    <>
      <PageHeader
        title={<span className="font-mono text-lg">{repository.fullName}</span>}
        description={repository.description ?? undefined}
        actions={
          <>
            <RepositoryHealth repository={repository} />
            <AddPipelineButton repository={repository} />
            {actions.canSync ? (
              <Button variant="secondary" disabled={actions.syncing} onClick={actions.sync}>
                <RefreshCw aria-hidden="true" />
                Sync now
              </Button>
            ) : null}
            {actions.canToggle ? (
              <Button variant="secondary" onClick={actions.toggle}>
                {repository.enabled ? "Disable" : "Enable"}
              </Button>
            ) : null}
            {actions.canDisconnect ? (
              <Button variant="outline" onClick={() => setConfirming(true)}>
                Disconnect
              </Button>
            ) : null}
          </>
        }
      />
      {repository.status === "unavailable" ? (
        <p
          role="status"
          className="mb-4 rounded-md border border-border-strong bg-secondary p-3 text-sm"
        >
          GitHub no longer reports this repository to the App ({repository.consecutiveSyncFailures}{" "}
          failed checks in a row). Check the repository&apos;s access on GitHub, then sync again. It
          is disconnected automatically after repeated failures; nothing is deleted. Its pipelines
          are stopped and resume automatically when the repository is active again.
        </p>
      ) : null}
      {repository.status === "disconnected" ? (
        <p
          role="status"
          className="mb-4 rounded-md border border-border-strong bg-secondary p-3 text-sm"
        >
          This repository is disconnected
          {repository.disconnectedAt ? ` since ${when(repository.disconnectedAt)}` : ""}.{" "}
          {repository.disconnectReason === "workspace_unlinked"
            ? "The GitHub account was unlinked from this workspace. Link it again on the workspace's Integrations page to restore the repository."
            : repository.disconnectReason === "installation_revoked"
              ? "The GitHub App was removed from the GitHub account. Install and link it again on the workspace's Integrations page to restore the repository."
              : "Its history is kept. Connect it again from the Connect repository page to restore it."}{" "}
          Its pipelines are stopped and resume automatically when the repository is active again.
          {repository.disconnectReason === "workspace_unlinked" ||
          repository.disconnectReason === "installation_revoked" ? (
            <>
              {" "}
              <Link
                className="underline underline-offset-2"
                to={`/workspaces/${repository.workspaceId}/integrations`}
              >
                Workspace integrations
              </Link>
            </>
          ) : null}
        </p>
      ) : null}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="max-w-full overflow-x-auto">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          {seesPipelines ? <TabsTrigger value="pipelines">Pipelines</TabsTrigger> : null}
          <TabsTrigger value="branches" disabled={!live}>
            Branches
          </TabsTrigger>
          <TabsTrigger value="pulls" disabled={!live}>
            Pull requests
          </TabsTrigger>
          <TabsTrigger value="webhooks">Webhooks</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <Card>
            <CardHeader>
              <CardTitle>Overview</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-muted-foreground">Provider</dt>
                  <dd>GitHub</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Visibility</dt>
                  <dd>
                    {repository.visibility}
                    {repository.archived ? " · archived on GitHub" : ""}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Default branch</dt>
                  <dd className="font-mono text-xs">{repository.defaultBranch ?? "—"}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Connected</dt>
                  <dd>{when(repository.connectedAt)}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Last synced</dt>
                  <dd>{when(repository.lastSyncedAt)}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Last event</dt>
                  <dd>{when(repository.lastEventAt)}</dd>
                </div>
                {seesPipelines ? (
                  <div>
                    <dt className="text-muted-foreground">Pipelines</dt>
                    <dd>
                      {repository.pipelineCount > 0 ? (
                        <button
                          type="button"
                          className="rounded-sm underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
                          onClick={() => setTab("pipelines")}
                        >
                          {repository.pipelineCount}
                        </button>
                      ) : (
                        <>
                          0
                          {can("pipeline.manage", {
                            type: "workspace",
                            workspaceId: repository.workspaceId,
                          }) &&
                          repository.status === "active" &&
                          repository.enabled ? (
                            <>
                              {" · "}
                              <Link
                                className="underline underline-offset-2"
                                to={`/workspaces/${repository.workspaceId}/pipelines/new?repository=${repository.id}`}
                              >
                                Add pipeline
                              </Link>
                            </>
                          ) : null}
                        </>
                      )}
                    </dd>
                  </div>
                ) : null}
                {repository.htmlUrl ? (
                  <div>
                    <dt className="text-muted-foreground">On GitHub</dt>
                    <dd>
                      <a
                        className="inline-flex items-center gap-1 underline-offset-2 hover:underline"
                        href={repository.htmlUrl}
                        target="_blank"
                        rel="noreferrer noopener"
                      >
                        Open
                        <ExternalLink className="size-3" aria-hidden="true" />
                      </a>
                    </dd>
                  </div>
                ) : null}
              </dl>
            </CardContent>
          </Card>
        </TabsContent>
        {seesPipelines ? (
          <TabsContent value="pipelines">
            <RepositoryPipelinesTab repository={repository} />
          </TabsContent>
        ) : null}
        <TabsContent value="branches">
          <Branches id={repository.id} />
        </TabsContent>
        <TabsContent value="pulls">
          <PullRequests id={repository.id} />
        </TabsContent>
        <TabsContent value="webhooks">
          <Card>
            <CardHeader>
              <CardTitle>Webhooks</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p>
                Events arrive through the QmentisAI GitHub App; there is no per-repository webhook
                to configure. Signatures are verified on every delivery.
              </p>
              <p className="text-muted-foreground">
                Last event received: {when(repository.lastEventAt)}
              </p>
              {can("integration.view") ? (
                <Link className="underline-offset-2 hover:underline" to="/integrations/github">
                  Delivery history on the GitHub integration page
                </Link>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="settings">
          <Settings repository={repository} canUpdate={actions.canUpdate} />
        </TabsContent>
      </Tabs>
      <DisconnectDialog
        repository={repository}
        open={confirming}
        onOpenChange={setConfirming}
        disconnect={actions.disconnect}
        onDone={() => navigate(`/workspaces/${repository.workspaceId}/repositories`)}
      />
    </>
  );
}

/**
 * T-24 Repository detail. The repository must belong to the workspace in the URL; otherwise it is the same not-found page
 * (a repository of another workspace or tenant is indistinguishable from a missing one).
 */
export function RepositoryDetailPage() {
  const { workspaceId, repositoryId } = useParams();
  const query = useRepository(repositoryId);
  if (query.isPending) return <LoadingState label="Loading repository" />;
  if (query.isError) return <QueryErrorState error={query.error} onRetry={query.refetch} />;
  if (query.data.workspaceId !== workspaceId) return <NotFoundState />;
  return <Detail repository={query.data} />;
}
