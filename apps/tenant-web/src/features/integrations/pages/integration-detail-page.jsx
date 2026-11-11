import { CheckCircle2, ExternalLink, Plug, RefreshCw } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { PageHeader } from "@/components/common/page-header.jsx";
import { Pager } from "@/components/common/pager.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { Select } from "@/components/ui/select.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { useCan, usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { describeError } from "@/lib/api/index.js";
import { LinkHealth } from "../components/link-health.jsx";
import {
  useCatalog,
  useDeliveries,
  useInstallations,
  useRefreshInstallation,
  useSetScope,
  useStartLinking,
  useUnlinkInstallation,
} from "../hooks/use-integrations.js";

const when = (value) =>
  new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const CAPABILITIES = [
  ["Repository metadata", (p) => Boolean(p.metadata)],
  ["Contents (read)", (p) => Boolean(p.contents)],
  ["Pull requests (read)", (p) => Boolean(p.pull_requests)],
  ["Organization members (read, for linking checks)", (p) => Boolean(p.members)],
];

/** Webhook health: recent deliveries with the signature already verified (only verified deliveries are recorded). */
function Webhooks({ linkId }) {
  const [page, setPage] = useState(1);
  const [outcome, setOutcome] = useState("");
  const deliveries = useDeliveries(linkId, { page, pageSize: 10 });
  const items = (deliveries.data?.items ?? []).filter((d) => !outcome || d.outcome === outcome);
  const all = deliveries.data?.items ?? [];
  const accepted = all.filter((d) => d.outcome === "accepted" || d.outcome === "ignored").length;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Webhook health</CardTitle>
        <CardDescription>
          {all.length > 0
            ? `Last delivery ${when(all[0].receivedAt)} · ${Math.round((accepted / all.length) * 100)}% processed in the latest ${all.length}`
            : "No deliveries received yet."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {deliveries.isPending ? <LoadingState label="Loading deliveries" /> : null}
        {deliveries.isError ? (
          <QueryErrorState error={deliveries.error} onRetry={deliveries.refetch} />
        ) : null}
        {deliveries.data && all.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Deliveries appear here after GitHub sends the first event.
          </p>
        ) : null}
        {all.length > 0 ? (
          <>
            <div className="mb-3 w-48">
              <label htmlFor="delivery-outcome" className="sr-only">
                Outcome
              </label>
              <Select
                id="delivery-outcome"
                value={outcome}
                onChange={(e) => setOutcome(e.target.value)}
              >
                <option value="">All outcomes</option>
                <option value="accepted">Accepted</option>
                <option value="ignored">Ignored</option>
                <option value="duplicate">Duplicate</option>
              </Select>
            </div>
            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-left text-[13px] leading-5">
                <caption className="sr-only">Recent webhook deliveries</caption>
                <thead className="border-b border-border text-muted-foreground">
                  <tr>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Time
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Event
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Outcome
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Signature
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((d) => (
                    <tr key={d.id} className="border-b border-border last:border-0">
                      <td className="px-3 py-2 whitespace-nowrap">{when(d.receivedAt)}</td>
                      <td className="px-3 py-2 font-mono text-xs">
                        {d.event}
                        {d.action ? `.${d.action}` : ""}
                      </td>
                      <td className="px-3 py-2">{d.outcome}</td>
                      <td className="px-3 py-2">
                        <span className="inline-flex items-center gap-1">
                          <CheckCircle2 className="size-3 text-status-success" aria-hidden="true" />
                          Verified
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager pagination={deliveries.data.pagination} onPage={setPage} />
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

function Scope({ link, canManage }) {
  const workspaces = usePermissions().workspaces;
  const setScope = useSetScope();
  const [selected, setSelected] = useState(() => new Set(link.workspaceScope));
  const allWorkspaces = selected.size === 0;
  const toggle = (id) =>
    setSelected((current) => {
      const next = new Set(current);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Scope</CardTitle>
        <CardDescription>
          Workspaces that may connect repositories through this account. None selected means every
          workspace.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <ul className="grid gap-1 sm:grid-cols-2">
          {workspaces.map((w) => (
            <li key={w.id}>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={selected.has(w.id)}
                  disabled={!canManage}
                  onChange={() => toggle(w.id)}
                />
                {w.name}
              </label>
            </li>
          ))}
        </ul>
        <p className="text-xs text-muted-foreground">
          {allWorkspaces
            ? "Every workspace can use this account."
            : `${selected.size} workspace(s) selected.`}
        </p>
        {setScope.error ? (
          <p role="alert" className="text-sm text-status-danger">
            {describeError(setScope.error)}
          </p>
        ) : null}
        <DisabledWithReason
          reason={canManage ? null : "You need the integration.manage permission."}
        >
          <Button
            variant="secondary"
            disabled={setScope.isPending}
            onClick={() =>
              setScope.mutate(
                { linkId: link.id, workspaceIds: [...selected] },
                { onSuccess: () => toast.success("Scope saved") },
              )
            }
          >
            Save scope
          </Button>
        </DisabledWithReason>
      </CardContent>
    </Card>
  );
}

function LinkSection({ link, canManage }) {
  const refresh = useRefreshInstallation();
  const unlink = useUnlinkInstallation();
  const [unlinking, setUnlinking] = useState(false);
  return (
    <section aria-labelledby={`link-${link.id}`} className="mb-8 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <h2 id={`link-${link.id}`} className="text-base font-semibold">
            <span className="font-mono">{link.account.login}</span>
          </h2>
          <LinkHealth status={link.health} />
          <Badge>
            {link.account.type === "organization" ? "Organization" : "Personal account"}
          </Badge>
        </div>
        <div className="flex gap-2">
          <DisabledWithReason
            reason={canManage ? null : "You need the integration.manage permission."}
          >
            <Button
              variant="secondary"
              disabled={refresh.isPending || link.status !== "linked"}
              onClick={() =>
                refresh.mutate(link.id, { onSuccess: () => toast.success("Connection checked") })
              }
            >
              <RefreshCw aria-hidden="true" />
              Test connection
            </Button>
          </DisabledWithReason>
          <DisabledWithReason
            reason={canManage ? null : "You need the integration.manage permission."}
          >
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
      {link.health !== "healthy" && link.health !== "unlinked" ? (
        <p
          role="status"
          className="rounded-md border border-border-strong bg-secondary p-3 text-sm"
        >
          {link.health === "degraded" &&
            `${link.unavailableRepositoryCount} repositories are unavailable. Open the repositories page and sync them, or check the access on GitHub.`}
          {link.health === "suspended" &&
            "GitHub reports this installation as suspended. Repositories are paused until it is unsuspended."}
          {link.health === "revoked" &&
            "The App was uninstalled from this GitHub account. Link it again to restore the repositories."}
        </p>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>Connection</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-muted-foreground">Authentication</dt>
              <dd>GitHub App installation</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Repository access</dt>
              <dd>
                {link.repositorySelection === "all" ? "All repositories" : "Selected repositories"}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Connected on</dt>
              <dd>{when(link.linkedAt)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Repositories in QmentisAI</dt>
              <dd>{link.repositoryCount}</dd>
            </div>
          </dl>
          <p className="mt-3 text-xs text-muted-foreground">
            No credentials are stored for you: access uses short-lived tokens issued by GitHub for
            this installation.
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Capabilities</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="grid gap-1 text-sm sm:grid-cols-2">
            <li className="flex items-center gap-2">
              <CheckCircle2 className="size-4 text-status-success" aria-hidden="true" />
              Webhooks (through the GitHub App)
            </li>
            {CAPABILITIES.map(([label, test]) => (
              <li key={label} className="flex items-center gap-2">
                <CheckCircle2
                  className={
                    test(link.permissions)
                      ? "size-4 text-status-success"
                      : "size-4 text-muted-foreground"
                  }
                  aria-hidden="true"
                />
                {label}
                {test(link.permissions) ? null : (
                  <span className="text-xs text-muted-foreground">(not granted)</span>
                )}
              </li>
            ))}
            <li className="text-muted-foreground">
              Pull request comments and commit status: not requested
            </li>
          </ul>
        </CardContent>
      </Card>
      <Scope key={link.workspaceScope.join(",")} link={link} canManage={canManage} />
      <Webhooks linkId={link.id} />
      <ConfirmDialog
        open={unlinking}
        onOpenChange={(open) => {
          setUnlinking(open);
          if (!open) unlink.reset();
        }}
        title="Unlink this GitHub account?"
        description="Its repositories become disconnected (nothing is deleted), their pipelines stop, and webhooks from this account are ignored. History, findings and audit entries are kept. The App stays installed on GitHub; linking it again restores the repositories."
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
                toast.success(`Unlinked; ${r.repositoriesDisconnected} repositories disconnected`);
              },
            },
          )
        }
      />
    </section>
  );
}

/**
 * T-14 Integration detail (GitHub). Read with integration.view; every action needs integration.manage (hidden or disabled
 * with the reason, never by role name). The link flow starts here: GitHub install page -> setup page -> authorize -> callback.
 */
export function IntegrationDetailPage() {
  const { provider } = useParams();
  const can = useCan();
  const canManage = can("integration.manage");
  const catalog = useCatalog();
  const installations = useInstallations({ enabled: provider === "github" });
  const start = useStartLinking();
  if (provider !== "github") return <NotFoundState />;
  const status = catalog.data?.items.find((i) => i.provider === "github")?.status;
  const links = installations.data ?? [];
  const linked = links.filter((l) => l.status === "linked");
  const unlinked = links.filter((l) => l.status === "unlinked");
  const startLinking = () =>
    start.mutate(undefined, { onSuccess: ({ installUrl }) => window.location.assign(installUrl) });
  return (
    <>
      <PageHeader
        title="GitHub"
        description="Source control through the QmentisAI GitHub App."
        actions={
          status === "not_configured" ? null : (
            <DisabledWithReason
              reason={
                canManage
                  ? null
                  : "You need the integration.manage permission to link a GitHub account."
              }
            >
              <Button onClick={startLinking} disabled={start.isPending}>
                <Plug aria-hidden="true" />
                Link a GitHub account
              </Button>
            </DisabledWithReason>
          )
        }
      />
      {start.error ? (
        <p role="alert" className="mb-3 text-sm text-status-danger">
          {describeError(start.error)}
        </p>
      ) : null}
      {installations.isPending || catalog.isPending ? (
        <LoadingState label="Loading GitHub connection" />
      ) : null}
      {installations.isError ? (
        <QueryErrorState error={installations.error} onRetry={installations.refetch} />
      ) : null}
      {status === "not_configured" ? (
        <EmptyState
          icon={Plug}
          title="GitHub is not configured"
          description="The GitHub App is not set up on this platform. Ask your platform administrator."
        />
      ) : null}
      {installations.data && status !== "not_configured" && linked.length === 0 ? (
        <EmptyState
          icon={Plug}
          title="No GitHub account linked"
          description={
            canManage
              ? "Link a GitHub organization or personal account to connect repositories. You must be an owner of the organization."
              : "Ask an organization administrator to link a GitHub account."
          }
        />
      ) : null}
      {linked.map((link) => (
        <LinkSection key={link.id} link={link} canManage={canManage} />
      ))}
      {unlinked.length > 0 ? (
        <p className="text-sm text-muted-foreground">
          Previously linked: {unlinked.map((l) => l.account.login).join(", ")}. Linking one of these
          accounts again restores its repositories.
        </p>
      ) : null}
      <p className="mt-6 inline-flex items-center gap-1 text-xs text-muted-foreground">
        <ExternalLink className="size-3" aria-hidden="true" />
        Removing the App from GitHub is done on GitHub; unlinking here only stops QmentisAI from
        using it.
      </p>
    </>
  );
}
