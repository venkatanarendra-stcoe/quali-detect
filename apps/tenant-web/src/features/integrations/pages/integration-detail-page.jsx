import { Plug } from "lucide-react";
import { AppPageLayout } from "@qmentisai/ui";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { LinkStatus, LinkStatusNotice } from "../components/link-status.jsx";
import { WebhookDeliveries } from "../components/webhook-deliveries.jsx";
import { WorkspaceUsage } from "../components/workspace-usage.jsx";
import { useInstallations } from "../hooks/use-integrations.js";

const when = (value) =>
  new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const PERMISSIONS = [
  ["Repository metadata", "metadata"],
  ["Contents (read)", "contents"],
  ["Pull requests (read)", "pull_requests"],
  ["Organization members (read, for linking checks)", "members"],
];

function Installation({ installation: i }) {
  return (
    <section aria-labelledby={`inst-${i.id}`} className="mb-8 space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h2 id={`inst-${i.id}`} className="text-base font-semibold">
          <span className="font-mono">{i.account.login}</span>
        </h2>
        <LinkStatus link={i} />
        <Badge>{i.account.type === "organization" ? "Organization" : "Personal account"}</Badge>
      </div>
      <LinkStatusNotice link={i} />
      <Card>
        <CardHeader>
          <CardTitle>Installation</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-muted-foreground">Repository access</dt>
              <dd>
                {i.repositorySelection === "all" ? "All repositories" : "Selected repositories"}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">First linked</dt>
              <dd>{when(i.linkedAt)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Repositories in QmentisAI</dt>
              <dd>
                {i.repositoryCount}
                {i.unavailableRepositoryCount > 0
                  ? ` (${i.unavailableRepositoryCount} unavailable)`
                  : ""}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Workspaces using it</dt>
              <dd>
                <WorkspaceUsage installation={i} />
              </dd>
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
          <CardTitle>Permissions</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="grid gap-1 text-sm sm:grid-cols-2">
            {PERMISSIONS.map(([label, key]) => (
              <li key={key}>
                {label}
                {i.permissions?.[key] ? "" : " (not granted)"}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
      <WebhookDeliveries installationId={i.id} login={i.account.login} />
    </section>
  );
}

/**
 * T-14 GitHub installations (organization, integration.view, read-only). Linking, testing, unlinking and the repository
 * allow-list live on each workspace's Integrations page.
 */
export function IntegrationDetailPage() {
  const installations = useInstallations();
  const items = (installations.data ?? []).filter((i) => i.status !== "unlinked");
  return (
    <AppPageLayout
      title="GitHub"
      description="Installations of the QmentisAI GitHub App and the workspaces using them. Linking is done from a workspace's Integrations page."
    >
      {installations.isPending ? <LoadingState label="Loading GitHub installations" /> : null}
      {installations.isError ? (
        <QueryErrorState error={installations.error} onRetry={installations.refetch} />
      ) : null}
      {installations.data && items.length === 0 ? (
        <EmptyState
          icon={Plug}
          title="No GitHub account linked"
          description="Source control is connected from a workspace's Integrations page."
        />
      ) : null}
      {items.map((i) => (
        <Installation key={i.id} installation={i} />
      ))}
    </AppPageLayout>
  );
}
