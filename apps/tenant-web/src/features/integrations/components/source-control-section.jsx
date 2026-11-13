import { DataTable } from "@qmentisai/ui";
import { Plug } from "lucide-react";
import { Link } from "react-router";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { useInstallations } from "../hooks/use-integrations.js";
import { LinkStatus, statusSummary } from "./link-status.jsx";
import { WorkspaceUsage } from "./workspace-usage.jsx";
import { can } from "@qmentisai/shared";

const COLUMNS = [
  {
    id: "account",
    header: "GitHub account",
    cell: ({ row: { original: i } }) => (
      <>
        <Link
          to="/integrations/github"
          className="font-mono text-xs underline-offset-2 hover:underline"
        >
          {i.account.login}
        </Link>
        <div className="text-xs text-muted-foreground">
          {i.account.type === "organization" ? "Organization" : "Personal account"}
        </div>
      </>
    ),
  },
  {
    id: "access",
    header: "Access",
    cell: ({ row: { original: i } }) =>
      i.repositorySelection === "all" ? "All repositories" : "Selected repositories",
  },
  {
    id: "health",
    header: "Health",
    cell: ({ row: { original: i } }) => (
      <>
        <LinkStatus link={i} />
        {statusSummary(i) ? (
          <div className="mt-1 text-xs text-muted-foreground">{statusSummary(i)}</div>
        ) : null}
      </>
    ),
  },
  {
    id: "repositories",
    header: "Repositories",
    cell: ({ row: { original: i } }) => i.repositoryCount,
  },
  {
    id: "usedBy",
    header: "Used by",
    cell: ({ row: { original: i } }) => <WorkspaceUsage installation={i} />,
  },
];

/** Read-only list of GitHub installations of the organization and the workspaces using them (T-13). */
export function SourceControlSection() {
  const installations = useInstallations();
  const permissions = usePermissions();
  const mine = permissions.workspaces.filter((w) =>
    can(permissions, "workspace_integration.view", { type: "workspace", workspaceId: w.id }),
  );
  const items = (installations.data ?? []).filter((i) => i.status !== "unlinked");
  return (
    <div className="space-y-3">
      {installations.isPending ? (
        <LoadingState label="Loading GitHub installations" rows={2} />
      ) : null}
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
      {items.length > 0 ? (
        <DataTable
          caption="GitHub installations and the workspaces using them"
          columns={COLUMNS}
          data={items}
          getRowId={(i) => i.id}
          height="auto"
          maxHeight="24rem"
        />
      ) : null}
      <p className="text-sm text-muted-foreground">
        Source control is connected from a workspace&apos;s Integrations page.
        {mine.length > 0 ? " Open one of your workspaces:" : ""}
      </p>
      {mine.length > 0 ? (
        <ul className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
          {mine.map((w) => (
            <li key={w.id}>
              <Link
                to={`/workspaces/${w.id}/integrations`}
                className="underline-offset-2 hover:underline"
              >
                {w.name}
              </Link>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
