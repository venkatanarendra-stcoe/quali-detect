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
        <div className="relative overflow-x-auto rounded-md border border-border bg-card">
          <table className="w-full text-left text-[13px] leading-5">
            <caption className="sr-only">
              GitHub installations and the workspaces using them
            </caption>
            <thead className="border-b border-border text-muted-foreground">
              <tr>
                {["GitHub account", "Access", "Health", "Repositories", "Used by"].map((h) => (
                  <th key={h} scope="col" className="px-3 py-2 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id} className="border-b border-border last:border-0">
                  <td className="px-3 py-2">
                    <Link
                      to="/integrations/github"
                      className="font-mono text-xs underline-offset-2 hover:underline"
                    >
                      {i.account.login}
                    </Link>
                    <div className="text-xs text-muted-foreground">
                      {i.account.type === "organization" ? "Organization" : "Personal account"}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    {i.repositorySelection === "all" ? "All repositories" : "Selected repositories"}
                  </td>
                  <td className="px-3 py-2">
                    <LinkStatus link={i} />
                    {statusSummary(i) ? (
                      <div className="mt-1 text-xs text-muted-foreground">{statusSummary(i)}</div>
                    ) : null}
                  </td>
                  <td className="px-3 py-2">{i.repositoryCount}</td>
                  <td className="px-3 py-2">
                    <WorkspaceUsage installation={i} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
