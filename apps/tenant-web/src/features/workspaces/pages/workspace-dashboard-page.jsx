import { Link } from "react-router";
import { AppPageLayout } from "@qmentisai/ui";
import { StatusChip } from "@/components/common/status-chip.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { useActiveWorkspace } from "@/features/authorization/hooks/use-permissions.js";
import { useWorkspaceDetail } from "../hooks/use-workspaces.js";

/** Workspace dashboard shell: always the active workspace. Metrics arrive with the modules that produce them. */
export function WorkspaceDashboardPage() {
  const active = useActiveWorkspace();
  const detail = useWorkspaceDetail(active?.id);
  if (detail.isPending) return <LoadingState rows={3} label="Loading workspace" />;
  if (detail.isError) return <QueryErrorState error={detail.error} onRetry={detail.refetch} />;
  const ws = detail.data;
  return (
    <AppPageLayout
      title={ws.name}
      description={ws.description ?? undefined}
      actions={<StatusChip status={ws.status} />}
    >
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Dashboard</CardTitle>
            <CardDescription>Security metrics for this workspace.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Findings, pipeline and SLA charts appear here once the repository, pipeline and
              findings modules are available.
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Your access</CardTitle>
            <CardDescription>What you can do in this workspace.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm">{active.permissions.length} permissions in this workspace.</p>
            <details className="mt-2 text-sm">
              <summary className="cursor-pointer text-primary-text">Show permissions</summary>
              <ul className="mt-2 flex flex-wrap gap-1.5">
                {active.permissions.map((key) => (
                  <li key={key} className="rounded-sm bg-secondary px-1.5 py-0.5 font-mono text-xs">
                    {key}
                  </li>
                ))}
              </ul>
            </details>
            <p className="mt-3 text-xs text-subtle-foreground">
              Shown for convenience. The server checks every action independently.
            </p>
          </CardContent>
        </Card>
      </div>
      <p className="mt-4 text-sm">
        <Link className="text-primary-text underline-offset-4 hover:underline" to="/workspaces">
          All workspaces
        </Link>
      </p>
    </AppPageLayout>
  );
}
