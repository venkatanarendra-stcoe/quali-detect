import { Boxes, Building2 } from "lucide-react";
import { Link } from "react-router";
import { AppPageLayout } from "@qmentisai/ui";
import { StatusChip } from "@/components/common/status-chip.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { LinkButton } from "@/components/common/link-button.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { useSession } from "@/features/auth/hooks/use-session.js";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useTotal } from "@/features/directory/hooks/use-directory.js";
import { useOverview } from "../hooks/use-overview.js";
import { useWorkspaceList } from "@/features/workspaces/hooks/use-workspaces.js";

const SHOWN = 12;

/** One number with loading, error and value states (each tile has its own query so one failure never blanks the page). */
function StatTile({ label, query, hint }) {
  return (
    <Card>
      <CardHeader className="pb-1">
        <CardDescription>{label}</CardDescription>
      </CardHeader>
      <CardContent>
        {query.isPending ? <Skeleton className="h-8 w-16" /> : null}
        {query.isError ? (
          <p role="alert" className="text-sm text-status-danger">
            Unavailable.{" "}
            <button type="button" className="underline" onClick={() => query.refetch()}>
              Retry
            </button>
          </p>
        ) : null}
        {query.isSuccess ? (
          <p className="text-[28px] leading-8 font-semibold tabular-nums">{query.data}</p>
        ) : null}
        {hint ? <p className="mt-1 text-xs text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
  );
}

/**
 * T-06 Organization overview: tenant-level counts and the workspaces the user can open. Tiles appear only for
 * permissions the user holds; security metrics arrive with the findings module (nothing is invented here).
 */
export function OverviewPage() {
  const { me } = useSession();
  const can = useCan();
  const canSeeUsers = can("user.view");
  const list = useWorkspaceList({ pageSize: SHOWN, sort: "name:asc" });
  const overview = useOverview();
  const archived = useWorkspaceList({ status: "archived", pageSize: 1 });
  const members = useTotal("users", { status: "active" }, { enabled: canSeeUsers });
  const invited = useTotal("users", { status: "invited" }, { enabled: canSeeUsers });
  const groups = useTotal("groups", {}, { enabled: can("group.view") });
  const total = list.data?.pagination?.totalItems ?? 0;

  // The server decides (GET /overview needs dashboard.view); the UI guard above is for usability only.
  const workspaceTile = {
    isPending: overview.isPending,
    isError: overview.isError,
    isSuccess: overview.isSuccess,
    data: overview.data?.accessibleWorkspaces ?? 0,
    refetch: overview.refetch,
  };
  const archivedTile = {
    isPending: archived.isPending,
    isError: archived.isError,
    isSuccess: archived.isSuccess,
    data: archived.data?.pagination?.totalItems ?? 0,
    refetch: archived.refetch,
  };

  return (
    <AppPageLayout
      title="Organization overview"
      description={me.tenant.name}
      actions={
        <PermissionGate
          permission="workspace.create"
          mode="disable"
          reason="You need the workspace.create permission to create workspaces."
        >
          <LinkButton to="/workspaces/new">New workspace</LinkButton>
        </PermissionGate>
      }
    >
      <section
        aria-label="Organization totals"
        className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-5"
      >
        <StatTile label="Active workspaces" query={workspaceTile} />
        <StatTile label="Archived workspaces" query={archivedTile} />
        <PermissionGate permission="user.view">
          <StatTile label="Members" query={members} />
        </PermissionGate>
        <PermissionGate permission="user.view">
          <StatTile label="Pending invitations" query={invited} />
        </PermissionGate>
        <PermissionGate permission="group.view">
          <StatTile label="Groups" query={groups} />
        </PermissionGate>
      </section>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Workspaces</CardTitle>
          <CardDescription>Open a workspace to see its dashboard.</CardDescription>
        </CardHeader>
        <CardContent>
          {list.isPending ? <LoadingState rows={3} label="Loading workspaces" /> : null}
          {list.isError ? <QueryErrorState error={list.error} onRetry={list.refetch} /> : null}
          {list.data && list.data.items.length === 0 ? (
            <EmptyState
              icon={Boxes}
              title="No workspaces yet"
              description={
                can("workspace.create")
                  ? "Create the first workspace to start organizing repositories and pipelines."
                  : "You don't have access to any workspace in this organization."
              }
              actions={
                can("workspace.create") ? (
                  <Button asChild>
                    <Link to="/workspaces/new">New workspace</Link>
                  </Button>
                ) : null
              }
            />
          ) : null}
          {list.data && list.data.items.length > 0 ? (
            <>
              <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {list.data.items.map((ws) => (
                  <li key={ws.id}>
                    <Link
                      to={`/workspaces/${ws.id}/dashboard`}
                      className="block rounded-md border border-border p-3 hover:bg-secondary"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-sm font-medium">{ws.name}</span>
                        <StatusChip status={ws.status} />
                      </div>
                      {ws.description ? (
                        <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">
                          {ws.description}
                        </p>
                      ) : null}
                      <p className="mt-2 text-xs text-subtle-foreground">
                        {ws.memberCount} {ws.memberCount === 1 ? "member" : "members"}
                        {ws.ownerName ? ` · Owner ${ws.ownerName}` : ""}
                      </p>
                    </Link>
                  </li>
                ))}
              </ul>
              {total > SHOWN ? (
                <p className="mt-3 text-sm">
                  <Link
                    className="text-primary-text underline-offset-4 hover:underline"
                    to="/workspaces"
                  >
                    View all {total} workspaces
                  </Link>
                </p>
              ) : null}
            </>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Security posture</CardTitle>
          <CardDescription>Findings, SLA and pipeline health across workspaces.</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-2 text-sm text-muted-foreground">
          <Building2 aria-hidden="true" className="size-4" />
          Security metrics appear here once repositories, pipelines and findings are available.
        </CardContent>
      </Card>
    </AppPageLayout>
  );
}
