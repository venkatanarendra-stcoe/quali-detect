import { AppPageLayout } from "@qmentisai/ui";
import { GitBranch, SearchX } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { LinkButton } from "@/components/common/link-button.jsx";
import { QueryTable } from "@/components/common/query-table.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { RepositoryRowActions } from "../components/repository-actions.jsx";
import { RepositoryHealth } from "../components/repository-health.jsx";
import { useRepositoryCursorList } from "../hooks/use-repositories.js";

const PAGE_SIZE = 20; // rows per "Load more" request
const when = (value) =>
  value
    ? new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
    : "—";

/**
 * T-22 Repositories (workspace). Filters and sort live in the URL; rows load with "Load more" (cursor), no totals are shown. The list only holds repositories of this
 * workspace; a "Connect repository" action needs repository.connect there.
 */
export function RepositoriesPage() {
  const { workspaceId } = useParams();
  const navigate = useNavigate();
  const can = useCan();
  const [params, setParams] = useSearchParams();
  const qParam = params.get("q") ?? "";
  const health = params.get("health") ?? "";
  const status = params.get("status") ?? "";
  const sort = params.get("sort") ?? "fullName:asc";
  const [search, setSearch] = useState(qParam);
  const debounced = useDebouncedValue(search);
  const filtered = Boolean(qParam || health || status);

  const update = (next) =>
    setParams(
      (current) => {
        const merged = new URLSearchParams(current);
        for (const [key, value] of Object.entries(next))
          value ? merged.set(key, value) : merged.delete(key);
        return merged;
      },
      { replace: true },
    );
  useEffect(() => {
    if (debounced.trim() !== qParam) update({ q: debounced.trim() });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the debounced text drives the URL
  }, [debounced]);

  const list = useRepositoryCursorList({
    workspaceId,
    q: qParam || undefined,
    health: health || undefined,
    status: status || undefined,
    sort,
    limit: PAGE_SIZE,
  });
  const clear = () => {
    setSearch("");
    setParams({}, { replace: true });
  };
  const canConnect = can("repository.connect");
  const canSeePipelines = can("pipeline.view");
  const connect = (
    <PermissionGate
      permission="repository.connect"
      mode="disable"
      reason="You need the repository.connect permission to connect repositories."
    >
      <LinkButton to={`/workspaces/${workspaceId}/repositories/connect`}>
        Connect repository
      </LinkButton>
    </PermissionGate>
  );

  const columns = [
    {
      id: "fullName",
      header: "Repository",
      sortDescFirst: false,
      accessorFn: () => null,
      cell: ({ row: { original: r } }) => (
        <>
          <Link
            className="font-mono text-xs underline-offset-2 hover:underline focus-visible:underline"
            to={`/workspaces/${r.workspaceId}/repositories/${r.id}`}
          >
            {r.fullName}
          </Link>
          <div className="text-xs text-muted-foreground">
            {r.visibility}
            {r.archived ? " · archived on GitHub" : ""}
          </div>
        </>
      ),
    },
    {
      id: "defaultBranch",
      header: "Default branch",
      enableSorting: false,
      cell: ({ row: { original: r } }) => (
        <span className="font-mono text-xs">{r.defaultBranch ?? "—"}</span>
      ),
    },
    {
      id: "health",
      header: "Health",
      enableSorting: false,
      cell: ({ row: { original: r } }) => <RepositoryHealth repository={r} />,
    },
    {
      id: "lastSyncedAt",
      header: "Last synced",
      sortDescFirst: false,
      accessorFn: () => null,
      meta: { className: "whitespace-nowrap" },
      cell: ({ row: { original: r } }) => when(r.lastSyncedAt),
    },
    {
      id: "pipelines",
      header: "Pipelines",
      enableSorting: false,
      cell: ({ row: { original: r } }) => (canSeePipelines ? r.pipelineCount : "—"),
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      enableSorting: false,
      meta: { className: "text-right" },
      cell: ({ row: { original: r } }) => <RepositoryRowActions repository={r} />,
    },
  ];

  return (
    <AppPageLayout
      title="Repositories"
      description="Repositories connected to this workspace."
      actions={connect}
      scroll={false}
    >
      <div className="mb-4 flex shrink-0 flex-wrap items-end gap-3">
        <div className="w-full max-w-xs">
          <label htmlFor="repo-search" className="sr-only">
            Search repositories
          </label>
          <Input
            id="repo-search"
            type="search"
            placeholder="Search repositories"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="w-40">
          <label htmlFor="repo-health" className="sr-only">
            Health
          </label>
          <Select
            id="repo-health"
            value={health}
            onChange={(e) => update({ health: e.target.value })}
          >
            <option value="">All health</option>
            <option value="healthy">Healthy</option>
            <option value="degraded">Degraded</option>
            <option value="error">Unavailable</option>
            <option value="disconnected">Disconnected</option>
          </Select>
        </div>
        <div className="w-40">
          <label htmlFor="repo-status" className="sr-only">
            Status
          </label>
          <Select
            id="repo-status"
            value={status}
            onChange={(e) => update({ status: e.target.value })}
          >
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="unavailable">Unavailable</option>
            <option value="disconnected">Disconnected</option>
          </Select>
        </div>
        {filtered ? (
          <Button variant="ghost" onClick={clear}>
            Clear filters
          </Button>
        ) : null}
      </div>
      <QueryTable
        caption="Repositories"
        query={list}
        columns={columns}
        getRowId={(r) => r.id}
        sort={sort}
        onSort={(s) => update({ sort: s === "fullName:asc" ? "" : s })}
        hasMore={list.hasMore}
        loadingMore={list.loadingMore}
        onLoadMore={list.loadMore}
        onRowClick={(r) => navigate(`/workspaces/${r.workspaceId}/repositories/${r.id}`)}
        rowLabel={(r) => `Open ${r.fullName}`}
        emptyState={
          filtered ? (
            <EmptyState
              icon={SearchX}
              title="No matching repositories"
              description="Try different filters."
              actions={
                <Button variant="secondary" onClick={clear}>
                  Clear filters
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={GitBranch}
              title="No repositories connected"
              description={
                canConnect
                  ? "Connect a repository from a GitHub account linked to this workspace. If no account is linked yet, link one on the workspace's Integrations page."
                  : "Ask someone with repository.connect to connect repositories to this workspace."
              }
              actions={
                <div className="flex gap-2">
                  {connect}
                  {can("workspace_integration.view") ? (
                    <LinkButton to={`/workspaces/${workspaceId}/integrations`} variant="secondary">
                      Workspace integrations
                    </LinkButton>
                  ) : null}
                </div>
              }
            />
          )
        }
      />
    </AppPageLayout>
  );
}
