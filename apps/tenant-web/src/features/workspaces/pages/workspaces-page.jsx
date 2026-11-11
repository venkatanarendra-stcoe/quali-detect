import { Boxes, MoreHorizontal, SearchX } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { PageHeader } from "@/components/common/page-header.jsx";
import { Pager } from "@/components/common/pager.jsx";
import { SortHeader } from "@/components/common/sort-header.jsx";
import { StatusChip } from "@/components/common/status-chip.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { LinkButton } from "@/components/common/link-button.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { useWorkspaceList } from "../hooks/use-workspaces.js";

const PAGE_SIZE = 20;
const date = (value) =>
  new Date(value).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });

function RowActions({ workspace }) {
  const navigate = useNavigate();
  const can = useCan();
  const scope = { type: "workspace", workspaceId: workspace.id };
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={`Actions for ${workspace.name}`}>
          <MoreHorizontal aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-52">
        <DropdownMenuItem onSelect={() => navigate(`/workspaces/${workspace.id}/dashboard`)}>
          Open dashboard
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => navigate(`/workspaces/${workspace.id}/members`)}>
          Members &amp; groups
        </DropdownMenuItem>
        {can("workspace.update", scope) ? (
          <DropdownMenuItem onSelect={() => navigate(`/workspaces/${workspace.id}/settings`)}>
            Settings
          </DropdownMenuItem>
        ) : null}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/**
 * T-07 Workspaces: the workspaces the caller can see, with search, status filter, sorting and pagination in the URL.
 * Columns follow what exists today (repositories, pipelines and findings columns arrive with their modules).
 */
export function WorkspacesPage() {
  const [params, setParams] = useSearchParams();
  const qParam = params.get("q") ?? "";
  const status = params.get("status") ?? "";
  const sort = params.get("sort") ?? "name:asc";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const [search, setSearch] = useState(qParam);
  const debounced = useDebouncedValue(search);
  const filtered = Boolean(qParam || status);

  const update = (next) => {
    setParams(
      (current) => {
        const merged = new URLSearchParams(current);
        for (const [key, value] of Object.entries(next))
          value ? merged.set(key, value) : merged.delete(key);
        return merged;
      },
      { replace: true },
    );
  };
  useEffect(() => {
    if (debounced.trim() !== qParam) update({ q: debounced.trim(), page: "" });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the debounced text drives the URL
  }, [debounced]);

  const list = useWorkspaceList({
    q: qParam || undefined,
    status: status || undefined,
    sort,
    page,
    pageSize: PAGE_SIZE,
  });
  const clear = () => {
    setSearch("");
    setParams({}, { replace: true });
  };

  return (
    <>
      <PageHeader
        title="Workspaces"
        description="Workspaces you can access in this organization."
        actions={
          <PermissionGate
            permission="workspace.create"
            mode="disable"
            reason="You need the workspace.create permission to create workspaces."
          >
            <LinkButton to="/workspaces/new">New workspace</LinkButton>
          </PermissionGate>
        }
      />
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div className="w-full max-w-xs">
          <label htmlFor="workspace-search" className="sr-only">
            Search workspaces
          </label>
          <Input
            id="workspace-search"
            type="search"
            placeholder="Search workspaces"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="w-40">
          <label htmlFor="workspace-status" className="sr-only">
            Status
          </label>
          <Select
            id="workspace-status"
            value={status}
            onChange={(e) => update({ status: e.target.value, page: "" })}
          >
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="archived">Archived</option>
          </Select>
        </div>
        {filtered ? (
          <Button variant="ghost" onClick={clear}>
            Clear filters
          </Button>
        ) : null}
        {list.data?.pagination ? (
          <p className="ml-auto text-sm text-muted-foreground" aria-live="polite">
            {list.data.pagination.totalItems}{" "}
            {list.data.pagination.totalItems === 1 ? "workspace" : "workspaces"}
          </p>
        ) : null}
      </div>

      {list.isPending ? <LoadingState label="Loading workspaces" /> : null}
      {list.isError ? <QueryErrorState error={list.error} onRetry={list.refetch} /> : null}
      {list.data && list.data.items.length === 0 ? (
        filtered ? (
          <EmptyState
            icon={SearchX}
            title="No matching workspaces"
            description="Try different filters."
            actions={
              <Button variant="secondary" onClick={clear}>
                Clear filters
              </Button>
            }
          />
        ) : (
          <EmptyState
            icon={Boxes}
            title="No workspaces yet"
            description="You don't have access to any workspace in this organization."
          />
        )
      ) : null}
      {list.data && list.data.items.length > 0 ? (
        <>
          <div className="overflow-x-auto rounded-md border border-border bg-card">
            <table className="w-full text-left text-[13px] leading-5">
              <caption className="sr-only">Workspaces</caption>
              <thead className="border-b border-border text-muted-foreground">
                <tr>
                  <SortHeader
                    label="Name"
                    field="name"
                    sort={sort}
                    onSort={(s) => update({ sort: s === "name:asc" ? "" : s, page: "" })}
                  />
                  <th scope="col" className="px-3 py-2 font-medium">
                    Business unit
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Owner
                  </th>
                  <th scope="col" className="px-3 py-2 text-right font-medium">
                    Members
                  </th>
                  <SortHeader
                    label="Status"
                    field="status"
                    sort={sort}
                    onSort={(s) => update({ sort: s, page: "" })}
                  />
                  <SortHeader
                    label="Created"
                    field="createdAt"
                    sort={sort}
                    onSort={(s) => update({ sort: s, page: "" })}
                  />
                  <th scope="col" className="w-12 px-3 py-2">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((ws) => (
                  <tr
                    key={ws.id}
                    className="h-9 border-b border-border last:border-0 hover:bg-secondary"
                  >
                    <td className="px-3 py-1.5">
                      <Link
                        className="font-medium text-primary-text underline-offset-4 hover:underline"
                        to={`/workspaces/${ws.id}/dashboard`}
                      >
                        {ws.name}
                      </Link>
                      {ws.description ? (
                        <p className="max-w-md truncate text-xs text-muted-foreground">
                          {ws.description}
                        </p>
                      ) : null}
                    </td>
                    <td className="px-3 text-muted-foreground">{ws.businessUnit ?? "—"}</td>
                    <td className="px-3 text-muted-foreground">{ws.ownerName ?? "—"}</td>
                    <td className="px-3 text-right tabular-nums">{ws.memberCount}</td>
                    <td className="px-3">
                      <StatusChip status={ws.status} />
                    </td>
                    <td className="px-3 text-muted-foreground">{date(ws.createdAt)}</td>
                    <td className="px-3">
                      <RowActions workspace={ws} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            pagination={list.data.pagination}
            onPage={(p) => update({ page: p > 1 ? String(p) : "" })}
          />
        </>
      ) : null}
    </>
  );
}
