import { AppPageLayout } from "@qmentisai/ui";
import { Boxes, MoreHorizontal, SearchX } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { QueryTable } from "@/components/common/query-table.jsx";
import { StatusChip } from "@/components/common/status-chip.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
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

const COLUMNS = [
  {
    id: "name",
    header: "Name",
    sortDescFirst: false,
    accessorFn: () => null,
    cell: ({ row: { original: ws } }) => (
      <>
        <Link
          className="font-medium text-primary-text underline-offset-4 hover:underline"
          to={`/workspaces/${ws.id}/dashboard`}
        >
          {ws.name}
        </Link>
        {ws.description ? (
          <p className="max-w-md truncate text-xs text-muted-foreground">{ws.description}</p>
        ) : null}
      </>
    ),
  },
  {
    id: "businessUnit",
    header: "Business unit",
    enableSorting: false,
    meta: { className: "text-muted-foreground" },
    cell: ({ row: { original: ws } }) => ws.businessUnit ?? "—",
  },
  {
    id: "owner",
    header: "Owner",
    enableSorting: false,
    meta: { className: "text-muted-foreground" },
    cell: ({ row: { original: ws } }) => ws.ownerName ?? "—",
  },
  {
    id: "members",
    header: "Members",
    enableSorting: false,
    meta: { className: "text-right tabular-nums" },
    cell: ({ row: { original: ws } }) => ws.memberCount,
  },
  {
    id: "status",
    header: "Status",
    sortDescFirst: false,
    accessorFn: () => null,
    cell: ({ row: { original: ws } }) => <StatusChip status={ws.status} />,
  },
  {
    id: "createdAt",
    header: "Created",
    sortDescFirst: false,
    accessorFn: () => null,
    meta: { className: "text-muted-foreground" },
    cell: ({ row: { original: ws } }) => date(ws.createdAt),
  },
  {
    id: "actions",
    header: () => <span className="sr-only">Actions</span>,
    enableSorting: false,
    meta: { className: "w-12" },
    cell: ({ row: { original: ws } }) => <RowActions workspace={ws} />,
  },
];

/**
 * T-07 Workspaces: the workspaces the caller can see, with search, status filter, sorting and pagination in the URL.
 * Columns follow what exists today (repositories, pipelines and findings columns arrive with their modules).
 */
export function WorkspacesPage() {
  const navigate = useNavigate();
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
    <AppPageLayout
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
      scroll={false}
    >
      <div className="mb-4 flex shrink-0 flex-wrap items-end gap-3">
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
      <QueryTable
        caption="Workspaces"
        query={list}
        columns={COLUMNS}
        getRowId={(ws) => ws.id}
        sort={sort}
        onSort={(s) => update({ sort: s === "name:asc" ? "" : s, page: "" })}
        pagination={list.data?.pagination}
        onPage={(p) => update({ page: p > 1 ? String(p) : "" })}
        onRowClick={(ws) => navigate(`/workspaces/${ws.id}/dashboard`)}
        rowLabel={(ws) => `Open ${ws.name}`}
        emptyState={
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
        }
      />
    </AppPageLayout>
  );
}
