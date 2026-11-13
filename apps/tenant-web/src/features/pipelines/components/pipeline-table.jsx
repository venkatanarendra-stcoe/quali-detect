import { Link, useNavigate } from "react-router";
import { QueryTable } from "@/components/common/query-table.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { PipelineEnabledSwitch, PipelineRowActions } from "./pipeline-actions.jsx";
import { EffectiveStateChip, LastRequest } from "./pipeline-bits.jsx";

const LOADED = Object.freeze({ isPending: false, isError: false, error: null, refetch: () => {} });

/**
 * Pipelines table of T-25 (full) and the T-24 tab (compact: no repository column), on `DataTable`. `sort` / `onSort` are
 * optional: without them the headers are plain text. Pass `query` (a TanStack Query result with `items`) to let the table
 * show loading / error / empty itself, or only `items` when the caller already handled those states. Row actions follow the
 * caller's permissions (hidden or disabled with a reason).
 * @param {{ items?: any[], query?: object, showRepository?: boolean, sort?: string, onSort?: (next: string) => void,
 *   caption: string, emptyState?: import("react").ReactNode, pagination?: object | null, onPage?: (page: number) => void,
 *   height?: "auto" | "fill", maxHeight?: string }} props
 */
export function PipelineTable({
  items,
  query = LOADED,
  showRepository = true,
  sort,
  onSort,
  caption,
  emptyState,
  pagination,
  onPage,
  height = "fill",
  maxHeight,
}) {
  const navigate = useNavigate();
  const rows = items ?? query.data?.items ?? [];
  const sortable = (id) =>
    onSort ? { id, sortDescFirst: false, accessorFn: () => null } : { id, enableSorting: false };
  const columns = [
    {
      ...sortable("name"),
      header: "Name",
      meta: { className: "max-w-64" },
      cell: ({ row: { original: p } }) => (
        <>
          <Link
            className="font-medium underline-offset-2 hover:underline focus-visible:underline"
            to={`/workspaces/${p.workspaceId}/pipelines/${p.id}`}
          >
            {p.name}
          </Link>
          {p.deletedAt ? (
            <Badge tone="neutral" className="ml-2">
              Deleted
            </Badge>
          ) : null}
          {p.description ? (
            <div className="truncate text-xs text-muted-foreground">{p.description}</div>
          ) : null}
        </>
      ),
    },
    ...(showRepository
      ? [
          {
            id: "repository",
            header: "Repository",
            enableSorting: false,
            cell: ({ row: { original: p } }) =>
              p.repository.name ? (
                <span className="font-mono text-xs break-all">{p.repository.name}</span>
              ) : (
                <span className="text-muted-foreground">Not shown</span>
              ),
          },
        ]
      : []),
    {
      ...sortable("lastRequestedAt"),
      header: "Last run",
      cell: ({ row: { original: p } }) => <LastRequest lastRequest={p.lastRequest} />,
    },
    {
      // The switch is the stored `enabled` flag; the chip is the derived effective state (its tooltip gives the reason).
      id: "enabled",
      header: "Enabled",
      enableSorting: false,
      cell: ({ row: { original: p } }) => (
        <span className="inline-flex flex-wrap items-center gap-2">
          <PipelineEnabledSwitch pipeline={p} />
          {p.deletedAt ? null : <EffectiveStateChip state={p.effectiveState} />}
        </span>
      ),
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      enableSorting: false,
      meta: { className: "text-right" },
      cell: ({ row: { original: p } }) => <PipelineRowActions pipeline={p} />,
    },
  ];
  return (
    <QueryTable
      caption={caption}
      query={query}
      items={rows}
      columns={columns}
      getRowId={(p) => p.id}
      sort={sort}
      onSort={onSort}
      pagination={pagination}
      onPage={onPage}
      emptyState={emptyState}
      height={height}
      maxHeight={maxHeight}
      onRowClick={(p) => navigate(`/workspaces/${p.workspaceId}/pipelines/${p.id}`)}
      rowLabel={(p) => `Open ${p.name}`}
    />
  );
}
