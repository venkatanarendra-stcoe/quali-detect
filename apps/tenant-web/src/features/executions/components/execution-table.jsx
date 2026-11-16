import { Link, useNavigate } from "react-router";
import { QueryTable } from "@/components/common/query-table.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { isActiveStatus } from "../constants/index.js";
import { useNow } from "../hooks/use-now.js";
import { ExecutionRowActions } from "./execution-actions.jsx";
import {
  ExecutionId,
  CommitSha,
  StatusCell,
  TimeAgo,
  TriggerCell,
  formatDuration,
} from "./execution-bits.jsx";
import { TaskSegments } from "./task-bits.jsx";

const P2 = "hidden min-[1280px]:table-cell";
const P3 = "hidden min-[1440px]:table-cell";

/** Duration of a row: ticks client side while the execution runs (from `startedAt`), static after, em dash when not started. */
export function Duration({ execution: e }) {
  const running = e.status === "running" && !e.finishedAt;
  const now = useNow(running);
  if (!e.startedAt) return <span className="text-muted-foreground">—</span>;
  const ms = e.finishedAt ? e.durationMs : Math.max(0, now - new Date(e.startedAt).getTime());
  return <span className="whitespace-nowrap tabular-nums">{formatDuration(ms)}</span>;
}

function Started({ execution: e }) {
  if (!e.startedAt && isActiveStatus(e.status))
    return (
      <span className="inline-flex gap-1 whitespace-nowrap">
        <span className="text-muted-foreground">Requested</span>
        <TimeAgo value={e.requestedAt} />
      </span>
    );
  return <TimeAgo value={e.startedAt ?? e.requestedAt} />;
}

function PipelineCell({ execution: e }) {
  const can = useCan();
  const name = e.pipeline?.name;
  if (!name) return <span className="text-muted-foreground">Not shown</span>;
  return (
    <>
      {can("pipeline.view", { type: "workspace", workspaceId: e.workspaceId }) ? (
        <Link
          className="font-medium underline-offset-2 hover:underline focus-visible:underline"
          to={`/workspaces/${e.workspaceId}/pipelines/${e.pipeline.id}`}
        >
          {name}
        </Link>
      ) : (
        <span className="font-medium">{name}</span>
      )}
      {e.repository?.fullName ? (
        <div className="font-mono text-xs break-all text-muted-foreground">
          {e.repository.fullName}
        </div>
      ) : null}
    </>
  );
}

/** Full-scan or incremental, with the short commit under it (the merged cell of the pipeline tab). */
function ScanCell({ execution: e }) {
  return (
    <>
      {e.scanKind === "full" ? "Full" : "Incremental"}
      {e.commitSha ? (
        <div>
          <CommitSha sha={e.commitSha} />
        </div>
      ) : null}
    </>
  );
}

const sortable = (id) => ({ id, sortDescFirst: false, accessorFn: () => null });

/** Columns of the executions table. `compact` is the pipeline tab: no Pipeline column; scan kind and commit share a cell. */
export function executionColumns({ compact = false, sortable: canSort = true } = {}) {
  const requested = canSort
    ? { ...sortable("requestedAt"), header: "Started" }
    : { id: "requestedAt", header: "Started", enableSorting: false };
  return [
    {
      id: "id",
      header: "Execution",
      enableSorting: false,
      cell: ({ row: { original: e } }) => <ExecutionId id={e.id} />,
    },
    ...(compact
      ? []
      : [
          {
            id: "pipeline",
            header: "Pipeline",
            enableSorting: false,
            meta: { className: "min-w-48 max-w-72" },
            cell: ({ row: { original: e } }) => <PipelineCell execution={e} />,
          },
        ]),
    {
      id: "status",
      header: "Status",
      enableSorting: false,
      cell: ({ row: { original: e } }) => <StatusCell execution={e} />,
    },
    {
      id: "trigger",
      header: "Trigger",
      enableSorting: false,
      meta: { className: P2 },
      cell: ({ row: { original: e } }) => <TriggerCell execution={e} />,
    },
    ...(compact
      ? [
          {
            id: "scan",
            header: "Scan",
            enableSorting: false,
            meta: { className: P2 },
            cell: ({ row: { original: e } }) => <ScanCell execution={e} />,
          },
        ]
      : []),
    {
      id: "tasks",
      header: "Tasks",
      enableSorting: false,
      meta: { className: P2 },
      cell: ({ row: { original: e } }) => <TaskSegments execution={e} />,
    },
    {
      ...requested,
      cell: ({ row: { original: e } }) => <Started execution={e} />,
    },
    {
      id: "duration",
      header: "Duration",
      enableSorting: false,
      meta: { className: P2 },
      cell: ({ row: { original: e } }) => <Duration execution={e} />,
    },
    ...(compact
      ? []
      : [
          {
            id: "commit",
            header: "Commit",
            enableSorting: false,
            meta: { className: P3 },
            cell: ({ row: { original: e } }) => <CommitSha sha={e.commitSha} />,
          },
        ]),
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      enableSorting: false,
      meta: { className: "text-right" },
      cell: ({ row: { original: e } }) => <ExecutionRowActions execution={e} />,
    },
  ];
}

/**
 * Executions table shared by T-28 and the pipeline tab: cursor "Load more" (no totals), sortable by requested time only,
 * row click / Enter opens T-29, row menu by state and permission.
 * @param {{ query: object, compact?: boolean, sort?: string, onSort?: (next: string) => void, emptyState: any,
 *   caption: string, height?: "auto" | "fill", maxHeight?: string, hasMore: boolean, loadingMore: boolean, onLoadMore: () => void }} props
 */
export function ExecutionTable({ query, compact = false, sort, onSort, ...rest }) {
  const navigate = useNavigate();
  return (
    <QueryTable
      query={query}
      columns={executionColumns({ compact, sortable: Boolean(onSort) })}
      getRowId={(e) => e.id}
      sort={sort}
      onSort={onSort}
      noun="executions"
      onRowClick={(e) => navigate(`/workspaces/${e.workspaceId}/executions/${e.id}`)}
      rowLabel={(e) => `Open execution ${e.id.slice(0, 8)}`}
      {...rest}
    />
  );
}
