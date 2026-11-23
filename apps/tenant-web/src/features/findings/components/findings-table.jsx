import { Link, useLocation, useNavigate } from "react-router";
import { toast } from "sonner";
import { QueryTable } from "@/components/common/query-table.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { Pagination } from "@qmentisai/ui";
import { BULK_MAX } from "../constants/index.js";
import { useFindingsUiStore } from "../stores/findings-ui-store.js";
import {
  AdvisoryHint,
  Identifier,
  LocationCell,
  Person,
  RecurrenceIcon,
  SeverityBadge,
  SlaChip,
  StatusBadge,
  TimeAgo,
  Untrusted,
} from "./finding-bits.jsx";

const P2 = "hidden min-[1536px]:table-cell";
const P3 = "hidden min-[1680px]:table-cell";
const sortable = (id) => ({ id, sortDescFirst: false, accessorFn: () => null });

/** The status cell: "In review by Ana" when claimed, the pending decision, the expiry of an accepted risk. @param {{ item: any }} props */
export function StatusCell({ item }) {
  const pending = item.pendingDecision;
  const detail =
    item.status === "awaiting_approval" && pending
      ? pending.decision === "false_positive"
        ? "pending FP decision"
        : "pending TP decision"
      : item.status !== "awaiting_approval" && pending?.kind === "exception"
        ? pending.exceptionKind === "suppress"
          ? "suppression requested"
          : "accepted risk requested"
        : undefined;
  return (
    <StatusBadge
      status={item.status}
      by={item.status === "in_review" ? item.claimedBy?.displayName : null}
      detail={detail}
    />
  );
}

/** Title (escaped text, two lines at most) as a real link, the rule id in mono below. */
function TitleCell({ item, workspaceId }) {
  const location = useLocation();
  return (
    <div className="min-w-48 max-w-96">
      <Link
        to={`/workspaces/${workspaceId}/findings/${item.id}`}
        state={{ list: location.search }}
        className="line-clamp-2 font-medium underline-offset-2 outline-none hover:underline focus-visible:underline focus-visible:ring-2 focus-visible:ring-ring"
        onClick={(e) => e.stopPropagation()}
      >
        <Untrusted>{item.title}</Untrusted>
      </Link>
      <div className="mt-0.5">
        <Identifier value={item.ruleId} max={22} label="rule id" />
      </div>
    </div>
  );
}

function PipelineCell({ item }) {
  return (
    <div className="max-w-56">
      <div className="truncate">{item.pipeline.name}</div>
      {item.pipeline.deleted ? (
        <span className="inline-flex items-center rounded-sm border border-border-strong px-1.5 py-0.5 text-xs text-muted-foreground">
          Pipeline deleted
        </span>
      ) : null}
    </div>
  );
}

/**
 * Columns of the list (SCREENS 4). `selectable` adds the checkbox column (selection lives in `useFindingsUiStore`, capped at 50).
 * @param {{ workspaceId: string, selectable: boolean, pageItems: any[] }} input
 */
export function findingColumns({ workspaceId, selectable, pageItems }) {
  const columns = [];
  if (selectable)
    columns.push({
      id: "select",
      enableSorting: false,
      meta: { className: "w-9" },
      header: () => <SelectAll items={pageItems} />,
      cell: ({ row: { original: item } }) => <RowCheck item={item} />,
    });
  columns.push(
    {
      ...sortable("severity"),
      header: "Severity",
      cell: ({ row: { original: i } }) => <SeverityBadge severity={i.severity} />,
    },
    {
      ...sortable("title"),
      header: "Title",
      cell: ({ row: { original: i } }) => <TitleCell item={i} workspaceId={workspaceId} />,
    },
    {
      id: "location",
      header: "Location",
      enableSorting: false,
      meta: { className: "max-w-60" },
      cell: ({ row: { original: i } }) => <LocationCell item={i} />,
    },
    {
      id: "pipeline",
      header: "Pipeline",
      enableSorting: false,
      meta: { className: P2 },
      cell: ({ row: { original: i } }) => <PipelineCell item={i} />,
    },
    {
      id: "status",
      header: "Status",
      enableSorting: false,
      cell: ({ row: { original: i } }) => <StatusCell item={i} />,
    },
    {
      ...sortable("slaDueAt"),
      header: "SLA",
      cell: ({ row: { original: i } }) => <SlaChip sla={i.sla} />,
    },
    {
      id: "assignee",
      header: "Assignee",
      enableSorting: false,
      meta: { className: P2 },
      cell: ({ row: { original: i } }) => <Person user={i.assignee} />,
    },
    {
      id: "ai",
      header: "AI",
      enableSorting: false,
      meta: { className: P3 },
      cell: ({ row: { original: i } }) => <AdvisoryHint hint={i.advisoryHint} />,
    },
    {
      ...sortable("firstDetectedAt"),
      header: "First seen",
      meta: { className: P3 },
      cell: ({ row: { original: i } }) => <TimeAgo value={i.firstDetectedAt} />,
    },
    {
      id: "recurrence",
      header: () => <span className="sr-only">Recurrence</span>,
      enableSorting: false,
      cell: ({ row: { original: i } }) => <RecurrenceIcon count={i.reopenCount} />,
    },
  );
  return columns;
}

function RowCheck({ item }) {
  const checked = useFindingsUiStore((s) => item.id in s.selected);
  const toggle = useFindingsUiStore((s) => s.toggle);
  return (
    <input
      type="checkbox"
      className="size-4 accent-[var(--foreground)]"
      aria-label={`Select ${item.title}`}
      checked={checked}
      onClick={(e) => e.stopPropagation()}
      onChange={() => {
        if (!toggle(item.id, { status: item.status, title: item.title }))
          toast.error(`You can select at most ${BULK_MAX} findings at a time.`);
      }}
    />
  );
}

function SelectAll({ items }) {
  const selected = useFindingsUiStore((s) => s.selected);
  const toggle = useFindingsUiStore((s) => s.toggle);
  const clear = useFindingsUiStore((s) => s.clear);
  const all = items.length > 0 && items.every((i) => i.id in selected);
  return (
    <input
      type="checkbox"
      className="size-4 accent-[var(--foreground)]"
      aria-label="Select all findings on this page"
      checked={all}
      onChange={() => {
        if (all) clear();
        else
          for (const i of items)
            if (!(i.id in selected)) toggle(i.id, { status: i.status, title: i.title });
      }}
    />
  );
}

/**
 * The T-31 table (above 768 px) or a card list (below). `query` is the page list from `useFindingList`. Row click, and Enter on
 * a focused row, open T-32; the title is also a real link (middle-click works).
 * @param {{ workspaceId: string, query: any, sort: string, onSort: (next: string) => void, pagination: object, onPage: (page: number) => void,
 *   onPageSize: (size: number) => void, emptyState: any, selectable: boolean, narrow: boolean, caption?: string }} props
 */
export function FindingsTable({
  workspaceId,
  query,
  sort,
  onSort,
  pagination,
  onPage,
  onPageSize,
  emptyState,
  selectable,
  narrow,
  caption = "Findings",
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const items = query.data?.items ?? [];
  const open = (item) =>
    navigate(`/workspaces/${workspaceId}/findings/${item.id}`, {
      state: { list: location.search },
    });
  if (narrow)
    return (
      <FindingCards
        workspaceId={workspaceId}
        query={query}
        pagination={pagination}
        onPage={onPage}
        onPageSize={onPageSize}
        emptyState={emptyState}
        selectable={selectable}
      />
    );
  return (
    <QueryTable
      caption={caption}
      query={query}
      columns={findingColumns({ workspaceId, selectable, pageItems: items })}
      getRowId={(i) => i.id}
      sort={sort}
      onSort={onSort}
      pagination={pagination}
      onPage={onPage}
      onPageSize={onPageSize}
      emptyState={emptyState}
      onRowClick={open}
      rowLabel={(i) => `${i.title}, ${i.severity}`}
      noun="findings"
    />
  );
}

/** Card list for phones: severity, title, status and SLA, the same row link and selection. */
export function FindingCards({
  workspaceId,
  query,
  pagination,
  onPage,
  onPageSize,
  emptyState,
  selectable,
}) {
  const location = useLocation();
  const items = query.data?.items ?? [];
  return (
    <div
      className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto"
      aria-busy={query.isPending || undefined}
    >
      {query.isPending ? (
        <div role="status" className="space-y-3">
          <span className="sr-only">Loading findings…</span>
          {Array.from({ length: 5 }, (_, i) => (
            <Skeleton key={i} className="h-24 w-full" />
          ))}
        </div>
      ) : query.isError ? (
        <QueryErrorState error={query.error} onRetry={query.refetch} />
      ) : items.length === 0 ? (
        emptyState
      ) : (
        <ul className="space-y-2" aria-label="Findings">
          {items.map((item) => (
            <li key={item.id} className="rounded-md border border-border bg-card p-3">
              <div className="flex items-start gap-2">
                {selectable ? <RowCheck item={item} /> : null}
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={item.severity} />
                    <SlaChip sla={item.sla} />
                    <RecurrenceIcon count={item.reopenCount} />
                  </div>
                  <Link
                    to={`/workspaces/${workspaceId}/findings/${item.id}`}
                    state={{ list: location.search }}
                    className="line-clamp-2 block text-sm font-medium underline-offset-2 hover:underline"
                  >
                    <Untrusted>{item.title}</Untrusted>
                  </Link>
                  <StatusCell item={item} />
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
      {pagination && onPage && pagination.totalItems > 0 ? (
        <Pagination
          page={pagination.page}
          totalPages={pagination.totalPages}
          totalItems={pagination.totalItems}
          pageSize={pagination.pageSize}
          onPageChange={onPage}
          onPageSizeChange={onPageSize}
          itemNoun="findings"
        />
      ) : null}
    </div>
  );
}
