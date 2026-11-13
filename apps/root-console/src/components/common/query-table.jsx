import { DataTable } from "@qmentisai/ui";
import { useEffect, useRef, useState } from "react";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { sortingFromParam, sortParamFromUpdater } from "@/lib/table-sort.js";

/**
 * Platform list table: `DataTable` (sticky column header, internal scroll) fed by a TanStack Query result. Loading,
 * error (403 unauthorized, 404 not found, else retry) and empty states use the table slots. Cursor lists use "Load more"
 * (`hasMore`, `loadingMore`, `onLoadMore`): rows append, no totals are shown, focus moves to the first new row and
 * "More rows loaded" is announced politely. Sorting uses the URL sort value (`sort` + `onSort`). It fills its flex
 * parent (`AppPageLayout scroll={false}`).
 * @param {{ query: { data?: any, isPending: boolean, isError: boolean, error: unknown, refetch: () => void },
 *   columns: Array<object>, caption: string, getRowId?: (row: any) => string, emptyState?: import("react").ReactNode,
 *   hasMore?: boolean, loadingMore?: boolean, onLoadMore?: () => void,
 *   sort?: string, onSort?: (next: string) => void,
 *   onRowClick?: (row: any) => void, rowLabel?: (row: any) => string }} props
 */
export function QueryTable({
  query,
  columns,
  caption,
  getRowId,
  emptyState,
  sort,
  onSort,
  onRowClick,
  rowLabel,
  hasMore = false,
  loadingMore = false,
  onLoadMore,
}) {
  const rows = query.data?.items ?? [];
  const liveRef = useRef(null);
  const awaiting = useRef(null); // row count when "Load more" was pressed
  const [announcement, setAnnouncement] = useState("");
  const loadMore = onLoadMore
    ? () => {
        awaiting.current = rows.length;
        onLoadMore();
      }
    : undefined;
  useEffect(() => {
    const before = awaiting.current;
    if (before === null || rows.length <= before) return;
    awaiting.current = null;
    const row = liveRef.current?.previousElementSibling?.querySelectorAll("tbody tr")[before];
    if (row) {
      if (!row.hasAttribute("tabindex")) row.setAttribute("tabindex", "-1");
      row.focus();
    }
    setAnnouncement("More rows loaded");
  }, [rows.length]);
  useEffect(() => {
    if (!announcement) return undefined;
    const timer = setTimeout(() => setAnnouncement(""), 3000);
    return () => clearTimeout(timer);
  }, [announcement]);
  const sorting = sortingFromParam(sort);
  return (
    <>
      <DataTable
        caption={caption}
        columns={columns}
        data={rows}
        getRowId={getRowId}
        height="fill"
        loading={query.isPending}
        error={query.isError}
        errorState={<QueryErrorState error={query.error} onRetry={query.refetch} />}
        emptyState={emptyState}
        sorting={onSort ? sorting : undefined}
        onSortingChange={onSort ? (u) => onSort(sortParamFromUpdater(u, sorting)) : undefined}
        onRowClick={onRowClick}
        rowLabel={rowLabel}
        hasMore={hasMore}
        loadingMore={loadingMore}
        onLoadMore={loadMore}
      />
      <div ref={liveRef} className="sr-only" role="status" aria-live="polite">
        {announcement}
      </div>
    </>
  );
}
