import { DataTable } from "@qmentisai/ui";
import { useEffect, useRef, useState } from "react";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { sortingFromParam, sortParamFromUpdater } from "@/lib/table-sort.js";
import { Pager } from "./pager.jsx";

/**
 * Tenant list table: `DataTable` (sticky column header, internal scroll) fed by a TanStack Query result. Loading, error
 * (403 -> unauthorized, 404 -> not found, else retry) and empty states use the table slots. Page-number paging stays in
 * the footer slot (`pagination` + `onPage`); alternatively "Load more" (`hasMore`, `loadingMore`, `onLoadMore`: cursor
 * lists append rows, show no totals, move focus to the first new row and announce "More rows loaded"); sorting uses the URL sort value (`sort` + `onSort`). Without `height`
 * it fills its flex parent (`AppPageLayout scroll={false}`).
 * @param {{ query: { data?: any, isPending: boolean, isError: boolean, error: unknown, refetch: () => void },
 *   items?: any[], columns: Array<object>, caption: string, getRowId?: (row: any) => string, emptyState?: import("react").ReactNode,
 *   hasMore?: boolean, loadingMore?: boolean, onLoadMore?: () => void,
 *   sort?: string, onSort?: (next: string) => void, pagination?: object | null, onPage?: (page: number) => void,
 *   onRowClick?: (row: any) => void, rowLabel?: (row: any) => string, height?: "auto" | "fill", maxHeight?: string }} props
 */
export function QueryTable({
  query,
  items,
  columns,
  caption,
  getRowId,
  emptyState,
  sort,
  onSort,
  pagination,
  onPage,
  onRowClick,
  rowLabel,
  hasMore = false,
  loadingMore = false,
  onLoadMore,
  height = "fill",
  maxHeight,
}) {
  const rows = items ?? query.data?.items ?? [];
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
  const pager =
    pagination && pagination.totalPages > 1 && onPage ? (
      <Pager pagination={pagination} onPage={onPage} className="w-full" />
    ) : undefined;
  return (
    <>
      <DataTable
        caption={caption}
        columns={columns}
        data={rows}
        getRowId={getRowId}
        height={height}
        maxHeight={maxHeight}
        loading={query.isPending}
        error={query.isError}
        errorState={<QueryErrorState error={query.error} onRetry={query.refetch} />}
        emptyState={emptyState}
        sorting={onSort ? sorting : undefined}
        onSortingChange={onSort ? (u) => onSort(sortParamFromUpdater(u, sorting)) : undefined}
        onRowClick={onRowClick}
        rowLabel={rowLabel}
        footer={pager}
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
