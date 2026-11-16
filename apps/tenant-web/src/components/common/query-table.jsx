import { DataTable, Pagination } from "@qmentisai/ui";
import { useEffect, useRef, useState } from "react";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { sortingFromParam, sortParamFromUpdater } from "@/lib/table-sort.js";

/**
 * Tenant list table: `DataTable` (sticky column header, internal scroll) fed by a TanStack Query result. Loading, error
 * (403 -> unauthorized, 404 -> not found, else retry) and empty states use the table slots. Numbered pages (owner decision
 * 2026-11-16, replacing "Load more" on every list) render the shared `Pagination` in the footer slot: `pagination`
 * (`{ page, pageSize, totalItems, totalPages }`), `onPage` and, for a page-size select, `onPageSize`; the table scrolls
 * back to the top and announces "Page N of M" on a page change. "Load more" (`hasMore`, `loadingMore`, `onLoadMore`) remains
 * only for the execution events history (a cursor-only endpoint). Sorting uses the URL sort value (`sort` + `onSort`).
 * Without `height` it fills its flex parent (`AppPageLayout scroll={false}`).
 * @param {{ query: { data?: any, isPending: boolean, isError: boolean, error: unknown, refetch: () => void },
 *   items?: any[], columns: Array<object>, caption: string, getRowId?: (row: any) => string, emptyState?: import("react").ReactNode,
 *   hasMore?: boolean, loadingMore?: boolean, onLoadMore?: () => void,
 *   sort?: string, onSort?: (next: string) => void, pagination?: object | null, onPage?: (page: number) => void, onPageSize?: (size: number) => void, pageNote?: import("react").ReactNode,
 *   onRowClick?: (row: any) => void, rowLabel?: (row: any) => string, height?: "auto" | "fill", maxHeight?: string, noun?: string }} props
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
  onPageSize,
  pageNote,
  onRowClick,
  rowLabel,
  hasMore = false,
  loadingMore = false,
  onLoadMore,
  height = "fill",
  maxHeight,
  noun = "rows",
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
    setAnnouncement(`${rows.length - before} more ${noun} loaded`);
  }, [rows.length, noun]);
  useEffect(() => {
    if (!announcement) return undefined;
    const timer = setTimeout(() => setAnnouncement(""), 3000);
    return () => clearTimeout(timer);
  }, [announcement]);
  const sorting = sortingFromParam(sort);
  const shown = pagination?.page;
  useEffect(() => {
    if (shown === undefined) return;
    liveRef.current?.previousElementSibling
      ?.querySelector("[data-data-table-scroll]")
      ?.scrollTo?.({ top: 0 });
  }, [shown]);
  const pager =
    pagination && onPage && (onPageSize ? pagination.totalItems > 0 : pagination.totalPages > 1) ? (
      <Pagination
        page={pagination.page}
        totalPages={pagination.totalPages}
        totalItems={pagination.totalItems}
        pageSize={pagination.pageSize ?? rows.length}
        onPageChange={onPage}
        onPageSizeChange={onPageSize}
        itemNoun={noun}
        note={pageNote}
      />
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
