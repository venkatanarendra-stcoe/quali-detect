import { DataTable, Pagination } from "@qmentisai/ui";
import { useEffect, useRef } from "react";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { sortingFromParam, sortParamFromUpdater } from "@/lib/table-sort.js";

/**
 * Platform list table: `DataTable` (sticky column header, internal scroll) fed by a TanStack Query result. Loading,
 * error (403 unauthorized, 404 not found, else retry) and empty states use the table slots. Numbered pages (owner decision
 * 2026-11-16, replacing "Load more") render the shared `Pagination` in the footer: `pagination`
 * (`{ page, pageSize, totalItems, totalPages }`), `onPage`, `onPageSize`; the table scrolls back to the top on a page change
 * and "Page N of M" is announced politely. Sorting uses the URL sort value (`sort` + `onSort`). It fills its flex parent
 * (`AppPageLayout scroll={false}`).
 * @param {{ query: { data?: any, isPending: boolean, isError: boolean, error: unknown, refetch: () => void },
 *   columns: Array<object>, caption: string, getRowId?: (row: any) => string, emptyState?: import("react").ReactNode,
 *   pagination?: { page: number, pageSize: number, totalItems: number, totalPages: number } | null,
 *   onPage?: (page: number) => void, onPageSize?: (size: number) => void, noun?: string,
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
  pagination,
  onPage,
  onPageSize,
  noun = "items",
  onRowClick,
  rowLabel,
}) {
  const rows = query.data?.items ?? [];
  const anchor = useRef(null);
  const shown = pagination?.page;
  useEffect(() => {
    if (shown === undefined) return;
    anchor.current?.previousElementSibling
      ?.querySelector("[data-data-table-scroll]")
      ?.scrollTo?.({ top: 0 });
  }, [shown]);
  const sorting = sortingFromParam(sort);
  const pager =
    pagination && onPage && pagination.totalItems > 0 ? (
      <Pagination
        page={pagination.page}
        totalPages={pagination.totalPages}
        totalItems={pagination.totalItems}
        pageSize={pagination.pageSize}
        onPageChange={onPage}
        onPageSizeChange={onPageSize}
        itemNoun={noun}
      />
    ) : undefined;
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
        footer={pager}
      />
      <span ref={anchor} hidden />
    </>
  );
}
