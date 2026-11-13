import { useRef } from "react";
import { flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { ArrowDownIcon, ArrowUpIcon, AlertIcon, LockIcon, LoaderIcon } from "./icons.jsx";
import { useScrollActivity } from "./use-scroll-activity.js";

const join = (...parts) => parts.filter(Boolean).join(" ");
const INTERACTIVE =
  "a[href],button,input,select,textarea,label,[role='button'],[role='checkbox'],[role='switch'],[role='menuitem']";

function StateBox({ icon, title, children }) {
  return (
    <div className="flex flex-col items-center gap-2 px-4 py-12 text-center">
      {icon}
      <p className="text-sm font-medium">{title}</p>
      {children}
    </div>
  );
}

/**
 * Data table on TanStack Table v8 (headless): sticky column header, body scrolling INSIDE the component (never the
 * page) with the thin fading scrollbar of `scroll.css`, and slots for every required state. Pass TanStack `columns`
 * and `data`; sorting is controlled and server-side friendly (`sorting` + `onSortingChange`, `manualSorting`).
 * Rows with `onRowClick` are focusable (`tabIndex=0`) and activate with Enter or Space, except when the key or click
 * comes from an interactive control inside the row (link, button, input).
 *
 * State precedence: `unauthorized` > `error` > `loading` (8 skeleton rows when empty, or rows stay while refetching) >
 * `empty` > rows. Each state renders its slot (`unauthorizedState`, `errorState`, `loadingState`, `emptyState`) or a
 * default. Height: `height="fill"` fills a flex parent (e.g. `AppPageLayout scroll={false}`); otherwise it grows
 * to `maxHeight` (default 32rem) and then scrolls internally.
 * @param {{ columns: Array<object>, data: Array<object>, getRowId?: (row: any, index: number) => string,
 *   caption: string, height?: "auto" | "fill", maxHeight?: string, loading?: boolean, error?: boolean | string,
 *   unauthorized?: boolean, onRetry?: () => void, loadingState?: import("react").ReactNode,
 *   emptyState?: import("react").ReactNode, errorState?: import("react").ReactNode,
 *   unauthorizedState?: import("react").ReactNode, sorting?: Array<{ id: string, desc: boolean }>,
 *   onSortingChange?: (updater: any) => void, manualSorting?: boolean, onRowClick?: (row: any) => void,
 *   rowLabel?: (row: any) => string, hasMore?: boolean, loadingMore?: boolean, onLoadMore?: () => void,
 *   footer?: import("react").ReactNode, className?: string }} props
 *   `caption` is the accessible name (screen-reader caption). `footer` replaces the default "Load more" footer, which
 *   shows when `hasMore` and `onLoadMore` are given. Column `meta.className` styles a column's cells.
 */
export function DataTable({
  columns,
  data,
  getRowId,
  caption,
  height = "auto",
  maxHeight = "32rem",
  loading = false,
  error = false,
  unauthorized = false,
  onRetry,
  loadingState,
  emptyState,
  errorState,
  unauthorizedState,
  sorting,
  onSortingChange,
  manualSorting = true,
  onRowClick,
  rowLabel,
  hasMore = false,
  loadingMore = false,
  onLoadMore,
  footer,
  className,
}) {
  const scrollRef = useRef(null);
  useScrollActivity(scrollRef);
  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Table is headless; the table instance is not memoized or passed on
  const table = useReactTable({
    columns,
    data,
    getRowId,
    getCoreRowModel: getCoreRowModel(),
    state: sorting ? { sorting } : undefined,
    onSortingChange,
    manualSorting,
    enableSorting: Boolean(onSortingChange),
  });
  const rows = table.getRowModel().rows;
  const colCount = table.getVisibleLeafColumns().length;
  const showSkeleton = loading && rows.length === 0;
  const body = unauthorized
    ? "unauthorized"
    : error
      ? "error"
      : showSkeleton
        ? "loading"
        : rows.length === 0
          ? "empty"
          : "rows";

  const activate = (row) => onRowClick?.(row.original, row);
  const slot =
    body === "unauthorized"
      ? (unauthorizedState ?? (
          <StateBox icon={<LockIcon className="size-6 text-muted-foreground" />} title="No access">
            <p className="text-sm text-muted-foreground">
              You do not have permission to view this. Ask a workspace admin for access.
            </p>
          </StateBox>
        ))
      : body === "error"
        ? (errorState ?? (
            <StateBox
              icon={<AlertIcon className="size-6 text-status-danger" />}
              title="Could not load this table"
            >
              <p role="alert" className="text-sm text-muted-foreground">
                {typeof error === "string" ? error : "Something went wrong. Try again."}
              </p>
              {onRetry ? (
                <button
                  type="button"
                  onClick={onRetry}
                  className="mt-1 h-8 rounded-sm border border-border-strong bg-secondary px-3 text-sm font-medium outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
                >
                  Retry
                </button>
              ) : null}
            </StateBox>
          ))
        : body === "empty"
          ? (emptyState ?? (
              <StateBox icon={null} title="Nothing here yet">
                <p className="text-sm text-muted-foreground">No rows to show.</p>
              </StateBox>
            ))
          : null;

  const footerNode =
    footer ??
    (hasMore && onLoadMore ? (
      <button
        type="button"
        onClick={onLoadMore}
        disabled={loadingMore}
        className="inline-flex h-8 items-center gap-2 rounded-sm border border-border-strong bg-secondary px-3 text-sm font-medium outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60"
      >
        {loadingMore ? <LoaderIcon className="size-4 animate-spin" /> : null}
        {loadingMore ? "Loading…" : "Load more"}
      </button>
    ) : null);

  return (
    <div
      data-data-table=""
      className={join(
        "flex min-h-0 flex-col overflow-hidden rounded-md border border-border bg-card",
        height === "fill" && "h-full flex-1",
        className,
      )}
      style={height === "fill" ? undefined : { maxHeight }}
    >
      <div
        ref={scrollRef}
        data-data-table-scroll=""
        className="qm-scroll min-h-0 flex-1 overflow-auto"
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        tabIndex={0}
        role="region"
        aria-label={`${caption} (scrollable)`}
      >
        <table
          className="w-full border-separate border-spacing-0 text-sm"
          aria-busy={loading || undefined}
        >
          <caption className="sr-only">{caption}</caption>
          <thead>
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id}>
                {group.headers.map((header) => {
                  const sortable = header.column.getCanSort();
                  const dir = header.column.getIsSorted();
                  const label = header.isPlaceholder
                    ? null
                    : flexRender(header.column.columnDef.header, header.getContext());
                  return (
                    <th
                      key={header.id}
                      scope="col"
                      aria-sort={
                        dir === "asc" ? "ascending" : dir === "desc" ? "descending" : undefined
                      }
                      className={join(
                        "sticky top-0 z-10 border-b border-border bg-card px-3 py-2 text-left text-xs font-medium whitespace-nowrap text-muted-foreground",
                        header.column.columnDef.meta?.className,
                      )}
                    >
                      {sortable && label ? (
                        <button
                          type="button"
                          onClick={header.column.getToggleSortingHandler()}
                          className="-mx-1 inline-flex items-center gap-1 rounded-sm px-1 outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
                        >
                          {label}
                          {dir === "asc" ? (
                            <ArrowUpIcon className="size-3.5" />
                          ) : dir === "desc" ? (
                            <ArrowDownIcon className="size-3.5" />
                          ) : null}
                        </button>
                      ) : (
                        label
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {body === "loading"
              ? (loadingState ??
                Array.from({ length: 8 }, (_, i) => (
                  <tr key={i} aria-hidden="true">
                    {Array.from({ length: colCount }, (_c, j) => (
                      <td key={j} className="border-b border-border px-3 py-2.5">
                        <div className="h-4 w-3/4 animate-pulse rounded-sm bg-muted" />
                      </td>
                    ))}
                  </tr>
                )))
              : null}
            {slot ? (
              <tr>
                <td colSpan={colCount}>{slot}</td>
              </tr>
            ) : null}
            {body === "rows"
              ? rows.map((row) => (
                  <tr
                    key={row.id}
                    tabIndex={onRowClick ? 0 : undefined}
                    aria-label={onRowClick && rowLabel ? rowLabel(row.original) : undefined}
                    onClick={
                      onRowClick
                        ? (e) => {
                            // portaled children (dialogs, menus) bubble through the React tree: only clicks inside the row count
                            if (
                              e.currentTarget.contains(e.target) &&
                              !e.target.closest(INTERACTIVE)
                            )
                              activate(row);
                          }
                        : undefined
                    }
                    onKeyDown={
                      onRowClick
                        ? (e) => {
                            if (e.target !== e.currentTarget) return;
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              activate(row);
                            }
                          }
                        : undefined
                    }
                    className={join(
                      "group/row outline-none",
                      onRowClick &&
                        "cursor-pointer hover:bg-accent focus-visible:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset",
                    )}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td
                        key={cell.id}
                        className={join(
                          "border-b border-border px-3 py-2.5 align-middle",
                          cell.column.columnDef.meta?.className,
                        )}
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              : null}
          </tbody>
        </table>
      </div>
      {footerNode && body === "rows" ? (
        <div
          data-data-table-footer=""
          className="flex shrink-0 items-center justify-center border-t border-border bg-card px-3 py-2"
        >
          {footerNode}
        </div>
      ) : null}
    </div>
  );
}
