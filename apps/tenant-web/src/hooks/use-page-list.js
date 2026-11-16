import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo } from "react";
import { useSearchParams } from "react-router";

/** Page sizes offered by every numbered list (the executions API accepts exactly these). */
export const PAGE_SIZES = Object.freeze([25, 50, 100]);
export const DEFAULT_PAGE_SIZE = 25;

const positiveInt = (value) => {
  const n = Number(value);
  return value !== null && value !== "" && Number.isInteger(n) && n >= 1 ? n : null;
};

/**
 * URL state of a numbered list: `page` and `limit` are query parameters next to the filters, so a reload or a shared link
 * lands on the same page. A missing, malformed or unsupported value falls back (page 1, the default size). `update` merges
 * values into the URL (an empty value removes the parameter) and ALWAYS resets `page` unless `page` is in `next`: any
 * filter, sort or page-size change returns to page 1. `setPage` pushes history (Back returns to the previous page);
 * filter changes replace it.
 * @param {{ defaultPageSize?: number, pageSizes?: readonly number[] }} [options]
 * @returns {{ searchParams: URLSearchParams, page: number, pageSize: number, pageSizes: readonly number[],
 *   update: (next: Record<string, string | string[] | number | null | undefined>, options?: { replace?: boolean }) => void,
 *   setPage: (page: number, options?: { replace?: boolean }) => void, setPageSize: (size: number) => void,
 *   reset: () => void }} `reset` clears every parameter (filters, sort, page, size)
 */
export function useListParams({
  defaultPageSize = DEFAULT_PAGE_SIZE,
  pageSizes = PAGE_SIZES,
} = {}) {
  const [searchParams, setSearchParams] = useSearchParams();
  const page = positiveInt(searchParams.get("page")) ?? 1;
  const asked = positiveInt(searchParams.get("limit"));
  const pageSize = asked !== null && pageSizes.includes(asked) ? asked : defaultPageSize;

  const update = useCallback(
    (next, { replace = true } = {}) =>
      setSearchParams(
        (current) => {
          const merged = new URLSearchParams(current);
          for (const [name, value] of Object.entries(next)) {
            const text = Array.isArray(value)
              ? value.join(",")
              : value === null || value === undefined
                ? ""
                : String(value);
            if (text) merged.set(name, text);
            else merged.delete(name);
          }
          if (!("page" in next)) merged.delete("page");
          return merged;
        },
        { replace },
      ),
    [setSearchParams],
  );
  const setPage = useCallback(
    (n, options) => update({ page: n > 1 ? n : "" }, options ?? { replace: false }),
    [update],
  );
  const setPageSize = useCallback(
    (size) => update({ limit: size === defaultPageSize ? "" : size }),
    [update, defaultPageSize],
  );
  const reset = useCallback(() => setSearchParams({}, { replace: true }), [setSearchParams]);
  return { searchParams, page, pageSize, pageSizes, update, setPage, setPageSize, reset };
}

/**
 * A numbered ("page 3 of 12") list on `useQuery` over an endpoint that takes `page` and a page size and returns
 * `meta.pagination.totalItems`. `queryKey` MUST contain every filter and the sort. The previous page stays on screen while
 * the next one loads, but only when just the page or size changed (a filter change shows the loading state). A page past
 * the end (a stale link, rows deleted meanwhile) is clamped: to the last page, or to page 1 when the list is empty.
 * `maxPage(pageSize)` caps the reachable pages when the API has a window ceiling (executions: 10 000 rows).
 * @param {{ queryKey: unknown[], fetchPage: (input: { page: number, pageSize: number }, signal: AbortSignal) => Promise<{ items: any[], pagination: any }>,
 *   page: number, pageSize: number, setPage: (page: number, options?: { replace?: boolean }) => void,
 *   maxPage?: (pageSize: number) => number, enabled?: boolean, refetchInterval?: number | false | ((query: any) => number | false) }} options
 * @returns {{ data: { items: any[] } | undefined, isPending: boolean, isError: boolean, error: unknown, refetch: () => void,
 *   isPlaceholderData: boolean, queryKey: unknown[], pagination: { page: number, pageSize: number, totalItems: number, totalPages: number } }}
 *   a query-like object `QueryTable` understands
 */
export function usePageList({
  queryKey,
  fetchPage,
  page,
  pageSize,
  setPage,
  maxPage,
  enabled = true,
  refetchInterval = false,
}) {
  const cap = maxPage ? Math.max(1, maxPage(pageSize)) : Number.POSITIVE_INFINITY;
  const current = Math.min(page, cap);
  const baseKey = JSON.stringify(queryKey);
  const fullKey = useMemo(
    () => [...queryKey, { page: current, pageSize }],
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `baseKey` is the structural hash of `queryKey`
    [baseKey, current, pageSize],
  );
  const query = useQuery({
    queryKey: fullKey,
    queryFn: ({ signal }) => fetchPage({ page: current, pageSize }, signal),
    placeholderData: (previous, previousQuery) =>
      previousQuery && JSON.stringify(previousQuery.queryKey.slice(0, -1)) === baseKey
        ? previous
        : undefined,
    enabled,
    refetchInterval,
  });
  const totalItems = query.data?.pagination?.totalItems ?? 0;
  const reported = query.data?.pagination?.totalPages ?? Math.ceil(totalItems / pageSize);
  const totalPages = Math.min(reported, cap);

  useEffect(() => {
    if (page > cap) setPage(cap, { replace: true });
  }, [page, cap, setPage]);
  useEffect(() => {
    if (!query.data || query.isPlaceholderData) return;
    if (current > Math.max(totalPages, 1)) setPage(Math.max(totalPages, 1), { replace: true });
  }, [query.data, query.isPlaceholderData, current, totalPages, setPage]);

  return {
    data: query.data ? { items: query.data.items } : undefined,
    isPending: query.isPending,
    isError: query.isError,
    error: query.error,
    refetch: query.refetch,
    isPlaceholderData: query.isPlaceholderData,
    queryKey: fullKey,
    pagination: {
      page: Math.min(current, Math.max(totalPages, 1)),
      pageSize,
      totalItems,
      totalPages,
    },
  };
}
