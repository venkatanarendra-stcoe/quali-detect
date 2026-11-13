import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo } from "react";
import { toast } from "sonner";
import { isApiError } from "@/lib/api/index.js";

/**
 * "Load more" list on `useInfiniteQuery` over a cursor-paginated collection. The first request carries no cursor; the next
 * one carries `meta.pagination.nextCursor`. The cursor is opaque and bound to the filter/sort set, so `queryKey` MUST
 * contain every filter and the sort: any change starts a new query (and a new first page); a cursor is never reused.
 * Totals in the response are deliberately not exposed. An `INVALID_CURSOR` answer (stale or foreign cursor) restarts the
 * list from its first page with a toast.
 * @param {{ queryKey: unknown[], fetchPage: (cursor: string | undefined, signal: AbortSignal) => Promise<{ items: any[], pagination: any }>,
 *   enabled?: boolean }} options
 * @returns {{ data: { items: any[] } | undefined, isPending: boolean, isError: boolean, error: unknown, refetch: () => void,
 *   hasMore: boolean, loadingMore: boolean, loadMore: () => void }} a query-like object `QueryTable` understands
 */
export function useCursorList({ queryKey, fetchPage, enabled = true }) {
  const queryClient = useQueryClient();
  const query = useInfiniteQuery({
    queryKey,
    queryFn: ({ pageParam, signal }) => fetchPage(pageParam, signal),
    initialPageParam: undefined,
    getNextPageParam: (last) => last.pagination?.nextCursor ?? undefined,
    enabled,
  });
  const { error, isFetchNextPageError } = query;
  const invalidCursor = isApiError(error) && error.code === "INVALID_CURSOR";
  useEffect(() => {
    if (!invalidCursor) return;
    toast.error("The list changed, so it was reloaded from the start.");
    queryClient.resetQueries({ queryKey, exact: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the key is stable per filter set
  }, [invalidCursor, queryClient]);
  useEffect(() => {
    if (isFetchNextPageError && !invalidCursor) toast.error("Could not load more rows. Try again.");
  }, [isFetchNextPageError, invalidCursor, error]);

  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  return {
    data: query.data ? { items } : undefined,
    isPending: query.isPending || invalidCursor,
    // an error while appending keeps the rows and shows a toast; only a failed first page is a table error
    isError: query.isError && !isFetchNextPageError,
    error,
    refetch: query.refetch,
    hasMore: Boolean(query.hasNextPage),
    loadingMore: query.isFetchingNextPage,
    loadMore: () => {
      if (query.hasNextPage && !query.isFetchingNextPage) query.fetchNextPage();
    },
  };
}
