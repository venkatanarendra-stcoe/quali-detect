import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { pipelineKeys } from "@/features/pipelines/hooks/use-pipelines.js";
import { useCursorList } from "@/hooks/use-cursor-list.js";
import { isActiveStatus } from "../constants/index.js";
import { executionsService } from "../services/executions-service.js";

/** Keys start with the tenant, then the workspace id, then `executions` (SCREENS §1): nothing crosses tenants or workspaces. */
export const executionKeys = {
  all: (tenantId, workspaceId) => ["tenant", tenantId, "workspace", workspaceId, "executions"],
  list: (tenantId, workspaceId, params) => [
    ...executionKeys.all(tenantId, workspaceId),
    "list",
    params,
  ],
  detail: (tenantId, workspaceId, id) => [
    ...executionKeys.all(tenantId, workspaceId),
    "detail",
    id,
  ],
  events: (tenantId, workspaceId, id) => [
    ...executionKeys.all(tenantId, workspaceId),
    "events",
    id,
  ],
  history: (tenantId, workspaceId, id, filters) => [
    ...executionKeys.all(tenantId, workspaceId),
    "logs",
    id,
    "history",
    filters,
  ],
  tail: (tenantId, workspaceId, id, filters) => [
    ...executionKeys.all(tenantId, workspaceId),
    "logs",
    id,
    "tail",
    filters,
  ],
};

/**
 * Polling rhythm when hints are not (or not only) driving the refresh. Socket up: a slow safety poll while something is
 * active (a missed hint is repaired by the next fetch). Socket down: 15 s while a visible row is active, 60 s otherwise.
 */
export const listInterval = (live, active) =>
  live ? (active ? 60_000 : false) : active ? 15_000 : 60_000;
/** Detail: 5 s while active without a socket; none once terminal. */
export const detailInterval = (live, status) =>
  status && isActiveStatus(status) ? (live ? 30_000 : 5_000) : false;

/**
 * "Load more" list of executions (cursor, no totals). `params` are the filters, sort and `limit` (never a cursor).
 * @param {string} workspaceId
 * @param {object} params
 * @param {{ live?: boolean, enabled?: boolean }} [options]
 */
export function useExecutionList(workspaceId, params, { live = false, enabled = true } = {}) {
  const tenantId = useTenantId();
  return useCursorList({
    queryKey: executionKeys.list(tenantId, workspaceId, params),
    fetchPage: (cursor, signal) =>
      executionsService.list({ workspaceId, ...params, cursor }, { signal }),
    enabled,
    refetchInterval: (query) => {
      const pages = query.state.data?.pages ?? [];
      const active = pages.some((p) => p.items.some((e) => isActiveStatus(e.status)));
      return listInterval(live, active);
    },
  });
}

export function useExecution(workspaceId, executionId, { live = false } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: executionKeys.detail(tenantId, workspaceId, executionId),
    queryFn: ({ signal }) => executionsService.get(executionId, { signal }),
    enabled: Boolean(executionId),
    staleTime: 0,
    refetchInterval: (query) => detailInterval(live, query.state.data?.status),
  });
}

/** Status history of an execution, oldest first, "Load more". */
export function useExecutionEvents(
  workspaceId,
  executionId,
  { enabled = true, live = false } = {},
) {
  const tenantId = useTenantId();
  return useCursorList({
    queryKey: executionKeys.events(tenantId, workspaceId, executionId),
    fetchPage: (cursor, signal) =>
      executionsService.events(executionId, { cursor, limit: 50 }, { signal }),
    enabled,
    refetchInterval: live ? false : 15_000,
  });
}

const LOG_PAGE = 200;
const TAIL_PAGE = 500;
const TAIL_MAX_LINES = 5000;

/**
 * Log lines (SPEC §8.1 "the UI loads the tail with `desc`, then appends live lines with `afterSeq`").
 * - `history`: the newest 200 lines first (`order=desc`), earlier ones on request (`fetchNextPage`, the cursor).
 * - `tail`: lines after the newest known `seq`, accumulated by the query function itself and refreshed by hints/polling
 *   (`enabled` only while the Logs tab is open or Follow is on).
 * Lines are returned oldest first, de-duplicated by `seq`.
 * @param {{ workspaceId: string, executionId: string, filters: { taskId?: string, level?: string },
 *   tailEnabled: boolean, active: boolean, live: boolean }} input
 */
export function useExecutionLogs({ workspaceId, executionId, filters, tailEnabled, active, live }) {
  const tenantId = useTenantId();
  const queryClient = useQueryClient();
  const history = useInfiniteQuery({
    queryKey: executionKeys.history(tenantId, workspaceId, executionId, filters),
    queryFn: ({ pageParam, signal }) =>
      executionsService.logs(
        executionId,
        { order: "desc", limit: LOG_PAGE, cursor: pageParam, ...filters },
        { signal },
      ),
    initialPageParam: undefined,
    getNextPageParam: (last) => (last.hasMore ? (last.nextCursor ?? undefined) : undefined),
    staleTime: Infinity,
    refetchOnMount: false,
  });
  const pages = history.data?.pages;
  const newest = pages?.[0]?.lines?.[0]?.seq ?? 0; // desc: the first line of the first page is the newest
  const tailKey = executionKeys.tail(tenantId, workspaceId, executionId, filters);
  const tail = useQuery({
    queryKey: tailKey,
    enabled: history.isSuccess && tailEnabled,
    staleTime: 0,
    gcTime: 0,
    refetchInterval: active ? (live ? 10_000 : 3_000) : false,
    queryFn: async ({ signal }) => {
      const previous = queryClient.getQueryData(tailKey);
      let after = previous?.lastSeq ?? newest;
      let lines = previous?.lines ?? [];
      let truncated = previous?.truncated ?? false;
      for (let i = 0; i < 10; i += 1) {
        const page = await executionsService.logs(
          executionId,
          { order: "asc", afterSeq: after, limit: TAIL_PAGE, ...filters },
          { signal },
        );
        lines = lines.concat(page.lines);
        truncated = truncated || page.truncated;
        if (page.lines.length) after = page.lines[page.lines.length - 1].seq;
        if (!page.hasMore || page.lines.length === 0) break;
      }
      if (lines.length > TAIL_MAX_LINES) lines = lines.slice(-TAIL_MAX_LINES);
      return { lines, lastSeq: after, truncated };
    },
  });
  const ordered = [];
  const seen = new Set();
  if (pages) {
    for (let p = pages.length - 1; p >= 0; p -= 1) {
      const chunk = pages[p].lines;
      for (let i = chunk.length - 1; i >= 0; i -= 1) {
        if (!seen.has(chunk[i].seq)) {
          seen.add(chunk[i].seq);
          ordered.push(chunk[i]);
        }
      }
    }
  }
  for (const line of tail.data?.lines ?? []) {
    if (!seen.has(line.seq)) {
      seen.add(line.seq);
      ordered.push(line);
    }
  }
  return {
    lines: ordered,
    isPending: history.isPending,
    isError: history.isError,
    error: history.error,
    refetch: history.refetch,
    truncated: Boolean(pages?.some((p) => p.truncated) || tail.data?.truncated),
    hasEarlier: Boolean(history.hasNextPage),
    loadingEarlier: history.isFetchingNextPage,
    loadEarlier: () =>
      history.hasNextPage && !history.isFetchingNextPage && history.fetchNextPage(),
    /** Fetches lines newer than the newest known one (a `log.appended` hint, or Follow turned on). */
    refreshTail: () => tail.refetch(),
  };
}

const useInvalidateAfterAction = () => {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  return (workspaceId) =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: executionKeys.all(tenantId, workspaceId) }),
      queryClient.invalidateQueries({ queryKey: pipelineKeys.all(tenantId) }),
    ]);
};

/** Cancel: the dialog owns the Idempotency-Key so a retry of the same attempt reuses it. Result `cancelRequested` tells 202 from 200. */
export function useCancelExecution() {
  const invalidate = useInvalidateAfterAction();
  return useMutation({
    mutationFn: ({ executionId, idempotencyKey }) =>
      executionsService.cancel(executionId, idempotencyKey),
    onSuccess: (_data, { workspaceId }) => invalidate(workspaceId),
  });
}

/** Retry: needs the Idempotency-Key (generated per user action by the dialog). Returns `{ execution }` (the NEW one). */
export function useRetryExecution() {
  const invalidate = useInvalidateAfterAction();
  return useMutation({
    mutationFn: ({ executionId, idempotencyKey }) =>
      executionsService.retry(executionId, idempotencyKey),
    onSuccess: (_data, { workspaceId }) => invalidate(workspaceId),
  });
}
