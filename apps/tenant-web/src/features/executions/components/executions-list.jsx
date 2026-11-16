import { useQueryClient } from "@tanstack/react-query";
import { History, SearchX } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { LinkButton } from "@/components/common/link-button.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { useListParams } from "@/hooks/use-page-list.js";
import { useRepositoryList } from "@/features/repositories/hooks/use-repositories.js";
import { FILTER_STATUSES } from "../constants/index.js";
import { MAX_LIST_WINDOW, executionKeys, useExecutionList } from "../hooks/use-executions.js";
import { useRealtime } from "../hooks/use-realtime.js";
import { ExecutionFilters, rangeProblem, rangeToInstants } from "./execution-filters.jsx";
import { ExecutionTable } from "./execution-table.jsx";
import { LiveIndicator } from "./live-indicator.jsx";

const DEFAULT_SORT = "requestedAt:desc";
const SETTLE_MS = 800;

/** Reads the filters from the URL (the single source of truth, repeated unchanged on every page request). */
function readFilters(params, fixedPipelineId) {
  const status = (params.get("status") ?? "").split(",").filter((s) => FILTER_STATUSES.includes(s));
  return {
    status,
    pipeline: fixedPipelineId ?? params.get("pipeline") ?? "",
    repository: params.get("repository") ?? "",
    trigger: params.get("trigger") ?? "",
    from: params.get("from") ?? "",
    to: params.get("to") ?? "",
    sort: params.get("sort") === "requestedAt:asc" ? "requestedAt:asc" : DEFAULT_SORT,
  };
}

/**
 * The executions list of T-28 and of the pipeline's Executions tab (`pipelineId` fixes the pipeline and hides its column and
 * filter). Filters, sort, `page` and `limit` live in the URL; numbered pages, the total only in the pager. Live updates: the
 * workspace room patches the status of a visible row and refetches quietly; hints for rows that are not on screen show a
 * non-modal "Refresh" bar and never move rows under the cursor. Without the socket the list polls (15 s active, 60 s idle).
 * @param {{ workspaceId: string, pipelineId?: string, compact?: boolean, height?: "auto" | "fill", maxHeight?: string,
 *   caption: string, headerSlot?: any }} props
 */
export function ExecutionsList({
  workspaceId,
  pipelineId,
  compact = false,
  height = "fill",
  maxHeight,
  caption,
}) {
  const tenantId = useTenantId();
  const queryClient = useQueryClient();
  const { searchParams, update, page, pageSize, setPage, setPageSize } = useListParams();
  const filters = readFilters(searchParams, pipelineId);
  const problem = rangeProblem(filters.from, filters.to);
  const statusKey = filters.status.join(",");
  const range = problem ? {} : rangeToInstants(filters.from, filters.to);
  const hasFilters = Boolean(
    filters.status.length ||
    (!pipelineId && filters.pipeline) ||
    filters.repository ||
    filters.trigger ||
    filters.from ||
    filters.to,
  );

  // a new object each render is fine: TanStack Query hashes the key structurally
  const params = {
    pipelineId: filters.pipeline || undefined,
    repositoryId: filters.repository || undefined,
    status: statusKey || undefined,
    triggerType: filters.trigger || undefined,
    ...range,
    sort: filters.sort,
  };
  const listKey = executionKeys.list(tenantId, workspaceId, params);

  const [pending, setPending] = useState({ key: "", ids: new Set() });
  const waiting = pending.key === JSON.stringify(listKey) ? pending.ids : new Set();
  const revs = useRef(new Map());
  const settle = useRef(null);
  const live = useRealtime({
    scope: "workspace",
    id: workspaceId,
    onHint: (name, hint) => {
      if (name !== "execution.changed") return;
      if ((revs.current.get(hint.executionId) ?? -1) >= hint.rev) return; // older or duplicate: ignored
      revs.current.set(hint.executionId, hint.rev);
      if (pipelineId && hint.pipelineId && hint.pipelineId !== pipelineId) return;
      // the page being shown: `listKey` plus `{ page, pageSize }` (see `usePageList`)
      const key = [
        ...listKey,
        { page: Math.min(page, Math.floor(MAX_LIST_WINDOW / pageSize)), pageSize },
      ];
      const data = queryClient.getQueryData(key);
      const visible = Boolean(data?.items.some((e) => e.id === hint.executionId));
      const refetchQuietly = () => {
        clearTimeout(settle.current);
        settle.current = setTimeout(
          () => queryClient.invalidateQueries({ queryKey: key, exact: true }),
          SETTLE_MS,
        );
      };
      if (visible) {
        queryClient.setQueryData(key, (old) =>
          old
            ? {
                ...old,
                items: old.items.map((e) =>
                  e.id === hint.executionId ? { ...e, status: hint.status } : e,
                ),
              }
            : old,
        );
        refetchQuietly();
        return;
      }
      // not on screen: on the first page of an unfiltered newest-first list, refresh silently; else offer a refresh
      if (!hasFilters && filters.sort === DEFAULT_SORT && page === 1) refetchQuietly();
      else
        setPending((cur) => {
          const ids = new Set(cur.key === JSON.stringify(listKey) ? cur.ids : []);
          ids.add(hint.executionId);
          return { key: JSON.stringify(listKey), ids };
        });
    },
  });
  useEffect(() => () => clearTimeout(settle.current), []);

  const list = useExecutionList(
    workspaceId,
    params,
    { page, pageSize, setPage },
    { live: live.live, enabled: !problem },
  );
  const repositories = useRepositoryList({ workspaceId, pageSize: 100, sort: "fullName:asc" });

  const clear = () =>
    update({ status: [], pipeline: "", repository: "", trigger: "", from: "", to: "" });
  const refresh = () => {
    setPending({ key: "", ids: new Set() });
    queryClient.resetQueries({ queryKey: listKey });
  };

  const workspaceHref = `/workspaces/${workspaceId}/pipelines`;
  const empty = hasFilters ? (
    <EmptyState
      icon={SearchX}
      title="No matching executions"
      description="No executions match these filters."
      actions={
        <Button variant="secondary" onClick={clear}>
          Clear filters
        </Button>
      }
    />
  ) : (
    <EmptyState
      icon={History}
      title="No executions yet"
      description="Executions appear here when a pipeline runs."
      actions={
        pipelineId ? null : (
          <PermissionGate permission="pipeline.view">
            <LinkButton to={workspaceHref} variant="secondary">
              Go to Pipelines
            </LinkButton>
          </PermissionGate>
        )
      }
    />
  );

  return (
    <>
      <ExecutionFilters
        workspaceId={workspaceId}
        filters={filters}
        onChange={update}
        onClear={clear}
        repositories={repositories.data?.items}
        showPipeline={!pipelineId}
        trailing={
          <>
            <LiveIndicator state={live} variant="list" />
          </>
        }
      />
      {waiting.size > 0 ? (
        <div
          role="status"
          className="mb-3 flex shrink-0 items-center justify-between gap-3 rounded-md border border-border-strong bg-secondary px-3 py-2 text-sm"
        >
          <span>
            {waiting.size} new or updated {waiting.size === 1 ? "execution" : "executions"}
          </span>
          <Button size="sm" variant="secondary" onClick={refresh}>
            Refresh
          </Button>
        </div>
      ) : null}
      <ExecutionTable
        caption={caption}
        query={
          problem
            ? { isPending: false, isError: false, data: { items: [] }, refetch: () => {} }
            : list
        }
        compact={compact}
        sort={filters.sort}
        onSort={(next) => update({ sort: next === DEFAULT_SORT ? "" : next })}
        pagination={list.pagination}
        onPage={setPage}
        onPageSize={setPageSize}
        pageNote={
          list.pagination.totalItems > MAX_LIST_WINDOW
            ? `Pages stop at the newest ${MAX_LIST_WINDOW.toLocaleString()}; narrow the filters for older runs.`
            : undefined
        }
        emptyState={empty}
        height={height}
        maxHeight={maxHeight}
      />
    </>
  );
}
