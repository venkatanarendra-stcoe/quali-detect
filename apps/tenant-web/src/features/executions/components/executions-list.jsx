import { useQueryClient } from "@tanstack/react-query";
import { History, SearchX } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { LinkButton } from "@/components/common/link-button.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { useRepositoryList } from "@/features/repositories/hooks/use-repositories.js";
import { FILTER_STATUSES, LIST_PAGE_SIZE } from "../constants/index.js";
import { executionKeys, useExecutionList } from "../hooks/use-executions.js";
import { useRealtime } from "../hooks/use-realtime.js";
import { ExecutionFilters, rangeProblem, rangeToInstants } from "./execution-filters.jsx";
import { ExecutionTable } from "./execution-table.jsx";
import { LiveIndicator } from "./live-indicator.jsx";

const DEFAULT_SORT = "requestedAt:desc";
const PAGE_SIZES = [25, 50, 100];
const SETTLE_MS = 800;

/** Reads the filters from the URL (the single source of truth, repeated unchanged on every "Load more" request). */
function readFilters(params, fixedPipelineId) {
  const status = (params.get("status") ?? "").split(",").filter((s) => FILTER_STATUSES.includes(s));
  const limit = Number(params.get("limit"));
  return {
    status,
    pipeline: fixedPipelineId ?? params.get("pipeline") ?? "",
    repository: params.get("repository") ?? "",
    trigger: params.get("trigger") ?? "",
    from: params.get("from") ?? "",
    to: params.get("to") ?? "",
    sort: params.get("sort") === "requestedAt:asc" ? "requestedAt:asc" : DEFAULT_SORT,
    limit: PAGE_SIZES.includes(limit) ? limit : LIST_PAGE_SIZE,
  };
}

/**
 * The executions list of T-28 and of the pipeline's Executions tab (`pipelineId` fixes the pipeline and hides its column and
 * filter). Filters, sort and page size live in the URL; rows load with "Load more" (cursor, no totals). Live updates: the
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
  const [searchParams, setSearchParams] = useSearchParams();
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
    limit: filters.limit,
  };
  const key = executionKeys.list(tenantId, workspaceId, params);

  const [pending, setPending] = useState({ key: "", ids: new Set() });
  const waiting = pending.key === JSON.stringify(key) ? pending.ids : new Set();
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
      const data = queryClient.getQueryData(key);
      const pages = data?.pages ?? [];
      const visible = pages.some((p) => p.items.some((e) => e.id === hint.executionId));
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
                pages: old.pages.map((p) => ({
                  ...p,
                  items: p.items.map((e) =>
                    e.id === hint.executionId ? { ...e, status: hint.status } : e,
                  ),
                })),
              }
            : old,
        );
        refetchQuietly();
        return;
      }
      // not on screen: at the top of an unfiltered newest-first list with one page, refresh silently; else offer a refresh
      if (!hasFilters && filters.sort === DEFAULT_SORT && pages.length <= 1) refetchQuietly();
      else
        setPending((cur) => {
          const ids = new Set(cur.key === JSON.stringify(key) ? cur.ids : []);
          ids.add(hint.executionId);
          return { key: JSON.stringify(key), ids };
        });
    },
  });
  useEffect(() => () => clearTimeout(settle.current), []);

  const list = useExecutionList(workspaceId, params, { live: live.live, enabled: !problem });
  const repositories = useRepositoryList({ workspaceId, pageSize: 100, sort: "fullName:asc" });

  const update = useCallback(
    (next) =>
      setSearchParams(
        (current) => {
          const merged = new URLSearchParams(current);
          for (const [name, value] of Object.entries(next)) {
            const urlName = name === "status" ? "status" : name;
            const text = Array.isArray(value) ? value.join(",") : value;
            if (text) merged.set(urlName, text);
            else merged.delete(urlName);
          }
          return merged;
        },
        { replace: true },
      ),
    [setSearchParams],
  );
  const clear = () =>
    update({ status: [], pipeline: "", repository: "", trigger: "", from: "", to: "" });
  const refresh = () => {
    setPending({ key: "", ids: new Set() });
    queryClient.resetQueries({ queryKey: key, exact: true });
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
            <label htmlFor="ex-limit" className="sr-only">
              Rows per load
            </label>
            <Select
              id="ex-limit"
              className="w-36"
              value={String(filters.limit)}
              onChange={(e) =>
                update({ limit: Number(e.target.value) === LIST_PAGE_SIZE ? "" : e.target.value })
              }
            >
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {n} per load
                </option>
              ))}
            </Select>
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
        hasMore={list.hasMore}
        loadingMore={list.loadingMore}
        onLoadMore={list.loadMore}
        emptyState={empty}
        height={height}
        maxHeight={maxHeight}
      />
    </>
  );
}
