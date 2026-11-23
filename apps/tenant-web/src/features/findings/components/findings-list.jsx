import { SearchX, ShieldCheck } from "lucide-react";
import { useEffect, useRef } from "react";
import { LinkButton } from "@/components/common/link-button.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs.jsx";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useListParams } from "@/hooks/use-page-list.js";
import { SAVED_VIEW_TABS } from "../constants/index.js";
import {
  useBindMockActor,
  useFindingList,
  useFindingsSummary,
  usePipelineOptions,
} from "../hooks/use-findings.js";
import { useMediaQuery } from "../hooks/use-media-query.js";
import {
  activeFilterCount,
  readFindingFilters,
  sortParam,
  toListQuery,
} from "../schemas/filters.js";
import { useFindingsUiStore } from "../stores/findings-ui-store.js";
import { BulkBar } from "./bulk-bar.jsx";
import { ActiveFilterChips, FilterPanel, FindingSearch } from "./findings-filters.jsx";
import { FindingsTable } from "./findings-table.jsx";

/** The saved-view tabs with the counts of the summary (`aria-label` carries the count in words). */
function ViewTabs({ view, onChange, summary }) {
  return (
    <Tabs value={view} onValueChange={onChange}>
      <TabsList aria-label="Saved views" className="mb-3 overflow-x-auto">
        {SAVED_VIEW_TABS.map((tab) => {
          const count = summary.data?.views?.[tab.count];
          return (
            <TabsTrigger key={tab.id} value={tab.id} className="whitespace-nowrap">
              {tab.label}
              {summary.isPending ? (
                <Skeleton className="ml-2 inline-block h-4 w-6 align-middle" />
              ) : typeof count === "number" ? (
                <span className="ml-2 rounded-sm bg-secondary px-1.5 text-xs tabular-nums text-muted-foreground">
                  {count}
                  <span className="sr-only"> findings</span>
                </span>
              ) : null}
            </TabsTrigger>
          );
        })}
      </TabsList>
    </Tabs>
  );
}

/**
 * T-31 body: saved views, search, the facet panel, active-filter chips, bulk actions, the table and the numbered pager. Filters,
 * sort, `page` and `limit` live in the URL, so a reload or shared link lands on the same page.
 * @param {{ workspaceId: string }} props
 */
export function FindingsList({ workspaceId }) {
  useBindMockActor(workspaceId);
  const can = useCan();
  const { searchParams, update, page, pageSize, setPage, setPageSize } = useListParams();
  const filters = readFindingFilters(searchParams);
  const defaultView =
    can("finding.remediate") && !can("finding.review") ? "assigned_to_me" : "all_open";
  const view = filters.view || defaultView;
  const facetCount = activeFilterCount(filters);
  const narrow = !useMediaQuery("(min-width: 768px)");
  const search = useRef(null);
  const scope = useFindingsUiStore((s) => s.scope);
  useEffect(() => scope(workspaceId), [scope, workspaceId]);

  useEffect(() => {
    const onKey = (event) => {
      const tag = event.target?.tagName;
      if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey) return;
      if (tag === "INPUT" || tag === "TEXTAREA" || event.target?.isContentEditable) return;
      event.preventDefault();
      search.current?.focus();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const summary = useFindingsSummary(workspaceId);
  const pipelines = usePipelineOptions(workspaceId);
  const params = toListQuery(filters, view);
  const list = useFindingList(workspaceId, params, { page, pageSize, setPage });
  const canBulk = can("finding.review") || can("finding.assign");

  const clearFacets = () =>
    update({
      severity: [],
      status: [],
      scanType: [],
      pipeline: "",
      repository: "",
      assignee: "",
      sla: [],
      ai: "",
      q: "",
    });
  const hasFilters = facetCount > 0;
  const emptyState = hasFilters ? (
    <EmptyState
      icon={SearchX}
      title="No findings match these filters"
      description="No findings match these filters."
      actions={
        <Button variant="secondary" onClick={clearFacets}>
          Clear filters
        </Button>
      }
    />
  ) : view !== "all_open" ? (
    <EmptyState
      icon={ShieldCheck}
      title="Nothing in this view"
      description="No findings are in this saved view right now."
      actions={
        <Button variant="secondary" onClick={() => update({ view: "all_open" })}>
          Show all open findings
        </Button>
      }
    />
  ) : (
    <EmptyState
      icon={ShieldCheck}
      title="No findings yet"
      description="No findings yet. Findings appear after a scan of the default branch finds issues."
      actions={
        <PermissionGate permission="pipeline.view">
          <LinkButton to={`/workspaces/${workspaceId}/pipelines`} variant="secondary">
            Go to Pipelines
          </LinkButton>
        </PermissionGate>
      }
    />
  );

  return (
    <>
      <ViewTabs
        view={view}
        summary={summary}
        onChange={(v) => update({ view: v === defaultView ? "" : v })}
      />
      <FilterPanel
        filters={filters}
        onChange={update}
        pipelines={pipelines.data}
        activeCount={facetCount}
        toolbar={
          <>
            <FindingSearch value={filters.qRaw} onChange={(q) => update({ q })} inputRef={search} />
            <p className="text-sm text-muted-foreground" aria-live="polite">
              {summary.data
                ? `${summary.data.views.allOpen} open ${summary.data.views.allOpen === 1 ? "finding" : "findings"}`
                : ""}
            </p>
          </>
        }
      >
        <ActiveFilterChips
          filters={filters}
          pipelines={pipelines.data}
          onChange={update}
          onClear={clearFacets}
        />
        {canBulk ? <BulkBar workspaceId={workspaceId} /> : null}
        <FindingsTable
          workspaceId={workspaceId}
          query={list}
          sort={sortParam(filters.sort, filters.dir) || "severity:desc"}
          onSort={(next) => update({ sort: next === "severity:desc" ? "" : next })}
          pagination={list.pagination}
          onPage={setPage}
          onPageSize={setPageSize}
          emptyState={emptyState}
          selectable={canBulk}
          narrow={narrow}
        />
      </FilterPanel>
    </>
  );
}
