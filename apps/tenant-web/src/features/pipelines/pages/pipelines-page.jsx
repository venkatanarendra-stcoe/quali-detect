import { AppPageLayout } from "@qmentisai/ui";
import { SearchX, Workflow } from "lucide-react";
import { useEffect, useState } from "react";
import { useParams, useSearchParams } from "react-router";
import { LinkButton } from "@/components/common/link-button.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useRepositoryList } from "@/features/repositories/hooks/use-repositories.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { PipelineTable } from "../components/pipeline-table.jsx";
import { TRIGGER_LABELS } from "../constants/index.js";
import { usePipelineList } from "../hooks/use-pipelines.js";

const PAGE_SIZE = 20; // rows per "Load more" request
const STATES = Object.freeze({
  enabled: { effectiveState: "running_normally" },
  disabled: { effectiveState: "disabled" },
  repository_disabled: { effectiveState: "repository_disabled" },
  repository_unavailable: { effectiveState: "repository_unavailable" },
  repository_disconnected: { effectiveState: "repository_disconnected" },
  workspace_archived: { effectiveState: "workspace_archived" },
});

/**
 * T-25 Pipelines (workspace). Search, repository, trigger and state filters, "Show deleted", and sort live in the URL; rows load with "Load more" (cursor), no totals are shown.
 * Columns that depend on later modules (duration, success rate, open findings) stay hidden (SCREENS §4, C6).
 */
export function PipelinesPage() {
  const { workspaceId } = useParams();
  const can = useCan();
  const [params, setParams] = useSearchParams();
  const qParam = params.get("q") ?? "";
  const repository = params.get("repository") ?? "";
  const trigger = params.get("trigger") ?? "";
  const state = params.get("state") ?? "";
  const deleted = params.get("deleted") === "1";
  const sort = params.get("sort") ?? "name:asc";
  const [search, setSearch] = useState(qParam);
  const debounced = useDebouncedValue(search);
  const filtered = Boolean(qParam || repository || trigger || state || deleted);

  const update = (next) =>
    setParams(
      (current) => {
        const merged = new URLSearchParams(current);
        for (const [key, value] of Object.entries(next))
          value ? merged.set(key, value) : merged.delete(key);
        return merged;
      },
      { replace: true },
    );
  useEffect(() => {
    if (debounced.trim() !== qParam) update({ q: debounced.trim() });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the debounced text drives the URL
  }, [debounced]);

  const repositories = useRepositoryList({ workspaceId, pageSize: 100, sort: "fullName:asc" });
  const list = usePipelineList(workspaceId, {
    q: qParam || undefined,
    repositoryId: repository || undefined,
    triggerType: trigger || undefined,
    ...(STATES[state] ?? {}),
    includeDeleted: deleted ? "true" : undefined,
    sort,
    limit: PAGE_SIZE,
  });
  const clear = () => {
    setSearch("");
    setParams({}, { replace: true });
  };
  const noRepositories = repositories.data && repositories.data.items.length === 0;
  const create = (
    <PermissionGate permission="pipeline.manage">
      <LinkButton to={`/workspaces/${workspaceId}/pipelines/new`}>Create pipeline</LinkButton>
    </PermissionGate>
  );

  return (
    <AppPageLayout
      title="Pipelines"
      description="What is scanned and when, for the repositories of this workspace."
      actions={create}
      scroll={false}
    >
      <div className="mb-4 flex shrink-0 flex-wrap items-end gap-3">
        <div className="w-full max-w-xs">
          <label htmlFor="pl-search" className="sr-only">
            Search pipelines
          </label>
          <Input
            id="pl-search"
            type="search"
            placeholder="Search by name"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="w-52">
          <label htmlFor="pl-repo" className="sr-only">
            Repository
          </label>
          <Select
            id="pl-repo"
            value={repository}
            onChange={(e) => update({ repository: e.target.value })}
          >
            <option value="">All repositories</option>
            {(repositories.data?.items ?? []).map((r) => (
              <option key={r.id} value={r.id}>
                {r.fullName}
              </option>
            ))}
          </Select>
        </div>
        <div className="w-40">
          <label htmlFor="pl-trigger" className="sr-only">
            Trigger type
          </label>
          <Select
            id="pl-trigger"
            value={trigger}
            onChange={(e) => update({ trigger: e.target.value })}
          >
            <option value="">All triggers</option>
            {Object.entries(TRIGGER_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </Select>
        </div>
        <div className="w-52">
          <label htmlFor="pl-state" className="sr-only">
            State
          </label>
          <Select id="pl-state" value={state} onChange={(e) => update({ state: e.target.value })}>
            <option value="">All states</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
            <option value="repository_disabled">Repository disabled</option>
            <option value="repository_unavailable">Repository unavailable</option>
            <option value="repository_disconnected">Repository disconnected</option>
            <option value="workspace_archived">Workspace archived</option>
          </Select>
        </div>
        <label className="flex h-9 items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={deleted}
            onChange={(e) => update({ deleted: e.target.checked ? "1" : "" })}
          />
          Show deleted
        </label>
        {filtered ? (
          <Button variant="ghost" onClick={clear}>
            Clear filters
          </Button>
        ) : null}
      </div>
      <PipelineTable
        caption="Pipelines"
        query={list}
        sort={sort}
        onSort={(s) => update({ sort: s === "name:asc" ? "" : s })}
        hasMore={list.hasMore}
        loadingMore={list.loadingMore}
        onLoadMore={list.loadMore}
        emptyState={
          filtered ? (
            <EmptyState
              icon={SearchX}
              title="No matching pipelines"
              description="Try different filters."
              actions={
                <Button variant="secondary" onClick={clear}>
                  Clear filters
                </Button>
              }
            />
          ) : noRepositories ? (
            <EmptyState
              icon={Workflow}
              title="No pipelines yet"
              description={
                can("repository.connect")
                  ? "A pipeline belongs to a repository. Connect a repository first."
                  : "A pipeline belongs to a repository. Ask someone who can connect repositories to this workspace."
              }
              actions={
                <PermissionGate permission="repository.connect">
                  <LinkButton to={`/workspaces/${workspaceId}/repositories/connect`}>
                    Connect a repository
                  </LinkButton>
                </PermissionGate>
              }
            />
          ) : (
            <EmptyState
              icon={Workflow}
              title="No pipelines yet"
              description={
                can("pipeline.manage")
                  ? "Create the first pipeline to start scanning a repository."
                  : "Pipelines decide what is scanned and when. None have been created in this workspace."
              }
              actions={create}
            />
          )
        }
      />
    </AppPageLayout>
  );
}
