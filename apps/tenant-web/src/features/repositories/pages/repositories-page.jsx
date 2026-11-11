import { GitBranch, SearchX } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { LinkButton } from "@/components/common/link-button.jsx";
import { PageHeader } from "@/components/common/page-header.jsx";
import { Pager } from "@/components/common/pager.jsx";
import { SortHeader } from "@/components/common/sort-header.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { RepositoryRowActions } from "../components/repository-actions.jsx";
import { RepositoryHealth } from "../components/repository-health.jsx";
import { useRepositoryList } from "../hooks/use-repositories.js";

const PAGE_SIZE = 20;
const when = (value) =>
  value
    ? new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
    : "—";

/**
 * T-22 Repositories (workspace). Filters, sort and page live in the URL. The list only holds repositories of this
 * workspace; a "Connect repository" action needs repository.connect there. Pipeline counts arrive with the Pipelines module.
 */
export function RepositoriesPage() {
  const { workspaceId } = useParams();
  const can = useCan();
  const [params, setParams] = useSearchParams();
  const qParam = params.get("q") ?? "";
  const health = params.get("health") ?? "";
  const status = params.get("status") ?? "";
  const sort = params.get("sort") ?? "fullName:asc";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const [search, setSearch] = useState(qParam);
  const debounced = useDebouncedValue(search);
  const filtered = Boolean(qParam || health || status);

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
    if (debounced.trim() !== qParam) update({ q: debounced.trim(), page: "" });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the debounced text drives the URL
  }, [debounced]);

  const list = useRepositoryList({
    workspaceId,
    q: qParam || undefined,
    health: health || undefined,
    status: status || undefined,
    sort,
    page,
    pageSize: PAGE_SIZE,
  });
  const clear = () => {
    setSearch("");
    setParams({}, { replace: true });
  };
  const canConnect = can("repository.connect");
  const connect = (
    <PermissionGate
      permission="repository.connect"
      mode="disable"
      reason="You need the repository.connect permission to connect repositories."
    >
      <LinkButton to={`/workspaces/${workspaceId}/repositories/connect`}>
        Connect repository
      </LinkButton>
    </PermissionGate>
  );

  return (
    <>
      <PageHeader
        title="Repositories"
        description="Repositories connected to this workspace."
        actions={connect}
      />
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div className="w-full max-w-xs">
          <label htmlFor="repo-search" className="sr-only">
            Search repositories
          </label>
          <Input
            id="repo-search"
            type="search"
            placeholder="Search repositories"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="w-40">
          <label htmlFor="repo-health" className="sr-only">
            Health
          </label>
          <Select
            id="repo-health"
            value={health}
            onChange={(e) => update({ health: e.target.value, page: "" })}
          >
            <option value="">All health</option>
            <option value="healthy">Healthy</option>
            <option value="degraded">Degraded</option>
            <option value="error">Unavailable</option>
            <option value="disconnected">Disconnected</option>
          </Select>
        </div>
        <div className="w-40">
          <label htmlFor="repo-status" className="sr-only">
            Status
          </label>
          <Select
            id="repo-status"
            value={status}
            onChange={(e) => update({ status: e.target.value, page: "" })}
          >
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="unavailable">Unavailable</option>
            <option value="disconnected">Disconnected</option>
          </Select>
        </div>
        {filtered ? (
          <Button variant="ghost" onClick={clear}>
            Clear filters
          </Button>
        ) : null}
        {list.data?.pagination ? (
          <p className="ml-auto text-sm text-muted-foreground" aria-live="polite">
            {list.data.pagination.totalItems}{" "}
            {list.data.pagination.totalItems === 1 ? "repository" : "repositories"}
          </p>
        ) : null}
      </div>

      {list.isPending ? <LoadingState label="Loading repositories" /> : null}
      {list.isError ? <QueryErrorState error={list.error} onRetry={list.refetch} /> : null}
      {list.data && list.data.items.length === 0 ? (
        filtered ? (
          <EmptyState
            icon={SearchX}
            title="No matching repositories"
            description="Try different filters."
            actions={
              <Button variant="secondary" onClick={clear}>
                Clear filters
              </Button>
            }
          />
        ) : (
          <EmptyState
            icon={GitBranch}
            title="No repositories connected"
            description={
              canConnect
                ? "Connect a repository from a linked GitHub account. If no account is linked yet, link one on the GitHub integration page."
                : "Ask someone with repository.connect to connect repositories to this workspace."
            }
            actions={
              <div className="flex gap-2">
                {connect}
                {can("integration.view") ? (
                  <LinkButton to="/integrations/github" variant="secondary">
                    GitHub integration
                  </LinkButton>
                ) : null}
              </div>
            }
          />
        )
      ) : null}
      {list.data && list.data.items.length > 0 ? (
        <>
          <div className="relative overflow-x-auto rounded-md border border-border bg-card">
            <table className="w-full text-left text-[13px] leading-5">
              <caption className="sr-only">Repositories</caption>
              <thead className="border-b border-border text-muted-foreground">
                <tr>
                  <SortHeader
                    label="Repository"
                    field="fullName"
                    sort={sort}
                    onSort={(s) => update({ sort: s === "fullName:asc" ? "" : s, page: "" })}
                  />
                  <th scope="col" className="px-3 py-2 font-medium">
                    Default branch
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Health
                  </th>
                  <SortHeader
                    label="Last synced"
                    field="lastSyncedAt"
                    sort={sort}
                    onSort={(s) => update({ sort: s, page: "" })}
                  />
                  <th scope="col" className="px-3 py-2 font-medium">
                    Pipelines
                  </th>
                  <th scope="col" className="px-3 py-2 text-right font-medium">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((r) => (
                  <tr key={r.id} className="border-b border-border last:border-0">
                    <td className="px-3 py-2">
                      <Link
                        className="font-mono text-xs underline-offset-2 hover:underline focus-visible:underline"
                        to={`/workspaces/${r.workspaceId}/repositories/${r.id}`}
                      >
                        {r.fullName}
                      </Link>
                      <div className="text-xs text-muted-foreground">
                        {r.visibility}
                        {r.archived ? " · archived on GitHub" : ""}
                      </div>
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{r.defaultBranch ?? "—"}</td>
                    <td className="px-3 py-2">
                      <RepositoryHealth repository={r} />
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">{when(r.lastSyncedAt)}</td>
                    <td className="px-3 py-2">{r.pipelineCount}</td>
                    <td className="px-3 py-2 text-right">
                      <RepositoryRowActions repository={r} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            pagination={list.data.pagination}
            onPage={(p) => update({ page: p > 1 ? String(p) : "" })}
          />
        </>
      ) : null}
    </>
  );
}
