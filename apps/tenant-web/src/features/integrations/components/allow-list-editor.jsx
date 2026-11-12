import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { Pager } from "@/components/common/pager.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { describeError } from "@/lib/api/index.js";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { integrationKeys, useAllowList, useSaveAllowList } from "../hooks/use-integrations.js";

const MANAGE_REASON = "You need the workspace_integration.manage permission in this workspace.";

/**
 * Repository allow-list editor of one workspace link: repositories the installation can access (live from GitHub), with
 * checkboxes. Only allow-listed repositories can be connected. Changes are kept across pages and saved as add/remove.
 */
export function AllowListEditor({ workspaceId, link, canManage }) {
  const [search, setSearch] = useState("");
  const q = useDebouncedValue(search);
  const [page, setPage] = useState(1);
  const [changes, setChanges] = useState(() => new Map()); // externalRepoId -> { want, was }
  const list = useAllowList(workspaceId, link.id, { q: q.trim() || undefined, page, pageSize: 20 });
  const save = useSaveAllowList(workspaceId);
  const queryClient = useQueryClient();
  const tenantId = useTenantId();

  const toggle = (repo, checked) =>
    setChanges((current) => {
      const next = new Map(current);
      if (checked === repo.allowed) next.delete(repo.externalRepoId);
      else next.set(repo.externalRepoId, { want: checked, was: repo.allowed });
      return next;
    });
  const add = [...changes].filter(([, c]) => c.want).map(([id]) => id);
  const remove = [...changes].filter(([, c]) => !c.want).map(([id]) => id);
  const submit = () =>
    save.mutate(
      { linkId: link.id, body: { add, remove } },
      {
        onSuccess: (r) => {
          setChanges(new Map());
          toast.success(`Allow-list saved: ${r.added} added, ${r.removed} removed`);
        },
        // A refusal means the list changed under us (another workspace took a repository, or one got connected): show the
        // current state and drop the selection so nothing stale is saved by accident.
        onError: () => {
          setChanges(new Map());
          queryClient.invalidateQueries({
            queryKey: integrationKeys.workspace(tenantId, workspaceId),
          });
        },
      },
    );

  return (
    <div className="space-y-3">
      <div className="max-w-xs">
        <label htmlFor={`allow-search-${link.id}`} className="sr-only">
          Search repositories of {link.account.login}
        </label>
        <Input
          id={`allow-search-${link.id}`}
          type="search"
          placeholder="Search repositories"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
        />
      </div>
      {list.isPending ? <LoadingState label="Loading repositories from GitHub" rows={3} /> : null}
      {list.isError ? <QueryErrorState error={list.error} onRetry={list.refetch} /> : null}
      {list.data && list.data.items.length === 0 ? (
        <EmptyState
          title={q.trim() ? "No matching repositories" : "No repositories to list"}
          description={
            q.trim()
              ? "Try a different search."
              : "The GitHub App has no access to repositories. Change its repository access on GitHub."
          }
        />
      ) : null}
      {list.data && list.data.items.length > 0 ? (
        <>
          <ul className="divide-y divide-border rounded-md border border-border bg-card">
            {list.data.items.map((repo) => {
              const id = `allow-${link.id}-${repo.externalRepoId}`;
              const checked = changes.has(repo.externalRepoId)
                ? changes.get(repo.externalRepoId).want
                : repo.allowed;
              const elsewhere = repo.allowedElsewhere && !repo.allowed;
              const lockedByConnection = repo.allowed && repo.connected;
              const disabled = !canManage || elsewhere || lockedByConnection;
              return (
                <li
                  key={repo.externalRepoId}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm"
                >
                  <input
                    id={id}
                    type="checkbox"
                    checked={checked}
                    disabled={disabled}
                    onChange={(e) => toggle(repo, e.target.checked)}
                  />
                  <label
                    htmlFor={id}
                    className="flex min-w-0 flex-1 basis-48 flex-wrap items-center gap-2"
                  >
                    <span className="font-mono text-xs break-all">{repo.fullName}</span>
                    <span className="text-xs text-muted-foreground">
                      {repo.visibility}
                      {repo.archived ? " · archived" : ""}
                    </span>
                  </label>
                  {elsewhere ? (
                    <span className="ml-7 w-full text-xs text-muted-foreground sm:ml-0 sm:w-auto">
                      Already used by another workspace
                    </span>
                  ) : null}
                  {lockedByConnection ? (
                    <span className="ml-7 w-full text-xs text-muted-foreground sm:ml-0 sm:w-auto">
                      Connected: disconnect it to remove
                    </span>
                  ) : null}
                </li>
              );
            })}
          </ul>
          <Pager pagination={list.data.pagination} onPage={setPage} />
        </>
      ) : null}
      {save.error ? (
        <p role="alert" className="text-sm text-status-danger">
          {describeError(save.error)} Nothing was saved; the list below is up to date.
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-2">
        <DisabledWithReason reason={canManage ? null : MANAGE_REASON}>
          <Button disabled={changes.size === 0 || save.isPending} onClick={submit}>
            Save allow-list
          </Button>
        </DisabledWithReason>
        <Button variant="ghost" disabled={changes.size === 0} onClick={() => setChanges(new Map())}>
          Discard changes
        </Button>
        <span className="text-xs text-muted-foreground" role="status">
          {changes.size === 0
            ? `${link.allowListCount} allowed`
            : `${add.length} to add, ${remove.length} to remove`}
        </span>
      </div>
    </div>
  );
}
