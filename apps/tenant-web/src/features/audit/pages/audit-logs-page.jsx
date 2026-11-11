import { CircleCheck, CircleX, ScrollText, SearchX } from "lucide-react";
import { useSearchParams } from "react-router";
import { PageHeader } from "@/components/common/page-header.jsx";
import { Pager } from "@/components/common/pager.jsx";
import { SortHeader } from "@/components/common/sort-header.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useUserSearch } from "@/features/directory/hooks/use-directory.js";
import { TENANT_AUDIT_ACTIONS } from "../constants/index.js";
import { useAuditLogs } from "../hooks/use-audit-logs.js";

const PAGE_SIZE = 25;
const when = (value) =>
  new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
const startOfDay = (day) => new Date(`${day}T00:00:00`).toISOString();
const endOfDay = (day) => new Date(`${day}T23:59:59.999`).toISOString();

function Outcome({ result }) {
  return result === "failure" ? (
    <Badge tone="danger">
      <CircleX aria-hidden="true" />
      Failure
    </Badge>
  ) : (
    <Badge tone="success">
      <CircleCheck aria-hidden="true" />
      Success
    </Badge>
  );
}

function Details({ entry }) {
  const detail = { changes: entry.changes, metadata: entry.metadata, ipAddress: entry.ipAddress };
  return (
    <details>
      <summary className="cursor-pointer text-muted-foreground">Details</summary>
      <pre className="mt-2 max-w-md overflow-x-auto rounded-sm bg-secondary p-2 font-mono text-xs">
        {JSON.stringify(detail, null, 2)}
      </pre>
    </details>
  );
}

/**
 * T-19 Audit logs: the organization's audit log (needs `audit_log.view_all`; the API scopes it to the session's tenant).
 * Filters (actor, action, date range, result), sorting and the page live in the URL.
 */
export function AuditLogsPage() {
  const can = useCan();
  const [params, setParams] = useSearchParams();
  const action = params.get("action") ?? "";
  const result = params.get("result") ?? "";
  const actor = params.get("actor") ?? "";
  const from = params.get("from") ?? "";
  const to = params.get("to") ?? "";
  const sort = params.get("sort") ?? "createdAt:desc";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const filtered = Boolean(action || result || actor || from || to);

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
  const users = useUserSearch("", { enabled: can("user.view") });
  const list = useAuditLogs({
    action: action || undefined,
    result: result || undefined,
    actor: actor || undefined,
    from: from ? startOfDay(from) : undefined,
    to: to ? endOfDay(to) : undefined,
    sort,
    page,
    pageSize: PAGE_SIZE,
  });
  const clear = () => setParams({}, { replace: true });

  return (
    <>
      <PageHeader
        title="Audit logs"
        description="Who did what in this organization. Entries cannot be changed or deleted."
      />
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div className="w-52">
          <label htmlFor="audit-action" className="sr-only">
            Action
          </label>
          <Select
            id="audit-action"
            value={action}
            onChange={(e) => update({ action: e.target.value, page: "" })}
          >
            <option value="">All actions</option>
            {TENANT_AUDIT_ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </Select>
        </div>
        {can("user.view") ? (
          <div className="w-48">
            <label htmlFor="audit-actor" className="sr-only">
              Actor
            </label>
            <Select
              id="audit-actor"
              value={actor}
              onChange={(e) => update({ actor: e.target.value, page: "" })}
            >
              <option value="">All actors</option>
              {(users.data ?? []).map((u) => (
                <option key={u.id} value={u.id}>
                  {u.name}
                </option>
              ))}
            </Select>
          </div>
        ) : null}
        <div className="w-36">
          <label htmlFor="audit-result" className="sr-only">
            Result
          </label>
          <Select
            id="audit-result"
            value={result}
            onChange={(e) => update({ result: e.target.value, page: "" })}
          >
            <option value="">Any result</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
          </Select>
        </div>
        <div>
          <label htmlFor="audit-from" className="mb-1 block text-xs text-muted-foreground">
            From
          </label>
          <Input
            id="audit-from"
            type="date"
            value={from}
            max={to || undefined}
            onChange={(e) => update({ from: e.target.value, page: "" })}
          />
        </div>
        <div>
          <label htmlFor="audit-to" className="mb-1 block text-xs text-muted-foreground">
            To
          </label>
          <Input
            id="audit-to"
            type="date"
            value={to}
            min={from || undefined}
            onChange={(e) => update({ to: e.target.value, page: "" })}
          />
        </div>
        {filtered ? (
          <Button variant="ghost" onClick={clear}>
            Clear filters
          </Button>
        ) : null}
        {list.data?.pagination ? (
          <p className="ml-auto text-sm text-muted-foreground" aria-live="polite">
            {list.data.pagination.totalItems}{" "}
            {list.data.pagination.totalItems === 1 ? "entry" : "entries"}
          </p>
        ) : null}
      </div>

      {list.isPending ? <LoadingState label="Loading audit log" /> : null}
      {list.isError ? <QueryErrorState error={list.error} onRetry={list.refetch} /> : null}
      {list.data && list.data.items.length === 0 ? (
        filtered ? (
          <EmptyState
            icon={SearchX}
            title="No matching entries"
            description="Try different filters or a wider date range."
            actions={
              <Button variant="secondary" onClick={clear}>
                Clear filters
              </Button>
            }
          />
        ) : (
          <EmptyState
            icon={ScrollText}
            title="No audit entries yet"
            description="Changes to users, roles, groups and workspaces are recorded here."
          />
        )
      ) : null}
      {list.data && list.data.items.length > 0 ? (
        <>
          <div className="relative overflow-x-auto rounded-md border border-border bg-card">
            <table className="w-full text-left text-[13px] leading-5">
              <caption className="sr-only">Audit log</caption>
              <thead className="border-b border-border text-muted-foreground">
                <tr>
                  <SortHeader
                    label="Time"
                    field="createdAt"
                    sort={sort}
                    onSort={(s) => update({ sort: s === "createdAt:desc" ? "" : s, page: "" })}
                  />
                  <th scope="col" className="px-3 py-2 font-medium">
                    Actor
                  </th>
                  <SortHeader
                    label="Action"
                    field="action"
                    sort={sort}
                    onSort={(s) => update({ sort: s, page: "" })}
                  />
                  <th scope="col" className="px-3 py-2 font-medium">
                    Resource
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Result
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Correlation ID
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    <span className="sr-only">Details</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((entry) => (
                  <tr key={entry.id} className="border-b border-border last:border-0 align-top">
                    <td className="px-3 py-2 whitespace-nowrap">{when(entry.createdAt)}</td>
                    <td className="px-3 py-2">
                      {entry.actor?.name ?? entry.actor?.type ?? "System"}
                      {entry.actor?.email ? (
                        <span className="block text-xs text-muted-foreground">
                          {entry.actor.email}
                        </span>
                      ) : null}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs">{entry.action}</td>
                    <td className="px-3 py-2">
                      {entry.target.type ?? "—"}
                      {entry.target.id ? (
                        <span className="block font-mono text-xs text-muted-foreground">
                          {entry.target.id}
                        </span>
                      ) : null}
                    </td>
                    <td className="px-3 py-2">
                      <Outcome result={entry.result} />
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                      {entry.correlationId ?? "—"}
                    </td>
                    <td className="px-3 py-2">
                      <Details entry={entry} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager pagination={list.data.pagination} onPage={(p) => update({ page: String(p) })} />
        </>
      ) : null}
    </>
  );
}
