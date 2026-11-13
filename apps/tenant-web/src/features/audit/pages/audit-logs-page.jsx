import { AppPageLayout } from "@qmentisai/ui";
import { CircleCheck, CircleX, ScrollText, SearchX } from "lucide-react";
import { useSearchParams } from "react-router";
import { QueryTable } from "@/components/common/query-table.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useUserSearch } from "@/features/directory/hooks/use-directory.js";
import { TENANT_AUDIT_ACTIONS } from "../constants/index.js";
import { useAuditLogs } from "../hooks/use-audit-logs.js";

const PAGE_SIZE = 25; // rows per "Load more" request
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

const COLUMNS = [
  {
    id: "createdAt",
    header: "Time",
    sortDescFirst: false,
    accessorFn: () => null,
    meta: { className: "whitespace-nowrap" },
    cell: ({ row: { original: entry } }) => when(entry.createdAt),
  },
  {
    id: "actor",
    header: "Actor",
    enableSorting: false,
    cell: ({ row: { original: entry } }) => (
      <>
        {entry.actor?.name ?? entry.actor?.type ?? "System"}
        {entry.actor?.email ? (
          <span className="block text-xs text-muted-foreground">{entry.actor.email}</span>
        ) : null}
      </>
    ),
  },
  {
    id: "action",
    header: "Action",
    sortDescFirst: false,
    accessorFn: () => null,
    cell: ({ row: { original: entry } }) => (
      <span className="font-mono text-xs">{entry.action}</span>
    ),
  },
  {
    id: "resource",
    header: "Resource",
    enableSorting: false,
    cell: ({ row: { original: entry } }) => (
      <>
        {entry.target.type ?? "—"}
        {entry.target.id ? (
          <span className="block font-mono text-xs text-muted-foreground">{entry.target.id}</span>
        ) : null}
      </>
    ),
  },
  {
    id: "result",
    header: "Result",
    enableSorting: false,
    cell: ({ row: { original: entry } }) => <Outcome result={entry.result} />,
  },
  {
    id: "correlationId",
    header: "Correlation ID",
    enableSorting: false,
    cell: ({ row: { original: entry } }) => (
      <span className="font-mono text-xs text-muted-foreground">{entry.correlationId ?? "—"}</span>
    ),
  },
  {
    id: "details",
    header: () => <span className="sr-only">Details</span>,
    enableSorting: false,
    cell: ({ row: { original: entry } }) => <Details entry={entry} />,
  },
];

/**
 * T-19 Audit logs: the organization's audit log (needs `audit_log.view_all`; the API scopes it to the session's tenant).
 * Filters (actor, action, date range, result), and sorting live in the URL; rows load with "Load more" (cursor), no totals are shown.
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
    limit: PAGE_SIZE,
  });
  const clear = () => setParams({}, { replace: true });

  return (
    <AppPageLayout
      title="Audit logs"
      description="Who did what in this organization. Entries cannot be changed or deleted."
      scroll={false}
    >
      <div className="mb-4 flex shrink-0 flex-wrap items-end gap-3">
        <div className="w-52">
          <label htmlFor="audit-action" className="sr-only">
            Action
          </label>
          <Select
            id="audit-action"
            value={action}
            onChange={(e) => update({ action: e.target.value })}
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
              onChange={(e) => update({ actor: e.target.value })}
            >
              <option value="">All actors</option>
              {(users.data ?? []).map((u) => (
                <option key={u.userId} value={u.userId}>
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
            onChange={(e) => update({ result: e.target.value })}
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
            onChange={(e) => update({ from: e.target.value })}
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
            onChange={(e) => update({ to: e.target.value })}
          />
        </div>
        {filtered ? (
          <Button variant="ghost" onClick={clear}>
            Clear filters
          </Button>
        ) : null}
      </div>
      <QueryTable
        caption="Audit log"
        query={list}
        columns={COLUMNS}
        getRowId={(entry) => entry.id}
        sort={sort}
        onSort={(s) => update({ sort: s === "createdAt:desc" ? "" : s })}
        hasMore={list.hasMore}
        loadingMore={list.loadingMore}
        onLoadMore={list.loadMore}
        emptyState={
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
        }
      />
    </AppPageLayout>
  );
}
