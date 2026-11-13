import { CircleCheck, CircleX, ScrollText, SearchX } from "lucide-react";
import { AppPageLayout } from "@qmentisai/ui";
import { useMemo } from "react";
import { useSearchParams } from "react-router";
import { QueryTable } from "@/components/common/query-table.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { PLATFORM_AUDIT_ACTIONS } from "../constants/index.js";
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
  const detail = { metadata: entry.metadata, ipAddress: entry.ipAddress };
  return (
    <details>
      <summary className="cursor-pointer text-muted-foreground">Details</summary>
      <pre className="qm-scroll mt-2 max-w-md overflow-x-auto rounded-sm bg-secondary p-2 font-mono text-xs">
        {JSON.stringify(detail, null, 2)}
      </pre>
    </details>
  );
}

/**
 * R-28 Platform audit logs: platform actions such as tenant lifecycle and platform sign-in (needs `platform.audit_log.view`).
 * It never shows a tenant's own audit log. Filters (actor, action, tenant, date range, result), and sorting live in the URL; rows load with "Load more" (cursor), no totals are shown.
 */
export function PlatformAuditLogsPage() {
  const [params, setParams] = useSearchParams();
  const action = params.get("action") ?? "";
  const result = params.get("result") ?? "";
  const actor = params.get("actor") ?? "";
  const tenantId = params.get("tenantId") ?? "";
  const from = params.get("from") ?? "";
  const to = params.get("to") ?? "";
  const sort = params.get("sort") ?? "createdAt:desc";
  const filtered = Boolean(action || result || actor || tenantId || from || to);

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
  const list = useAuditLogs({
    action: action || undefined,
    result: result || undefined,
    actor: actor || undefined,
    tenantId: tenantId || undefined,
    from: from ? startOfDay(from) : undefined,
    to: to ? endOfDay(to) : undefined,
    sort,
    limit: PAGE_SIZE,
  });
  const clear = () => setParams({}, { replace: true });
  const columns = useMemo(
    () => [
      {
        id: "createdAt",
        accessorKey: "createdAt",
        header: "Time",
        sortDescFirst: false,
        meta: { className: "align-top min-w-32" },
        cell: ({ row: { original: e } }) => when(e.createdAt),
      },
      {
        id: "actor",
        header: "Actor",
        enableSorting: false,
        meta: { className: "align-top" },
        cell: ({ row: { original: e } }) => (
          <>
            {e.actor?.name ?? e.actor?.type ?? "System"}
            {e.actor?.email ? (
              <span className="block text-xs text-muted-foreground">{e.actor.email}</span>
            ) : null}
          </>
        ),
      },
      {
        id: "action",
        accessorKey: "action",
        header: "Action",
        sortDescFirst: false,
        meta: { className: "align-top min-w-44 font-mono text-xs [overflow-wrap:anywhere]" },
        cell: ({ row: { original: e } }) => e.action,
      },
      {
        id: "resource",
        header: "Resource",
        enableSorting: false,
        meta: { className: "align-top" },
        cell: ({ row: { original: e } }) => (
          <>
            {e.target.type ?? "—"}
            {e.target.id ? (
              <span className="block font-mono text-xs text-muted-foreground [overflow-wrap:anywhere]">
                {e.target.id}
              </span>
            ) : null}
          </>
        ),
      },
      {
        id: "tenant",
        header: "Tenant",
        enableSorting: false,
        meta: {
          className: "align-top font-mono text-xs text-muted-foreground [overflow-wrap:anywhere]",
        },
        cell: ({ row: { original: e } }) => e.tenantId ?? "—",
      },
      {
        id: "result",
        header: "Result",
        enableSorting: false,
        meta: { className: "align-top" },
        cell: ({ row: { original: e } }) => <Outcome result={e.result} />,
      },
      {
        id: "correlationId",
        header: "Correlation ID",
        enableSorting: false,
        meta: {
          className: "align-top font-mono text-xs text-muted-foreground [overflow-wrap:anywhere]",
        },
        cell: ({ row: { original: e } }) => e.correlationId ?? "—",
      },
      {
        id: "details",
        header: () => <span className="sr-only">Details</span>,
        enableSorting: false,
        meta: { className: "align-top" },
        cell: ({ row: { original: e } }) => <Details entry={e} />,
      },
    ],
    [],
  );

  return (
    <AppPageLayout
      title="Platform audit logs"
      description="Platform actions: tenant lifecycle, platform sign-in and administration. Entries cannot be changed or deleted."
      scroll={false}
      offset="7.5rem"
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
            {PLATFORM_AUDIT_ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </Select>
        </div>
        <div className="w-72">
          <label htmlFor="audit-actor" className="sr-only">
            Actor ID
          </label>
          <Input
            id="audit-actor"
            placeholder="Actor ID (platform user UUID)"
            value={actor}
            onChange={(e) => update({ actor: e.target.value.trim() })}
          />
        </div>
        <div className="w-72">
          <label htmlFor="audit-tenant" className="sr-only">
            Tenant ID
          </label>
          <Input
            id="audit-tenant"
            placeholder="Tenant ID (UUID)"
            value={tenantId}
            onChange={(e) => update({ tenantId: e.target.value.trim() })}
          />
        </div>
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
        query={list}
        columns={columns}
        caption="Platform audit log"
        getRowId={(e) => e.id}
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
              description="Tenant lifecycle changes and platform sign-ins are recorded here."
            />
          )
        }
      />
    </AppPageLayout>
  );
}
