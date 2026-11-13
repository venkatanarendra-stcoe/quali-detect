import { AppPageLayout, AuditTerminal, TerminalMessage, TerminalResult } from "@qmentisai/ui";
import { useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { describeError, isApiError } from "@/lib/api/index.js";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useSession } from "@/features/auth/hooks/use-session.js";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useUserSearch } from "@/features/directory/hooks/use-directory.js";
import { TENANT_AUDIT_ACTIONS } from "../constants/index.js";
import { AuditEntrySheet } from "../components/audit-entry-sheet.jsx";
import { useAuditLogs } from "../hooks/use-audit-logs.js";

const PAGE_SIZE = 25; // rows per "Load more" request
const when = (value) =>
  new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
const startOfDay = (day) => new Date(`${day}T00:00:00`).toISOString();
const endOfDay = (day) => new Date(`${day}T23:59:59.999`).toISOString();

const pad = (n) => String(n).padStart(2, "0");
/** Local `YYYY-MM-DD HH:mm:ss`: fixed width, sortable by eye, and good for copying into tickets. */
const stamp = (value) => {
  const d = new Date(value);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};
const actorName = (entry) => entry.actor?.name ?? entry.actor?.type ?? "System";

const COLUMNS = [
  {
    id: "createdAt",
    header: "timestamp",
    width: "18%",
    sortKey: "createdAt",
    cell: (entry) => stamp(entry.createdAt),
    title: (entry) => when(entry.createdAt),
  },
  {
    id: "actor",
    header: "actor",
    width: "22%",
    cell: (entry) => (
      <>
        {actorName(entry)}
        {entry.actor?.email ? (
          <span className="qm-terminal-muted block">{entry.actor.email}</span>
        ) : null}
      </>
    ),
    title: (entry) => entry.actor?.email ?? actorName(entry),
  },
  {
    id: "action",
    header: "action",
    width: "24%",
    sortKey: "action",
    cell: (entry) => entry.action,
    title: (entry) => entry.action,
  },
  {
    id: "target",
    header: "target",
    width: "22%",
    cell: (entry) => (
      <>
        {entry.target.type ?? "—"}
        {entry.target.id ? (
          <span className="qm-terminal-muted block">{entry.target.id}</span>
        ) : null}
      </>
    ),
    title: (entry) => [entry.target.type, entry.target.id].filter(Boolean).join(" "),
  },
  {
    id: "result",
    header: "result",
    width: "14%",
    cell: (entry) => <TerminalResult tone={entry.result === "failure" ? "failure" : "success"} />,
  },
];

/**
 * T-19 Audit logs: the organization's audit log (needs `audit_log.view_all`; the API scopes it to the session's tenant).
 * Filters (actor, action, date range, result), and sorting live in the URL; rows load with "Load more" (cursor), no totals are shown. Rendered as the audit-log terminal; a row opens the detail sheet.
 */
export function AuditLogsPage() {
  const can = useCan();
  const { me } = useSession();
  const [openId, setOpenId] = useState(null);
  const originRef = useRef(null); // the row that opened the sheet; focus returns to it on close
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
  const entries = list.data?.items ?? [];
  const opened = entries.find((e) => e.id === openId) ?? null;
  const forbidden =
    list.isError &&
    isApiError(list.error) &&
    list.error.status === 403 &&
    list.error.code !== "TENANT_SUSPENDED";
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
      <AuditTerminal
        ariaLabel="Audit log"
        promptLabel={`${me?.tenant?.slug ?? "tenant"}@qmentisai:~$`}
        rows={entries}
        columns={COLUMNS}
        getRowId={(entry) => entry.id}
        rowLabel={(entry) =>
          `${entry.action}, ${actorName(entry)}, ${entry.result}. Press Enter for details.`
        }
        onRowActivate={(entry, element) => {
          originRef.current = element;
          setOpenId(entry.id);
        }}
        selectedId={openId}
        sort={sort}
        onSort={(s) => update({ sort: s === "createdAt:desc" ? "" : s })}
        loading={list.isPending}
        unauthorized={
          forbidden ? (
            <TerminalMessage title="Permission denied" icon="lock">
              You do not have permission to view audit logs. Ask an administrator for access.
            </TerminalMessage>
          ) : undefined
        }
        error={
          list.isError && !forbidden ? (
            <TerminalMessage title="Could not load the audit log" icon="alert" role="alert">
              <p>{describeError(list.error)}</p>
              {isApiError(list.error) && list.error.correlationId ? (
                <p>Reference {list.error.correlationId}</p>
              ) : null}
              <button type="button" className="qm-terminal-retry" onClick={() => list.refetch()}>
                -- retry --
              </button>
            </TerminalMessage>
          ) : undefined
        }
        empty={
          filtered ? (
            <TerminalMessage title="No matching entries">
              Try different filters or a wider date range.{" "}
              <button type="button" className="qm-terminal-retry" onClick={clear}>
                -- clear filters --
              </button>
            </TerminalMessage>
          ) : (
            <TerminalMessage title="No audit entries yet">
              Changes to users, roles, groups and workspaces are recorded here.
            </TerminalMessage>
          )
        }
        hasMore={list.hasMore}
        loadingMore={list.loadingMore}
        onLoadMore={list.loadMore}
      />
      <AuditEntrySheet entry={opened} onClose={() => setOpenId(null)} returnFocusTo={originRef} />
    </AppPageLayout>
  );
}
