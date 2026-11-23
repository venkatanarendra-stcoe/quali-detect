import { Combobox, Pagination } from "@qmentisai/ui";
import { CircleCheck, UserX } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { QueryTable } from "@/components/common/query-table.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { absoluteTime } from "@/features/executions/components/execution-bits.jsx";
import { useListParams } from "@/hooks/use-page-list.js";
import { REASONS, SEVERITY_OPTIONS, SEVERITY_LABELS } from "../constants/index.js";
import {
  useApprovalQueue,
  useBindMockActor,
  useFinding,
  usePipelineOptions,
} from "../hooks/use-findings.js";
import { useMediaQuery } from "../hooks/use-media-query.js";
import { readFindingFilters, readId } from "../schemas/filters.js";
import { AiAdvisoryCard } from "./ai-advisory-card.jsx";
import { DecideDialog } from "./action-dialogs.jsx";
import { EvidencePanel } from "./code-viewer.jsx";
import { Person, SeverityBadge, SlaChip, TimeAgo, Untrusted } from "./finding-bits.jsx";

const KIND_OPTIONS = [
  { value: "review", label: "Decisions (true or false positive)" },
  { value: "exception", label: "Exceptions (accepted risk or suppression)" },
];

/** The decision as a neutral outlined chip (never a status colour) and, for the SOD case, the icon and words (never colour only). */
function DecisionCell({ item }) {
  const label =
    item.kind === "review"
      ? item.decision === "false_positive"
        ? "False positive"
        : "True positive"
      : item.exceptionKind === "suppress"
        ? "Suppression"
        : `Accepted risk${item.expiresAt ? ` until ${absoluteTime(item.expiresAt, { dateStyle: "medium" })}` : ""}`;
  return (
    <div className="space-y-1">
      <span className="inline-flex items-center rounded-sm border border-border-strong px-1.5 py-0.5 text-xs font-medium whitespace-nowrap">
        {label}
      </span>
      {item.cannotDecideReason === "separation_of_duties" ? (
        <div className="flex items-center gap-1 text-xs text-muted-foreground">
          <UserX aria-hidden="true" className="size-3.5" />
          Needs another approver
        </div>
      ) : null}
    </div>
  );
}

const columns = [
  {
    id: "finding",
    header: "Finding",
    enableSorting: false,
    meta: { className: "min-w-56 max-w-96" },
    cell: ({ row: { original: i } }) => (
      <div className="space-y-1">
        <SeverityBadge severity={i.finding.severity} />
        <div className="line-clamp-2 font-medium">
          <Untrusted>{i.finding.title}</Untrusted>
        </div>
      </div>
    ),
  },
  {
    id: "decision",
    header: "Decision",
    enableSorting: false,
    cell: ({ row: { original: i } }) => <DecisionCell item={i} />,
  },
  {
    id: "by",
    header: "Submitted by",
    enableSorting: false,
    meta: { className: "hidden min-[1280px]:table-cell" },
    cell: ({ row: { original: i } }) => <Person user={i.requestedBy} />,
  },
  {
    id: "rationale",
    header: "Rationale",
    enableSorting: false,
    meta: { className: "hidden max-w-80 min-[1280px]:table-cell" },
    cell: ({ row: { original: i } }) => (
      <Untrusted className="line-clamp-2 text-muted-foreground">{i.rationalePreview}</Untrusted>
    ),
  },
  {
    id: "submitted",
    header: "Submitted",
    enableSorting: false,
    cell: ({ row: { original: i } }) => <TimeAgo value={i.submittedAt} />,
  },
  {
    id: "sla",
    header: "SLA",
    enableSorting: false,
    cell: ({ row: { original: i } }) => <SlaChip sla={i.finding.sla} />,
  },
];

/** The right sheet: evidence, rationale, the advisory (read only, as context) and Approve / Reject (SCREENS 9). */
function ApprovalSheet({ workspaceId, item, onClose, onDecided }) {
  const query = useFinding(workspaceId, item.finding.id);
  const [dialog, setDialog] = useState(null);
  const finding = query.data;
  const request = {
    kind: item.kind,
    requestId: item.requestId,
    decision: item.decision,
    exceptionKind: item.exceptionKind,
  };
  const sod = item.cannotDecideReason === "separation_of_duties";
  const reason = sod
    ? item.kind === "exception"
      ? REASONS.sod_exception
      : REASONS.sod_review
    : null;
  const decide = item.cannotDecideReason !== "missing_permission";
  const detail = finding?.review.current ?? null;
  const exc = finding?.exception ?? null;
  return (
    <>
      <SheetTitle className="pr-6 text-base font-semibold">
        <Untrusted>{item.finding.title}</Untrusted>
      </SheetTitle>
      <SheetDescription className="sr-only">
        Review the request and approve or reject it.
      </SheetDescription>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={item.finding.severity} />
        <DecisionCell item={item} />
      </div>
      <p className="text-sm text-muted-foreground">
        Submitted by {item.requestedBy.displayName} <TimeAgo value={item.submittedAt} />
      </p>
      {query.isPending ? (
        <div role="status" aria-busy="true" className="space-y-3">
          <span className="sr-only">Loading finding…</span>
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      ) : query.isError ? (
        <QueryErrorState error={query.error} onRetry={query.refetch} />
      ) : (
        <div className="space-y-4">
          <section
            aria-label="Rationale"
            className="rounded-md border border-border bg-card p-3 text-sm"
          >
            <h3 className="mb-1 text-sm font-semibold">
              {item.kind === "review" ? "Rationale" : "Justification"}
            </h3>
            <Untrusted className="block">
              {detail?.rationale ?? exc?.justification ?? item.rationalePreview}
            </Untrusted>
            {detail?.severityOverride ? (
              <p className="mt-2 text-muted-foreground">
                Proposed severity change: {SEVERITY_LABELS[finding.toolSeverity]} to{" "}
                {SEVERITY_LABELS[detail.severityOverride]}.
              </p>
            ) : null}
            {exc?.expiresAt ? (
              <p className="mt-2 text-muted-foreground">
                Expires {absoluteTime(exc.expiresAt, { dateStyle: "medium" })}.
              </p>
            ) : null}
          </section>
          <EvidencePanel finding={finding} compact />
          <AiAdvisoryCard advisory={finding.advisory} secret={finding.scanType === "secrets"} />
          <Link
            to={`/workspaces/${workspaceId}/findings/${finding.id}?tab=history`}
            className="text-sm underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            See the finding history
          </Link>
        </div>
      )}
      <div className="mt-auto flex flex-wrap items-center justify-end gap-2 border-t border-border pt-4">
        {decide && finding ? (
          <>
            <DisabledWithReason reason={reason}>
              <Button variant="secondary" onClick={() => setDialog("reject")}>
                Reject with comment
              </Button>
            </DisabledWithReason>
            <DisabledWithReason reason={reason}>
              <Button onClick={() => setDialog("approve")}>Approve</Button>
            </DisabledWithReason>
          </>
        ) : !decide ? (
          <p className="text-sm text-muted-foreground">You can see this queue but not decide.</p>
        ) : null}
      </div>
      {dialog && finding ? (
        <DecideDialog
          workspaceId={workspaceId}
          finding={finding}
          request={request}
          mode={dialog}
          onClose={() => setDialog(null)}
          onReload={() => query.refetch()}
          onDone={() => onDecided(dialog)}
        />
      ) : null}
      <Button variant="ghost" className="sr-only" onClick={onClose}>
        Close
      </Button>
    </>
  );
}

function ApprovalCards({ query, onOpen }) {
  const items = query.data?.items ?? [];
  if (query.isPending)
    return (
      <div role="status" className="space-y-3">
        <span className="sr-only">Loading approvals…</span>
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-24 w-full" />
        ))}
      </div>
    );
  if (query.isError) return <QueryErrorState error={query.error} onRetry={query.refetch} />;
  return (
    <ul className="space-y-2" aria-label="Approvals">
      {items.map((i) => (
        <li key={i.requestId} className="space-y-2 rounded-md border border-border bg-card p-3">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={i.finding.severity} />
            <SlaChip sla={i.finding.sla} />
          </div>
          <button
            type="button"
            onClick={() => onOpen(i)}
            className="line-clamp-2 w-full rounded-sm text-left text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <Untrusted>{i.finding.title}</Untrusted>
            <span className="sr-only">. Open this request.</span>
          </button>
          <DecisionCell item={i} />
        </li>
      ))}
    </ul>
  );
}

/**
 * T-35 body: the pending decision requests with the right sheet (`request` in the URL). `canDecide` and `cannotDecideReason`
 * come from the server (SOD, SCREENS 9): a disabled Approve with the reason, never a guess.
 * @param {{ workspaceId: string }} props
 */
export function ApprovalsQueue({ workspaceId }) {
  useBindMockActor(workspaceId);
  const { searchParams, update, page, pageSize, setPage, setPageSize } = useListParams();
  const filters = readFindingFilters(searchParams);
  const kind = ["review", "exception"].includes(searchParams.get("kind"))
    ? searchParams.get("kind")
    : "";
  const requestId = readId(searchParams.get("request"));
  const narrow = !useMediaQuery("(min-width: 768px)");
  const wide = useMediaQuery("(min-width: 1024px)");
  const pipelines = usePipelineOptions(workspaceId);
  const [announcement, setAnnouncement] = useState("");
  const list = useApprovalQueue(
    workspaceId,
    {
      kind: kind || undefined,
      severity: filters.severity.join(",") || undefined,
      pipelineId: filters.pipeline || undefined,
    },
    { page, pageSize, setPage },
  );
  const items = list.data?.items ?? [];
  const open = items.find((i) => i.requestId === requestId) ?? null;
  const filtered = Boolean(kind || filters.severity.length || filters.pipeline);
  const openItem = (item) =>
    update({ request: item.requestId, page: page > 1 ? page : "" }, { replace: false });
  const close = () => update({ request: "", page: page > 1 ? page : "" }, { replace: true });

  const empty = filtered ? (
    <EmptyState
      icon={CircleCheck}
      title="No requests match these filters"
      description="No requests match these filters."
      actions={
        <Button
          variant="secondary"
          onClick={() => update({ kind: "", severity: [], pipeline: "" })}
        >
          Clear filters
        </Button>
      }
    />
  ) : (
    <EmptyState
      icon={CircleCheck}
      title="Nothing is waiting"
      description="Nothing is waiting for approval."
    />
  );

  return (
    <>
      <div className="sr-only" role="status" aria-live="polite">
        {announcement}
      </div>
      <div className="mb-3 flex shrink-0 flex-wrap items-end gap-3">
        <div className="w-72">
          <span id="ap-kind" className="mb-1 block text-xs text-muted-foreground">
            Decision type
          </span>
          <Combobox
            aria-labelledby="ap-kind"
            options={KIND_OPTIONS}
            value={kind || null}
            onChange={(v) => update({ kind: v ?? "" })}
            placeholder="All requests"
            searchable={false}
            clearable
          />
        </div>
        <div className="w-44">
          <span id="ap-sev" className="mb-1 block text-xs text-muted-foreground">
            Severity
          </span>
          <Combobox
            aria-labelledby="ap-sev"
            options={SEVERITY_OPTIONS}
            value={filters.severity[0] ?? null}
            onChange={(v) => update({ severity: v ? [v] : [] })}
            placeholder="All severities"
            searchable={false}
            clearable
          />
        </div>
        <div className="w-56">
          <span id="ap-pipe" className="mb-1 block text-xs text-muted-foreground">
            Pipeline
          </span>
          <Combobox
            aria-labelledby="ap-pipe"
            options={(pipelines.data ?? []).map((p) => ({ value: p.id, label: p.name }))}
            value={filters.pipeline || null}
            onChange={(v) => update({ pipeline: v ?? "" })}
            placeholder="All pipelines"
            clearable
          />
        </div>
        {list.pagination.totalItems > 0 ? (
          <p className="pb-2 text-sm text-muted-foreground">{list.pagination.totalItems} waiting</p>
        ) : null}
      </div>
      {narrow ? (
        <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto">
          {!list.isPending && !list.isError && items.length === 0 ? (
            empty
          ) : (
            <ApprovalCards query={list} onOpen={openItem} />
          )}
          {list.pagination.totalPages > 1 ? (
            <Pagination
              page={list.pagination.page}
              totalPages={list.pagination.totalPages}
              totalItems={list.pagination.totalItems}
              pageSize={list.pagination.pageSize}
              onPageChange={setPage}
              itemNoun="requests"
            />
          ) : null}
        </div>
      ) : (
        <QueryTable
          caption="Approvals"
          query={list}
          columns={columns}
          getRowId={(i) => i.requestId}
          pagination={list.pagination}
          onPage={setPage}
          onPageSize={setPageSize}
          emptyState={empty}
          onRowClick={openItem}
          rowLabel={(i) =>
            `${i.finding.title}, ${i.kind === "review" ? "decision" : "exception"} request`
          }
          noun="requests"
        />
      )}
      <Sheet open={Boolean(open)} onOpenChange={(o) => !o && close()}>
        <SheetContent className={wide ? "max-w-xl" : "max-w-none"}>
          {open ? (
            <ApprovalSheet
              workspaceId={workspaceId}
              item={open}
              onClose={close}
              onDecided={(mode) => {
                close();
                setAnnouncement(
                  `${mode === "approve" ? "Approved" : "Rejected"}. The request left the queue.`,
                );
              }}
            />
          ) : null}
        </SheetContent>
      </Sheet>
    </>
  );
}
