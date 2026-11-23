import { Combobox } from "@qmentisai/ui";
import { Pagination } from "@qmentisai/ui";
import { ClipboardList, ExternalLink, SearchX } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { Switch } from "@/components/ui/switch.jsx";
import { useSession } from "@/features/auth/hooks/use-session.js";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { cn } from "@/lib/cn.js";
import { useListParams } from "@/hooks/use-page-list.js";
import { AI_SUGGESTION_OPTIONS, SCAN_TYPE_OPTIONS, SEVERITY_OPTIONS } from "../constants/index.js";
import {
  describeActionError,
  useBindMockActor,
  useFinding,
  useFindingAction,
  usePipelineOptions,
  useReviewQueue,
} from "../hooks/use-findings.js";
import { useMediaQuery } from "../hooks/use-media-query.js";
import { readFindingFilters, readId } from "../schemas/filters.js";
import { newIdempotencyKey } from "../services/findings-service.js";
import { useFindingsUiStore } from "../stores/findings-ui-store.js";
import { AiAdvisoryCard } from "./ai-advisory-card.jsx";
import { EvidencePanel } from "./code-viewer.jsx";
import { DecisionForm } from "./decision-form.jsx";
import {
  AdvisoryHint,
  LocationCell,
  SeverityBadge,
  StatusBadge,
  TimeAgo,
  Untrusted,
} from "./finding-bits.jsx";
import { ConflictBanner } from "./form-bits.jsx";

function Pick({ id, label, children }) {
  return (
    <div className="w-44">
      <span id={id} className="mb-1 block text-xs text-muted-foreground">
        {label}
      </span>
      {children}
    </div>
  );
}

/** Filter strip of T-34: severity, pipeline, scan type, mine / unclaimed, AI suggestion, sort. Writes the URL. */
function QueueFilters({ filters, mode, sort, onChange, pipelines }) {
  const one = (list, value) => list.some((o) => o.value === value);
  return (
    <div className="mb-3 flex shrink-0 flex-wrap items-end gap-3">
      <Pick id="rq-sev" label="Severity">
        <Combobox
          aria-labelledby="rq-sev"
          options={SEVERITY_OPTIONS}
          value={filters.severity[0] ?? null}
          onChange={(v) => onChange({ severity: v && one(SEVERITY_OPTIONS, v) ? [v] : [] })}
          placeholder="All severities"
          searchable={false}
          clearable
        />
      </Pick>
      <Pick id="rq-pipe" label="Pipeline">
        <Combobox
          aria-labelledby="rq-pipe"
          options={(pipelines ?? []).map((p) => ({ value: p.id, label: p.name }))}
          value={filters.pipeline || null}
          onChange={(v) => onChange({ pipeline: v ?? "" })}
          placeholder="All pipelines"
          clearable
        />
      </Pick>
      <Pick id="rq-type" label="Scan type">
        <Combobox
          aria-labelledby="rq-type"
          options={SCAN_TYPE_OPTIONS}
          value={filters.scanType[0] ?? null}
          onChange={(v) => onChange({ scanType: v ? [v] : [] })}
          placeholder="All types"
          searchable={false}
          clearable
        />
      </Pick>
      <Pick id="rq-who" label="Claim">
        <Combobox
          aria-labelledby="rq-who"
          options={[
            { value: "mine", label: "Mine" },
            { value: "unclaimed", label: "Unclaimed" },
          ]}
          value={mode || null}
          onChange={(v) => onChange({ claim: v ?? "" })}
          placeholder="Anyone"
          searchable={false}
          clearable
        />
      </Pick>
      <Pick id="rq-ai" label="AI suggestion">
        <Combobox
          aria-labelledby="rq-ai"
          options={AI_SUGGESTION_OPTIONS}
          value={filters.ai || null}
          onChange={(v) => onChange({ ai: v ?? "" })}
          placeholder="Any"
          searchable={false}
          clearable
        />
      </Pick>
      <Pick id="rq-sort" label="Sort">
        <Combobox
          aria-labelledby="rq-sort"
          options={[
            { value: "oldest", label: "Oldest first" },
            { value: "severity", label: "Severity" },
          ]}
          value={sort}
          onChange={(v) => onChange({ qsort: v === "oldest" ? "" : v })}
          searchable={false}
        />
      </Pick>
    </div>
  );
}

function QueueRow({ item, selected, onSelect, mine }) {
  return (
    // the listbox owns the keyboard (aria-activedescendant, arrow keys, J and K); the click is for the pointer only
    // eslint-disable-next-line jsx-a11y/click-events-have-key-events
    <li
      id={`rq-${item.id}`}
      role="option"
      aria-selected={selected}
      onClick={() => onSelect(item.id)}
      className={cn(
        "cursor-pointer space-y-1.5 border-b border-border px-3 py-2.5 text-sm last:border-b-0 hover:bg-accent",
        selected && "bg-secondary",
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={item.severity} />
        <AdvisoryHint hint={item.advisoryHint} />
      </div>
      <div className="line-clamp-2 font-medium">
        <Untrusted>{item.title}</Untrusted>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
        <span className="truncate">{item.pipeline.name}</span>
        <span className="inline-flex gap-1">
          age <TimeAgo value={item.firstDetectedAt} />
        </span>
        <span>
          {item.status === "in_review"
            ? mine
              ? "In review by you"
              : `In review by ${item.claimedBy?.displayName ?? "someone"}`
            : "Unclaimed"}
        </span>
      </div>
    </li>
  );
}

/** The right panel of T-34: evidence, advisory (above the form, never inside), "Open full detail" and the decision form. */
function ReviewPanel({ workspaceId, findingId, onSubmitted, shortcutRef }) {
  const can = useCan();
  const query = useFinding(workspaceId, findingId);
  const act = useFindingAction(workspaceId);
  const finding = query.data;
  if (query.isPending)
    return (
      <div role="status" aria-busy="true" className="space-y-3">
        <span className="sr-only">Loading finding…</span>
        <Skeleton className="h-6 w-2/3" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  if (query.isError) return <QueryErrorState error={query.error} onRetry={query.refetch} />;
  const actions = Object.fromEntries(finding.lifecycle.allowedActions.map((a) => [a.action, a]));
  const advisoryAction = actions.request_advisory;
  const claim = async () => {
    try {
      await act.mutateAsync({
        run: (s) => s.claim(finding.id, { expectedRev: finding.rev }, newIdempotencyKey()),
      });
      toast.success("Review started");
    } catch (error) {
      toast.error(describeActionError(error).text);
    }
  };
  const takeOver = finding.status === "in_review" && actions.claim;
  return (
    <div className="space-y-4" aria-label={`Review of ${finding.title}`} role="region">
      <div className="space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge
            status={finding.status}
            by={finding.status === "in_review" ? finding.claimedBy?.displayName : null}
          />
        </div>
        <h2 className="text-lg font-semibold">
          <Untrusted>{finding.title}</Untrusted>
        </h2>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground">
          <LocationCell item={finding} />
          <Link
            to={`/workspaces/${workspaceId}/findings/${finding.id}`}
            className="inline-flex items-center gap-1 rounded-sm underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            Open full detail
            <ExternalLink aria-hidden="true" className="size-3.5" />
          </Link>
        </div>
      </div>

      <EvidencePanel finding={finding} compact />
      <AiAdvisoryCard
        advisory={finding.advisory}
        secret={finding.scanType === "secrets"}
        onRequest={
          advisoryAction && finding.scanType !== "secrets"
            ? () => act.mutate({ run: (s) => s.requestAdvisory(finding.id, newIdempotencyKey()) })
            : undefined
        }
        requestDisabledReason={
          advisoryAction && !advisoryAction.allowed ? advisoryAction.disabledReason : null
        }
      />

      <section
        aria-label="Your decision"
        className="space-y-3 rounded-md border border-border bg-card p-4"
      >
        <h3 className="text-sm font-semibold">Your decision</h3>
        {!can("finding.review") ? (
          <p className="text-sm text-muted-foreground">
            You can read this queue but not record decisions.
          </p>
        ) : !actions.record_review ? (
          <ConflictBanner text="This finding is no longer waiting for a decision." />
        ) : (
          <>
            {(actions.claim && finding.status === "new") || takeOver ? (
              <Button variant="secondary" onClick={claim} disabled={act.isPending}>
                {takeOver ? "Take over" : "Start review"}
              </Button>
            ) : null}
            <DecisionForm
              key={finding.id}
              workspaceId={workspaceId}
              finding={finding}
              controlRef={shortcutRef}
              formId="review-decision"
              onDone={() => onSubmitted(finding.id)}
              onReload={() => query.refetch()}
            />
          </>
        )}
      </section>
    </div>
  );
}

function ShortcutLegend({ enabled, onToggle }) {
  return (
    <div className="mt-2 flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1 border-t border-border pt-2 text-xs text-muted-foreground">
      <span>
        <kbd className="font-mono">J</kbd> / <kbd className="font-mono">K</kbd> next and previous
      </span>
      <span>
        <kbd className="font-mono">T</kbd> true positive
      </span>
      <span>
        <kbd className="font-mono">F</kbd> false positive
      </span>
      <span>
        <kbd className="font-mono">R</kbd> rationale
      </span>
      <span>
        <kbd className="font-mono">Ctrl</kbd>+<kbd className="font-mono">Enter</kbd> submit
      </span>
      <div className="ml-auto flex items-center gap-2">
        <span id="rq-shortcuts">Shortcuts</span>
        <Switch checked={enabled} onCheckedChange={onToggle} aria-labelledby="rq-shortcuts" />
      </div>
    </div>
  );
}

/**
 * T-34 body: the queue (a listbox with roving selection) beside the review panel (SCREENS 7). Selection is the URL `finding`;
 * submitting a decision selects the next finding and announces it. Below 1024 px the panel is a full-screen sheet.
 * @param {{ workspaceId: string }} props
 */
export function ReviewQueue({ workspaceId }) {
  useBindMockActor(workspaceId);
  const can = useCan();
  const myId = useSession().me?.user?.id;
  const { searchParams, update, page, pageSize, setPage, setPageSize } = useListParams();
  const filters = readFindingFilters(searchParams);
  const mode = ["mine", "unclaimed"].includes(searchParams.get("claim"))
    ? searchParams.get("claim")
    : "";
  const sort = searchParams.get("qsort") === "severity" ? "severity" : "oldest";
  const selectedId = readId(searchParams.get("finding"));
  const wide = useMediaQuery("(min-width: 1024px)");
  const shortcuts = useFindingsUiStore((s) => s.shortcuts);
  const setShortcuts = useFindingsUiStore((s) => s.setShortcuts);
  const pipelines = usePipelineOptions(workspaceId);
  const control = useRef(null);
  const listRef = useRef(null);
  const [announcement, setAnnouncement] = useState("");

  const params = {
    severity: filters.severity.join(",") || undefined,
    scanType: filters.scanType.join(",") || undefined,
    pipelineId: filters.pipeline || undefined,
    aiSuggestion: filters.ai || undefined,
    sort,
  };
  const queue = useReviewQueue(workspaceId, params, { page, pageSize, setPage });
  const all = queue.data?.items ?? [];
  const items = mode
    ? all.filter((i) =>
        mode === "mine" ? i.status === "in_review" && i.claimedBy?.id === myId : i.status === "new",
      )
    : all;
  const index = items.findIndex((i) => i.id === selectedId);
  // keep `page` when selecting: `update` resets it unless named
  const choose = (id) =>
    update({ finding: id ?? "", page: page > 1 ? page : "" }, { replace: true });

  // default selection: the first finding (desktop only; a phone opens the sheet on tap)
  useEffect(() => {
    if (wide && !selectedId && items.length) choose(items[0].id);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- selection follows the loaded list
  }, [wide, selectedId, items.length, queue.data]);

  const move = (delta) => {
    if (!items.length) return;
    const next = items[Math.min(items.length - 1, Math.max(0, (index < 0 ? 0 : index) + delta))];
    if (next) choose(next.id);
  };

  useEffect(() => {
    if (!shortcuts || !can("finding.review")) return undefined;
    const onKey = (event) => {
      const target = event.target;
      const typing =
        ["INPUT", "TEXTAREA", "SELECT"].includes(target?.tagName) || target?.isContentEditable;
      if (event.key === "Enter" && event.ctrlKey) {
        event.preventDefault();
        control.current?.submit();
        return;
      }
      if (typing || event.ctrlKey || event.metaKey || event.altKey) return;
      const key = event.key.toLowerCase();
      if (key === "j") move(1);
      else if (key === "k") move(-1);
      else if (key === "t") control.current?.setDecision("true_positive");
      else if (key === "f") control.current?.setDecision("false_positive");
      else if (key === "r") {
        event.preventDefault();
        control.current?.focusRationale();
      } else return;
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const onSubmitted = (id) => {
    const at = items.findIndex((i) => i.id === id);
    const next = items[at + 1] ?? items[at - 1];
    if (next) choose(next.id);
    else choose(null);
    setAnnouncement(
      next
        ? "Decision submitted for approval. Next finding selected."
        : "Decision submitted for approval. No more findings in the queue.",
    );
    toast.success("Decision submitted for approval");
  };

  const clear = () => update({ severity: [], pipeline: "", scanType: [], ai: "", claim: "" });
  const filtered = Boolean(
    filters.severity.length || filters.pipeline || filters.scanType.length || filters.ai || mode,
  );
  const panel = selectedId ? (
    <ReviewPanel
      workspaceId={workspaceId}
      findingId={selectedId}
      onSubmitted={onSubmitted}
      shortcutRef={control}
    />
  ) : null;

  return (
    <>
      <div className="sr-only" role="status" aria-live="polite">
        {announcement}
      </div>
      <QueueFilters
        filters={filters}
        mode={mode}
        sort={sort}
        pipelines={pipelines.data}
        onChange={(next) => {
          const { qsort, claim, ...rest } = next;
          update({
            ...rest,
            ...(qsort !== undefined ? { qsort } : {}),
            ...(claim !== undefined ? { claim } : {}),
          });
        }}
      />
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:grid-cols-[minmax(20rem,26rem)_minmax(0,1fr)]">
        <div className="flex min-h-0 flex-col rounded-md border border-border bg-card">
          <div
            className="qm-scroll min-h-0 flex-1 overflow-y-auto"
            aria-busy={queue.isPending || undefined}
          >
            {queue.isPending ? (
              <div role="status" className="space-y-2 p-3">
                <span className="sr-only">Loading the review queue…</span>
                {Array.from({ length: 6 }, (_, i) => (
                  <Skeleton key={i} className="h-20 w-full" />
                ))}
              </div>
            ) : queue.isError ? (
              <QueryErrorState error={queue.error} onRetry={queue.refetch} />
            ) : items.length === 0 ? (
              filtered ? (
                <EmptyState
                  icon={SearchX}
                  title="No findings match these filters"
                  description="No findings in the queue match these filters."
                  actions={
                    <Button variant="secondary" onClick={clear}>
                      Clear filters
                    </Button>
                  }
                />
              ) : (
                <EmptyState
                  icon={ClipboardList}
                  title="The queue is empty"
                  description="No findings are waiting for review. New findings appear here after a scan of the default branch."
                />
              )
            ) : (
              <ul
                ref={listRef}
                role="listbox"
                aria-label="Findings waiting for review"
                aria-activedescendant={selectedId ? `rq-${selectedId}` : undefined}
                tabIndex={0}
                className="outline-none focus-visible:ring-2 focus-visible:ring-ring"
                onKeyDown={(e) => {
                  if (e.key === "ArrowDown") {
                    e.preventDefault();
                    move(1);
                  } else if (e.key === "ArrowUp") {
                    e.preventDefault();
                    move(-1);
                  } else if (e.key === "Enter" && !wide && selectedId) {
                    e.preventDefault();
                  }
                }}
              >
                {items.map((item) => (
                  <QueueRow
                    key={item.id}
                    item={item}
                    selected={item.id === selectedId}
                    onSelect={choose}
                    mine={item.claimedBy?.id === myId}
                  />
                ))}
              </ul>
            )}
          </div>
          {queue.pagination.totalItems > 0 ? (
            <Pagination
              page={queue.pagination.page}
              totalPages={queue.pagination.totalPages}
              totalItems={queue.pagination.totalItems}
              pageSize={queue.pagination.pageSize}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              itemNoun="findings"
            />
          ) : null}
        </div>
        {wide ? (
          <div className="qm-scroll min-h-0 overflow-y-auto pr-1" data-review-panel="">
            {panel ?? (
              <p className="p-6 text-sm text-muted-foreground">Select a finding to review it.</p>
            )}
          </div>
        ) : (
          <Sheet open={Boolean(selectedId)} onOpenChange={(open) => !open && choose(null)}>
            <SheetContent className="max-w-none">
              <SheetTitle className="sr-only">Review finding</SheetTitle>
              <SheetDescription className="sr-only">
                Evidence, advice and your decision.
              </SheetDescription>
              {panel}
            </SheetContent>
          </Sheet>
        )}
      </div>
      {wide && can("finding.review") ? (
        <ShortcutLegend enabled={shortcuts} onToggle={setShortcuts} />
      ) : null}
    </>
  );
}
