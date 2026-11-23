import { Combobox } from "@qmentisai/ui";
import { ExternalLink, GripVertical, MoveRight, Wrench } from "lucide-react";
import { useRef, useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { cn } from "@/lib/cn.js";
import { useListParams } from "@/hooks/use-page-list.js";
import {
  BOARD_COLUMNS,
  BOARD_COLUMN_META,
  REASONS,
  SEVERITY_OPTIONS,
  SLA_OPTIONS,
} from "../constants/index.js";
import {
  describeActionError,
  useBindMockActor,
  useBoard,
  useFindingAction,
  useFindingList,
  usePipelineOptions,
} from "../hooks/use-findings.js";
import { useMediaQuery } from "../hooks/use-media-query.js";
import { readFindingFilters, sortParam, toListQuery } from "../schemas/filters.js";
import { findingsService, newIdempotencyKey } from "../services/findings-service.js";
import { AssignDialog, SubmitFixDialog } from "./action-dialogs.jsx";
import { FindingsTable } from "./findings-table.jsx";
import { Person, RecurrenceIcon, SeverityBadge, SlaChip, Untrusted } from "./finding-bits.jsx";

const SYSTEM_TEXT = "Only a complete scan can verify or reopen a finding.";

/**
 * The moves a card may make (SCREENS 10): the UI mirrors the server, which decides. `canRemediate` is the server's flag for this
 * card; assigning needs `finding.assign`. Columns that only scans set (Verified fixed, Reopened, out of Fixed pending verification)
 * are never targets.
 * @param {string} column @param {{ canRemediate: boolean }} card @param {(key: string) => boolean} can
 * @returns {{ moves: Array<{ to: string, label: string }>, reason: string | null }}
 */
export function movesFor(column, card, can) {
  // SPEC 5.13: a deleted pipeline only blocks submitting a fix (no scan can verify it). The server's `canRemediate` is false for such
  // a card, so the board offers no move; Start work stays available on the finding page (its `allowedActions`). Assigning a reopened
  // card is not affected.
  if (card.pipeline?.deleted && ["assigned", "in_remediation"].includes(column))
    return {
      moves: [],
      reason:
        "The pipeline was deleted, so no scan can verify a fix. Open the finding for the other actions.",
    };
  if (column === "assigned" || column === "in_remediation") {
    if (!card.canRemediate) return { moves: [], reason: REASONS.own_only };
    return {
      moves: [
        ...(column === "assigned" ? [{ to: "in_remediation", label: "In progress" }] : []),
        { to: "fixed_pending_verification", label: "Fixed, pending verification" },
      ],
      reason: null,
    };
  }
  if (column === "reopened") {
    return can("finding.assign")
      ? { moves: [{ to: "assigned", label: "Assigned" }], reason: null }
      : { moves: [], reason: REASONS.no_assign };
  }
  return { moves: [], reason: null };
}

const isHttps = (url) => typeof url === "string" && /^https:\/\/[^\s]+$/.test(url);

/**
 * The pull request link and ticket key of the latest submitted fix (SPEC 0.5 OD-10; both optional and nullable on the card). The
 * link is a real anchor only for an `https` URL (opens in a new tab, `noopener noreferrer`); anything else is shown as plain text.
 * The ticket key is an identifier (mono) and not a link: the platform knows no ticket system.
 * @param {{ card: { pullRequestUrl?: string | null, ticketKey?: string | null } }} props
 */
function CardFixLinks({ card }) {
  const { pullRequestUrl, ticketKey } = card;
  if (!pullRequestUrl && !ticketKey) return null;
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
      {pullRequestUrl ? (
        isHttps(pullRequestUrl) ? (
          <a
            href={pullRequestUrl}
            target="_blank"
            rel="noopener noreferrer"
            draggable={false}
            className="inline-flex items-center gap-1 rounded-sm underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            Pull request
            <ExternalLink aria-hidden="true" className="size-3" />
            <span className="sr-only"> (opens in a new tab)</span>
          </a>
        ) : (
          <Untrusted className="break-all">{pullRequestUrl}</Untrusted>
        )
      ) : null}
      {ticketKey ? (
        <span className="inline-flex items-center gap-1 text-muted-foreground">
          <span className="sr-only">Ticket</span>
          <span className="font-mono">{ticketKey}</span>
        </span>
      ) : null}
    </div>
  );
}

/** One card: severity, title (a link), repository, assignee, SLA, recurrence; a "Move to" menu and, when allowed, a drag handle. */
function BoardCard({ card, column, workspaceId, can, onMove, onDragStart, onDragEnd, dragging }) {
  const { moves, reason } = movesFor(column, card, can);
  const [menuOpen, setMenuOpen] = useState(false);
  const draggable = moves.length > 0;
  return (
    // A card is a focus stop with its own keys (M opens "Move to", Enter opens the finding) and a draggable region: a
    // group with a keyboard model, so the non-interactive rules do not apply. The menu button is the keyboard path.
    /* eslint-disable jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/no-noninteractive-tabindex */
    <li
      tabIndex={0}
      aria-disabled={!draggable || undefined}
      aria-keyshortcuts={draggable ? "M" : undefined}
      data-card=""
      data-column={column}
      draggable={draggable}
      onDragStart={(e) => {
        if (!draggable) return;
        e.dataTransfer.effectAllowed = "move";
        e.dataTransfer.setData("text/plain", card.id);
        onDragStart(card, column);
      }}
      onDragEnd={onDragEnd}
      onKeyDown={(e) => {
        if (e.target !== e.currentTarget) return;
        if (e.key === "m" || e.key === "M") {
          if (draggable) {
            e.preventDefault();
            setMenuOpen(true);
          }
        } else if (e.key === "Enter") {
          e.currentTarget.querySelector("a")?.click();
        }
      }}
      className={cn(
        "space-y-2 rounded-md border border-border bg-card p-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring",
        dragging && "opacity-50",
        card.pendingMove && "border-border-strong",
      )}
    >
      <div className="flex items-center gap-2">
        {draggable ? (
          <GripVertical
            aria-hidden="true"
            className="size-4 shrink-0 cursor-grab text-muted-foreground"
          />
        ) : null}
        <SeverityBadge severity={card.severity} />
        <span className="ml-auto flex items-center gap-1">
          <RecurrenceIcon count={card.reopenCount} />
        </span>
      </div>
      <Link
        to={`/workspaces/${workspaceId}/findings/${card.id}`}
        className="line-clamp-2 block font-medium underline-offset-2 outline-none hover:underline focus-visible:underline"
        draggable={false}
      >
        <Untrusted>{card.title}</Untrusted>
      </Link>
      <div className="truncate text-xs text-muted-foreground">{card.repository.fullName}</div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Person user={card.assignee} />
        <SlaChip sla={card.sla} />
      </div>
      <CardFixLinks card={card} />
      {draggable ? (
        <DropdownMenu open={menuOpen} onOpenChange={setMenuOpen}>
          <DropdownMenuTrigger asChild>
            <Button size="sm" variant="secondary" aria-label={`Move to, ${card.title}`}>
              <MoveRight aria-hidden="true" />
              Move to
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            {moves.map((m) => (
              <DropdownMenuItem key={m.to} onSelect={() => onMove(card, column, m.to)}>
                {m.label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : reason ? (
        <DisabledWithReason reason={reason}>
          <Button size="sm" variant="secondary">
            <MoveRight aria-hidden="true" />
            Move to
          </Button>
        </DisabledWithReason>
      ) : null}
    </li>
  );
}

/** A column: a labelled list with the count, the drop zone and "Load more" past the first 25. */
function BoardColumn({
  id,
  data,
  workspaceId,
  can,
  drag,
  onMove,
  onDragStart,
  onDragEnd,
  onDrop,
  params,
}) {
  const meta = BOARD_COLUMN_META[id];
  const [extra, setExtra] = useState({ items: [], cursor: undefined, done: false });
  const [loading, setLoading] = useState(false);
  const headingId = `board-${id}`;
  const items = [...data.items, ...extra.items];
  const cursor = extra.done ? null : (extra.cursor ?? data.nextCursor);
  const target = drag && drag.from !== id;
  const allowed = drag?.moves?.some((m) => m.to === id);
  const system = id === "verified_fixed" || id === "reopened";
  const loadMore = async () => {
    setLoading(true);
    try {
      const page = await findingsService.boardColumn(id, {
        workspaceId,
        ...params,
        cursor,
        limit: 25,
      });
      setExtra((e) => ({
        items: [...e.items, ...page.items],
        cursor: page.pagination?.nextCursor ?? null,
        done: !page.pagination?.nextCursor,
      }));
    } catch (error) {
      toast.error(describeActionError(error).text);
    } finally {
      setLoading(false);
    }
  };
  return (
    <section
      aria-labelledby={headingId}
      data-column-id={id}
      onDragOver={(e) => {
        if (drag) e.preventDefault();
      }}
      onDrop={(e) => {
        e.preventDefault();
        onDrop(id);
      }}
      className={cn(
        "flex min-h-0 w-72 shrink-0 flex-col rounded-md border bg-secondary/40 min-[1280px]:w-auto min-[1280px]:min-w-60 min-[1280px]:flex-1",
        target && allowed ? "border-foreground border-dashed" : "border-border",
      )}
    >
      <header className="border-b border-border px-3 py-2">
        <h2 id={headingId} className="text-sm font-semibold">
          {meta.label} <span className="font-normal text-muted-foreground">({data.count})</span>
        </h2>
        {meta.note ? <p className="text-xs text-muted-foreground">{meta.note}</p> : null}
        {target && system ? (
          <p className="text-xs font-medium text-muted-foreground">Set by scans</p>
        ) : null}
        {target && !system && !allowed ? (
          <p className="text-xs text-muted-foreground">Not allowed from here</p>
        ) : null}
      </header>
      <ul
        aria-labelledby={headingId}
        className="qm-scroll min-h-0 flex-1 space-y-2 overflow-y-auto p-2"
      >
        {items.length === 0 ? (
          <li className="px-1 py-4 text-center text-sm text-muted-foreground">Nothing here</li>
        ) : null}
        {items.map((card) => (
          <BoardCard
            key={card.id}
            card={card}
            column={id}
            workspaceId={workspaceId}
            can={can}
            onMove={onMove}
            onDragStart={onDragStart}
            onDragEnd={onDragEnd}
            dragging={drag?.card.id === card.id}
          />
        ))}
        {cursor ? (
          <li className="text-center">
            <Button size="sm" variant="secondary" onClick={loadMore} disabled={loading}>
              {loading ? "Loading…" : `Load more (${data.count - items.length} more)`}
            </Button>
          </li>
        ) : null}
      </ul>
    </section>
  );
}

function BoardSkeleton() {
  return (
    <div role="status" aria-busy="true" className="flex min-h-0 flex-1 gap-3 overflow-hidden">
      <span className="sr-only">Loading the board…</span>
      {BOARD_COLUMNS.map((c) => (
        <div key={c} className="w-72 shrink-0 space-y-2 rounded-md border border-border p-2">
          <Skeleton className="h-6 w-40" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      ))}
    </div>
  );
}

function BoardFilters({ filters, onChange, pipelines, view, onView }) {
  return (
    <div className="mb-3 flex shrink-0 flex-wrap items-end gap-3">
      <div
        className="inline-flex rounded-md border border-border-strong p-0.5"
        role="radiogroup"
        aria-label="View"
      >
        {[
          ["board", "Board"],
          ["table", "Table"],
        ].map(([value, label]) => (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={view === value}
            onClick={() => onView(value)}
            className={cn(
              "rounded-sm px-3 py-1 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring",
              view === value
                ? "bg-secondary text-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="w-40">
        <span id="rb-assignee" className="mb-1 block text-xs text-muted-foreground">
          Assignee
        </span>
        <Combobox
          aria-labelledby="rb-assignee"
          options={[{ value: "me", label: "Me" }]}
          value={filters.assignee || null}
          onChange={(v) => onChange({ assignee: v ?? "" })}
          placeholder="Anyone"
          searchable={false}
          clearable
        />
      </div>
      <div className="w-40">
        <span id="rb-sev" className="mb-1 block text-xs text-muted-foreground">
          Severity
        </span>
        <Combobox
          aria-labelledby="rb-sev"
          options={SEVERITY_OPTIONS}
          value={filters.severity[0] ?? null}
          onChange={(v) => onChange({ severity: v ? [v] : [] })}
          placeholder="All severities"
          searchable={false}
          clearable
        />
      </div>
      <div className="w-52">
        <span id="rb-pipe" className="mb-1 block text-xs text-muted-foreground">
          Pipeline
        </span>
        <Combobox
          aria-labelledby="rb-pipe"
          options={(pipelines ?? []).map((p) => ({ value: p.id, label: p.name }))}
          value={filters.pipeline || null}
          onChange={(v) => onChange({ pipeline: v ?? "" })}
          placeholder="All pipelines"
          clearable
        />
      </div>
      <div className="w-40">
        <span id="rb-sla" className="mb-1 block text-xs text-muted-foreground">
          SLA
        </span>
        <Combobox
          aria-labelledby="rb-sla"
          options={SLA_OPTIONS}
          value={filters.sla[0] ?? null}
          onChange={(v) => onChange({ sla: v ? [v] : [] })}
          placeholder="Any"
          searchable={false}
          clearable
        />
      </div>
    </div>
  );
}

/**
 * T-36 body (SCREENS 10): five columns, drag only where the server allows it and always a "Move to" menu (`M` on a focused card),
 * arrow keys between cards and columns, a live region for every move, a column selector on phones, and a Table view.
 * @param {{ workspaceId: string }} props
 */
export function RemediationBoard({ workspaceId }) {
  useBindMockActor(workspaceId);
  const can = useCan();
  const { searchParams, update, page, pageSize, setPage, setPageSize } = useListParams();
  const filters = readFindingFilters(searchParams);
  const view = searchParams.get("view") === "table" ? "table" : "board";
  const narrow = !useMediaQuery("(min-width: 768px)");
  const pipelines = usePipelineOptions(workspaceId);
  const act = useFindingAction(workspaceId);
  const [drag, setDrag] = useState(null);
  const [dialog, setDialog] = useState(null);
  const [announcement, setAnnouncement] = useState("");
  const [phoneColumn, setPhoneColumn] = useState("assigned");
  const boardRef = useRef(null);

  const boardParams = {
    assignee: filters.assignee || undefined,
    severity: filters.severity.join(",") || undefined,
    pipelineId: filters.pipeline || undefined,
    sla: filters.sla.join(",") || undefined,
  };
  const board = useBoard(workspaceId, boardParams, { enabled: view === "board" });
  const tableQuery = useFindingList(
    workspaceId,
    { ...toListQuery(filters, ""), status: BOARD_COLUMNS.join(",") },
    { page, pageSize, setPage },
    { enabled: view === "table" },
  );
  const hasFilters = Boolean(
    filters.assignee || filters.severity.length || filters.pipeline || filters.sla.length,
  );
  const clear = () => update({ assignee: "", severity: [], pipeline: "", sla: [] });

  const refuse = (text) => {
    toast.error(text);
    setAnnouncement(text);
  };
  const run = async (card, to) => {
    try {
      await act.mutateAsync({
        run: (s) => s.startRemediation(card.id, { expectedRev: card.rev }, newIdempotencyKey()),
      });
      const label = BOARD_COLUMN_META[to].label;
      setAnnouncement(`Moved to ${label}`);
      toast.success(`Moved to ${label}`);
    } catch (error) {
      refuse(describeActionError(error).text);
    }
  };
  const move = (card, from, to) => {
    setDrag(null);
    if (to === from) return;
    const { moves, reason } = movesFor(from, card, can);
    if (
      to === "verified_fixed" ||
      to === "reopened" ||
      from === "fixed_pending_verification" ||
      from === "verified_fixed"
    )
      return refuse(SYSTEM_TEXT);
    if (!moves.some((m) => m.to === to)) return refuse(reason ?? "That move isn't allowed.");
    if (to === "in_remediation") return run(card, to);
    if (to === "fixed_pending_verification") return setDialog({ type: "fix", card });
    if (to === "assigned") return setDialog({ type: "assign", card });
    return undefined;
  };

  const onKeyDown = (event) => {
    if (event.target.dataset.card === undefined) return;
    const key = event.key;
    if (!["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(key)) return;
    const card = event.target;
    const columnEl = card.closest("[data-column-id]");
    const siblings = [...columnEl.querySelectorAll("[data-card]")];
    const idx = siblings.indexOf(card);
    let next = null;
    if (key === "ArrowDown") next = siblings[idx + 1];
    if (key === "ArrowUp") next = siblings[idx - 1];
    if (key === "ArrowLeft" || key === "ArrowRight") {
      const columns = [...boardRef.current.querySelectorAll("[data-column-id]")];
      const at = columns.indexOf(columnEl);
      for (
        let i = at + (key === "ArrowRight" ? 1 : -1);
        i >= 0 && i < columns.length;
        i += key === "ArrowRight" ? 1 : -1
      ) {
        const cards = columns[i].querySelectorAll("[data-card]");
        if (cards.length) {
          next = cards[Math.min(idx, cards.length - 1)];
          break;
        }
      }
    }
    if (next) {
      event.preventDefault();
      next.focus();
    }
  };

  const columns = board.data?.columns;
  const total = columns ? BOARD_COLUMNS.reduce((n, c) => n + columns[c].count, 0) : 0;
  const empty = (
    <EmptyState
      icon={Wrench}
      title={hasFilters ? "No work matches these filters" : "No remediation work yet"}
      description={
        hasFilters
          ? "No remediation work matches these filters."
          : "No remediation work yet. Findings appear here after a lead assigns them."
      }
      actions={
        hasFilters ? (
          <Button variant="secondary" onClick={clear}>
            Clear filters
          </Button>
        ) : null
      }
    />
  );

  const dragState = drag ? { ...drag, moves: movesFor(drag.from, drag.card, can).moves } : null;
  const shown = narrow ? [phoneColumn] : BOARD_COLUMNS;

  return (
    <>
      <div className="sr-only" role="status" aria-live="polite">
        {announcement}
      </div>
      <BoardFilters
        filters={filters}
        onChange={update}
        pipelines={pipelines.data}
        view={view}
        onView={(v) => update({ view: v === "board" ? "" : v })}
      />
      {view === "table" ? (
        <FindingsTable
          workspaceId={workspaceId}
          query={tableQuery}
          sort={sortParam(filters.sort, filters.dir) || "severity:desc"}
          onSort={(next) => update({ sort: next === "severity:desc" ? "" : next })}
          pagination={tableQuery.pagination}
          onPage={setPage}
          onPageSize={setPageSize}
          emptyState={empty}
          selectable={false}
          narrow={narrow}
          caption="Remediation work"
        />
      ) : board.isPending ? (
        <BoardSkeleton />
      ) : board.isError ? (
        <QueryErrorState error={board.error} onRetry={board.refetch} />
      ) : total === 0 ? (
        empty
      ) : (
        <>
          {narrow ? (
            <div
              role="tablist"
              aria-label="Board columns"
              className="mb-3 flex shrink-0 gap-1 overflow-x-auto"
            >
              {BOARD_COLUMNS.map((c) => (
                <button
                  key={c}
                  type="button"
                  role="tab"
                  aria-selected={phoneColumn === c}
                  onClick={() => setPhoneColumn(c)}
                  className={cn(
                    "shrink-0 rounded-sm border px-3 py-1.5 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring",
                    phoneColumn === c
                      ? "border-foreground bg-secondary"
                      : "border-border text-muted-foreground",
                  )}
                >
                  {BOARD_COLUMN_META[c].label} ({columns[c].count})
                </button>
              ))}
            </div>
          ) : null}
          {/* arrow keys between cards and columns (a roving model over the cards' own focus stops) */}
          {/* eslint-disable-next-line jsx-a11y/no-static-element-interactions */}
          <div
            ref={boardRef}
            onKeyDown={onKeyDown}
            aria-label="Remediation board"
            className="qm-scroll flex min-h-0 flex-1 gap-3 overflow-x-auto pb-2"
          >
            {shown.map((id) => (
              <BoardColumn
                key={id}
                id={id}
                data={columns[id]}
                workspaceId={workspaceId}
                can={can}
                drag={dragState}
                params={boardParams}
                onMove={move}
                onDragStart={(card, from) => setDrag({ card, from })}
                onDragEnd={() => setDrag(null)}
                onDrop={(to) => drag && move(drag.card, drag.from, to)}
              />
            ))}
          </div>
        </>
      )}
      {dialog?.type === "fix" ? (
        <SubmitFixDialog
          workspaceId={workspaceId}
          finding={dialog.card}
          onClose={() => setDialog(null)}
          onDone={() => setAnnouncement("Moved to Fixed, pending verification")}
        />
      ) : null}
      {dialog?.type === "assign" ? (
        <AssignDialog
          workspaceId={workspaceId}
          finding={dialog.card}
          onClose={() => setDialog(null)}
        />
      ) : null}
    </>
  );
}
