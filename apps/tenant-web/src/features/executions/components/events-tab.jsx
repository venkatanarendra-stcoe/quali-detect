import { ArrowRight, History } from "lucide-react";
import { QueryTable } from "@/components/common/query-table.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { EVENT_LABELS, reasonText } from "../constants/index.js";
import { useExecutionEvents } from "../hooks/use-executions.js";
import { ExecutionStatusChip, TimeAgo } from "./execution-bits.jsx";

const columns = [
  {
    id: "at",
    header: "Time",
    cell: ({ row: { original: ev } }) => <TimeAgo value={ev.at} />,
  },
  {
    id: "transition",
    header: "Event",
    cell: ({ row: { original: ev } }) =>
      ev.type === "transition" && ev.toStatus ? (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          {ev.fromStatus ? (
            <>
              <ExecutionStatusChip status={ev.fromStatus} />
              <ArrowRight aria-label="to" className="size-3.5 text-muted-foreground" />
            </>
          ) : null}
          <ExecutionStatusChip status={ev.toStatus} />
        </span>
      ) : (
        (EVENT_LABELS[ev.type] ?? ev.type.replace(/_/g, " "))
      ),
  },
  {
    id: "reason",
    header: "Reason",
    cell: ({ row: { original: ev } }) =>
      reasonText(ev.reason) ?? <span className="text-muted-foreground">—</span>,
  },
  {
    id: "actor",
    header: "By",
    cell: ({ row: { original: ev } }) => (ev.actorType === "user" ? "A team member" : "System"),
  },
];

/** Events tab: the status history, oldest first, cursor "Load more". The API reports the actor kind only, not a name. */
export function EventsTab({ workspaceId, executionId, enabled, live }) {
  const events = useExecutionEvents(workspaceId, executionId, { enabled, live });
  return (
    <QueryTable
      caption="Execution history"
      query={events}
      columns={columns.map((c) => ({ ...c, enableSorting: false }))}
      getRowId={(ev) => String(ev.seq)}
      height="auto"
      maxHeight="28rem"
      noun="events"
      hasMore={events.hasMore}
      loadingMore={events.loadingMore}
      onLoadMore={events.loadMore}
      emptyState={
        <EmptyState
          icon={History}
          title="No history yet"
          description="Status changes appear here."
        />
      }
    />
  );
}
