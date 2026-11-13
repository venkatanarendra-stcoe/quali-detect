import { History, ListX } from "lucide-react";
import { useSearchParams } from "react-router";
import { QueryTable } from "@/components/common/query-table.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Select } from "@/components/ui/select.jsx";
import { SOURCE_LABELS, TRIGGER_ICONS, TRIGGER_LABELS, reasonText } from "../constants/index.js";
import { usePipelineExecutions, useTriggerDecisions } from "../hooks/use-pipelines.js";
import { ExecutionStatusChip, Identifier, TimeAgo, absoluteTime } from "./pipeline-bits.jsx";

function triggerSummary(e) {
  if (e.triggerType === "pull_request")
    return e.pullRequestNumber ? `PR #${e.pullRequestNumber}` : "Pull request";
  if (e.triggerType === "push") return `push to ${e.refName}`;
  if (e.triggerType === "schedule") return "schedule";
  return "manual run";
}

const requestColumns = [
  {
    id: "status",
    header: "Status",
    cell: ({ row: { original: e } }) => {
      const why = reasonText(e.statusReason);
      return (
        <>
          <ExecutionStatusChip status={e.status} />
          {why ? <div className="mt-1 text-xs text-muted-foreground">{why}</div> : null}
        </>
      );
    },
  },
  {
    id: "trigger",
    header: "Trigger",
    cell: ({ row: { original: e } }) => {
      const Icon = TRIGGER_ICONS[e.triggerType];
      return (
        <span className="inline-flex items-center gap-1.5">
          {Icon ? <Icon aria-hidden="true" className="size-3.5 text-muted-foreground" /> : null}
          {triggerSummary(e)}
        </span>
      );
    },
  },
  {
    id: "ref",
    header: "Ref",
    cell: ({ row: { original: e } }) => (
      <span className="font-mono text-xs break-all">{e.refName}</span>
    ),
  },
  {
    id: "commit",
    header: "Commit",
    cell: ({ row: { original: e } }) => (
      <Identifier value={e.commitSha} max={7} copy label="commit SHA" />
    ),
  },
  {
    id: "scan",
    header: "Scan",
    cell: ({ row: { original: e } }) => (
      <>
        {e.scanKind === "full" ? "Full" : "Incremental"}
        {e.trust === "untrusted_fork" ? (
          <Badge tone="warning" className="ml-1">
            Untrusted fork
          </Badge>
        ) : null}
      </>
    ),
  },
  {
    id: "requested",
    header: "Requested",
    cell: ({ row: { original: e } }) => <TimeAgo value={e.requestedAt} />,
  },
];

/** Requests: the minimal list of execution requests (queued rows; later statuses render neutrally). */
function Requests({ pipelineId }) {
  const [params, setParams] = useSearchParams();
  const page = Math.max(1, Number(params.get("xpage")) || 1);
  const query = usePipelineExecutions(pipelineId, { page, pageSize: 10 });
  const setPage = (p) =>
    setParams(
      (cur) => {
        const next = new URLSearchParams(cur);
        p > 1 ? next.set("xpage", String(p)) : next.delete("xpage");
        return next;
      },
      { replace: true },
    );
  return (
    <section aria-labelledby="requests-h" className="mb-8">
      <h3 id="requests-h" className="mb-2 text-sm font-semibold">
        Requests
      </h3>
      <QueryTable
        caption="Execution requests"
        query={query}
        columns={requestColumns}
        getRowId={(e) => e.id}
        height="auto"
        maxHeight="22rem"
        pagination={query.data?.pagination}
        onPage={setPage}
        emptyState={
          <EmptyState
            icon={History}
            title="No requests yet"
            description="Requests appear when a trigger fires or someone runs the pipeline."
          />
        }
      />
    </section>
  );
}

function SlotTime({ value }) {
  if (!value) return <span className="text-muted-foreground">—</span>;
  return (
    <time dateTime={value} title={`UTC ${new Date(value).toISOString()}`}>
      {absoluteTime(value, { dateStyle: "medium", timeStyle: "short", timeZoneName: "short" })}
    </time>
  );
}

function sourceKey(d) {
  if (d.sourceType === "scm_event")
    return d.scmDeliveryId ? (
      <Identifier value={d.scmDeliveryId} max={8} copy label="delivery id" />
    ) : (
      "—"
    );
  if (d.sourceType === "schedule_slot") return <SlotTime value={d.scheduleSlot} />;
  return <span className="font-mono text-xs break-all">{d.manualKey ?? "—"}</span>;
}

function refText(d) {
  if (d.refType === "pull_request")
    return d.pullRequestNumber ? `PR #${d.pullRequestNumber}` : "Pull request";
  return d.refName;
}

const skippedColumns = [
  {
    id: "time",
    header: "Time",
    cell: ({ row: { original: d } }) => <TimeAgo value={d.decidedAt} />,
  },
  {
    id: "source",
    header: "Source",
    cell: ({ row: { original: d } }) => (
      <Badge tone="neutral" data-source={d.sourceType}>
        {SOURCE_LABELS[d.sourceType] ?? d.sourceType}
      </Badge>
    ),
  },
  {
    id: "key",
    header: "Delivery, slot or key",
    cell: ({ row: { original: d } }) => sourceKey(d),
  },
  {
    id: "trigger",
    header: "Trigger",
    cell: ({ row: { original: d } }) => {
      const Icon = TRIGGER_ICONS[d.triggerType];
      return (
        <>
          <span className="inline-flex items-center gap-1.5">
            {Icon ? <Icon aria-hidden="true" className="size-3.5 text-muted-foreground" /> : null}
            <span className="font-mono text-xs">{d.triggerKey}</span>
          </span>
          <div className="text-xs text-muted-foreground">{TRIGGER_LABELS[d.triggerType]}</div>
        </>
      );
    },
  },
  {
    id: "ref",
    header: "Ref",
    cell: ({ row: { original: d } }) => (
      <span className="font-mono text-xs break-all">{refText(d)}</span>
    ),
  },
  { id: "reason", header: "Reason", cell: ({ row: { original: d } }) => reasonText(d.reason) },
];

/** Skipped events: trigger decision rows of the three sources (SPEC §7.8). Non-matching events are never listed. */
function SkippedEvents({ pipelineId }) {
  const [params, setParams] = useSearchParams();
  const source = params.get("source") ?? "";
  const page = Math.max(1, Number(params.get("spage")) || 1);
  const query = useTriggerDecisions(pipelineId, {
    sourceType: source || undefined,
    page,
    pageSize: 10,
  });
  const update = (next) =>
    setParams(
      (cur) => {
        const merged = new URLSearchParams(cur);
        for (const [k, v] of Object.entries(next)) v ? merged.set(k, v) : merged.delete(k);
        return merged;
      },
      { replace: true },
    );
  return (
    <section aria-labelledby="skipped-h">
      <div className="mb-2 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h3 id="skipped-h" className="text-sm font-semibold">
            Skipped events
          </h3>
          <p className="text-xs text-muted-foreground">
            Events that matched a trigger but were skipped by policy. Events that matched no trigger
            are not listed.
          </p>
        </div>
        <div className="w-48">
          <Label htmlFor="skip-source" className="sr-only">
            Source
          </Label>
          <Select
            id="skip-source"
            value={source}
            onChange={(e) => update({ source: e.target.value, spage: "" })}
          >
            <option value="">All sources</option>
            {Object.entries(SOURCE_LABELS).map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </Select>
        </div>
      </div>
      <QueryTable
        caption="Skipped events"
        query={query}
        columns={skippedColumns}
        getRowId={(d) => d.id}
        height="auto"
        maxHeight="22rem"
        pagination={query.data?.pagination}
        onPage={(p) => update({ spage: p > 1 ? String(p) : "" })}
        emptyState={
          <EmptyState
            icon={ListX}
            title="No skipped events"
            description={
              source ? "No skipped events from this source." : "Nothing was skipped by policy."
            }
          />
        }
      />
    </section>
  );
}

/** Executions tab of T-27: Requests and Skipped events. Later modules add detail links. */
export function ExecutionsTab({ pipelineId }) {
  return (
    <>
      <Requests pipelineId={pipelineId} />
      <SkippedEvents pipelineId={pipelineId} />
    </>
  );
}
