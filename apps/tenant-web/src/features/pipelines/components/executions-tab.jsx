import { ListX } from "lucide-react";
import { Link, useSearchParams } from "react-router";
import { QueryTable } from "@/components/common/query-table.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import {
  Identifier,
  TimeAgo,
  absoluteTime,
} from "@/features/executions/components/execution-bits.jsx";
import { ExecutionsList } from "@/features/executions/components/executions-list.jsx";
import { reasonText } from "@/features/executions/constants/index.js";
import { SOURCE_LABELS, TRIGGER_ICONS, TRIGGER_LABELS } from "../constants/index.js";
import { useTriggerDecisions } from "../hooks/use-pipelines.js";

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

/**
 * Executions tab of T-27: the executions of this pipeline (the same list component as T-28, filtered by the pipeline, cursor
 * "Load more", no totals) with a link to the workspace-wide list, then the Skipped events section (unchanged).
 */
export function ExecutionsTab({ pipelineId, workspaceId }) {
  const can = useCan();
  const showAll = can("execution.view", { type: "workspace", workspaceId });
  return (
    <>
      <section aria-labelledby="executions-h" className="mb-8">
        <div className="mb-2 flex flex-wrap items-baseline justify-between gap-3">
          <h3 id="executions-h" className="text-sm font-semibold">
            Executions
          </h3>
          {showAll ? (
            <Link
              className="text-sm underline-offset-2 hover:underline"
              to={`/workspaces/${workspaceId}/executions?pipeline=${pipelineId}`}
            >
              View all executions
            </Link>
          ) : null}
        </div>
        <ExecutionsList
          workspaceId={workspaceId}
          pipelineId={pipelineId}
          compact
          height="auto"
          maxHeight="30rem"
          caption="Executions of this pipeline"
        />
      </section>
      <SkippedEvents pipelineId={pipelineId} />
    </>
  );
}
