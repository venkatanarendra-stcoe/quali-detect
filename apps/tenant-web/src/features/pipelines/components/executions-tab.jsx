import { History, ListX } from "lucide-react";
import { useSearchParams } from "react-router";
import { Pager } from "@/components/common/pager.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Select } from "@/components/ui/select.jsx";
import { SOURCE_LABELS, TRIGGER_ICONS, TRIGGER_LABELS, reasonText } from "../constants/index.js";
import { usePipelineExecutions, useTriggerDecisions } from "../hooks/use-pipelines.js";
import { ExecutionStatusChip, Identifier, TimeAgo, absoluteTime } from "./pipeline-bits.jsx";

const TH = "px-3 py-2 font-medium";

function triggerSummary(e) {
  if (e.triggerType === "pull_request")
    return e.pullRequestNumber ? `PR #${e.pullRequestNumber}` : "Pull request";
  if (e.triggerType === "push") return `push to ${e.refName}`;
  if (e.triggerType === "schedule") return "schedule";
  return "manual run";
}

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
      {query.isPending ? <LoadingState rows={4} label="Loading requests" /> : null}
      {query.isError ? <QueryErrorState error={query.error} onRetry={query.refetch} /> : null}
      {query.data && query.data.items.length === 0 ? (
        <EmptyState
          icon={History}
          title="No requests yet"
          description="Requests appear when a trigger fires or someone runs the pipeline."
        />
      ) : null}
      {query.data && query.data.items.length > 0 ? (
        <>
          <div className="overflow-x-auto rounded-md border border-border bg-card">
            <table className="w-full text-left text-[13px] leading-5">
              <caption className="sr-only">Execution requests</caption>
              <thead className="border-b border-border text-muted-foreground">
                <tr>
                  <th scope="col" className={TH}>
                    Status
                  </th>
                  <th scope="col" className={TH}>
                    Trigger
                  </th>
                  <th scope="col" className={TH}>
                    Ref
                  </th>
                  <th scope="col" className={TH}>
                    Commit
                  </th>
                  <th scope="col" className={TH}>
                    Scan
                  </th>
                  <th scope="col" className={TH}>
                    Requested
                  </th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((e) => {
                  const Icon = TRIGGER_ICONS[e.triggerType];
                  const why = reasonText(e.statusReason);
                  return (
                    <tr key={e.id} className="border-b border-border align-top last:border-0">
                      <td className="px-3 py-2">
                        <ExecutionStatusChip status={e.status} />
                        {why ? (
                          <div className="mt-1 text-xs text-muted-foreground">{why}</div>
                        ) : null}
                      </td>
                      <td className="px-3 py-2">
                        <span className="inline-flex items-center gap-1.5">
                          {Icon ? (
                            <Icon aria-hidden="true" className="size-3.5 text-muted-foreground" />
                          ) : null}
                          {triggerSummary(e)}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs break-all">{e.refName}</td>
                      <td className="px-3 py-2">
                        <Identifier value={e.commitSha} max={7} copy label="commit SHA" />
                      </td>
                      <td className="px-3 py-2">
                        {e.scanKind === "full" ? "Full" : "Incremental"}
                        {e.trust === "untrusted_fork" ? (
                          <Badge tone="warning" className="ml-1">
                            Untrusted fork
                          </Badge>
                        ) : null}
                      </td>
                      <td className="px-3 py-2">
                        <TimeAgo value={e.requestedAt} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pager pagination={query.data.pagination} onPage={setPage} />
        </>
      ) : null}
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
      {query.isPending ? <LoadingState rows={3} label="Loading skipped events" /> : null}
      {query.isError ? <QueryErrorState error={query.error} onRetry={query.refetch} /> : null}
      {query.data && query.data.items.length === 0 ? (
        <EmptyState
          icon={ListX}
          title="No skipped events"
          description={
            source ? "No skipped events from this source." : "Nothing was skipped by policy."
          }
        />
      ) : null}
      {query.data && query.data.items.length > 0 ? (
        <>
          <div className="overflow-x-auto rounded-md border border-border bg-card">
            <table className="w-full text-left text-[13px] leading-5">
              <caption className="sr-only">Skipped events</caption>
              <thead className="border-b border-border text-muted-foreground">
                <tr>
                  <th scope="col" className={TH}>
                    Time
                  </th>
                  <th scope="col" className={TH}>
                    Source
                  </th>
                  <th scope="col" className={TH}>
                    Delivery, slot or key
                  </th>
                  <th scope="col" className={TH}>
                    Trigger
                  </th>
                  <th scope="col" className={TH}>
                    Ref
                  </th>
                  <th scope="col" className={TH}>
                    Reason
                  </th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((d) => {
                  const Icon = TRIGGER_ICONS[d.triggerType];
                  return (
                    <tr key={d.id} className="border-b border-border align-top last:border-0">
                      <td className="px-3 py-2">
                        <TimeAgo value={d.decidedAt} />
                      </td>
                      <td className="px-3 py-2">
                        <Badge tone="neutral" data-source={d.sourceType}>
                          {SOURCE_LABELS[d.sourceType] ?? d.sourceType}
                        </Badge>
                      </td>
                      <td className="px-3 py-2">{sourceKey(d)}</td>
                      <td className="px-3 py-2">
                        <span className="inline-flex items-center gap-1.5">
                          {Icon ? (
                            <Icon aria-hidden="true" className="size-3.5 text-muted-foreground" />
                          ) : null}
                          <span className="font-mono text-xs">{d.triggerKey}</span>
                        </span>
                        <div className="text-xs text-muted-foreground">
                          {TRIGGER_LABELS[d.triggerType]}
                        </div>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs break-all">{refText(d)}</td>
                      <td className="px-3 py-2">{reasonText(d.reason)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pager
            pagination={query.data.pagination}
            onPage={(p) => update({ spage: p > 1 ? String(p) : "" })}
          />
        </>
      ) : null}
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
