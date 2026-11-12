import { CheckCircle2 } from "lucide-react";
import { useState } from "react";
import { Pager } from "@/components/common/pager.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useDeliveries } from "../hooks/use-integrations.js";

const when = (value) =>
  new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

/** Installation-level webhook health: recent deliveries (only signature-verified deliveries are recorded). */
export function WebhookDeliveries({ installationId, login }) {
  const [page, setPage] = useState(1);
  const [outcome, setOutcome] = useState("");
  const deliveries = useDeliveries(installationId, { page, pageSize: 10 });
  const all = deliveries.data?.items ?? [];
  const items = all.filter((d) => !outcome || d.outcome === outcome);
  const processed = all.filter((d) => d.outcome === "accepted" || d.outcome === "ignored").length;
  const selectId = `delivery-outcome-${installationId}`;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Webhook health</CardTitle>
        <CardDescription>
          {all.length > 0
            ? `Last delivery ${when(all[0].receivedAt)} · ${Math.round((processed / all.length) * 100)}% processed in the latest ${all.length}`
            : "No deliveries received yet."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {deliveries.isPending ? <LoadingState label="Loading deliveries" /> : null}
        {deliveries.isError ? (
          <QueryErrorState error={deliveries.error} onRetry={deliveries.refetch} />
        ) : null}
        {deliveries.data && all.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Deliveries appear here after GitHub sends the first event.
          </p>
        ) : null}
        {all.length > 0 ? (
          <>
            <div className="mb-3 w-48">
              <label htmlFor={selectId} className="sr-only">
                Outcome
              </label>
              <Select id={selectId} value={outcome} onChange={(e) => setOutcome(e.target.value)}>
                <option value="">All outcomes</option>
                <option value="accepted">Accepted</option>
                <option value="ignored">Ignored</option>
                <option value="duplicate">Duplicate</option>
              </Select>
            </div>
            <div className="relative overflow-x-auto rounded-md border border-border">
              <table className="w-full text-left text-[13px] leading-5">
                <caption className="sr-only">Recent webhook deliveries for {login}</caption>
                <thead className="border-b border-border text-muted-foreground">
                  <tr>
                    {["Time", "Event", "Outcome", "Signature"].map((h) => (
                      <th key={h} scope="col" className="px-3 py-2 font-medium">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {items.map((d) => (
                    <tr key={d.id} className="border-b border-border last:border-0">
                      <td className="px-3 py-2 whitespace-nowrap">{when(d.receivedAt)}</td>
                      <td className="px-3 py-2 font-mono text-xs">
                        {d.event}
                        {d.action ? `.${d.action}` : ""}
                      </td>
                      <td className="px-3 py-2">{d.outcome}</td>
                      <td className="px-3 py-2">
                        <span className="inline-flex items-center gap-1">
                          <CheckCircle2 className="size-3 text-status-success" aria-hidden="true" />
                          Verified
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager pagination={deliveries.data.pagination} onPage={setPage} />
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
