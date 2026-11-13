import { DataTable } from "@qmentisai/ui";
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

const COLUMNS = [
  {
    id: "time",
    header: "Time",
    meta: { className: "whitespace-nowrap" },
    cell: ({ row: { original: d } }) => when(d.receivedAt),
  },
  {
    id: "event",
    header: "Event",
    cell: ({ row: { original: d } }) => (
      <span className="font-mono text-xs">
        {d.event}
        {d.action ? `.${d.action}` : ""}
      </span>
    ),
  },
  { id: "outcome", header: "Outcome", cell: ({ row: { original: d } }) => d.outcome },
  {
    id: "signature",
    header: "Signature",
    cell: () => (
      <span className="inline-flex items-center gap-1">
        <CheckCircle2 className="size-3 text-status-success" aria-hidden="true" />
        Verified
      </span>
    ),
  },
];

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
            <DataTable
              caption={`Recent webhook deliveries for ${login}`}
              columns={COLUMNS}
              data={items}
              getRowId={(d) => d.id}
              height="auto"
              maxHeight="22rem"
              footer={
                deliveries.data.pagination.totalPages > 1 ? (
                  <Pager
                    pagination={deliveries.data.pagination}
                    onPage={setPage}
                    className="w-full"
                  />
                ) : undefined
              }
            />
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
