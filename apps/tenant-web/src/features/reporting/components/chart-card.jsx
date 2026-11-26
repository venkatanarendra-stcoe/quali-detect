import {
  BarChart3,
  Clock,
  Inbox,
  Info,
  RefreshCw,
  ShieldOff,
  Table2,
  TriangleAlert,
} from "lucide-react";
import { useId } from "react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import { describeError, isApiError } from "@/lib/api/index.js";
import { cn } from "@/lib/cn.js";
import { exactIn, footerText } from "../schemas/format.js";
import { useReportingUiStore } from "../stores/reporting-ui-store.js";

/** "Live · updated 14:02" footer; hover or focus shows the exact instant and the source (SCREENS 1). @param {{ meta?: any }} props */
export function DataFooter({ meta }) {
  if (!meta) return null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="rounded-sm text-xs text-muted-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {footerText(meta)}
        </button>
      </TooltipTrigger>
      <TooltipContent>
        {exactIn(meta.asOf, meta.timeZone)}
        <br />
        Source: {meta.source === "live" ? "live query" : "daily rollup"}
      </TooltipContent>
    </Tooltip>
  );
}

/** A chip with an icon and words (never colour alone). */
export function InfoChip({ icon: Icon, children, tone = "neutral", title }) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 rounded-sm border border-border-strong px-1.5 py-0.5 text-xs font-medium whitespace-nowrap",
        tone === "warning" && "text-status-warning",
      )}
    >
      <Icon aria-hidden="true" className="size-3" />
      {children}
    </span>
  );
}

/** The stale chip: a rollup over two hours late (SPEC RPT-009). */
export const StaleChip = () => (
  <InfoChip
    icon={Clock}
    tone="warning"
    title="The daily rollup is over two hours late; the numbers may lag."
  >
    Stale
  </InfoChip>
);
/** The recomputing chip: rollups are rebuilding after a time-zone change. */
export const RecomputingChip = () => (
  <InfoChip
    icon={RefreshCw}
    tone="warning"
    title="Daily rollups are being rebuilt; trend numbers may change."
  >
    Recomputing
  </InfoChip>
);

/** The state body of a card whose query failed: no permission or an error with its reference and Retry. @param {{ error: unknown, onRetry?: () => void }} props */
export function CardError({ error, onRetry }) {
  if (isApiError(error) && error.status === 403 && error.code !== "TENANT_SUSPENDED")
    return (
      <div role="status" className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
        <ShieldOff aria-hidden="true" className="size-4 shrink-0" />
        This section is not available to you.
      </div>
    );
  return (
    <div role="alert" className="flex flex-col items-start gap-2 py-4 text-sm">
      <p className="flex items-center gap-2">
        <TriangleAlert aria-hidden="true" className="size-4 shrink-0 text-status-danger" />
        {describeError(error)}
      </p>
      {isApiError(error) && error.correlationId ? (
        <p className="text-xs text-subtle-foreground">
          Reference <span className="font-mono">{error.correlationId}</span>
        </p>
      ) : null}
      {onRetry ? (
        <Button variant="secondary" size="sm" onClick={() => onRetry()}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

/** The "No data" bodies: nothing yet (with the next step) or nothing in this period (with the range and a way to widen it). */
export function CardEmpty({ kind, rangeText, onWiden, next }) {
  if (kind === "period")
    return (
      <div className="flex flex-col items-start gap-2 py-6 text-sm">
        <p className="flex items-center gap-2 font-medium">
          <Inbox aria-hidden="true" className="size-4 text-muted-foreground" />
          No activity in this period
        </p>
        {rangeText ? <p className="text-muted-foreground">{rangeText}</p> : null}
        {onWiden ? (
          <Button variant="secondary" size="sm" onClick={onWiden}>
            Widen to 90 days
          </Button>
        ) : null}
      </div>
    );
  return (
    <div className="flex flex-col items-start gap-2 py-6 text-sm">
      <p className="flex items-center gap-2 font-medium">
        <Inbox aria-hidden="true" className="size-4 text-muted-foreground" />
        No findings yet. Run a scan.
      </p>
      {next ? <div className="text-muted-foreground">{next}</div> : null}
    </div>
  );
}

/** Chart / Table segmented toggle (SCREENS 1). */
function ViewToggle({ id, showTable, onChange }) {
  const common =
    "inline-flex h-7 items-center gap-1 px-2 text-xs font-medium outline-none focus-visible:z-10 focus-visible:ring-2 focus-visible:ring-ring";
  return (
    <div
      role="group"
      aria-label="Show as"
      className="inline-flex overflow-hidden rounded-sm border border-border-strong"
    >
      <button
        type="button"
        aria-pressed={!showTable}
        onClick={() => onChange(false)}
        className={cn(
          common,
          !showTable ? "bg-secondary text-foreground" : "text-muted-foreground hover:bg-accent",
        )}
      >
        <BarChart3 aria-hidden="true" className="size-3.5" />
        Chart
      </button>
      <button
        type="button"
        aria-pressed={showTable}
        onClick={() => onChange(true)}
        className={cn(
          common,
          "border-l border-border-strong",
          showTable ? "bg-secondary text-foreground" : "text-muted-foreground hover:bg-accent",
        )}
        data-chart-id={id}
      >
        <Table2 aria-hidden="true" className="size-3.5" />
        Table
      </button>
    </div>
  );
}

/**
 * The frame of every chart or table of the reporting screens: title, the Chart / Table toggle, the one-sentence summary (the text
 * alternative), the body with every state, a legend slot, a "View details" link and the "data as of" footer.
 * `state` is computed by the screen from its data: `"empty"` (nothing yet) or `"period"` (nothing in this period).
 * @param {{ id: string, title: string, summary?: string, note?: string, query: { isPending: boolean, isError: boolean, error: unknown, refetch: () => void, data?: { meta?: any } },
 *   state?: "empty" | "period" | null, rangeText?: string, onWiden?: () => void, next?: import("react").ReactNode,
 *   table?: import("react").ReactNode, legend?: import("react").ReactNode, link?: { to: string, label: string },
 *   recomputing?: boolean, skeletonHeight?: string, className?: string, children: import("react").ReactNode }} props
 */
export function ChartCard({
  id,
  title,
  summary,
  note,
  query,
  state = null,
  rangeText,
  onWiden,
  next,
  table,
  legend,
  link,
  recomputing = false,
  skeletonHeight = "h-52",
  className,
  children,
}) {
  const showTable = useReportingUiStore((s) => Boolean(s.tables[id]));
  const setTable = useReportingUiStore((s) => s.setTable);
  const summaryId = useId();
  const meta = query.data?.meta;
  const ready = !query.isPending && !query.isError && query.data;
  const hasContent = ready && !state;
  return (
    <Card className={cn("min-w-0", className)} data-testid={`card-${id}`}>
      <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm">{title}</CardTitle>
        <div className="flex flex-wrap items-center gap-2">
          {meta?.stale ? <StaleChip /> : null}
          {recomputing ? <RecomputingChip /> : null}
          {hasContent && table ? (
            <ViewToggle id={id} showTable={showTable} onChange={(v) => setTable(id, v)} />
          ) : null}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {hasContent && summary ? (
          <p id={summaryId} className="text-sm text-muted-foreground">
            {summary}
          </p>
        ) : null}
        {ready && note ? (
          <p
            role="note"
            data-testid="forward-only-note"
            className="flex items-start gap-1.5 rounded-sm border border-border bg-secondary/50 px-2 py-1 text-xs text-muted-foreground"
          >
            <Info aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
            {note}
          </p>
        ) : null}
        {query.isPending ? (
          <div role="status" aria-busy="true" aria-live="polite">
            <span className="sr-only">Loading {title}…</span>
            <Skeleton className={cn("w-full", skeletonHeight)} />
          </div>
        ) : null}
        {query.isError ? <CardError error={query.error} onRetry={query.refetch} /> : null}
        {ready && state ? (
          <CardEmpty kind={state} rangeText={rangeText} onWiden={onWiden} next={next} />
        ) : null}
        {hasContent ? (
          <figure
            aria-label={title}
            aria-describedby={summary ? summaryId : undefined}
            className="m-0 min-w-0"
          >
            {showTable && table ? table : children}
          </figure>
        ) : null}
        {hasContent && legend ? legend : null}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <DataFooter meta={meta} />
          {hasContent && link ? (
            <Link
              to={link.to}
              className="rounded-sm text-xs text-primary-text underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
            >
              {link.label}
            </Link>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}
