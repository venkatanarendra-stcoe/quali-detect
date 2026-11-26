import { RISK_FORMULA_TEXT } from "@qmentisai/shared";
import { useQueries } from "@tanstack/react-query";
import { Activity, AlertTriangle, Boxes, Download, Info, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import {
  SEVERITY_FILL,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  SEVERITY_PATTERN,
} from "../constants/index.js";
import { CardError, ChartCard, DataFooter } from "../components/chart-card.jsx";
import { SeverityAreaChart } from "../components/charts.jsx";
import { Legend, Swatch } from "../components/chart-parts.jsx";
import { GenerateReportDialog } from "../components/generate-report-dialog.jsx";
import { KpiCard } from "../components/kpi-card.jsx";
import { PeriodControl } from "../components/period-control.jsx";
import { RefreshButton } from "../components/reporting-page.jsx";
import { ReportTable } from "../components/report-table.jsx";
import { reportingKeys, useReportingOverview } from "../hooks/use-reporting.js";
import { useReportingParams } from "../hooks/use-reporting-params.js";
import { retryTransient } from "../hooks/use-reporting.js";
import { sumOf } from "../schemas/derive.js";
import { formatCount, formatPercent } from "../schemas/format.js";
import { reportingService } from "../services/reporting-service.js";
import { useReportingUiStore } from "../stores/reporting-ui-store.js";

const TREND_WORKSPACE_CAP = 10;
const NONE = [];

/** A labelled severity bar: Critical to Info counts as segments plus the numbers in text. */
function SeverityStrip({ counts }) {
  const total = sumOf(counts);
  return (
    <div>
      <div
        role="img"
        aria-label={`Open by severity: ${SEVERITY_ORDER.map((s) => `${counts[s]} ${SEVERITY_LABELS[s].toLowerCase()}`).join(", ")}`}
        className="flex h-2.5 overflow-hidden rounded-full bg-muted"
      >
        {SEVERITY_ORDER.map((s) =>
          counts[s] ? (
            <span
              key={s}
              style={{ width: `${(counts[s] / total) * 100}%`, background: SEVERITY_FILL[s] }}
            />
          ) : null,
        )}
      </div>
      <ul className="mt-1.5 flex flex-wrap gap-x-2.5 gap-y-0.5 text-xs text-muted-foreground">
        {SEVERITY_ORDER.map((s) => (
          <li key={s} className="inline-flex items-center gap-1">
            <Swatch fill={SEVERITY_FILL[s]} pattern={SEVERITY_PATTERN[s]} />
            {SEVERITY_LABELS[s]}{" "}
            <span className="font-medium text-foreground tabular-nums">{counts[s]}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function WorkspaceCard({ w }) {
  const noFindings = w.open === null;
  return (
    <li>
      <Card className="h-full" data-testid="overview-workspace">
        <CardHeader className="pb-2">
          <CardTitle className="truncate text-sm" title={w.name}>
            {w.name}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {noFindings ? (
            <p className="text-sm text-muted-foreground">No findings access</p>
          ) : (
            <>
              <SeverityStrip counts={w.bySeverity} />
              <dl className="grid grid-cols-3 gap-2 text-xs">
                <div>
                  <dt className="text-muted-foreground">Open</dt>
                  <dd className="text-base font-semibold tabular-nums">{formatCount(w.open)}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">SLA breached</dt>
                  <dd className="text-base font-semibold tabular-nums">
                    {w.slaBreached === null ? "—" : formatCount(w.slaBreached)}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Executions</dt>
                  <dd className="text-base font-semibold tabular-nums">
                    {w.executions === null ? "—" : formatCount(w.executions)}
                  </dd>
                  {w.successRate !== null ? (
                    <dd className="text-muted-foreground">
                      {formatPercent(w.successRate)} succeeded
                    </dd>
                  ) : null}
                </div>
              </dl>
            </>
          )}
          <Link
            to={`/workspaces/${w.workspaceId}/dashboard`}
            className="inline-block rounded-sm text-sm text-primary-text underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
          >
            Open dashboard
          </Link>
        </CardContent>
      </Card>
    </li>
  );
}

/** The tenant-wide "Findings over time": the sum of the workspaces' own trends (the API serves trends per workspace). */
function OrgTrend({ workspaces, params }) {
  const tenantId = useTenantId();
  const visible = workspaces.filter((w) => w.open !== null);
  const tooMany = visible.length > TREND_WORKSPACE_CAP;
  const query = { ...params.periodQuery, series: "severity" };
  const results = useQueries({
    queries: visible.slice(0, TREND_WORKSPACE_CAP).map((w) => ({
      queryKey: reportingKeys.metric(tenantId, w.workspaceId, "GET /reporting/trends", query),
      queryFn: ({ signal }) =>
        reportingService.read(
          "GET /reporting/trends",
          { workspaceId: w.workspaceId, ...query },
          { signal },
        ),
      enabled: !tooMany,
      staleTime: 15_000,
      retry: retryTransient,
    })),
  });
  const hidden = useReportingUiStore((s) => s.hidden.orgTrend ?? NONE);
  const toggle = useReportingUiStore((s) => s.toggleSeries);
  const pending = results.some((r) => r.isPending);
  const failed = results.find((r) => r.isError);
  const ok = results.filter((r) => r.data);
  const merged =
    !tooMany && !pending && ok.length === results.length && ok.length > 0
      ? {
          dataFrom:
            ok
              .map((r) => r.data.data.dataFrom)
              .filter(Boolean)
              .sort()[0] ?? null,
          points: ok[0].data.data.points.map((p, i) => ({
            day: p.day,
            openBySeverity: ok.every((r) => r.data.data.points[i].openBySeverity)
              ? Object.fromEntries(
                  SEVERITY_ORDER.map((s) => [
                    s,
                    ok.reduce((a, r) => a + r.data.data.points[i].openBySeverity[s], 0),
                  ]),
                )
              : undefined,
          })),
        }
      : null;
  const virtual = {
    isPending: !tooMany && pending,
    isError: !tooMany && Boolean(failed) && !merged,
    error: failed?.error,
    refetch: () => results.forEach((r) => r.refetch()),
    data: ok[0] ? { meta: ok[0].data.meta } : undefined,
  };
  if (tooMany)
    return (
      <Card data-testid="card-org-trend">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Findings over time</CardTitle>
        </CardHeader>
        <CardContent className="flex items-start gap-2 text-sm text-muted-foreground">
          <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          This organization has more than {TREND_WORKSPACE_CAP} workspaces. The API serves trends
          per workspace, so open a workspace dashboard for its trend.
        </CardContent>
      </Card>
    );
  const days = merged ? merged.points.filter((p) => p.openBySeverity) : [];
  const first = days[0] ? sumOf(days[0].openBySeverity) : 0;
  const last = days.length ? sumOf(days.at(-1).openBySeverity) : 0;
  return (
    <ChartCard
      id="org-trend"
      title="Findings over time"
      query={virtual}
      state={merged && merged.dataFrom === null ? "empty" : null}
      summary={
        merged
          ? `Open findings summed over ${ok.length} workspaces: ${first === last ? `stayed at ${formatCount(last)}` : `${last < first ? "fell" : "rose"} from ${formatCount(first)} to ${formatCount(last)}`} over the period.`
          : undefined
      }
      legend={
        <Legend
          label="Severity (toggle)"
          onToggle={(k) => toggle("orgTrend", k)}
          items={SEVERITY_ORDER.map((s) => ({
            key: s,
            label: SEVERITY_LABELS[s],
            fill: SEVERITY_FILL[s],
            pattern: SEVERITY_PATTERN[s],
            off: hidden.includes(s),
          }))}
        />
      }
      table={
        merged ? (
          <ReportTable
            caption="Open findings per day, all workspaces you can see"
            rows={merged.points}
            getRowId={(r) => r.day}
            maxHeight="18rem"
            columns={[
              { key: "day", header: "Day", cell: (r) => r.day },
              ...SEVERITY_ORDER.map((s) => ({
                key: s,
                header: SEVERITY_LABELS[s],
                align: "right",
                cell: (r) => (r.openBySeverity ? r.openBySeverity[s] : "no data"),
              })),
            ]}
          />
        ) : undefined
      }
    >
      {merged ? (
        <SeverityAreaChart
          points={merged.points}
          dataFrom={merged.dataFrom}
          hidden={hidden}
          height={220}
        />
      ) : null}
    </ChartCard>
  );
}

/**
 * T-06 reporting content of the Organization Overview: KPI row, workspace cards, top risky repositories and findings over time. Only
 * accessible workspaces are counted; a workspace without finding access shows a muted "No findings access" and no number.
 */
export function OrganizationReporting() {
  const can = useCan();
  const params = useReportingParams(undefined);
  const overview = useReportingOverview(params.periodQuery);
  const [exporting, setExporting] = useState(false);
  const d = overview.data?.data;
  const timeZone = overview.data?.meta.timeZone;
  const sorted = d
    ? [...d.workspaces].sort(
        (a, b) =>
          (b.bySeverity?.critical ?? -1) - (a.bySeverity?.critical ?? -1) ||
          (b.slaBreached ?? -1) - (a.slaBreached ?? -1),
      )
    : [];
  const executions = d ? d.workspaces.reduce((a, w) => a + (w.executions ?? 0), 0) : 0;
  const weighted = d
    ? d.workspaces.reduce((a, w) => a + (w.executions ?? 0) * (w.successRate ?? 0), 0)
    : 0;
  const hiddenCount = d ? d.workspaces.filter((w) => w.open === null).length : 0;

  return (
    <section aria-label="Security reporting" className="mb-6 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3 print:hidden">
        <PeriodControl params={params} timeZone={timeZone} />
        <div className="flex items-center gap-2">
          {can("report.export") ? (
            <Button variant="secondary" onClick={() => setExporting(true)}>
              <Download aria-hidden="true" />
              Export
            </Button>
          ) : null}
          <RefreshButton workspaceId={null} />
        </div>
      </div>
      {hiddenCount > 0 ? (
        <p role="status" className="text-sm text-muted-foreground">
          Some sections are not available to you: findings of {hiddenCount}{" "}
          {hiddenCount === 1 ? "workspace" : "workspaces"}.
        </p>
      ) : null}

      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <KpiCard
          id="workspaces"
          label="Workspaces"
          icon={Boxes}
          query={overview}
          value={d ? formatCount(d.workspaces.length) : null}
          href="/workspaces"
        />
        <KpiCard
          id="critical"
          label="Open critical findings"
          icon={ShieldAlert}
          tone="critical"
          query={overview}
          value={d ? formatCount(d.totals.bySeverity.critical) : null}
          sub={d ? `${formatCount(d.totals.open)} open in total` : null}
        />
        <KpiCard
          id="executions"
          label="Executions"
          icon={Activity}
          query={overview}
          value={d ? formatCount(executions) : null}
          sub={d && executions ? `${formatPercent(weighted / executions)} succeeded` : null}
        />
        <KpiCard
          id="breaches"
          label="SLA breaches"
          icon={AlertTriangle}
          tone="danger"
          query={overview}
          value={d ? formatCount(d.totals.slaBreached) : null}
        />
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">Your workspaces</h2>
        {overview.isPending ? (
          <div role="status" aria-busy="true">
            <span className="sr-only">Loading workspaces…</span>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {[0, 1, 2].map((i) => (
                <div key={i} className="h-40 animate-pulse rounded-lg bg-muted" />
              ))}
            </div>
          </div>
        ) : null}
        {overview.isError ? <CardError error={overview.error} onRetry={overview.refetch} /> : null}
        {d && d.workspaces.length === 0 ? (
          <EmptyState
            icon={Boxes}
            title="No workspaces yet"
            description="Workspaces you can access appear here."
          />
        ) : null}
        {d && d.workspaces.length ? (
          <ul className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {sorted.map((w) => (
              <WorkspaceCard key={w.workspaceId} w={w} />
            ))}
          </ul>
        ) : null}
        <div className="mt-1">
          <DataFooter meta={overview.data?.meta} />
        </div>
      </div>

      {d ? (
        <Card data-testid="card-top-risk">
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm">Top risky repositories</CardTitle>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  className="inline-flex items-center gap-1 rounded-sm text-xs text-muted-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <Info aria-hidden="true" className="size-3.5" />
                  Risk points
                </button>
              </TooltipTrigger>
              <TooltipContent>{RISK_FORMULA_TEXT}</TooltipContent>
            </Tooltip>
          </CardHeader>
          <CardContent>
            <ReportTable
              caption="Top risky repositories across the workspaces you can see"
              rows={d.topRisk}
              getRowId={(r) => r.repositoryId}
              empty="No open findings in any repository."
              columns={[
                {
                  key: "name",
                  header: "Repository",
                  sortValue: (r) => r.repositoryName,
                  cell: (r) => (
                    <span
                      className="block max-w-64 truncate font-mono text-xs"
                      title={r.repositoryName}
                    >
                      {r.repositoryName}
                    </span>
                  ),
                },
                {
                  key: "score",
                  header: "Risk points",
                  align: "right",
                  sortValue: (r) => r.score,
                  cell: (r) => r.score,
                },
                {
                  key: "critical",
                  header: "Critical",
                  align: "right",
                  sortValue: (r) => r.critical,
                  cell: (r) => r.critical,
                },
                {
                  key: "high",
                  header: "High",
                  align: "right",
                  sortValue: (r) => r.high,
                  cell: (r) => r.high,
                },
                {
                  key: "breached",
                  header: "Breached",
                  align: "right",
                  sortValue: (r) => r.breachedCriticalHigh,
                  cell: (r) => r.breachedCriticalHigh,
                },
              ]}
            />
          </CardContent>
        </Card>
      ) : null}

      {d && d.workspaces.length ? <OrgTrend workspaces={d.workspaces} params={params} /> : null}
      <GenerateReportDialog
        open={exporting}
        onOpenChange={setExporting}
        tenantWide
        initial={{ template: "executive_summary" }}
      />
    </section>
  );
}
