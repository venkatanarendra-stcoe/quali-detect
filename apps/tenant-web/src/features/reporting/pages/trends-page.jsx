import { Download, Info } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { isApiError } from "@/lib/api/index.js";
import {
  SEVERITY_FILL,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  SEVERITY_PATTERN,
} from "../constants/index.js";
import { ChartCard } from "../components/chart-card.jsx";
import { FlowChart, LinesChart, SeverityAreaChart } from "../components/charts.jsx";
import { Legend } from "../components/chart-parts.jsx";
import { SeverityFilter } from "../components/dashboard-controls.jsx";
import { GenerateReportDialog } from "../components/generate-report-dialog.jsx";
import { KpiCard } from "../components/kpi-card.jsx";
import { ReportTable } from "../components/report-table.jsx";
import { ReportingPage } from "../components/reporting-page.jsx";
import { usePosture, useTrends } from "../hooks/use-reporting.js";
import { useReportingParams } from "../hooks/use-reporting-params.js";
import {
  dataPoints,
  flowEmpty,
  flowSummary,
  openChangeSummary,
  trendsEmpty,
} from "../schemas/derive.js";
import { findingsUrl, openFindingsUrl } from "../schemas/drilldown.js";
import { dayLabel, dayLong, formatCount } from "../schemas/format.js";
import { useReportingUiStore } from "../stores/reporting-ui-store.js";
import { periodDays } from "./workspace-dashboard-view.jsx";
import { useActiveWorkspace } from "@/features/authorization/hooks/use-permissions.js";

const NONE = [];

/** T-46 Findings trends: open findings by severity, new vs fixed, burn-down with an estimate, awaiting verification, and the as-of day. */
export function TrendsPage() {
  const { workspaceId } = useParams();
  const active = useActiveWorkspace();
  const live = usePosture(workspaceId, {});
  const timeZone = live.data?.meta.timeZone;
  const params = useReportingParams(timeZone);
  const { periodQuery, asOf, severities } = params;
  const days = periodDays(params.period);
  const trends = useTrends(workspaceId, {
    ...periodQuery,
    series: "flow,severity,backlog,awaiting_verification",
  });
  const past = usePosture(workspaceId, { asOf }, { enabled: Boolean(asOf) });
  const posture = asOf ? past : live;
  const hiddenSev = SEVERITY_ORDER.filter((s) => severities.length > 0 && !severities.includes(s));
  const hiddenFlow = useReportingUiStore((s) => s.hidden.flow ?? NONE);
  const toggleSeries = useReportingUiStore((s) => s.toggleSeries);
  const [exporting, setExporting] = useState(false);
  const t = trends.data?.data;
  const p = posture.data?.data;
  const sparse = t && t.dataFrom !== null && dataPoints(t).length < 3;
  const rangeText = `${dayLabel(t?.period.from ?? params.today)} to ${dayLabel(t?.period.to ?? params.today)}`;
  const asOfUnavailable =
    isApiError(posture.error) && posture.error.code === "REPORT_AS_OF_UNAVAILABLE";

  const projection = t?.projection ?? null;
  const burn = t
    ? [
        ...t.points.map((pt, i) => ({
          day: pt.day,
          open: pt.open ?? null,
          projection: projection && i === t.points.length - 1 ? pt.open : null,
        })),
        ...(projection?.days ?? []).map((d) => ({ day: d.day, open: null, projection: d.open })),
      ]
    : [];
  const zeroDay = projection?.days.at(-1)?.open === 0 ? projection.days.at(-1).day : null;

  return (
    <ReportingPage
      workspaceId={workspaceId}
      current="trends"
      title="Findings trends"
      description={active?.name}
      params={params}
      timeZone={timeZone}
      controls={
        <div className="flex flex-wrap items-end gap-3 print:hidden">
          <SeverityFilter params={params} />
          <div className="space-y-1">
            <Label htmlFor="as-of" className="text-xs">
              As of day
            </Label>
            <div className="flex items-center gap-1.5">
              <Input
                id="as-of"
                type="date"
                className="h-8 w-40"
                value={asOf}
                max={params.today}
                onChange={(e) => params.setAsOf(e.target.value)}
              />
              {asOf ? (
                <Button variant="ghost" size="sm" onClick={() => params.setAsOf("")}>
                  Live
                </Button>
              ) : null}
            </div>
          </div>
          <PermissionGate permission="report.export">
            <Button variant="secondary" onClick={() => setExporting(true)}>
              <Download aria-hidden="true" />
              Download CSV of this view
            </Button>
          </PermissionGate>
        </div>
      }
    >
      {asOf ? (
        <p
          role="status"
          className="mb-4 flex items-start gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm"
        >
          <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          Showing {dayLong(asOf)}, end of day ({timeZone ?? "organization time zone"}). The numbers
          below the charts stay live.
        </p>
      ) : null}
      {asOfUnavailable ? (
        <p
          role="alert"
          className="mb-4 rounded-md border border-border bg-card px-3 py-2 text-sm text-status-danger"
        >
          There is no data for that day yet. Choose a later day.
        </p>
      ) : (
        <section
          aria-label={asOf ? "Point-in-time numbers" : "Current numbers"}
          className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4"
        >
          <KpiCard
            id="open"
            label={asOf ? "Open findings then" : "Open findings"}
            query={posture}
            value={p ? formatCount(p.open) : null}
            href={!asOf && p ? openFindingsUrl(workspaceId) : undefined}
          />
          <KpiCard
            id="crit-high"
            label="Critical and high open"
            tone="critical"
            query={posture}
            value={p ? formatCount(p.criticalHighOpen) : null}
            href={!asOf && p ? openFindingsUrl(workspaceId, ["critical", "high"]) : undefined}
          />
          <KpiCard
            id="backlog"
            label="Backlog"
            query={posture}
            value={p ? formatCount(p.backlog) : null}
            sub="Not yet in anyone's hands"
          />
          <KpiCard
            id="wip"
            label="Work in progress"
            query={posture}
            value={p ? formatCount(p.workInProgress) : null}
            sub="Assigned, in remediation or awaiting verification"
          />
        </section>
      )}

      {sparse ? (
        <p
          role="status"
          className="mb-4 flex items-start gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm"
        >
          <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          Trends need at least 3 days of data. Only {dataPoints(t).length}{" "}
          {dataPoints(t).length === 1 ? "day is" : "days are"} available so far; earlier days show
          no data.
        </p>
      ) : null}
      {t && !t.severityBackfilled ? (
        <p role="status" className="mb-4 text-xs text-muted-foreground">
          The severity series starts when reporting was switched on; earlier days cannot be rebuilt
          exactly.
        </p>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-2">
        <ChartCard
          id="trend-severity"
          title="Open findings by severity"
          query={trends}
          state={t ? trendsEmpty(t) : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          recomputing={t?.recomputing}
          summary={t ? openChangeSummary(t, days) : undefined}
          link={{
            to: findingsUrl(workspaceId, { view: "all_open", severity: severities }),
            label: "Open in Findings",
          }}
          legend={
            <Legend
              label="Severity"
              onToggle={params.toggleSeverity}
              items={SEVERITY_ORDER.map((s) => ({
                key: s,
                label: SEVERITY_LABELS[s],
                fill: SEVERITY_FILL[s],
                pattern: SEVERITY_PATTERN[s],
                off: hiddenSev.includes(s),
              }))}
            />
          }
          table={
            t ? (
              <ReportTable
                caption="Open findings by severity per day"
                rows={t.points}
                getRowId={(r) => r.day}
                maxHeight="18rem"
                columns={[
                  { key: "day", header: "Day", cell: (r) => dayLabel(r.day) },
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
          {t ? (
            <SeverityAreaChart points={t.points} dataFrom={t.dataFrom} hidden={hiddenSev} />
          ) : null}
        </ChartCard>

        <ChartCard
          id="trend-flow"
          title="New, fixed, closed without a fix and reopened"
          query={trends}
          state={t ? flowEmpty(t) : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          recomputing={t?.recomputing}
          summary={t ? flowSummary(t, days) : undefined}
          legend={
            t ? (
              <Legend
                label="Series (toggle)"
                onToggle={(k) => toggleSeries("flow", k)}
                items={[
                  { key: "new", label: "New", fill: "var(--chart-2)", pattern: "solid" },
                  { key: "fixed", label: "Fixed", fill: "var(--chart-1)", pattern: "solid" },
                  {
                    key: "closedWithoutFix",
                    label: "Closed without a fix",
                    fill: "var(--chart-3)",
                    pattern: "solid",
                  },
                  { key: "reopened", label: "Reopened", fill: "var(--chart-4)", pattern: "stripe" },
                ].map((i) => ({ ...i, off: hiddenFlow.includes(i.key) }))}
              />
            ) : undefined
          }
          table={
            t ? (
              <ReportTable
                caption="Flow per day"
                rows={t.points}
                getRowId={(r) => r.day}
                maxHeight="18rem"
                columns={[
                  { key: "day", header: "Day", cell: (r) => dayLabel(r.day) },
                  { key: "new", header: "New", align: "right", cell: (r) => r.new ?? "no data" },
                  {
                    key: "fixed",
                    header: "Fixed",
                    align: "right",
                    cell: (r) => r.fixed ?? "no data",
                  },
                  {
                    key: "closed",
                    header: "Closed without a fix",
                    align: "right",
                    cell: (r) => r.closedWithoutFix ?? "no data",
                  },
                  {
                    key: "reopened",
                    header: "Reopened",
                    align: "right",
                    cell: (r) => r.reopened ?? "no data",
                  },
                ]}
              />
            ) : undefined
          }
        >
          {t ? (
            <FlowChart
              points={t.points}
              dataFrom={t.dataFrom}
              variant="grouped"
              hidden={hiddenFlow}
            />
          ) : null}
        </ChartCard>

        <ChartCard
          id="trend-burndown"
          title="Backlog burn-down"
          query={trends}
          state={t ? trendsEmpty(t) : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          summary={
            t
              ? `Open findings per day.${zeroDay ? ` Estimate: at the last 14 days' pace, zero open on ${dayLabel(zeroDay)}.` : " No downward trend to project."}`
              : undefined
          }
          legend={
            <Legend
              label="Burn-down"
              items={[
                { key: "open", label: "Open", fill: "var(--chart-1)", pattern: "solid" },
                ...(projection
                  ? [
                      {
                        key: "projection",
                        label: "Estimate",
                        fill: "var(--chart-3)",
                        pattern: "stripe",
                      },
                    ]
                  : []),
              ]}
            />
          }
          table={
            t ? (
              <ReportTable
                caption="Open findings per day"
                rows={burn}
                getRowId={(r) => r.day}
                maxHeight="18rem"
                columns={[
                  { key: "day", header: "Day", cell: (r) => dayLabel(r.day) },
                  { key: "open", header: "Open", align: "right", cell: (r) => r.open ?? "no data" },
                  {
                    key: "projection",
                    header: "Estimate",
                    align: "right",
                    cell: (r) => r.projection ?? "",
                  },
                ]}
              />
            ) : undefined
          }
        >
          {t ? (
            <LinesChart
              data={burn}
              points={t.points}
              dataFrom={t.dataFrom}
              series={[
                { key: "open", label: "Open", stroke: "var(--chart-1)", width: 2.5 },
                { key: "projection", label: "Estimate", stroke: "var(--chart-3)", dash: "6 4" },
              ]}
            />
          ) : null}
        </ChartCard>

        <ChartCard
          id="trend-awaiting"
          title="Awaiting verification"
          query={trends}
          state={t ? trendsEmpty(t) : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          summary={
            t
              ? `Findings waiting for a later complete scan to confirm the fix, per day.`
              : undefined
          }
          table={
            t ? (
              <ReportTable
                caption="Awaiting verification per day"
                rows={t.points}
                getRowId={(r) => r.day}
                maxHeight="18rem"
                columns={[
                  { key: "day", header: "Day", cell: (r) => dayLabel(r.day) },
                  {
                    key: "n",
                    header: "Awaiting verification",
                    align: "right",
                    cell: (r) => r.awaitingVerification ?? "no data",
                  },
                ]}
              />
            ) : undefined
          }
        >
          {t ? (
            <LinesChart
              height={200}
              data={t.points.map((pt) => ({
                day: pt.day,
                awaiting: pt.awaitingVerification ?? null,
              }))}
              points={t.points}
              dataFrom={t.dataFrom}
              series={[
                { key: "awaiting", label: "Awaiting verification", stroke: "var(--chart-2)" },
              ]}
            />
          ) : null}
        </ChartCard>
      </div>

      <GenerateReportDialog
        open={exporting}
        onOpenChange={setExporting}
        workspaceId={workspaceId}
        initial={
          asOf
            ? { template: "point_in_time_snapshot", format: "csv", asOfDay: asOf }
            : { template: "findings_by_pipeline", format: "csv" }
        }
      />
    </ReportingPage>
  );
}
