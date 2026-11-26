import {
  CircleCheck,
  CircleMinus,
  Code2,
  Download,
  KeyRound,
  Library,
  Package,
  TriangleAlert,
} from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { useActiveWorkspace } from "@/features/authorization/hooks/use-permissions.js";
import { formatDuration } from "@/features/executions/components/execution-bits.jsx";
import {
  COVERAGE_REASON_LABELS,
  EXECUTION_STATUS_LABELS,
  EXECUTION_STATUS_STYLE,
  SCAN_TYPE_FULL,
} from "../constants/index.js";
import { BarsChart, LinesChart } from "../components/charts.jsx";
import { CardError, ChartCard, DataFooter } from "../components/chart-card.jsx";
import { Legend } from "../components/chart-parts.jsx";
import { GenerateReportDialog } from "../components/generate-report-dialog.jsx";
import { KpiCard } from "../components/kpi-card.jsx";
import { ReportTable } from "../components/report-table.jsx";
import { ReportingPage } from "../components/reporting-page.jsx";
import { useCoverage, usePosture, useSbom, useScanActivity } from "../hooks/use-reporting.js";
import { useReportingParams } from "../hooks/use-reporting-params.js";
import { executionSummary, sumOf } from "../schemas/derive.js";
import { dayLabel, formatCount, formatPercent } from "../schemas/format.js";
import { periodDays } from "./workspace-dashboard-view.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";

const STATUSES = ["succeeded", "failed", "partial", "timed_out", "cancelled", "skipped", "blocked"];
const SCAN_ICON = { sbom: Package, sca: Library, sast: Code2, secrets: KeyRound };

/** Four small icons with text for the scan types a pipeline runs (never an icon alone). */
function ScanTypes({ scanTypes }) {
  return (
    <ul className="flex flex-wrap gap-x-3 gap-y-1">
      {scanTypes.map((s) => {
        const Icon = SCAN_ICON[s.type];
        const state = !s.enabled
          ? "off"
          : s.lastComplete === true
            ? "complete"
            : s.lastComplete === false
              ? "partial"
              : "not run";
        const StateIcon = !s.enabled
          ? CircleMinus
          : s.lastComplete === true
            ? CircleCheck
            : TriangleAlert;
        return (
          <li key={s.type} className="inline-flex items-center gap-1 text-xs">
            <Icon aria-hidden="true" className="size-3.5 text-muted-foreground" />
            {SCAN_TYPE_FULL[s.type]}
            <StateIcon
              aria-hidden="true"
              className={`size-3 ${s.enabled && s.lastComplete !== true ? "text-status-warning" : "text-muted-foreground"}`}
            />
            <span className="text-muted-foreground">{state}</span>
          </li>
        );
      })}
    </ul>
  );
}

/** T-48 Scan activity and coverage. */
export function ScanActivityPage() {
  const { workspaceId } = useParams();
  const active = useActiveWorkspace();
  const live = useCoverage(workspaceId);
  const posture = usePosture(workspaceId, {});
  const timeZone = posture.data?.meta.timeZone ?? live.data?.meta.timeZone;
  const params = useReportingParams(timeZone);
  const days = periodDays(params.period);
  const scan = useScanActivity(workspaceId, params.periodQuery);
  const sbom = useSbom(workspaceId, params.periodQuery);
  const [exporting, setExporting] = useState(false);
  const d = scan.data?.data;
  const cov = live.data?.data;
  const sb = sbom.data?.data;
  const total = d ? d.perDay.reduce((a, x) => a + x.total, 0) : 0;
  const rangeText = `The last ${days} days.`;
  const rate = d?.successRate;
  const eligible = d?.ingestionEligibleShare;

  return (
    <ReportingPage
      workspaceId={workspaceId}
      current="scan-activity"
      title="Scan activity and coverage"
      description={active?.name}
      params={params}
      timeZone={timeZone}
    >
      <section aria-label="Key figures" className="mb-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KpiCard
          id="executions"
          label="Executions"
          query={scan}
          value={d ? formatCount(total) : null}
          sub={d ? `in ${days} days` : null}
          href={`/workspaces/${workspaceId}/executions`}
        />
        <KpiCard
          id="success"
          label="Success rate"
          query={scan}
          value={d ? formatPercent(rate.rate) : null}
          sub={d ? `${rate.numerator} of ${rate.denominator} with a result` : null}
          title="Succeeded divided by (succeeded, failed, partial and timed out). Cancelled, skipped and blocked runs are shown apart and are not in the rate."
        />
        <KpiCard
          id="duration"
          label="Median duration"
          query={scan}
          value={d ? formatDuration(d.duration.medianMs) : null}
          sub={
            d
              ? `p90 ${formatDuration(d.duration.p90Ms)} · queue wait median ${formatDuration(d.queueWait.medianMs)}`
              : null
          }
        />
        <KpiCard
          id="eligible"
          label="Ingestion eligible"
          query={scan}
          value={
            d ? (eligible.total ? formatPercent(eligible.eligible / eligible.total) : "—") : null
          }
          sub={
            d
              ? `${eligible.eligible} of ${eligible.total} executions can create findings (trusted default branch)`
              : null
          }
        />
      </section>

      <div className="grid gap-4 xl:grid-cols-2">
        <ChartCard
          id="scan-per-day"
          title="Executions per day by status"
          query={scan}
          state={d && total === 0 ? "period" : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          summary={d ? executionSummary(d, days) : undefined}
          link={{ to: `/workspaces/${workspaceId}/executions`, label: "Open executions" }}
          legend={
            <Legend
              label="Execution status"
              items={STATUSES.map((k) => ({
                key: k,
                label: EXECUTION_STATUS_LABELS[k],
                ...EXECUTION_STATUS_STYLE[k],
              }))}
            />
          }
          table={
            d ? (
              <ReportTable
                caption="Executions per day by status"
                rows={d.perDay}
                getRowId={(x) => x.day}
                maxHeight="18rem"
                columns={[
                  { key: "day", header: "Day", cell: (x) => dayLabel(x.day) },
                  ...STATUSES.map((k) => ({
                    key: k,
                    header: EXECUTION_STATUS_LABELS[k],
                    align: "right",
                    cell: (x) => x.byStatus[k],
                  })),
                ]}
              />
            ) : undefined
          }
        >
          {d ? (
            <BarsChart
              data={d.perDay.map((x) => ({ day: x.day, ...x.byStatus }))}
              xFormatter={dayLabel}
              labelFormatter={(l) => dayLabel(l)}
              series={STATUSES.map((k) => ({
                key: k,
                label: EXECUTION_STATUS_LABELS[k],
                ...EXECUTION_STATUS_STYLE[k],
              }))}
            />
          ) : null}
        </ChartCard>

        <ChartCard
          id="scan-duration"
          title="Duration and queue wait"
          query={scan}
          state={d && total === 0 ? "period" : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          summary={
            d
              ? `Median duration ${formatDuration(d.duration.medianMs)} and p90 ${formatDuration(d.duration.p90Ms)}; queue wait median ${formatDuration(d.queueWait.medianMs)} and p90 ${formatDuration(d.queueWait.p90Ms)}. The API gives the period figures, not a per-day trend.`
              : undefined
          }
          skeletonHeight="h-32"
        >
          {d ? (
            <ReportTable
              caption="Duration and queue wait"
              rows={[
                {
                  key: "duration",
                  name: "Duration",
                  median: d.duration.medianMs,
                  p90: d.duration.p90Ms,
                },
                {
                  key: "queue",
                  name: "Queue wait",
                  median: d.queueWait.medianMs,
                  p90: d.queueWait.p90Ms,
                },
              ]}
              getRowId={(x) => x.key}
              columns={[
                { key: "name", header: "Measure", cell: (x) => x.name },
                {
                  key: "median",
                  header: "Median",
                  align: "right",
                  cell: (x) => formatDuration(x.median),
                },
                { key: "p90", header: "p90", align: "right", cell: (x) => formatDuration(x.p90) },
              ]}
            />
          ) : null}
        </ChartCard>

        <ChartCard
          id="scan-completeness"
          title="Result completeness"
          query={scan}
          state={d && sumOf(d.completeness) === 0 ? "period" : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          summary={
            d
              ? `${formatCount(d.completeness.complete)} of ${formatCount(sumOf(d.completeness))} results with an outcome were complete; ${formatCount(d.completeness.incomplete)} were partial. The API gives the total, not a split by scan type.`
              : undefined
          }
          skeletonHeight="h-24"
          legend={
            <Legend
              label="Completeness"
              items={[
                {
                  key: "complete",
                  label: "Complete",
                  fill: "var(--status-success)",
                  pattern: "solid",
                },
                {
                  key: "incomplete",
                  label: "Incomplete",
                  fill: "var(--status-warning)",
                  pattern: "stripe",
                },
              ]}
            />
          }
        >
          {d ? (
            <BarsChart
              horizontal
              height={90}
              xKey="name"
              yWidth={8}
              data={[{ name: "Results", ...d.completeness }]}
              series={[
                {
                  key: "complete",
                  label: "Complete",
                  fill: "var(--status-success)",
                  pattern: "solid",
                },
                {
                  key: "incomplete",
                  label: "Incomplete",
                  fill: "var(--status-warning)",
                  pattern: "stripe",
                },
              ]}
            />
          ) : null}
        </ChartCard>

        <Card data-testid="card-coverage" className="min-w-0">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Coverage</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {live.isPending ? (
              <p role="status" className="text-sm text-muted-foreground">
                Loading coverage…
              </p>
            ) : null}
            {live.isError ? <CardError error={live.error} onRetry={live.refetch} /> : null}
            {cov ? (
              cov.repositories.total === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No repositories without pipelines or scans to report: no repository is connected
                  yet.
                </p>
              ) : (
                <>
                  <p className="text-sm">
                    <span className="font-medium tabular-nums">
                      {cov.repositories.covered} of {cov.repositories.total}
                    </span>{" "}
                    active repositories were scanned in the last 30 days.
                  </p>
                  {cov.uncovered.length ? (
                    <ReportTable
                      caption="Repositories that were not covered"
                      rows={cov.uncovered}
                      getRowId={(x) => x.repositoryId}
                      maxHeight="14rem"
                      columns={[
                        {
                          key: "name",
                          header: "Repository",
                          sortValue: (x) => x.repositoryName,
                          cell: (x) => (
                            <Link
                              to={`/workspaces/${workspaceId}/repositories/${x.repositoryId}`}
                              className="block max-w-64 truncate font-mono text-xs underline-offset-4 hover:underline"
                              title={x.repositoryName}
                            >
                              {x.repositoryName}
                            </Link>
                          ),
                        },
                        {
                          key: "reason",
                          header: "Reason",
                          cell: (x) => (
                            <span className="rounded-sm border border-border-strong px-1.5 py-0.5 text-xs">
                              {COVERAGE_REASON_LABELS[x.reason] ?? x.reason}
                            </span>
                          ),
                        },
                      ]}
                    />
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      Every active repository was scanned.
                    </p>
                  )}
                  {cov.pipelines.length ? (
                    <ReportTable
                      caption="Scan types per pipeline"
                      rows={cov.pipelines}
                      getRowId={(x) => x.pipelineId}
                      maxHeight="14rem"
                      columns={[
                        {
                          key: "name",
                          header: "Pipeline",
                          cell: (x) => (
                            <span className="block max-w-48 truncate" title={x.pipelineName}>
                              {x.pipelineName}
                            </span>
                          ),
                        },
                        {
                          key: "types",
                          header: "Scan types",
                          cell: (x) => <ScanTypes scanTypes={x.scanTypes} />,
                        },
                      ]}
                    />
                  ) : null}
                </>
              )
            ) : null}
            <DataFooter meta={live.data?.meta} />
          </CardContent>
        </Card>
      </div>

      <ChartCard
        id="scan-sbom"
        title="SBOM inventory"
        className="mt-4"
        query={sbom}
        state={sb && sb.components === 0 ? "empty" : null}
        next={<span>Components appear after a scan with SBOM enabled finishes.</span>}
        summary={
          sb
            ? `${formatCount(sb.components)} components, ${formatCount(sb.vulnerable)} with a known vulnerability (${sb.components ? formatPercent(sb.vulnerable / sb.components) : "—"}).`
            : undefined
        }
        legend={
          sb ? (
            <PermissionGate permission="report.export">
              <Button variant="secondary" size="sm" onClick={() => setExporting(true)}>
                <Download aria-hidden="true" />
                Download SBOM inventory (CSV)
              </Button>
            </PermissionGate>
          ) : undefined
        }
        table={
          sb ? (
            <ReportTable
              caption="Components by ecosystem"
              rows={sb.byEcosystem}
              getRowId={(x) => x.ecosystem}
              columns={[
                {
                  key: "eco",
                  header: "Ecosystem",
                  cell: (x) => <span className="font-mono text-xs">{x.ecosystem}</span>,
                },
                {
                  key: "n",
                  header: "Components",
                  align: "right",
                  cell: (x) => formatCount(x.components),
                },
              ]}
            />
          ) : undefined
        }
      >
        {sb ? (
          <div className="grid gap-4 lg:grid-cols-2">
            <BarsChart
              horizontal
              stacked={false}
              height={200}
              xKey="ecosystem"
              yWidth={64}
              showLabels
              data={sb.byEcosystem}
              series={[
                {
                  key: "components",
                  label: "Components",
                  fill: "var(--chart-2)",
                  pattern: "solid",
                },
              ]}
            />
            <LinesChart
              height={200}
              yWidth={48}
              data={sb.trend}
              series={[
                { key: "components", label: "Components", stroke: "var(--chart-1)" },
                {
                  key: "vulnerable",
                  label: "With a known vulnerability",
                  stroke: "var(--chart-3)",
                  dash: "5 3",
                },
              ]}
            />
          </div>
        ) : null}
      </ChartCard>
      <GenerateReportDialog
        open={exporting}
        onOpenChange={setExporting}
        workspaceId={workspaceId}
        initial={{ template: "sbom_inventory", format: "csv" }}
      />
    </ReportingPage>
  );
}
