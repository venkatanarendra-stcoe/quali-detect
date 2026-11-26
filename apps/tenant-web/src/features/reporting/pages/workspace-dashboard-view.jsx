import { LIFECYCLE_GROUP_IDS } from "@qmentisai/shared";
import { AlertTriangle, Bug, Clock, FileCheck2, ShieldAlert, Workflow } from "lucide-react";
import { Link } from "react-router";
import { isApiError } from "@/lib/api/index.js";
import { LinkButton } from "@/components/common/link-button.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { PermissionGate } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import {
  COVERAGE_REASON_LABELS,
  EXECUTION_STATUS_LABELS,
  EXECUTION_STATUS_STYLE,
  GROUP_LABELS,
  GROUP_STYLE,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
} from "../constants/index.js";
import {
  BarsChart,
  FlowChart,
  LifecycleChart,
  LinesChart,
  SeverityBarsChart,
} from "../components/charts.jsx";
import { CardError, ChartCard, DataFooter } from "../components/chart-card.jsx";
import { Legend } from "../components/chart-parts.jsx";
import { DashboardViewToggle, SeverityFilter } from "../components/dashboard-controls.jsx";
import { KpiCard } from "../components/kpi-card.jsx";
import { ReportTable } from "../components/report-table.jsx";
import { ReportingPage } from "../components/reporting-page.jsx";
import { SlaBars } from "../components/sla-bars.jsx";
import {
  useCoverage,
  usePosture,
  useQuality,
  useRemediation,
  useScanActivity,
  useSla,
  useTrends,
  useWorkload,
} from "../hooks/use-reporting.js";
import { useReportingParams } from "../hooks/use-reporting-params.js";
import {
  changeOver,
  executionSummary,
  flowEmpty,
  flowSummary,
  lifecycleSummary,
  postureEmpty,
  postureSummary,
  slaSummary,
  sumOf,
} from "../schemas/derive.js";
import {
  findingsUrl,
  groupFindingsUrl,
  openFindingsUrl,
  slaFindingsUrl,
} from "../schemas/drilldown.js";
import { dayLabel, formatCount, formatDays, formatPercent } from "../schemas/format.js";
import { useReportingUiStore } from "../stores/reporting-ui-store.js";
import { DashboardTables } from "./dashboard-tables.jsx";

const EMPTY_HIDDEN = [];

/** Days of the shown period (for the sentences). */
export function periodDays(period) {
  if (period.kind === "custom")
    return Math.round((Date.parse(period.to) - Date.parse(period.from)) / 86_400_000) + 1;
  return period.period;
}

function Grid({ className = "", children }) {
  return <div className={`mb-4 grid gap-4 ${className}`}>{children}</div>;
}

/** "9 of 11 active repositories were scanned" and the repositories that were not, with the reason (S-4). */
function CoverageCard({ query, workspaceId }) {
  const data = query.data?.data;
  return (
    <Card data-testid="card-coverage" className="min-w-0">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Repository coverage</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {query.isPending ? (
          <p role="status" className="text-sm text-muted-foreground">
            Loading coverage…
          </p>
        ) : null}
        {query.isError ? <CardError error={query.error} onRetry={query.refetch} /> : null}
        {data ? (
          data.repositories.total === 0 ? (
            <p className="text-sm text-muted-foreground">No repositories are connected yet.</p>
          ) : (
            <>
              <p className="text-sm">
                <span className="font-medium tabular-nums">
                  {data.repositories.covered} of {data.repositories.total}
                </span>{" "}
                active repositories were scanned in the last 30 days.
              </p>
              {data.uncovered.length ? (
                <ul aria-label="Repositories not scanned" className="space-y-1.5 text-sm">
                  {data.uncovered.slice(0, 6).map((r) => (
                    <li key={r.repositoryId} className="flex items-center justify-between gap-2">
                      <Link
                        to={`/workspaces/${workspaceId}/repositories/${r.repositoryId}`}
                        className="min-w-0 truncate rounded-sm font-mono text-xs underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
                      >
                        {r.repositoryName}
                      </Link>
                      <span className="shrink-0 rounded-sm border border-border-strong px-1.5 py-0.5 text-xs">
                        {COVERAGE_REASON_LABELS[r.reason] ?? r.reason}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">
                  Every active repository was scanned.
                </p>
              )}
            </>
          )
        ) : null}
        <DataFooter meta={query.data?.meta} />
      </CardContent>
    </Card>
  );
}

/** The mini card of Detection quality (T-49) for `security_review.view` holders. */
function QualityMini({ query, workspaceId }) {
  const data = query.data?.data;
  const fp = data?.falsePositiveRate.overall;
  const agree = data?.advisoryAgreement;
  return (
    <Card data-testid="card-quality" className="min-w-0">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Detection quality</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {query.isPending ? (
          <p role="status" className="text-sm text-muted-foreground">
            Loading…
          </p>
        ) : null}
        {query.isError ? <CardError error={query.error} onRetry={query.refetch} /> : null}
        {data ? (
          <dl className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <dt className="text-xs text-muted-foreground">False-positive rate</dt>
              <dd className="text-xl font-semibold tabular-nums">
                {fp.tooFew ? "Too few" : formatPercent(fp.rate)}
              </dd>
              <dd className="text-xs text-muted-foreground">
                {fp.tooFew ? `n = ${fp.denominator}, too few to rate` : `n = ${fp.denominator}`}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Advisory agreement</dt>
              <dd className="text-xl font-semibold tabular-nums">
                {agree.tooFew ? "Too few" : formatPercent(agree.rate)}
              </dd>
              <dd className="text-xs text-muted-foreground">n = {agree.decided}</dd>
            </div>
          </dl>
        ) : null}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <DataFooter meta={query.data?.meta} />
          {data ? (
            <Link
              to={`/workspaces/${workspaceId}/dashboard/quality`}
              className="rounded-sm text-xs text-primary-text underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
            >
              View detection quality
            </Link>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * T-20 (chart view) and T-21 (`?view=table`) of the workspace dashboard. Every section has its own query and its own states, so
 * one failing card never blanks the page; a section without its permission is hidden (listed in the partial notice).
 * @param {{ workspaceId: string, workspaceName?: string }} props
 */
export function WorkspaceDashboardView({ workspaceId, workspaceName }) {
  const can = useCan();
  const canFinding = can("finding.view");
  const canExec = can("execution.view");
  const canQuality = can("security_review.view");
  const canAssign = can("finding.assign");
  const canApprovals = can("approval.view");

  const posture = usePosture(workspaceId, {}, { enabled: canFinding });
  const timeZone = posture.data?.meta.timeZone;
  const params = useReportingParams(timeZone);
  const { periodQuery, period, severities } = params;
  const days = periodDays(period);
  const rangeText =
    params.period.kind === "custom"
      ? `${dayLabel(params.period.from)} to ${dayLabel(params.period.to)}`
      : `The last ${days} days.`;

  const trends = useTrends(
    workspaceId,
    { ...periodQuery, series: "flow,severity,backlog" },
    { enabled: canFinding },
  );
  const remediation = useRemediation(workspaceId, periodQuery, { enabled: canFinding });
  const sla = useSla(workspaceId, { enabled: canFinding });
  const scan = useScanActivity(workspaceId, periodQuery, { enabled: canExec });
  const coverage = useCoverage(workspaceId, { enabled: canExec });
  const workload = useWorkload(workspaceId, { enabled: canAssign });
  const quality = useQuality(workspaceId, periodQuery, { enabled: canQuality });

  const hiddenFlow = useReportingUiStore((s) => s.hidden.flow ?? EMPTY_HIDDEN);
  const toggleSeries = useReportingUiStore((s) => s.toggleSeries);
  const widen = () => params.setPreset(90);

  const hidden = [];
  if (!canFinding) hidden.push("findings, trends and SLA");
  if (!canExec) hidden.push("scan activity and coverage");
  if (!canQuality) hidden.push("detection quality");
  // a section the server refused (403) is listed too, even when the person's permission set suggested it (the server decides)
  const refused = (query) => isApiError(query.error) && query.error.status === 403;
  if (canFinding && [posture, trends, sla].some(refused)) hidden.push("findings");
  if (canExec && [scan, coverage].some(refused)) hidden.push("scan activity and coverage");
  if (canAssign && refused(workload)) hidden.push("team workload");
  if (canQuality && refused(quality)) hidden.push("detection quality");
  const p = posture.data?.data;
  const t = trends.data?.data;
  const r = remediation.data?.data;
  const trendsKnown = Boolean(t);

  const flowItems = [
    { key: "new", label: "New", fill: "var(--chart-2)", pattern: "solid" },
    { key: "fixed", label: "Fixed", fill: "var(--chart-1)", pattern: "solid" },
    {
      key: "closedWithoutFix",
      label: "Closed without a fix",
      fill: "var(--chart-3)",
      pattern: "solid",
    },
    { key: "reopened", label: "Reopened", fill: "var(--chart-4)", pattern: "stripe" },
  ].map((i) => ({ ...i, off: hiddenFlow.includes(i.key) }));

  const emptyWorkspace =
    p &&
    postureEmpty(p) === "empty" &&
    (!canExec || (scan.data && scan.data.data.perDay.every((d) => d.total === 0)));

  return (
    <ReportingPage
      workspaceId={workspaceId}
      current="dashboard"
      title="Dashboard"
      description={workspaceName}
      params={params}
      timeZone={timeZone}
      hiddenSections={hidden}
      controls={
        <div className="flex flex-wrap items-center gap-3 print:hidden">
          {canFinding ? <SeverityFilter params={params} /> : null}
          <DashboardViewToggle params={params} />
        </div>
      }
    >
      {emptyWorkspace ? (
        <Card className="mb-4" data-testid="empty-workspace">
          <CardContent className="flex flex-wrap items-center justify-between gap-3 py-4">
            <div>
              <p className="text-sm font-medium">This workspace has no findings yet</p>
              <p className="text-sm text-muted-foreground">
                Connect a repository and create a pipeline to start scanning.
              </p>
            </div>
            <div className="flex gap-2">
              <PermissionGate permission="repository.connect">
                <LinkButton
                  variant="secondary"
                  to={`/workspaces/${workspaceId}/repositories/connect`}
                >
                  Connect a repository
                </LinkButton>
              </PermissionGate>
              <PermissionGate permission="pipeline.manage">
                <LinkButton variant="secondary" to={`/workspaces/${workspaceId}/pipelines/new`}>
                  Create a pipeline
                </LinkButton>
              </PermissionGate>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {params.view === "table" ? (
        <DashboardTables
          workspaceId={workspaceId}
          params={params}
          canFinding={canFinding}
          canExec={canExec}
          canAssign={canAssign}
          workload={workload}
          coverage={coverage}
        />
      ) : (
        <>
          {canFinding || canExec ? (
            <section
              aria-label="Key figures"
              className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 min-[1500px]:grid-cols-6"
            >
              {canFinding ? (
                <>
                  <KpiCard
                    id="open"
                    label="Open findings"
                    icon={Bug}
                    query={posture}
                    value={p ? formatCount(p.open) : null}
                    href={canFinding && p ? openFindingsUrl(workspaceId) : undefined}
                    change={trendsKnown ? changeOver(t, (pt) => pt.open) : undefined}
                  />
                  <KpiCard
                    id="critical"
                    label="Critical"
                    icon={ShieldAlert}
                    tone="critical"
                    query={posture}
                    value={p ? formatCount(p.bySeverity.critical) : null}
                    href={p ? openFindingsUrl(workspaceId, "critical") : undefined}
                    change={
                      trendsKnown ? changeOver(t, (pt) => pt.openBySeverity?.critical) : undefined
                    }
                  />
                  <KpiCard
                    id="median"
                    label="Median time to remediate"
                    icon={Clock}
                    query={remediation}
                    value={r ? formatDays(r.timeToRemediate.overall.medianDays) : null}
                    sub={
                      r
                        ? `p90 ${formatDays(r.timeToRemediate.overall.p90Days)} · n = ${r.timeToRemediate.overall.count}`
                        : null
                    }
                    title={
                      r
                        ? `Mean ${formatDays(r.timeToRemediate.overall.meanDays)} (the median is the headline: a few old findings do not skew it)`
                        : undefined
                    }
                    href={`/workspaces/${workspaceId}/dashboard/remediation`}
                  />
                  <KpiCard
                    id="breaches"
                    label="SLA breaches"
                    icon={AlertTriangle}
                    tone="danger"
                    query={sla}
                    value={sla.data ? formatCount(sla.data.data.open.total.breached) : null}
                    href={sla.data ? slaFindingsUrl(workspaceId, "breached") : undefined}
                  />
                  {canApprovals ? (
                    <KpiCard
                      id="awaiting"
                      label="Awaiting approval"
                      icon={FileCheck2}
                      query={posture}
                      value={p ? formatCount(p.awaitingDecision.awaitingApproval) : null}
                      sub={
                        p
                          ? `${formatCount(p.awaitingDecision.pendingExceptions)} exception requests`
                          : null
                      }
                      href={`/workspaces/${workspaceId}/approvals`}
                    />
                  ) : null}
                </>
              ) : null}
              {canExec ? (
                <KpiCard
                  id="pipelines"
                  label="Pipelines healthy"
                  icon={Workflow}
                  query={posture}
                  value={
                    p?.pipelinesHealthy
                      ? `${p.pipelinesHealthy.healthy} of ${p.pipelinesHealthy.total}`
                      : null
                  }
                  unavailable={p && !p.pipelinesHealthy ? "Not available" : undefined}
                  href={`/workspaces/${workspaceId}/pipelines`}
                />
              ) : null}
            </section>
          ) : null}

          {canFinding ? (
            <Grid className="lg:grid-cols-2">
              <ChartCard
                id="severity"
                title="Findings by severity"
                query={posture}
                state={p ? postureEmpty(p) : null}
                summary={p ? postureSummary(p) : undefined}
                link={
                  p
                    ? {
                        to: openFindingsUrl(workspaceId, severities),
                        label: `Open ${severities.length ? "these" : "all"} in Findings`,
                      }
                    : undefined
                }
                next={<span>Findings appear after the first scan finishes.</span>}
                table={
                  p ? (
                    <ReportTable
                      caption="Open findings by severity"
                      rows={SEVERITY_ORDER.map((s) => ({ severity: s, count: p.bySeverity[s] }))}
                      getRowId={(row) => row.severity}
                      columns={[
                        {
                          key: "severity",
                          header: "Severity",
                          cell: (row) => SEVERITY_LABELS[row.severity],
                        },
                        {
                          key: "count",
                          header: "Open findings",
                          align: "right",
                          cell: (row) => (
                            <Link
                              className="underline-offset-4 hover:underline"
                              to={openFindingsUrl(workspaceId, row.severity)}
                            >
                              {formatCount(row.count)}
                            </Link>
                          ),
                        },
                      ]}
                    />
                  ) : undefined
                }
                legend={
                  p ? (
                    <Legend
                      label="Severity filter"
                      onToggle={params.toggleSeverity}
                      items={SEVERITY_ORDER.map((s) => ({
                        key: s,
                        label: SEVERITY_LABELS[s],
                        value: formatCount(p.bySeverity[s]),
                        fill: `var(--sev-${s})`,
                        pattern: ["solid", "stripe", "dots", "cross", "lines"][
                          SEVERITY_ORDER.indexOf(s)
                        ],
                        off: severities.length > 0 && !severities.includes(s),
                      }))}
                    />
                  ) : undefined
                }
              >
                {p ? (
                  <SeverityBarsChart
                    counts={p.bySeverity}
                    selected={severities}
                    onSelect={params.toggleSeverity}
                  />
                ) : null}
              </ChartCard>
              <ChartCard
                id="lifecycle"
                title="Finding lifecycle"
                query={posture}
                state={p ? postureEmpty(p) : null}
                summary={p ? lifecycleSummary(p) : undefined}
                table={
                  p ? (
                    <ReportTable
                      caption="Findings by lifecycle group"
                      rows={LIFECYCLE_GROUP_IDS.map((g) => ({ group: g, count: p.byGroup[g] }))}
                      getRowId={(row) => row.group}
                      columns={[
                        { key: "group", header: "Group", cell: (row) => GROUP_LABELS[row.group] },
                        {
                          key: "count",
                          header: "Findings",
                          align: "right",
                          cell: (row) => (
                            <Link
                              className="underline-offset-4 hover:underline"
                              to={groupFindingsUrl(workspaceId, row.group)}
                            >
                              {formatCount(row.count)}
                            </Link>
                          ),
                        },
                      ]}
                    />
                  ) : undefined
                }
                legend={
                  p ? (
                    <Legend
                      label="Lifecycle groups"
                      items={LIFECYCLE_GROUP_IDS.map((g) => ({
                        key: g,
                        label: GROUP_LABELS[g],
                        value: formatCount(p.byGroup[g]),
                        fill: GROUP_STYLE[g].fill,
                        pattern: GROUP_STYLE[g].pattern,
                        href: groupFindingsUrl(workspaceId, g),
                      }))}
                    />
                  ) : undefined
                }
              >
                {p ? <LifecycleChart byGroup={p.byGroup} /> : null}
              </ChartCard>
            </Grid>
          ) : null}

          <Grid className="lg:grid-cols-2">
            {canFinding ? (
              <ChartCard
                id="flow"
                title="New vs fixed"
                query={trends}
                state={t ? flowEmpty(t) : null}
                rangeText={rangeText}
                onWiden={widen}
                recomputing={t?.recomputing}
                summary={t ? flowSummary(t, days) : undefined}
                link={{ to: `/workspaces/${workspaceId}/dashboard/trends`, label: "View trends" }}
                legend={
                  t ? (
                    <Legend
                      label="Series (toggle)"
                      items={flowItems}
                      onToggle={(k) => toggleSeries("flow", k)}
                    />
                  ) : undefined
                }
                table={t ? <FlowTable points={t.points} /> : undefined}
              >
                {t ? (
                  <FlowChart points={t.points} dataFrom={t.dataFrom} hidden={hiddenFlow} />
                ) : null}
              </ChartCard>
            ) : null}
            {canExec ? (
              <ChartCard
                id="executions"
                title="Execution trend"
                query={scan}
                state={
                  scan.data && scan.data.data.perDay.every((d) => d.total === 0) ? "period" : null
                }
                rangeText={rangeText}
                onWiden={widen}
                summary={scan.data ? executionSummary(scan.data.data, days) : undefined}
                link={{
                  to: `/workspaces/${workspaceId}/dashboard/scan-activity`,
                  label: "View scan activity",
                }}
                legend={
                  <Legend
                    label="Execution statuses"
                    items={["succeeded", "failed", "partial", "timed_out"].map((k) => ({
                      key: k,
                      label: EXECUTION_STATUS_LABELS[k],
                      ...EXECUTION_STATUS_STYLE[k],
                    }))}
                  />
                }
                table={scan.data ? <ExecutionTable perDay={scan.data.data.perDay} /> : undefined}
              >
                {scan.data ? (
                  <LinesChart
                    data={scan.data.data.perDay.map((d) => ({ day: d.day, ...d.byStatus }))}
                    series={[
                      { key: "succeeded", label: "Succeeded", stroke: "var(--status-success)" },
                      { key: "failed", label: "Failed", stroke: "var(--status-danger)" },
                      {
                        key: "partial",
                        label: "Partial",
                        stroke: "var(--status-warning)",
                        dash: "5 3",
                      },
                      {
                        key: "timed_out",
                        label: "Timed out",
                        stroke: "var(--status-danger)",
                        dash: "1 3",
                      },
                    ]}
                  />
                ) : null}
              </ChartCard>
            ) : null}
          </Grid>

          <Grid className="lg:grid-cols-3">
            {canFinding ? (
              <ChartCard
                id="sla"
                title="SLA status"
                query={sla}
                state={sla.data && sumOf(sla.data.data.open.total) === 0 ? "empty" : null}
                summary={sla.data ? slaSummary(sla.data.data) : undefined}
                link={{
                  to: `/workspaces/${workspaceId}/dashboard/remediation`,
                  label: "View remediation",
                }}
                skeletonHeight="h-40"
                table={
                  sla.data ? (
                    <ReportTable
                      caption="Open findings by SLA state and severity"
                      rows={SEVERITY_ORDER.filter((s) => s !== "info").map((s) => ({
                        severity: s,
                        ...sla.data.data.open.bySeverity[s],
                      }))}
                      getRowId={(row) => row.severity}
                      columns={[
                        {
                          key: "severity",
                          header: "Severity",
                          cell: (row) => SEVERITY_LABELS[row.severity],
                        },
                        {
                          key: "onTrack",
                          header: "On track",
                          align: "right",
                          cell: (row) => formatCount(row.onTrack),
                        },
                        {
                          key: "dueSoon",
                          header: "Due soon",
                          align: "right",
                          cell: (row) => formatCount(row.dueSoon),
                        },
                        {
                          key: "breached",
                          header: "Breached",
                          align: "right",
                          cell: (row) => formatCount(row.breached),
                        },
                      ]}
                    />
                  ) : undefined
                }
              >
                {sla.data ? (
                  <SlaBars
                    total={sla.data.data.open.total}
                    workspaceId={workspaceId}
                    canDrill={canFinding}
                  />
                ) : null}
              </ChartCard>
            ) : null}
            {canExec ? <CoverageCard query={coverage} workspaceId={workspaceId} /> : null}
            {canAssign ? <WorkloadCard query={workload} workspaceId={workspaceId} /> : null}
          </Grid>

          {canQuality ? (
            <Grid className="lg:grid-cols-3">
              <QualityMini query={quality} workspaceId={workspaceId} />
            </Grid>
          ) : null}
        </>
      )}
    </ReportingPage>
  );
}

function FlowTable({ points }) {
  return (
    <ReportTable
      caption="New, fixed, closed without a fix and reopened per day"
      rows={points}
      getRowId={(row) => row.day}
      maxHeight="18rem"
      columns={[
        { key: "day", header: "Day", cell: (row) => dayLabel(row.day) },
        {
          key: "new",
          header: "New",
          align: "right",
          cell: (row) => (row.new === undefined ? "no data" : row.new),
        },
        {
          key: "fixed",
          header: "Fixed",
          align: "right",
          cell: (row) => (row.fixed === undefined ? "no data" : row.fixed),
        },
        {
          key: "closed",
          header: "Closed without a fix",
          align: "right",
          cell: (row) => (row.closedWithoutFix === undefined ? "no data" : row.closedWithoutFix),
        },
        {
          key: "reopened",
          header: "Reopened",
          align: "right",
          cell: (row) => (row.reopened === undefined ? "no data" : row.reopened),
        },
      ]}
    />
  );
}

function ExecutionTable({ perDay }) {
  return (
    <ReportTable
      caption="Executions per day by status"
      rows={perDay}
      getRowId={(row) => row.day}
      maxHeight="18rem"
      columns={[
        { key: "day", header: "Day", cell: (row) => dayLabel(row.day) },
        ...["succeeded", "failed", "partial", "timed_out"].map((k) => ({
          key: k,
          header: EXECUTION_STATUS_LABELS[k],
          align: "right",
          cell: (row) => row.byStatus[k],
        })),
      ]}
    />
  );
}

/** Team workload (B-6): only for `finding.assign`; alphabetical, never ranked (SPEC 5 rule 10). */
function WorkloadCard({ query, workspaceId }) {
  const data = query.data?.data;
  const rows = data
    ? [...data.assignees].sort((a, b) => a.user.displayName.localeCompare(b.user.displayName))
    : [];
  const chartRows = rows.map((a) => ({
    name: a.user.displayName,
    onTrack: Math.max(0, a.open - a.dueSoon - a.breached),
    dueSoon: a.dueSoon,
    breached: a.breached,
  }));
  return (
    <ChartCard
      id="workload"
      title="Team workload"
      query={query}
      state={data && rows.length === 0 && data.unassigned === 0 ? "empty" : null}
      summary={
        data
          ? `${formatCount(rows.length)} ${rows.length === 1 ? "person has" : "people have"} open findings; ${formatCount(data.unassigned)} are unassigned. People are listed alphabetically, not ranked.`
          : undefined
      }
      skeletonHeight="h-40"
      link={
        data
          ? {
              to: findingsUrl(workspaceId, { view: "all_open", assignee: "unassigned" }),
              label: "Open unassigned in Findings",
            }
          : undefined
      }
      legend={
        <Legend
          label="Workload"
          items={[
            { key: "onTrack", label: "On track", fill: "var(--status-success)", pattern: "solid" },
            { key: "dueSoon", label: "Due soon", fill: "var(--status-warning)", pattern: "stripe" },
            { key: "breached", label: "Breached", fill: "var(--status-danger)", pattern: "solid" },
          ]}
        />
      }
      table={
        data ? (
          <ReportTable
            caption="Open findings per assignee"
            rows={rows}
            getRowId={(row) => row.user.id}
            columns={[
              { key: "name", header: "Assignee", cell: (row) => row.user.displayName },
              {
                key: "open",
                header: "Open",
                align: "right",
                cell: (row) => (
                  <Link
                    className="underline-offset-4 hover:underline"
                    to={findingsUrl(workspaceId, { view: "all_open", assignee: row.user.id })}
                  >
                    {row.open}
                  </Link>
                ),
              },
              { key: "dueSoon", header: "Due soon", align: "right", cell: (row) => row.dueSoon },
              { key: "breached", header: "Breached", align: "right", cell: (row) => row.breached },
            ]}
          />
        ) : undefined
      }
    >
      {data ? (
        <BarsChart
          data={chartRows}
          xKey="name"
          horizontal
          yWidth={96}
          height={Math.max(140, chartRows.length * 44 + 40)}
          series={[
            { key: "onTrack", label: "On track", fill: "var(--status-success)", pattern: "solid" },
            { key: "dueSoon", label: "Due soon", fill: "var(--status-warning)", pattern: "stripe" },
            { key: "breached", label: "Breached", fill: "var(--status-danger)", pattern: "solid" },
          ]}
        />
      ) : null}
    </ChartCard>
  );
}
