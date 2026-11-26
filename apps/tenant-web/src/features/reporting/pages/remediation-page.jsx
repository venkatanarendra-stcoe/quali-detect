import { Info } from "lucide-react";
import { Link, useParams } from "react-router";
import { useActiveWorkspace } from "@/features/authorization/hooks/use-permissions.js";
import { SeverityBadge } from "@/features/findings/components/finding-bits.jsx";
import {
  SEVERITY_FILL,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  SLA_STATE_STYLE,
} from "../constants/index.js";
import { BarsChart } from "../components/charts.jsx";
import { ChartCard } from "../components/chart-card.jsx";
import { Legend } from "../components/chart-parts.jsx";
import { KpiCard } from "../components/kpi-card.jsx";
import { RangeBarsChart } from "../components/range-chart.jsx";
import { ReportTable } from "../components/report-table.jsx";
import { ReportingPage } from "../components/reporting-page.jsx";
import { useAging, usePosture, useRemediation, useSla } from "../hooks/use-reporting.js";
import { useReportingParams } from "../hooks/use-reporting-params.js";
import { remediationSummary, slaSummary, sumOf } from "../schemas/derive.js";
import { findingUrl, openFindingsUrl, slaFindingsUrl } from "../schemas/drilldown.js";
import { dayLabel, formatCount, formatDays, formatPercent } from "../schemas/format.js";
import { periodDays } from "./workspace-dashboard-view.jsx";
import { SlaBars } from "../components/sla-bars.jsx";

const BUCKET_LABEL = {
  "0-7": "0 to 7 days",
  "8-30": "8 to 30 days",
  "31-90": "31 to 90 days",
  "90+": "Over 90 days",
};

/**
 * Aging heat strip: age bucket by severity. The count is written in every cell (never colour alone); the tint only shows relative
 * density. An age bucket is not expressible as a Findings URL filter, so a cell is not a link.
 */
function AgingHeat({ buckets }) {
  const max = Math.max(1, ...buckets.flatMap((b) => SEVERITY_ORDER.map((s) => b.bySeverity[s])));
  return (
    <div className="qm-scroll overflow-x-auto">
      <table className="w-full min-w-[28rem] border-separate border-spacing-1 text-sm">
        <caption className="sr-only">Open findings by age and severity</caption>
        <thead>
          <tr>
            <th
              scope="col"
              className="px-2 py-1 text-left text-xs font-medium text-muted-foreground"
            >
              Age
            </th>
            {SEVERITY_ORDER.map((s) => (
              <th
                key={s}
                scope="col"
                className="px-2 py-1 text-right text-xs font-medium text-muted-foreground"
              >
                {SEVERITY_LABELS[s]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {buckets.map((b) => (
            <tr key={b.bucket}>
              <th scope="row" className="px-2 py-1 text-left text-xs font-medium whitespace-nowrap">
                {BUCKET_LABEL[b.bucket]}
              </th>
              {SEVERITY_ORDER.map((s) => (
                <td
                  key={s}
                  className="rounded-sm px-2 py-2 text-right font-medium tabular-nums"
                  style={{
                    background: `color-mix(in srgb, ${SEVERITY_FILL[s]} ${Math.round((b.bySeverity[s] / max) * 35)}%, var(--card))`,
                  }}
                >
                  {b.bySeverity[s]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** T-47 Remediation and SLA performance. */
export function RemediationPage() {
  const { workspaceId } = useParams();
  const active = useActiveWorkspace();
  const live = usePosture(workspaceId, {});
  const timeZone = live.data?.meta.timeZone;
  const params = useReportingParams(timeZone);
  const days = periodDays(params.period);
  const remediation = useRemediation(workspaceId, params.periodQuery);
  const sla = useSla(workspaceId);
  const aging = useAging(workspaceId);
  const r = remediation.data?.data;
  const s = sla.data?.data;
  const a = aging.data?.data;

  const closedTotals = s
    ? SEVERITY_ORDER.filter((x) => x !== "info").reduce(
        (acc, k) => ({
          withTarget: acc.withTarget + s.closed[k].withTarget,
          within: acc.within + s.closed[k].withinSla,
        }),
        { withTarget: 0, within: 0 },
      )
    : null;
  const weeks = r?.velocity.length ?? 0;
  const fixedTotal = r ? r.velocity.reduce((x, w) => x + w.fixed, 0) : 0;
  const rangeRows = r
    ? SEVERITY_ORDER.filter((k) => r.timeToRemediate.bySeverity[k].count > 0).map((k) => ({
        severity: k,
        median: r.timeToRemediate.bySeverity[k].medianDays,
        p90: r.timeToRemediate.bySeverity[k].p90Days,
        count: r.timeToRemediate.bySeverity[k].count,
      }))
    : [];
  const noFixes = r && r.timeToRemediate.overall.count === 0;
  const rangeText = `${dayLabel(params.today)} and the ${days - 1} days before`;

  return (
    <ReportingPage
      workspaceId={workspaceId}
      current="remediation"
      title="Remediation and SLA performance"
      description={active?.name}
      params={params}
      timeZone={timeZone}
    >
      <p className="mb-4 flex items-start gap-2 text-xs text-muted-foreground">
        <Info aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
        Findings are per pipeline; the same issue in two pipelines counts twice.
      </p>
      <section
        aria-label="Key figures"
        className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5"
      >
        <KpiCard
          id="median"
          label="Median time to remediate"
          query={remediation}
          value={r ? formatDays(r.timeToRemediate.overall.medianDays) : null}
          sub={
            r
              ? `p90 ${formatDays(r.timeToRemediate.overall.p90Days)} · n = ${r.timeToRemediate.overall.count}`
              : null
          }
          title={r ? `Mean ${formatDays(r.timeToRemediate.overall.meanDays)}` : undefined}
        />
        <KpiCard
          id="first-decision"
          label="Time to first decision"
          query={remediation}
          value={r ? formatDays(r.timeToFirstDecision.overall.medianDays) : null}
          sub={
            r
              ? `median · p90 ${formatDays(r.timeToFirstDecision.overall.p90Days)} · n = ${r.timeToFirstDecision.overall.count}`
              : null
          }
        />
        <KpiCard
          id="sla-compliance"
          label="Fixed within SLA"
          query={sla}
          value={
            closedTotals
              ? closedTotals.withTarget
                ? formatPercent(closedTotals.within / closedTotals.withTarget)
                : "—"
              : null
          }
          sub={
            closedTotals
              ? `${closedTotals.within} of ${closedTotals.withTarget} fixes with an SLA`
              : null
          }
        />
        <KpiCard
          id="velocity"
          label="Fixed per week"
          query={remediation}
          value={r ? formatCount(weeks ? Math.round((fixedTotal / weeks) * 10) / 10 : 0) : null}
          sub={r ? `average over ${weeks} ${weeks === 1 ? "week" : "weeks"}` : null}
        />
        <KpiCard
          id="reopen"
          label="Reopen rate"
          query={remediation}
          value={r ? (r.reopenRate.tooFew ? "Too few" : formatPercent(r.reopenRate.rate)) : null}
          sub={
            r
              ? r.reopenRate.tooFew
                ? `n = ${r.reopenRate.denominator}, too few to rate`
                : `${r.reopenRate.numerator} of ${r.reopenRate.denominator} fixed findings`
              : null
          }
        />
      </section>

      <div className="grid gap-4 xl:grid-cols-2">
        <ChartCard
          id="rem-range"
          title="Time to remediate by severity"
          query={remediation}
          state={noFixes ? "period" : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          summary={r ? remediationSummary(r) : undefined}
          table={
            r ? (
              <ReportTable
                caption="Time to remediate by severity"
                rows={SEVERITY_ORDER.map((k) => ({
                  severity: k,
                  ...r.timeToRemediate.bySeverity[k],
                }))}
                getRowId={(x) => x.severity}
                columns={[
                  { key: "severity", header: "Severity", cell: (x) => SEVERITY_LABELS[x.severity] },
                  { key: "count", header: "Fixed (n)", align: "right", cell: (x) => x.count },
                  {
                    key: "median",
                    header: "Median",
                    align: "right",
                    cell: (x) => formatDays(x.medianDays),
                  },
                  { key: "p90", header: "p90", align: "right", cell: (x) => formatDays(x.p90Days) },
                  {
                    key: "mean",
                    header: "Mean",
                    align: "right",
                    cell: (x) => formatDays(x.meanDays),
                  },
                ]}
              />
            ) : undefined
          }
        >
          {r ? <RangeBarsChart rows={rangeRows} /> : null}
        </ChartCard>

        <ChartCard
          id="rem-sla"
          title="SLA status by severity"
          query={sla}
          state={s && sumOf(s.open.total) === 0 ? "empty" : null}
          summary={s ? slaSummary(s) : undefined}
          legend={
            <Legend
              label="SLA state"
              items={Object.values(SLA_STATE_STYLE).map((x) => ({
                key: x.filter,
                label: x.label,
                fill: x.fill,
                pattern: x.pattern,
                href: slaFindingsUrl(workspaceId, x.filter),
              }))}
            />
          }
          table={
            s ? (
              <ReportTable
                caption="Open findings by SLA state and severity"
                rows={SEVERITY_ORDER.filter((k) => k !== "info").map((k) => ({
                  severity: k,
                  ...s.open.bySeverity[k],
                }))}
                getRowId={(x) => x.severity}
                columns={[
                  { key: "severity", header: "Severity", cell: (x) => SEVERITY_LABELS[x.severity] },
                  { key: "onTrack", header: "On track", align: "right", cell: (x) => x.onTrack },
                  { key: "dueSoon", header: "Due soon", align: "right", cell: (x) => x.dueSoon },
                  {
                    key: "breached",
                    header: "Breached",
                    align: "right",
                    cell: (x) => (
                      <Link
                        className="underline-offset-4 hover:underline"
                        to={slaFindingsUrl(workspaceId, "breached", x.severity)}
                      >
                        {x.breached}
                      </Link>
                    ),
                  },
                ]}
              />
            ) : undefined
          }
        >
          {s ? (
            <>
              <BarsChart
                horizontal
                height={210}
                yWidth={64}
                xKey="label"
                data={SEVERITY_ORDER.filter((k) => k !== "info").map((k) => ({
                  label: SEVERITY_LABELS[k],
                  ...s.open.bySeverity[k],
                }))}
                series={Object.entries(SLA_STATE_STYLE).map(([key, x]) => ({
                  key,
                  label: x.label,
                  fill: x.fill,
                  pattern: x.pattern,
                }))}
              />
              <div className="mt-3">
                <SlaBars total={s.open.total} workspaceId={workspaceId} canDrill />
              </div>
            </>
          ) : null}
        </ChartCard>

        <ChartCard
          id="rem-aging"
          title="Aging of open findings"
          query={aging}
          state={a && a.buckets.every((b) => sumOf(b.bySeverity) === 0) ? "empty" : null}
          summary={
            a
              ? `${formatCount(a.buckets.reduce((x, b) => x + sumOf(b.bySeverity), 0))} open findings by age; ${formatCount(sumOf(a.buckets[3].bySeverity))} are older than 90 days.`
              : undefined
          }
          link={{ to: openFindingsUrl(workspaceId), label: "Open in Findings" }}
        >
          {a ? <AgingHeat buckets={a.buckets} /> : null}
        </ChartCard>

        <ChartCard
          id="rem-velocity"
          title="Fixed per week"
          query={remediation}
          state={noFixes ? "period" : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          summary={
            r
              ? `${formatCount(fixedTotal)} findings were fixed over ${weeks} ${weeks === 1 ? "week" : "weeks"} (a week starts on the day shown).`
              : undefined
          }
          table={
            r ? (
              <ReportTable
                caption="Fixed per week"
                rows={r.velocity}
                getRowId={(x) => x.weekStart}
                columns={[
                  { key: "week", header: "Week starting", cell: (x) => dayLabel(x.weekStart) },
                  { key: "fixed", header: "Fixed", align: "right", cell: (x) => x.fixed },
                ]}
              />
            ) : undefined
          }
        >
          {r ? (
            <BarsChart
              height={220}
              xKey="weekStart"
              xFormatter={dayLabel}
              labelFormatter={(l) => `Week of ${dayLabel(l)}`}
              stacked={false}
              data={r.velocity}
              series={[{ key: "fixed", label: "Fixed", fill: "var(--chart-1)", pattern: "solid" }]}
            />
          ) : null}
        </ChartCard>
      </div>

      <ChartCard
        id="rem-oldest"
        title="Oldest open critical and high findings"
        className="mt-4"
        query={aging}
        state={a && a.oldest.length === 0 ? "empty" : null}
        skeletonHeight="h-40"
        link={{
          to: openFindingsUrl(workspaceId, ["critical", "high"]),
          label: "Open critical and high in Findings",
        }}
      >
        {a ? (
          <ReportTable
            caption="Oldest open critical and high findings"
            rows={a.oldest}
            getRowId={(x) => x.id}
            defaultSort={{ key: "age", desc: true }}
            columns={[
              {
                key: "severity",
                header: "Severity",
                sortValue: (x) => SEVERITY_ORDER.indexOf(x.severity),
                cell: (x) => <SeverityBadge severity={x.severity} />,
              },
              {
                key: "title",
                header: "Title",
                cell: (x) => (
                  <Link
                    to={findingUrl(workspaceId, x.id)}
                    className="block max-w-96 truncate underline-offset-4 hover:underline"
                    title={x.title}
                  >
                    {x.title}
                  </Link>
                ),
              },
              {
                key: "repo",
                header: "Repository",
                sortValue: (x) => x.repositoryName ?? "",
                cell: (x) => (
                  <span
                    className="block max-w-56 truncate font-mono text-xs"
                    title={x.repositoryName ?? ""}
                  >
                    {x.repositoryName ?? "—"}
                  </span>
                ),
              },
              {
                key: "age",
                header: "Age",
                align: "right",
                sortValue: (x) => x.ageDays,
                cell: (x) => `${x.ageDays} d`,
              },
            ]}
          />
        ) : null}
      </ChartCard>
    </ReportingPage>
  );
}
