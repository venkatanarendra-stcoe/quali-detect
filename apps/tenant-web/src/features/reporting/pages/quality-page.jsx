import { Info, Sparkles } from "lucide-react";
import { useParams } from "react-router";
import { FINDING_SCAN_TYPES } from "@qmentisai/shared";
import { useActiveWorkspace } from "@/features/authorization/hooks/use-permissions.js";
import { SCAN_TYPE_LABELS } from "@/features/findings/constants/index.js";
import { BarsChart } from "../components/charts.jsx";
import { ChartCard } from "../components/chart-card.jsx";
import { KpiCard } from "../components/kpi-card.jsx";
import { ReportTable } from "../components/report-table.jsx";
import { ReportingPage } from "../components/reporting-page.jsx";
import { usePosture, useQuality } from "../hooks/use-reporting.js";
import { useReportingParams } from "../hooks/use-reporting-params.js";
import { formatCount, formatPercent } from "../schemas/format.js";
import { periodDays } from "./workspace-dashboard-view.jsx";

const OUTCOME_LABELS = {
  ready: "Ready",
  pending: "Pending",
  failed: "Failed",
  consent_blocked: "Needs consent",
  not_configured: "Not configured",
  none: "None",
  ok: "Ready",
  consent_required: "Needs consent",
  skipped_untrusted: "Skipped (untrusted)",
  skipped_cap: "Skipped (limit)",
  timeout: "Timed out",
  invalid_output: "Invalid output",
};

/** "n = 14, too few to rate" or a percentage (SPEC 5 rule 9): a small sample is never shown as a rate. */
const rateValue = (rate) => (rate.tooFew ? "Too few" : formatPercent(rate.rate));
const rateSub = (rate) =>
  rate.tooFew
    ? `n = ${rate.denominator}, too few to rate (${rate.numerator} of ${rate.denominator})`
    : `${rate.numerator} of ${rate.denominator}`;

/** The advice against the human decision, labelled; agreement and disagreement are words, not colours. */
function AdviceMatrix({ matrix }) {
  const cell = (n, agree) => (
    <td className="rounded-sm border border-border px-3 py-3 text-center align-middle">
      <p className="text-xl font-semibold tabular-nums">{formatCount(n)}</p>
      <p className="text-xs text-muted-foreground">{agree ? "Agreement" : "Disagreement"}</p>
    </td>
  );
  return (
    <div className="qm-scroll overflow-x-auto">
      <table className="w-full min-w-[26rem] border-separate border-spacing-1 text-sm">
        <caption className="sr-only">Advice against the human decision</caption>
        <thead>
          <tr>
            <td />
            <th
              scope="col"
              className="px-2 py-1 text-center text-xs font-medium text-muted-foreground"
            >
              Approved false positive
            </th>
            <th
              scope="col"
              className="px-2 py-1 text-center text-xs font-medium text-muted-foreground"
            >
              Approved true positive
            </th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th scope="row" className="px-2 py-1 text-left text-xs font-medium">
              Advisory: likely false positive
            </th>
            {cell(matrix.advisoryFpHumanFp, true)}
            {cell(matrix.advisoryFpHumanTp, false)}
          </tr>
          <tr>
            <th scope="row" className="px-2 py-1 text-left text-xs font-medium">
              Advisory: likely true positive
            </th>
            {cell(matrix.advisoryTpHumanFp, false)}
            {cell(matrix.advisoryTpHumanTp, true)}
          </tr>
          <tr>
            <th scope="row" className="px-2 py-1 text-left text-xs font-medium">
              Advisory: uncertain
            </th>
            <td colSpan={2} className="rounded-sm border border-border px-3 py-3 text-center">
              <p className="text-xl font-semibold tabular-nums">
                {formatCount(matrix.advisoryUncertain)}
              </p>
              <p className="text-xs text-muted-foreground">
                Any human decision (the API does not split it)
              </p>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

/** T-49 Detection quality (false positives and advisories). Counts, rates and sample sizes only: never advice text, reasoning or titles. */
export function QualityPage() {
  const { workspaceId } = useParams();
  const active = useActiveWorkspace();
  const live = usePosture(workspaceId, {});
  const timeZone = live.data?.meta.timeZone;
  const params = useReportingParams(timeZone);
  const days = periodDays(params.period);
  const quality = useQuality(workspaceId, params.periodQuery);
  const q = quality.data?.data;
  const off =
    q &&
    (q.advisoryOutcomes.length === 0 ||
      q.advisoryOutcomes.every((o) => ["not_configured", "disabled"].includes(o.status)));
  const noDecisions =
    q && q.falsePositiveRate.overall.denominator === 0 && q.advisoryAgreement.decided === 0;
  const rangeText = `The last ${days} days.`;
  const byType = q
    ? FINDING_SCAN_TYPES.map((t) => ({
        type: t,
        label: SCAN_TYPE_LABELS[t],
        ...q.falsePositiveRate.byType[t],
      }))
    : [];

  return (
    <ReportingPage
      workspaceId={workspaceId}
      current="quality"
      title="Detection quality"
      description={active?.name}
      params={params}
      timeZone={timeZone}
    >
      {off ? (
        <p
          role="status"
          className="mb-4 flex items-start gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm"
        >
          <Sparkles aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          AI advice is turned off; only human decisions are measured.
        </p>
      ) : null}
      <p className="mb-4 flex items-start gap-2 text-xs text-muted-foreground">
        <Info aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
        Counts and rates only. No advice text, reasoning, rationale or finding title is shown here.
        A rate over fewer than 20 decisions is not shown as a percentage.
      </p>
      <section aria-label="Key figures" className="mb-4 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <KpiCard
          id="fp"
          label="False-positive rate"
          query={quality}
          value={q ? rateValue(q.falsePositiveRate.overall) : null}
          sub={q ? rateSub(q.falsePositiveRate.overall) : null}
        />
        <KpiCard
          id="coverage"
          label="Advisory coverage"
          query={quality}
          value={q ? rateValue(q.advisoryCoverage) : null}
          sub={q ? `${rateSub(q.advisoryCoverage)} decisions with advice` : null}
        />
        <KpiCard
          id="agreement"
          label="Advisory agreement"
          query={quality}
          value={
            q
              ? q.advisoryAgreement.tooFew
                ? "Too few"
                : formatPercent(q.advisoryAgreement.rate)
              : null
          }
          sub={
            q
              ? q.advisoryAgreement.tooFew
                ? `n = ${q.advisoryAgreement.decided}, too few to rate`
                : `${q.advisoryAgreement.agreed} of ${q.advisoryAgreement.decided} agreed`
              : null
          }
        />
        <KpiCard
          id="override"
          label="Human override of confident advice"
          query={quality}
          value={q ? rateValue(q.humanOverrideRate) : null}
          sub={q ? rateSub(q.humanOverrideRate) : null}
        />
      </section>

      <div className="grid gap-4 xl:grid-cols-2">
        <ChartCard
          id="q-fp-type"
          title="False-positive rate by scan type"
          query={quality}
          state={noDecisions ? "period" : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          summary={
            q
              ? byType
                  .map(
                    (t) =>
                      `${t.label}: ${t.tooFew ? `n = ${t.denominator}, too few to rate` : `${formatPercent(t.rate)} (n = ${t.denominator})`}`,
                  )
                  .join("; ") + "."
              : undefined
          }
          table={
            q ? (
              <ReportTable
                caption="False-positive rate by scan type"
                rows={byType}
                getRowId={(x) => x.type}
                columns={[
                  { key: "type", header: "Scan type", cell: (x) => x.label },
                  { key: "n", header: "Decisions (n)", align: "right", cell: (x) => x.denominator },
                  {
                    key: "fp",
                    header: "False positives",
                    align: "right",
                    cell: (x) => x.numerator,
                  },
                  {
                    key: "rate",
                    header: "Rate",
                    align: "right",
                    cell: (x) => (x.tooFew ? "too few" : formatPercent(x.rate)),
                  },
                ]}
              />
            ) : undefined
          }
        >
          {q ? (
            <>
              <BarsChart
                stacked={false}
                height={200}
                xKey="label"
                data={byType.map((t) => ({
                  label: t.label,
                  rate: t.tooFew ? null : Math.round(t.rate * 1000) / 10,
                }))}
                valueFormatter={(v) => `${v}%`}
                showLabels
                series={[
                  {
                    key: "rate",
                    label: "False-positive rate (%)",
                    fill: "var(--chart-2)",
                    pattern: "solid",
                  },
                ]}
              />
              {byType.some((t) => t.tooFew) ? (
                <p className="mt-2 text-xs text-muted-foreground">
                  {byType
                    .filter((t) => t.tooFew)
                    .map((t) => `${t.label}: n = ${t.denominator}, too few to rate`)
                    .join("; ")}
                  .
                </p>
              ) : null}
            </>
          ) : null}
        </ChartCard>

        <ChartCard
          id="q-matrix"
          title="Advice against the human decision"
          query={quality}
          state={noDecisions ? "period" : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          summary="Advice is not a decision. A disagreement may mean the advice was wrong or the reviewer was."
        >
          {q ? <AdviceMatrix matrix={q.advisoryAgreement.matrix} /> : null}
        </ChartCard>

        <ChartCard
          id="q-outcomes"
          title="Advisory outcomes"
          query={quality}
          state={q && q.advisoryOutcomes.length === 0 ? "period" : null}
          rangeText={rangeText}
          onWiden={() => params.setPreset(90)}
          summary={
            q
              ? `Advisories by outcome: ${q.advisoryOutcomes.map((o) => `${OUTCOME_LABELS[o.status] ?? o.status} ${formatCount(o.count)}`).join(", ")}.`
              : undefined
          }
          skeletonHeight="h-24"
        >
          {q ? (
            <ul aria-label="Advisory outcomes" className="flex flex-wrap gap-2">
              {q.advisoryOutcomes.map((o) => (
                <li
                  key={`${o.status}-${o.providerKind}`}
                  className="rounded-sm border border-border-strong px-2.5 py-1.5 text-sm"
                >
                  <span className="text-muted-foreground">
                    {OUTCOME_LABELS[o.status] ?? o.status}
                  </span>{" "}
                  <span className="font-semibold tabular-nums">{formatCount(o.count)}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </ChartCard>

        <ChartCard
          id="q-rules"
          title="Noisiest rules"
          query={quality}
          state={q && q.noisyRules.length === 0 ? "period" : null}
          rangeText="Only rules with at least 20 decisions are listed."
          summary="Rules with the largest share of decisions that were approved as false positives."
          skeletonHeight="h-32"
        >
          {q ? (
            <ReportTable
              caption="Noisiest rules"
              rows={q.noisyRules}
              getRowId={(x) => `${x.scanType}-${x.ruleId}`}
              defaultSort={{ key: "share", desc: true }}
              columns={[
                {
                  key: "rule",
                  header: "Rule",
                  cell: (x) => (
                    <span className="block max-w-64 truncate font-mono text-xs" title={x.ruleId}>
                      {x.ruleId}
                    </span>
                  ),
                },
                {
                  key: "type",
                  header: "Scan type",
                  cell: (x) => SCAN_TYPE_LABELS[x.scanType] ?? x.scanType,
                },
                {
                  key: "n",
                  header: "Decisions",
                  align: "right",
                  sortValue: (x) => x.decisions,
                  cell: (x) => x.decisions,
                },
                {
                  key: "share",
                  header: "False-positive share",
                  align: "right",
                  sortValue: (x) => x.falsePositiveShare,
                  cell: (x) => formatPercent(x.falsePositiveShare),
                },
              ]}
            />
          ) : null}
        </ChartCard>
      </div>
    </ReportingPage>
  );
}
