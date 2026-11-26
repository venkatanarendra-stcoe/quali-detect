import { Link } from "react-router";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { useFindingList } from "@/features/findings/hooks/use-findings.js";
import {
  SeverityBadge,
  StatusBadge,
  TimeAgo,
} from "@/features/findings/components/finding-bits.jsx";
import { COVERAGE_REASON_LABELS, SEVERITY_ORDER } from "../constants/index.js";
import { CardError, DataFooter } from "../components/chart-card.jsx";
import { ReportTable } from "../components/report-table.jsx";
import { useBreakdown, useTopRisk } from "../hooks/use-reporting.js";
import { findingUrl, findingsUrl } from "../schemas/drilldown.js";
import { formatCount } from "../schemas/format.js";

/** Untrusted text: escaped by React, never HTML, long values clipped (SCREENS 1). */
const Text = ({ children, mono = false }) => (
  <span
    className={`block max-w-72 truncate ${mono ? "font-mono text-xs" : ""}`}
    title={String(children ?? "")}
  >
    {children ?? "—"}
  </span>
);

function TableCard({ id, title, meta, children, openHref, openLabel = "Open in Findings" }) {
  return (
    <Card data-testid={`card-${id}`} className="min-w-0">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm">{title}</CardTitle>
        {openHref ? (
          <Link
            to={openHref}
            className="rounded-sm text-xs text-primary-text underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
          >
            {openLabel}
          </Link>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-2">
        {children}
        <DataFooter meta={meta} />
      </CardContent>
    </Card>
  );
}

function QueryBody({ query, children }) {
  if (query.isPending)
    return (
      <div role="status" aria-busy="true">
        <span className="sr-only">Loading…</span>
        <Skeleton className="h-40 w-full" />
      </div>
    );
  if (query.isError) return <CardError error={query.error} onRetry={query.refetch} />;
  return children;
}

/** Findings table: the oldest open critical and high first, 25 rows, the rest in Findings (T-21). Uses the Findings list API. */
function FindingsTable({ workspaceId, severities }) {
  const wanted = severities.length ? severities : ["critical", "high"];
  const query = useFindingList(
    workspaceId,
    { view: "all_open", severity: wanted.join(","), sort: "firstDetectedAt", direction: "asc" },
    { page: 1, pageSize: 25 },
  );
  const items = query.data?.items ?? [];
  return (
    <TableCard
      id="table-findings"
      title="Findings"
      openHref={findingsUrl(workspaceId, { view: "all_open", severity: wanted })}
    >
      <QueryBody query={query}>
        <ReportTable
          caption="Oldest open findings"
          rows={items}
          getRowId={(row) => row.id}
          empty="No open findings match."
          columns={[
            {
              key: "severity",
              header: "Severity",
              sortValue: (r) => SEVERITY_ORDER.indexOf(r.severity),
              cell: (r) => <SeverityBadge severity={r.severity} />,
            },
            {
              key: "title",
              header: "Title",
              cell: (r) => (
                <Link
                  to={findingUrl(workspaceId, r.id)}
                  className="block max-w-72 truncate underline-offset-4 hover:underline"
                  title={r.title}
                >
                  {r.title}
                </Link>
              ),
            },
            {
              key: "repository",
              header: "Repository",
              sortValue: (r) => r.repository.fullName,
              cell: (r) => <Text mono>{r.repository.fullName}</Text>,
            },
            {
              key: "pipeline",
              header: "Pipeline",
              sortValue: (r) => r.pipeline.name,
              cell: (r) => <Text>{r.pipeline.name}</Text>,
            },
            { key: "status", header: "Status", cell: (r) => <StatusBadge status={r.status} /> },
            {
              key: "age",
              header: "Age",
              sortValue: (r) => r.firstDetectedAt,
              cell: (r) => <TimeAgo value={r.firstDetectedAt} />,
            },
            {
              key: "assignee",
              header: "Assignee",
              cell: (r) => <Text>{r.assignee?.displayName}</Text>,
            },
          ]}
        />
      </QueryBody>
    </TableCard>
  );
}

function BreakdownTable({ workspaceId, by, id, title, columns, openFilter, params }) {
  const query = useBreakdown(workspaceId, { ...params.periodQuery, by, limit: "25" });
  const rows = query.data?.data.items ?? [];
  const sev = params.severities;
  return (
    <TableCard
      id={id}
      title={title}
      meta={query.data?.meta}
      openHref={findingsUrl(workspaceId, { view: "all_open", severity: sev })}
      openLabel="Open in Findings"
    >
      <QueryBody query={query}>
        <ReportTable
          caption={title}
          rows={rows}
          getRowId={(r) => r.key}
          empty="Nothing to show for this period."
          defaultSort={{ key: "open", desc: true }}
          columns={columns(query, openFilter, sev)}
        />
      </QueryBody>
    </TableCard>
  );
}

/**
 * The T-21 table stack: Findings, Pipelines, Repositories, Workload and SLA, Activity. Each table is a drill-down of a card, never a
 * new data source; each has its own loading, empty, error and no-permission states.
 */
export function DashboardTables({
  workspaceId,
  params,
  canFinding,
  canExec,
  canAssign,
  workload,
  coverage,
}) {
  const risk = useTopRisk(workspaceId, { limit: "50" }, { enabled: canFinding });
  const riskById = new Map((risk.data?.data.items ?? []).map((i) => [i.repositoryId, i.score]));
  const uncovered = new Map(
    (coverage.data?.data.uncovered ?? []).map((u) => [u.repositoryId, u.reason]),
  );
  const lastScan = (r) =>
    r.lastScan ? (
      <span className="inline-flex items-center gap-1.5">
        {r.lastScan.status}
        <TimeAgo value={r.lastScan.at} />
      </span>
    ) : (
      "—"
    );
  return (
    <div className="space-y-4">
      {canFinding ? (
        <FindingsTable workspaceId={workspaceId} severities={params.severities} />
      ) : null}
      {canFinding ? (
        <BreakdownTable
          workspaceId={workspaceId}
          by="pipeline"
          id="table-pipelines"
          title="Pipelines"
          params={params}
          openFilter="pipeline"
          columns={(_q, filter, sev) => [
            {
              key: "label",
              header: "Pipeline",
              sortValue: (r) => r.label,
              cell: (r) => (
                <Link
                  to={findingsUrl(workspaceId, {
                    view: "all_open",
                    [filter]: r.key,
                    severity: sev,
                  })}
                  className="block max-w-72 truncate underline-offset-4 hover:underline"
                  title={r.label}
                >
                  {r.label}
                </Link>
              ),
            },
            { key: "last", header: "Last run", cell: lastScan },
            {
              key: "open",
              header: "Open findings",
              align: "right",
              sortValue: (r) => r.open,
              cell: (r) => formatCount(r.open),
            },
            {
              key: "critical",
              header: "Critical",
              align: "right",
              sortValue: (r) => r.bySeverity.critical,
              cell: (r) => r.bySeverity.critical,
            },
            {
              key: "breached",
              header: "SLA breached",
              align: "right",
              sortValue: (r) => r.slaBreached,
              cell: (r) => r.slaBreached,
            },
          ]}
        />
      ) : null}
      {canFinding ? (
        <BreakdownTable
          workspaceId={workspaceId}
          by="repository"
          id="table-repositories"
          title="Repositories"
          params={params}
          openFilter="repository"
          columns={(_q, filter, sev) => [
            {
              key: "label",
              header: "Repository",
              sortValue: (r) => r.label,
              cell: (r) => (
                <Link
                  to={findingsUrl(workspaceId, {
                    view: "all_open",
                    [filter]: r.key,
                    severity: sev,
                  })}
                  className="block max-w-72 truncate font-mono text-xs underline-offset-4 hover:underline"
                  title={r.label}
                >
                  {r.label}
                </Link>
              ),
            },
            {
              key: "coverage",
              header: "Coverage",
              cell: (r) =>
                canExec
                  ? uncovered.get(r.key)
                    ? `Not scanned: ${COVERAGE_REASON_LABELS[uncovered.get(r.key)] ?? uncovered.get(r.key)}`
                    : "Scanned"
                  : "—",
            },
            { key: "last", header: "Last scan", cell: lastScan },
            {
              key: "open",
              header: "Open findings",
              align: "right",
              sortValue: (r) => r.open,
              cell: (r) => formatCount(r.open),
            },
            {
              key: "risk",
              header: "Risk points",
              align: "right",
              sortValue: (r) => riskById.get(r.key) ?? 0,
              cell: (r) => riskById.get(r.key) ?? "—",
            },
          ]}
        />
      ) : null}
      {canAssign ? (
        <TableCard id="table-workload" title="Workload and SLA" meta={workload.data?.meta}>
          <QueryBody query={workload}>
            <ReportTable
              caption="Open findings and SLA per assignee"
              rows={workload.data?.data.assignees ?? []}
              getRowId={(r) => r.user.id}
              empty="No one has open findings."
              defaultSort={{ key: "name" }}
              columns={[
                {
                  key: "name",
                  header: "Assignee",
                  sortValue: (r) => r.user.displayName,
                  cell: (r) => <Text>{r.user.displayName}</Text>,
                },
                {
                  key: "open",
                  header: "Open",
                  align: "right",
                  sortValue: (r) => r.open,
                  cell: (r) => (
                    <Link
                      className="underline-offset-4 hover:underline"
                      to={findingsUrl(workspaceId, { view: "all_open", assignee: r.user.id })}
                    >
                      {r.open}
                    </Link>
                  ),
                },
                {
                  key: "dueSoon",
                  header: "Due soon",
                  align: "right",
                  sortValue: (r) => r.dueSoon,
                  cell: (r) => r.dueSoon,
                },
                {
                  key: "breached",
                  header: "Breached",
                  align: "right",
                  sortValue: (r) => r.breached,
                  cell: (r) => r.breached,
                },
              ]}
            />
          </QueryBody>
        </TableCard>
      ) : null}
      <TableCard id="table-activity" title="Activity">
        <p className="text-sm text-muted-foreground">
          The workspace activity feed is planned. It is not a reporting metric and is not shown here
          yet.
        </p>
      </TableCard>
    </div>
  );
}
