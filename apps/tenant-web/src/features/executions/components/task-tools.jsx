import { TriangleAlert } from "lucide-react";
import { Fragment } from "react";
import { ADVISORY_ATTRIBUTION } from "@qmentisai/shared";
import { Badge } from "@/components/ui/badge.jsx";
import { inertText } from "../constants/decision-text.js";
import { TASK_TITLES } from "../constants/index.js";
import {
  TRUNCATED_LINE,
  coverageLine,
  dataNotice,
  producedResults,
  toolReasonText,
  toolStatusMeta,
  toolsSummary,
} from "../constants/tool-text.js";
import { useNow } from "../hooks/use-now.js";
import { parseTaskTools } from "../schemas/tools.js";
import { formatDuration } from "./execution-bits.jsx";
import { InertMono } from "./inert-text.jsx";
import { SeverityPills } from "./severity-pills.jsx";

const SEVERITY_LABEL_TEXT = "text-xs text-muted-foreground";

/** A tool's name as text: the platform catalog name, cleaned (a hostile value is inert), or the tool id when it is empty. */
const nameOf = (tool) => inertText(tool.displayName || tool.toolId, 60) || "Unknown tool";

function ToolStatusChip({ status }) {
  const { label, tone, icon: Icon } = toolStatusMeta(status);
  return (
    <Badge tone={tone}>
      <Icon aria-hidden="true" />
      {label}
    </Badge>
  );
}

/** The Findings cell: pills for non-zero counts, "None" for a clean success, "Components N" for an inventory, an em dash otherwise. */
function FindingsCell({ tool }) {
  if (!producedResults(tool))
    return (
      <span className="text-muted-foreground">
        <span aria-hidden="true">—</span>
        <span className="sr-only">No results</span>
      </span>
    );
  if (tool.resultKind === "component")
    return <span className="text-xs">Components {tool.findingsMapped}</span>;
  const total = Object.values(tool.counts).reduce((n, v) => n + v, 0);
  if (total === 0) return <span className="text-xs text-muted-foreground">None</span>;
  return <SeverityPills counts={tool.counts} label={`Findings by severity, ${nameOf(tool)}`} />;
}

/** The Data cell (SCA tools): the build date of the vulnerability data and the short snapshot id, with the age warning. */
function DataCell({ tool, notice }) {
  if (!tool.db || (!tool.db.builtAt && !tool.db.versionShort)) return null;
  const built = tool.db.builtAt ? new Date(tool.db.builtAt) : null;
  const valid = built && !Number.isNaN(built.getTime());
  return (
    <span className="block space-y-0.5 text-xs">
      {valid ? (
        <span className="block">
          Vulnerability data from{" "}
          <time dateTime={built.toISOString()}>
            {built.toLocaleDateString(undefined, { dateStyle: "medium" })}
          </time>
        </span>
      ) : null}
      {tool.db.versionShort ? (
        <InertMono max={24} className="block text-muted-foreground">
          {tool.db.versionShort}
        </InertMono>
      ) : null}
      {notice ? (
        <span className="flex items-center gap-1 text-status-warning">
          <TriangleAlert aria-hidden="true" className="size-3" />
          {notice.tier === "hard" ? "out of date" : "older than 3 days"}
        </span>
      ) : null}
    </span>
  );
}

const imageText = (tool) =>
  tool.builtIn ? (
    <span className="text-xs text-muted-foreground">built in</span>
  ) : tool.imageShort ? (
    <InertMono max={24}>{tool.imageShort}</InertMono>
  ) : (
    <span className="text-muted-foreground">—</span>
  );

function perToolNotice(tool, now) {
  return tool.db ? dataNotice([tool], now) : null;
}

function ToolsTable({ title, tools, now }) {
  return (
    <table className="hidden w-full text-left text-xs @[28rem]:table">
      <caption className="sr-only">Tools used for {title}</caption>
      <thead className="text-muted-foreground">
        <tr>
          <th scope="col" className="py-1 pr-2 font-medium">
            Tool
          </th>
          <th scope="col" className="py-1 pr-2 font-medium">
            Version
          </th>
          <th scope="col" className="py-1 pr-2 font-medium">
            Image
          </th>
          <th scope="col" className="py-1 pr-2 font-medium">
            Status
          </th>
          <th scope="col" className="py-1 pr-2 font-medium">
            Duration
          </th>
          <th scope="col" className="py-1 font-medium">
            Findings
          </th>
        </tr>
      </thead>
      <tbody>
        {tools.map((tool) => {
          const notice = perToolNotice(tool, now);
          const hasData = tool.db && (tool.db.builtAt || tool.db.versionShort);
          return (
            <Fragment key={tool.toolId}>
              <tr className="border-t border-border align-top">
                <th
                  scope="row"
                  className="min-w-24 py-1.5 pr-2 text-sm font-medium [overflow-wrap:anywhere]"
                >
                  {nameOf(tool)}
                </th>
                <td className="py-1.5 pr-2 whitespace-nowrap">
                  {tool.version ? (
                    <InertMono max={20}>{tool.version}</InertMono>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </td>
                <td className="py-1.5 pr-2 whitespace-nowrap">{imageText(tool)}</td>
                <td className="py-1.5 pr-2">
                  <ToolStatusChip status={tool.status} />
                </td>
                <td className="py-1.5 pr-2 whitespace-nowrap text-muted-foreground">
                  {formatDuration(tool.durationMs)}
                </td>
                <td className="py-1.5">
                  <FindingsCell tool={tool} />
                </td>
              </tr>
              {hasData ? (
                <tr>
                  <td colSpan={6} className="pb-1.5">
                    <DataCell tool={tool} notice={notice} />
                  </td>
                </tr>
              ) : null}
            </Fragment>
          );
        })}
      </tbody>
    </table>
  );
}

/** Below the card width of 28rem: each tool is a block (name and chip, then version, image and duration, findings, data). */
function ToolsStack({ title, tools, now }) {
  return (
    <ul aria-label={`Tools used for ${title}`} className="space-y-2 @[28rem]:hidden">
      {tools.map((tool) => (
        <li key={tool.toolId} className="space-y-1 rounded-sm border border-border p-2">
          <div className="flex flex-wrap items-center justify-between gap-1.5">
            <span className="text-sm font-medium [overflow-wrap:anywhere]">{nameOf(tool)}</span>
            <ToolStatusChip status={tool.status} />
          </div>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-muted-foreground">
            {tool.version ? <InertMono max={40}>{tool.version}</InertMono> : null}
            {tool.builtIn || tool.imageShort ? imageText(tool) : null}
            <span>{formatDuration(tool.durationMs)}</span>
          </div>
          <FindingsCell tool={tool} />
          <DataCell tool={tool} notice={perToolNotice(tool, now)} />
        </li>
      ))}
    </ul>
  );
}

/** Splits the advisory attribution at its two fixed URLs and renders only those as links (constants, never tool output). */
function Attribution() {
  const { text, advisoryUrl, licenceUrl } = ADVISORY_ATTRIBUTION;
  const link = (url) => (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className="rounded-sm underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      {url}
    </a>
  );
  const [before, rest] = text.split(advisoryUrl);
  const [middle, after] = rest.split(licenceUrl);
  return (
    <p className={`mt-2 ${SEVERITY_LABEL_TEXT}`}>
      {before}
      {link(advisoryUrl)}
      {middle}
      {link(licenceUrl)}
      {after}
    </p>
  );
}

/** The reasons below the table: "Trivy: The tool ran out of time." Plain text from the fixed-word map. */
function ReasonList({ tools }) {
  const withReason = tools.filter((t) => t.reason && t.status !== "succeeded");
  if (!withReason.length) return null;
  return (
    <dl className="mt-2 space-y-0.5 text-xs">
      {withReason.map((tool) => (
        <div key={tool.toolId} className="flex flex-wrap gap-x-1">
          <dt className="font-medium">{nameOf(tool)}:</dt>
          <dd className="text-muted-foreground">{toolReasonText(tool.reason)}</dd>
        </div>
      ))}
    </dl>
  );
}

function Notice({ line }) {
  if (!line) return null;
  const Icon = line.icon;
  return (
    <p className="mt-2 flex items-start gap-1.5 text-sm">
      <Icon
        aria-hidden="true"
        className={`mt-0.5 size-4 shrink-0 ${line.tone === "warning" ? "text-status-warning" : "text-muted-foreground"}`}
      />
      <span>{line.text}</span>
    </p>
  );
}

/**
 * The one summary line of the COLLAPSED card (SCREENS 2): "3 tools", "3 tools, 1 did not finish (degraded)". Rendered only
 * when the DTO has tools; the warning icon appears for the problem case only and the text is always present.
 * @param {{ task: any }} props
 */
export function ToolsSummaryLine({ task }) {
  const { tools } = parseTaskTools(task);
  const summary = toolsSummary(tools);
  if (!summary) return null;
  return (
    <span className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
      {summary.problem ? (
        <TriangleAlert aria-hidden="true" className="size-3 shrink-0 text-status-warning" />
      ) : null}
      {summary.text}
    </span>
  );
}

/**
 * The "Tools" sub-section and the coverage line of the EXPANDED card (SCREENS 3). Not rendered for a task without tools (older
 * executions, `unsupported`, a task that has not finished) and no placeholder is shown. Read-only: no action, no link out of the
 * application apart from the two attribution links when advisory data is shown.
 * @param {{ task: any, now?: number }} props
 */
export function ToolsSection({ task, now: given }) {
  const mounted = useNow(false);
  const now = given ?? mounted;
  const { tools, coverage } = parseTaskTools(task);
  if (!tools) return null;
  const title = TASK_TITLES[task.scanType] ?? "this scan type";
  const stale = dataNotice(tools, now);
  const line = coverageLine(coverage, { staleData: Boolean(stale) });
  const advisory =
    task.scanType === "sca" && tools.some((t) => t.db && (t.db.builtAt || t.db.versionShort));
  return (
    <section aria-labelledby={`tools-${task.id}`} className="mb-3 @container">
      <h4 id={`tools-${task.id}`} className="mb-1.5 text-xs font-semibold">
        Tools
      </h4>
      {tools.length ? (
        <>
          <ToolsTable title={title} tools={tools} now={now} />
          <ToolsStack title={title} tools={tools} now={now} />
          <ReasonList tools={tools} />
        </>
      ) : null}
      <Notice line={stale ? { tone: "warning", icon: TriangleAlert, text: stale.text } : null} />
      <Notice line={line} />
      <Notice
        line={
          task.resultSummary?.truncated
            ? { tone: "warning", icon: TriangleAlert, text: TRUNCATED_LINE }
            : null
        }
      />
      {advisory ? <Attribution /> : null}
    </section>
  );
}
