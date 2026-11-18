import { Check, ChevronDown, ChevronRight, Copy, Info, Minus, Sparkles } from "lucide-react";
import { useId, useState } from "react";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent } from "@/components/ui/card.jsx";
import { cn } from "@/lib/cn.js";
import {
  AGENT_FALLBACK_GENERIC,
  AGENT_FALLBACK_TEXT,
  AGENT_OK_NO_ADDITIONS,
  CLASS_ORDER,
  CLASS_TITLES,
  DECISION_STATE_LABELS,
  STATUS_ORDER,
  STATUS_TITLES,
} from "../constants/decision-rules.js";
import {
  finalTypes,
  notSelectedReasonText,
  providerLine,
  requiredReasonText,
  samplesTruncated,
  summaryLine,
  usageLine,
} from "../constants/decision-text.js";
import { TASK_ORDER, TASK_TITLES, taskToggleId } from "../constants/index.js";
import { useAnalysisCardStore } from "../stores/analysis-card-store.js";
import { TaskStatusChip } from "./execution-bits.jsx";
import { ClampedText, InertMono } from "./inert-text.jsx";

const STATE_ICONS = { required: Check, added: Sparkles, not_selected: Minus, not_enabled: Minus };
const STATE_CLASS = {
  required: "",
  added: "bg-secondary",
  not_selected: "border-border text-muted-foreground [&_svg]:text-muted-foreground",
  not_enabled: "border-border text-muted-foreground [&_svg]:text-muted-foreground",
};

/** Decision chip: icon + text, never colour alone. "Added by assistant" uses the existing neutral secondary fill. */
function DecisionChip({ state }) {
  const Icon = STATE_ICONS[state] ?? Minus;
  return (
    <Badge tone="neutral" className={cn(STATE_CLASS[state])}>
      <Icon aria-hidden="true" />
      {DECISION_STATE_LABELS[state] ?? "Unknown"}
    </Badge>
  );
}

function goToTask(taskId) {
  const el = document.getElementById(taskToggleId(taskId));
  if (!el) return;
  el.scrollIntoView?.({ block: "nearest" });
  el.focus();
}

function ReasonCell({ scanType, secretsRule }) {
  if (scanType.state === "required") return requiredReasonText(scanType.ruleIds, secretsRule);
  if (scanType.state === "added")
    return scanType.reason ? (
      <ClampedText max={500}>{scanType.reason}</ClampedText>
    ) : (
      "Added by the assistant"
    );
  if (scanType.state === "not_selected") return notSelectedReasonText(scanType.reason);
  return <span className="text-muted-foreground">Not enabled in this pipeline</span>;
}

function DecisionTable({ decision, tasks }) {
  const byId = new Map(tasks.map((t) => [t.id, t]));
  const rows = [...decision.scanTypes].sort(
    (a, b) => TASK_ORDER.indexOf(a.scanType) - TASK_ORDER.indexOf(b.scanType),
  );
  return (
    <div className="qm-scroll overflow-x-auto">
      <table className="w-full min-w-[34rem] border-collapse text-left text-sm">
        <caption className="sr-only">Scan types with decision, reason and task</caption>
        <thead>
          <tr className="border-b border-border text-xs text-muted-foreground">
            <th scope="col" className="py-1.5 pr-3 font-medium">
              Scan type
            </th>
            <th scope="col" className="py-1.5 pr-3 font-medium">
              Decision
            </th>
            <th scope="col" className="py-1.5 pr-3 font-medium">
              Reason
            </th>
            <th scope="col" className="py-1.5 font-medium">
              Task
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const task = row.taskId ? byId.get(row.taskId) : null;
            return (
              <tr
                key={row.scanType}
                className={cn(
                  "border-b border-border align-top last:border-b-0",
                  row.state === "not_enabled" && "text-muted-foreground",
                )}
              >
                <th scope="row" className="py-2 pr-3 font-medium">
                  {TASK_TITLES[row.scanType] ?? "Unknown"}
                </th>
                <td className="py-2 pr-3">
                  <DecisionChip state={row.state} />
                </td>
                <td className="min-w-0 py-2 pr-3">
                  <ReasonCell scanType={row} secretsRule={decision.secretsRule} />
                </td>
                <td className="py-2">
                  {task ? (
                    <span className="flex flex-wrap items-center gap-2">
                      <TaskStatusChip status={task.status} />
                      <Button
                        variant="link"
                        className="h-auto p-0 text-xs"
                        onClick={() => goToTask(task.id)}
                      >
                        View task
                        <span className="sr-only"> {TASK_TITLES[row.scanType]}</span>
                      </Button>
                    </span>
                  ) : (
                    <span className="text-muted-foreground" aria-label="No task">
                      —
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function CopyPath({ path }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={`Copy path ${path}`}
      onClick={() =>
        navigator.clipboard?.writeText(path).then(
          () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          },
          () => {},
        )
      }
      className="shrink-0 rounded-sm p-0.5 text-muted-foreground outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
    >
      {copied ? (
        <Check aria-hidden="true" className="size-3" />
      ) : (
        <Copy aria-hidden="true" className="size-3" />
      )}
    </button>
  );
}

/** Sample paths per class: text only, mono, closed by default (native disclosure: keyboard operable). */
function ChangedPaths({ summary }) {
  const groups = CLASS_ORDER.map((c) => [c, summary.samples?.[c] ?? []]).filter(
    ([, paths]) => paths.length > 0,
  );
  if (!groups.length) return null;
  return (
    <details className="mt-3 text-sm">
      <summary className="w-fit cursor-pointer rounded-sm underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring">
        Show changed paths
      </summary>
      <div className="mt-2 space-y-3">
        {groups.map(([cls, paths]) => (
          <div key={cls}>
            <p className="text-xs font-medium text-muted-foreground">{CLASS_TITLES[cls]}</p>
            <ul className="mt-1 space-y-0.5">
              {paths.map((path, i) => (
                <li key={`${i}-${path}`} className="flex items-start gap-1.5">
                  <InertMono className="min-w-0">{path}</InertMono>
                  <CopyPath path={path} />
                </li>
              ))}
            </ul>
          </div>
        ))}
        {samplesTruncated(summary) ? (
          <p className="text-xs text-muted-foreground">
            Showing a sample; the full list is not stored.
          </p>
        ) : null}
      </div>
    </details>
  );
}

function Fact({ label, children }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function ChangeSummary({ diff }) {
  const s = diff.summary;
  if (diff.status !== "complete") return null;
  const classes = CLASS_ORDER.filter((c) => (s.byClass?.[c] ?? 0) > 0);
  const statuses = STATUS_ORDER.filter((c) => (s.byStatus?.[c] ?? 0) > 0);
  return (
    <div>
      <h3 className="mb-1.5 text-sm font-semibold">Change summary</h3>
      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 min-[1440px]:grid-cols-4">
        <Fact label="Changed files">{diff.changedTotal}</Fact>
        <Fact label="By kind">
          {classes.length
            ? classes.map((c) => `${CLASS_TITLES[c]} ${s.byClass[c]}`).join(", ")
            : "—"}
        </Fact>
        <Fact label="By change">
          {statuses.length
            ? statuses.map((c) => `${STATUS_TITLES[c]} ${s.byStatus[c]}`).join(", ")
            : "—"}
        </Fact>
        <Fact label="Lines">
          +{s.additions} / −{s.deletions}
        </Fact>
      </dl>
      <ChangedPaths summary={s} />
    </div>
  );
}

function AssistantBlock({ agent, additions }) {
  const model = providerLine(agent);
  const usage = usageLine(agent);
  const fallback =
    agent.status === "ok" ? null : (AGENT_FALLBACK_TEXT[agent.status] ?? AGENT_FALLBACK_GENERIC);
  const calledModel = Boolean(model);
  if (!fallback && !calledModel) return null;
  return (
    <div className="space-y-2">
      {fallback ? (
        <p className="flex items-start gap-2 text-sm">
          <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          {fallback}
        </p>
      ) : null}
      {calledModel ? (
        <div className="rounded-md border border-border p-3 text-sm">
          <h3 className="flex items-center gap-1.5 text-sm font-semibold">
            <Sparkles aria-hidden="true" className="size-4 text-muted-foreground" />
            Analysis assistant
          </h3>
          <p className="mt-1">
            <InertMono>{model}</InertMono>
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Written by a language model. It can only add scans; it cannot remove required ones. It
            may be inaccurate.
          </p>
          {agent.summary ? <ClampedText className="mt-2">{agent.summary}</ClampedText> : null}
          {agent.status === "ok" && additions === 0 ? (
            <p className="mt-2">{AGENT_OK_NO_ADDITIONS}</p>
          ) : null}
          {usage ? <p className="mt-2 text-xs text-muted-foreground">{usage}</p> : null}
        </div>
      ) : null}
    </div>
  );
}

function InProgress() {
  return (
    <div role="status">
      <p className="text-sm">Analysis in progress.</p>
      {/* indeterminate: the API reports no percentage */}
      <div className="mt-2 h-1 overflow-hidden rounded-full bg-muted" aria-hidden="true">
        <div className="h-full w-1/3 animate-pulse rounded-full bg-foreground motion-reduce:animate-none" />
      </div>
    </div>
  );
}

/**
 * "Analysis and decision" (T-29, docs/modules/scan-decisioning/SCREENS.md). Rendered when the detail has a `decision`, or
 * while the execution is preparing and not decided yet ("Analysis in progress."). Expanded by default while the execution is
 * preparing or running and collapsed once it has finished; the person's choice is remembered in this browser.
 * @param {{ execution: any }} props
 */
export function AnalysisCard({ execution: e }) {
  const decision = e.decision ?? null;
  const pending = !decision && e.status === "preparing";
  const stored = useAnalysisCardStore((s) => s.open);
  const setOpen = useAnalysisCardStore((s) => s.setOpen);
  const headingId = useId();
  const panelId = useId();
  if (!decision && !pending) return null;
  const open = stored ?? (e.status === "preparing" || e.status === "running");
  const summary = decision ? summaryLine(decision) : null;
  const additions = decision ? decision.scanTypes.filter((t) => t.state === "added").length : 0;
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <section aria-labelledby={headingId}>
      <Card>
        <h2 id={headingId} className="text-base leading-6 font-semibold">
          <button
            type="button"
            aria-expanded={open}
            aria-controls={panelId}
            onClick={() => setOpen(!open)}
            className="flex w-full items-center justify-between gap-2 rounded-md p-4 pb-2 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            Analysis and decision
            <Chevron aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
          </button>
        </h2>
        {open ? (
          <CardContent id={panelId} className="space-y-4">
            {pending ? (
              <InProgress />
            ) : (
              <>
                <p className="flex items-start gap-2 text-sm">
                  {summary.incomplete ? (
                    <Info
                      aria-hidden="true"
                      className="mt-0.5 size-4 shrink-0 text-muted-foreground"
                    />
                  ) : null}
                  {summary.text}
                </p>
                <ChangeSummary diff={decision.diff} />
                <div>
                  <h3 className="mb-1.5 text-sm font-semibold">Decision per scan type</h3>
                  <DecisionTable decision={decision} tasks={e.tasks ?? []} />
                  {finalTypes(decision).length === 0 ? (
                    <p className="mt-2 text-sm text-muted-foreground">
                      No scan applied to these changes.
                    </p>
                  ) : null}
                </div>
                <AssistantBlock agent={decision.agent} additions={additions} />
              </>
            )}
          </CardContent>
        ) : (
          <span id={panelId} hidden />
        )}
      </Card>
    </section>
  );
}
