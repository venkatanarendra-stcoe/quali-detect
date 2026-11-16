import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { Badge } from "@/components/ui/badge.jsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import { cn } from "@/lib/cn.js";
import {
  SHORT_ID_LENGTH,
  TRIGGER_ICONS,
  executionStatus,
  isCancelling,
  reasonText,
  taskStatus,
} from "../constants/index.js";

const RTF = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const UNITS = [
  ["year", 31_536_000],
  ["month", 2_592_000],
  ["day", 86_400],
  ["hour", 3600],
  ["minute", 60],
];

/** Relative time ("3 hours ago", "in 2 days"). @param {string | Date} value */
export function relativeTime(value) {
  const seconds = Math.round((new Date(value).getTime() - Date.now()) / 1000);
  for (const [unit, size] of UNITS)
    if (Math.abs(seconds) >= size) return RTF.format(Math.round(seconds / size), unit);
  return Math.abs(seconds) < 45 ? "just now" : RTF.format(Math.round(seconds / 60), "minute");
}
/**
 * Locale date and time. `dateStyle`/`timeStyle` cannot be combined with `timeZoneName` in `Intl`, so a request for the zone
 * name is expanded to explicit fields.
 */
export function absoluteTime(value, options = { dateStyle: "medium", timeStyle: "short" }) {
  const { timeStyle, ...rest } = options;
  delete rest.dateStyle;
  const resolved = rest.timeZoneName
    ? {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        ...(timeStyle === "medium" ? { second: "2-digit" } : {}),
        ...rest,
      }
    : options;
  return new Date(value).toLocaleString(undefined, resolved);
}

/** Clock time of the user's locale, for "Stops by 14:02" and similar. @param {string} value */
export const clockTime = (value) =>
  new Date(value).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });

/** "1 h 4 min", "3 min 12 s", "45 s", "800 ms". @param {number | null | undefined} ms */
export function formatDuration(ms) {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h) return `${h} h ${m} min`;
  if (m) return `${m} min ${s} s`;
  return `${s} s`;
}

/** First 8 characters of an execution id (SPEC EQ-9). @param {string} id */
export const shortId = (id) => String(id).slice(0, SHORT_ID_LENGTH);

/** Relative time with the absolute time (and the UTC instant) as a tooltip. @param {{ value?: string | null }} props */
export function TimeAgo({ value }) {
  if (!value) return <span className="text-muted-foreground">—</span>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="cursor-default rounded-sm whitespace-nowrap outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <time dateTime={value}>{relativeTime(value)}</time>
        </button>
      </TooltipTrigger>
      <TooltipContent>
        {absoluteTime(value, { dateStyle: "medium", timeStyle: "medium" })}
        <br />
        <span className="font-mono">{new Date(value).toISOString()}</span>
      </TooltipContent>
    </Tooltip>
  );
}

/** Mono identifier, truncated in the middle when long, full value in a tooltip, optional copy button. */
export function Identifier({ value, max = 12, copy = false, label = "value", full }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-muted-foreground">—</span>;
  const shown = value.length > max * 2 + 1 ? `${value.slice(0, max)}…${value.slice(-max)}` : value;
  const complete = full ?? value;
  return (
    <span className="inline-flex items-center gap-1">
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            className="cursor-default rounded-sm font-mono text-xs outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {shown}
          </button>
        </TooltipTrigger>
        <TooltipContent className="font-mono break-all">{complete}</TooltipContent>
      </Tooltip>
      {copy ? (
        <button
          type="button"
          aria-label={`Copy ${label}`}
          onClick={(event) => {
            event.stopPropagation();
            navigator.clipboard?.writeText(complete).then(
              () => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              },
              () => {},
            );
          }}
          className="flex size-5 items-center justify-center rounded-sm text-muted-foreground outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
        >
          {copied ? (
            <Check aria-hidden="true" className="size-3" />
          ) : (
            <Copy aria-hidden="true" className="size-3" />
          )}
        </button>
      ) : null}
    </span>
  );
}

/** Commit SHA: the first 7 characters in mono, the full SHA as the tooltip and the copied value. */
export const CommitSha = ({ sha }) => (
  <Identifier
    value={sha ? sha.slice(0, 7) : sha}
    full={sha ?? undefined}
    max={7}
    copy
    label="commit SHA"
  />
);

/** Short execution id in mono with its copy button (the full id is the tooltip and the copied value). */
export const ExecutionId = ({ id }) => (
  <Identifier value={shortId(id)} full={id} copy label="execution id" max={SHORT_ID_LENGTH} />
);

function StatusBadge({ meta, className }) {
  const { label, tone, icon: Icon, active, spin } = meta;
  return (
    <Badge tone={tone} className={cn(active && "[&_svg]:text-foreground", className)}>
      <Icon aria-hidden="true" className={spin ? "animate-spin motion-reduce:animate-none" : ""} />
      {label}
    </Badge>
  );
}

/**
 * Status chip of an execution: icon + text. A cancel in progress keeps the chip and adds the sub-label "Cancelling"
 * (SPEC CF-1). Pass the whole execution to get the sub-label, or `status` alone for a bare chip.
 * @param {{ status?: string, execution?: { status: string, cancelRequested?: boolean } }} props
 */
export function ExecutionStatusChip({ status, execution }) {
  const value = execution?.status ?? status;
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <StatusBadge meta={executionStatus(value)} />
      {execution && isCancelling(execution) ? (
        <span className="text-xs text-muted-foreground">Cancelling</span>
      ) : null}
    </span>
  );
}

/** Status chip of a scan task (`unsupported` reads "Not supported", neutral: it is not a failure). */
export const TaskStatusChip = ({ status }) => <StatusBadge meta={taskStatus(status)} />;

/** Status chip plus the reason text under it, for non-success terminal states. */
export function StatusCell({ execution }) {
  const why = reasonText(execution.statusReason, execution.status);
  return (
    <>
      <ExecutionStatusChip execution={execution} />
      {why ? <div className="mt-1 text-xs text-muted-foreground">{why}</div> : null}
    </>
  );
}

/** Short trigger text: "PR #214", "push to main", "schedule", "manual by Priya N.", "retry of 3f9a2c1e". */
export function triggerText(e) {
  if (e.retryOfExecutionId) return `retry of ${shortId(e.retryOfExecutionId)}`;
  if (e.triggerType === "pull_request")
    return e.pullRequestNumber ? `PR #${e.pullRequestNumber}` : "Pull request";
  if (e.triggerType === "push") return e.refName ? `push to ${e.refName}` : "push";
  if (e.triggerType === "schedule") return "schedule";
  return e.requestedBy?.displayName ? `manual by ${e.requestedBy.displayName}` : "manual";
}

/** Trigger icon + text, with the "Untrusted fork" badge when the execution ran on a fork. */
export function TriggerCell({ execution: e }) {
  const Icon = TRIGGER_ICONS[e.triggerType];
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
      <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
        {Icon ? <Icon aria-hidden="true" className="size-3.5 text-muted-foreground" /> : null}
        {triggerText(e)}
      </span>
      {e.trust === "untrusted_fork" ? <UntrustedForkBadge /> : null}
    </span>
  );
}

/** "Untrusted fork" badge with the explanation of what that means (PT §5.4.1). */
export function UntrustedForkBadge() {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="inline-flex rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Badge tone="warning">Untrusted fork</Badge>
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        This pull request comes from a fork. It was scanned without credentials and its findings are
        not auto-assigned.
      </TooltipContent>
    </Tooltip>
  );
}
