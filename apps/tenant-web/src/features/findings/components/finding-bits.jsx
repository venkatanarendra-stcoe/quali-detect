import { useState } from "react";
import {
  CircleAlert,
  CircleDot,
  Info,
  Repeat,
  ShieldAlert,
  Sparkles,
  TriangleAlert,
} from "lucide-react";
import { Badge } from "@/components/ui/badge.jsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import { cn } from "@/lib/cn.js";
import {
  Identifier,
  TimeAgo,
  absoluteTime,
} from "@/features/executions/components/execution-bits.jsx";
import {
  SEVERITY_LABELS,
  SLA_ICON,
  SUGGESTION_HINT_LABELS,
  statusPresentation,
} from "../constants/index.js";

export { Identifier, TimeAgo };

const SEVERITY_ICON = {
  critical: ShieldAlert,
  high: TriangleAlert,
  medium: CircleAlert,
  low: Info,
  info: CircleDot,
};
const SEVERITY_CLASS = {
  critical: "bg-sev-critical-bg text-sev-critical-fg",
  high: "bg-sev-high-bg text-sev-high-fg",
  medium: "bg-sev-medium-bg text-sev-medium-fg",
  low: "bg-sev-low-bg text-sev-low-fg",
  info: "bg-sev-info-bg text-sev-info-fg",
};

/**
 * Severity: a filled tint pill with an icon AND the label (DESIGN_SYSTEM 2.2: colour is never the only signal). The severity
 * tokens are independent of the accent (mint never appears here).
 * @param {{ severity: string, className?: string }} props
 */
export function SeverityBadge({ severity, className }) {
  const Icon = SEVERITY_ICON[severity] ?? CircleDot;
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center gap-1 rounded-full px-2 text-xs font-medium whitespace-nowrap",
        SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info,
        className,
      )}
    >
      <Icon aria-hidden="true" className="size-3" />
      {SEVERITY_LABELS[severity] ?? severity}
    </span>
  );
}

/**
 * Status: an OUTLINED chip with a leading icon and the label (SCREENS 2). `detail` adds a muted sentence part such as
 * "pending true positive decision" or "until 12 Feb".
 * @param {{ status: string, detail?: string, by?: string | null, className?: string }} props
 */
export function StatusBadge({ status, detail, by, className }) {
  const { label, icon: Icon, tone, muted } = statusPresentation(status);
  return (
    <span className="inline-flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
      <Badge tone={tone} className={cn(muted && "text-muted-foreground", className)}>
        <Icon aria-hidden="true" />
        {label}
      </Badge>
      {by ? <span className="text-xs text-muted-foreground">by {by}</span> : null}
      {detail ? <span className="text-xs text-muted-foreground">{detail}</span> : null}
    </span>
  );
}

const HOUR = 3_600_000;
function span(ms) {
  const hours = Math.max(0, Math.round(ms / HOUR));
  if (hours >= 48) return `${Math.round(hours / 24)} d`;
  if (hours >= 1) return `${hours} h`;
  return "under 1 h";
}

/**
 * SLA chip: icon, text and the state word (visible text plus a screen-reader prefix), the due date in a tooltip. Closed findings
 * and findings without a target show an em dash (SCREENS 2). `now` lets a detail card tick every minute.
 * @param {{ sla: { state: string, dueAt: string | null }, now?: number }} props
 */
export function SlaChip({ sla, now }) {
  const [rendered] = useState(() => Date.now());
  if (!sla || sla.state === "not_applicable" || !sla.dueAt)
    return (
      <span className="text-muted-foreground" aria-label="No SLA">
        —
      </span>
    );
  const delta = Date.parse(sla.dueAt) - (now ?? rendered);
  const Icon = SLA_ICON[sla.state] ?? SLA_ICON.on_track;
  const text =
    sla.state === "breached"
      ? `Overdue ${span(-delta)}`
      : sla.state === "due_soon"
        ? `Due in ${span(delta)}`
        : `${span(delta)} left`;
  const word = { on_track: "On track", due_soon: "Due soon", breached: "Breached" }[sla.state];
  const tone =
    sla.state === "breached" ? "danger" : sla.state === "due_soon" ? "warning" : "neutral";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Badge tone={tone}>
            <Icon aria-hidden="true" />
            <span className="sr-only">{word}: </span>
            {text}
          </Badge>
        </button>
      </TooltipTrigger>
      <TooltipContent>
        {word}. Due {absoluteTime(sla.dueAt, { dateStyle: "medium", timeStyle: "short" })}
      </TooltipContent>
    </Tooltip>
  );
}

/** The recurrence icon with "Reopened N times" (only when `reopenCount > 0`). @param {{ count: number }} props */
export function RecurrenceIcon({ count }) {
  if (!count) return null;
  const text = `Reopened ${count} ${count === 1 ? "time" : "times"}`;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={text}
          className="inline-flex size-5 items-center justify-center rounded-sm text-status-warning outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Repeat aria-hidden="true" className="size-3.5" />
        </button>
      </TooltipTrigger>
      <TooltipContent>{text}</TooltipContent>
    </Tooltip>
  );
}

/**
 * The small advisory hint of a list row ("Likely TP 87%"): neutral, never a status colour, only when the advice is ready. It is
 * labelled "AI advisory" for assistive technology.
 * @param {{ hint: { suggestion: string, confidence: number } | null | undefined }} props
 */
export function AdvisoryHint({ hint }) {
  if (!hint) return <span className="text-muted-foreground">—</span>;
  return (
    <span
      className="inline-flex items-center gap-1 rounded-sm border border-dashed border-border-strong px-1.5 py-0.5 text-xs whitespace-nowrap text-muted-foreground"
      title="AI advisory: requires a human decision"
    >
      <Sparkles aria-hidden="true" className="size-3" />
      <span className="sr-only">AI advisory: </span>
      {SUGGESTION_HINT_LABELS[hint.suggestion]} {hint.confidence}%
    </span>
  );
}

/** A person: a monogram avatar (decorative) and the name, or "Unassigned". @param {{ user: { displayName: string } | null, empty?: string }} props */
export function Person({ user, empty = "Unassigned" }) {
  if (!user) return <span className="text-muted-foreground">{empty}</span>;
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        aria-hidden="true"
        className="flex size-5 shrink-0 items-center justify-center rounded-full bg-secondary text-[10px] font-medium text-secondary-foreground"
      >
        {initials(user.displayName)}
      </span>
      <span className="truncate">{user.displayName}</span>
    </span>
  );
}
const initials = (name) =>
  name
    .split(/\s+/)
    .map((p) => p[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase() || "?";

/** Location text: `path:line` in mono (middle-truncated) or `name@version` for SCA. @param {{ item: any }} props */
export function LocationCell({ item }) {
  if (item.scanType === "sca" && item.component)
    return (
      <Identifier
        value={`${item.component.name}@${item.component.version ?? "?"}`}
        max={24}
        label="component"
      />
    );
  if (!item.location?.path) return <span className="text-muted-foreground">—</span>;
  const line = item.location.startLine ? `:${item.location.startLine}` : "";
  return <Identifier value={`${item.location.path}${line}`} max={20} copy label="path" />;
}

/** Plain, escaped text of untrusted origin (never HTML or Markdown). @param {{ children: any, className?: string }} props */
export const Untrusted = ({ children, className }) => (
  <span className={cn("break-words whitespace-pre-wrap", className)}>{children}</span>
);
