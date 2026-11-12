import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { Badge } from "@/components/ui/badge.jsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import {
  EFFECTIVE_STATES,
  SCAN_SHORT,
  TRIGGER_ICONS,
  TRIGGER_LABELS,
  executionStatus,
} from "../constants/index.js";
import { describeCron } from "../schemas/index.js";
import { DEFAULT_BRANCH_TOKEN, PIPELINE_SCAN_TYPES } from "@qmentisai/shared";

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
export function Identifier({ value, max = 12, copy = false, label = "value" }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-muted-foreground">—</span>;
  const shown = value.length > max * 2 + 1 ? `${value.slice(0, max)}…${value.slice(-max)}` : value;
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
        <TooltipContent className="font-mono break-all">{value}</TooltipContent>
      </Tooltip>
      {copy ? (
        <button
          type="button"
          aria-label={`Copy ${label}`}
          onClick={() => {
            navigator.clipboard?.writeText(value).then(
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

/** Derived effective state as an outlined chip with icon and text; the reason is the tooltip. */
export function EffectiveStateChip({ state }) {
  const entry = EFFECTIVE_STATES[state] ?? EFFECTIVE_STATES.disabled;
  const Icon = entry.icon;
  const chip = (
    <Badge tone={entry.tone}>
      <Icon aria-hidden="true" />
      {entry.label}
    </Badge>
  );
  if (!entry.reason) return chip;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="inline-flex cursor-default rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {chip}
        </button>
      </TooltipTrigger>
      <TooltipContent>{entry.reason}</TooltipContent>
    </Tooltip>
  );
}

/** Status chip of an execution request. Reserved statuses of later modules render neutrally. */
export function ExecutionStatusChip({ status }) {
  const { label, tone, icon: Icon } = executionStatus(status);
  return (
    <Badge tone={tone}>
      <Icon aria-hidden="true" />
      {label}
    </Badge>
  );
}

/** Short text of one trigger for chips; `config` is the trigger from a configuration version (optional). */
export function triggerText(trigger, config) {
  const base = TRIGGER_LABELS[trigger.type] ?? trigger.type;
  if (!config) return base;
  if (trigger.type === "push") {
    const names = (config.branches?.include ?? []).map((p) =>
      p === DEFAULT_BRANCH_TOKEN ? "default branch" : p,
    );
    return names.length
      ? `${base} ${names.slice(0, 2).join(", ")}${names.length > 2 ? "…" : ""}`
      : base;
  }
  if (trigger.type === "schedule")
    return `${base} ${describeCron(config.cron) ?? config.cron} ${config.timezone}`;
  return base;
}

/** Chips of a pipeline's triggers. `config` (current version) adds patterns and cron details when loaded. */
export function TriggerChips({ pipeline, config }) {
  if (pipeline.triggers.length === 0) return <span className="text-muted-foreground">None</span>;
  return (
    <ul className="flex flex-wrap gap-1" aria-label="Triggers">
      {pipeline.triggers.map((t) => {
        const Icon = TRIGGER_ICONS[t.type];
        const detail = config?.triggers?.find((c) => c.key === t.key);
        return (
          <li key={t.key}>
            <Badge tone="neutral" className={t.enabled ? "" : "text-muted-foreground"}>
              {Icon ? <Icon aria-hidden="true" /> : null}
              <span className={t.type === "schedule" && detail ? "font-mono" : undefined}>
                {triggerText(t, detail)}
              </span>
              {t.enabled ? "" : <span className="font-normal"> (off)</span>}
            </Badge>
          </li>
        );
      })}
    </ul>
  );
}

/** Chips of the enabled scans of a configuration (`undefined` while it loads, `null` when there is none to show). */
export function ScanChips({ config }) {
  if (config === null) return <span className="text-muted-foreground">—</span>;
  if (!config) return <span className="text-muted-foreground">…</span>;
  const enabled = PIPELINE_SCAN_TYPES.filter((type) => config.scans?.[type]?.enabled);
  if (enabled.length === 0) return <span className="text-muted-foreground">None</span>;
  return (
    <ul className="flex flex-wrap gap-1" aria-label="Scans">
      {enabled.map((type) => (
        <li key={type}>
          <Badge tone="neutral">{SCAN_SHORT[type]}</Badge>
        </li>
      ))}
    </ul>
  );
}

/** Last request: status chip and relative time. @param {{ lastRequest: any }} props */
export function LastRequest({ lastRequest }) {
  if (!lastRequest) return <span className="text-muted-foreground">No requests yet</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <ExecutionStatusChip status={lastRequest.status} />
      <TimeAgo value={lastRequest.requestedAt} />
    </span>
  );
}
