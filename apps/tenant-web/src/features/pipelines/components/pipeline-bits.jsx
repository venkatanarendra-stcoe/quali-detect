import { Badge } from "@/components/ui/badge.jsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import { ExecutionStatusChip, TimeAgo } from "@/features/executions/components/execution-bits.jsx";
import { EFFECTIVE_STATES, SCAN_SHORT, TRIGGER_ICONS, TRIGGER_LABELS } from "../constants/index.js";
import { describeCron } from "../schemas/index.js";
import { DEFAULT_BRANCH_TOKEN, PIPELINE_SCAN_TYPES } from "@qmentisai/shared";

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
