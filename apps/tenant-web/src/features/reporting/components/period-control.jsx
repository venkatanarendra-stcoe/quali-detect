import {
  REPORT_MAX_PERIOD_DAYS,
  REPORT_PERIOD_PRESETS,
  isValidTimeZone,
  resolvePeriod,
} from "@qmentisai/shared";
import { Globe } from "lucide-react";
import { useId, useState } from "react";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { cn } from "@/lib/cn.js";
import { customRangeError } from "../schemas/params.js";
import { dayLabel } from "../schemas/format.js";

/** The resolved first and last day of the shown period, or null when the zone is not known yet. */
export function resolvedRange(period, timeZone) {
  if (period.kind === "custom") return { from: period.from, to: period.to };
  try {
    const r = resolvePeriod(
      { period: period.period },
      { now: new Date(), timeZone: timeZone && isValidTimeZone(timeZone) ? timeZone : "UTC" },
    );
    return { from: r.from, to: r.to };
  } catch {
    return null;
  }
}

const SEGMENT =
  "inline-flex h-8 items-center px-3 text-sm font-medium outline-none focus-visible:z-10 focus-visible:ring-2 focus-visible:ring-ring";

/**
 * The shared period control (SCREENS 1): segmented 7, 30, 90 days and Custom (two native date inputs, From and To), the tenant
 * time zone, an inline refusal over 400 days, and the helper line that states the half-open range. State is in the URL
 * (`period`, `from`, `to`) through `useReportingParams`.
 * @param {{ params: ReturnType<typeof import("../hooks/use-reporting-params.js").useReportingParams>, timeZone?: string, className?: string }} props
 */
export function PeriodControl({ params, timeZone, className }) {
  const { period, today, setPreset, setCustom } = params;
  const [open, setOpen] = useState(period.kind === "custom" || Boolean(period.invalid));
  const [from, setFrom] = useState(period.from ?? "");
  const [to, setTo] = useState(period.to ?? "");
  const [touched, setTouched] = useState(Boolean(period.invalid));
  const fromId = useId();
  const toId = useId();
  const showCustom = open || period.kind === "custom";
  const draftError = touched || (from && to) ? customRangeError(from, to, today) : "";
  const message = draftError || (touched ? "" : period.invalid);
  const range = resolvedRange(period, timeZone);
  const apply = () => {
    setTouched(true);
    if (customRangeError(from, to, today)) return;
    setCustom(from, to);
  };
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <div className="flex flex-wrap items-center gap-2">
        <div
          role="group"
          aria-label="Period"
          className="inline-flex overflow-hidden rounded-sm border border-border-strong"
        >
          {REPORT_PERIOD_PRESETS.map((n) => {
            const on = period.kind === "preset" && period.period === n && !open;
            return (
              <button
                key={n}
                type="button"
                aria-pressed={on}
                onClick={() => {
                  setOpen(false);
                  setPreset(n);
                }}
                className={cn(
                  SEGMENT,
                  "border-r border-border-strong",
                  on ? "bg-secondary text-foreground" : "text-muted-foreground hover:bg-accent",
                )}
              >
                {n} days
              </button>
            );
          })}
          <button
            type="button"
            aria-pressed={showCustom}
            onClick={() => setOpen(true)}
            className={cn(
              SEGMENT,
              showCustom ? "bg-secondary text-foreground" : "text-muted-foreground hover:bg-accent",
            )}
          >
            Custom
          </button>
        </div>
        <span
          className="inline-flex items-center gap-1 text-xs text-muted-foreground"
          title="Days are counted in the organization reporting time zone"
        >
          <Globe aria-hidden="true" className="size-3.5" />
          {timeZone ?? "Organization time zone"}
        </span>
      </div>
      {showCustom ? (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            apply();
          }}
        >
          <div className="space-y-1">
            <Label htmlFor={fromId} className="text-xs">
              From
            </Label>
            <Input
              id={fromId}
              type="date"
              value={from}
              max={today}
              onChange={(e) => setFrom(e.target.value)}
              aria-invalid={Boolean(message) || undefined}
              className="h-8 w-40"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor={toId} className="text-xs">
              To
            </Label>
            <Input
              id={toId}
              type="date"
              value={to}
              max={today}
              onChange={(e) => setTo(e.target.value)}
              aria-invalid={Boolean(message) || undefined}
              className="h-8 w-40"
            />
          </div>
          <Button type="submit" variant="secondary" size="sm">
            Apply
          </Button>
        </form>
      ) : null}
      {message ? (
        <p role="alert" className="text-xs text-status-danger">
          {message}
        </p>
      ) : null}
      <p className="text-xs text-muted-foreground">
        {period.kind === "preset"
          ? `${period.period} days = the last ${period.period} days including today (so far)`
          : "A custom range includes both its first and its last day"}
        {range ? `: ${dayLabel(range.from)} to ${dayLabel(range.to)}` : ""}. Each day runs from
        00:00 up to, not including, the next 00:00. At most {REPORT_MAX_PERIOD_DAYS} days.
      </p>
    </div>
  );
}
