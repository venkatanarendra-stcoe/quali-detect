import { Info, Timer } from "lucide-react";
import { useState } from "react";
import { SLA_DEFAULT_HOURS, FINDINGS_LIMITS } from "@qmentisai/shared";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { UnauthorizedState } from "@/components/states/unauthorized-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { describeError } from "@/lib/api/index.js";
import { useSlaSettings, useUpdateSlaSettings } from "../hooks/use-findings.js";
import { SeverityBadge } from "./finding-bits.jsx";

/** The four severities that have a target; Info never has one (SPEC SL-1). */
const ROWS = Object.freeze(["critical", "high", "medium", "low"]);
const HOURS_PER_DAY = 24;
const MAX_HOURS = FINDINGS_LIMITS.slaHoursMax;

/** The text shown for a typed value, or "" when it is valid. @param {string} raw @param {"hours" | "days"} unit */
function validate(raw, unit) {
  const value = Number(raw);
  if (raw.trim() === "" || !Number.isFinite(value)) return "Enter a number.";
  if (!Number.isInteger(value)) return "Use a whole number.";
  const hours = unit === "days" ? value * HOURS_PER_DAY : value;
  if (hours < 1) return "Use at least 1 hour.";
  if (hours > MAX_HOURS)
    return `Use at most ${MAX_HOURS.toLocaleString()} hours (${(MAX_HOURS / HOURS_PER_DAY).toLocaleString()} days).`;
  return "";
}

function Frame({ children }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Timer aria-hidden="true" className="size-4 text-muted-foreground" />
          Findings SLA targets
        </CardTitle>
        <CardDescription>
          How long a finding of each severity may stay open before it is overdue.
        </CardDescription>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function SlaForm({ settings, canManage }) {
  const update = useUpdateSlaSettings();
  const [unit, setUnit] = useState(/** @type {"hours" | "days"} */ ("hours"));
  const [values, setValues] = useState(() =>
    Object.fromEntries(settings.targets.map((t) => [t.severity, String(t.hours ?? "")])),
  );
  const [errors, setErrors] = useState({});
  const rowsByKey = Object.fromEntries(settings.targets.map((t) => [t.severity, t]));
  const toUnit = (hours) => (unit === "days" ? String(hours / HOURS_PER_DAY) : String(hours));

  const switchUnit = (next) => {
    if (next === unit) return;
    // convert what is typed so the number keeps its meaning (a days value must divide into hours)
    const converted = {};
    for (const sev of ROWS) {
      const n = Number(values[sev]);
      converted[sev] =
        Number.isFinite(n) && values[sev] !== ""
          ? next === "days"
            ? String(Math.round((n / HOURS_PER_DAY) * 100) / 100)
            : String(Math.round(n * HOURS_PER_DAY))
          : values[sev];
    }
    setValues(converted);
    setUnit(next);
    setErrors({});
  };

  const hoursOf = (sev) => Number(values[sev]) * (unit === "days" ? HOURS_PER_DAY : 1);
  const dirty = ROWS.some((sev) => hoursOf(sev) !== rowsByKey[sev]?.hours);

  const submit = (event) => {
    event.preventDefault();
    const found = {};
    for (const sev of ROWS) {
      const message = validate(values[sev] ?? "", unit);
      if (message) found[sev] = message;
    }
    setErrors(found);
    if (Object.keys(found).length) {
      document.getElementById(`sla-${Object.keys(found)[0]}`)?.focus();
      return;
    }
    update.mutate(ROWS.map((severity) => ({ severity, hours: hoursOf(severity) })));
  };

  return (
    <form onSubmit={submit} noValidate className="space-y-4" aria-label="Findings SLA targets">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span id="sla-unit-label" className="text-muted-foreground">
          Show targets in
        </span>
        <div role="group" aria-labelledby="sla-unit-label" className="flex gap-1">
          {["hours", "days"].map((u) => (
            <Button
              key={u}
              type="button"
              size="sm"
              variant="secondary"
              aria-pressed={unit === u}
              onClick={() => switchUnit(u)}
              className={unit === u ? "border-border-strong bg-accent" : undefined}
            >
              {u === "hours" ? "Hours" : "Days"}
            </Button>
          ))}
        </div>
      </div>

      <ul className="divide-y divide-border rounded-md border border-border">
        {ROWS.map((sev) => {
          const row = rowsByKey[sev];
          const error = errors[sev];
          return (
            <li key={sev} className="flex flex-wrap items-start gap-x-4 gap-y-1 px-3 py-2.5">
              <div className="w-24 pt-1.5">
                <SeverityBadge severity={sev} />
              </div>
              <div className="min-w-0 flex-1 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Label htmlFor={`sla-${sev}`} className="sr-only">
                    {sev} target in {unit}
                  </Label>
                  <Input
                    id={`sla-${sev}`}
                    type="number"
                    inputMode="numeric"
                    min={1}
                    max={unit === "days" ? MAX_HOURS / HOURS_PER_DAY : MAX_HOURS}
                    step={1}
                    className="w-32"
                    value={values[sev] ?? ""}
                    disabled={!canManage || update.isPending}
                    onChange={(e) => setValues((v) => ({ ...v, [sev]: e.target.value }))}
                    aria-invalid={error ? true : undefined}
                    aria-describedby={error ? `sla-${sev}-error` : `sla-${sev}-hint`}
                  />
                  <span className="text-sm text-muted-foreground">{unit}</span>
                  {row?.isDefault ? (
                    <span className="text-xs text-subtle-foreground">Default</span>
                  ) : (
                    <span className="text-xs text-subtle-foreground">
                      Default is {toUnit(SLA_DEFAULT_HOURS[sev])} {unit}
                    </span>
                  )}
                </div>
                {error ? (
                  <p id={`sla-${sev}-error`} role="alert" className="text-xs text-status-danger">
                    {error}
                  </p>
                ) : (
                  <p id={`sla-${sev}-hint`} className="sr-only">
                    Whole {unit}, from 1 hour to {MAX_HOURS.toLocaleString()} hours.
                  </p>
                )}
              </div>
            </li>
          );
        })}
        <li className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2.5">
          <div className="w-24">
            <SeverityBadge severity="info" />
          </div>
          <p className="text-sm text-muted-foreground">No SLA. Info findings have no target.</p>
        </li>
      </ul>

      <p className="flex items-start gap-2 text-sm text-muted-foreground">
        <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
        Changes are not retroactive. A finding keeps its due date; a new target applies when a
        finding&apos;s clock starts again (for example when it is reopened). Overdue findings stay
        overdue. Changes are recorded in the audit log.
      </p>

      {canManage ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" disabled={!dirty || update.isPending}>
            {update.isPending ? "Saving…" : "Save targets"}
          </Button>
          <Button
            type="button"
            variant="secondary"
            disabled={update.isPending}
            onClick={() => {
              setValues(
                Object.fromEntries(
                  ROWS.map((sev) => [
                    sev,
                    unit === "days"
                      ? String(SLA_DEFAULT_HOURS[sev] / HOURS_PER_DAY)
                      : String(SLA_DEFAULT_HOURS[sev]),
                  ]),
                ),
              );
              setErrors({});
            }}
          >
            Reset to defaults
          </Button>
          {update.isError ? (
            <p role="alert" className="text-sm text-status-danger">
              {describeError(update.error)}
            </p>
          ) : null}
        </div>
      ) : (
        <p className="flex items-start gap-2 text-sm">
          <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          You can see these targets but you cannot change them. Ask an administrator.
        </p>
      )}
    </form>
  );
}

/**
 * "Findings SLA targets" card of the organization Settings (SCREENS 11): Critical, High, Medium and Low in hours or days, Info shown
 * as "no SLA". Seen with `tenant_settings.view`, changed with `tenant_settings.manage` (the central engine decides; the server
 * enforces both). Saving replaces the tenant's targets and is not retroactive.
 */
export function FindingsSlaCard() {
  const can = useCan();
  const canView = can("tenant_settings.view");
  const canManage = can("tenant_settings.manage");
  const query = useSlaSettings({ enabled: canView });
  if (!canView)
    return (
      <Frame>
        <UnauthorizedState description="You don't have permission to see these targets." />
      </Frame>
    );
  if (query.isPending)
    return (
      <Frame>
        <div role="status" aria-busy="true" className="space-y-2">
          <span className="sr-only">Loading SLA targets…</span>
          <Skeleton className="h-9 w-1/2" />
          <Skeleton className="h-32 w-full" />
        </div>
      </Frame>
    );
  if (query.isError)
    return (
      <Frame>
        <QueryErrorState error={query.error} onRetry={() => query.refetch()} />
      </Frame>
    );
  if (!query.data?.targets?.length)
    return (
      <Frame>
        <p className="text-sm text-muted-foreground">No SLA targets are available.</p>
      </Frame>
    );
  return (
    <Frame>
      {/* keyed by the stored targets: a save (or another admin's change) resets the form to what is stored */}
      <SlaForm
        key={JSON.stringify(query.data.targets)}
        settings={query.data}
        canManage={canManage}
      />
    </Frame>
  );
}
