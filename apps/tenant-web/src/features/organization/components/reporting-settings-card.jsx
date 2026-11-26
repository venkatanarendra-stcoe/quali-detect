import { BarChart3, Info, Loader2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Controller, useForm, useWatch } from "react-hook-form";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
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
import { Label } from "@/components/ui/label.jsx";
import { Select } from "@/components/ui/select.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { absoluteTime } from "@/features/executions/components/execution-bits.jsx";
import {
  useReportingSettings,
  useUpdateReportingSettings,
} from "../hooks/use-reporting-settings.js";

const CONFIRM_TEXT =
  "Trends and daily counts will be recomputed in the new zone; severity history before the change is not recorded again. Reports already generated keep the days they were made with. The change is recorded in the audit log.";

/** The IANA names this browser knows, plus UTC and the current value (a name set elsewhere must stay selectable). @param {string} current */
export function timeZoneOptions(current) {
  let names = [];
  try {
    names = Intl.supportedValuesOf("timeZone");
  } catch {
    names = [];
  }
  return [...new Set(["UTC", ...names, ...(current ? [current] : [])])].sort((a, b) =>
    a === "UTC" ? -1 : b === "UTC" ? 1 : a.localeCompare(b),
  );
}

function Frame({ children }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BarChart3 aria-hidden="true" className="size-4 text-muted-foreground" />
          Reporting
        </CardTitle>
        <CardDescription>
          The time zone that decides which day a finding, a scan or a decision belongs to. Days in
          reports and charts follow it.
        </CardDescription>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function Note({ children }) {
  return (
    <p className="flex items-start gap-2 text-sm">
      <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      <span>{children}</span>
    </p>
  );
}

function Recomputing() {
  return (
    <p role="status" className="flex items-start gap-2 text-sm">
      <Loader2
        aria-hidden="true"
        className="mt-0.5 size-4 shrink-0 animate-spin text-muted-foreground motion-reduce:animate-none"
      />
      <span>
        <span className="font-medium">Recomputing.</span>{" "}
        <span className="text-muted-foreground">
          Trends and daily counts are being rebuilt in the new zone. Days not rebuilt yet show as
          not recorded, never as zero. This page checks again every few seconds.
        </span>
      </span>
    </p>
  );
}

function ZoneForm({ settings, canManage }) {
  const update = useUpdateReportingSettings();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const options = useMemo(
    () => timeZoneOptions(settings.reportingTimezone),
    [settings.reportingTimezone],
  );
  const form = useForm({ values: { zone: settings.reportingTimezone } });
  const chosen = useWatch({ control: form.control, name: "zone" });
  const dirty = chosen !== settings.reportingTimezone;
  const busy = update.isPending || settings.recomputing;

  const confirm = () =>
    update.mutate(
      { reportingTimezone: chosen },
      {
        onSuccess: () => {
          setConfirmOpen(false);
        },
      },
    );

  return (
    <div className="space-y-4">
      <div className="space-y-1 text-sm">
        <p className="text-muted-foreground">Reporting time zone</p>
        <p>
          <span className="font-mono font-medium" data-testid="reporting-zone">
            {settings.reportingTimezone}
          </span>
          {settings.updatedAt ? (
            <span className="text-xs text-muted-foreground">
              {" · last changed "}
              <time dateTime={settings.updatedAt} title={absoluteTime(settings.updatedAt)}>
                {absoluteTime(settings.updatedAt)}
              </time>
              {settings.updatedBy?.displayName ? ` by ${settings.updatedBy.displayName}` : ""}
            </span>
          ) : (
            <span className="text-xs text-muted-foreground"> · default, never changed</span>
          )}
        </p>
      </div>

      {settings.recomputing ? <Recomputing /> : null}

      {canManage ? (
        <form
          noValidate
          aria-label="Reporting time zone"
          className="space-y-3"
          onSubmit={form.handleSubmit(() => {
            if (dirty) setConfirmOpen(true);
          })}
        >
          <div className="max-w-sm space-y-1.5">
            <Label htmlFor="reporting-zone-select">Change the time zone</Label>
            <Controller
              control={form.control}
              name="zone"
              render={({ field }) => (
                <Select
                  id="reporting-zone-select"
                  name={field.name}
                  ref={field.ref}
                  value={field.value}
                  onChange={field.onChange}
                  onBlur={field.onBlur}
                  disabled={busy}
                  placeholder="Search a time zone"
                  aria-describedby="reporting-zone-help"
                >
                  {options.map((zone) => (
                    <option key={zone} value={zone}>
                      {zone}
                    </option>
                  ))}
                </Select>
              )}
            />
            <p id="reporting-zone-help" className="text-xs text-muted-foreground">
              Search by city or region, for example Europe/Berlin. A day is midnight to midnight in
              this zone, so a change moves the day boundary of every report and chart.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" disabled={!dirty || busy}>
              Save time zone
            </Button>
            {dirty ? (
              <Button
                type="button"
                variant="ghost"
                disabled={busy}
                onClick={() => form.reset({ zone: settings.reportingTimezone })}
              >
                Discard
              </Button>
            ) : null}
          </div>
        </form>
      ) : (
        <Note>You can see this setting but you cannot change it. Ask an administrator.</Note>
      )}

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(open) => {
          setConfirmOpen(open);
          if (!open) update.reset();
        }}
        title={`Change the reporting time zone to ${chosen}?`}
        description={CONFIRM_TEXT}
        confirmLabel="Change time zone"
        pending={update.isPending}
        error={update.error}
        onConfirm={confirm}
      />
    </div>
  );
}

/**
 * "Reporting" card of the organization Settings (docs/modules/reporting-dashboards/AS_BUILT_TZ.md): the tenant reporting time zone,
 * a searchable list of IANA names, and the "Recomputing" state while a rebuild runs. Seen with `tenant_settings.view`, changed with
 * `tenant_settings.manage` (the central engine decides; the server enforces both). With the reporting module off for the deployment
 * the server answers 404 and the card says so instead of showing an error.
 */
export function ReportingSettingsCard() {
  const can = useCan();
  const canView = can("tenant_settings.view");
  const canManage = can("tenant_settings.manage");
  const query = useReportingSettings({ enabled: canView });
  if (!canView)
    return (
      <Frame>
        <UnauthorizedState description="You don't have permission to see this setting." />
      </Frame>
    );
  if (query.isPending)
    return (
      <Frame>
        <div role="status" aria-busy="true" className="space-y-2">
          <span className="sr-only">Loading reporting settings…</span>
          <Skeleton className="h-5 w-1/2" />
          <Skeleton className="h-10 w-full max-w-sm" />
        </div>
      </Frame>
    );
  if (query.isError) {
    if (query.error?.status === 404)
      return (
        <Frame>
          <Note>
            Reporting is not turned on for this platform yet, so there is no time zone to set.
          </Note>
        </Frame>
      );
    return (
      <Frame>
        <QueryErrorState error={query.error} onRetry={() => query.refetch()} />
      </Frame>
    );
  }
  return (
    <Frame>
      <ZoneForm settings={query.data} canManage={canManage} />
    </Frame>
  );
}
