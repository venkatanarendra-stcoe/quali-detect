import {
  REPORT_EXCLUSION_NOTICE,
  REPORT_MAX_PERIOD_DAYS,
  REPORT_PERIOD_PRESETS,
  REPORT_TEMPLATES,
  REPORT_TEMPLATE_BY_ID,
} from "@qmentisai/shared";
import { useId, useState } from "react";
import { Button } from "@/components/ui/button.jsx";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { describeError, isApiError } from "@/lib/api/index.js";
import { cn } from "@/lib/cn.js";
import { DEFAULT_PERIOD, GENERATE_ERROR_TEXT } from "../constants/index.js";
import { useReturnFocus } from "../hooks/use-return-focus.js";
import { useGenerateReport, usePosture, useSbom } from "../hooks/use-reporting.js";
import { customRangeError, todayIn } from "../schemas/params.js";
import { formatCount } from "../schemas/format.js";

const V1_TEMPLATES = REPORT_TEMPLATES.filter((t) => t.v1);
const CHIP =
  "inline-flex h-8 items-center rounded-sm border px-3 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring";

/** The estimated row count where the API gives a number to base it on (open findings, SBOM components); otherwise "a summary". */
function useRowEstimate(open, templateId, workspaceId, scope, canFinding, canExec) {
  const wantsFindings =
    open &&
    Boolean(workspaceId) &&
    templateId === "findings_by_pipeline" &&
    scope === "workspace" &&
    canFinding;
  const wantsSbom =
    open &&
    Boolean(workspaceId) &&
    templateId === "sbom_inventory" &&
    scope === "workspace" &&
    canExec;
  const posture = usePosture(workspaceId, {}, { enabled: wantsFindings });
  const sbom = useSbom(workspaceId, { period: String(DEFAULT_PERIOD) }, { enabled: wantsSbom });
  if (wantsFindings)
    return {
      loading: posture.isPending,
      text: posture.data
        ? `About ${formatCount(posture.data.data.open)} rows (the open findings today).`
        : "Not available.",
    };
  if (wantsSbom)
    return {
      loading: sbom.isPending,
      text: sbom.data
        ? `About ${formatCount(sbom.data.data.components)} rows (the components today).`
        : "Not available.",
    };
  const t = REPORT_TEMPLATE_BY_ID[templateId];
  return {
    loading: false,
    text: t?.csvColumns.length
      ? "The row count is known when the report is built."
      : "A summary of a few pages.",
  };
}

/**
 * T-50 Generate report. Opened from a template card (`lockTemplate`), from a "Download CSV of this view" link or from the
 * Organization Overview. Needs `report.export` (the opener is hidden without it). Errors from the API stay in the dialog with
 * their stable message; Escape closes without losing the options (state lives in this component, the content only mounts open).
 * @param {{ open: boolean, onOpenChange: (open: boolean) => void, workspaceId?: string, lockTemplate?: boolean, tenantWide?: boolean,
 *   initial?: { template?: string, format?: string, asOfDay?: string, period?: { from: string, to: string } } }} props
 */
export function GenerateReportDialog({
  open,
  onOpenChange,
  workspaceId,
  lockTemplate = false,
  tenantWide = false,
  initial = {},
}) {
  const can = useCan();
  const canFinding = can("finding.view");
  const canExec = can("execution.view");
  const canTenantScope = can("dashboard.view");
  const [templateId, setTemplateId] = useState(initial.template ?? "executive_summary");
  const template = REPORT_TEMPLATE_BY_ID[templateId] ?? V1_TEMPLATES[0];
  const [format, setFormat] = useState(initial.format ?? template.formats[0]);
  const [scope, setScope] = useState(tenantWide ? "tenant" : "workspace");
  const [preset, setPreset] = useState(DEFAULT_PERIOD);
  const [custom, setCustom] = useState(Boolean(initial.period));
  const [from, setFrom] = useState(initial.period?.from ?? "");
  const [to, setTo] = useState(initial.period?.to ?? "");
  const [asOfDay, setAsOfDay] = useState(initial.asOfDay ?? "");
  const [error, setError] = useState("");
  const fromId = useId();
  const toId = useId();
  const asOfId = useId();
  const today = todayIn(undefined);
  const returnFocus = useReturnFocus();
  const generate = useGenerateReport(workspaceId);
  const estimate = useRowEstimate(open, templateId, workspaceId, scope, canFinding, canExec);

  const effectiveFormat = template.formats.includes(format) ? format : template.formats[0];
  const needsPeriod = template.periodMode === "period";
  const needsAsOf = template.periodMode === "asOfDay";
  const rangeProblem = needsPeriod && custom ? customRangeError(from, to, today) : "";
  const asOfProblem = needsAsOf
    ? !asOfDay
      ? "Choose the day."
      : asOfDay >= today
        ? "Choose a day before today."
        : ""
    : "";
  const blocked = rangeProblem || asOfProblem || estimate.loading;
  const reason = estimate.loading ? "Waiting for the row estimate…" : rangeProblem || asOfProblem;

  const columns =
    effectiveFormat === "csv"
      ? template.csvColumns
          .filter((c) => !c.requiresPermission || can(c.requiresPermission))
          .map((c) => c.header)
      : template.pdfSections.map((s) => s.title);
  const assigneeNote =
    effectiveFormat === "csv" &&
    template.csvColumns.some((c) => c.requiresPermission === "finding.assign") &&
    can("finding.assign");

  const submit = (event) => {
    event.preventDefault();
    if (blocked || generate.isPending) return;
    setError("");
    const body = {
      template: templateId,
      format: effectiveFormat,
      ...(scope === "workspace" ? { workspaceId } : {}),
      ...(needsPeriod ? (custom ? { from, to } : { period: String(preset) }) : {}),
      ...(needsAsOf ? { asOfDay } : {}),
    };
    generate.mutate(body, {
      onSuccess: () => onOpenChange(false),
      onError: (e) =>
        setError(
          isApiError(e) ? (GENERATE_ERROR_TEXT[e.code] ?? describeError(e)) : describeError(e),
        ),
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open ? (
        <DialogContent className="max-w-3xl" data-testid="generate-dialog" {...returnFocus}>
          <form onSubmit={submit}>
            <DialogHeader>
              <DialogTitle>Generate report</DialogTitle>
              <DialogDescription>
                The report is built in the background. Download it from the table when it is ready.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-6 md:grid-cols-[1fr_16rem]">
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <Label>Template</Label>
                  {lockTemplate ? (
                    <p className="text-sm font-medium">{template.title}</p>
                  ) : (
                    <Select
                      aria-label="Template"
                      value={templateId}
                      onChange={(e) => e.target.value && setTemplateId(e.target.value)}
                    >
                      {V1_TEMPLATES.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.title}
                        </option>
                      ))}
                    </Select>
                  )}
                </div>
                <div className="space-y-1.5">
                  <Label id="gen-format">Format</Label>
                  <div role="group" aria-labelledby="gen-format" className="flex gap-2">
                    {template.formats.map((f) => (
                      <button
                        key={f}
                        type="button"
                        aria-pressed={effectiveFormat === f}
                        onClick={() => setFormat(f)}
                        className={cn(
                          CHIP,
                          effectiveFormat === f
                            ? "border-border-strong bg-secondary"
                            : "border-border text-muted-foreground hover:bg-accent",
                        )}
                      >
                        {f.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>
                {canTenantScope && !tenantWide ? (
                  <div className="space-y-1.5">
                    <Label id="gen-scope">Scope</Label>
                    <div role="group" aria-labelledby="gen-scope" className="flex gap-2">
                      {[
                        ["workspace", "This workspace"],
                        ["tenant", "Entire organization"],
                      ].map(([v, label]) => (
                        <button
                          key={v}
                          type="button"
                          aria-pressed={scope === v}
                          onClick={() => setScope(v)}
                          className={cn(
                            CHIP,
                            scope === v
                              ? "border-border-strong bg-secondary"
                              : "border-border text-muted-foreground hover:bg-accent",
                          )}
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    <Label>Scope</Label>
                    <p className="text-sm">
                      {scope === "tenant" ? "Entire organization" : "This workspace"}
                    </p>
                  </div>
                )}
                {needsPeriod ? (
                  <div className="space-y-1.5">
                    <Label id="gen-period">Period</Label>
                    <div role="group" aria-labelledby="gen-period" className="flex flex-wrap gap-2">
                      {REPORT_PERIOD_PRESETS.map((n) => (
                        <button
                          key={n}
                          type="button"
                          aria-pressed={!custom && preset === n}
                          onClick={() => {
                            setCustom(false);
                            setPreset(n);
                          }}
                          className={cn(
                            CHIP,
                            !custom && preset === n
                              ? "border-border-strong bg-secondary"
                              : "border-border text-muted-foreground hover:bg-accent",
                          )}
                        >
                          {n} days
                        </button>
                      ))}
                      <button
                        type="button"
                        aria-pressed={custom}
                        onClick={() => setCustom(true)}
                        className={cn(
                          CHIP,
                          custom
                            ? "border-border-strong bg-secondary"
                            : "border-border text-muted-foreground hover:bg-accent",
                        )}
                      >
                        Custom
                      </button>
                    </div>
                    {custom ? (
                      <div className="flex flex-wrap items-end gap-2 pt-1">
                        <div className="space-y-1">
                          <Label htmlFor={fromId} className="text-xs">
                            From
                          </Label>
                          <Input
                            id={fromId}
                            type="date"
                            max={today}
                            value={from}
                            onChange={(e) => setFrom(e.target.value)}
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
                            max={today}
                            value={to}
                            onChange={(e) => setTo(e.target.value)}
                            className="h-8 w-40"
                          />
                        </div>
                      </div>
                    ) : null}
                    {rangeProblem && (from || to) ? (
                      <p role="alert" className="text-xs text-status-danger">
                        {rangeProblem}
                      </p>
                    ) : null}
                    <p className="text-xs text-subtle-foreground">
                      At most {REPORT_MAX_PERIOD_DAYS} days. A preset ends today, so far.
                    </p>
                  </div>
                ) : null}
                {needsAsOf ? (
                  <div className="space-y-1.5">
                    <Label htmlFor={asOfId}>As of day</Label>
                    <Input
                      id={asOfId}
                      type="date"
                      max={today}
                      value={asOfDay}
                      onChange={(e) => setAsOfDay(e.target.value)}
                      className="h-8 w-40"
                      aria-invalid={Boolean(asOfProblem && asOfDay) || undefined}
                    />
                    <p className="text-xs text-subtle-foreground">
                      The open findings at the end of that day.
                    </p>
                  </div>
                ) : null}
                {assigneeNote ? (
                  <p className="text-xs text-muted-foreground">
                    The assignee display name is included because you can assign findings.
                  </p>
                ) : null}
                {error ? (
                  <p role="alert" className="text-sm text-status-danger">
                    {error}
                  </p>
                ) : null}
              </div>
              <aside
                aria-label="What this report contains"
                className="space-y-2 rounded-md border border-border bg-card p-3 text-sm"
              >
                <h3 className="text-sm font-medium">What this report contains</h3>
                <ul className="list-disc space-y-0.5 pl-4 text-xs text-muted-foreground">
                  {columns.map((c) => (
                    <li key={c}>{c}</li>
                  ))}
                </ul>
                <p className="text-xs">
                  <span className="font-medium">Estimate:</span>{" "}
                  <span className="text-muted-foreground">{estimate.text}</span>
                </p>
                <p className="text-xs text-muted-foreground">
                  Excluded by design: code excerpts, comments, rationales, AI reasoning, secret
                  previews. {REPORT_EXCLUSION_NOTICE}
                </p>
              </aside>
            </div>
            <DialogFooter>
              {reason ? (
                <span className="mr-auto self-center text-xs text-muted-foreground" id="gen-reason">
                  {reason}
                </span>
              ) : null}
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={Boolean(blocked) || generate.isPending}
                aria-describedby={reason ? "gen-reason" : undefined}
              >
                {generate.isPending ? "Generating…" : "Generate"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      ) : null}
    </Dialog>
  );
}
