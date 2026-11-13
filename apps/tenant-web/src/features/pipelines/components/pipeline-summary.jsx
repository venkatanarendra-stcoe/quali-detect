import { Badge } from "@/components/ui/badge.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { TRIGGER_ICONS, TRIGGER_LABELS } from "../constants/index.js";
import { usePipelineVersion } from "../hooks/use-pipelines.js";
import { absoluteTime, ScanChips, triggerText } from "./pipeline-bits.jsx";

function Metric({ title, children }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent className="text-sm">{children}</CardContent>
    </Card>
  );
}

/**
 * Summary of T-27 (top of Overview): triggers (type, on/off, next scheduled run), enabled scans, success rate and open
 * findings. Triggers come from the pipeline DTO and scans from the current configuration version; success rate and open
 * findings have no data until the execution and findings modules exist, so they say so instead of showing a number.
 * @param {{ pipeline: any }} props
 */
export function PipelineSummary({ pipeline }) {
  const version = usePipelineVersion(pipeline.id, pipeline.currentVersion?.version, {
    enabled: !pipeline.deletedAt,
  });
  const config = version.data?.config;
  const scans = pipeline.deletedAt || version.isError ? null : config;
  return (
    <section aria-label="Pipeline summary" className="mb-4 grid gap-3 md:grid-cols-3">
      <div className="md:col-span-3">
        <Metric title="Triggers">
          {pipeline.triggers.length === 0 ? (
            <p className="text-muted-foreground">No triggers configured.</p>
          ) : (
            <ul className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
              {pipeline.triggers.map((t) => {
                const Icon = TRIGGER_ICONS[t.type];
                const detail = config?.triggers?.find((c) => c.key === t.key);
                return (
                  <li key={t.key} className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="inline-flex items-center gap-1.5 font-medium">
                      {Icon ? <Icon aria-hidden="true" className="size-3.5" /> : null}
                      {t.type === "schedule" && detail
                        ? triggerText(t, detail)
                        : (TRIGGER_LABELS[t.type] ?? t.type)}
                    </span>
                    <Badge tone={t.enabled ? "success" : "neutral"}>
                      {t.enabled ? "Enabled" : "Disabled"}
                    </Badge>
                    {t.type === "schedule" ? (
                      <span className="text-xs text-muted-foreground">
                        {t.enabled && t.nextRunAt
                          ? `Next run ${absoluteTime(t.nextRunAt, { timeStyle: "short", timeZoneName: "short" })}`
                          : "No upcoming run"}
                      </span>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          )}
        </Metric>
      </div>
      <Metric title="Scans enabled">
        <ScanChips config={scans} />
      </Metric>
    </section>
  );
}
