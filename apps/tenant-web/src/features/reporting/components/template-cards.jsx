import { REPORT_TEMPLATES } from "@qmentisai/shared";
import { CalendarClock, FileText, Package, Sparkles, Table2, Timer, Wrench } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { NOT_INCLUDED_TEXT, TEMPLATE_COPY } from "../constants/index.js";

const ICON = {
  executive_summary: FileText,
  findings_by_pipeline: Table2,
  sla_compliance: Timer,
  remediation_performance: Wrench,
  sbom_inventory: Package,
  detection_quality: Sparkles,
  point_in_time_snapshot: CalendarClock,
};

/**
 * The report template cards (T-39). Only the v1 templates are rendered: the Audit evidence pack is deferred and NOT shown. Each
 * card has the formats as chips, a "What's included" disclosure and Generate (only with `report.export`).
 * @param {{ canExport: boolean, onGenerate: (templateId: string) => void }} props
 */
export function TemplateCards({ canExport, onGenerate }) {
  return (
    <ul aria-label="Report templates" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
      {REPORT_TEMPLATES.filter((t) => t.v1).map((t) => {
        const Icon = ICON[t.id] ?? FileText;
        const copy = TEMPLATE_COPY[t.id];
        return (
          <li key={t.id}>
            <Card className="h-full" data-testid={`template-${t.id}`}>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Icon aria-hidden="true" className="size-4 text-muted-foreground" />
                  {t.title}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">{copy?.description}</p>
                <ul aria-label="Formats" className="flex gap-1.5">
                  {t.formats.map((f) => (
                    <li
                      key={f}
                      className="rounded-sm border border-border-strong px-1.5 py-0.5 text-xs font-medium"
                    >
                      {f.toUpperCase()}
                    </li>
                  ))}
                </ul>
                <details className="text-sm">
                  <summary className="cursor-pointer rounded-sm text-primary-text outline-none focus-visible:ring-2 focus-visible:ring-ring">
                    What&apos;s included
                  </summary>
                  <ul className="mt-2 list-disc space-y-0.5 pl-5 text-xs text-muted-foreground">
                    {(copy?.includes ?? []).map((line) => (
                      <li key={line}>{line}</li>
                    ))}
                  </ul>
                  <p className="mt-2 text-xs text-subtle-foreground">{NOT_INCLUDED_TEXT}</p>
                </details>
                {canExport ? (
                  <Button variant="secondary" size="sm" onClick={() => onGenerate(t.id)}>
                    Generate
                  </Button>
                ) : null}
              </CardContent>
            </Card>
          </li>
        );
      })}
    </ul>
  );
}
