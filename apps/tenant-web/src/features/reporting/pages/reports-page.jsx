import { REPORT_STATUSES } from "@qmentisai/shared";
import { FileText } from "lucide-react";
import { useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router";
import { AppPageLayout } from "@qmentisai/ui";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Select } from "@/components/ui/select.jsx";
import { Switch } from "@/components/ui/switch.jsx";
import { useSession } from "@/features/auth/hooks/use-session.js";
import { useActiveWorkspace, useCan } from "@/features/authorization/hooks/use-permissions.js";
import { REPORT_STATUS_LABELS } from "../constants/index.js";
import { GenerateReportDialog } from "../components/generate-report-dialog.jsx";
import { ReportDetailsSheet } from "../components/report-details-sheet.jsx";
import { ReportsTable, TEMPLATE_FILTER_OPTIONS } from "../components/reports-table.jsx";
import { TemplateCards } from "../components/template-cards.jsx";
import { useDeleteReport, useDownloadReport, useReportsList } from "../hooks/use-reporting.js";

/** T-39 Reports: the template cards and the generated-reports table (polled every 5 s while a row is queued or running). */
export function ReportsPage() {
  const { workspaceId } = useParams();
  const can = useCan();
  const active = useActiveWorkspace();
  const { me } = useSession();
  const [searchParams, setSearchParams] = useSearchParams();
  const canExport = can("report.export");
  const status = REPORT_STATUSES.includes(searchParams.get("status") ?? "")
    ? searchParams.get("status")
    : "";
  const template = TEMPLATE_FILTER_OPTIONS.some((o) => o.value === searchParams.get("template"))
    ? searchParams.get("template")
    : "";
  const mine = searchParams.get("mine") === "1";
  const openId = searchParams.get("report") ?? "";

  const setParam = (changes) =>
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        for (const [k, v] of Object.entries(changes)) v ? next.set(k, v) : next.delete(k);
        return next;
      },
      { replace: true },
    );

  const list = useReportsList(workspaceId, { status });
  const rows = useMemo(
    () =>
      (list.data?.items ?? []).filter(
        (r) =>
          (!template || r.template === template) && (!mine || r.requestedBy.id === me?.user?.id),
      ),
    [list.data, template, mine, me],
  );
  const download = useDownloadReport();
  const remove = useDeleteReport(workspaceId);
  const [dialog, setDialog] = useState(null); // { template?, initial?, lock }
  const [toDelete, setToDelete] = useState(null);
  const canDelete = (report) => report.requestedBy.id === me?.user?.id || canExport;
  const filtered = Boolean(status || template || mine);

  return (
    <AppPageLayout
      title="Reports"
      description={
        canExport
          ? active?.name
          : "You can see reports that were generated. Ask a lead or manager to generate new ones."
      }
      actions={
        canExport ? (
          <Button onClick={() => setDialog({ key: "any", lock: false, initial: {} })}>
            Generate report
          </Button>
        ) : null
      }
    >
      <section aria-labelledby="templates-heading" className="mb-8">
        <h2 id="templates-heading" className="mb-3 text-sm font-semibold">
          Report templates
        </h2>
        <TemplateCards
          canExport={canExport}
          onGenerate={(id) => setDialog({ key: id, lock: true, initial: { template: id } })}
        />
      </section>

      <section aria-labelledby="generated-heading">
        <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
          <h2 id="generated-heading" className="text-sm font-semibold">
            Generated reports
          </h2>
          <div className="flex flex-wrap items-end gap-3">
            <div className="w-52 space-y-1">
              <Label className="text-xs">Template</Label>
              <Select
                aria-label="Filter by template"
                value={template}
                onChange={(e) => setParam({ template: e.target.value })}
                placeholder="All templates"
              >
                <option value="">All templates</option>
                {TEMPLATE_FILTER_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
            </div>
            <div className="w-40 space-y-1">
              <Label className="text-xs">Status</Label>
              <Select
                aria-label="Filter by status"
                value={status}
                onChange={(e) => setParam({ status: e.target.value })}
                placeholder="All statuses"
              >
                <option value="">All statuses</option>
                {REPORT_STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {REPORT_STATUS_LABELS[s]}
                  </option>
                ))}
              </Select>
            </div>
            <div className="flex h-8 items-center gap-2">
              <Switch
                id="mine"
                checked={mine}
                onCheckedChange={(on) => setParam({ mine: on ? "1" : "" })}
              />
              <Label htmlFor="mine" className="text-sm">
                Mine
              </Label>
            </div>
          </div>
        </div>
        <ReportsTable
          list={list}
          rows={rows}
          workspaceName={active?.name}
          onOpen={(id) => setParam({ report: id })}
          onDownload={(id) => download.mutate(id)}
          downloadingId={download.isPending ? download.variables : null}
          canDelete={canDelete}
          onDelete={setToDelete}
          emptyState={
            <EmptyState
              icon={FileText}
              title={filtered ? "No reports match" : "No reports yet"}
              description={
                filtered
                  ? "Change or clear the filters."
                  : canExport
                    ? "Generate one from a template above."
                    : "Reports that your team generates appear here."
              }
            />
          }
        />
      </section>

      {dialog ? (
        <GenerateReportDialog
          key={dialog.key}
          open
          onOpenChange={(open) => !open && setDialog(null)}
          workspaceId={workspaceId}
          lockTemplate={dialog.lock}
          initial={dialog.initial}
        />
      ) : null}
      <ReportDetailsSheet
        workspaceId={workspaceId}
        workspaceName={active?.name}
        reportId={openId || null}
        onClose={() => setParam({ report: "" })}
        onDownload={(id) => download.mutate(id)}
        downloading={download.isPending}
        canDelete={canDelete}
        canExport={canExport}
        onDelete={setToDelete}
        onAgain={(r) => {
          setParam({ report: "" });
          setDialog({
            key: `again-${r.id}`,
            lock: true,
            initial: {
              template: r.template,
              format: r.format,
              asOfDay: r.asOfDay ?? undefined,
              period: r.period ?? undefined,
            },
          });
        }}
      />
      <ConfirmDialog
        open={Boolean(toDelete)}
        onOpenChange={(open) => !open && setToDelete(null)}
        title="Delete this report?"
        description="The file is removed. You can generate the report again."
        confirmLabel="Delete report"
        destructive
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() =>
          remove.mutate(toDelete.id, {
            onSuccess: () => {
              if (openId === toDelete.id) setParam({ report: "" });
              setToDelete(null);
            },
          })
        }
      />
    </AppPageLayout>
  );
}
