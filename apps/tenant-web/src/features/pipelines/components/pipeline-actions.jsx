import {
  Copy,
  MoreHorizontal,
  Pencil,
  Play,
  Trash2,
  FlaskConical,
  ExternalLink,
} from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.jsx";
import { Switch } from "@/components/ui/switch.jsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import { describeError } from "@/lib/api/index.js";
import { CONFLICT_MESSAGES } from "../constants/index.js";
import { useDeletePipeline, useSetPipelineEnabled } from "../hooks/use-pipelines.js";
import { usePipelineAccess } from "../hooks/use-pipeline-access.js";
import { RunDialog } from "./run-dialog.jsx";
import { DryRunDialog } from "./dry-run-dialog.jsx";

/** Message for a failed pipeline action: the stable `details.reason` in plain words, else the server's client-safe text. */
export function actionMessage(error) {
  const reason = error?.details?.reason;
  return (reason && CONFLICT_MESSAGES[reason]) || describeError(error);
}

/**
 * Enabled switch. Without `pipeline.manage` it stays visible, read only, with the reason as a tooltip. A pipeline that is
 * incomplete (no scan or no trigger) is refused by the API (`pipeline_incomplete`) and the message is shown.
 */
export function PipelineEnabledSwitch({ pipeline }) {
  const access = usePipelineAccess(pipeline);
  const set = useSetPipelineEnabled();
  if (access.deleted) return <span className="text-muted-foreground">—</span>;
  const label = `Enabled: ${pipeline.name}`;
  if (!access.canManage)
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            tabIndex={0}
            role="switch"
            aria-checked={pipeline.enabled}
            aria-disabled="true"
            aria-label={`${label}. You don't have permission to change this.`}
            className="inline-flex rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <Switch checked={pipeline.enabled} disabled aria-hidden="true" tabIndex={-1} />
          </span>
        </TooltipTrigger>
        <TooltipContent>
          You don&apos;t have permission to enable or disable pipelines.
        </TooltipContent>
      </Tooltip>
    );
  return (
    <Switch
      aria-label={label}
      checked={pipeline.enabled}
      disabled={set.isPending}
      onCheckedChange={(enabled) =>
        set.mutate(
          { pipelineId: pipeline.id, enabled },
          {
            onSuccess: () => toast.success(enabled ? "Pipeline enabled" : "Pipeline disabled"),
            onError: (error) => toast.error(actionMessage(error)),
          },
        )
      }
    />
  );
}

/** Typed-name delete dialog (history and findings are kept, queued requests are cancelled). */
export function DeletePipelineDialog({ pipeline, open, onOpenChange, onDone }) {
  const del = useDeletePipeline();
  const blocked = del.error?.details?.reason === "has_active_executions";
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        if (!next) del.reset();
      }}
      title="Delete this pipeline?"
      description="History and findings are kept. Queued requests are cancelled and the pipeline stops firing. This cannot be undone from the interface."
      confirmLabel="Delete pipeline"
      destructive
      confirmText={pipeline.name}
      pending={del.isPending}
      error={del.error}
      errorText={del.error ? actionMessage(del.error) : undefined}
      confirmDisabled={blocked}
      onConfirm={({ confirm }) =>
        del.mutate(
          { pipelineId: pipeline.id, confirm },
          {
            onSuccess: () => {
              onOpenChange(false);
              toast.success("Pipeline deleted");
              onDone?.();
            },
          },
        )
      }
    />
  );
}

function RunItem({ access, onSelect }) {
  return (
    <DropdownMenuItem
      disabled={Boolean(access.runReason)}
      onSelect={onSelect}
      className="flex-col items-start gap-0"
    >
      <span className="flex items-center gap-2">
        <Play aria-hidden="true" /> Run now
      </span>
      {access.runReason ? (
        <span className="pl-6 text-xs font-normal text-muted-foreground">{access.runReason}</span>
      ) : null}
    </DropdownMenuItem>
  );
}

/** Row menu of a pipeline: Run now (disabled with the reason), Open, Edit, Duplicate, Test triggers, Delete. */
export function PipelineRowActions({ pipeline }) {
  const navigate = useNavigate();
  const access = usePipelineAccess(pipeline);
  const [running, setRunning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [testing, setTesting] = useState(false);
  const base = `/workspaces/${pipeline.workspaceId}/pipelines`;
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" aria-label={`Actions for ${pipeline.name}`}>
            <MoreHorizontal aria-hidden="true" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          <DropdownMenuItem onSelect={() => navigate(`${base}/${pipeline.id}`)}>
            <ExternalLink aria-hidden="true" /> Open
          </DropdownMenuItem>
          {access.showRun ? <RunItem access={access} onSelect={() => setRunning(true)} /> : null}
          {access.canManage ? (
            <>
              <DropdownMenuItem onSelect={() => navigate(`${base}/${pipeline.id}/edit`)}>
                <Pencil aria-hidden="true" /> Edit
              </DropdownMenuItem>
              <DropdownMenuItem
                onSelect={() =>
                  navigate(`${base}/new?repository=${pipeline.repositoryId}&copy=${pipeline.id}`)
                }
              >
                <Copy aria-hidden="true" /> Duplicate
              </DropdownMenuItem>
            </>
          ) : null}
          {!access.deleted ? (
            <DropdownMenuItem onSelect={() => setTesting(true)}>
              <FlaskConical aria-hidden="true" /> Test triggers
            </DropdownMenuItem>
          ) : null}
          {access.canDelete ? (
            <DropdownMenuItem onSelect={() => setDeleting(true)}>
              <Trash2 aria-hidden="true" /> Delete…
            </DropdownMenuItem>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      <RunDialog pipeline={pipeline} open={running} onOpenChange={setRunning} />
      <DryRunDialog pipeline={pipeline} open={testing} onOpenChange={setTesting} />
      <DeletePipelineDialog pipeline={pipeline} open={deleting} onOpenChange={setDeleting} />
    </>
  );
}
