import { useState } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { Switch } from "@/components/ui/switch.jsx";
import { FlaskConical } from "lucide-react";
import { TRIGGER_ICONS, TRIGGER_LABELS } from "../constants/index.js";
import { usePipelineAccess } from "../hooks/use-pipeline-access.js";
import { usePipelineVersion, usePublishConfig } from "../hooks/use-pipelines.js";
import { newIdempotencyKey } from "../services/pipelines-service.js";
import { actionMessage } from "./pipeline-actions.jsx";
import { DryRunDialog } from "./dry-run-dialog.jsx";
import { TimeAgo, absoluteTime } from "@/features/executions/components/execution-bits.jsx";
import { TriggerDetails } from "./config-view.jsx";

/**
 * Triggers tab of T-27: one card per trigger of the current version. The switch needs `pipeline.manage`; changing it
 * publishes a NEW version (the dialog says so). Schedules show the next planned fire time the API returned.
 */
export function TriggersTab({ pipeline }) {
  const access = usePipelineAccess(pipeline);
  const version = usePipelineVersion(pipeline.id, pipeline.currentVersion?.version);
  const publish = usePublishConfig();
  const [pending, setPending] = useState(null);
  const [testing, setTesting] = useState(false);
  if (version.isPending) return <LoadingState rows={3} label="Loading triggers" />;
  if (version.isError) return <QueryErrorState error={version.error} onRetry={version.refetch} />;
  const config = version.data.config;
  const nextRun = (key) => pipeline.triggers.find((t) => t.key === key)?.nextRunAt;
  const confirm = () => {
    const next = structuredClone(config);
    next.triggers = next.triggers.map((t) =>
      t.key === pending.key ? { ...t, enabled: !t.enabled } : t,
    );
    publish.mutate(
      {
        pipelineId: pipeline.id,
        body: {
          expectedVersion: version.data.version,
          config: next,
          changeNote: `${pending.enabled ? "Turned off" : "Turned on"} the ${pending.key} trigger`,
        },
        idempotencyKey: newIdempotencyKey(),
      },
      {
        onSuccess: (published) => {
          setPending(null);
          toast.success(`Published version ${published.version}`);
        },
      },
    );
  };
  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button variant="secondary" onClick={() => setTesting(true)} disabled={access.deleted}>
          <FlaskConical aria-hidden="true" /> Test triggers
        </Button>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        {config.triggers.map((t) => {
          const Icon = TRIGGER_ICONS[t.type];
          const next = t.type === "schedule" ? nextRun(t.key) : null;
          return (
            <Card key={t.key}>
              <CardHeader className="flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Icon aria-hidden="true" className="size-4 text-muted-foreground" />
                  {TRIGGER_LABELS[t.type]}
                  <span className="font-mono text-xs font-normal text-muted-foreground">
                    {t.key}
                  </span>
                </CardTitle>
                {access.canManage ? (
                  <Switch
                    aria-label={`${TRIGGER_LABELS[t.type]} trigger ${t.key} enabled`}
                    checked={t.enabled}
                    onCheckedChange={() => {
                      publish.reset();
                      setPending(t);
                    }}
                  />
                ) : (
                  <span className="text-xs text-muted-foreground">{t.enabled ? "On" : "Off"}</span>
                )}
              </CardHeader>
              <CardContent>
                <TriggerDetails trigger={t} />
                {t.type === "schedule" ? (
                  <p className="mt-2 text-sm">
                    Next run:{" "}
                    {next ? (
                      <>
                        <span title={`UTC ${new Date(next).toISOString()}`}>
                          {absoluteTime(next, {
                            dateStyle: "medium",
                            timeStyle: "short",
                            timeZoneName: "short",
                          })}
                        </span>{" "}
                        (<TimeAgo value={next} />)
                      </>
                    ) : (
                      <span className="text-muted-foreground">
                        not scheduled (the pipeline or trigger is off, or it is stopped)
                      </span>
                    )}
                  </p>
                ) : null}
              </CardContent>
            </Card>
          );
        })}
      </div>
      <ConfirmDialog
        open={Boolean(pending)}
        onOpenChange={(open) => !open && setPending(null)}
        title={pending?.enabled ? "Turn this trigger off?" : "Turn this trigger on?"}
        description="This publishes a new configuration version. Requests already made keep the version they were made with."
        confirmLabel="Publish new version"
        pending={publish.isPending}
        error={publish.error}
        errorText={publish.error ? actionMessage(publish.error) : undefined}
        onConfirm={confirm}
      />
      <DryRunDialog pipeline={pipeline} open={testing} onOpenChange={setTesting} />
    </div>
  );
}
