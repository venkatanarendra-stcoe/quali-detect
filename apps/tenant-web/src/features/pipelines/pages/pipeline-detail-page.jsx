import { Copy, FlaskConical, MoreHorizontal, Pencil, Play, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { LinkButton } from "@/components/common/link-button.jsx";
import { PageHeader } from "@/components/common/page-header.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import { UnauthorizedState } from "@/components/states/unauthorized-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.jsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { ConfigurationTab } from "../components/configuration-tab.jsx";
import { DryRunDialog } from "../components/dry-run-dialog.jsx";
import { ExecutionsTab } from "../components/executions-tab.jsx";
import { DeletePipelineDialog, PipelineEnabledSwitch } from "../components/pipeline-actions.jsx";
import {
  EffectiveStateChip,
  Identifier,
  LastRequest,
  TimeAgo,
  absoluteTime,
} from "../components/pipeline-bits.jsx";
import { RunDialog } from "../components/run-dialog.jsx";
import { TriggersTab } from "../components/triggers-tab.jsx";
import { EFFECTIVE_STATES } from "../constants/index.js";
import { usePipelineAccess } from "../hooks/use-pipeline-access.js";
import { usePipeline } from "../hooks/use-pipelines.js";

const TABS = ["overview", "executions", "configuration", "triggers"];

function Overview({ pipeline }) {
  const can = useCan();
  const next = pipeline.triggers
    .filter((t) => t.type === "schedule" && t.nextRunAt)
    .map((t) => t.nextRunAt)
    .sort()[0];
  return (
    <Card>
      <CardHeader>
        <CardTitle>Overview</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
          <div className="sm:col-span-2">
            <dt className="text-muted-foreground">Description</dt>
            <dd className="break-words">{pipeline.description ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Repository</dt>
            <dd>
              {pipeline.repository.name ? (
                can("repository.view", { type: "workspace", workspaceId: pipeline.workspaceId }) ? (
                  <Link
                    className="font-mono text-xs underline-offset-2 hover:underline"
                    to={`/workspaces/${pipeline.workspaceId}/repositories/${pipeline.repositoryId}`}
                  >
                    {pipeline.repository.name}
                  </Link>
                ) : (
                  <span className="font-mono text-xs">{pipeline.repository.name}</span>
                )
              ) : (
                "Not shown"
              )}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">State</dt>
            <dd>
              <EffectiveStateChip state={pipeline.effectiveState} />
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Current version</dt>
            <dd>
              {pipeline.currentVersion ? (
                <span className="inline-flex flex-wrap items-center gap-2">
                  {pipeline.currentVersion.version}
                  <Identifier
                    value={pipeline.currentVersion.configHash}
                    max={6}
                    copy
                    label="configuration hash"
                  />
                </span>
              ) : (
                "—"
              )}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Next scheduled run</dt>
            <dd>
              {next ? (
                <span title={`UTC ${new Date(next).toISOString()}`}>
                  {absoluteTime(next, {
                    dateStyle: "medium",
                    timeStyle: "short",
                    timeZoneName: "short",
                  })}
                </span>
              ) : (
                "None scheduled"
              )}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Last request</dt>
            <dd>
              <LastRequest lastRequest={pipeline.lastRequest} />
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Skipped by policy (last 24 hours)</dt>
            <dd>{pipeline.counters?.skippedByPolicyLast24h ?? 0}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Created</dt>
            <dd>
              <TimeAgo value={pipeline.createdAt} />
            </dd>
          </div>
        </dl>
      </CardContent>
    </Card>
  );
}

function Detail({ pipeline }) {
  const navigate = useNavigate();
  const access = usePipelineAccess(pipeline);
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab");
  const tab = TABS.includes(requested) ? requested : "overview";
  const [running, setRunning] = useState(false);
  const [testing, setTesting] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const base = `/workspaces/${pipeline.workspaceId}/pipelines`;
  const state = EFFECTIVE_STATES[pipeline.effectiveState];
  // One primary (mint) action: Edit for managers, Run now for roles that can run but not manage.
  const runIsPrimary = !access.canManage && access.canRunPermission && !access.runReason;
  const run = access.showRun ? (
    <DisabledWithReason reason={access.runReason}>
      <Button variant={runIsPrimary ? "default" : "secondary"} onClick={() => setRunning(true)}>
        <Play aria-hidden="true" />
        Run now
      </Button>
    </DisabledWithReason>
  ) : null;
  return (
    <>
      <PageHeader
        title={pipeline.name}
        description={
          pipeline.repository.name ? (
            <span className="font-mono text-xs">{pipeline.repository.name}</span>
          ) : undefined
        }
        actions={
          <>
            <EffectiveStateChip state={pipeline.effectiveState} />
            <PipelineEnabledSwitch pipeline={pipeline} />
            {run}
            {access.canManage ? (
              <LinkButton to={`${base}/${pipeline.id}/edit`}>
                <Pencil aria-hidden="true" />
                Edit
              </LinkButton>
            ) : null}
            {!access.deleted ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="icon" aria-label="More actions">
                    <MoreHorizontal aria-hidden="true" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-48">
                  {access.canManage ? (
                    <DropdownMenuItem
                      onSelect={() =>
                        navigate(
                          `${base}/new?repository=${pipeline.repositoryId}&copy=${pipeline.id}`,
                        )
                      }
                    >
                      <Copy aria-hidden="true" /> Duplicate
                    </DropdownMenuItem>
                  ) : null}
                  <DropdownMenuItem onSelect={() => setTesting(true)}>
                    <FlaskConical aria-hidden="true" /> Test triggers
                  </DropdownMenuItem>
                  {access.canDelete ? (
                    <DropdownMenuItem onSelect={() => setDeleting(true)}>
                      <Trash2 aria-hidden="true" /> Delete…
                    </DropdownMenuItem>
                  ) : null}
                </DropdownMenuContent>
              </DropdownMenu>
            ) : null}
          </>
        }
      />
      {access.deleted ? (
        <p
          role="status"
          className="mb-4 rounded-md border border-border-strong bg-secondary p-3 text-sm"
        >
          Deleted on {absoluteTime(pipeline.deletedAt)}. History and findings are kept; this view is
          read only.
        </p>
      ) : state.reason ? (
        <p
          role="status"
          className="mb-4 rounded-md border border-border-strong bg-secondary p-3 text-sm"
        >
          {state.reason}
        </p>
      ) : null}
      <p className="mb-4 text-sm text-muted-foreground">
        Findings in this pipeline have their own identity and lifecycle, independent of other
        pipelines.
      </p>
      <Tabs
        value={tab}
        onValueChange={(value) =>
          setParams(value === "overview" ? {} : { tab: value }, { replace: true })
        }
      >
        <TabsList className="max-w-full overflow-x-auto">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="executions">Executions</TabsTrigger>
          <TabsTrigger value="configuration">Configuration</TabsTrigger>
          <TabsTrigger value="triggers">Triggers</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <Overview pipeline={pipeline} />
        </TabsContent>
        <TabsContent value="executions">
          {access.canViewExecutions ? (
            <ExecutionsTab pipelineId={pipeline.id} />
          ) : (
            <UnauthorizedState />
          )}
        </TabsContent>
        <TabsContent value="configuration">
          <ConfigurationTab pipeline={pipeline} />
        </TabsContent>
        <TabsContent value="triggers">
          {access.deleted ? (
            <p className="text-sm text-muted-foreground">
              A deleted pipeline has no active triggers.
            </p>
          ) : (
            <TriggersTab pipeline={pipeline} />
          )}
        </TabsContent>
      </Tabs>
      <RunDialog pipeline={pipeline} open={running} onOpenChange={setRunning} />
      <DryRunDialog pipeline={pipeline} open={testing} onOpenChange={setTesting} />
      <DeletePipelineDialog
        pipeline={pipeline}
        open={deleting}
        onOpenChange={setDeleting}
        onDone={() => navigate(base)}
      />
    </>
  );
}

/**
 * T-27 Pipeline detail. The pipeline must belong to the workspace in the URL; otherwise it is the same not-found page as
 * a missing one. Findings and Activity tabs are not rendered until their data exists (no workspace activity API yet).
 */
export function PipelineDetailPage() {
  const { workspaceId, pipelineId } = useParams();
  const query = usePipeline(pipelineId);
  if (query.isPending) return <LoadingState label="Loading pipeline" />;
  if (query.isError) return <QueryErrorState error={query.error} onRetry={query.refetch} />;
  if (query.data.workspaceId !== workspaceId) return <NotFoundState />;
  return <Detail pipeline={query.data} />;
}
