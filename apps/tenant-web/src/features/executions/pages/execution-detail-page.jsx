import { useQueryClient } from "@tanstack/react-query";
import { AppPageLayout } from "@qmentisai/ui";
import { ChevronRight } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { TabsContent, Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs.jsx";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import {
  executionStatus,
  isActiveStatus,
  isTerminalStatus,
  reasonText,
} from "../constants/index.js";
import {
  CancelDialog,
  ExecutionHeaderActions,
  RetryDialog,
} from "../components/execution-actions.jsx";
import {
  ExecutionId,
  ExecutionStatusChip,
  CommitSha,
  UntrustedForkBadge,
  triggerText,
} from "../components/execution-bits.jsx";
import { AnalysisCard } from "../components/analysis-card.jsx";
import { ExecutionFacts, Notices } from "../components/execution-facts.jsx";
import { EventsTab } from "../components/events-tab.jsx";
import { LiveIndicator } from "../components/live-indicator.jsx";
import { LogPanel } from "../components/log-panel.jsx";
import { StageTimeline } from "../components/stage-timeline.jsx";
import { TaskCards } from "../components/task-cards.jsx";
import { executionKeys, useExecution } from "../hooks/use-executions.js";
import { useRealtime } from "../hooks/use-realtime.js";
import { useExecutionUiStore } from "../stores/execution-ui-store.js";

const TABS = ["logs", "events"];
const ANNOUNCE_GAP_MS = 2000;

function DetailSkeleton() {
  return (
    <div role="status" aria-busy="true" className="space-y-4">
      <span className="sr-only">Loading execution…</span>
      <Skeleton className="h-6 w-80" />
      <Skeleton className="h-16 w-full" />
      <div className="grid grid-cols-1 gap-3 min-[1280px]:grid-cols-2 min-[1440px]:grid-cols-4">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-28" />
        ))}
      </div>
      <Skeleton className="h-64 w-full" />
    </div>
  );
}

/** Polite, throttled announcement of status changes only (never log lines). */
function useStatusAnnouncement(status) {
  const [message, setMessage] = useState("");
  const previous = useRef(status);
  const last = useRef(0);
  useEffect(() => {
    if (previous.current === status) return undefined;
    previous.current = status;
    const label = executionStatus(status).label;
    const text = isTerminalStatus(status)
      ? `Execution finished: ${label}`
      : `Execution status: ${label}`;
    const wait = Math.max(0, ANNOUNCE_GAP_MS - (Date.now() - last.current));
    const timer = setTimeout(() => {
      last.current = Date.now();
      setMessage(text);
    }, wait);
    return () => clearTimeout(timer);
  }, [status]);
  return message;
}

function Description({ execution: e, live, updatedAt }) {
  const can = useCan();
  const scope = { type: "workspace", workspaceId: e.workspaceId };
  return (
    <span className="block space-y-1">
      <span className="flex flex-wrap items-center gap-2">
        <ExecutionId id={e.id} />
        <ExecutionStatusChip execution={e} />
        {e.trust === "untrusted_fork" ? <UntrustedForkBadge /> : null}
        <LiveIndicator
          state={live}
          variant="detail"
          lastUpdate={updatedAt}
          hidden={isTerminalStatus(e.status)}
        />
      </span>
      <span className="flex flex-wrap items-center gap-x-1.5 text-sm">
        {e.pipeline?.name ? (
          can("pipeline.view", scope) ? (
            <Link
              className="underline-offset-2 hover:underline"
              to={`/workspaces/${e.workspaceId}/pipelines/${e.pipeline.id}`}
            >
              {e.pipeline.name}
            </Link>
          ) : (
            e.pipeline.name
          )
        ) : null}
        {e.repository?.fullName ? (
          <>
            on <span className="font-mono text-xs">{e.repository.fullName}</span>
          </>
        ) : null}
        {e.refName ? (
          <>
            · <span className="font-mono text-xs">{e.refName}</span>
          </>
        ) : null}
        {e.commitSha ? (
          <>
            · <CommitSha sha={e.commitSha} />
          </>
        ) : null}
        · {triggerText(e)}
      </span>
    </span>
  );
}

function Detail({ execution, live, registerRefresh }) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  const [params, setParams] = useSearchParams();
  const tab = TABS.includes(params.get("tab")) ? params.get("tab") : "logs";
  const taskId = params.get("task") ?? "";
  const [cancelOpen, setCancelOpen] = useState(false);
  const [retryOpen, setRetryOpen] = useState(false);
  const reset = useExecutionUiStore((s) => s.reset);
  useEffect(() => {
    reset();
    return reset;
  }, [execution.id, reset]);

  const key = executionKeys.detail(tenantId, execution.workspaceId, execution.id);
  const updatedAt = queryClient.getQueryState(key)?.dataUpdatedAt;
  const announcement = useStatusAnnouncement(execution.status);
  const setTab = (value) =>
    setParams(
      (cur) => {
        const next = new URLSearchParams(cur);
        value === "logs" ? next.delete("tab") : next.set("tab", value);
        if (value !== "logs") next.delete("task");
        return next;
      },
      { replace: true },
    );
  const setTask = (id) =>
    setParams(
      (cur) => {
        const next = new URLSearchParams(cur);
        id ? next.set("task", id) : next.delete("task");
        return next;
      },
      { replace: true },
    );
  const viewLog = (task) => {
    setParams(
      (cur) => {
        const next = new URLSearchParams(cur);
        next.delete("tab");
        next.set("task", task.id);
        return next;
      },
      { replace: true },
    );
  };

  const e = execution;
  const noScans = e.status === "blocked" || e.status === "skipped";
  return (
    <AppPageLayout
      title="Execution"
      breadcrumb={
        <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-muted-foreground">
          <Link
            className="underline-offset-2 hover:underline"
            to={`/workspaces/${e.workspaceId}/executions`}
          >
            Executions
          </Link>
          <ChevronRight aria-hidden="true" className="size-3.5" />
          <span aria-current="page" className="font-mono text-xs text-foreground">
            {e.id.slice(0, 8)}
          </span>
        </nav>
      }
      description={
        <Description
          execution={e}
          live={live}
          updatedAt={updatedAt ? new Date(updatedAt).toISOString() : null}
        />
      }
      actions={
        <ExecutionHeaderActions
          execution={e}
          onCancel={() => setCancelOpen(true)}
          onRetry={() => setRetryOpen(true)}
        />
      }
    >
      <div className="sr-only" role="status" aria-live="polite">
        {announcement}
      </div>
      <Notices execution={e} />
      {noScans ? (
        <p className="mb-4 rounded-md border border-border-strong bg-secondary p-3 text-sm">
          {reasonText(e.statusReason, e.status) ?? executionStatus(e.status).label}
        </p>
      ) : (
        <div className="mb-4 grid gap-4 min-[1440px]:grid-cols-[minmax(0,1fr)_minmax(0,24rem)]">
          <div className="min-w-0 space-y-4">
            <StageTimeline execution={e} />
            <AnalysisCard execution={e} />
            <TaskCards tasks={e.tasks} onViewLog={viewLog} />
          </div>
          <ExecutionFacts execution={e} />
        </div>
      )}
      {noScans ? <ExecutionFacts execution={e} /> : null}
      <Tabs value={tab} onValueChange={setTab} className="mt-4">
        <TabsList>
          <TabsTrigger value="logs">Logs</TabsTrigger>
          <TabsTrigger value="events">Events</TabsTrigger>
        </TabsList>
        <TabsContent value="logs" className="flex h-[min(32rem,70vh)] flex-col">
          <LogPanel
            workspaceId={e.workspaceId}
            execution={e}
            taskId={taskId}
            onTaskChange={setTask}
            visible={tab === "logs"}
            live={live.live}
            registerRefresh={registerRefresh}
          />
        </TabsContent>
        <TabsContent value="events">
          <EventsTab
            workspaceId={e.workspaceId}
            executionId={e.id}
            enabled={tab === "events"}
            live={live.live}
            decision={e.decision ?? null}
          />
        </TabsContent>
      </Tabs>
      <CancelDialog execution={e} open={cancelOpen} onOpenChange={setCancelOpen} />
      <RetryDialog execution={e} open={retryOpen} onOpenChange={setRetryOpen} />
    </AppPageLayout>
  );
}

/**
 * T-29 Execution detail (live). The execution must belong to the workspace in the URL; otherwise (and for a hidden, other-
 * tenant or missing one) it is the same not-found page. Permission (`execution.view`) comes from the route guard.
 */
export function ExecutionDetailPage() {
  const { workspaceId, executionId } = useParams();
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  const refreshLogs = useRef(null);
  const registerRefresh = useCallback((fn) => {
    refreshLogs.current = fn;
  }, []);
  const key = executionKeys.detail(tenantId, workspaceId, executionId);
  // read the cache (not the query) so the subscription can start before, and decide, the polling rhythm of the query below
  const cachedStatus = queryClient.getQueryData(key)?.status;
  const active = !cachedStatus || isActiveStatus(cachedStatus); // a terminal execution stops all live work
  const live = useRealtime({
    scope: "execution",
    id: executionId,
    enabled: active,
    onHint: (name, hint) => {
      const cached = queryClient.getQueryData(key);
      if (name === "execution.changed") {
        if (cached && hint.rev <= cached.rev) return; // older or duplicate hint: ignored
        queryClient.invalidateQueries({ queryKey: key, exact: true });
        queryClient.invalidateQueries({
          queryKey: executionKeys.events(tenantId, workspaceId, executionId),
        });
      } else if (name === "execution.decision") {
        // the decision was recorded: read it (and the new history rows) through the API; the hint carries no decision data
        queryClient.invalidateQueries({ queryKey: key, exact: true });
        queryClient.invalidateQueries({
          queryKey: executionKeys.events(tenantId, workspaceId, executionId),
        });
      } else if (name === "task.changed") {
        if (cached && hint.rev !== undefined && hint.rev < cached.rev) return;
        queryClient.invalidateQueries({ queryKey: key, exact: true });
      } else if (name === "log.appended") refreshLogs.current?.();
    },
  });
  const query = useExecution(workspaceId, executionId, { live: live.live });
  const status = query.data?.status;

  // on the way to a terminal status: one final full refetch (detail, history, the log tail), then nothing live
  const wasActive = useRef(true);
  useEffect(() => {
    if (!status) return;
    const nowActive = isActiveStatus(status);
    if (wasActive.current && !nowActive) {
      queryClient.invalidateQueries({
        queryKey: executionKeys.all(tenantId, workspaceId),
        refetchType: "active",
      });
      refreshLogs.current?.();
    }
    wasActive.current = nowActive;
  }, [status, queryClient, tenantId, workspaceId]);

  if (query.isPending)
    return (
      <AppPageLayout title="Execution" scroll={false}>
        <DetailSkeleton />
      </AppPageLayout>
    );
  if (query.isError) return <QueryErrorState error={query.error} onRetry={query.refetch} />;
  if (query.data.workspaceId !== workspaceId) return <NotFoundState />;
  return (
    <Detail
      key={query.data.id}
      execution={query.data}
      live={live}
      registerRefresh={registerRefresh}
    />
  );
}
