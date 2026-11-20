import { ChevronDown, ChevronRight } from "lucide-react";
import { useId, useState } from "react";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import { TASK_ORDER, TASK_TITLES, taskReasonText, taskToggleId } from "../constants/index.js";
import { TaskStatusChip, formatDuration } from "./execution-bits.jsx";
import { SeverityPills } from "./severity-pills.jsx";
import { ToolsSection, ToolsSummaryLine } from "./task-tools.jsx";

function ResultSummary({ result }) {
  return (
    <div className="mt-2 space-y-1.5 text-sm">
      <p>
        {result.itemCount} {result.itemCount === 1 ? "item" : "items"}
      </p>
      <SeverityPills counts={result.severityCounts} label="Items by severity" />
      {result.truncated || result.completeness !== "complete" ? (
        <p className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
          {result.truncated ? <Badge tone="warning">Truncated</Badge> : null}
          Partial results
        </p>
      ) : null}
    </div>
  );
}

function TaskCard({ task, onViewLog }) {
  const [open, setOpen] = useState(false);
  const panel = useId();
  const unsupported = task.status === "unsupported";
  const duration =
    task.startedAt && task.finishedAt ? new Date(task.finishedAt) - new Date(task.startedAt) : null;
  const reason = taskReasonText(task.statusReason);
  return (
    <li className="min-w-0 rounded-md border border-border bg-card text-card-foreground">
      <button
        id={taskToggleId(task.id)}
        type="button"
        aria-expanded={open}
        aria-controls={panel}
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start justify-between gap-2 rounded-md p-3 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <span className="min-w-0 space-y-1.5">
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-semibold">
              {TASK_TITLES[task.scanType] ?? task.scanType}
            </span>
            <TaskStatusChip status={task.status} />
          </span>
          {unsupported ? (
            <span className="block text-sm text-muted-foreground">
              No engine is available for this scan type yet.
            </span>
          ) : (
            <>
              <span className="block font-mono text-xs break-all text-muted-foreground">
                {task.engine.id}
                {task.engine.profile ? ` · ${task.engine.profile}` : ""}
              </span>
              <span className="block text-xs text-muted-foreground">
                {task.attempt > 1 ? `Attempt ${task.attempt} of ${task.maxAttempts}` : null}
                {task.attempt > 1 && duration !== null ? " · " : null}
                {duration !== null ? formatDuration(duration) : null}
              </span>
              <ToolsSummaryLine task={task} />
            </>
          )}
        </span>
        {open ? (
          <ChevronDown
            aria-hidden="true"
            className="mt-0.5 size-4 shrink-0 text-muted-foreground"
          />
        ) : (
          <ChevronRight
            aria-hidden="true"
            className="mt-0.5 size-4 shrink-0 text-muted-foreground"
          />
        )}
      </button>
      <div className="px-3 pb-3">
        {task.status === "running" ? (
          <div role="status">
            {/* indeterminate: the API reports no percentage */}
            <div className="h-1 overflow-hidden rounded-full bg-muted" aria-hidden="true">
              <div className="h-full w-1/3 animate-pulse rounded-full bg-foreground motion-reduce:animate-none" />
            </div>
            <p className="mt-1 text-xs text-muted-foreground">Running</p>
          </div>
        ) : null}
        {task.resultSummary ? <ResultSummary result={task.resultSummary} /> : null}
      </div>
      <div
        id={panel}
        role="region"
        aria-label={`${TASK_TITLES[task.scanType] ?? task.scanType} details`}
        hidden={!open}
        className="border-t border-border p-3 text-sm"
      >
        {open ? (
          <>
            {unsupported ? (
              <p>Reason: {taskReasonText("engine_not_registered")} This is not a failure.</p>
            ) : (
              <>
                <ToolsSection task={task} />
                <p>
                  Attempt {task.attempt} of {task.maxAttempts}
                  {duration !== null ? `, ${formatDuration(duration)}` : ""}
                </p>
                {reason && task.status !== "succeeded" ? <p className="mt-1">{reason}</p> : null}
                <Button variant="link" className="mt-2 h-auto p-0" onClick={() => onViewLog(task)}>
                  View log
                </Button>
              </>
            )}
          </>
        ) : null}
      </div>
    </li>
  );
}

/** One card per enabled scan type, in the order SBOM, SCA, SAST, Secrets: 2 columns at 1280 px, 4 at 1440 px. */
export function TaskCards({ tasks, onViewLog }) {
  const ordered = [...tasks].sort(
    (a, b) => TASK_ORDER.indexOf(a.scanType) - TASK_ORDER.indexOf(b.scanType),
  );
  if (!ordered.length) return null;
  return (
    <section aria-labelledby="tasks-h">
      <h2 id="tasks-h" className="mb-2 text-sm font-semibold">
        Scans
      </h2>
      <ul className="grid grid-cols-1 gap-3 min-[1280px]:grid-cols-2 min-[1440px]:grid-cols-4">
        {ordered.map((task) => (
          <TaskCard key={task.id} task={task} onViewLog={onViewLog} />
        ))}
      </ul>
    </section>
  );
}
