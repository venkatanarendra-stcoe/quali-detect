import { Combobox } from "@qmentisai/ui";
import { ArrowDownToLine, CircleAlert, Info, TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef } from "react";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { LOG_LEVELS, TASK_TITLES, isActiveStatus } from "../constants/index.js";
import { useExecutionLogs } from "../hooks/use-executions.js";
import { useExecutionUiStore } from "../stores/execution-ui-store.js";

const NEAR_BOTTOM_PX = 24;
const LEVEL_OPTIONS = LOG_LEVELS.map((value) => ({ value, label: value }));
const time = (value) =>
  new Date(value).toLocaleTimeString(undefined, {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
  });

function LevelCell({ level }) {
  const Icon =
    level === "error"
      ? CircleAlert
      : level === "warn"
        ? TriangleAlert
        : level === "info"
          ? Info
          : null;
  const emphasis =
    level === "error"
      ? "font-semibold text-status-danger"
      : level === "warn"
        ? "font-semibold text-status-warning"
        : "text-muted-foreground";
  return (
    <span className={`inline-flex w-14 items-center gap-1 ${emphasis}`}>
      {Icon ? (
        <Icon aria-hidden="true" className="size-3 shrink-0" />
      ) : (
        <span className="size-3 shrink-0" />
      )}
      {level}
    </span>
  );
}

function sourceTag(line, tasks) {
  const task = line.taskId ? tasks.find((t) => t.id === line.taskId) : null;
  return task ? (TASK_TITLES[task.scanType] ?? task.scanType) : line.source;
}

/**
 * Logs tab of T-29: a themed mono panel (follows the app theme, NOT an always-dark terminal). Newest 200 lines first, "Load
 * earlier" for older ones, then live lines via `afterSeq`. `role="log"` with `aria-live="off"`: log lines are never announced.
 * Follow is on by default while the execution is active; scrolling up turns it off and offers "Jump to latest". Messages are
 * escaped text (React text nodes) and redacted at write time (`[REDACTED]`).
 * @param {{ workspaceId: string, execution: { id: string, status: string, tasks: any[] }, taskId: string, onTaskChange: (id: string) => void,
 *   visible: boolean, live: boolean, registerRefresh: (fn: (() => void) | null) => void }} props
 */
export function LogPanel({
  workspaceId,
  execution,
  taskId,
  onTaskChange,
  visible,
  live,
  registerRefresh,
}) {
  const active = isActiveStatus(execution.status);
  const followChoice = useExecutionUiStore((s) => s.follow);
  const setFollow = useExecutionUiStore((s) => s.setFollow);
  const level = useExecutionUiStore((s) => s.level);
  const setLevel = useExecutionUiStore((s) => s.setLevel);
  const follow = followChoice ?? active;
  const filters = useMemo(
    () => ({ ...(taskId ? { taskId } : {}), ...(level ? { level } : {}) }),
    [taskId, level],
  );
  const logs = useExecutionLogs({
    workspaceId,
    executionId: execution.id,
    filters,
    tailEnabled: visible && (active || follow),
    active,
    live,
  });
  const { refreshTail } = logs;
  useEffect(() => {
    registerRefresh(refreshTail);
    return () => registerRefresh(null);
  }, [registerRefresh, refreshTail]);

  const scroller = useRef(null);
  const scrollToEnd = useCallback(() => {
    const el = scroller.current;
    // "instant": the panel's `scroll-behavior: smooth` would otherwise fire scroll events mid-way and switch Follow off
    el?.scrollTo({ top: el.scrollHeight, behavior: "instant" });
  }, []);
  const lineCount = logs.lines.length;
  useLayoutEffect(() => {
    if (follow && visible) scrollToEnd();
  }, [lineCount, follow, visible, scrollToEnd]);
  const onScroll = () => {
    const el = scroller.current;
    if (!el) return;
    const atEnd = el.scrollHeight - el.scrollTop - el.clientHeight <= NEAR_BOTTOM_PX;
    if (!atEnd && follow) setFollow(false);
  };
  const jumpToLatest = () => {
    setFollow(true);
    scrollToEnd();
  };

  const taskOptions = execution.tasks.map((t) => ({
    value: t.id,
    label: TASK_TITLES[t.scanType] ?? t.scanType,
  }));
  const empty = lineCount === 0 && !logs.isPending && !logs.isError;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex flex-wrap items-end gap-3">
        <div className="w-44">
          <span id="log-task-l" className="mb-1 block text-xs text-muted-foreground">
            Scan
          </span>
          <Combobox
            aria-labelledby="log-task-l"
            options={taskOptions}
            value={taskId || null}
            onChange={(value) => onTaskChange(value ?? "")}
            placeholder="All scans"
            searchable={false}
            clearable
          />
        </div>
        <div className="w-36">
          <span id="log-level-l" className="mb-1 block text-xs text-muted-foreground">
            Level
          </span>
          <Combobox
            aria-labelledby="log-level-l"
            options={LEVEL_OPTIONS}
            value={level || null}
            onChange={(value) => setLevel(value ?? "")}
            placeholder="All levels"
            searchable={false}
            clearable
          />
        </div>
        <Button
          variant={follow ? "secondary" : "outline"}
          aria-pressed={follow}
          onClick={() => (follow ? setFollow(false) : jumpToLatest())}
        >
          <ArrowDownToLine aria-hidden="true" />
          Follow
        </Button>
        {!follow && lineCount > 0 ? (
          <Button variant="ghost" onClick={jumpToLatest}>
            Jump to latest
          </Button>
        ) : null}
      </div>
      {/* A scrollable log region must be keyboard focusable (WCAG 2.1.1) and handles End to jump to the latest line. */}
      {/* eslint-disable jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/no-noninteractive-tabindex */}
      <div
        ref={scroller}
        role="log"
        aria-live="off"
        aria-label="Execution log"
        tabIndex={0}
        onScroll={onScroll}
        onKeyDown={(event) => {
          if (event.key === "End") {
            event.preventDefault();
            jumpToLatest();
          }
        }}
        className="qm-scroll min-h-48 flex-1 overflow-auto rounded-md border border-border bg-card p-3 font-mono text-xs leading-5 text-card-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {logs.isPending ? (
          <div aria-busy="true" className="space-y-2">
            <span className="sr-only">Loading log…</span>
            {Array.from({ length: 8 }, (_, i) => (
              <Skeleton key={i} className="h-4 w-full" />
            ))}
          </div>
        ) : logs.isError ? (
          <QueryErrorState error={logs.error} onRetry={logs.refetch} />
        ) : empty ? (
          <p className="font-sans text-sm text-muted-foreground">
            {["queued", "preparing"].includes(execution.status)
              ? "No log lines yet."
              : "No log lines were recorded."}
          </p>
        ) : (
          <>
            {logs.hasEarlier ? (
              <div className="mb-2 font-sans">
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={logs.loadingEarlier}
                  onClick={logs.loadEarlier}
                >
                  {logs.loadingEarlier ? "Loading…" : "Load earlier"}
                </Button>
              </div>
            ) : null}
            {logs.truncated ? (
              <p className="mb-2 font-sans text-muted-foreground">Log truncated at 20,000 lines.</p>
            ) : null}
            <ol>
              {logs.lines.map((line) => (
                <li key={line.seq} className="flex gap-3">
                  <time dateTime={line.at} className="shrink-0 text-muted-foreground">
                    {time(line.at)}
                  </time>
                  <LevelCell level={line.level} />
                  <span
                    className="w-20 shrink-0 truncate text-muted-foreground"
                    title={sourceTag(line, execution.tasks)}
                  >
                    {sourceTag(line, execution.tasks)}
                  </span>
                  <span className="min-w-0 whitespace-pre-wrap break-words">{line.message}</span>
                </li>
              ))}
            </ol>
          </>
        )}
      </div>
      {/* eslint-enable jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/no-noninteractive-tabindex */}
    </div>
  );
}
