import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";

/**
 * "3/4" plus four small segments. The list DTO carries counts, not per-task statuses, so the segments are drawn from
 * `taskSummary` (succeeded, failed, running, then the rest); the count text and the tooltip carry the meaning, colour never
 * does alone. Hidden for queued, blocked and skipped executions (nothing ran).
 * @param {{ execution: { status: string, taskSummary: { total: number, succeeded: number, failed: number, running: number } } }} props
 */
export function TaskSegments({ execution }) {
  const { total, succeeded, failed, running } = execution.taskSummary;
  if (["queued", "blocked", "skipped"].includes(execution.status) || total === 0)
    return <span className="text-muted-foreground">—</span>;
  const other = Math.max(0, total - succeeded - failed - running);
  const segments = [
    ...Array(succeeded).fill("bg-status-success"),
    ...Array(failed).fill("bg-status-danger"),
    ...Array(running).fill("bg-foreground"),
    ...Array(other).fill("bg-border-strong"),
  ];
  const description = [
    `${succeeded} succeeded`,
    failed ? `${failed} failed` : null,
    running ? `${running} running` : null,
    other ? `${other} not succeeded or waiting` : null,
  ]
    .filter(Boolean)
    .join(", ");
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={`${succeeded} of ${total} scans succeeded: ${description}`}
          className="inline-flex items-center gap-2 rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <span className="text-xs tabular-nums">
            {succeeded}/{total}
          </span>
          <span aria-hidden="true" className="flex gap-0.5">
            {segments.map((tone, i) => (
              <span key={i} className={`h-1.5 w-3 rounded-[1px] ${tone}`} />
            ))}
          </span>
        </button>
      </TooltipTrigger>
      <TooltipContent>{description}</TooltipContent>
    </Tooltip>
  );
}
