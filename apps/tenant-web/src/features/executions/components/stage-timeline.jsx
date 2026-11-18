import { Check, Circle, CircleDot } from "lucide-react";
import { executionStatus, isActiveStatus } from "../constants/index.js";
import { absoluteTime, relativeTime } from "./execution-bits.jsx";

/**
 * Where the execution is in its life: Queued, Preparing, Scans, then the outcome. The stages the SPEC defers to later
 * modules (repository analysis, finding normalization) are not shown. Times: Queued = requested, Scans = started, last =
 * finished. The preparing time is not in the API (no claim time), so that stage shows none.
 */
export function stagesOf(e) {
  const done = isActiveStatus(e.status) ? null : e.status;
  const rank = { queued: 0, preparing: 1, running: 2 }[e.status] ?? 3;
  const reached = (index) => rank > index || (rank === 3 && index <= (e.startedAt ? 2 : 0));
  return [
    { id: "queued", label: "Queued", at: e.requestedAt, state: rank === 0 ? "current" : "done" },
    {
      id: "preparing",
      label: "Preparing",
      at: null,
      sub: e.decision?.decidedAt
        ? { label: "Analysis and decision", at: e.decision.decidedAt }
        : null,
      state: rank === 1 ? "current" : reached(1) ? "done" : "skipped",
    },
    {
      id: "scans",
      label: "Scans",
      at: e.startedAt,
      state: rank === 2 ? "current" : reached(2) ? "done" : "skipped",
    },
    {
      id: "completed",
      label: done ? executionStatus(done).label : "Completed",
      at: e.finishedAt,
      state: done ? "done" : "upcoming",
    },
  ];
}

const ICONS = { done: Check, current: CircleDot, upcoming: Circle, skipped: Circle };

/** Horizontal ordered list; the current stage carries `aria-current="step"`. Scrolls sideways when narrow. */
export function StageTimeline({ execution }) {
  const stages = stagesOf(execution);
  return (
    <ol aria-label="Execution stages" className="qm-scroll flex gap-6 overflow-x-auto pb-1">
      {stages.map((stage) => {
        const Icon = ICONS[stage.state];
        return (
          <li
            key={stage.id}
            aria-current={stage.state === "current" ? "step" : undefined}
            ref={(el) =>
              stage.state === "current" &&
              el?.scrollIntoView?.({ inline: "nearest", block: "nearest" })
            }
            className={`flex min-w-28 shrink-0 items-start gap-2 text-sm ${stage.state === "upcoming" || stage.state === "skipped" ? "text-muted-foreground" : ""}`}
          >
            <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            <span>
              <span className="block font-medium">
                {stage.label}
                {stage.state === "current" ? <span className="sr-only"> (current)</span> : null}
                {stage.state === "skipped" ? <span className="sr-only"> (not reached)</span> : null}
              </span>
              {stage.at && stage.state !== "upcoming" ? (
                <time
                  dateTime={stage.at}
                  title={absoluteTime(stage.at, { dateStyle: "medium", timeStyle: "medium" })}
                  className="block text-xs text-muted-foreground"
                >
                  {relativeTime(stage.at)}
                </time>
              ) : null}
              {stage.sub && stage.state !== "upcoming" ? (
                <span className="block text-xs text-muted-foreground">
                  {stage.sub.label}{" "}
                  <time
                    dateTime={stage.sub.at}
                    title={absoluteTime(stage.sub.at, { dateStyle: "medium", timeStyle: "medium" })}
                  >
                    {relativeTime(stage.sub.at)}
                  </time>
                </span>
              ) : null}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
