import { Info } from "lucide-react";
import { Link } from "react-router";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { isActiveStatus, scanKindText } from "../constants/index.js";
import { useNow } from "../hooks/use-now.js";
import { Duration } from "./execution-table.jsx";
import {
  ExecutionId,
  Identifier,
  TimeAgo,
  TriggerCell,
  absoluteTime,
  clockTime,
  formatDuration,
  shortId,
} from "./execution-bits.jsx";

const INCOMPLETE = ["partial", "failed", "timed_out", "cancelled"];

/** The notices that are true for this execution (plain text with an icon, never a colour alone). */
export function noticesOf(e) {
  const notices = [];
  if (e.resolutionEligible === false && e.status !== "queued") {
    if (INCOMPLETE.includes(e.status))
      notices.push("This run did not complete a full scan. It cannot mark findings fixed.");
    else if (e.scanKind === "incremental")
      notices.push(
        "Incremental scan. Findings that are absent from this run are not marked fixed.",
      );
    if (e.trust === "untrusted_fork")
      notices.push("Scanned without credentials. Findings from this run are not auto-assigned.");
  }
  return notices;
}

export function Notices({ execution }) {
  const notices = noticesOf(execution);
  if (!notices.length) return null;
  return (
    <ul className="mb-3 space-y-1">
      {notices.map((text) => (
        <li key={text} className="flex items-start gap-2 text-sm">
          <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          {text}
        </li>
      ))}
    </ul>
  );
}

function Fact({ label, children }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="break-words">{children}</dd>
    </div>
  );
}

/** Facts card of T-29. No base SHA; the base ref only for a pull request. */
export function ExecutionFacts({ execution: e }) {
  const now = useNow(isActiveStatus(e.status) && Boolean(e.deadlineAt));
  const wait = e.startedAt ? new Date(e.startedAt) - new Date(e.requestedAt) : null;
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle>Details</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
          <Fact label="Trigger">
            <TriggerCell execution={e} />
          </Fact>
          {e.requestedBy ? <Fact label="Requested by">{e.requestedBy.displayName}</Fact> : null}
          <Fact label="Scan kind">{scanKindText(e.scanKind, e.scanKindReason)}</Fact>
          <Fact label="Configuration">
            v{e.configVersion}{" "}
            <Identifier value={e.configHash} max={6} copy label="configuration hash" />
          </Fact>
          <Fact label="Requested">
            <TimeAgo value={e.requestedAt} />
          </Fact>
          <Fact label="Started">
            <TimeAgo value={e.startedAt} />
          </Fact>
          <Fact label="Finished">
            <TimeAgo value={e.finishedAt} />
          </Fact>
          <Fact label="Duration">
            <Duration execution={e} />
          </Fact>
          {wait !== null ? <Fact label="Queue wait">{formatDuration(wait)}</Fact> : null}
          {isActiveStatus(e.status) && e.deadlineAt ? (
            <Fact label="Deadline">
              <time dateTime={e.deadlineAt} title={absoluteTime(e.deadlineAt)}>
                Stops by {clockTime(e.deadlineAt)}
              </time>
              <span className="sr-only">
                {" "}
                {now > new Date(e.deadlineAt).getTime() ? "(passed)" : ""}
              </span>
            </Fact>
          ) : null}
          {e.retryOfExecutionId ? (
            <Fact label="Retry of">
              <Link
                className="font-mono text-xs underline-offset-2 hover:underline"
                to={`/workspaces/${e.workspaceId}/executions/${e.retryOfExecutionId}`}
              >
                {shortId(e.retryOfExecutionId)}
              </Link>
            </Fact>
          ) : null}
          {e.triggerType === "pull_request" && e.baseRef ? (
            <Fact label="Pull request">
              {e.pullRequestNumber ? `#${e.pullRequestNumber} into ` : "into "}
              <span className="font-mono text-xs">{e.baseRef}</span>
            </Fact>
          ) : null}
          <Fact label="Execution id">
            <ExecutionId id={e.id} />
          </Fact>
        </dl>
      </CardContent>
    </Card>
  );
}
