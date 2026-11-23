import { useEffect, useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";
import { SEVERITY_LABELS, SCAN_TYPE_LABELS } from "../constants/index.js";
import {
  describeActionError,
  useFindingAction,
  useSimilarFindings,
} from "../hooks/use-findings.js";
import { newIdempotencyKey } from "../services/findings-service.js";
import { AiAdvisoryCard } from "./ai-advisory-card.jsx";
import { EvidencePanel } from "./code-viewer.jsx";
import {
  Identifier,
  Person,
  SeverityBadge,
  SlaChip,
  StatusBadge,
  TimeAgo,
  Untrusted,
} from "./finding-bits.jsx";
import { absoluteTime } from "@/features/executions/components/execution-bits.jsx";

function Card({ title, children, className }) {
  return (
    <section className={`rounded-md border border-border bg-card p-4 ${className ?? ""}`}>
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      {children}
    </section>
  );
}
function Row({ label, children }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-0.5 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-right">{children}</dd>
    </div>
  );
}

/** A minute-resolution clock (the SLA countdown is not announced every minute, only redrawn). */
function useMinute() {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(timer);
  }, []);
  return now;
}

function Description({ finding }) {
  return (
    <Card title="About this finding">
      <dl className="space-y-0.5">
        <Row label="Rule">
          <Identifier value={finding.ruleId} max={28} copy label="rule id" />
        </Row>
        {finding.advisories.length ? (
          <Row label="Advisories">
            <span className="flex flex-wrap justify-end gap-x-3 gap-y-0.5">
              {finding.advisories.map((a) => (
                <span key={a.id} className="font-mono text-xs">
                  {a.id} <span className="font-sans text-muted-foreground">({a.family})</span>
                </span>
              ))}
            </span>
          </Row>
        ) : null}
        {finding.cwe.length ? (
          <Row label="CWE">
            <span className="font-mono text-xs">
              {finding.cwe.map((c) => `CWE-${c}`).join(", ")}
            </span>
          </Row>
        ) : null}
        {finding.component ? (
          <Row label="Affected component">
            <span className="font-mono text-xs">
              {finding.component.name}@{finding.component.version ?? "?"}
            </span>{" "}
            <span className="text-muted-foreground">({finding.component.ecosystem})</span>
          </Row>
        ) : null}
        {finding.fix?.fixedVersions?.length ? (
          <Row label="Fix">
            Upgrade to <span className="font-mono text-xs">{finding.fix.fixedVersions[0]}</span> or
            later
          </Row>
        ) : null}
      </dl>
    </Card>
  );
}

function DecisionBlock({ finding }) {
  const review = finding.review.current;
  if (!review) return null;
  const raised = finding.severityOverridden;
  return (
    <Card title="Decision">
      <p className="text-sm">
        <span className="font-medium">
          {review.decision === "true_positive" ? "True positive" : "False positive"}
        </span>{" "}
        recorded by {review.reviewer.displayName} <TimeAgo value={review.submittedAt} />
        {finding.status === "awaiting_approval" ? ", waiting for a lead's approval" : ""}.
      </p>
      {raised ? (
        <p className="mt-1 text-sm text-muted-foreground">
          {finding.severity === finding.toolSeverity
            ? ""
            : `Severity changed from ${SEVERITY_LABELS[finding.toolSeverity]} to ${SEVERITY_LABELS[finding.severity]} by review.`}
        </p>
      ) : null}
      <Untrusted className="mt-2 block text-sm">{review.rationale}</Untrusted>
    </Card>
  );
}

function ExceptionBlock({ finding, workspaceId, onReload }) {
  const exception = finding.exception;
  const act = useFindingAction(workspaceId);
  const canWithdraw = finding.lifecycle.allowedActions.some(
    (a) => a.action === "withdraw_exception" && a.allowed,
  );
  if (!exception) return null;
  const pending = exception.state === "pending";
  const kind = exception.kind === "suppress" ? "Suppression" : "Accepted risk";
  const withdraw = async () => {
    try {
      await act.mutateAsync({
        run: (s) => s.withdrawException(finding.id, exception.id, newIdempotencyKey()),
      });
      toast.success("Request withdrawn");
    } catch (error) {
      const { text, conflict } = describeActionError(error);
      toast.error(text);
      if (conflict) onReload();
    }
  };
  return (
    <Card title={pending ? `${kind} requested` : kind}>
      <p className="text-sm">
        {pending
          ? `${kind === "Suppression" ? "Suppression" : "Accepted risk"} requested by ${exception.requestedBy.displayName}, waiting for approval.`
          : `Approved by ${exception.approvedBy?.displayName ?? "a lead"}.`}
        {exception.expiresAt
          ? ` ${pending ? "Requested until" : "Until"} ${absoluteTime(exception.expiresAt, { dateStyle: "medium" })}.`
          : " No expiry."}{" "}
        {pending && canWithdraw ? (
          <button
            type="button"
            onClick={withdraw}
            disabled={act.isPending}
            className="rounded-sm font-medium underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            Withdraw
          </button>
        ) : null}
      </p>
      <Untrusted className="mt-2 block text-sm">{exception.justification}</Untrusted>
    </Card>
  );
}

function RemediationBlock({ finding }) {
  const { assignment, lastRecord } = finding.remediation;
  if (!assignment && !lastRecord) return null;
  const prUrl = lastRecord?.pullRequestUrl;
  const safe = typeof prUrl === "string" && /^https:\/\/[^\s]+$/.test(prUrl);
  return (
    <Card title="Remediation">
      <dl className="space-y-0.5">
        {assignment ? (
          <Row label="Assigned to">
            <Person user={assignment.assignee} />
          </Row>
        ) : null}
        {assignment?.note ? (
          <Row label="Note">
            <Untrusted>{assignment.note}</Untrusted>
          </Row>
        ) : null}
        {lastRecord ? (
          <Row label={lastRecord.kind === "fix_submitted" ? "Fix submitted" : "Work started"}>
            <TimeAgo value={lastRecord.at} />
          </Row>
        ) : null}
        {prUrl ? (
          <Row label="Pull request">
            {safe ? (
              <a
                href={prUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="break-all underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                {prUrl}
                <span className="sr-only"> (opens in a new tab)</span>
              </a>
            ) : (
              <Untrusted>{prUrl}</Untrusted>
            )}
          </Row>
        ) : null}
        {lastRecord?.ticketKey ? (
          <Row label="Ticket">
            <span className="font-mono text-xs">{lastRecord.ticketKey}</span>
          </Row>
        ) : null}
        {lastRecord?.note ? (
          <Row label="Fix note">
            <Untrusted>{lastRecord.note}</Untrusted>
          </Row>
        ) : null}
      </dl>
    </Card>
  );
}

function SimilarCard({ workspaceId, finding }) {
  const similar = useSimilarFindings(workspaceId, finding.id, {
    enabled: finding.similarCount > 0,
  });
  if (!finding.similarCount) return null;
  return (
    <Card title="Similar in other pipelines">
      <p className="mb-2 text-xs text-muted-foreground">
        Not merged: each pipeline tracks its own finding.
      </p>
      {similar.isPending ? <p className="text-sm text-muted-foreground">Loading…</p> : null}
      <ul className="space-y-1.5 text-sm">
        {(similar.data ?? []).map((s) => (
          <li key={s.id}>
            <Link
              className="underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
              to={`/workspaces/${workspaceId}/findings/${s.id}`}
            >
              <Untrusted>{s.title}</Untrusted>
            </Link>
            <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <SeverityBadge severity={s.severity} />
              <StatusBadge status={s.status} />
              {s.pipeline.name}
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}

/**
 * The Overview tab of T-32 (SCREENS 6): the structured description, location with evidence, the advisory card, decision,
 * exception and remediation blocks, and the right column of risk, SLA, assignee, detections and similar findings.
 * @param {{ workspaceId: string, finding: any, onReload: () => void }} props
 */
export function FindingOverview({ workspaceId, finding, onReload }) {
  const now = useMinute();
  const act = useFindingAction(workspaceId);
  const advisoryAction = finding.lifecycle.allowedActions.find(
    (a) => a.action === "request_advisory",
  );
  const requestAdvice = async () => {
    try {
      await act.mutateAsync({ run: (s) => s.requestAdvisory(finding.id, newIdempotencyKey()) });
    } catch (error) {
      toast.error(describeActionError(error).text);
    }
  };
  const reviewed = Boolean(finding.review.current);
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
      <div className="min-w-0 space-y-4">
        <Description finding={finding} />
        <Card title="Location">
          <EvidencePanel finding={finding} compact />
        </Card>
        <AiAdvisoryCard
          advisory={finding.advisory}
          secret={finding.scanType === "secrets"}
          onRequest={advisoryAction && finding.scanType !== "secrets" ? requestAdvice : undefined}
          requesting={act.isPending}
          requestDisabledReason={
            advisoryAction && !advisoryAction.allowed ? advisoryAction.disabledReason : null
          }
        />
        <DecisionBlock finding={finding} />
        <ExceptionBlock finding={finding} workspaceId={workspaceId} onReload={onReload} />
        <RemediationBlock finding={finding} />
      </div>
      <div className="min-w-0 space-y-4">
        <Card title="Risk">
          <dl>
            <Row label="Severity">
              <SeverityBadge severity={finding.severity} />
            </Row>
            <Row label="Tool severity">{SEVERITY_LABELS[finding.toolSeverity]}</Row>
            <Row label="Confidence">
              {finding.confidence[0].toUpperCase() + finding.confidence.slice(1)}
            </Row>
            <Row label="Reviewed">{reviewed ? "Yes" : "Not yet"}</Row>
            <Row label="Scan type">{SCAN_TYPE_LABELS[finding.scanType]}</Row>
          </dl>
        </Card>
        <Card title="SLA">
          <dl>
            <Row label="State">
              <SlaChip sla={finding.sla} now={now} />
            </Row>
            <Row label="Target">
              {finding.sla.targetHours
                ? `${finding.sla.targetHours >= 48 ? Math.round(finding.sla.targetHours / 24) + " days" : finding.sla.targetHours + " hours"}`
                : "No SLA"}
            </Row>
            <Row label="Started">
              <TimeAgo value={finding.firstDetectedAt} />
            </Row>
            <Row label="Due">{finding.sla.dueAt ? <TimeAgo value={finding.sla.dueAt} /> : "—"}</Row>
          </dl>
        </Card>
        <Card title="Assignee">
          <Person user={finding.assignee} />
        </Card>
        <Card title="Detections">
          <dl>
            <Row label="First seen">
              <TimeAgo value={finding.firstDetectedAt} />
            </Row>
            <Row label="Last seen">
              <TimeAgo value={finding.lastSeenAt} />
            </Row>
            <Row label="Seen">{finding.occurrenceCount} times</Row>
            <Row label="Reopened">{finding.reopenCount} times</Row>
          </dl>
        </Card>
        <SimilarCard workspaceId={workspaceId} finding={finding} />
      </div>
    </div>
  );
}
