import { MoreHorizontal } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { ACTION_LABELS } from "../constants/index.js";
import { describeActionError, useFindingAction } from "../hooks/use-findings.js";
import { newIdempotencyKey } from "../services/findings-service.js";
import { AssignDialog, DecideDialog, DecisionDialog, SubmitFixDialog } from "./action-dialogs.jsx";
import { ExceptionDialog } from "./exception-dialog.jsx";

/** The primary (mint) action per state, in the order of SCREENS 6. The server's `allowed` still decides whether it shows. */
const PRIMARY_ORDER = [
  "claim",
  "record_review",
  "approve_review",
  "approve_exception",
  "assign",
  "start_work",
  "submit_fix",
];
const PRIMARY_STATUS = {
  claim: ["new"],
  record_review: ["in_review"],
  assign: ["approved", "reopened"],
  start_work: ["assigned"],
  submit_fix: ["in_remediation"],
};
/** Actions that appear as their own buttons (decisions), never inside the menu, so a disabled reason is always reachable. */
const BUTTON_ACTIONS = ["approve_review", "reject_review", "approve_exception", "reject_exception"];

/**
 * Header actions of T-32, rendered from `lifecycle.allowedActions` (never recomputed; SPEC 8.3). An action absent from the list is
 * hidden; an action present with `allowed: false` is shown DISABLED with its reason as a tooltip reachable by keyboard (Approve
 * and Reject for the reviewer, the segregation-of-duties rule). The permission key is never shown.
 * @param {{ workspaceId: string, finding: any, onReload: () => void }} props
 */
export function FindingActions({ workspaceId, finding, onReload }) {
  const act = useFindingAction(workspaceId);
  const [dialog, setDialog] = useState(null);
  const close = () => setDialog(null);
  const actions = finding.lifecycle.allowedActions;
  const byId = Object.fromEntries(actions.map((a) => [a.action, a]));
  const usable = (id) => byId[id]?.allowed;
  const primaryId = PRIMARY_ORDER.find(
    (id) =>
      usable(id) && (id.startsWith("approve_") || PRIMARY_STATUS[id]?.includes(finding.status)),
  );

  const quick = async (fn, message) => {
    try {
      await act.mutateAsync({ run: (s) => fn(s, newIdempotencyKey()) });
      if (message) toast.success(message);
    } catch (error) {
      const { text, conflict } = describeActionError(error);
      if (conflict) {
        toast.error(text, { action: { label: "Reload", onClick: onReload } });
        onReload();
      } else toast.error(text);
    }
  };
  const rev = finding.rev;
  const run = {
    claim: () => {
      if (finding.status === "in_review" && finding.claimedBy) setDialog({ type: "takeover" });
      else quick((s, k) => s.claim(finding.id, { expectedRev: rev }, k), "Review started");
    },
    record_review: () => setDialog({ type: "decision" }),
    withdraw_review: () => setDialog({ type: "withdraw" }),
    approve_review: () => setDialog({ type: "decide", mode: "approve", kind: "review" }),
    reject_review: () => setDialog({ type: "decide", mode: "reject", kind: "review" }),
    approve_exception: () => setDialog({ type: "decide", mode: "approve", kind: "exception" }),
    reject_exception: () => setDialog({ type: "decide", mode: "reject", kind: "exception" }),
    reopen_review: () => setDialog({ type: "reopen" }),
    assign: () => setDialog({ type: "assign" }),
    reassign: () => setDialog({ type: "assign" }),
    unassign: () => setDialog({ type: "unassign" }),
    start_work: () =>
      quick((s, k) => s.startRemediation(finding.id, { expectedRev: rev }, k), "Work started"),
    submit_fix: () => setDialog({ type: "fix" }),
    request_accept_risk: () => setDialog({ type: "exception", kind: "accept_risk" }),
    request_suppression: () => setDialog({ type: "exception", kind: "suppress" }),
    withdraw_exception: () =>
      quick(
        (s, k) => s.withdrawException(finding.id, finding.exception.id, k),
        "Request withdrawn",
      ),
    revoke_accept_risk: () => setDialog({ type: "revoke" }),
    revoke_suppression: () => setDialog({ type: "revoke" }),
    request_advisory: () => quick((s, k) => s.requestAdvisory(finding.id, k), "Advice requested"),
  };

  const buttons = BUTTON_ACTIONS.filter((id) => byId[id]);
  const menu = actions.filter(
    (a) => !BUTTON_ACTIONS.includes(a.action) && a.action !== primaryId && run[a.action],
  );
  const request =
    dialog?.type === "decide"
      ? dialog.kind === "review"
        ? {
            kind: "review",
            requestId: finding.review.current?.id,
            decision: finding.review.current?.decision,
          }
        : {
            kind: "exception",
            requestId: finding.exception?.id,
            exceptionKind: finding.exception?.kind,
          }
      : null;

  return (
    <div className="flex flex-wrap items-center gap-2" aria-label="Finding actions" role="group">
      {primaryId && !BUTTON_ACTIONS.includes(primaryId) ? (
        <Button onClick={run[primaryId]} disabled={act.isPending}>
          {ACTION_LABELS[primaryId]}
        </Button>
      ) : null}
      {buttons.map((id) => {
        const a = byId[id];
        const isPrimary = id === primaryId;
        const label = id.startsWith("approve") ? "Approve" : "Reject";
        return (
          <DisabledWithReason
            key={id}
            reason={a.allowed ? null : (a.disabledReason ?? "Not available now.")}
          >
            <Button variant={isPrimary ? "default" : "secondary"} onClick={run[id]}>
              {label}
            </Button>
          </DisabledWithReason>
        );
      })}
      {menu.length ? (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="secondary" aria-label="More actions">
              <MoreHorizontal aria-hidden="true" />
              <span className="max-sm:hidden">More</span>
              <span className="sm:hidden">Actions</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-64">
            {menu.map((a) => (
              <DropdownMenuItem
                key={a.action}
                disabled={!a.allowed}
                onSelect={() => a.allowed && run[a.action]()}
                className="flex-col items-start gap-0"
              >
                <span>
                  {a.action === "claim" && finding.status !== "new"
                    ? "Take over review"
                    : ACTION_LABELS[a.action]}
                </span>
                {!a.allowed && a.disabledReason ? (
                  <span className="text-xs text-muted-foreground">{a.disabledReason}</span>
                ) : null}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : null}

      {dialog?.type === "decision" ? (
        <DecisionDialog
          workspaceId={workspaceId}
          finding={finding}
          onClose={close}
          onReload={onReload}
        />
      ) : null}
      {dialog?.type === "decide" ? (
        <DecideDialog
          workspaceId={workspaceId}
          finding={finding}
          request={request}
          mode={dialog.mode}
          onClose={close}
          onReload={onReload}
        />
      ) : null}
      {dialog?.type === "assign" ? (
        <AssignDialog
          workspaceId={workspaceId}
          finding={finding}
          onClose={close}
          onReload={onReload}
        />
      ) : null}
      {dialog?.type === "fix" ? (
        <SubmitFixDialog
          workspaceId={workspaceId}
          finding={finding}
          onClose={close}
          onReload={onReload}
        />
      ) : null}
      {dialog?.type === "exception" ? (
        <ExceptionDialog
          workspaceId={workspaceId}
          finding={finding}
          initialKind={dialog.kind}
          onClose={close}
          onReload={onReload}
        />
      ) : null}

      <ConfirmDialog
        open={dialog?.type === "takeover"}
        onOpenChange={(o) => !o && close()}
        title="Take over this review?"
        description={`${finding.claimedBy?.displayName ?? "Someone"} is reviewing this finding. Taking over is recorded in the history.`}
        confirmLabel="Take over"
        pending={act.isPending}
        onConfirm={async () => {
          await quick(
            (s, k) => s.claim(finding.id, { expectedRev: rev }, k),
            "You took over the review",
          );
          close();
        }}
      />
      <ConfirmDialog
        open={dialog?.type === "withdraw"}
        onOpenChange={(o) => !o && close()}
        title="Withdraw your decision?"
        description="The finding goes back to In review and your decision is no longer waiting for approval."
        confirmLabel="Withdraw decision"
        pending={act.isPending}
        onConfirm={async () => {
          await quick(
            (s, k) =>
              s.withdrawReview(finding.id, finding.review.current.id, { expectedRev: rev }, k),
            "Decision withdrawn",
          );
          close();
        }}
      />
      <ConfirmDialog
        open={dialog?.type === "unassign"}
        onOpenChange={(o) => !o && close()}
        title="Unassign this finding?"
        description="It returns to Confirmed, unassigned and can be assigned to someone else."
        confirmLabel="Unassign"
        pending={act.isPending}
        onConfirm={async () => {
          await quick(
            (s, k) => s.clearAssignment(finding.id, { expectedRev: rev }, k),
            "Unassigned",
          );
          close();
        }}
      />
      <ConfirmDialog
        open={dialog?.type === "reopen"}
        onOpenChange={(o) => !o && close()}
        title="Reopen for review?"
        description="The finding goes back to In review so an analyst can decide again."
        confirmLabel="Reopen for review"
        reasonLabel="Reason"
        pending={act.isPending}
        onConfirm={async ({ reason }) => {
          await quick(
            (s, k) => s.reopenReview(finding.id, { reason, expectedRev: rev }, k),
            "Reopened for review",
          );
          close();
        }}
      />
      <ConfirmDialog
        open={dialog?.type === "revoke"}
        onOpenChange={(o) => !o && close()}
        title={finding.status === "suppressed" ? "Revoke suppression?" : "Revoke accepted risk?"}
        description="The finding is reopened and its SLA clock starts again."
        confirmLabel="Revoke"
        destructive
        reasonLabel="Reason"
        pending={act.isPending}
        onConfirm={async ({ reason }) => {
          await quick(
            (s, k) =>
              s.revokeException(finding.id, finding.exception.id, { reason, expectedRev: rev }, k),
            "Revoked",
          );
          close();
        }}
      />
    </div>
  );
}
