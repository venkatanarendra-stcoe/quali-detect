import { CircleOff, ExternalLink, MoreHorizontal, RotateCcw } from "lucide-react";
import { useRef, useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { Button } from "@/components/ui/button.jsx";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog.jsx";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { describeError, isApiError } from "@/lib/api/index.js";
import { isRetryableExecutionStatus } from "@qmentisai/shared";
import {
  CANCEL_DENIED,
  CANCELLABLE_STATUSES,
  CONFLICT_MESSAGES,
  RETRY_DENIED,
  isCancelling,
} from "../constants/index.js";
import { useCancelExecution, useRetryExecution } from "../hooks/use-executions.js";
import { newIdempotencyKey } from "../services/executions-service.js";
import { clockTime, shortId } from "./execution-bits.jsx";

/**
 * What the caller may do with one execution, from the central engine (never a role name). Usability only: the API enforces.
 * `showCancel` / `showRetry` follow the state; `cancelReason` / `retryReason` are the sentences of the disabled control.
 * @param {{ workspaceId: string, status: string, cancelRequested?: boolean }} execution
 */
export function useExecutionAccess(execution) {
  const can = useCan();
  const scope = { type: "workspace", workspaceId: execution.workspaceId };
  return {
    showCancel: CANCELLABLE_STATUSES.includes(execution.status) && !isCancelling(execution),
    cancelReason: can("execution.cancel", scope) ? null : CANCEL_DENIED,
    showRetry: isRetryableExecutionStatus(execution.status),
    retryReason: can("execution.run", scope) ? null : RETRY_DENIED,
  };
}

/** The refusal of a cancel or a retry in plain words (stable 409 reason, quota and entitlement codes, 403, 404). */
export function actionRefusal(error) {
  if (!isApiError(error)) return describeError(error);
  const reason = error.details?.reason;
  if (reason && CONFLICT_MESSAGES[reason]) return CONFLICT_MESSAGES[reason];
  if (error.code === "QUOTA_EXCEEDED")
    return "The monthly scan quota is used up, so no more runs can be requested.";
  if (error.code === "ENTITLEMENT_REQUIRED") return "Your plan does not include this action.";
  if (error.status === 403) return "You don't have permission to do this in this workspace.";
  if (error.status === 404) return "This execution no longer exists or is not visible to you.";
  return describeError(error);
}

function ActionError({ error }) {
  if (!error) return null;
  return (
    <div
      role="alert"
      className="mt-4 rounded-md border border-border-strong bg-secondary p-3 text-sm"
    >
      <p>{actionRefusal(error)}</p>
      {isApiError(error) && error.correlationId ? (
        <p className="mt-1 text-xs text-subtle-foreground">
          Reference <span className="font-mono">{error.correlationId}</span>
        </p>
      ) : null}
    </div>
  );
}

/** The sentence of the cancel dialog: the mode and grace come from the execution DTO, never from user input. */
export function cancelExplanation(execution) {
  if (execution.status === "queued")
    return "This execution has not started. Cancelling it returns its scan unit.";
  if (execution.cancelMode === "immediate")
    return "Scans are stopped now. Results of finished scans are kept.";
  if (execution.cancelMode === "graceful")
    return "Running scans may finish for up to 60 seconds, then they are stopped. Results of finished scans are kept.";
  return "Running scans are stopped according to this pipeline's cancellation setting: at once, or after a short grace period. Results of finished scans are kept.";
}

function CancelBody({ execution, onOpenChange }) {
  const cancel = useCancelExecution();
  const dismiss = useRef(null);
  const key = useRef(newIdempotencyKey()); // one key per opened dialog: a retry of the same attempt reuses it
  const confirm = () =>
    cancel.mutate(
      {
        executionId: execution.id,
        workspaceId: execution.workspaceId,
        idempotencyKey: key.current,
      },
      {
        onSuccess: (result) => {
          toast.success(
            result?.cancelRequested
              ? "Cancel requested. Running scans are being stopped."
              : "Execution cancelled.",
          );
          onOpenChange(false);
        },
      },
    );
  return (
    <DialogContent
      onOpenAutoFocus={(event) => {
        event.preventDefault(); // the destructive confirm is never the default focus
        dismiss.current?.focus();
      }}
    >
      <DialogHeader>
        <DialogTitle>Cancel execution {shortId(execution.id)}?</DialogTitle>
        <DialogDescription>{cancelExplanation(execution)}</DialogDescription>
      </DialogHeader>
      <ActionError error={cancel.error} />
      <DialogFooter>
        <Button ref={dismiss} type="button" variant="ghost" onClick={() => onOpenChange(false)}>
          Keep running
        </Button>
        <Button type="button" variant="destructive" disabled={cancel.isPending} onClick={confirm}>
          {cancel.isPending ? "Cancelling…" : "Cancel execution"}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

/** Cancel confirmation (needs `execution.cancel`; the caller decides whether to open it, the API enforces regardless). */
export function CancelDialog({ execution, open, onOpenChange }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open ? <CancelBody execution={execution} onOpenChange={onOpenChange} /> : null}
    </Dialog>
  );
}

function RetryBody({ execution, onOpenChange }) {
  const navigate = useNavigate();
  const retry = useRetryExecution();
  const dismiss = useRef(null);
  const key = useRef(newIdempotencyKey()); // generated per user action; a retry of the SAME attempt reuses it
  const confirm = () =>
    retry.mutate(
      {
        executionId: execution.id,
        workspaceId: execution.workspaceId,
        idempotencyKey: key.current,
      },
      {
        onSuccess: ({ execution: created }) => {
          toast.success("Retry started.");
          onOpenChange(false);
          navigate(`/workspaces/${created.workspaceId}/executions/${created.id}`);
        },
      },
    );
  return (
    <DialogContent
      onOpenAutoFocus={(event) => {
        event.preventDefault();
        dismiss.current?.focus();
      }}
    >
      <DialogHeader>
        <DialogTitle>Retry execution {shortId(execution.id)}?</DialogTitle>
        <DialogDescription>
          Starts a new execution on the same commit with the same configuration version. It counts
          toward your scan quota.
        </DialogDescription>
      </DialogHeader>
      <ActionError error={retry.error} />
      <DialogFooter>
        <Button ref={dismiss} type="button" variant="ghost" onClick={() => onOpenChange(false)}>
          Not now
        </Button>
        <Button type="button" disabled={retry.isPending} onClick={confirm}>
          {retry.isPending ? "Starting…" : retry.error ? "Try again" : "Retry"}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

/** Retry confirmation (needs `execution.run`). Sends a generated `Idempotency-Key`; on success opens the new execution. */
export function RetryDialog({ execution, open, onOpenChange }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open ? <RetryBody execution={execution} onOpenChange={onOpenChange} /> : null}
    </Dialog>
  );
}

/** Header buttons of T-29: Retry (the page's one mint action) and Cancel (destructive outline). */
export function ExecutionHeaderActions({ execution, onCancel, onRetry }) {
  const access = useExecutionAccess(execution);
  return (
    <>
      {isCancelling(execution) ? (
        <span role="status" className="text-sm text-muted-foreground">
          Cancelling: running scans are being stopped
          {execution.cancelRequestedAt
            ? ` (requested ${clockTime(execution.cancelRequestedAt)})`
            : ""}
        </span>
      ) : null}
      {access.showCancel ? (
        <DisabledWithReason reason={access.cancelReason}>
          <Button
            variant="outline"
            className="border-destructive text-destructive hover:text-destructive"
            onClick={onCancel}
          >
            <CircleOff aria-hidden="true" />
            Cancel
          </Button>
        </DisabledWithReason>
      ) : null}
      {access.showRetry ? (
        <DisabledWithReason reason={access.retryReason}>
          <Button onClick={onRetry}>
            <RotateCcw aria-hidden="true" />
            Retry
          </Button>
        </DisabledWithReason>
      ) : null}
    </>
  );
}

/** Row menu of the list: View, Cancel, Retry, each by state and permission (a missing permission is shown disabled with its reason). */
export function ExecutionRowActions({ execution }) {
  const navigate = useNavigate();
  const access = useExecutionAccess(execution);
  const [dialog, setDialog] = useState(null);
  const open = `/workspaces/${execution.workspaceId}/executions/${execution.id}`;
  const item = (icon, label, reason, onSelect) => (
    <DropdownMenuItem disabled={Boolean(reason)} onSelect={onSelect} aria-describedby={undefined}>
      {icon}
      <span className="flex flex-col">
        {label}
        {reason ? (
          <span className="text-xs font-normal text-muted-foreground">{reason}</span>
        ) : null}
      </span>
    </DropdownMenuItem>
  );
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            aria-label={`Actions for execution ${shortId(execution.id)}`}
          >
            <MoreHorizontal aria-hidden="true" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-72">
          <DropdownMenuItem onSelect={() => navigate(open)}>
            <ExternalLink aria-hidden="true" /> View
          </DropdownMenuItem>
          {access.showCancel
            ? item(<CircleOff aria-hidden="true" />, "Cancel…", access.cancelReason, () =>
                setDialog("cancel"),
              )
            : null}
          {access.showRetry
            ? item(<RotateCcw aria-hidden="true" />, "Retry…", access.retryReason, () =>
                setDialog("retry"),
              )
            : null}
        </DropdownMenuContent>
      </DropdownMenu>
      <CancelDialog
        execution={execution}
        open={dialog === "cancel"}
        onOpenChange={(next) => !next && setDialog(null)}
      />
      <RetryDialog
        execution={execution}
        open={dialog === "retry"}
        onOpenChange={(next) => !next && setDialog(null)}
      />
    </>
  );
}
