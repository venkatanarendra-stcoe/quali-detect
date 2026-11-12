import { useState } from "react";
import { Button } from "@/components/ui/button.jsx";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { describeError } from "@/lib/api/index.js";

const MIN_REASON = 5;

function ConfirmBody({
  title,
  description,
  confirmLabel,
  destructive,
  confirmText,
  reasonLabel,
  onConfirm,
  onCancel,
  pending,
  error,
  errorText,
  confirmDisabled = false,
  children,
}) {
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const typedOk = confirmText === undefined || typed === confirmText;
  const reasonOk = reasonLabel === undefined || reason.trim().length >= MIN_REASON;
  return (
    <DialogContent>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (typedOk && reasonOk && !pending) onConfirm({ reason: reason.trim(), confirm: typed });
        }}
      >
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          {children}
          {reasonLabel !== undefined ? (
            <div className="space-y-1.5">
              <Label htmlFor="confirm-reason">{reasonLabel}</Label>
              <Textarea
                id="confirm-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={500}
                aria-describedby="confirm-reason-hint"
              />
              <p id="confirm-reason-hint" className="text-xs text-subtle-foreground">
                At least {MIN_REASON} characters. It is recorded in the audit log.
              </p>
            </div>
          ) : null}
          {confirmText !== undefined ? (
            <div className="space-y-1.5">
              <Label htmlFor="confirm-typed">
                Type <span className="font-mono font-semibold">{confirmText}</span> to confirm
              </Label>
              <Input
                id="confirm-typed"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
          ) : null}
          {error || errorText ? (
            <p role="alert" className="text-sm text-status-danger">
              {errorText ?? describeError(error)}
            </p>
          ) : null}
        </div>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant={destructive ? "destructive" : "default"}
            disabled={!typedOk || !reasonOk || pending || confirmDisabled}
          >
            {pending ? "Working…" : confirmLabel}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

/**
 * Confirmation dialog for consequential actions. Optional typed confirmation (`confirmText`: the exact value to type,
 * for example the workspace or tenant name) and optional reason (`reasonLabel`: required, recorded in the audit log).
 * The body state resets every time the dialog opens. `onConfirm({ reason, confirm })` should return when done; the parent
 * closes the dialog on success and passes `error` / `pending` from its mutation. `errorText` replaces the generic message of `error` with a more specific sentence. `confirmDisabled` keeps the confirm button
 * disabled for a refusal the user cannot retry away (for example "cancel the running executions first").
 */
export function ConfirmDialog({ open, onOpenChange, ...rest }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open ? <ConfirmBody {...rest} onCancel={() => onOpenChange(false)} /> : null}
    </Dialog>
  );
}
