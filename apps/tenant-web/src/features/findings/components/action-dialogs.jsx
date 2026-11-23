import { zodResolver } from "@hookform/resolvers/zod";
import { Combobox } from "@qmentisai/ui";
import { useCallback, useRef, useState } from "react";
import { Controller, useForm } from "react-hook-form";
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
import { Input } from "@/components/ui/input.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { LIMITS } from "../constants/index.js";
import { describeActionError, useFindingAction } from "../hooks/use-findings.js";
import {
  assignFormSchema,
  optionalCommentSchema,
  requiredCommentSchema,
  submitFixSchema,
} from "../schemas/forms.js";
import { findingsService, newIdempotencyKey } from "../services/findings-service.js";
import { DecisionForm } from "./decision-form.jsx";
import { ConflictBanner, Field, describedBy } from "./form-bits.jsx";

/** A dialog frame that the parent mounts only while it is open (so each opening gets a fresh form and Idempotency-Key). */
function Frame({ title, description, onClose, children, className }) {
  return (
    <Dialog open onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent className={className}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        {children}
      </DialogContent>
    </Dialog>
  );
}

/** Hook shared by the small dialogs: the mutation, a per-opening key, and the error banner state. */
function useSubmit(workspaceId) {
  const act = useFindingAction(workspaceId);
  const key = useRef(newIdempotencyKey());
  const [banner, setBanner] = useState(null);
  const run = async (fn, { onDone, setError, setFocus, fields = [] }) => {
    setBanner(null);
    try {
      const result = await act.mutateAsync({ run: (s) => fn(s, key.current) });
      key.current = newIdempotencyKey();
      onDone?.(result);
    } catch (error) {
      const { text, field, conflict } = describeActionError(error);
      if (!conflict && field && fields.includes(field)) {
        setError?.(field, { message: text });
        setFocus?.(field);
      } else setBanner({ text, conflict });
    }
  };
  return { act, banner, run };
}

/** The decision form in a dialog (T-32 "Record decision"). @param {{ workspaceId: string, finding: any, onClose: () => void, onReload: () => void }} props */
export function DecisionDialog({ workspaceId, finding, onClose, onReload }) {
  return (
    <Frame
      title="Record decision"
      description="Decide whether this finding is a real issue. A lead approves it before anything changes."
      onClose={onClose}
    >
      <DecisionForm
        workspaceId={workspaceId}
        finding={finding}
        onDone={() => {
          toast.success("Decision submitted for approval");
          onClose();
        }}
        onReload={onReload}
      />
    </Frame>
  );
}

/**
 * Approve or reject a decision request, always with a confirmation (SCREENS 9). Reject needs a comment. `request` is
 * `{ kind: "review" | "exception", requestId, decision?, exceptionKind? }`.
 * @param {{ workspaceId: string, finding: any, request: any, mode: "approve" | "reject", onClose: () => void, onDone?: (r: any) => void, onReload?: () => void }} props
 */
export function DecideDialog({ workspaceId, finding, request, mode, onClose, onDone, onReload }) {
  const { act, banner, run } = useSubmit(workspaceId);
  const schema = mode === "reject" ? requiredCommentSchema : optionalCommentSchema;
  const {
    register,
    handleSubmit,
    watch,
    setError,
    setFocus,
    formState: { errors },
  } = useForm({ resolver: zodResolver(schema), defaultValues: { comment: "" } });
  const comment = watch("comment") ?? "";
  const isException = request.kind === "exception";
  const subject = isException
    ? request.exceptionKind === "suppress"
      ? "suppression"
      : "accepted risk"
    : request.decision === "false_positive"
      ? "false positive"
      : "true positive";
  const title =
    mode === "approve"
      ? `Approve this ${subject}?`
      : `Reject this ${isException ? subject : "decision"}?`;
  const body =
    mode === "approve"
      ? isException
        ? request.exceptionKind === "suppress"
          ? "The finding will be hidden from the default views until the suppression ends."
          : "The finding stays visible, with an accepted-risk status, until the expiry date."
        : request.decision === "false_positive"
          ? "The finding will be marked as a false positive and leave the open work."
          : "The finding will be confirmed and can then be assigned."
      : "The requester is told why. The finding goes back so they can decide again.";
  const submit = handleSubmit((values) =>
    run(
      (s, key) => {
        const payload = {
          ...(values.comment ? { comment: values.comment } : {}),
          expectedRev: finding.rev,
        };
        if (isException)
          return mode === "approve"
            ? s.approveException(finding.id, request.requestId, payload, key)
            : s.rejectException(
                finding.id,
                request.requestId,
                { comment: values.comment, expectedRev: finding.rev },
                key,
              );
        return mode === "approve"
          ? s.approveReview(finding.id, request.requestId, payload, key)
          : s.rejectReview(
              finding.id,
              request.requestId,
              { comment: values.comment, expectedRev: finding.rev },
              key,
            );
      },
      {
        setError,
        setFocus,
        fields: ["comment"],
        onDone: (result) => {
          toast.success(mode === "approve" ? "Approved" : "Rejected");
          onDone?.(result);
          onClose();
        },
      },
    ),
  );
  return (
    <Frame title={title} description={body} onClose={onClose}>
      <form onSubmit={submit} noValidate className="space-y-4">
        {banner ? (
          <ConflictBanner text={banner.text} onReload={banner.conflict ? onReload : undefined} />
        ) : null}
        <Field
          id="decide-comment"
          label={mode === "reject" ? "Comment" : "Comment (optional)"}
          required={mode === "reject"}
          error={errors.comment?.message}
          counter={{ value: comment.length, max: LIMITS.approvalCommentMax }}
        >
          <Textarea
            id="decide-comment"
            rows={3}
            {...register("comment")}
            {...describedBy("decide-comment", false, errors.comment?.message)}
          />
        </Field>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant={mode === "reject" ? "secondary" : "default"}
            disabled={act.isPending}
          >
            {act.isPending ? "Working…" : mode === "approve" ? "Approve" : "Reject with comment"}
          </Button>
        </DialogFooter>
      </form>
    </Frame>
  );
}

/** Member picker over the workspace's members (the server rejects an ineligible person, `assignee_not_eligible`). */
export function AssigneePicker({
  workspaceId,
  value,
  onChange,
  label = "Assignee",
  id,
  invalid,
  describedby,
  excludeUserId,
  placeholder = "Choose a person",
}) {
  const load = useCallback(
    async (query, { signal }) => {
      const people = await findingsService.assignees(workspaceId, query, { signal });
      return people
        .filter((p) => p.id !== excludeUserId)
        .map((p) => ({ value: p.id, label: p.displayName }));
    },
    [workspaceId, excludeUserId],
  );
  const [picked, setPicked] = useState(null);
  return (
    <Combobox
      id={id}
      aria-label={label}
      aria-describedby={describedby}
      loadOptions={load}
      options={picked ? [picked] : []}
      value={value || null}
      onChange={(v, option) => {
        setPicked(option ?? null);
        onChange(v ?? "");
      }}
      placeholder={placeholder}
      searchPlaceholder="Search members"
      invalid={invalid}
    />
  );
}

/**
 * Assign or reassign one finding (`finding.assign`; the server lists only eligible assignees).
 * @param {{ workspaceId: string, finding: any, onClose: () => void, onReload?: () => void }} props
 */
export function AssignDialog({ workspaceId, finding, onClose, onReload }) {
  const { act, banner, run } = useSubmit(workspaceId);
  const {
    register,
    control,
    handleSubmit,
    setError,
    setFocus,
    watch,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(assignFormSchema),
    defaultValues: { assigneeUserId: "", note: "" },
  });
  const note = watch("note") ?? "";
  const submit = handleSubmit((values) =>
    run(
      (s, key) =>
        s.assign(
          finding.id,
          {
            assigneeUserId: values.assigneeUserId,
            ...(values.note ? { note: values.note } : {}),
            expectedRev: finding.rev,
          },
          key,
        ),
      {
        setError,
        setFocus,
        fields: ["assigneeUserId", "note"],
        onDone: () => {
          toast.success("Assigned");
          onClose();
        },
      },
    ),
  );
  const re = finding.status === "assigned" || finding.status === "in_remediation";
  return (
    <Frame
      title={re ? "Reassign finding" : "Assign finding"}
      description="Choose the person who will fix this. They are notified and the SLA clock keeps running."
      onClose={onClose}
    >
      <form onSubmit={submit} noValidate className="space-y-4">
        {banner ? (
          <ConflictBanner text={banner.text} onReload={banner.conflict ? onReload : undefined} />
        ) : null}
        <Field id="assign-who" label="Assignee" required error={errors.assigneeUserId?.message}>
          <Controller
            control={control}
            name="assigneeUserId"
            render={({ field }) => (
              <AssigneePicker
                id="assign-who"
                workspaceId={workspaceId}
                value={field.value}
                onChange={field.onChange}
                invalid={Boolean(errors.assigneeUserId)}
                describedby={errors.assigneeUserId ? "assign-who-error" : undefined}
              />
            )}
          />
        </Field>
        <Field
          id="assign-note"
          label="Note (optional)"
          error={errors.note?.message}
          counter={{ value: note.length, max: LIMITS.assignmentNoteMax }}
        >
          <Textarea
            id="assign-note"
            rows={2}
            {...register("note")}
            {...describedBy("assign-note", false, errors.note?.message)}
          />
        </Field>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={act.isPending}>
            {act.isPending ? "Assigning…" : re ? "Reassign" : "Assign"}
          </Button>
        </DialogFooter>
      </form>
    </Frame>
  );
}

/**
 * Submit a fix: PR link, ticket key, note (SCREENS 6, 10). The sentence says what happens next: it is NOT verified yet.
 * @param {{ workspaceId: string, finding: any, onClose: () => void, onReload?: () => void, onDone?: () => void }} props
 */
export function SubmitFixDialog({ workspaceId, finding, onClose, onReload, onDone }) {
  const { act, banner, run } = useSubmit(workspaceId);
  const {
    register,
    handleSubmit,
    setError,
    setFocus,
    watch,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(submitFixSchema),
    defaultValues: { pullRequestUrl: "", ticketKey: "", note: "" },
  });
  const note = watch("note") ?? "";
  const submit = handleSubmit((v) =>
    run(
      (s, key) =>
        s.submitRemediation(
          finding.id,
          {
            ...(v.pullRequestUrl ? { pullRequestUrl: v.pullRequestUrl } : {}),
            ...(v.ticketKey ? { ticketKey: v.ticketKey } : {}),
            ...(v.note ? { note: v.note } : {}),
            expectedRev: finding.rev,
          },
          key,
        ),
      {
        setError,
        setFocus,
        fields: ["note"],
        onDone: () => {
          toast.success("Fix submitted. It is verified by the next complete scan.");
          onDone?.();
          onClose();
        },
      },
    ),
  );
  return (
    <Frame
      title="Submit fix"
      description="This marks the fix as submitted. It becomes Verified fixed only after the next complete scan finds it gone."
      onClose={onClose}
    >
      <form onSubmit={submit} noValidate className="space-y-4">
        {banner ? (
          <ConflictBanner text={banner.text} onReload={banner.conflict ? onReload : undefined} />
        ) : null}
        <Field
          id="fix-pr"
          label="Pull request link (optional)"
          hint="An https link, for example your pull request."
          error={errors.pullRequestUrl?.message}
        >
          <Input
            id="fix-pr"
            inputMode="url"
            autoComplete="off"
            {...register("pullRequestUrl")}
            {...describedBy("fix-pr", true, errors.pullRequestUrl?.message)}
          />
        </Field>
        <Field
          id="fix-ticket"
          label="Ticket key (optional)"
          hint="Shown as text, for example SEC-123."
          error={errors.ticketKey?.message}
        >
          <Input
            id="fix-ticket"
            autoComplete="off"
            className="font-mono"
            {...register("ticketKey")}
            {...describedBy("fix-ticket", true, errors.ticketKey?.message)}
          />
        </Field>
        <Field
          id="fix-note"
          label="Note (optional)"
          error={errors.note?.message}
          counter={{ value: note.length, max: LIMITS.remediationNoteMax }}
        >
          <Textarea
            id="fix-note"
            rows={2}
            {...register("note")}
            {...describedBy("fix-note", false, errors.note?.message)}
          />
        </Field>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={act.isPending}>
            {act.isPending ? "Submitting…" : "Submit fix"}
          </Button>
        </DialogFooter>
      </form>
    </Frame>
  );
}
