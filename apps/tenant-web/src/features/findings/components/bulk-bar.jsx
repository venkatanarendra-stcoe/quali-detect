import { zodResolver } from "@hookform/resolvers/zod";
import { CircleCheck, CircleX } from "lucide-react";
import { useRef, useState } from "react";
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
import { Textarea } from "@/components/ui/textarea.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import {
  BULK_ASSIGN_STATUSES,
  BULK_MAX,
  BULK_START_REVIEW_STATUSES,
  CONFLICT_TEXT,
  LIMITS,
} from "../constants/index.js";
import { describeActionError, useFindingAction } from "../hooks/use-findings.js";
import { assignFormSchema } from "../schemas/forms.js";
import { newIdempotencyKey } from "../services/findings-service.js";
import { useFindingsUiStore } from "../stores/findings-ui-store.js";
import { AssigneePicker } from "./action-dialogs.jsx";
import { ConflictBanner, Field, describedBy } from "./form-bits.jsx";

const OUTCOME_TEXT = {
  RESOURCE_NOT_FOUND: "Not found",
  FORBIDDEN: "You can't change this finding",
  VALIDATION_FAILED: "This person can't be assigned this finding",
  FINDING_STATE_CONFLICT: "Not changed",
};

/** Per-finding outcomes of a bulk action (SCREENS 4: "the result dialog lists per-finding outcomes"). */
function ResultDialog({ title, results, titles, onClose }) {
  const ok = results.filter((r) => r.ok).length;
  return (
    <Dialog open onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {ok} of {results.length} findings changed.
          </DialogDescription>
        </DialogHeader>
        <ul className="max-h-72 space-y-1.5 overflow-y-auto text-sm" aria-label="Results">
          {results.map((r) => (
            <li key={r.findingId} className="flex items-start gap-2">
              {r.ok ? (
                <CircleCheck
                  aria-hidden="true"
                  className="mt-0.5 size-4 shrink-0 text-status-success"
                />
              ) : (
                <CircleX aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-status-danger" />
              )}
              <span className="min-w-0 flex-1 break-words">
                {titles[r.findingId] ?? r.findingId}
              </span>
              <span className="shrink-0 text-muted-foreground">
                {r.ok
                  ? "Done"
                  : `${OUTCOME_TEXT[r.errorCode] ?? "Failed"}${r.reason ? `: ${CONFLICT_TEXT[r.reason] ?? r.reason.replaceAll("_", " ")}` : ""}`}
              </span>
            </li>
          ))}
        </ul>
        <DialogFooter>
          <Button onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function BulkAssignDialog({ workspaceId, ids, titles, onClose, onResult }) {
  const act = useFindingAction(workspaceId);
  const key = useRef(newIdempotencyKey());
  const [banner, setBanner] = useState(null);
  const {
    register,
    control,
    handleSubmit,
    watch,
    setError,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(assignFormSchema),
    defaultValues: { assigneeUserId: "", note: "" },
  });
  const note = watch("note") ?? "";
  const submit = handleSubmit(async (v) => {
    try {
      const result = await act.mutateAsync({
        run: (s) =>
          s.bulkAssign(
            {
              workspaceId,
              findingIds: ids,
              assigneeUserId: v.assigneeUserId,
              ...(v.note ? { note: v.note } : {}),
            },
            key.current,
          ),
      });
      onResult(result.results, titles);
    } catch (error) {
      const { text, field } = describeActionError(error);
      if (field === "note") setError("note", { message: text });
      else setBanner({ text });
    }
  });
  return (
    <Dialog open onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            Assign {ids.length} {ids.length === 1 ? "finding" : "findings"}
          </DialogTitle>
          <DialogDescription>
            Choose the person who will fix them. Each finding is checked separately.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} noValidate className="space-y-4">
          {banner ? <ConflictBanner text={banner.text} /> : null}
          <Field id="bulk-who" label="Assignee" required error={errors.assigneeUserId?.message}>
            <Controller
              control={control}
              name="assigneeUserId"
              render={({ field }) => (
                <AssigneePicker
                  id="bulk-who"
                  workspaceId={workspaceId}
                  value={field.value}
                  onChange={field.onChange}
                  invalid={Boolean(errors.assigneeUserId)}
                />
              )}
            />
          </Field>
          <Field
            id="bulk-note"
            label="Note (optional)"
            error={errors.note?.message}
            counter={{ value: note.length, max: LIMITS.assignmentNoteMax }}
          >
            <Textarea
              id="bulk-note"
              rows={2}
              {...register("note")}
              {...describedBy("bulk-note", false, errors.note?.message)}
            />
          </Field>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={act.isPending}>
              {act.isPending ? "Assigning…" : "Assign"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Bulk actions of T-31 (SCREENS 4, D-29): Start review and Assign only, at most 50 rows, same workspace, no export and no bulk
 * decision. An action the user can never perform is hidden; ineligible rows are explained in words and left out of the request.
 * @param {{ workspaceId: string }} props
 */
export function BulkBar({ workspaceId }) {
  const can = useCan();
  const selected = useFindingsUiStore((s) => s.selected);
  const clear = useFindingsUiStore((s) => s.clear);
  const act = useFindingAction(workspaceId);
  const [dialog, setDialog] = useState(null);
  const [result, setResult] = useState(null);
  const entries = Object.entries(selected);
  const count = entries.length;
  const titles = Object.fromEntries(entries.map(([id, v]) => [id, v.title]));
  const eligible = (statuses) =>
    entries.filter(([, v]) => statuses.includes(v.status)).map(([id]) => id);
  const canReview = can("finding.review");
  const canAssign = can("finding.assign");
  const startIds = eligible(BULK_START_REVIEW_STATUSES);
  const assignIds = eligible(BULK_ASSIGN_STATUSES);

  const startReview = async () => {
    try {
      const out = await act.mutateAsync({
        run: (s) => s.bulkClaim({ workspaceId, findingIds: startIds }, newIdempotencyKey()),
      });
      setResult({ title: "Start review", results: out.results, titles });
      clear();
    } catch (error) {
      toast.error(describeActionError(error).text);
    }
  };

  return (
    <>
      <div className="mb-3 shrink-0 space-y-1" aria-live="polite">
        {count > 0 && (canReview || canAssign) ? (
          <div className="flex flex-wrap items-center gap-2 rounded-md border border-border-strong bg-secondary px-3 py-2 text-sm">
            <span className="font-medium">
              {count} selected{count >= BULK_MAX ? ` (the most you can select)` : ""}
            </span>
            {canReview ? (
              <Button
                size="sm"
                variant="secondary"
                disabled={startIds.length === 0 || act.isPending}
                onClick={startReview}
              >
                Start review{startIds.length ? ` (${startIds.length})` : ""}
              </Button>
            ) : null}
            {canAssign ? (
              <Button
                size="sm"
                variant="secondary"
                disabled={assignIds.length === 0}
                onClick={() => setDialog("assign")}
              >
                Assign{assignIds.length ? ` (${assignIds.length})` : ""}
              </Button>
            ) : null}
            <Button size="sm" variant="ghost" onClick={clear}>
              Clear selection
            </Button>
          </div>
        ) : null}
        {count > 0 && canAssign && assignIds.length < count ? (
          <p className="text-xs text-muted-foreground">
            {count - assignIds.length} of {count} selected findings can&apos;t be assigned (not
            confirmed yet).
          </p>
        ) : null}
        {count > 0 && canReview && startIds.length < count ? (
          <p className="text-xs text-muted-foreground">
            {count - startIds.length} of {count} selected findings can&apos;t start review (already
            in review or decided).
          </p>
        ) : null}
      </div>
      {dialog === "assign" ? (
        <BulkAssignDialog
          workspaceId={workspaceId}
          ids={assignIds}
          titles={titles}
          onClose={() => setDialog(null)}
          onResult={(results, t) => {
            setDialog(null);
            setResult({ title: "Assign", results, titles: t });
            clear();
          }}
        />
      ) : null}
      {result ? <ResultDialog {...result} onClose={() => setResult(null)} /> : null}
    </>
  );
}
