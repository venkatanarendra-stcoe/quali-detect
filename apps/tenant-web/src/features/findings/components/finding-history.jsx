import { zodResolver } from "@hookform/resolvers/zod";
import { Cog, History } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { LIMITS } from "../constants/index.js";
import {
  describeActionError,
  useFindingAction,
  useFindingComments,
  useFindingHistory,
} from "../hooks/use-findings.js";
import { commentFormSchema } from "../schemas/forms.js";
import { newIdempotencyKey } from "../services/findings-service.js";
import { Field, describedBy } from "./form-bits.jsx";
import { StatusBadge, TimeAgo, Untrusted } from "./finding-bits.jsx";

const REASON_TEXT = {
  detected: "Detected",
  review_started: "Review started",
  review_recorded: "Decision recorded",
  review_withdrawn: "Decision withdrawn",
  approved_tp: "Approved as a true positive",
  approved_fp: "Approved as a false positive",
  rejected: "Decision rejected",
  fp_reopened: "Reopened for review",
  rereview: "Reopened for review",
  assigned: "Assigned",
  reassigned: "Reassigned",
  unassigned: "Unassigned",
  work_started: "Work started",
  fix_submitted: "Fix submitted",
  absent_in_complete_scan: "Not found in a complete scan",
  verified: "Verified fixed by a complete scan",
  recurred: "Detected again",
  risk_accepted: "Risk accepted",
  suppressed: "Suppressed",
  risk_acceptance_expired: "Accepted risk expired",
  suppression_expired: "Suppression expired",
  revoked: "Exception revoked",
  severity_increased: "Severity increased",
  exception_requested: "Exception requested",
  exception_rejected: "Exception request rejected",
};
const SYSTEM_NAME = { ingestion: "System (scan)", sla: "System (SLA)", expiry: "System (expiry)" };

/** A rationale or comment clamped to four lines with "Show more" (plain text, never Markdown). */
function ClampedText({ text }) {
  const [open, setOpen] = useState(false);
  const long = text.length > 220 || text.split("\n").length > 4;
  return (
    <>
      <Untrusted className={`mt-1 block text-sm ${open ? "" : "line-clamp-4"}`}>{text}</Untrusted>
      {long ? (
        <button
          type="button"
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
          className="rounded-sm text-xs font-medium underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {open ? "Show less" : "Show more"}
        </button>
      ) : null}
    </>
  );
}

function ListSkeleton({ label }) {
  return (
    <div role="status" aria-busy="true" className="space-y-3">
      <span className="sr-only">{label}</span>
      {Array.from({ length: 4 }, (_, i) => (
        <Skeleton key={i} className="h-14 w-full" />
      ))}
    </div>
  );
}

function LoadMore({ list }) {
  return list.hasMore ? (
    <Button variant="secondary" onClick={list.loadMore} disabled={list.loadingMore}>
      {list.loadingMore ? "Loading…" : "Load more"}
    </Button>
  ) : null;
}

/** The immutable timeline, newest first, keyset "Load more" (SCREENS 6, History). @param {{ workspaceId: string, findingId: string }} props */
export function HistoryTab({ workspaceId, findingId }) {
  const list = useFindingHistory(workspaceId, findingId);
  if (list.isPending) return <ListSkeleton label="Loading history…" />;
  if (list.isError) return <QueryErrorState error={list.error} onRetry={list.refetch} />;
  const items = list.data?.items ?? [];
  if (!items.length)
    return (
      <EmptyState
        icon={History}
        title="No history yet"
        description="Nothing has happened to this finding yet."
      />
    );
  return (
    <div className="space-y-4">
      <ol className="space-y-3" aria-label="History, newest first">
        {items.map((entry) => {
          const system = "system" in entry.actor;
          return (
            <li key={entry.id} className="rounded-md border border-border bg-card p-3">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                <span className="font-medium">
                  {REASON_TEXT[entry.reason] ?? entry.reason ?? entry.type}
                </span>
                {entry.toStatus ? <StatusBadge status={entry.toStatus} /> : null}
                <span className="inline-flex items-center gap-1 text-muted-foreground">
                  {system ? <Cog aria-hidden="true" className="size-3.5" /> : null}
                  {system ? SYSTEM_NAME[entry.actor.system] : entry.actor.displayName}
                </span>
                <span className="text-muted-foreground">
                  <TimeAgo value={entry.at} />
                </span>
              </div>
              {entry.note ? <ClampedText text={entry.note} /> : null}
            </li>
          );
        })}
      </ol>
      <LoadMore list={list} />
    </div>
  );
}

function CommentComposer({ workspaceId, findingId }) {
  const act = useFindingAction(workspaceId);
  const {
    register,
    handleSubmit,
    reset,
    setError,
    setFocus,
    watch,
    formState: { errors },
  } = useForm({ resolver: zodResolver(commentFormSchema), defaultValues: { body: "" } });
  const body = watch("body") ?? "";
  const submit = handleSubmit(async (v) => {
    try {
      await act.mutateAsync({
        run: (s) => s.addComment(findingId, { body: v.body }, newIdempotencyKey()),
      });
      reset();
      toast.success("Comment added");
    } catch (error) {
      const { text, field } = describeActionError(error);
      if (field) {
        setError("body", { message: text });
        setFocus("body");
      } else toast.error(text);
    }
  });
  return (
    <form onSubmit={submit} noValidate className="space-y-2">
      <Field
        id="comment-body"
        label="Add a comment"
        error={errors.body?.message}
        counter={{ value: body.length, max: LIMITS.commentMax }}
      >
        <Textarea
          id="comment-body"
          rows={3}
          {...register("body")}
          {...describedBy("comment-body", false, errors.body?.message)}
        />
      </Field>
      <div className="flex justify-end">
        <Button type="submit" variant="secondary" disabled={act.isPending}>
          {act.isPending ? "Submitting…" : "Submit comment"}
        </Button>
      </div>
    </form>
  );
}

/** Comments: a list (author, time, plain text) and, with `finding.comment`, a composer. No edit, no delete (OQ-7). @param {{ workspaceId: string, findingId: string }} props */
export function CommentsTab({ workspaceId, findingId }) {
  const can = useCan();
  const list = useFindingComments(workspaceId, findingId);
  const items = list.data?.items ?? [];
  return (
    <div className="space-y-4">
      {can("finding.comment") ? (
        <CommentComposer workspaceId={workspaceId} findingId={findingId} />
      ) : (
        <p className="text-sm text-muted-foreground">You can read comments but not add them.</p>
      )}
      {list.isPending ? (
        <ListSkeleton label="Loading comments…" />
      ) : list.isError ? (
        <QueryErrorState error={list.error} onRetry={list.refetch} />
      ) : items.length === 0 ? (
        <p className="text-sm text-muted-foreground">No comments yet.</p>
      ) : (
        <>
          <ul className="space-y-3" aria-label="Comments, newest first">
            {items.map((c) => (
              <li key={c.id} className="rounded-md border border-border bg-card p-3">
                <div className="flex flex-wrap items-center gap-x-3 text-sm">
                  <span className="font-medium">{c.author.displayName}</span>
                  <span className="text-muted-foreground">
                    <TimeAgo value={c.createdAt} />
                  </span>
                </div>
                <ClampedText text={c.body} />
              </li>
            ))}
          </ul>
          <LoadMore list={list} />
        </>
      )}
    </div>
  );
}
