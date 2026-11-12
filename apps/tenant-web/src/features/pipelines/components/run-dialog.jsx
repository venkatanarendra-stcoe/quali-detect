import { useRef, useState } from "react";
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
import { Label } from "@/components/ui/label.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useBranches } from "@/features/repositories/hooks/use-repositories.js";
import { describeError, isApiError } from "@/lib/api/index.js";
import { isValidRefName } from "@qmentisai/shared";
import { CONFLICT_MESSAGES } from "../constants/index.js";
import { useRunPipeline } from "../hooks/use-pipelines.js";
import { newIdempotencyKey } from "../services/pipelines-service.js";

/** The refusal of a manual run in plain words: the stable reason when the API sent one, else its client-safe message. */
export function runRefusal(error) {
  if (!isApiError(error)) return describeError(error);
  const reason = error.details?.reason;
  if (reason && CONFLICT_MESSAGES[reason]) return CONFLICT_MESSAGES[reason];
  if (error.code === "QUOTA_EXCEEDED")
    return "The monthly scan quota is used up, so no more runs can be requested.";
  if (error.status === 403) return "You don't have permission to run pipelines in this workspace.";
  if (error.status === 404) return "This pipeline no longer exists or is not visible to you.";
  return describeError(error);
}

function Body({ pipeline, onOpenChange }) {
  const run = useRunPipeline();
  const [refType, setRefType] = useState("branch");
  const [refName, setRefName] = useState("");
  const [scanKind, setScanKind] = useState("");
  const branches = useBranches(pipeline.repositoryId);
  // One Idempotency-Key per attempt: a retry of the SAME request reuses it, a changed request gets a new one.
  const attempt = useRef({ signature: "", key: "" });
  const trimmed = refName.trim();
  const refProblem =
    trimmed && !isValidRefName(trimmed) ? "This is not a valid branch or tag name." : null;
  const body = {
    ...(trimmed ? { ref: { type: refType, name: trimmed } } : {}),
    ...(scanKind ? { scanKind } : {}),
  };
  const submit = (event) => {
    event.preventDefault();
    if (refProblem || run.isPending) return;
    const signature = JSON.stringify(body);
    if (attempt.current.signature !== signature)
      attempt.current = { signature, key: newIdempotencyKey() };
    run.mutate(
      { pipelineId: pipeline.id, body, idempotencyKey: attempt.current.key },
      {
        onSuccess: ({ execution }) => {
          toast.success(`Run requested: ${execution.refName} (${execution.status})`);
          onOpenChange(false);
        },
      },
    );
  };
  const names = branches.data?.items?.map((b) => b.name) ?? [];
  return (
    <DialogContent>
      <form onSubmit={submit}>
        <DialogHeader>
          <DialogTitle>Run now</DialogTitle>
          <DialogDescription>
            Request a manual scan of <span className="font-medium">{pipeline.name}</span>. It is
            queued as one execution request. Scans read manifests and lockfiles; they never run
            repository code.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-[8rem_1fr]">
            <div className="space-y-1.5">
              <Label htmlFor="run-ref-type">Ref type</Label>
              <Select
                id="run-ref-type"
                value={refType}
                onChange={(e) => setRefType(e.target.value)}
              >
                <option value="branch">Branch</option>
                <option value="tag">Tag</option>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="run-ref">{refType === "tag" ? "Tag" : "Branch"}</Label>
              <Input
                id="run-ref"
                className="font-mono"
                value={refName}
                list={refType === "branch" ? "run-branches" : undefined}
                onChange={(e) => setRefName(e.target.value)}
                placeholder="Default branch of the repository"
                aria-invalid={Boolean(refProblem)}
                aria-describedby="run-ref-hint"
                autoComplete="off"
                spellCheck={false}
              />
              <datalist id="run-branches">
                {names.map((n) => (
                  <option key={n} value={n} />
                ))}
              </datalist>
              <p
                id="run-ref-hint"
                className={
                  refProblem ? "text-xs text-status-danger" : "text-xs text-subtle-foreground"
                }
              >
                {refProblem ?? "Leave empty to scan the repository's default branch."}
              </p>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="run-kind">Scan kind</Label>
            <Select id="run-kind" value={scanKind} onChange={(e) => setScanKind(e.target.value)}>
              <option value="">Use the pipeline setting</option>
              <option value="full">Full scan</option>
              <option value="incremental">Incremental scan</option>
            </Select>
          </div>
          {run.error ? (
            <div
              role="alert"
              className="rounded-md border border-border-strong bg-secondary p-3 text-sm"
            >
              <p className="font-medium text-status-danger">The run was not requested.</p>
              <p>{runRefusal(run.error)}</p>
              {isApiError(run.error) && run.error.correlationId ? (
                <p className="mt-1 text-xs text-subtle-foreground">
                  Reference <span className="font-mono">{run.error.correlationId}</span>
                </p>
              ) : null}
            </div>
          ) : null}
        </div>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button type="submit" disabled={run.isPending || Boolean(refProblem)}>
            {run.isPending ? "Requesting…" : run.error ? "Try again" : "Run now"}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

/** Manual run dialog (SPEC §6.3). Needs `execution.run`; the caller decides whether to open it (the API enforces regardless). */
export function RunDialog({ pipeline, open, onOpenChange }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open ? <Body pipeline={pipeline} onOpenChange={onOpenChange} /> : null}
    </Dialog>
  );
}
