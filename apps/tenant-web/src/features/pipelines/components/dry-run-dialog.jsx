import { evaluatePipelineTriggers, toDryRunDecision, isValidRefName } from "@qmentisai/shared";
import { useState } from "react";
import { Badge } from "@/components/ui/badge.jsx";
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
import { describeError } from "@/lib/api/index.js";
import { DRY_RUN_DECISIONS, DRY_RUN_REASONS } from "../constants/index.js";
import { useDryRun } from "../hooks/use-pipelines.js";
import { EffectiveStateChip } from "./pipeline-bits.jsx";

const PR_ACTIONS = [
  "opened",
  "synchronize",
  "reopened",
  "ready_for_review",
  "closed",
  "edited",
  "converted_to_draft",
];

function ResultList({ items }) {
  return (
    <div aria-live="polite" className="space-y-3">
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">No pipeline to test.</p>
      ) : null}
      {items.map((item) => (
        <div key={item.pipelineId} className="rounded-md border border-border p-3 text-sm">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="font-medium">{item.pipelineName}</span>
            <EffectiveStateChip state={item.effectiveState} />
          </div>
          {item.triggers.length === 0 ? (
            <p className="text-muted-foreground">
              This pipeline has no trigger for this kind of event.
            </p>
          ) : (
            <ul className="space-y-2">
              {item.triggers.map((t) => {
                const d = DRY_RUN_DECISIONS[t.decision];
                const Icon = d.icon;
                return (
                  <li key={t.triggerKey} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs">{t.triggerKey}</span>
                    <Badge tone={d.tone}>
                      <Icon aria-hidden="true" />
                      {d.label}
                    </Badge>
                    {t.decision === "would_run" ? (
                      <span className="text-muted-foreground">
                        {t.scanKind === "full" ? "Full scan" : "Incremental scan"}
                        {t.trust === "untrusted_fork" ? " · untrusted fork (no credentials)" : ""}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">
                        {t.reasons
                          .map((r) => DRY_RUN_REASONS[r] ?? r.replace(/_/g, " "))
                          .join(", ")}
                      </span>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

/** The sample event of the form -> API body. */
function toBody(form, pipelineId) {
  return form.event === "push"
    ? {
        event: "push",
        ...(form.kind === "tag" ? { tag: form.ref } : { branch: form.ref }),
        created: form.created,
        forced: form.forced,
        ...(pipelineId ? { pipelineId } : {}),
      }
    : {
        event: "pull_request",
        action: form.action,
        number: 1,
        baseRef: form.ref,
        isFork: form.isFork,
        draft: form.draft,
        ...(pipelineId ? { pipelineId } : {}),
      };
}

function Body({ pipeline, draft, onOpenChange }) {
  const dry = useDryRun();
  const [local, setLocal] = useState(null);
  const [form, setForm] = useState({
    event: "push",
    kind: "branch",
    ref: draft?.defaultBranch ?? "main",
    created: false,
    forced: false,
    action: "opened",
    isFork: false,
    draft: false,
  });
  const set = (patch) => setForm((f) => ({ ...f, ...patch }));
  const problem = !isValidRefName(form.ref) ? "This is not a valid branch or tag name." : null;
  const repositoryId = pipeline?.repositoryId ?? draft?.repositoryId;

  const test = (event) => {
    event.preventDefault();
    if (problem) return;
    if (draft) {
      // The wizard tests the UNSAVED draft in the browser with the same pure evaluator the API and the worker use.
      const sample =
        form.event === "push"
          ? {
              kind: "push",
              ref: `refs/${form.kind === "tag" ? "tags" : "heads"}/${form.ref}`,
              branch: form.kind === "tag" ? null : form.ref,
              created: form.created,
              forced: form.forced,
              deleted: false,
            }
          : {
              kind: "pull_request",
              action: form.action,
              number: 1,
              baseRef: form.ref,
              isFork: form.isFork,
              draft: form.draft,
              merged: false,
            };
      const evaluations = evaluatePipelineTriggers({
        config: draft.config,
        event: sample,
        repository: { defaultBranch: draft.defaultBranch },
        effectiveState: "running_normally",
      });
      setLocal({
        items: [
          {
            pipelineId: "draft",
            pipelineName: draft.name || "This draft",
            effectiveState: "running_normally",
            triggers: evaluations.map((e) => ({
              triggerKey: e.triggerKey,
              triggerType: e.triggerType,
              decision: toDryRunDecision(e),
              reasons: e.reasons,
              scanKind: e.scanKind,
              trust: e.trust,
            })),
          },
        ],
      });
      return;
    }
    dry.mutate({ repositoryId, body: toBody(form, pipeline?.id) });
  };
  const result = draft ? local : dry.data;
  return (
    <DialogContent className="max-w-xl">
      <form onSubmit={test}>
        <DialogHeader>
          <DialogTitle>Test triggers</DialogTitle>
          <DialogDescription>
            {draft
              ? "Checks a sample event against the triggers you are editing now (nothing is saved)."
              : "Checks a sample event against the pipeline's saved configuration. It has no side effects and creates no request."}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="dry-event">Sample event</Label>
              <Select
                id="dry-event"
                value={form.event}
                onChange={(e) => set({ event: e.target.value, action: "opened" })}
              >
                <option value="push">Push</option>
                <option value="pull_request">Pull request</option>
              </Select>
            </div>
            {form.event === "push" ? (
              <div className="space-y-1.5">
                <Label htmlFor="dry-kind">Pushed</Label>
                <Select
                  id="dry-kind"
                  value={form.kind}
                  onChange={(e) => set({ kind: e.target.value })}
                >
                  <option value="branch">A branch</option>
                  <option value="tag">A tag</option>
                </Select>
              </div>
            ) : (
              <div className="space-y-1.5">
                <Label htmlFor="dry-action">Action</Label>
                <Select
                  id="dry-action"
                  value={form.action}
                  onChange={(e) => set({ action: e.target.value })}
                >
                  {PR_ACTIONS.map((a) => (
                    <option key={a} value={a}>
                      {a.replace(/_/g, " ")}
                    </option>
                  ))}
                </Select>
              </div>
            )}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="dry-ref">
              {form.event === "push"
                ? form.kind === "tag"
                  ? "Tag name"
                  : "Branch name"
                : "Target branch"}
            </Label>
            <Input
              id="dry-ref"
              className="font-mono"
              value={form.ref}
              onChange={(e) => set({ ref: e.target.value })}
              aria-invalid={Boolean(problem)}
              autoComplete="off"
              spellCheck={false}
            />
            {problem ? <p className="text-xs text-status-danger">{problem}</p> : null}
          </div>
          <div className="flex flex-wrap gap-4 text-sm">
            {form.event === "push" ? (
              <>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.created}
                    onChange={(e) => set({ created: e.target.checked })}
                  />
                  New branch or tag
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.forced}
                    onChange={(e) => set({ forced: e.target.checked })}
                  />
                  Force push
                </label>
              </>
            ) : (
              <>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.isFork}
                    onChange={(e) => set({ isFork: e.target.checked })}
                  />
                  From a fork
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.draft}
                    onChange={(e) => set({ draft: e.target.checked })}
                  />
                  Draft
                </label>
              </>
            )}
          </div>
          {dry.error ? (
            <p role="alert" className="text-sm text-status-danger">
              {describeError(dry.error)}
            </p>
          ) : null}
          {result ? <ResultList items={result.items} /> : null}
        </div>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          <Button type="submit" variant="secondary" disabled={dry.isPending || Boolean(problem)}>
            {dry.isPending ? "Testing…" : "Test"}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

/**
 * Dry run (SPEC §8): `pipeline` tests the saved configuration through the API; `draft` ({ repositoryId, defaultBranch,
 * name, config }) tests the wizard's unsaved configuration in the browser with the shared evaluator. Needs `pipeline.view`.
 */
export function DryRunDialog({ pipeline, draft, open, onOpenChange }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open ? <Body pipeline={pipeline} draft={draft} onOpenChange={onOpenChange} /> : null}
    </Dialog>
  );
}
