import { AppPageLayout, WizardLayout } from "@qmentisai/ui";
import { useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { toast } from "sonner";
import { Pager } from "@/components/common/pager.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useWorkspaceLinks } from "@/features/integrations/hooks/use-integrations.js";
import {
  LinkStatus,
  LinkStatusNotice,
  isLinkBroken,
  statusSummary,
} from "@/features/integrations/components/link-status.jsx";
import { describeError } from "@/lib/api/index.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { useAvailableRepositories, useConnectRepository } from "../hooks/use-repositories.js";
import { newIdempotencyKey } from "../services/repositories-service.js";

const STEPS = [
  { id: "provider", label: "Provider" },
  { id: "select", label: "Select repositories" },
  { id: "review", label: "Review" },
];

/**
 * T-23 Connect repository wizard: provider -> select repositories -> review. Repositories are connected one request each
 * (a failure of one does not undo the others); each carries its own Idempotency-Key, reused when the user retries.
 */
export function ConnectRepositoryPage() {
  const { workspaceId } = useParams();
  const navigate = useNavigate();
  const can = useCan();
  const installations = useWorkspaceLinks(workspaceId);
  const connect = useConnectRepository(workspaceId);
  const [step, setStep] = useState(0);
  const [linkId, setLinkId] = useState("");
  const [search, setSearch] = useState("");
  const q = useDebouncedValue(search);
  const [page, setPage] = useState(1);
  const [picked, setPicked] = useState(() => new Map()); // externalRepoId -> repo
  const [results, setResults] = useState({}); // externalRepoId -> "pending" | "done" | error message
  const keys = useRef(new Map());

  const links = useMemo(() => installations.data ?? [], [installations.data]);
  // Revoked and suspended links are listed but never selectable (SPEC §16.2); a lone usable link is preselected.
  const usable = useMemo(() => links.filter((l) => !isLinkBroken(l)), [links]);
  const brokenLinks = links.filter(isLinkBroken);
  const selected =
    linkId && usable.some((l) => l.id === linkId)
      ? linkId
      : usable.length === 1
        ? usable[0].id
        : "";
  const available = useAvailableRepositories(
    workspaceId,
    { workspaceLinkId: selected, q: q.trim() || undefined, page, pageSize: 30 },
    { enabled: step === 1 && Boolean(selected) },
  );

  if (!can("repository.connect"))
    return (
      <EmptyState
        title="You can't connect repositories here"
        description="You need the repository.connect permission in this workspace."
      />
    );

  const toggle = (repo) =>
    setPicked((current) => {
      const next = new Map(current);
      next.has(repo.externalRepoId)
        ? next.delete(repo.externalRepoId)
        : next.set(repo.externalRepoId, repo);
      return next;
    });

  const submit = async () => {
    for (const repo of picked.values()) {
      if (results[repo.externalRepoId] === "done") continue;
      if (!keys.current.has(repo.externalRepoId))
        keys.current.set(repo.externalRepoId, newIdempotencyKey());
      setResults((r) => ({ ...r, [repo.externalRepoId]: "pending" }));
      try {
        await connect.mutateAsync({
          body: { workspaceLinkId: selected, externalRepoId: repo.externalRepoId },
          idempotencyKey: keys.current.get(repo.externalRepoId),
        });
        setResults((r) => ({ ...r, [repo.externalRepoId]: "done" }));
      } catch (error) {
        setResults((r) => ({ ...r, [repo.externalRepoId]: describeError(error) }));
      }
    }
  };
  const allDone = picked.size > 0 && [...picked.keys()].every((id) => results[id] === "done");
  const anyFailed = [...picked.keys()].some(
    (id) => results[id] && results[id] !== "done" && results[id] !== "pending",
  );
  const running = [...picked.keys()].some((id) => results[id] === "pending");
  const back = `/workspaces/${workspaceId}/repositories`;

  const account = links.find((l) => l.id === selected)?.account.login;
  const cancel = (
    <Button variant="ghost" asChild>
      <Link to={back}>Cancel</Link>
    </Button>
  );
  const actions =
    step === 0 ? (
      <>
        {cancel}
        <Button disabled={!selected} onClick={() => setStep(1)}>
          Next
        </Button>
      </>
    ) : step === 1 ? (
      <>
        {cancel}
        <div className="flex gap-2">
          <Button variant="secondary" onClick={() => setStep(0)}>
            Back
          </Button>
          <Button disabled={picked.size === 0} onClick={() => setStep(2)}>
            Review ({picked.size})
          </Button>
        </div>
      </>
    ) : (
      <>
        {cancel}
        <div className="flex gap-2">
          <Button variant="secondary" disabled={running} onClick={() => setStep(1)}>
            Back
          </Button>
          {allDone ? (
            <Button
              onClick={() => {
                toast.success(`${picked.size} repositories connected`);
                navigate(back);
              }}
            >
              Done
            </Button>
          ) : (
            <Button disabled={running} onClick={submit}>
              {anyFailed
                ? "Retry failed"
                : `Connect ${picked.size} ${picked.size === 1 ? "repository" : "repositories"}`}
            </Button>
          )}
        </div>
      </>
    );

  return (
    <AppPageLayout
      title="Connect repository"
      description="Choose repositories from a linked GitHub account."
      scroll={false}
    >
      <WizardLayout
        fill
        steps={STEPS}
        current={STEPS[step].id}
        stepperLabel="Connect steps"
        onStepChange={(id) => setStep(STEPS.findIndex((x) => x.id === id))}
        stepDisabled={Object.fromEntries(STEPS.map((x, i) => [x.id, i > step || running]))}
        stepStatus={Object.fromEntries(
          STEPS.map((x, i) => [x.id, i < step || (allDone && i === 2) ? "complete" : undefined]),
        )}
        summaryTitle="Connection summary"
        summary={
          <Card className="h-fit">
            <CardHeader>
              <CardTitle className="text-sm">Connection summary</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="space-y-2 text-sm">
                <div>
                  <dt className="text-muted-foreground">Provider</dt>
                  <dd>GitHub</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Account</dt>
                  <dd className="break-words">{account ?? "—"}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Repositories</dt>
                  <dd>
                    {picked.size === 0 ? (
                      "—"
                    ) : (
                      <ul className="space-y-1">
                        {[...picked.values()].map((r) => (
                          <li
                            key={r.externalRepoId}
                            className="font-mono text-xs [overflow-wrap:anywhere]"
                          >
                            {r.fullName}
                          </li>
                        ))}
                      </ul>
                    )}
                  </dd>
                </div>
              </dl>
            </CardContent>
          </Card>
        }
        actions={actions}
      >
        {step === 0 ? (
          <section aria-labelledby="provider-heading" className="space-y-4">
            <h2 id="provider-heading" className="text-base font-semibold">
              GitHub
            </h2>
            {installations.isPending ? (
              <LoadingState label="Loading linked accounts" rows={2} />
            ) : null}
            {installations.isError ? (
              <QueryErrorState error={installations.error} onRetry={installations.refetch} />
            ) : null}
            {installations.data && links.length === 0 ? (
              <EmptyState
                title="No GitHub account available"
                description={
                  can("workspace_integration.manage")
                    ? "Link a GitHub account to this workspace first."
                    : "No GitHub account is linked to this workspace. Ask a workspace administrator."
                }
                actions={
                  can("workspace_integration.manage") ? (
                    <Button asChild variant="secondary">
                      <Link to={`/workspaces/${workspaceId}/integrations`}>
                        Workspace integrations
                      </Link>
                    </Button>
                  ) : null
                }
              />
            ) : null}
            {links.length > 0 ? (
              <div className="max-w-sm space-y-2">
                <label htmlFor="link" className="text-sm font-medium">
                  GitHub account
                </label>
                <Select id="link" value={selected} onChange={(e) => setLinkId(e.target.value)}>
                  <option value="">Select an account</option>
                  {links.map((l) => (
                    <option key={l.id} value={l.id} disabled={isLinkBroken(l)}>
                      {l.account.login}
                      {isLinkBroken(l) ? ` (${statusSummary(l)})` : ""}
                    </option>
                  ))}
                </Select>
                {selected ? <LinkStatus link={links.find((l) => l.id === selected)} /> : null}
              </div>
            ) : null}
            {brokenLinks.length > 0 ? (
              <div className="max-w-xl space-y-2">
                {brokenLinks.map((l) => (
                  <div key={l.id} className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-sm">
                      <span className="font-mono">{l.account.login}</span>
                      <LinkStatus link={l} />
                      <span className="text-muted-foreground">Not selectable</span>
                    </div>
                    <LinkStatusNotice link={l} />
                  </div>
                ))}
              </div>
            ) : null}
            <p className="text-xs text-muted-foreground">
              Events arrive through the GitHub App. Signatures are verified on every delivery.
            </p>
          </section>
        ) : null}

        {step === 1 ? (
          <section aria-labelledby="select-heading" className="space-y-4">
            <h2 id="select-heading" className="text-base font-semibold">
              Select repositories
            </h2>
            <div className="max-w-xs">
              <label htmlFor="available-search" className="sr-only">
                Search repositories
              </label>
              <Input
                id="available-search"
                type="search"
                placeholder="Search repositories"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
              />
            </div>
            {available.isPending ? <LoadingState label="Loading allowed repositories" /> : null}
            {available.isError ? (
              <QueryErrorState error={available.error} onRetry={available.refetch} />
            ) : null}
            {available.data && available.data.items.length === 0 ? (
              q.trim() ? (
                <EmptyState
                  title="No matching repositories"
                  description="Only repositories allowed for this workspace are listed. Try a different search."
                />
              ) : (
                <EmptyState
                  title="No repositories are allowed yet"
                  description={
                    can("workspace_integration.manage")
                      ? "Choose which repositories of this account the workspace may connect in the allow-list on the Integrations page."
                      : "A workspace administrator must allow repositories of this account before they can be connected."
                  }
                  actions={
                    can("workspace_integration.manage") ? (
                      <Button asChild variant="secondary">
                        <Link to={`/workspaces/${workspaceId}/integrations`}>
                          Edit allowed repositories
                        </Link>
                      </Button>
                    ) : null
                  }
                />
              )
            ) : null}
            {available.data && available.data.items.length > 0 ? (
              <>
                <ul className="divide-y divide-border rounded-md border border-border bg-card">
                  {available.data.items.map((repo) => (
                    <li
                      key={repo.externalRepoId}
                      className="flex items-center gap-3 px-3 py-2 text-sm"
                    >
                      <input
                        id={`repo-${repo.externalRepoId}`}
                        type="checkbox"
                        checked={picked.has(repo.externalRepoId) || repo.alreadyConnected}
                        disabled={repo.alreadyConnected}
                        onChange={() => toggle(repo)}
                      />
                      <label
                        htmlFor={`repo-${repo.externalRepoId}`}
                        className="flex flex-1 flex-wrap items-center gap-2"
                      >
                        <span className="font-mono text-xs">{repo.fullName}</span>
                        <span className="text-xs text-muted-foreground">
                          {repo.visibility}
                          {repo.archived ? " · archived" : ""}
                        </span>
                      </label>
                      {repo.alreadyConnected ? (
                        <span className="text-xs text-muted-foreground">Already connected</span>
                      ) : null}
                    </li>
                  ))}
                </ul>
                <Pager pagination={available.data.pagination} onPage={setPage} />
              </>
            ) : null}
          </section>
        ) : null}

        {step === 2 ? (
          <section aria-labelledby="review-heading" className="space-y-4">
            <h2 id="review-heading" className="text-base font-semibold">
              Review
            </h2>
            <ul className="divide-y divide-border rounded-md border border-border bg-card">
              {[...picked.values()].map((repo) => {
                const result = results[repo.externalRepoId];
                return (
                  <li
                    key={repo.externalRepoId}
                    className="flex items-center justify-between gap-3 px-3 py-2 text-sm"
                  >
                    <span className="font-mono text-xs">{repo.fullName}</span>
                    <span role="status" className="text-xs">
                      {result === "pending" ? (
                        "Connecting…"
                      ) : result === "done" ? (
                        "Connected"
                      ) : result ? (
                        <span className="text-status-danger">{result}</span>
                      ) : (
                        "Ready"
                      )}
                    </span>
                  </li>
                );
              })}
            </ul>
            <p className="text-xs text-muted-foreground">
              Connecting saves the repository to this workspace. Pipelines are added separately.
            </p>
          </section>
        ) : null}
      </WizardLayout>
    </AppPageLayout>
  );
}
