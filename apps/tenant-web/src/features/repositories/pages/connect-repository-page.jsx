import { useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { toast } from "sonner";
import { PageHeader } from "@/components/common/page-header.jsx";
import { Pager } from "@/components/common/pager.jsx";
import { Stepper } from "@/components/common/stepper.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useInstallations } from "@/features/integrations/hooks/use-integrations.js";
import { LinkHealth } from "@/features/integrations/components/link-health.jsx";
import { describeError } from "@/lib/api/index.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { useAvailableRepositories, useConnectRepository } from "../hooks/use-repositories.js";
import { newIdempotencyKey } from "../services/repositories-service.js";

const STEPS = ["Provider", "Select repositories", "Review"];

/**
 * T-23 Connect repository wizard: provider -> select repositories -> review. Repositories are connected one request each
 * (a failure of one does not undo the others); each carries its own Idempotency-Key, reused when the user retries.
 */
export function ConnectRepositoryPage() {
  const { workspaceId } = useParams();
  const navigate = useNavigate();
  const can = useCan();
  const installations = useInstallations();
  const connect = useConnectRepository(workspaceId);
  const [step, setStep] = useState(0);
  const [linkId, setLinkId] = useState("");
  const [search, setSearch] = useState("");
  const q = useDebouncedValue(search);
  const [page, setPage] = useState(1);
  const [picked, setPicked] = useState(() => new Map()); // externalRepoId -> repo
  const [results, setResults] = useState({}); // externalRepoId -> "pending" | "done" | error message
  const keys = useRef(new Map());

  const links = useMemo(
    () =>
      (installations.data ?? []).filter(
        (l) =>
          l.status === "linked" &&
          (l.workspaceScope.length === 0 || l.workspaceScope.includes(workspaceId)),
      ),
    [installations.data, workspaceId],
  );
  const selected = linkId || (links.length === 1 ? links[0].id : "");
  const available = useAvailableRepositories(
    workspaceId,
    { installationId: selected, q: q.trim() || undefined, page, pageSize: 30 },
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
          body: { installationId: selected, externalRepoId: repo.externalRepoId },
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

  return (
    <>
      <PageHeader
        title="Connect repository"
        description="Choose repositories from a linked GitHub account."
      />
      <Stepper steps={STEPS} current={step} />

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
                can("integration.manage")
                  ? "Link a GitHub account first. It must also be allowed for this workspace."
                  : "No linked GitHub account is available to this workspace. Ask an organization administrator."
              }
              actions={
                can("integration.view") ? (
                  <Button asChild variant="secondary">
                    <Link to="/integrations/github">GitHub integration</Link>
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
                  <option key={l.id} value={l.id}>
                    {l.account.login}
                  </option>
                ))}
              </Select>
              {selected ? (
                <LinkHealth status={links.find((l) => l.id === selected)?.health ?? "healthy"} />
              ) : null}
            </div>
          ) : null}
          <p className="text-xs text-muted-foreground">
            Events arrive through the GitHub App. Signatures are verified on every delivery.
          </p>
          <div className="flex gap-2">
            <Button variant="ghost" asChild>
              <Link to={back}>Cancel</Link>
            </Button>
            <Button disabled={!selected} onClick={() => setStep(1)}>
              Next
            </Button>
          </div>
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
          {available.isPending ? <LoadingState label="Loading repositories from GitHub" /> : null}
          {available.isError ? (
            <QueryErrorState error={available.error} onRetry={available.refetch} />
          ) : null}
          {available.data && available.data.items.length === 0 ? (
            <EmptyState
              title="No repositories found"
              description="The GitHub App has no access to matching repositories. Change the App's repository access on GitHub, then search again."
            />
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
          <div className="flex gap-2">
            <Button variant="ghost" onClick={() => setStep(0)}>
              Back
            </Button>
            <Button disabled={picked.size === 0} onClick={() => setStep(2)}>
              Review ({picked.size})
            </Button>
          </div>
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
          <div className="flex gap-2">
            <Button variant="ghost" disabled={running} onClick={() => setStep(1)}>
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
        </section>
      ) : null}
    </>
  );
}
