import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { PageHeader } from "@/components/common/page-header.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Select } from "@/components/ui/select.jsx";
import {
  useAuthorizeInstallation,
  useDiscoverInstallations,
  useManageableWorkspaces,
  useStartLinking,
} from "../hooks/use-integrations.js";
import { linkErrorMessage } from "../services/link-errors.js";
import { linkHint } from "../services/link-hint.js";

/**
 * Landing page of GitHub's Setup URL (`/integrations/github/setup?installation_id=...`). Anyone can open this URL with any
 * installation id, so it proves nothing: it asks the workspace-scoped API for a single-use state and sends the user to
 * GitHub to authorize, where the real verification starts. The workspace comes from the hint stored by the Integrations
 * page; without it the user picks one where they hold workspace_integration.manage. Without an `installation_id` (the user
 * came here by hand) the page offers the same choice as T-42: install the App, or use an existing installation.
 */
export function GitHubSetupPage() {
  const [params] = useSearchParams();
  const installationId = params.get("installation_id") ?? "";
  const valid = /^\d{1,20}$/.test(installationId);
  const none = !params.has("installation_id");
  const manageable = useManageableWorkspaces();
  const hint = linkHint.read();
  const hinted = manageable.find((w) => w.id === hint) ?? null;
  const [picked, setPicked] = useState("");
  const authorize = useAuthorizeInstallation();
  const started = useRef(false);
  const go = (workspaceId) => {
    started.current = true;
    linkHint.write(workspaceId);
    authorize.mutate(
      { workspaceId, installationId },
      { onSuccess: ({ authorizeUrl }) => window.location.assign(authorizeUrl) },
    );
  };
  const discover = useDiscoverInstallations();
  const start = useStartLinking();
  const [chosen, setChosen] = useState("");
  const workspaceId = hinted?.id ?? chosen;
  const goDiscover = () => {
    linkHint.write(workspaceId);
    discover.mutate(workspaceId, {
      onSuccess: ({ authorizeUrl }) => window.location.assign(authorizeUrl),
    });
  };
  const goInstall = () => {
    linkHint.write(workspaceId);
    start.mutate(workspaceId, {
      onSuccess: ({ installUrl }) => window.location.assign(installUrl),
    });
  };
  useEffect(() => {
    if (started.current || !valid || !hinted) return;
    go(hinted.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once per landing
  }, [valid, hinted?.id]);
  const back = hinted ? `/workspaces/${hinted.id}/integrations` : "/workspaces";
  const choiceError = discover.error ?? start.error;
  const needsPick = valid && !hinted && !authorize.isPending && !authorize.isError;
  return (
    <>
      <PageHeader title="Connecting GitHub" description="Confirming your access with GitHub." />
      {none ? (
        manageable.length === 0 ? (
          <p role="alert" className="text-sm text-status-danger">
            You do not have permission to link source control in any workspace.
          </p>
        ) : (
          <div className="max-w-md space-y-3">
            <p className="text-sm text-muted-foreground">
              GitHub did not send an installation. Install the App on a GitHub account, or use an
              installation that already exists on an account you administer.
            </p>
            {hinted ? (
              <p className="text-sm">
                Workspace: <span className="font-semibold">{hinted.name}</span>
              </p>
            ) : (
              <>
                <label htmlFor="choice-workspace" className="text-sm font-medium">
                  Which workspace should use the GitHub account?
                </label>
                <Select
                  id="choice-workspace"
                  value={chosen}
                  onChange={(e) => setChosen(e.target.value)}
                >
                  <option value="">Select a workspace</option>
                  {manageable.map((w) => (
                    <option key={w.id} value={w.id}>
                      {w.name}
                    </option>
                  ))}
                </Select>
              </>
            )}
            <div className="flex flex-wrap gap-2">
              <Button
                onClick={goDiscover}
                disabled={!workspaceId || discover.isPending || start.isPending}
              >
                Use an existing installation
              </Button>
              <Button
                variant="secondary"
                onClick={goInstall}
                disabled={!workspaceId || discover.isPending || start.isPending}
              >
                Install the App on a GitHub account
              </Button>
            </div>
            {choiceError ? (
              <p role="alert" className="text-sm text-status-danger">
                {linkErrorMessage(choiceError)}
              </p>
            ) : null}
          </div>
        )
      ) : authorize.isError || !valid ? (
        <div role="alert" className="space-y-3">
          <p className="text-sm text-status-danger">
            {!valid
              ? "GitHub did not send an installation to link."
              : linkErrorMessage(authorize.error)}
          </p>
          <Button asChild variant="secondary">
            <Link to={back}>Back to Integrations</Link>
          </Button>
        </div>
      ) : needsPick ? (
        manageable.length === 0 ? (
          <p role="alert" className="text-sm text-status-danger">
            You do not have permission to link source control in any workspace.
          </p>
        ) : (
          <form
            className="max-w-sm space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (picked) go(picked);
            }}
          >
            <label htmlFor="link-workspace" className="text-sm font-medium">
              Which workspace should use this GitHub account?
            </label>
            <Select id="link-workspace" value={picked} onChange={(e) => setPicked(e.target.value)}>
              <option value="">Select a workspace</option>
              {manageable.map((w) => (
                <option key={w.id} value={w.id}>
                  {w.name}
                </option>
              ))}
            </Select>
            <Button type="submit" disabled={!picked}>
              Continue
            </Button>
          </form>
        )
      ) : (
        <LoadingState label="Redirecting to GitHub to confirm your access" />
      )}
    </>
  );
}
