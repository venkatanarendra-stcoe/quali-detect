import { Plug } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { toast } from "sonner";
import { AppPageLayout } from "@qmentisai/ui";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Select } from "@/components/ui/select.jsx";
import { DiscoveryList } from "../components/discovery-list.jsx";
import {
  useAuthorizeInstallation,
  useLinkAccount,
  useManageableWorkspaces,
  useStartLinking,
} from "../hooks/use-integrations.js";
import { linkErrorMessage } from "../services/link-errors.js";
import { linkHint } from "../services/link-hint.js";

/**
 * Landing page after the user authorized the App on GitHub (`code` and our `state`). It submits them ONCE (the state is
 * single use), removes them from the address bar and clears the workspace hint. Two answers: a link (201) opens that
 * workspace's Integrations page (the workspace comes from the API response); a discovery (200, `mode: "discover"`) lists
 * the installations the user can see, and choosing one starts the normal flow with that installation id. A refusal
 * explains what to do.
 */
export function GitHubCallbackPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const link = useLinkAccount();
  const started = useRef(false);
  const [hint] = useState(() => linkHint.read());
  const code = params.get("code") ?? "";
  const state = params.get("state") ?? "";
  useEffect(() => {
    if (started.current || !code || !state) return;
    started.current = true;
    window.history.replaceState(null, "", window.location.pathname);
    linkHint.clear();
    link.mutate(
      { code, state },
      {
        onSuccess: (result) => {
          if (result.mode === "discover") return;
          toast.success(`GitHub account ${result.account.login} linked`);
          navigate(`/workspaces/${result.workspaceId}/integrations`, { replace: true });
        },
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once per landing
  }, [code, state]);
  const missing = !code || !state;
  const retry = hint ? `/workspaces/${hint}/integrations` : "/workspaces";
  const discovery = link.data?.mode === "discover" ? link.data : null;
  return (
    <AppPageLayout
      title={discovery ? "Use an existing installation" : "Linking GitHub"}
      description={
        discovery
          ? "Installations of the App on the GitHub accounts you can access."
          : "Verifying your access to the GitHub account."
      }
    >
      {link.isError || missing ? (
        <div role="alert" className="space-y-3">
          <p className="text-sm text-status-danger">
            {link.isError
              ? linkErrorMessage(link.error)
              : "This link is incomplete or was already used."}
          </p>
          <Button asChild variant="secondary">
            <Link to={retry}>Start again</Link>
          </Button>
        </div>
      ) : discovery ? (
        <Discovery discovery={discovery} hint={hint} back={retry} />
      ) : (
        <LoadingState label="Verifying with GitHub" />
      )}
    </AppPageLayout>
  );
}

/** The candidates, the workspace they will be linked to, and the way out when there are none. */
function Discovery({ discovery, hint, back }) {
  const manageable = useManageableWorkspaces();
  const hinted = manageable.find((w) => w.id === hint) ?? null;
  const [picked, setPicked] = useState("");
  const workspaceId = hinted?.id ?? picked;
  const authorize = useAuthorizeInstallation();
  const start = useStartLinking();
  const error = authorize.error ?? start.error;
  const choose = (installationId) => {
    linkHint.write(workspaceId);
    authorize.mutate(
      { workspaceId, installationId },
      { onSuccess: ({ authorizeUrl }) => window.location.assign(authorizeUrl) },
    );
  };
  const install = () => {
    linkHint.write(workspaceId);
    start.mutate(workspaceId, {
      onSuccess: ({ installUrl }) => window.location.assign(installUrl),
    });
  };
  const busy = authorize.isPending || start.isPending;
  if (manageable.length === 0)
    return (
      <p role="alert" className="text-sm text-status-danger">
        You do not have permission to link source control in any workspace.
      </p>
    );
  return (
    <div className="space-y-4">
      {hinted ? (
        <p className="text-sm text-muted-foreground">
          The installation you choose will be linked to the workspace{" "}
          <span className="font-semibold text-foreground">{hinted.name}</span>.
        </p>
      ) : (
        <div className="max-w-sm space-y-2">
          <label htmlFor="discover-workspace" className="text-sm font-medium">
            Which workspace should use the installation?
          </label>
          <Select
            id="discover-workspace"
            value={picked}
            onChange={(e) => setPicked(e.target.value)}
          >
            <option value="">Select a workspace</option>
            {manageable.map((w) => (
              <option key={w.id} value={w.id}>
                {w.name}
              </option>
            ))}
          </Select>
        </div>
      )}
      {discovery.candidates.length === 0 ? (
        <EmptyState
          icon={Plug}
          title="No installation found"
          description="No installation of the App found for your GitHub account. Install the App on a GitHub account."
          actions={
            <Button onClick={install} disabled={!workspaceId || busy}>
              Install the App on a GitHub account
            </Button>
          }
        />
      ) : (
        <DiscoveryList
          candidates={discovery.candidates}
          pending={busy || !workspaceId}
          onChoose={choose}
        />
      )}
      {discovery.truncated ? (
        <p role="status" className="text-sm text-muted-foreground">
          Only the first organizations were checked. Some installations may not be listed.
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-sm text-status-danger">
          {linkErrorMessage(error)}
        </p>
      ) : null}
      <Button asChild variant="ghost">
        <Link to={back}>Back to Integrations</Link>
      </Button>
    </div>
  );
}
