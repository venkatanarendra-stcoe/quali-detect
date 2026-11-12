import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { toast } from "sonner";
import { PageHeader } from "@/components/common/page-header.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { useLinkAccount } from "../hooks/use-integrations.js";
import { linkErrorMessage } from "../services/link-errors.js";
import { linkHint } from "../services/link-hint.js";

/**
 * Landing page after the user authorized the App on GitHub (`code` and our `state`). It submits them ONCE (the state is
 * single use), removes them from the address bar and clears the workspace hint. Success opens that workspace's
 * Integrations page (the workspace comes from the API response); a refusal explains what to do.
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
          toast.success(`GitHub account ${result.account.login} linked`);
          navigate(`/workspaces/${result.workspaceId}/integrations`, { replace: true });
        },
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once per landing
  }, [code, state]);
  const missing = !code || !state;
  const retry = hint ? `/workspaces/${hint}/integrations` : "/workspaces";
  return (
    <>
      <PageHeader
        title="Linking GitHub"
        description="Verifying your access to the GitHub account."
      />
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
      ) : (
        <LoadingState label="Verifying with GitHub" />
      )}
    </>
  );
}
