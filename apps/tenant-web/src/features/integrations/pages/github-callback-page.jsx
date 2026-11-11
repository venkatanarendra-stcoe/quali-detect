import { useEffect, useRef } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { toast } from "sonner";
import { PageHeader } from "@/components/common/page-header.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { describeError } from "@/lib/api/index.js";
import { useLinkInstallation } from "../hooks/use-integrations.js";

/**
 * Landing page after the user authorized the App on GitHub (`code` and our `state`). It submits them ONCE (the state is
 * single use) and then removes them from the address bar. Success goes to the GitHub page; a refusal explains what to do.
 */
export function GitHubCallbackPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const link = useLinkInstallation();
  const started = useRef(false);
  const code = params.get("code") ?? "";
  const state = params.get("state") ?? "";
  useEffect(() => {
    if (started.current || !code || !state) return;
    started.current = true;
    window.history.replaceState(null, "", window.location.pathname);
    link.mutate(
      { code, state },
      {
        onSuccess: (result) => {
          toast.success(`GitHub account ${result.account.login} linked`);
          navigate("/integrations/github", { replace: true });
        },
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once per landing
  }, [code, state]);
  const missing = !code || !state;
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
              ? describeError(link.error)
              : "This link is incomplete or was already used."}
          </p>
          <Button asChild variant="secondary">
            <Link to="/integrations/github">Start again</Link>
          </Button>
        </div>
      ) : (
        <LoadingState label="Verifying with GitHub" />
      )}
    </>
  );
}
