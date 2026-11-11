import { useEffect, useRef } from "react";
import { Link, useSearchParams } from "react-router";
import { PageHeader } from "@/components/common/page-header.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { describeError } from "@/lib/api/index.js";
import { useAuthorizeInstallation } from "../hooks/use-integrations.js";

/**
 * Landing page of GitHub's Setup URL (`/integrations/github/setup?installation_id=...`). Anyone can open this URL with any
 * installation id, so it proves nothing: it only asks the API for a single-use state and sends the user to GitHub to
 * authorize, where the real verification starts (SPEC R-2).
 */
export function GitHubSetupPage() {
  const [params] = useSearchParams();
  const installationId = params.get("installation_id") ?? "";
  const authorize = useAuthorizeInstallation();
  const started = useRef(false);
  useEffect(() => {
    if (started.current || !/^\d{1,20}$/.test(installationId)) return;
    started.current = true;
    authorize.mutate(installationId, {
      onSuccess: ({ authorizeUrl }) => window.location.assign(authorizeUrl),
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once per landing
  }, [installationId]);
  const invalid = !/^\d{1,20}$/.test(installationId);
  return (
    <>
      <PageHeader title="Connecting GitHub" description="Confirming your access with GitHub." />
      {authorize.isError || invalid ? (
        <div role="alert" className="space-y-3">
          <p className="text-sm text-status-danger">
            {invalid
              ? "GitHub did not send an installation to link."
              : describeError(authorize.error)}
          </p>
          <Button asChild variant="secondary">
            <Link to="/integrations/github">Back to GitHub</Link>
          </Button>
        </div>
      ) : (
        <LoadingState label="Redirecting to GitHub to confirm your access" />
      )}
    </>
  );
}
