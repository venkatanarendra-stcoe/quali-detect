import { Ban } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { StateLayout } from "@/components/states/state-layout.jsx";
import { useAuthActions } from "../hooks/use-auth-actions.js";
import { TenantChoices } from "../components/tenant-choices.jsx";

/** Shown when the session's active tenant is suspended or deactivated (API: 403 TENANT_SUSPENDED). */
export function TenantBlockedPage() {
  const { logout } = useAuthActions();
  return (
    <main className="min-h-screen bg-background">
      <StateLayout
        icon={Ban}
        title="This organization is not active"
        role="alert"
        actions={
          <Button variant="secondary" onClick={() => logout.mutate()}>
            Sign out
          </Button>
        }
      >
        <p>
          Access to this organization is suspended. Contact your administrator, or continue in
          another organization.
        </p>
      </StateLayout>
      <div className="mx-auto max-w-md px-4 pb-10">
        <TenantChoices />
      </div>
    </main>
  );
}
