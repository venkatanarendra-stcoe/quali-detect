import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button.jsx";
import { StatusChip } from "@/components/common/status-chip.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { describeError } from "@/lib/api/index.js";
import { useAuthActions } from "../hooks/use-auth-actions.js";
import { authService } from "../services/auth-service.js";

/** Organizations the user can enter and pending invitations (shared by tenant selection and the blocked page). */
export function TenantChoices() {
  const { switchTenant, acceptInvitation } = useAuthActions();
  const tenants = useQuery({
    queryKey: ["account", "tenants"],
    queryFn: ({ signal }) => authService.listTenants({ signal }),
  });
  const invitations = useQuery({
    queryKey: ["account", "invitations"],
    queryFn: ({ signal }) => authService.listInvitations({ signal }),
  });

  if (tenants.isPending || invitations.isPending)
    return <LoadingState rows={2} label="Loading organizations" />;
  if (tenants.isError || invitations.isError) {
    return (
      <p role="alert" className="text-sm text-status-danger">
        {describeError(tenants.error ?? invitations.error)}
      </p>
    );
  }
  const enter = (tenantId) =>
    switchTenant.mutate(tenantId, { onError: (e) => toast.error(describeError(e)) });
  const accept = (tenantId) =>
    acceptInvitation.mutate(tenantId, {
      onSuccess: () => {
        tenants.refetch();
        invitations.refetch();
      },
      onError: (e) => toast.error(describeError(e)),
    });

  if (tenants.data.length === 0 && invitations.data.length === 0) {
    return (
      <p className="text-center text-sm text-muted-foreground">
        Your account is not a member of any organization yet. Ask an administrator to invite you.
      </p>
    );
  }
  return (
    <div className="space-y-4">
      {tenants.data.length > 0 ? (
        <section aria-labelledby="orgs-heading">
          <h2 id="orgs-heading" className="mb-2 text-base font-semibold">
            Your organizations
          </h2>
          <ul className="divide-y divide-border rounded-md border border-border bg-card">
            {tenants.data.map((t) => (
              <li key={t.id} className="flex items-center justify-between gap-3 p-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{t.name}</p>
                  <p className="font-mono text-xs text-subtle-foreground">{t.slug}</p>
                </div>
                <div className="flex items-center gap-2">
                  {t.status !== "active" ? <StatusChip status={t.status} /> : null}
                  <Button
                    size="sm"
                    disabled={switchTenant.isPending || !["active", "trial"].includes(t.status)}
                    onClick={() => enter(t.id)}
                  >
                    Continue
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {invitations.data.length > 0 ? (
        <section aria-labelledby="invites-heading">
          <h2 id="invites-heading" className="mb-2 text-base font-semibold">
            Invitations
          </h2>
          <ul className="divide-y divide-border rounded-md border border-border bg-card">
            {invitations.data.map((t) => (
              <li key={t.id} className="flex items-center justify-between gap-3 p-3">
                <p className="truncate text-sm font-medium">{t.name}</p>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={acceptInvitation.isPending}
                  onClick={() => accept(t.id)}
                >
                  Accept
                </Button>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
