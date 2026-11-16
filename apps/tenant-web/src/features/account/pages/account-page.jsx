import { useQuery } from "@tanstack/react-query";
import { AppPageLayout } from "@qmentisai/ui";
import { Building2, LogOut } from "lucide-react";
import { Link } from "react-router";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { useAuthActions } from "@/features/auth/hooks/use-auth-actions.js";
import { authService } from "@/features/auth/services/auth-service.js";
import { useSession } from "@/features/auth/hooks/use-session.js";

/** Account (T-03): who you are signed in as. Read-only; any signed-in user may open it, no permission needed. */
export function AccountPage() {
  const { me } = useSession();
  const { logout } = useAuthActions();
  const tenants = useQuery({
    queryKey: ["account", "tenants"],
    queryFn: ({ signal }) => authService.listTenants({ signal }),
    staleTime: 60_000,
  });
  const canSwitchOrganization = (tenants.data?.length ?? 0) > 1;
  const rows = [
    ["Name", me.user.name],
    ["Email", me.user.email],
    ["Organization", me.tenant.name],
  ];
  return (
    <AppPageLayout title="Account" description="Your sign-in identity.">
      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>Managed by your organization.</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[8rem_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            {rows.map(([term, value]) => (
              <div key={term} className="contents">
                <dt className="text-muted-foreground">{term}</dt>
                <dd className="truncate">{value}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>
      <div className="mt-4 flex max-w-xl flex-wrap gap-2">
        {canSwitchOrganization ? (
          <Button asChild variant="secondary">
            <Link to="/select-tenant">
              <Building2 aria-hidden="true" /> Switch organization
            </Link>
          </Button>
        ) : null}
        <Button variant="secondary" onClick={() => logout.mutate()} disabled={logout.isPending}>
          <LogOut aria-hidden="true" /> Sign out
        </Button>
      </div>
    </AppPageLayout>
  );
}
