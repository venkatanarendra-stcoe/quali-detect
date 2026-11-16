import { AppPageLayout } from "@qmentisai/ui";
import { LogOut, Settings } from "lucide-react";
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
import { usePlatformSession } from "@/features/auth/hooks/use-platform-session.js";

/** Account: the signed-in platform user. Read-only; any verified platform session may open it (no permission). */
export function AccountPage() {
  const { me } = usePlatformSession();
  const { logout } = useAuthActions();
  const rows = [
    ["Name", me.platformUser.name],
    ["Email", me.platformUser.email],
    ["Platform role", me.role.name],
  ];
  return (
    <AppPageLayout title="Account" description="Your platform sign-in identity." offset="4.5rem">
      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>
            Managed by platform administrators. Theme is under Settings.
          </CardDescription>
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
        <Button asChild variant="secondary">
          <Link to="/account/settings">
            <Settings aria-hidden="true" /> Settings
          </Link>
        </Button>
        <Button variant="secondary" onClick={() => logout.mutate()} disabled={logout.isPending}>
          <LogOut aria-hidden="true" /> Sign out
        </Button>
      </div>
    </AppPageLayout>
  );
}
