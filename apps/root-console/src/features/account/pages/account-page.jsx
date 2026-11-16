import { AppPageLayout } from "@qmentisai/ui";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { usePlatformSession } from "@/features/auth/hooks/use-platform-session.js";

/** Account: the signed-in platform user. Read-only; any verified platform session may open it (no permission). */
export function AccountPage() {
  const { me } = usePlatformSession();
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
    </AppPageLayout>
  );
}
