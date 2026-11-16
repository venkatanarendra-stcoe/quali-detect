import { AppPageLayout } from "@qmentisai/ui";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { useSession } from "@/features/auth/hooks/use-session.js";

/** Account (T-03): who you are signed in as. Read-only; any signed-in user may open it, no permission needed. */
export function AccountPage() {
  const { me } = useSession();
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
          <CardDescription>
            Managed by your organization. Theme and accent colour are under Settings.
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
