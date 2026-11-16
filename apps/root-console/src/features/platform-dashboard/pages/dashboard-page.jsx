import { AppPageLayout } from "@qmentisai/ui";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { usePlatformSession } from "@/features/auth/hooks/use-platform-session.js";

/**
 * Platform dashboard shell. Metrics (tenants by status, usage versus quota, queue health, platform audit events) arrive with
 * the modules that produce them; nothing is invented here (billing metrics are an open decision).
 */
export function DashboardPage() {
  const { me } = usePlatformSession();
  return (
    <AppPageLayout
      title="Platform dashboard"
      description={`Signed in as ${me.platformUser.name} · ${me.role.name}`}
      offset="4.5rem"
    >
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Platform health</CardTitle>
            <CardDescription>Tenants, usage, queues and errors.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Tenant, usage and job-health metrics appear here once tenant management and monitoring
              are available.
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Your platform access</CardTitle>
            <CardDescription>Permissions of your platform role.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm">{me.permissions.length} platform permissions.</p>
            <details className="mt-2 text-sm">
              <summary className="cursor-pointer text-primary-text">Show permissions</summary>
              <ul className="mt-2 flex flex-wrap gap-1.5">
                {me.permissions.map((key) => (
                  <li key={key} className="rounded-sm bg-secondary px-1.5 py-0.5 font-mono text-xs">
                    {key}
                  </li>
                ))}
              </ul>
            </details>
            <p className="mt-3 text-xs text-subtle-foreground">
              Shown for convenience. The server checks every action independently.
            </p>
          </CardContent>
        </Card>
      </div>
    </AppPageLayout>
  );
}
