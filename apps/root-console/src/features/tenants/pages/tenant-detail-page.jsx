import { AppPageLayout } from "@qmentisai/ui";
import { useState } from "react";
import { useParams } from "react-router";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { TenantStatusChip } from "@/components/common/tenant-status-chip.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { DisabledWithReason } from "@/features/authorization/index.js";
import { useTenantDetail, useTenantLifecycle } from "../hooks/use-tenants.js";

const dateTime = (value) =>
  new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const date = (value) =>
  new Date(value).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });

/** Which actions make sense in each status (the server re-checks status, permission and the typed name). */
const STATUS_ACTIONS = {
  active: ["suspend", "deactivate"],
  trial: ["suspend", "deactivate"],
  suspended: ["reactivate", "deactivate"],
  deactivated: ["restore"],
};
const ACTIONS = {
  suspend: {
    label: "Suspend",
    permission: "platform.tenant.suspend",
    destructive: true,
    typed: true,
    title: "Suspend this tenant?",
    description:
      "Everyone in the tenant is signed out of the application immediately and cannot use it until you reactivate it. Nothing is deleted.",
  },
  reactivate: {
    label: "Reactivate",
    permission: "platform.tenant.reactivate",
    destructive: false,
    typed: false,
    title: "Reactivate this tenant?",
    description: "The tenant can use the application again.",
  },
  restore: {
    label: "Restore",
    permission: "platform.tenant.restore",
    destructive: false,
    typed: false,
    title: "Restore this tenant?",
    description:
      "The deactivated tenant returns to service with its data as it was. This is only possible during the retention window.",
  },
  deactivate: {
    label: "Deactivate",
    permission: "platform.tenant.deactivate",
    destructive: true,
    typed: true,
    title: "Deactivate this tenant?",
    description:
      "Deactivation ends the tenant's service. A Platform Super Admin can restore it until the retention window ends; after that it is final. Data is retained.",
  },
};
const EVENT_LABEL = {
  "tenant.created": "Provisioned",
  "tenant.suspended": "Suspended",
  "tenant.reactivated": "Reactivated",
  "tenant.deactivated": "Deactivated",
  "tenant.restored": "Restored",
};

function Count({ label, value }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-xl leading-7 font-semibold tabular-nums">{value}</dd>
    </div>
  );
}

/**
 * R-06 Tenant detail: status, subscription, usage counts (never tenant content), administrators and lifecycle history.
 * Lifecycle actions are permission-aware: valid for the status but not permitted shows a disabled button with the reason.
 * Suspend and deactivate need a reason and the tenant name typed.
 */
export function TenantDetailPage() {
  const { tenantId } = useParams();
  const detail = useTenantDetail(tenantId);
  const lifecycle = useTenantLifecycle(tenantId);
  const [pending, setPending] = useState(null);

  if (detail.isPending)
    return (
      <AppPageLayout title="Tenant" offset="4.5rem">
        <LoadingState rows={4} label="Loading tenant" />
      </AppPageLayout>
    );
  if (detail.isError) return <QueryErrorState error={detail.error} onRetry={detail.refetch} />;
  const {
    tenant,
    subscription,
    usage,
    administrators,
    pendingAdministrators,
    lifecycle: history,
    allowedActions,
  } = detail.data;
  const rule = pending ? ACTIONS[pending] : null;

  return (
    <AppPageLayout
      title={tenant.name}
      description={<span className="font-mono text-xs">{tenant.slug}</span>}
      offset="4.5rem"
      actions={
        <>
          <TenantStatusChip status={tenant.status} />
          {STATUS_ACTIONS[tenant.status]
            .filter((action) => action !== "restore" || tenant.restorableUntil)
            .map((action) => (
              <DisabledWithReason
                key={action}
                reason={
                  allowedActions.includes(action)
                    ? null
                    : `You need the ${ACTIONS[action].permission} permission.`
                }
              >
                <Button
                  variant={ACTIONS[action].destructive ? "outline" : "secondary"}
                  onClick={() => setPending(action)}
                >
                  {ACTIONS[action].label}
                </Button>
              </DisabledWithReason>
            ))}
        </>
      }
    >
      {tenant.status === "suspended" ? (
        <p
          role="status"
          className="mb-4 rounded-md border border-border-strong bg-secondary p-3 text-sm"
        >
          This tenant is suspended. Its users cannot use the application.
        </p>
      ) : null}
      {tenant.status === "deactivated" ? (
        <p
          role="status"
          className="mb-4 rounded-md border border-border-strong bg-secondary p-3 text-sm"
        >
          This tenant is deactivated
          {tenant.deactivatedAt ? ` since ${date(tenant.deactivatedAt)}` : ""}.{" "}
          {tenant.restorableUntil
            ? `A Platform Super Admin can restore it until ${date(tenant.restorableUntil)}.`
            : "The retention window has ended, so deactivation is final."}
        </p>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Subscription</CardTitle>
            <CardDescription>Current plan and period.</CardDescription>
          </CardHeader>
          <CardContent>
            {subscription ? (
              <dl className="space-y-1.5 text-sm">
                <div className="flex gap-2">
                  <dt className="w-20 text-muted-foreground">Plan</dt>
                  <dd>
                    {subscription.plan.name} (v{subscription.plan.version})
                  </dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-20 text-muted-foreground">Status</dt>
                  <dd className="capitalize">{subscription.status}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-20 text-muted-foreground">Starts</dt>
                  <dd>{date(subscription.startsAt)}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-20 text-muted-foreground">Ends</dt>
                  <dd>{subscription.endsAt ? date(subscription.endsAt) : "No end date"}</dd>
                </div>
              </dl>
            ) : (
              <p className="text-sm text-muted-foreground">No plan is assigned to this tenant.</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Usage</CardTitle>
            <CardDescription>Counts only; tenant content is never shown here.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-3 gap-4 text-sm">
              <Count label="Active users" value={usage.users.active} />
              <Count label="Invited" value={usage.users.invited} />
              <Count label="Suspended users" value={usage.users.suspended} />
              <Count label="Active workspaces" value={usage.workspaces.active} />
              <Count label="Archived" value={usage.workspaces.archived} />
              <Count label="Groups" value={usage.groups} />
            </dl>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Administrators</CardTitle>
            <CardDescription>People who can administer this tenant.</CardDescription>
          </CardHeader>
          <CardContent>
            {administrators.length === 0 && pendingAdministrators.length === 0 ? (
              <p className="text-sm text-status-warning">This tenant has no administrator.</p>
            ) : null}
            <ul className="divide-y divide-border text-sm">
              {administrators.map((a) => (
                <li key={a.id} className="flex items-center justify-between gap-2 py-2">
                  <span>
                    {a.name}
                    <span className="block text-xs text-muted-foreground">{a.email}</span>
                  </span>
                  <Badge tone="success">Active</Badge>
                </li>
              ))}
              {pendingAdministrators.map((a) => (
                <li key={a.id} className="flex items-center justify-between gap-2 py-2">
                  <span>
                    {a.email}
                    <span className="block text-xs text-muted-foreground">
                      Invitation not accepted yet
                    </span>
                  </span>
                  <Badge>Invited</Badge>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Lifecycle history</CardTitle>
            <CardDescription>Provisioning and status changes.</CardDescription>
          </CardHeader>
          <CardContent>
            {history === null ? (
              <p className="text-sm text-muted-foreground">
                Lifecycle history needs the platform.audit_log.view permission.
              </p>
            ) : history.length === 0 ? (
              <p className="text-sm text-muted-foreground">No lifecycle events recorded.</p>
            ) : (
              <ol className="space-y-2 text-sm">
                {history.map((e, i) => (
                  <li key={`${e.at}-${i}`}>
                    <p>
                      <span className="font-medium">{EVENT_LABEL[e.action] ?? e.action}</span>
                      <span className="text-muted-foreground">
                        {" "}
                        · {dateTime(e.at)}
                        {e.actorName ? ` · ${e.actorName}` : ""}
                      </span>
                    </p>
                    {e.reason ? (
                      <p className="text-xs text-muted-foreground">Reason: {e.reason}</p>
                    ) : null}
                  </li>
                ))}
              </ol>
            )}
          </CardContent>
        </Card>
      </div>
      <p className="mt-4 text-xs text-subtle-foreground">Created {dateTime(tenant.createdAt)}</p>

      <ConfirmDialog
        open={Boolean(pending)}
        onOpenChange={(open) => {
          if (!open) {
            setPending(null);
            lifecycle.reset();
          }
        }}
        title={rule?.title ?? ""}
        description={rule?.description ?? ""}
        confirmLabel={rule?.label ?? "Confirm"}
        destructive={rule?.destructive}
        confirmText={rule?.typed ? tenant.name : undefined}
        reasonLabel="Reason"
        pending={lifecycle.isPending}
        error={lifecycle.error}
        onConfirm={({ reason, confirm }) =>
          lifecycle.mutate(
            { action: pending, reason, ...(rule.typed ? { confirm } : {}) },
            {
              onSuccess: () => {
                toast.success(`${tenant.name}: ${ACTIONS[pending].label.toLowerCase()} done`);
                setPending(null);
              },
            },
          )
        }
      />
    </AppPageLayout>
  );
}
