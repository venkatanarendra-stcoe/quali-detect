/** Current subscription's plan as shown in lists and details. @param {any} subscription with planVersion.plan */
export const toPlanSummary = (subscription) =>
  subscription
    ? {
        key: subscription.planVersion.plan.key,
        name: subscription.planVersion.plan.name,
        version: subscription.planVersion.version,
      }
    : null;

/** @param {any} tenant @param {{ userCount: number, workspaceCount: number, subscription: any }} aggregates */
export const toTenantListItem = (tenant, { userCount, workspaceCount, subscription }) => ({
  id: tenant.id,
  slug: tenant.slug,
  name: tenant.name,
  status: tenant.status,
  plan: toPlanSummary(subscription),
  userCount,
  workspaceCount,
  createdAt: tenant.createdAt,
});

/** @param {any} event platform audit row with `actor` */
export const toLifecycleEvent = (event) => ({
  action: event.action,
  at: event.createdAt,
  actorName: event.actor?.name ?? null,
  reason: typeof event.metadata?.reason === "string" ? event.metadata.reason : null,
});
