import { ComponentGalleryPage } from "@/features/dev/pages/component-gallery-page.jsx";
import { ProvisionTenantPage } from "@/features/tenants/pages/provision-tenant-page.jsx";
import { TenantDetailPage } from "@/features/tenants/pages/tenant-detail-page.jsx";
import { TenantsPage } from "@/features/tenants/pages/tenants-page.jsx";
import { PlannedModulePage } from "@/features/placeholders/pages/planned-module-page.jsx";
import { DashboardPage } from "@/features/platform-dashboard/pages/dashboard-page.jsx";

const planned = (title, description) => (
  <PlannedModulePage title={title} description={description} />
);

/**
 * Route table = the single list of pages that exist. Navigation consults `isRouteAvailable(itemId)`, so an item can appear
 * only when its route is registered here. `permission` is a `platform.*` key (the same key the nav definition uses).
 */
export const PLATFORM_ROUTES = [
  {
    itemId: "dashboard",
    path: "dashboard",
    permission: "platform.tenant.view",
    element: <DashboardPage />,
  },
  {
    itemId: "monitoring",
    path: "monitoring",
    permission: "platform.monitoring.view",
    element: planned("System monitoring", "Job, queue and error monitoring is planned."),
  },
  {
    itemId: "tenants",
    path: "tenants",
    permission: "platform.tenant.view",
    element: <TenantsPage />,
  },
  { path: "tenants/new", permission: "platform.tenant.create", element: <ProvisionTenantPage /> },
  { path: "tenants/:tenantId", permission: "platform.tenant.view", element: <TenantDetailPage /> },
  {
    itemId: "subscriptions",
    path: "subscriptions",
    permission: "platform.subscription.view",
    element: planned("Subscription management", "Plans and subscriptions are planned."),
  },
  {
    itemId: "licenses",
    path: "licenses",
    permission: "platform.license.view",
    element: planned("License management", "License grants are planned."),
  },
  {
    itemId: "entitlements",
    path: "entitlements",
    permission: "platform.entitlement.view",
    element: planned("Feature entitlements", "Entitlement management is planned."),
  },
  {
    itemId: "usage-quotas",
    path: "usage",
    permission: "platform.usage.view",
    element: planned("Usage & quotas", "Usage and quota management is planned."),
  },
  {
    itemId: "platform-users",
    path: "platform-users",
    permission: "platform.user.view",
    element: planned("Platform users", "Platform user administration is planned."),
  },
  {
    itemId: "integration-catalog",
    path: "integration-catalog",
    permission: "platform.integration_catalog.view",
    element: planned("Integration catalog", "The integration catalog is planned."),
  },
  {
    itemId: "global-config",
    path: "config",
    permission: "platform.config.view",
    element: planned("Global configuration", "Global configuration and feature flags are planned."),
  },
  {
    itemId: "support",
    path: "support",
    permission: "platform.support.request_access",
    element: planned(
      "Support & diagnostics",
      "Support access requests and diagnostics are planned.",
    ),
  },
  {
    itemId: "audit-logs",
    path: "audit-logs",
    permission: "platform.audit_log.view",
    element: planned("Platform audit logs", "The platform audit log viewer is planned."),
  },
];

/** Development-only routes (excluded from production builds). */
export const DEV_ROUTES = import.meta.env.DEV
  ? [{ path: "dev/components", element: <ComponentGalleryPage /> }]
  : [];

const AVAILABLE = new Set(PLATFORM_ROUTES.map((r) => r.itemId));

/** Whether a page is registered for the navigation item. @param {string} itemId */
export const isRouteAvailable = (itemId) => AVAILABLE.has(itemId);
