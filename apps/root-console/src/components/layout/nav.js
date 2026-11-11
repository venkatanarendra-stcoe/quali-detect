import {
  Activity,
  Building2,
  Cable,
  Gauge,
  KeyRound,
  LayoutGrid,
  LifeBuoy,
  Layers,
  ScrollText,
  SlidersHorizontal,
  ToggleRight,
  Users,
} from "lucide-react";

/**
 * App-side presentation of `PLATFORM_NAV_GROUPS` (defined in @qmentisai/shared/platform): labels, icons and URLs only.
 * Which items exist and who sees them is decided by `evaluatePlatformNavigation` with `platform.*` permissions.
 */
export const GROUP_LABELS = Object.freeze({
  platform: "Platform",
  customers: "Customers",
  "platform-administration": "Platform administration",
  operations: "Operations",
});

const item = (label, icon, to) => ({ label, icon, to });

export const NAV_ITEMS = Object.freeze({
  dashboard: item("Platform dashboard", LayoutGrid, "/dashboard"),
  monitoring: item("System monitoring", Activity, "/monitoring"),
  tenants: item("Tenant management", Building2, "/tenants"),
  subscriptions: item("Subscription management", Layers, "/subscriptions"),
  licenses: item("License management", KeyRound, "/licenses"),
  entitlements: item("Feature entitlements", ToggleRight, "/entitlements"),
  "usage-quotas": item("Usage & quotas", Gauge, "/usage"),
  "platform-users": item("Platform users", Users, "/platform-users"),
  "integration-catalog": item("Integration catalog", Cable, "/integration-catalog"),
  "global-config": item("Global configuration", SlidersHorizontal, "/config"),
  support: item("Support & diagnostics", LifeBuoy, "/support"),
  "audit-logs": item("Platform audit logs", ScrollText, "/audit-logs"),
});
