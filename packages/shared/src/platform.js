/**
 * Platform-only entry point (`@qmentisai/shared/platform`) used by the Root Console. It re-exports ONLY platform
 * navigation and platform permission helpers, so the Root Console never needs the package root (which also carries tenant
 * navigation and the tenant permission engine).
 */
export {
  PLATFORM_NAV_GROUPS,
  canPlatform,
  evaluatePlatformNavigation,
} from "./platform-navigation.js";
export {
  PLATFORM_PERMISSION_CATALOG,
  PLATFORM_PERMISSION_KEYS,
  isPlatformPermissionKey,
} from "./platform-permissions.js";
