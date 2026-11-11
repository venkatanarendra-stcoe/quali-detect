# @qmentisai/root-console

Root Console: platform administration (tenants, plans, entitlements, platform audit). Runs on port 5174. Separate app, separate sessions (`qm_platform_session`), separate permission model (`platform.*` only).

```bash
pnpm --filter @qmentisai/root-console dev   # proxies /api to the API (VITE_DEV_API_TARGET, default http://localhost:3000)
```

## What exists (foundation)

- **Theme:** `@qmentisai/ui/root-theme.css` on top of the shared tokens: violet accent, always-dark sidebar, active only under `<html data-app="root">` (decision record in `docs/design/DESIGN_SYSTEM.md` §7; the violet values are Recommended until approved).
- **Shell:** environment strip (`VITE_ENVIRONMENT`: development / staging / production), dark sidebar with the "QmentisAI Platform" header, top bar with a persistent PLATFORM chip and the account menu. No workspace switcher.
- **Sign-in:** platform login, then a **mandatory MFA screen** (mock verifier). The server withholds all platform data until the code is verified, so the screen cannot be skipped; route guards send MFA-pending visitors back to `/mfa`.
- **Navigation:** `PLATFORM_NAV_GROUPS` in `@qmentisai/shared/platform`, evaluated by `evaluatePlatformNavigation` with `platform.*` permissions only; `implemented && permitted && route exists`; empty groups hidden.
- **Separation from tenant code:** only `@qmentisai/shared/platform` may be imported from the shared package (ESLint `no-restricted-imports`); the production bundle contains no tenant or workspace permission keys.
- **Components:** `SupportAccessBanner` (active / expiring / expired) and `EnvironmentStrip`; both are shown in a development-only gallery at `/dev/components` (not in production builds). The banner is presentational: support-access grants do not exist on the server yet.
- **Authorization UI:** `PlatformPermissionGate` (hide or disable with tooltip), `RequirePlatformPermission`, 403/404/error states.
- **Screens with real data:** R-04 Tenants list (search, status and plan filters, sorting, pagination in the URL), R-05 Provision tenant (first administrator is invited), R-06 Tenant detail (subscription, usage counts, administrators, lifecycle history; suspend, reactivate, deactivate with a reason and the tenant name typed). Platform access shows metadata and counts only. Details: `docs/modules/access-management/SCREENS.md`.
- Other pages: the dashboard shell and honest "Coming soon" pages reachable only with the permission.

Notes: generic code (API client, UI primitives, state components) is copied from the Tenant Application per the shadcn convention; moving it into a shared package is a possible later cleanup. A tenant session cookie from the Tenant Application (same host, other port) reaches platform routes and is answered with 404; the Root Console treats that as "signed out". No tests are committed (scratch verification only).
