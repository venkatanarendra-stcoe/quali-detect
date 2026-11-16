# @qmentisai/tenant-web

Tenant Application (React + Vite + Tailwind v4 + shadcn/ui-style components). Runs on port 5173.

```bash
pnpm --filter @qmentisai/tenant-web dev   # proxies /api to the API (VITE_DEV_API_TARGET, default http://localhost:3000)
```

## What exists (frontend foundation)

- **Tokens and theme:** `@qmentisai/ui/preset.css` (CSS variables + Tailwind v4 `@theme`; v4 is CSS-first, so the "preset" is a CSS file, not a JS config). Light / Dark / System, persisted per browser. Geist Sans / Geist Mono self-hosted.
- **API client** (`src/lib/api`): session cookie (`credentials: "include"`), envelope unwrapping, `ApiError` normalization with the server's stable `code`, `x-correlation-id` per request (shown to users on errors), AbortController cancellation plus a timeout, one handler for 401.
- **State:** TanStack Query owns server state (keys always start with the tenant and include the workspace id); Zustand holds only UI preferences (theme, mobile drawer) and the last workspace per tenant; URL params hold filters and pagination.
- **Auth:** login (T-01), `GET /me` bootstrap, route guards (`RequireAuth`, `RequireTenant`, `PublicOnly`), organization chooser (also accepts invitations), a blocked page when the active tenant is suspended.
- **Shell:** `useNavContext` picks the Organization layout (T-00a) or the Workspace layout (T-00b) from the URL. `ORG_NAV_GROUPS` / `WORKSPACE_NAV_GROUPS` live in `@qmentisai/shared`; `evaluateNavigation` shows an item only if `implemented && permitted && route exists` and hides empty groups. This app only adds labels, icons and URLs (`components/layout/nav.js`) and the route table (`app/routes.jsx`). The workspace switcher keeps the current section when allowed in the target workspace; legacy redirects: `/workspaces/:id`, `/workspaces/:id/edit`, `/repositories`. There is no top bar (owner decision 2026-11-16): logo, search / command palette (⌘K), Notifications and the account area (Account, Settings > Appearance / Preferences, Sign out) live in the sidebar.
- **Authorization UI:** `PermissionGate` (hide, or disable with an explanatory tooltip), `RequirePermission` route guard, `useCan`. Usability only; the API enforces.
- **States (T-05):** 403, 404 (identical for "missing" and "not visible"), error with correlation id, empty, loading, error boundary.
- **Screens with real data:** T-06 Organization overview, T-07 Workspaces list (search, status filter, sorting, pagination in the URL), T-08 Create workspace (wizard with partial-failure retry), T-40 Members & groups (add access, remove, revoke), T-44 Workspace settings (edit, archive and restore with typed confirmation), plus the workspace dashboard shell. Details and deviations: `docs/modules/access-management/SCREENS.md`. Other nav targets are honest "Coming soon" placeholders reachable only with the permission.
- **Shared UI added:** dialog, tabs, select, textarea, `ConfirmDialog` (typed confirmation and audited reason), `Stepper`, `SearchPicker`, `SortHeader`, `Pager`, `LinkButton`.

Not built yet: global search, notifications, charts and tables beyond the lists above (TanStack Table / Recharts are not installed yet), forms for creating or editing anything, code-splitting (the bundle is one chunk of about 620 kB). No tests are committed (scratch verification only).
