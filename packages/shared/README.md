# @qmentisai/shared

Permission catalog, built-in role bundles, navigation definitions, key builders and the **central authorization engine** (`authorization.js`: `resolveEffectivePermissions`, `can`, `canInAnyWorkspace`, escalation helpers). `platform-navigation.js` / `platform-permissions.js` (entry point `@qmentisai/shared/platform`) hold the Root Console navigation (`PLATFORM_NAV_GROUPS`, `evaluatePlatformNavigation`) and the `platform.*` permission catalog; they never touch tenant navigation, so the Root Console can import them without any tenant model. The engine is pure (no I/O) so the API enforces with it and the frontends evaluate the permissions returned by `GET /api/v1/me` with the same `can`; role names are never used.

`keys.js` holds the tenant-scoped key builders (cache, lock, rate limit, idempotency keys and Socket.IO rooms). They require a valid `tenantId` and throw otherwise; platform data uses the explicit `buildPlatformKey`.

Navigation is defined here once and evaluated by the central authorization engine; UI code never checks role names.
