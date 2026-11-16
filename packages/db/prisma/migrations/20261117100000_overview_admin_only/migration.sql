-- Organization overview is Admin-only (owner decision 2026-11-17, docs/AUTHORIZATION.md decision 30).
-- Built-in roles are global rows (roles.kind = 'built_in', tenant_id NULL) whose bundles live in role_permissions and are
-- re-synced by the seed. A database that is not re-seeded would keep `dashboard.view` on the other six built-in bundles, so
-- this data migration removes it. Idempotent (a second run deletes nothing). Custom (tenant-owned) roles are NEVER touched:
-- tenants that deliberately granted `dashboard.view` to a custom role keep that grant. The Admin bundle keeps the key.
DELETE FROM "role_permissions"
WHERE "permission_key" = 'dashboard.view'
  AND "role_id" IN (
    SELECT "id" FROM "roles" WHERE "kind" = 'built_in' AND "key" <> 'admin'
  );
