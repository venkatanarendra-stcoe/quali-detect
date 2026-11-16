-- Default workspace preference (owner decision 2026-11-17): the workspace a user lands on after sign-in.
-- A preference only: it grants nothing and the API re-validates it against the caller's visible workspaces at every use.
-- The composite foreign key keeps the pointer inside the row's own tenant (same (tenant_id, id) key the other tenant-safe
-- chains use). ON DELETE SET NULL (default_workspace_id) lists the column on purpose: a plain SET NULL would also try to
-- null tenant_id, which is NOT NULL, and make deleting a workspace fail. A deleted workspace therefore just clears the
-- pointer and never errors. The column-list form needs PostgreSQL 15 or newer. Prisma cannot model it, so the schema has
-- the scalar only. MATCH SIMPLE: while default_workspace_id IS NULL the constraint is not evaluated.

ALTER TABLE "user_preferences" ADD COLUMN "default_workspace_id" UUID;

ALTER TABLE "user_preferences"
  ADD CONSTRAINT "user_preferences_default_workspace_fkey"
  FOREIGN KEY ("tenant_id", "default_workspace_id") REFERENCES "workspaces"("tenant_id", "id")
  ON DELETE SET NULL ("default_workspace_id") ON UPDATE CASCADE;
