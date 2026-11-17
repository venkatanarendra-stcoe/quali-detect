-- Default workspace preference withdrawn by the owner (2026-11-17). The column and its composite foreign key (added by
-- 20261117110000_user_preferences_default_workspace, which stays in history) are removed. Dropping the column drops the
-- constraint with it; the explicit DROP CONSTRAINT keeps the intent readable. The feature never shipped a release, so no
-- data needs preserving.

ALTER TABLE "user_preferences" DROP CONSTRAINT IF EXISTS "user_preferences_default_workspace_fkey";
ALTER TABLE "user_preferences" DROP COLUMN IF EXISTS "default_workspace_id";
