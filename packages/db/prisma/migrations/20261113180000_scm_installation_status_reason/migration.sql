-- SPEC repositories-github §16.2 (owner, 2026-11-12/13): a revoked or suspended installation shows its status, the date and
-- the reason everywhere. The installation records WHEN it left `active` and WHY. Generated part first, then the
-- hand-written constraint and backfill.

-- AlterTable
ALTER TABLE "scm_installations" ADD COLUMN     "status_changed_at" TIMESTAMPTZ(6),
ADD COLUMN     "status_reason" TEXT;

-- Backfill: rows that are already revoked or suspended get their last update time and the only causes known so far.
UPDATE "scm_installations" SET "status_changed_at" = "updated_at", "status_reason" = 'uninstalled' WHERE "status" = 'revoked';
UPDATE "scm_installations" SET "status_changed_at" = "updated_at", "status_reason" = 'suspended' WHERE "status" = 'suspended';

-- Reason domain, and the pair is set exactly when the installation is not active.
ALTER TABLE "scm_installations" ADD CONSTRAINT "scm_installations_status_reason_check" CHECK (
  ("status" = 'active' AND "status_changed_at" IS NULL AND "status_reason" IS NULL)
  OR ("status" = 'suspended' AND "status_changed_at" IS NOT NULL AND "status_reason" = 'suspended')
  OR ("status" = 'revoked' AND "status_changed_at" IS NOT NULL AND "status_reason" IN ('uninstalled', 'not_found_on_github'))
);
