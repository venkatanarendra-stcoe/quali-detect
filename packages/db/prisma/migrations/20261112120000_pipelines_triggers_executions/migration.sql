-- SPEC (docs/modules/pipelines-triggers/SPEC.md) §7, §13.3 part B: pipelines, immutable configuration versions, trigger projection,
-- minimal executions, policy-skip decisions. Additive: no existing data is touched. The generated part comes first; the hand-written
-- part (partial indexes, CHECK constraints, immutability triggers) follows, because Prisma cannot express it.

-- CreateEnum
CREATE TYPE "pipeline_trigger_type" AS ENUM ('push', 'pull_request', 'schedule', 'manual');

-- CreateEnum
CREATE TYPE "pipeline_missed_policy" AS ENUM ('skip', 'run_once');

-- CreateEnum
CREATE TYPE "execution_status" AS ENUM ('queued', 'blocked', 'skipped', 'cancelled', 'preparing', 'running', 'cancelling', 'succeeded', 'failed', 'timed_out');

-- CreateEnum
CREATE TYPE "execution_ref_type" AS ENUM ('branch', 'tag', 'pull_request');

-- CreateEnum
CREATE TYPE "execution_scan_kind" AS ENUM ('full', 'incremental');

-- CreateEnum
CREATE TYPE "execution_trust" AS ENUM ('trusted', 'untrusted_fork');

-- CreateEnum
CREATE TYPE "trigger_decision_kind" AS ENUM ('skipped_by_policy');

-- CreateEnum
CREATE TYPE "trigger_decision_reason" AS ENUM ('fork_policy_skip', 'draft_policy_skip', 'repository_inactive', 'repository_disabled', 'workspace_archived', 'pipeline_disabled', 'trigger_disabled');

-- CreateTable
CREATE TABLE "pipelines" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "name_normalized" TEXT NOT NULL,
    "description" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "current_version" INTEGER NOT NULL DEFAULT 0,
    "current_version_id" UUID,
    "created_by_user_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,
    "deleted_at" TIMESTAMPTZ(6),
    "deleted_by_user_id" UUID,

    CONSTRAINT "pipelines_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pipeline_config_versions" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "version" INTEGER NOT NULL,
    "schema_version" INTEGER NOT NULL,
    "config" JSONB NOT NULL,
    "config_hash" TEXT NOT NULL,
    "change_summary" JSONB NOT NULL DEFAULT '{}',
    "change_note" TEXT,
    "created_by_user_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pipeline_config_versions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pipeline_triggers" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "trigger_key" TEXT NOT NULL,
    "type" "pipeline_trigger_type" NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "version_id" UUID NOT NULL,
    "cron" TEXT,
    "timezone" TEXT,
    "next_fire_at" TIMESTAMPTZ(6),
    "last_slot_at" TIMESTAMPTZ(6),
    "missed_policy" "pipeline_missed_policy",
    "jitter_offset_seconds" INTEGER,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "pipeline_triggers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "executions" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "config_version_id" UUID NOT NULL,
    "config_version" INTEGER NOT NULL,
    "config_hash" TEXT NOT NULL,
    "trigger_type" "pipeline_trigger_type" NOT NULL,
    "trigger_key" TEXT NOT NULL,
    "scm_event_id" UUID,
    "scm_delivery_id" TEXT,
    "scm_event_kind" "scm_event_kind",
    "schedule_slot" TIMESTAMPTZ(6),
    "requested_by_user_id" UUID,
    "ref_type" "execution_ref_type" NOT NULL,
    "ref_name" TEXT NOT NULL,
    "base_ref" TEXT,
    "pull_request_number" INTEGER,
    "commit_sha" TEXT,
    "base_sha" TEXT,
    "scan_kind" "execution_scan_kind" NOT NULL,
    "scan_kind_reason" TEXT NOT NULL,
    "trust" "execution_trust" NOT NULL DEFAULT 'trusted',
    "concurrency_group" TEXT NOT NULL,
    "status" "execution_status" NOT NULL DEFAULT 'queued',
    "status_reason" TEXT,
    "quota_period" TEXT,
    "quota_consumed" INTEGER NOT NULL DEFAULT 0,
    "idempotency_key" TEXT NOT NULL,
    "correlation_id" TEXT,
    "requested_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "executions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pipeline_trigger_decisions" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "trigger_type" "pipeline_trigger_type" NOT NULL,
    "trigger_key" TEXT NOT NULL,
    "scm_event_id" UUID,
    "scm_delivery_id" TEXT NOT NULL,
    "scm_event_kind" "scm_event_kind" NOT NULL,
    "decision" "trigger_decision_kind" NOT NULL DEFAULT 'skipped_by_policy',
    "reason" "trigger_decision_reason" NOT NULL,
    "ref_type" "execution_ref_type" NOT NULL,
    "ref_name" TEXT NOT NULL,
    "pull_request_number" INTEGER,
    "decided_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "correlation_id" TEXT,

    CONSTRAINT "pipeline_trigger_decisions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "pipelines_tenant_id_workspace_id_deleted_at_name_idx" ON "pipelines"("tenant_id", "workspace_id", "deleted_at", "name");

-- CreateIndex
CREATE INDEX "pipelines_tenant_id_repository_id_deleted_at_enabled_idx" ON "pipelines"("tenant_id", "repository_id", "deleted_at", "enabled");

-- CreateIndex
CREATE UNIQUE INDEX "pipelines_tenant_id_id_key" ON "pipelines"("tenant_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "pipelines_tenant_id_workspace_id_repository_id_id_key" ON "pipelines"("tenant_id", "workspace_id", "repository_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "pipeline_config_versions_tenant_id_pipeline_id_version_key" ON "pipeline_config_versions"("tenant_id", "pipeline_id", "version");

-- CreateIndex
CREATE UNIQUE INDEX "pipeline_config_versions_tenant_id_id_key" ON "pipeline_config_versions"("tenant_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "pipeline_config_versions_tenant_id_pipeline_id_id_key" ON "pipeline_config_versions"("tenant_id", "pipeline_id", "id");

-- CreateIndex
CREATE INDEX "pipeline_triggers_tenant_id_workspace_id_idx" ON "pipeline_triggers"("tenant_id", "workspace_id");

-- CreateIndex
CREATE UNIQUE INDEX "pipeline_triggers_tenant_id_pipeline_id_trigger_key_key" ON "pipeline_triggers"("tenant_id", "pipeline_id", "trigger_key");

-- CreateIndex
CREATE UNIQUE INDEX "pipeline_triggers_tenant_id_id_key" ON "pipeline_triggers"("tenant_id", "id");

-- CreateIndex
CREATE INDEX "executions_tenant_id_pipeline_id_requested_at_idx" ON "executions"("tenant_id", "pipeline_id", "requested_at" DESC);

-- CreateIndex
CREATE INDEX "executions_tenant_id_workspace_id_status_requested_at_idx" ON "executions"("tenant_id", "workspace_id", "status", "requested_at" DESC);

-- CreateIndex
CREATE INDEX "executions_tenant_id_pipeline_id_concurrency_group_status_idx" ON "executions"("tenant_id", "pipeline_id", "concurrency_group", "status");

-- CreateIndex
CREATE INDEX "executions_status_requested_at_idx" ON "executions"("status", "requested_at");

-- CreateIndex
CREATE UNIQUE INDEX "executions_tenant_id_id_key" ON "executions"("tenant_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "executions_tenant_id_pipeline_id_idempotency_key_key" ON "executions"("tenant_id", "pipeline_id", "idempotency_key");

-- CreateIndex
CREATE UNIQUE INDEX "executions_tenant_id_pipeline_id_scm_event_id_key" ON "executions"("tenant_id", "pipeline_id", "scm_event_id");

-- CreateIndex
CREATE UNIQUE INDEX "executions_tenant_id_pipeline_id_schedule_slot_key" ON "executions"("tenant_id", "pipeline_id", "schedule_slot");

-- CreateIndex
CREATE INDEX "pipeline_trigger_decisions_tenant_id_pipeline_id_decided_at_idx" ON "pipeline_trigger_decisions"("tenant_id", "pipeline_id", "decided_at" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "pipeline_trigger_decisions_tenant_id_pipeline_id_scm_delive_key" ON "pipeline_trigger_decisions"("tenant_id", "pipeline_id", "scm_delivery_id", "scm_event_kind", "trigger_key");

-- CreateIndex
CREATE UNIQUE INDEX "repositories_tenant_id_workspace_id_id_key" ON "repositories"("tenant_id", "workspace_id", "id");

-- AddForeignKey
ALTER TABLE "pipelines" ADD CONSTRAINT "pipelines_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pipelines" ADD CONSTRAINT "pipelines_tenant_id_workspace_id_fkey" FOREIGN KEY ("tenant_id", "workspace_id") REFERENCES "workspaces"("tenant_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pipelines" ADD CONSTRAINT "pipelines_tenant_id_workspace_id_repository_id_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id") REFERENCES "repositories"("tenant_id", "workspace_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pipelines" ADD CONSTRAINT "pipelines_tenant_id_id_current_version_id_fkey" FOREIGN KEY ("tenant_id", "id", "current_version_id") REFERENCES "pipeline_config_versions"("tenant_id", "pipeline_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pipeline_config_versions" ADD CONSTRAINT "pipeline_config_versions_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pipeline_config_versions" ADD CONSTRAINT "pipeline_config_versions_tenant_id_pipeline_id_fkey" FOREIGN KEY ("tenant_id", "pipeline_id") REFERENCES "pipelines"("tenant_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pipeline_triggers" ADD CONSTRAINT "pipeline_triggers_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pipeline_triggers" ADD CONSTRAINT "pipeline_triggers_tenant_id_workspace_id_repository_id_pip_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id") REFERENCES "pipelines"("tenant_id", "workspace_id", "repository_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pipeline_triggers" ADD CONSTRAINT "pipeline_triggers_tenant_id_pipeline_id_version_id_fkey" FOREIGN KEY ("tenant_id", "pipeline_id", "version_id") REFERENCES "pipeline_config_versions"("tenant_id", "pipeline_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "executions" ADD CONSTRAINT "executions_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "executions" ADD CONSTRAINT "executions_tenant_id_workspace_id_repository_id_pipeline_i_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id") REFERENCES "pipelines"("tenant_id", "workspace_id", "repository_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "executions" ADD CONSTRAINT "executions_tenant_id_pipeline_id_config_version_id_fkey" FOREIGN KEY ("tenant_id", "pipeline_id", "config_version_id") REFERENCES "pipeline_config_versions"("tenant_id", "pipeline_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pipeline_trigger_decisions" ADD CONSTRAINT "pipeline_trigger_decisions_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pipeline_trigger_decisions" ADD CONSTRAINT "pipeline_trigger_decisions_tenant_id_workspace_id_reposito_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id") REFERENCES "pipelines"("tenant_id", "workspace_id", "repository_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- ====================================================================================================================
-- Hand-written part
-- ====================================================================================================================

-- Pipeline name: unique per repository, case-insensitive (name_normalized is lower-case), among non-deleted pipelines (R-2, R-5).
CREATE UNIQUE INDEX "pipelines_one_active_name_per_repository" ON "pipelines"("tenant_id", "repository_id", "name_normalized") WHERE "deleted_at" IS NULL;

-- Due schedules for the scheduler's FOR UPDATE SKIP LOCKED scan (SPEC §7.2, §6.4). Platform-wide scan, so no tenant column.
CREATE INDEX "pipeline_triggers_schedule_due_idx" ON "pipeline_triggers"("next_fire_at") WHERE "type" = 'schedule' AND "enabled";

-- pipelines
ALTER TABLE "pipelines" ADD CONSTRAINT "pipelines_name_check" CHECK (char_length("name") BETWEEN 1 AND 100 AND char_length("name_normalized") BETWEEN 1 AND 100);
ALTER TABLE "pipelines" ADD CONSTRAINT "pipelines_description_check" CHECK ("description" IS NULL OR char_length("description") <= 500);
-- current_version 0 / null pointer exists only between the pipeline insert and version 1 (same transaction); afterwards both are set.
ALTER TABLE "pipelines" ADD CONSTRAINT "pipelines_current_version_check" CHECK ("current_version" >= 0 AND ("current_version_id" IS NULL) = ("current_version" = 0));
ALTER TABLE "pipelines" ADD CONSTRAINT "pipelines_deleted_check" CHECK ("deleted_by_user_id" IS NULL OR "deleted_at" IS NOT NULL);

-- pipeline_config_versions
ALTER TABLE "pipeline_config_versions" ADD CONSTRAINT "pipeline_config_versions_version_check" CHECK ("version" >= 1 AND "schema_version" >= 1);
ALTER TABLE "pipeline_config_versions" ADD CONSTRAINT "pipeline_config_versions_hash_check" CHECK (char_length("config_hash") BETWEEN 1 AND 128);
ALTER TABLE "pipeline_config_versions" ADD CONSTRAINT "pipeline_config_versions_json_check" CHECK (jsonb_typeof("config") = 'object' AND jsonb_typeof("change_summary") = 'object');
ALTER TABLE "pipeline_config_versions" ADD CONSTRAINT "pipeline_config_versions_note_check" CHECK ("change_note" IS NULL OR char_length("change_note") <= 200);

-- pipeline_triggers: schedule fields are present for schedules (cron has 5 space-separated fields) and absent otherwise.
ALTER TABLE "pipeline_triggers" ADD CONSTRAINT "pipeline_triggers_key_check" CHECK (char_length("trigger_key") BETWEEN 1 AND 64);
ALTER TABLE "pipeline_triggers" ADD CONSTRAINT "pipeline_triggers_schedule_fields_check" CHECK (
  ("type" = 'schedule' AND "cron" IS NOT NULL AND "timezone" IS NOT NULL AND "missed_policy" IS NOT NULL AND "jitter_offset_seconds" IS NOT NULL)
  OR ("type" <> 'schedule' AND "cron" IS NULL AND "timezone" IS NULL AND "missed_policy" IS NULL AND "jitter_offset_seconds" IS NULL AND "next_fire_at" IS NULL AND "last_slot_at" IS NULL)
);
ALTER TABLE "pipeline_triggers" ADD CONSTRAINT "pipeline_triggers_cron_check" CHECK ("cron" IS NULL OR ("cron" ~ '^[^[:space:]]+( +[^[:space:]]+){4}$' AND char_length("cron") <= 100));
ALTER TABLE "pipeline_triggers" ADD CONSTRAINT "pipeline_triggers_timezone_check" CHECK ("timezone" IS NULL OR char_length("timezone") BETWEEN 1 AND 64);
ALTER TABLE "pipeline_triggers" ADD CONSTRAINT "pipeline_triggers_jitter_check" CHECK ("jitter_offset_seconds" IS NULL OR "jitter_offset_seconds" >= 0);

-- executions
ALTER TABLE "executions" ADD CONSTRAINT "executions_snapshot_check" CHECK ("config_version" >= 1 AND char_length("config_hash") BETWEEN 1 AND 128);
ALTER TABLE "executions" ADD CONSTRAINT "executions_trigger_key_check" CHECK (char_length("trigger_key") BETWEEN 1 AND 64);
-- Webhook triggers carry their SCM origin (and the event kind equals the trigger type); schedule and manual carry none.
ALTER TABLE "executions" ADD CONSTRAINT "executions_origin_check" CHECK (
  ("trigger_type" IN ('push', 'pull_request') AND "scm_event_id" IS NOT NULL AND "scm_delivery_id" IS NOT NULL AND "scm_event_kind" IS NOT NULL AND "scm_event_kind"::text = "trigger_type"::text)
  OR ("trigger_type" IN ('schedule', 'manual') AND "scm_event_id" IS NULL AND "scm_delivery_id" IS NULL AND "scm_event_kind" IS NULL)
);
ALTER TABLE "executions" ADD CONSTRAINT "executions_schedule_slot_check" CHECK (("trigger_type" = 'schedule') = ("schedule_slot" IS NOT NULL));
ALTER TABLE "executions" ADD CONSTRAINT "executions_requested_by_check" CHECK (("trigger_type" = 'manual') = ("requested_by_user_id" IS NOT NULL));
ALTER TABLE "executions" ADD CONSTRAINT "executions_ref_check" CHECK (
  ("ref_type" = 'pull_request') = ("trigger_type" = 'pull_request')
  AND ("ref_type" = 'pull_request') = ("pull_request_number" IS NOT NULL)
  AND ("pull_request_number" IS NULL OR "pull_request_number" > 0)
);
ALTER TABLE "executions" ADD CONSTRAINT "executions_trust_check" CHECK ("trust" = 'trusted' OR "trigger_type" = 'pull_request');
ALTER TABLE "executions" ADD CONSTRAINT "executions_status_reason_check" CHECK (
  ("status_reason" IS NULL OR "status_reason" ~ '^[a-z][a-z_]{0,63}$')
  AND ("status" NOT IN ('blocked', 'skipped', 'cancelled') OR "status_reason" IS NOT NULL)
);
ALTER TABLE "executions" ADD CONSTRAINT "executions_scan_kind_reason_check" CHECK ("scan_kind_reason" ~ '^[a-z][a-z_]{0,63}$');
ALTER TABLE "executions" ADD CONSTRAINT "executions_quota_check" CHECK (
  "quota_consumed" >= 0 AND ("quota_consumed" = 0 OR "quota_period" IS NOT NULL) AND ("quota_period" IS NULL OR "quota_period" ~ '^[0-9]{4}-[0-9]{2}$')
);
ALTER TABLE "executions" ADD CONSTRAINT "executions_shas_check" CHECK (
  ("commit_sha" IS NULL OR "commit_sha" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$') AND ("base_sha" IS NULL OR "base_sha" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$')
);
ALTER TABLE "executions" ADD CONSTRAINT "executions_lengths_check" CHECK (
  char_length("ref_name") BETWEEN 1 AND 255 AND ("base_ref" IS NULL OR char_length("base_ref") <= 255)
  AND char_length("concurrency_group") BETWEEN 1 AND 300 AND char_length("idempotency_key") BETWEEN 1 AND 400
  AND ("scm_delivery_id" IS NULL OR char_length("scm_delivery_id") <= 128) AND ("correlation_id" IS NULL OR char_length("correlation_id") <= 128)
);

-- pipeline_trigger_decisions: policy skips of webhook triggers only.
ALTER TABLE "pipeline_trigger_decisions" ADD CONSTRAINT "pipeline_trigger_decisions_origin_check" CHECK (
  "trigger_type" IN ('push', 'pull_request') AND "scm_event_kind"::text = "trigger_type"::text
);
ALTER TABLE "pipeline_trigger_decisions" ADD CONSTRAINT "pipeline_trigger_decisions_ref_check" CHECK (
  ("ref_type" = 'pull_request') = ("pull_request_number" IS NOT NULL) AND ("pull_request_number" IS NULL OR "pull_request_number" > 0)
);
ALTER TABLE "pipeline_trigger_decisions" ADD CONSTRAINT "pipeline_trigger_decisions_lengths_check" CHECK (
  char_length("trigger_key") BETWEEN 1 AND 64 AND char_length("scm_delivery_id") BETWEEN 1 AND 128
  AND char_length("ref_name") BETWEEN 1 AND 255 AND ("correlation_id" IS NULL OR char_length("correlation_id") <= 128)
);

-- Immutability. Configuration versions: no UPDATE, DELETE or TRUNCATE; an INSERT must be the pipeline's next version number
-- (1 for a new pipeline), so history has no gaps or rewrites (R-3, PIP-018).
CREATE FUNCTION forbid_pipeline_version_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% on % is not allowed: pipeline configuration versions are immutable', TG_OP, TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE FUNCTION require_next_pipeline_version() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  latest integer;
BEGIN
  SELECT COALESCE(MAX("version"), 0) INTO latest FROM "pipeline_config_versions" WHERE "tenant_id" = NEW."tenant_id" AND "pipeline_id" = NEW."pipeline_id";
  IF NEW."version" <> latest + 1 THEN
    RAISE EXCEPTION 'pipeline configuration version must be % (got %)', latest + 1, NEW."version" USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "pipeline_config_versions_immutable" BEFORE UPDATE OR DELETE ON "pipeline_config_versions" FOR EACH ROW EXECUTE FUNCTION forbid_pipeline_version_mutation();
CREATE TRIGGER "pipeline_config_versions_no_truncate" BEFORE TRUNCATE ON "pipeline_config_versions" FOR EACH STATEMENT EXECUTE FUNCTION forbid_pipeline_version_mutation();
CREATE TRIGGER "pipeline_config_versions_next_version" BEFORE INSERT ON "pipeline_config_versions" FOR EACH ROW EXECUTE FUNCTION require_next_pipeline_version();

-- Executions: everything except status, status_reason, updated_at and a one-time commit_sha (null -> value) is immutable, so the
-- configuration snapshot, trigger context and idempotency identity never change (PIP-018). DELETE stays possible for the
-- retention purge (Open, SPEC §7.6).
CREATE FUNCTION forbid_execution_snapshot_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (to_jsonb(NEW) - 'status' - 'status_reason' - 'updated_at' - 'commit_sha') IS DISTINCT FROM (to_jsonb(OLD) - 'status' - 'status_reason' - 'updated_at' - 'commit_sha') THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: only status, status_reason and the first commit_sha may change', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD."commit_sha" IS NOT NULL AND NEW."commit_sha" IS DISTINCT FROM OLD."commit_sha" THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: commit_sha is already pinned', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "executions_snapshot_immutable" BEFORE UPDATE ON "executions" FOR EACH ROW EXECUTE FUNCTION forbid_execution_snapshot_mutation();

-- Trigger decisions: insert-only (a redelivery writes nothing twice by the unique key; deletion only by the retention purge, Open).
CREATE FUNCTION forbid_pipeline_decision_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'UPDATE on % is not allowed: trigger decisions are insert-only', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "pipeline_trigger_decisions_insert_only" BEFORE UPDATE ON "pipeline_trigger_decisions" FOR EACH ROW EXECUTE FUNCTION forbid_pipeline_decision_update();
