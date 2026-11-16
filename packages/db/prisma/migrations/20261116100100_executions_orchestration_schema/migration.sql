-- SPEC executions (docs/modules/executions/SPEC.md) §7, part B, step 2 of 2: the database layer of the execution module.
-- Runs after 20261116100000_execution_status_partial (the enum value `partial` is committed and can be used here).
-- The generated part comes first (columns, tables, indexes, foreign keys); the hand-written part (CHECK constraints, partial
-- indexes, the state-machine and guard triggers) follows, because Prisma cannot express it.
--
-- Existing rows (queued, blocked, skipped, cancelled) migrate unchanged; see the pre-flight in the hand-written part for the
-- states that application code never wrote.

-- CreateEnum
CREATE TYPE "scan_task_type" AS ENUM ('sca', 'sbom', 'sast', 'secrets');

-- CreateEnum
CREATE TYPE "scan_task_status" AS ENUM ('pending', 'queued', 'running', 'succeeded', 'failed', 'timed_out', 'cancelled', 'skipped');

-- CreateEnum
CREATE TYPE "execution_cancel_mode" AS ENUM ('graceful', 'immediate');

-- DropIndex
DROP INDEX "executions_tenant_id_pipeline_id_schedule_slot_key";

-- DropIndex
DROP INDEX "executions_tenant_id_pipeline_id_scm_event_id_key";

-- AlterTable
ALTER TABLE "executions" ADD COLUMN     "archive_bytes" BIGINT,
ADD COLUMN     "archive_sha256" TEXT,
ADD COLUMN     "cancel_grace_until" TIMESTAMPTZ(6),
ADD COLUMN     "cancel_mode" "execution_cancel_mode",
ADD COLUMN     "cancel_requested_at" TIMESTAMPTZ(6),
ADD COLUMN     "cancel_requested_by_user_id" UUID,
ADD COLUMN     "claimed_at" TIMESTAMPTZ(6),
ADD COLUMN     "deadline_at" TIMESTAMPTZ(6),
ADD COLUMN     "finished_at" TIMESTAMPTZ(6),
ADD COLUMN     "heartbeat_at" TIMESTAMPTZ(6),
ADD COLUMN     "lease_epoch" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "lease_expires_at" TIMESTAMPTZ(6),
ADD COLUMN     "lease_owner" TEXT,
ADD COLUMN     "quota_released_at" TIMESTAMPTZ(6),
ADD COLUMN     "retry_of_execution_id" UUID,
ADD COLUMN     "started_at" TIMESTAMPTZ(6),
ADD COLUMN     "status_rev" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "task_counts" JSONB;

-- CreateTable
CREATE TABLE "execution_events" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "seq" INTEGER NOT NULL DEFAULT 0,
    "type" TEXT NOT NULL,
    "from_status" "execution_status",
    "to_status" "execution_status",
    "reason" TEXT,
    "actor_type" TEXT NOT NULL DEFAULT 'system',
    "actor_user_id" UUID,
    "at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "correlation_id" TEXT,
    "details" JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT "execution_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_tasks" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "scan_type" "scan_task_type" NOT NULL,
    "ordinal" INTEGER NOT NULL,
    "status" "scan_task_status" NOT NULL DEFAULT 'pending',
    "status_reason" TEXT,
    "status_rev" INTEGER NOT NULL DEFAULT 0,
    "attempt" INTEGER NOT NULL DEFAULT 0,
    "max_attempts" INTEGER NOT NULL DEFAULT 2,
    "engine_id" TEXT NOT NULL,
    "engine_profile" TEXT NOT NULL,
    "severity_threshold" TEXT NOT NULL,
    "timeout_seconds" INTEGER NOT NULL,
    "queued_at" TIMESTAMPTZ(6),
    "started_at" TIMESTAMPTZ(6),
    "finished_at" TIMESTAMPTZ(6),
    "deadline_at" TIMESTAMPTZ(6),
    "lease_owner" TEXT,
    "lease_expires_at" TIMESTAMPTZ(6),
    "heartbeat_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "scan_tasks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_task_attempts" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "scan_task_id" UUID NOT NULL,
    "attempt" INTEGER NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'running',
    "error_class" TEXT,
    "error_code" TEXT,
    "worker_id" TEXT,
    "started_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finished_at" TIMESTAMPTZ(6),
    "duration_ms" INTEGER,

    CONSTRAINT "scan_task_attempts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_results" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "scan_task_id" UUID NOT NULL,
    "attempt" INTEGER NOT NULL,
    "scan_type" "scan_task_type" NOT NULL,
    "schema_version" INTEGER NOT NULL DEFAULT 1,
    "engine_id" TEXT NOT NULL,
    "engine_version" TEXT NOT NULL,
    "completeness" TEXT NOT NULL,
    "truncated" BOOLEAN NOT NULL DEFAULT false,
    "item_count" INTEGER NOT NULL DEFAULT 0,
    "severity_counts" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_result_items" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "scan_result_id" UUID NOT NULL,
    "ordinal" INTEGER NOT NULL,
    "kind" TEXT NOT NULL,
    "rule_id" TEXT,
    "severity" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "path" TEXT,
    "start_line" INTEGER,
    "end_line" INTEGER,
    "component_purl" TEXT,
    "component_version" TEXT,
    "data" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_result_items_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "execution_orchestrator_markers" (
    "marker_key" TEXT NOT NULL,
    "first_enabled_at" TIMESTAMPTZ(6) NOT NULL,
    "sweep_started_at" TIMESTAMPTZ(6),
    "sweep_completed_at" TIMESTAMPTZ(6),
    "swept_count" INTEGER NOT NULL DEFAULT 0,
    "sweep_lease_owner" TEXT,
    "sweep_lease_expires_at" TIMESTAMPTZ(6),

    CONSTRAINT "execution_orchestrator_markers_pkey" PRIMARY KEY ("marker_key")
);

-- CreateIndex
CREATE UNIQUE INDEX "execution_events_tenant_id_execution_id_seq_key" ON "execution_events"("tenant_id", "execution_id", "seq");

-- CreateIndex
CREATE INDEX "scan_tasks_tenant_id_execution_id_ordinal_idx" ON "scan_tasks"("tenant_id", "execution_id", "ordinal");

-- CreateIndex
CREATE UNIQUE INDEX "scan_tasks_tenant_id_execution_id_scan_type_key" ON "scan_tasks"("tenant_id", "execution_id", "scan_type");

-- CreateIndex
CREATE UNIQUE INDEX "scan_tasks_tenant_id_id_key" ON "scan_tasks"("tenant_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "scan_tasks_tenant_id_workspace_id_repository_id_pipeline_id_key" ON "scan_tasks"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "scan_task_attempts_tenant_id_scan_task_id_attempt_key" ON "scan_task_attempts"("tenant_id", "scan_task_id", "attempt");

-- CreateIndex
CREATE UNIQUE INDEX "scan_results_tenant_id_scan_task_id_key" ON "scan_results"("tenant_id", "scan_task_id");

-- CreateIndex
CREATE UNIQUE INDEX "scan_results_tenant_id_execution_id_id_key" ON "scan_results"("tenant_id", "execution_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "scan_result_items_tenant_id_scan_result_id_ordinal_key" ON "scan_result_items"("tenant_id", "scan_result_id", "ordinal");

-- CreateIndex
CREATE INDEX "executions_tenant_id_workspace_id_requested_at_id_idx" ON "executions"("tenant_id", "workspace_id", "requested_at" DESC, "id" DESC);

-- CreateIndex
CREATE INDEX "executions_tenant_id_pipeline_id_requested_at_id_idx" ON "executions"("tenant_id", "pipeline_id", "requested_at" DESC, "id" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "executions_tenant_id_pipeline_id_id_key" ON "executions"("tenant_id", "pipeline_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "executions_tenant_id_workspace_id_repository_id_pipeline_id_key" ON "executions"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "id");

-- AddForeignKey
ALTER TABLE "execution_events" ADD CONSTRAINT "execution_events_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "execution_events" ADD CONSTRAINT "execution_events_tenant_id_workspace_id_repository_id_pipe_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id") REFERENCES "executions"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_tasks" ADD CONSTRAINT "scan_tasks_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_tasks" ADD CONSTRAINT "scan_tasks_tenant_id_workspace_id_repository_id_pipeline_i_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id") REFERENCES "executions"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_task_attempts" ADD CONSTRAINT "scan_task_attempts_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_task_attempts" ADD CONSTRAINT "scan_task_attempts_tenant_id_workspace_id_repository_id_pi_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "scan_task_id") REFERENCES "scan_tasks"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_tenant_id_workspace_id_repository_id_pipeline_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "scan_task_id") REFERENCES "scan_tasks"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_result_items" ADD CONSTRAINT "scan_result_items_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_result_items" ADD CONSTRAINT "scan_result_items_tenant_id_execution_id_scan_result_id_fkey" FOREIGN KEY ("tenant_id", "execution_id", "scan_result_id") REFERENCES "scan_results"("tenant_id", "execution_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "executions" ADD CONSTRAINT "executions_tenant_id_pipeline_id_retry_of_execution_id_fkey" FOREIGN KEY ("tenant_id", "pipeline_id", "retry_of_execution_id") REFERENCES "executions"("tenant_id", "pipeline_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;



-- ====================================================================================================================
-- Hand-written part
-- ====================================================================================================================

-- ---- 1. Retire the old executions trigger, check what the new rules would reject, normalise what is certain ---------------
-- The previous guard only allowed status, status_reason, updated_at and a one-time commit_sha to change and validated no
-- transition (SPEC CF-2). The new guard (section 4 below) is a strict superset. It is dropped first so the backfill can run.
DROP TRIGGER "executions_snapshot_immutable" ON "executions";
DROP FUNCTION forbid_execution_snapshot_mutation();

-- Pre-flight. The pipelines module only ever wrote queued, blocked, skipped and cancelled (with a reason), so none of these
-- can exist in a database that only ran application code. A hand-edited row would make the new CHECK constraints fail with an
-- unhelpful message, so say what is wrong instead of guessing a repair.
DO $$
DECLARE
  n integer;
BEGIN
  SELECT count(*) INTO n FROM "executions" WHERE "status" = 'cancelling';
  IF n > 0 THEN
    RAISE EXCEPTION 'executions: % row(s) are in the legacy status cancelling, which is never written any more (SPEC CF-1); resolve them by hand before migrating', n USING ERRCODE = 'check_violation';
  END IF;
  SELECT count(*) INTO n FROM "executions" WHERE "status" IN ('failed', 'timed_out') AND "status_reason" IS NULL;
  IF n > 0 THEN
    RAISE EXCEPTION 'executions: % failed/timed_out row(s) without status_reason; the new rule requires a reason on every unsuccessful terminal status', n USING ERRCODE = 'check_violation';
  END IF;
  SELECT count(*) INTO n FROM "executions" WHERE "status" IN ('queued', 'preparing', 'running', 'succeeded') AND "status_reason" IS NOT NULL;
  IF n > 0 THEN
    RAISE EXCEPTION 'executions: % queued/preparing/running/succeeded row(s) carry a status_reason; the new rule allows a reason only on blocked, skipped, cancelled, failed, partial and timed_out', n USING ERRCODE = 'check_violation';
  END IF;
  SELECT count(*) INTO n FROM "executions" WHERE "status" IN ('preparing', 'running');
  IF n > 0 THEN
    RAISE EXCEPTION 'executions: % row(s) are preparing/running without a lease; no worker has ever driven an execution, so they were written by hand', n USING ERRCODE = 'check_violation';
  END IF;
END;
$$;

-- A cancelled row has gone through exactly one status change (queued -> cancelled) and the cancel time is its last update.
UPDATE "executions" SET "status_rev" = 1, "finished_at" = "updated_at" WHERE "status" = 'cancelled' AND "finished_at" IS NULL;

-- ---- 2. Partial indexes ------------------------------------------------------------------------------------------------
-- A retry repeats the origin of the execution it retries (same SCM event, same schedule slot), so the unique keys of the
-- original request only cover the original requests (CF-2c). Prisma cannot model partial indexes.
CREATE UNIQUE INDEX "executions_origin_event_unique" ON "executions"("tenant_id", "pipeline_id", "scm_event_id") WHERE "retry_of_execution_id" IS NULL;
CREATE UNIQUE INDEX "executions_origin_slot_unique" ON "executions"("tenant_id", "pipeline_id", "schedule_slot") WHERE "retry_of_execution_id" IS NULL;
-- Claim peek (oldest queued first), deadline sweep and lease reclaim peek: platform-wide scans that return ids only.
CREATE INDEX "executions_queued_claim_idx" ON "executions"("requested_at", "id") WHERE "status" = 'queued';
CREATE INDEX "executions_deadline_idx" ON "executions"("deadline_at") WHERE "status" IN ('preparing', 'running');
CREATE INDEX "executions_lease_expiry_idx" ON "executions"("lease_expires_at") WHERE "status" IN ('preparing', 'running');

-- ---- 3. executions: CHECK constraints -------------------------------------------------------------------------------------
-- `cancelling` stays in the enum (PostgreSQL cannot drop a value) but can never be written (CF-1): a cancel request is the
-- cancel_* columns of a preparing/running row.
ALTER TABLE "executions" ADD CONSTRAINT "executions_not_cancelling_check" CHECK ("status" <> 'cancelling');

-- Origin: webhook triggers carry their SCM origin, schedule and manual carry none; a RETRY (retry_of_execution_id) copies the
-- origin of the execution it retries (all of it, or none of it).
ALTER TABLE "executions" DROP CONSTRAINT "executions_origin_check";
ALTER TABLE "executions" ADD CONSTRAINT "executions_origin_check" CHECK (
  ("trigger_type" IN ('push', 'pull_request') AND "scm_event_id" IS NOT NULL AND "scm_delivery_id" IS NOT NULL AND "scm_event_kind" IS NOT NULL AND "scm_event_kind"::text = "trigger_type"::text)
  OR ("trigger_type" IN ('schedule', 'manual') AND "scm_event_id" IS NULL AND "scm_delivery_id" IS NULL AND "scm_event_kind" IS NULL)
  OR ("retry_of_execution_id" IS NOT NULL AND (
    ("scm_event_id" IS NULL AND "scm_delivery_id" IS NULL AND "scm_event_kind" IS NULL)
    OR ("scm_delivery_id" IS NOT NULL AND "scm_event_kind" IS NOT NULL AND "scm_event_kind"::text = "trigger_type"::text)
  ))
);
-- Requested by a user: a manual run or a retry (the person who retried), nobody else.
ALTER TABLE "executions" DROP CONSTRAINT "executions_requested_by_check";
ALTER TABLE "executions" ADD CONSTRAINT "executions_requested_by_check" CHECK (
  ("trigger_type" = 'manual' OR "retry_of_execution_id" IS NOT NULL) = ("requested_by_user_id" IS NOT NULL)
);
-- A reason is required exactly for the statuses that need explaining; codes may carry one ':' qualifier (prepare_failed:<code>).
ALTER TABLE "executions" DROP CONSTRAINT "executions_status_reason_check";
ALTER TABLE "executions" ADD CONSTRAINT "executions_status_reason_check" CHECK (
  ("status_reason" IS NULL OR "status_reason" ~ '^[a-z][a-z_:]{0,63}$')
  AND (("status" IN ('blocked', 'skipped', 'cancelled', 'failed', 'partial', 'timed_out')) = ("status_reason" IS NOT NULL))
);
ALTER TABLE "executions" ADD CONSTRAINT "executions_retry_check" CHECK ("retry_of_execution_id" IS NULL OR "retry_of_execution_id" <> "id");
ALTER TABLE "executions" ADD CONSTRAINT "executions_lifecycle_check" CHECK (
  "status_rev" >= 0 AND "lease_epoch" >= 0
  AND ("finished_at" IS NULL OR "status" IN ('succeeded', 'failed', 'partial', 'cancelled', 'timed_out'))
  AND ("task_counts" IS NULL OR jsonb_typeof("task_counts") = 'object')
);
-- Cancel request: all four columns together, once (ER-18).
ALTER TABLE "executions" ADD CONSTRAINT "executions_cancel_check" CHECK (
  ("cancel_requested_at" IS NULL) = ("cancel_requested_by_user_id" IS NULL)
  AND ("cancel_requested_at" IS NULL) = ("cancel_mode" IS NULL)
  AND ("cancel_requested_at" IS NULL) = ("cancel_grace_until" IS NULL)
  AND ("cancel_grace_until" IS NULL OR "cancel_grace_until" >= "cancel_requested_at")
);
-- Lease (ER-27): owner, expiry and heartbeat together; held exactly while the execution is preparing or running, so a row that
-- is being worked on always has an expiry the reclaim peek can find.
ALTER TABLE "executions" ADD CONSTRAINT "executions_lease_check" CHECK (
  ("lease_owner" IS NULL) = ("lease_expires_at" IS NULL)
  AND ("lease_owner" IS NULL) = ("heartbeat_at" IS NULL)
  AND (("status" IN ('preparing', 'running')) = ("lease_owner" IS NOT NULL))
  AND ("lease_owner" IS NULL OR char_length("lease_owner") BETWEEN 1 AND 128)
);
-- A quota unit is given back at most once, and only when one was taken (section 5.9).
ALTER TABLE "executions" ADD CONSTRAINT "executions_quota_release_check" CHECK ("quota_released_at" IS NULL OR "quota_consumed" > 0);
ALTER TABLE "executions" ADD CONSTRAINT "executions_archive_check" CHECK (
  ("archive_sha256" IS NULL) = ("archive_bytes" IS NULL)
  AND ("archive_sha256" IS NULL OR "archive_sha256" ~ '^[0-9a-f]{64}$')
  AND ("archive_bytes" IS NULL OR "archive_bytes" >= 0)
);

-- ---- 4. State machine and guard of `executions` ---------------------------------------------------------------------------
-- The ONLY allowed status changes (SPEC §6.1). The same table is exported by @qmentisai/shared (EXECUTION_TRANSITIONS); the
-- security suite compares both for every pair of statuses (EXECDB-012).
CREATE FUNCTION execution_transition_allowed(from_status "execution_status", to_status "execution_status") RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT (from_status::text, to_status::text) IN (
    ('queued', 'preparing'), ('queued', 'cancelled'),
    ('preparing', 'running'), ('preparing', 'failed'), ('preparing', 'cancelled'), ('preparing', 'timed_out'),
    ('running', 'succeeded'), ('running', 'partial'), ('running', 'failed'), ('running', 'cancelled'), ('running', 'timed_out')
  );
$$;

-- Terminal: no UPDATE of any column is ever accepted again. blocked and skipped are terminal at creation.
CREATE FUNCTION execution_status_is_terminal(s "execution_status") RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT s::text IN ('succeeded', 'failed', 'partial', 'cancelled', 'timed_out', 'blocked', 'skipped');
$$;

-- Outcome: terminal after having been requested (a finish time exists).
CREATE FUNCTION execution_status_is_outcome(s "execution_status") RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT s::text IN ('succeeded', 'failed', 'partial', 'cancelled', 'timed_out');
$$;

CREATE FUNCTION guard_execution_update() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  changing boolean := NEW."status" IS DISTINCT FROM OLD."status";
  oj jsonb := to_jsonb(OLD);
  nj jsonb := to_jsonb(NEW);
  col text;
BEGIN
  IF execution_status_is_terminal(OLD."status") THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: the execution is % (terminal executions are immutable)', TG_TABLE_NAME, OLD."status" USING ERRCODE = 'restrict_violation';
  END IF;

  -- Everything that is not lifecycle is the snapshot and never changes.
  IF (nj - ARRAY['status', 'status_reason', 'status_rev', 'updated_at', 'commit_sha', 'claimed_at', 'started_at', 'finished_at', 'deadline_at', 'task_counts',
        'cancel_requested_at', 'cancel_requested_by_user_id', 'cancel_mode', 'cancel_grace_until', 'lease_owner', 'lease_epoch', 'lease_expires_at', 'heartbeat_at',
        'quota_released_at', 'archive_sha256', 'archive_bytes'])
     IS DISTINCT FROM
     (oj - ARRAY['status', 'status_reason', 'status_rev', 'updated_at', 'commit_sha', 'claimed_at', 'started_at', 'finished_at', 'deadline_at', 'task_counts',
        'cancel_requested_at', 'cancel_requested_by_user_id', 'cancel_mode', 'cancel_grace_until', 'lease_owner', 'lease_epoch', 'lease_expires_at', 'heartbeat_at',
        'quota_released_at', 'archive_sha256', 'archive_bytes']) THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: only the lifecycle columns may change (the configuration snapshot, trigger context and idempotency identity are immutable)', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;

  -- One-time columns accept null -> value only.
  FOREACH col IN ARRAY ARRAY['commit_sha', 'claimed_at', 'started_at', 'finished_at', 'deadline_at', 'task_counts', 'cancel_requested_at', 'cancel_requested_by_user_id',
      'cancel_mode', 'cancel_grace_until', 'quota_released_at', 'archive_sha256', 'archive_bytes'] LOOP
    IF oj -> col <> 'null'::jsonb AND nj -> col IS DISTINCT FROM oj -> col THEN
      RAISE EXCEPTION 'UPDATE on % is not allowed: % is already set and can only be set once', TG_TABLE_NAME, col USING ERRCODE = 'restrict_violation';
    END IF;
  END LOOP;

  IF changing THEN
    IF NOT execution_transition_allowed(OLD."status", NEW."status") THEN
      RAISE EXCEPTION 'execution status transition % -> % is not allowed', OLD."status", NEW."status" USING ERRCODE = 'restrict_violation';
    END IF;
    -- status_rev follows every status change: assigned here unless the writer sent exactly the next value.
    IF NEW."status_rev" = OLD."status_rev" THEN
      NEW."status_rev" := OLD."status_rev" + 1;
    ELSIF NEW."status_rev" <> OLD."status_rev" + 1 THEN
      RAISE EXCEPTION 'status_rev must follow the status change (% -> %, got %)', OLD."status_rev", OLD."status_rev" + 1, NEW."status_rev" USING ERRCODE = 'restrict_violation';
    END IF;
  ELSE
    IF NEW."status_rev" <> OLD."status_rev" THEN
      RAISE EXCEPTION 'status_rev changes only together with the status' USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW."status_reason" IS DISTINCT FROM OLD."status_reason" THEN
      RAISE EXCEPTION 'status_reason changes only together with the status' USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;

  -- Lifecycle timestamps belong to one transition each.
  IF NEW."claimed_at" IS DISTINCT FROM OLD."claimed_at" OR NEW."deadline_at" IS DISTINCT FROM OLD."deadline_at" THEN
    IF NOT (OLD."status" = 'queued' AND NEW."status" = 'preparing') THEN
      RAISE EXCEPTION 'claimed_at and deadline_at are set by the claim (queued -> preparing) only' USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  IF NEW."started_at" IS DISTINCT FROM OLD."started_at" AND NOT (OLD."status" = 'preparing' AND NEW."status" = 'running') THEN
    RAISE EXCEPTION 'started_at is set by preparing -> running only' USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW."archive_sha256" IS DISTINCT FROM OLD."archive_sha256" AND OLD."status" <> 'preparing' THEN
    RAISE EXCEPTION 'the archive facts are recorded while the execution is preparing' USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW."cancel_requested_at" IS DISTINCT FROM OLD."cancel_requested_at" AND OLD."status" NOT IN ('preparing', 'running') THEN
    RAISE EXCEPTION 'a cancel request is recorded on a preparing or running execution (a queued execution is cancelled directly)' USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW."task_counts" IS DISTINCT FROM OLD."task_counts" AND NOT (changing AND execution_status_is_outcome(NEW."status")) THEN
    RAISE EXCEPTION 'task_counts is set once, by the statement that makes the execution terminal' USING ERRCODE = 'restrict_violation';
  END IF;
  -- A quota unit is given back only by the statement that ends an execution before any scan task started (section 5.9).
  IF NEW."quota_released_at" IS DISTINCT FROM OLD."quota_released_at" THEN
    IF NOT ((OLD."status", NEW."status") IN (('queued', 'cancelled'), ('preparing', 'cancelled'), ('preparing', 'failed'))) THEN
      RAISE EXCEPTION 'quota_released_at is set only by queued -> cancelled, preparing -> cancelled or preparing -> failed' USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;

  IF changing AND OLD."status" = 'queued' AND NEW."status" = 'preparing' THEN
    NEW."claimed_at" := COALESCE(NEW."claimed_at", now());
    IF NEW."deadline_at" IS NULL THEN
      RAISE EXCEPTION 'the claim must set deadline_at' USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW."lease_epoch" <> OLD."lease_epoch" + 1 THEN
      RAISE EXCEPTION 'the claim must increase lease_epoch by one (% -> got %)', OLD."lease_epoch", NEW."lease_epoch" USING ERRCODE = 'restrict_violation';
    END IF;
  ELSIF changing AND OLD."status" = 'preparing' AND NEW."status" = 'running' THEN
    NEW."started_at" := COALESCE(NEW."started_at", now());
  END IF;

  -- Lease (ER-27, ER-28): the epoch only grows, by exactly one per claim or reclaim; a renewal never moves time backwards; a
  -- terminal row holds no lease and keeps its last epoch. WHO may write is decided by the WHERE clause of the data-access
  -- functions (ER-30); the database guarantees monotonic epochs and clean terminal rows.
  IF execution_status_is_terminal(NEW."status") THEN
    IF NEW."lease_owner" IS NOT NULL OR NEW."lease_expires_at" IS NOT NULL OR NEW."heartbeat_at" IS NOT NULL THEN
      RAISE EXCEPTION 'a terminal execution holds no lease; clear the lease in the statement that ends the execution' USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW."lease_epoch" <> OLD."lease_epoch" THEN
      RAISE EXCEPTION 'lease_epoch is kept when the execution ends' USING ERRCODE = 'restrict_violation';
    END IF;
    IF execution_status_is_outcome(NEW."status") THEN
      NEW."finished_at" := COALESCE(NEW."finished_at", now());
    END IF;
  ELSE
    IF NEW."lease_epoch" NOT IN (OLD."lease_epoch", OLD."lease_epoch" + 1) THEN
      RAISE EXCEPTION 'lease_epoch only grows, by one per claim or reclaim (% -> got %)', OLD."lease_epoch", NEW."lease_epoch" USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW."lease_epoch" = OLD."lease_epoch" AND OLD."lease_owner" IS NOT NULL AND NEW."lease_owner" IS NOT NULL
       AND (NEW."lease_expires_at" < OLD."lease_expires_at" OR NEW."heartbeat_at" < OLD."heartbeat_at") THEN
      RAISE EXCEPTION 'a lease renewal never moves the expiry or the heartbeat backwards' USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "executions_guard" BEFORE UPDATE ON "executions" FOR EACH ROW EXECUTE FUNCTION guard_execution_update();

-- Every status change writes its `transition` event in the same statement (EXEC-003). Who did it comes from transaction-local
-- settings that the data-access functions set (qm.actor_type user|system, qm.actor_user_id, qm.correlation_id, qm.event_details);
-- without them the actor is the system.
CREATE FUNCTION record_execution_transition() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  actor text := COALESCE(NULLIF(current_setting('qm.actor_type', true), ''), 'system');
BEGIN
  INSERT INTO "execution_events" ("id", "tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "type", "from_status", "to_status", "reason",
      "actor_type", "actor_user_id", "correlation_id", "details")
  VALUES (gen_random_uuid(), NEW."tenant_id", NEW."workspace_id", NEW."repository_id", NEW."pipeline_id", NEW."id", 'transition', OLD."status", NEW."status", NEW."status_reason",
      actor, NULLIF(current_setting('qm.actor_user_id', true), '')::uuid, NULLIF(current_setting('qm.correlation_id', true), ''),
      COALESCE(NULLIF(current_setting('qm.event_details', true), '')::jsonb, '{}'::jsonb));
  RETURN NULL;
END;
$$;

CREATE TRIGGER "executions_record_transition" AFTER UPDATE ON "executions" FOR EACH ROW WHEN (OLD."status" IS DISTINCT FROM NEW."status") EXECUTE FUNCTION record_execution_transition();

-- Retention purge (Open) may delete executions; nothing may empty the tables.
CREATE FUNCTION forbid_execution_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'TRUNCATE on % is not allowed', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "executions_no_truncate" BEFORE TRUNCATE ON "executions" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

-- ---- 5. execution_events ------------------------------------------------------------------------------------------------
ALTER TABLE "execution_events" ADD CONSTRAINT "execution_events_type_check" CHECK ("type" IN ('transition', 'recovered', 'cancel_requested', 'limit_deferred', 'retry_requested'));
ALTER TABLE "execution_events" ADD CONSTRAINT "execution_events_seq_check" CHECK ("seq" >= 1);
ALTER TABLE "execution_events" ADD CONSTRAINT "execution_events_status_check" CHECK (
  ("type" <> 'transition' OR ("from_status" IS NOT NULL AND "to_status" IS NOT NULL AND "from_status" <> "to_status"))
  AND ("from_status" IS NULL OR "from_status" <> 'cancelling') AND ("to_status" IS NULL OR "to_status" <> 'cancelling')
);
ALTER TABLE "execution_events" ADD CONSTRAINT "execution_events_actor_check" CHECK ("actor_type" IN ('user', 'system') AND (("actor_type" = 'user') = ("actor_user_id" IS NOT NULL)));
ALTER TABLE "execution_events" ADD CONSTRAINT "execution_events_text_check" CHECK (
  ("reason" IS NULL OR "reason" ~ '^[a-z][a-z_:]{0,63}$') AND ("correlation_id" IS NULL OR char_length("correlation_id") <= 128)
  AND jsonb_typeof("details") = 'object' AND octet_length("details"::text) <= 4096
);

-- Assigns seq (1, 2, ... per execution) under a lock on the execution row, and refuses events for a terminal execution except
-- the one `transition` event that made it terminal (written by record_execution_transition in the same statement).
CREATE FUNCTION before_insert_execution_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  parent_status "execution_status";
BEGIN
  SELECT "status" INTO parent_status FROM "executions" WHERE "tenant_id" = NEW."tenant_id" AND "id" = NEW."execution_id" FOR UPDATE;
  IF NOT FOUND THEN
    NEW."seq" := 1;
    RETURN NEW; -- the foreign key reports the missing parent
  END IF;
  IF execution_status_is_terminal(parent_status) THEN
    IF NOT (NEW."type" = 'transition' AND NEW."to_status" = parent_status AND execution_status_is_outcome(parent_status)
            AND NOT EXISTS (SELECT 1 FROM "execution_events" e WHERE e."tenant_id" = NEW."tenant_id" AND e."execution_id" = NEW."execution_id" AND e."type" = 'transition' AND e."to_status" = parent_status)) THEN
      RAISE EXCEPTION 'INSERT on % is not allowed: the execution is % (terminal)', TG_TABLE_NAME, parent_status USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  SELECT COALESCE(MAX("seq"), 0) + 1 INTO NEW."seq" FROM "execution_events" WHERE "tenant_id" = NEW."tenant_id" AND "execution_id" = NEW."execution_id";
  RETURN NEW;
END;
$$;

CREATE TRIGGER "execution_events_before_insert" BEFORE INSERT ON "execution_events" FOR EACH ROW EXECUTE FUNCTION before_insert_execution_event();

CREATE FUNCTION forbid_execution_child_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'UPDATE on % is not allowed: the table is insert-only', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "execution_events_insert_only" BEFORE UPDATE ON "execution_events" FOR EACH ROW EXECUTE FUNCTION forbid_execution_child_update();
CREATE TRIGGER "execution_events_no_truncate" BEFORE TRUNCATE ON "execution_events" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

-- ---- 6. scan_tasks --------------------------------------------------------------------------------------------------------
ALTER TABLE "scan_tasks" ADD CONSTRAINT "scan_tasks_values_check" CHECK (
  "ordinal" >= 0 AND "status_rev" >= 0 AND "timeout_seconds" > 0
  AND "max_attempts" BETWEEN 1 AND 10 AND "attempt" >= 0 AND "attempt" < "max_attempts"
  AND "severity_threshold" IN ('critical', 'high', 'medium', 'low', 'info')
  AND char_length("engine_id") BETWEEN 1 AND 100 AND char_length("engine_profile") BETWEEN 1 AND 100
);
ALTER TABLE "scan_tasks" ADD CONSTRAINT "scan_tasks_status_reason_check" CHECK (
  ("status_reason" IS NULL OR "status_reason" ~ '^[a-z][a-z_:]{0,63}$')
  AND (("status" IN ('failed', 'timed_out', 'cancelled', 'skipped')) = ("status_reason" IS NOT NULL))
);
ALTER TABLE "scan_tasks" ADD CONSTRAINT "scan_tasks_lease_check" CHECK (
  ("lease_owner" IS NULL) = ("lease_expires_at" IS NULL) AND ("lease_owner" IS NULL) = ("heartbeat_at" IS NULL)
  AND (("status" = 'running') = ("lease_owner" IS NOT NULL))
  AND ("lease_owner" IS NULL OR char_length("lease_owner") BETWEEN 1 AND 128)
);
ALTER TABLE "scan_tasks" ADD CONSTRAINT "scan_tasks_finished_check" CHECK (
  ("finished_at" IS NOT NULL) = ("status" IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'skipped'))
);

CREATE FUNCTION scan_task_transition_allowed(from_status "scan_task_status", to_status "scan_task_status") RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT (from_status::text, to_status::text) IN (
    ('pending', 'queued'), ('pending', 'cancelled'), ('pending', 'skipped'),
    ('queued', 'running'), ('queued', 'cancelled'), ('queued', 'skipped'),
    ('running', 'queued'), ('running', 'succeeded'), ('running', 'failed'), ('running', 'timed_out'), ('running', 'cancelled')
  );
$$;

CREATE FUNCTION scan_task_status_is_terminal(s "scan_task_status") RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT s::text IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'skipped');
$$;

CREATE FUNCTION guard_scan_task_change() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  parent_status "execution_status";
  oj jsonb;
  nj jsonb;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT "status" INTO parent_status FROM "executions" WHERE "tenant_id" = NEW."tenant_id" AND "id" = NEW."execution_id";
    IF FOUND AND execution_status_is_terminal(parent_status) THEN
      RAISE EXCEPTION 'INSERT on % is not allowed: the execution is % (terminal)', TG_TABLE_NAME, parent_status USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW."status" NOT IN ('pending', 'queued') OR NEW."attempt" <> 0 OR NEW."status_rev" <> 0 THEN
      RAISE EXCEPTION 'a scan task is created pending or queued, at attempt 0' USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
  END IF;

  IF scan_task_status_is_terminal(OLD."status") THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: the task is % (terminal tasks are immutable)', TG_TABLE_NAME, OLD."status" USING ERRCODE = 'restrict_violation';
  END IF;
  oj := to_jsonb(OLD);
  nj := to_jsonb(NEW);
  IF (nj - ARRAY['status', 'status_reason', 'status_rev', 'attempt', 'queued_at', 'started_at', 'finished_at', 'deadline_at', 'lease_owner', 'lease_expires_at', 'heartbeat_at', 'updated_at'])
     IS DISTINCT FROM
     (oj - ARRAY['status', 'status_reason', 'status_rev', 'attempt', 'queued_at', 'started_at', 'finished_at', 'deadline_at', 'lease_owner', 'lease_expires_at', 'heartbeat_at', 'updated_at']) THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: only the lifecycle columns may change', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF (oj -> 'queued_at' <> 'null'::jsonb AND nj -> 'queued_at' IS DISTINCT FROM oj -> 'queued_at') OR (oj -> 'started_at' <> 'null'::jsonb AND nj -> 'started_at' IS DISTINCT FROM oj -> 'started_at') THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: queued_at and started_at are set once', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;

  IF NEW."status" IS DISTINCT FROM OLD."status" THEN
    IF NOT scan_task_transition_allowed(OLD."status", NEW."status") THEN
      RAISE EXCEPTION 'scan task status transition % -> % is not allowed', OLD."status", NEW."status" USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW."status_rev" = OLD."status_rev" THEN
      NEW."status_rev" := OLD."status_rev" + 1;
    ELSIF NEW."status_rev" <> OLD."status_rev" + 1 THEN
      RAISE EXCEPTION 'status_rev must follow the status change' USING ERRCODE = 'restrict_violation';
    END IF;
    IF scan_task_status_is_terminal(NEW."status") THEN
      NEW."finished_at" := COALESCE(NEW."finished_at", now());
    END IF;
    IF NEW."status" = 'queued' AND OLD."status" = 'pending' THEN
      NEW."queued_at" := COALESCE(NEW."queued_at", now());
    ELSIF NEW."status" = 'running' THEN
      NEW."started_at" := COALESCE(NEW."started_at", now());
    END IF;
  ELSE
    IF NEW."status_rev" <> OLD."status_rev" OR NEW."status_reason" IS DISTINCT FROM OLD."status_reason" THEN
      RAISE EXCEPTION 'status_rev and status_reason change only together with the status' USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;

  -- The attempt is the fence of the task (ER-30): it only grows, by one, while the task runs (a retry or a lease reclaim).
  IF NEW."attempt" NOT IN (OLD."attempt", OLD."attempt" + 1) OR (NEW."attempt" = OLD."attempt" + 1 AND OLD."status" <> 'running') THEN
    RAISE EXCEPTION 'the attempt of a scan task grows by one, only while the task runs (retry or reclaim)' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "scan_tasks_guard" BEFORE INSERT OR UPDATE ON "scan_tasks" FOR EACH ROW EXECUTE FUNCTION guard_scan_task_change();
CREATE TRIGGER "scan_tasks_no_truncate" BEFORE TRUNCATE ON "scan_tasks" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

-- ---- 7. scan_task_attempts ------------------------------------------------------------------------------------------------
ALTER TABLE "scan_task_attempts" ADD CONSTRAINT "scan_task_attempts_values_check" CHECK (
  "attempt" >= 0
  AND "status" IN ('running', 'succeeded', 'failed', 'timed_out', 'cancelled')
  AND (("status" = 'running') = ("finished_at" IS NULL))
  AND ("error_class" IS NULL OR "error_class" IN ('transient', 'permanent', 'timeout', 'cancelled', 'lease_expired'))
  AND ("error_code" IS NULL OR "error_code" ~ '^[a-z][a-z_:]{0,63}$')
  AND ("worker_id" IS NULL OR char_length("worker_id") BETWEEN 1 AND 128)
  AND ("duration_ms" IS NULL OR "duration_ms" >= 0)
);

-- An attempt row is inserted while its task runs exactly that attempt and closed once, while the task still runs it: a zombie
-- holder whose attempt was superseded by a retry or a reclaim cannot write its attempt any more (ER-30).
CREATE FUNCTION guard_scan_task_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  task_status "scan_task_status";
  task_attempt integer;
  exec_status "execution_status";
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD."status" <> 'running' THEN
      RAISE EXCEPTION 'UPDATE on % is not allowed: the attempt is closed', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['status', 'error_class', 'error_code', 'finished_at', 'duration_ms']) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['status', 'error_class', 'error_code', 'finished_at', 'duration_ms']) THEN
      RAISE EXCEPTION 'UPDATE on % is not allowed: only closing an attempt may change it', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW."status" = 'running' THEN
      RAISE EXCEPTION 'UPDATE on % is not allowed: an attempt can only be closed', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
    END IF;
  ELSIF NEW."status" <> 'running' THEN
    RAISE EXCEPTION 'an attempt is inserted running and closed afterwards' USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT t."status", t."attempt" INTO task_status, task_attempt FROM "scan_tasks" t WHERE t."tenant_id" = NEW."tenant_id" AND t."id" = NEW."scan_task_id" FOR SHARE;
  IF NOT FOUND THEN
    RETURN NEW; -- the foreign key reports the missing task
  END IF;
  IF task_status <> 'running' OR task_attempt <> NEW."attempt" THEN
    RAISE EXCEPTION '% refused: attempt % is not the running attempt of the task (task is %, attempt %)', TG_OP, NEW."attempt", task_status, task_attempt USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT "status" INTO exec_status FROM "executions" WHERE "tenant_id" = NEW."tenant_id" AND "id" = NEW."execution_id";
  IF execution_status_is_terminal(exec_status) THEN
    RAISE EXCEPTION '% on % is not allowed: the execution is % (terminal)', TG_OP, TG_TABLE_NAME, exec_status USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "scan_task_attempts_guard" BEFORE INSERT OR UPDATE ON "scan_task_attempts" FOR EACH ROW EXECUTE FUNCTION guard_scan_task_attempt();
CREATE TRIGGER "scan_task_attempts_no_truncate" BEFORE TRUNCATE ON "scan_task_attempts" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

-- ---- 8. scan_results and scan_result_items --------------------------------------------------------------------------------
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_values_check" CHECK (
  "attempt" >= 0 AND "schema_version" >= 1 AND "item_count" >= 0
  AND "completeness" IN ('complete', 'incomplete') AND (NOT "truncated" OR "completeness" = 'incomplete')
  AND jsonb_typeof("severity_counts") = 'object'
  AND char_length("engine_id") BETWEEN 1 AND 100 AND char_length("engine_version") BETWEEN 1 AND 100
);

-- A result is accepted only for the task's current running attempt and its own scan type (database backing of the zombie
-- fence, ER-30), and only while the execution is not terminal.
CREATE FUNCTION guard_scan_result_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  task_status "scan_task_status";
  task_attempt integer;
  task_type "scan_task_type";
  exec_status "execution_status";
BEGIN
  SELECT t."status", t."attempt", t."scan_type" INTO task_status, task_attempt, task_type FROM "scan_tasks" t WHERE t."tenant_id" = NEW."tenant_id" AND t."id" = NEW."scan_task_id" FOR SHARE;
  IF NOT FOUND THEN
    RETURN NEW; -- the foreign key reports the missing task
  END IF;
  IF task_status <> 'running' OR task_attempt <> NEW."attempt" THEN
    RAISE EXCEPTION 'INSERT on % refused: attempt % is not the running attempt of the task (task is %, attempt %)', TG_TABLE_NAME, NEW."attempt", task_status, task_attempt USING ERRCODE = 'restrict_violation';
  END IF;
  IF task_type <> NEW."scan_type" THEN
    RAISE EXCEPTION 'INSERT on % refused: the result scan type differs from the task''s' , TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT "status" INTO exec_status FROM "executions" WHERE "tenant_id" = NEW."tenant_id" AND "id" = NEW."execution_id";
  IF execution_status_is_terminal(exec_status) THEN
    RAISE EXCEPTION 'INSERT on % is not allowed: the execution is % (terminal)', TG_TABLE_NAME, exec_status USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "scan_results_guard" BEFORE INSERT ON "scan_results" FOR EACH ROW EXECUTE FUNCTION guard_scan_result_insert();
CREATE TRIGGER "scan_results_insert_only" BEFORE UPDATE ON "scan_results" FOR EACH ROW EXECUTE FUNCTION forbid_execution_child_update();
CREATE TRIGGER "scan_results_no_truncate" BEFORE TRUNCATE ON "scan_results" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

ALTER TABLE "scan_result_items" ADD CONSTRAINT "scan_result_items_values_check" CHECK (
  "ordinal" >= 0
  AND "kind" IN ('vulnerability', 'license', 'secret', 'code_issue', 'component')
  AND "severity" IN ('critical', 'high', 'medium', 'low', 'info')
  AND ("rule_id" IS NULL OR char_length("rule_id") <= 200) AND char_length("title") <= 200
  AND ("path" IS NULL OR char_length("path") <= 1024)
  AND ("start_line" IS NULL OR "start_line" >= 1) AND ("end_line" IS NULL OR ("start_line" IS NOT NULL AND "end_line" >= "start_line"))
  AND ("component_purl" IS NULL OR char_length("component_purl") <= 500) AND ("component_version" IS NULL OR char_length("component_version") <= 100)
  AND jsonb_typeof("data") = 'object' AND octet_length("data"::text) <= 4096
);

CREATE FUNCTION guard_scan_result_item_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  exec_status "execution_status";
BEGIN
  SELECT "status" INTO exec_status FROM "executions" WHERE "tenant_id" = NEW."tenant_id" AND "id" = NEW."execution_id";
  IF FOUND AND execution_status_is_terminal(exec_status) THEN
    RAISE EXCEPTION 'INSERT on % is not allowed: the execution is % (terminal)', TG_TABLE_NAME, exec_status USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "scan_result_items_guard" BEFORE INSERT ON "scan_result_items" FOR EACH ROW EXECUTE FUNCTION guard_scan_result_item_insert();
CREATE TRIGGER "scan_result_items_insert_only" BEFORE UPDATE ON "scan_result_items" FOR EACH ROW EXECUTE FUNCTION forbid_execution_child_update();
CREATE TRIGGER "scan_result_items_no_truncate" BEFORE TRUNCATE ON "scan_result_items" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

-- ---- 9. execution_orchestrator_markers (platform-level, no tenant column) -----------------------------------------------
ALTER TABLE "execution_orchestrator_markers" ADD CONSTRAINT "execution_orchestrator_markers_check" CHECK (
  "marker_key" ~ '^[a-z][a-z0-9_.]{0,63}$' AND "swept_count" >= 0
  AND ("sweep_completed_at" IS NULL OR "sweep_started_at" IS NOT NULL)
  AND ("sweep_lease_owner" IS NULL) = ("sweep_lease_expires_at" IS NULL)
  AND ("sweep_lease_owner" IS NULL OR char_length("sweep_lease_owner") BETWEEN 1 AND 128)
);

CREATE FUNCTION guard_orchestrator_marker() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'DELETE on % is not allowed: the first-enable marker is permanent', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW."marker_key" <> OLD."marker_key" OR NEW."first_enabled_at" <> OLD."first_enabled_at" THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: marker_key and first_enabled_at are set once', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD."sweep_completed_at" IS NOT NULL THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: the sweep is completed and never runs again', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD."sweep_started_at" IS NOT NULL AND NEW."sweep_started_at" IS DISTINCT FROM OLD."sweep_started_at" THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: sweep_started_at is set once', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW."swept_count" < OLD."swept_count" THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: swept_count only grows', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "execution_orchestrator_markers_guard" BEFORE UPDATE OR DELETE ON "execution_orchestrator_markers" FOR EACH ROW EXECUTE FUNCTION guard_orchestrator_marker();
CREATE TRIGGER "execution_orchestrator_markers_no_truncate" BEFORE TRUNCATE ON "execution_orchestrator_markers" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();
