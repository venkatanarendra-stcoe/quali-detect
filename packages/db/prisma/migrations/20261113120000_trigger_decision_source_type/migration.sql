-- Pipelines and triggers, owner decision of 2026-11-13: a trigger decision row has a SOURCE TYPE and the matching key, so a
-- schedule policy skip (keyed by its nominal slot) and, later, a manual-run skip can be recorded next to the SCM decisions
-- (SPEC §7.8). Existing rows are all SCM decisions and are backfilled as `scm_event`. The generated part comes first; the
-- hand-written part (CHECK constraints, partial unique indexes) follows.

-- CreateEnum
CREATE TYPE "trigger_decision_source" AS ENUM ('scm_event', 'schedule_slot', 'manual');

-- AlterTable
ALTER TABLE "pipeline_trigger_decisions" ADD COLUMN     "manual_key" TEXT,
ADD COLUMN     "schedule_slot" TIMESTAMPTZ(6),
ADD COLUMN     "source_type" "trigger_decision_source" NOT NULL DEFAULT 'scm_event',
ALTER COLUMN "scm_delivery_id" DROP NOT NULL,
ALTER COLUMN "scm_event_kind" DROP NOT NULL;

-- Backfill: the temporary default above made every existing row `scm_event` (they are webhook decisions, the router was the
-- only writer; an UPDATE would be refused by the insert-only trigger). From now on the column has no default: every writer
-- states its source type.
ALTER TABLE "pipeline_trigger_decisions" ALTER COLUMN "source_type" DROP DEFAULT;

-- DropIndex (replaced by the partial unique indexes below)
DROP INDEX "pipeline_trigger_decisions_tenant_id_pipeline_id_scm_delive_key";

-- Constraints replaced: the origin check knew only webhooks, the lengths check required a delivery id.
ALTER TABLE "pipeline_trigger_decisions" DROP CONSTRAINT "pipeline_trigger_decisions_origin_check";
ALTER TABLE "pipeline_trigger_decisions" DROP CONSTRAINT "pipeline_trigger_decisions_lengths_check";

-- Exactly the key that matches the source type is set (the others are NULL), and the trigger type fits the source:
-- scm_event -> push / pull_request with the same SCM event kind; schedule_slot -> schedule; manual -> manual.
ALTER TABLE "pipeline_trigger_decisions" ADD CONSTRAINT "pipeline_trigger_decisions_source_check" CHECK (
  ("source_type" = 'scm_event'
    AND "scm_delivery_id" IS NOT NULL AND "scm_event_kind" IS NOT NULL AND "schedule_slot" IS NULL AND "manual_key" IS NULL
    AND "trigger_type" IN ('push', 'pull_request') AND "scm_event_kind"::text = "trigger_type"::text)
  OR ("source_type" = 'schedule_slot'
    AND "schedule_slot" IS NOT NULL AND "scm_delivery_id" IS NULL AND "scm_event_kind" IS NULL AND "scm_event_id" IS NULL AND "manual_key" IS NULL
    AND "trigger_type" = 'schedule' AND "pull_request_number" IS NULL)
  OR ("source_type" = 'manual'
    AND "manual_key" IS NOT NULL AND "scm_delivery_id" IS NULL AND "scm_event_kind" IS NULL AND "scm_event_id" IS NULL AND "schedule_slot" IS NULL
    AND "trigger_type" = 'manual' AND "pull_request_number" IS NULL)
);
ALTER TABLE "pipeline_trigger_decisions" ADD CONSTRAINT "pipeline_trigger_decisions_lengths_check" CHECK (
  char_length("trigger_key") BETWEEN 1 AND 64 AND ("scm_delivery_id" IS NULL OR char_length("scm_delivery_id") BETWEEN 1 AND 128)
  AND ("manual_key" IS NULL OR char_length("manual_key") BETWEEN 1 AND 400)
  AND char_length("ref_name") BETWEEN 1 AND 255 AND ("correlation_id" IS NULL OR char_length("correlation_id") <= 128)
);

-- One decision per (tenant, pipeline, trigger, source type, key): a redelivery, a repeated tick or a replayed manual call
-- writes nothing twice. Partial indexes, one per source type (NULL keys never compare equal, so a plain composite index would
-- not protect the other types). Prisma cannot model them; the schema documents it.
CREATE UNIQUE INDEX "pipeline_trigger_decisions_scm_key" ON "pipeline_trigger_decisions"("tenant_id", "pipeline_id", "trigger_key", "scm_delivery_id", "scm_event_kind") WHERE "source_type" = 'scm_event';
CREATE UNIQUE INDEX "pipeline_trigger_decisions_slot_key" ON "pipeline_trigger_decisions"("tenant_id", "pipeline_id", "trigger_key", "schedule_slot") WHERE "source_type" = 'schedule_slot';
CREATE UNIQUE INDEX "pipeline_trigger_decisions_manual_key" ON "pipeline_trigger_decisions"("tenant_id", "pipeline_id", "trigger_key", "manual_key") WHERE "source_type" = 'manual';

-- Decisions stay insert-only: the existing BEFORE UPDATE trigger "pipeline_trigger_decisions_insert_only" is unchanged and
-- covers the new columns (any UPDATE is refused, whatever the column).
