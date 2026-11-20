-- Scan engines, part F (docs/modules/scan-engines/SPEC.md 5.12, 7.3, SE-32..SE-39, SE-45, SE-46): the vulnerability DB mirror's
-- snapshot metadata. PLATFORM-LEVEL public data, no tenant column (like execution_orchestrator_markers); never exposed by an API.
-- One `active` snapshot per tool, one-way status changes, immutable identity, no DELETE or TRUNCATE.

-- CreateTable
CREATE TABLE "scan_db_snapshots" (
    "id" UUID NOT NULL,
    "tool_id" TEXT NOT NULL,
    "source_version" TEXT NOT NULL,
    "upstream_built_at" TIMESTAMPTZ(6) NOT NULL,
    "fetched_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "size_bytes" BIGINT NOT NULL,
    "sha256" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'candidate',
    "promoted_at" TIMESTAMPTZ(6),
    "retired_at" TIMESTAMPTZ(6),
    "rejected_reason" TEXT,
    "content_pruned_at" TIMESTAMPTZ(6),
    "sources" JSONB NOT NULL DEFAULT '[]',
    "record_counts" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_db_snapshots_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "scan_db_snapshots_tool_sha256_key" ON "scan_db_snapshots"("tool_id", "sha256");

-- CreateIndex
CREATE INDEX "scan_db_snapshots_tool_status_built_idx" ON "scan_db_snapshots"("tool_id", "status", "upstream_built_at" DESC);

-- Values: Grype has no mirror in v1 (D-21), so the tool list is closed; the reject reasons are fixed words (never upstream text).
ALTER TABLE "scan_db_snapshots" ADD CONSTRAINT "scan_db_snapshots_values_check" CHECK (
  "tool_id" IN ('trivy', 'osv-scanner')
  AND "sha256" ~ '^[0-9a-f]{64}$'
  AND "size_bytes" > 0
  AND char_length("source_version") BETWEEN 1 AND 128
  AND "source_version" ~ '^[A-Za-z0-9][A-Za-z0-9._:+-]*$'
  AND "status" IN ('candidate', 'active', 'retired', 'rejected')
  AND ("rejected_reason" IS NULL OR "rejected_reason" IN (
    'integrity_mismatch', 'integrity_unverified', 'too_large', 'empty', 'too_small', 'too_old', 'future_built', 'archive_hostile',
    'record_invalid', 'quarantined_source', 'source_not_allowed', 'canary_failed', 'abandoned'))
  AND jsonb_typeof("sources") = 'array' AND jsonb_array_length("sources") <= 50 AND octet_length("sources"::text) <= 4096
  AND jsonb_typeof("record_counts") = 'object' AND octet_length("record_counts"::text) <= 4096
);

-- Status and its companion columns agree.
ALTER TABLE "scan_db_snapshots" ADD CONSTRAINT "scan_db_snapshots_state_check" CHECK (
  ("status" = 'candidate' AND "promoted_at" IS NULL AND "retired_at" IS NULL AND "rejected_reason" IS NULL)
  OR ("status" = 'active' AND "promoted_at" IS NOT NULL AND "retired_at" IS NULL AND "rejected_reason" IS NULL)
  OR ("status" = 'retired' AND "promoted_at" IS NOT NULL AND "retired_at" IS NOT NULL AND "rejected_reason" IS NULL)
  OR ("status" = 'rejected' AND "promoted_at" IS NULL AND "retired_at" IS NULL AND "rejected_reason" IS NOT NULL)
);

-- At most ONE active snapshot per tool: the atomic switch (retire the old, activate the new, one transaction) can never leave two.
CREATE UNIQUE INDEX "scan_db_snapshots_one_active_per_tool" ON "scan_db_snapshots" ("tool_id") WHERE "status" = 'active';

CREATE FUNCTION guard_scan_db_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."status" NOT IN ('candidate', 'rejected') THEN
      RAISE EXCEPTION 'INSERT on % is not allowed: a snapshot enters as candidate (or as rejected)', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'DELETE on % is not allowed: snapshot rows are the provenance of past results', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW."id" <> OLD."id" OR NEW."tool_id" <> OLD."tool_id" OR NEW."sha256" <> OLD."sha256" OR NEW."size_bytes" <> OLD."size_bytes"
     OR NEW."upstream_built_at" <> OLD."upstream_built_at" OR NEW."fetched_at" <> OLD."fetched_at"
     OR NEW."source_version" <> OLD."source_version" OR NEW."sources" <> OLD."sources" OR NEW."record_counts" <> OLD."record_counts"
     OR NEW."created_at" <> OLD."created_at" THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: identity and provenance are immutable', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD."content_pruned_at" IS NOT NULL AND NEW."content_pruned_at" IS DISTINCT FROM OLD."content_pruned_at" THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: content_pruned_at is set once', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW."status" <> OLD."status" THEN
    IF NOT (
      (OLD."status" = 'candidate' AND NEW."status" IN ('active', 'rejected'))
      OR (OLD."status" = 'active' AND NEW."status" = 'retired')
    ) THEN
      RAISE EXCEPTION 'UPDATE on % is not allowed: status % to % is not a valid transition', TG_TABLE_NAME, OLD."status", NEW."status" USING ERRCODE = 'restrict_violation';
    END IF;
  ELSIF NEW."promoted_at" IS DISTINCT FROM OLD."promoted_at" OR NEW."retired_at" IS DISTINCT FROM OLD."retired_at"
        OR NEW."rejected_reason" IS DISTINCT FROM OLD."rejected_reason" THEN
    RAISE EXCEPTION 'UPDATE on % is not allowed: those columns change only with a status transition', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "scan_db_snapshots_guard" BEFORE INSERT OR UPDATE OR DELETE ON "scan_db_snapshots" FOR EACH ROW EXECUTE FUNCTION guard_scan_db_snapshot();
CREATE TRIGGER "scan_db_snapshots_no_truncate" BEFORE TRUNCATE ON "scan_db_snapshots" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();
