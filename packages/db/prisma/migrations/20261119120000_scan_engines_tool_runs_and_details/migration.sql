-- Scan engines, part D (docs/modules/scan-engines/SPEC.md 7.3, owner decision D-8): the per-tool run record, the 1:1 finding detail
-- row, the ensemble columns of scan_results and the shared credential-shape predicate. Additive: two new tenant-owned tables, two
-- nullable columns, new CHECKs, triggers and one function; no existing row, status enum or transition guard changes (CX-10).
-- Nothing writes these tables yet (the scan worker is wired in part K, behind SCAN_ENGINES_ENSEMBLE_ENABLED, off by default).
-- Everything Prisma cannot express (CHECK constraints, triggers, SQL functions) is below.

-- ---- 1. the credential-shape predicate (the shapes of packages/infra credential-guard.js, as in execution_logs) -------------------
-- A second line of defence behind the redaction of the worker: no new text column of this migration can hold a credential shape,
-- whoever writes the row. NULL is treated as "no credential".
CREATE FUNCTION qm_has_credential_shape(t text) RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT COALESCE(
    t ~ '\ygh[pousr]_[A-Za-z0-9_]{8,}'
    OR t ~ '\ygithub_pat_[A-Za-z0-9_]{8,}'
    OR t ~* '\yBearer\s+[A-Za-z0-9._~+/=-]{8,}'
    OR t ~ '-----BEGIN [A-Z ]*PRIVATE KEY-----'
    OR t ~ '\yAKIA[0-9A-Z]{16}\y'
    OR t ~* '\y[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@'
    OR t ~* '[?&](access_token|token|X-Amz-Signature|sig)=[^&\s]{6,}',
    false)
$$;

-- At most 6 provenance entries, each a JSON object of at most 600 bytes (SPEC 7.3).
CREATE FUNCTION qm_provenance_ok(p jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE WHEN jsonb_typeof(p) = 'array' THEN
    jsonb_array_length(p) BETWEEN 1 AND 6
    AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(p) e WHERE jsonb_typeof(e) <> 'object' OR octet_length(e::text) > 600)
  ELSE false END
$$;

-- ---- 2. scan_tool_runs -------------------------------------------------------------------------------------------------------
CREATE TABLE "scan_tool_runs" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "scan_task_id" UUID NOT NULL,
    "attempt" INTEGER NOT NULL,
    "tool_id" TEXT NOT NULL,
    "tool_version" TEXT NOT NULL,
    "image_digest" TEXT,
    "config_digest" TEXT NOT NULL,
    "rulepack_digest" TEXT,
    "db_snapshot_sha256" TEXT,
    "db_built_at" TIMESTAMPTZ(6),
    "status" TEXT NOT NULL,
    "reason" TEXT,
    "exit_code" INTEGER,
    "started_at" TIMESTAMPTZ(6) NOT NULL,
    "finished_at" TIMESTAMPTZ(6) NOT NULL,
    "duration_ms" INTEGER NOT NULL,
    "scope" JSONB NOT NULL DEFAULT '{}',
    "records_seen" INTEGER NOT NULL DEFAULT 0,
    "records_dropped" INTEGER NOT NULL DEFAULT 0,
    "findings_mapped" INTEGER NOT NULL DEFAULT 0,
    "severity_counts" JSONB NOT NULL DEFAULT '{}',
    "truncated" BOOLEAN NOT NULL DEFAULT false,
    "limits" JSONB NOT NULL DEFAULT '{}',
    "capacity_wait_ms" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_tool_runs_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "scan_tool_runs_tenant_id_scan_task_id_attempt_tool_id_key" ON "scan_tool_runs"("tenant_id", "scan_task_id", "attempt", "tool_id");
CREATE INDEX "scan_tool_runs_tenant_id_execution_id_idx" ON "scan_tool_runs"("tenant_id", "execution_id");

ALTER TABLE "scan_tool_runs" ADD CONSTRAINT "scan_tool_runs_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "scan_tool_runs" ADD CONSTRAINT "scan_tool_runs_task_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "scan_task_id") REFERENCES "scan_tasks"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Only the tools of the v1 ensembles can be recorded: Grype is DEFERRED to v2 (owner decision OQ-24) and the excluded tools never
-- run, so a row for any of them is refused by the database as well. Adding a tool is a reviewed migration.
ALTER TABLE "scan_tool_runs" ADD CONSTRAINT "scan_tool_runs_values_check" CHECK (
  "tool_id" IN ('sbom-lite', 'syft', 'trivy', 'osv-scanner', 'opengrep', 'bandit', 'gosec', 'gitleaks', 'detect-secrets')
  AND "attempt" >= 0
  AND char_length("tool_version") BETWEEN 1 AND 100 AND "tool_version" !~ '[[:cntrl:]]'
  AND ("image_digest" IS NULL OR "image_digest" ~ '^sha256:[0-9a-f]{64}$')
  AND ("image_digest" IS NOT NULL OR "tool_id" = 'sbom-lite' OR "status" IN ('skipped', 'unavailable'))
  AND "config_digest" ~ '^[0-9a-f]{64}$'
  AND ("rulepack_digest" IS NULL OR "rulepack_digest" ~ '^[0-9a-f]{64}$')
  AND ("db_snapshot_sha256" IS NULL OR "db_snapshot_sha256" ~ '^[0-9a-f]{64}$')
  AND "status" IN ('succeeded', 'partial', 'failed', 'timed_out', 'cancelled', 'skipped', 'unavailable')
  AND ("reason" IS NULL OR "reason" IN ('image_unavailable', 'db_unavailable', 'db_stale', 'timeout', 'out_of_memory', 'exit_code', 'output_invalid', 'output_too_large', 'sandbox_error', 'killed', 'no_applicable_files', 'config_invalid', 'capacity', 'cancelled', 'deadline'))
  AND ("status" <> 'succeeded' OR "reason" IS NULL)
  AND ("status" NOT IN ('failed', 'timed_out', 'unavailable', 'skipped') OR "reason" IS NOT NULL)
  AND ("exit_code" IS NULL OR "exit_code" BETWEEN 0 AND 255)
  AND "finished_at" >= "started_at" AND "duration_ms" >= 0 AND "capacity_wait_ms" >= 0
  AND "records_seen" >= 0 AND "records_dropped" BETWEEN 0 AND "records_seen" AND "findings_mapped" BETWEEN 0 AND "records_seen"
  AND jsonb_typeof("scope") = 'object' AND octet_length("scope"::text) <= 4096
  AND jsonb_typeof("severity_counts") = 'object' AND octet_length("severity_counts"::text) <= 1024
  AND jsonb_typeof("limits") = 'object' AND octet_length("limits"::text) <= 4096
);
-- No stdout, no stderr, no tool message text is stored; the free-form columns can still never hold a credential shape.
ALTER TABLE "scan_tool_runs" ADD CONSTRAINT "scan_tool_runs_no_credentials_check" CHECK (
  NOT qm_has_credential_shape("tool_version" || ' ' || "scope"::text || ' ' || "limits"::text || ' ' || "severity_counts"::text)
);

-- A tool run is accepted only for the task's current running attempt (database backing of the zombie fence, ER-30), and only while
-- the execution is not terminal. Same rule as scan_results.
CREATE FUNCTION guard_scan_tool_run_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  task_status "scan_task_status";
  task_attempt integer;
  exec_status "execution_status";
BEGIN
  SELECT t."status", t."attempt" INTO task_status, task_attempt FROM "scan_tasks" t WHERE t."tenant_id" = NEW."tenant_id" AND t."id" = NEW."scan_task_id" FOR SHARE;
  IF NOT FOUND THEN
    RETURN NEW; -- the foreign key reports the missing task
  END IF;
  IF task_status <> 'running' OR task_attempt <> NEW."attempt" THEN
    RAISE EXCEPTION 'INSERT on % refused: attempt % is not the running attempt of the task (task is %, attempt %)', TG_TABLE_NAME, NEW."attempt", task_status, task_attempt USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT "status" INTO exec_status FROM "executions" WHERE "tenant_id" = NEW."tenant_id" AND "id" = NEW."execution_id";
  IF execution_status_is_terminal(exec_status) THEN
    RAISE EXCEPTION 'INSERT on % is not allowed: the execution is % (terminal)', TG_TABLE_NAME, exec_status USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "scan_tool_runs_guard" BEFORE INSERT ON "scan_tool_runs" FOR EACH ROW EXECUTE FUNCTION guard_scan_tool_run_insert();
CREATE TRIGGER "scan_tool_runs_insert_only" BEFORE UPDATE ON "scan_tool_runs" FOR EACH ROW EXECUTE FUNCTION forbid_execution_child_update();
CREATE TRIGGER "scan_tool_runs_no_truncate" BEFORE TRUNCATE ON "scan_tool_runs" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

-- ---- 3. scan_result_item_details (1:1 with scan_result_items; the 4 KiB item `data` stays untouched, CX-5) ------------------------
-- The key mirrors scan_result_items (tenant, execution, result, ordinal): an item row carries no workspace / repository / pipeline
-- columns either, and the composite keys tie the detail to its item and to its result in the same tenant and execution.
CREATE TABLE "scan_result_item_details" (
    "tenant_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "scan_result_id" UUID NOT NULL,
    "item_ordinal" INTEGER NOT NULL,
    "schema_version" INTEGER NOT NULL,
    "dedup_key" TEXT NOT NULL,
    "confidence" TEXT NOT NULL,
    "confidence_basis" TEXT NOT NULL,
    "severity_assumed" BOOLEAN NOT NULL DEFAULT false,
    "provenance" JSONB NOT NULL,
    "advisories" JSONB NOT NULL DEFAULT '[]',
    "cwe" INTEGER[] DEFAULT ARRAY[]::INTEGER[],
    "evidence" JSONB,
    "scm_ref" JSONB,
    "url" TEXT,
    "scope" JSONB NOT NULL DEFAULT '{}',
    "extra" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_result_item_details_pkey" PRIMARY KEY ("tenant_id", "scan_result_id", "item_ordinal")
);

ALTER TABLE "scan_result_item_details" ADD CONSTRAINT "scan_result_item_details_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "scan_result_item_details" ADD CONSTRAINT "scan_result_item_details_item_fkey" FOREIGN KEY ("tenant_id", "scan_result_id", "item_ordinal") REFERENCES "scan_result_items"("tenant_id", "scan_result_id", "ordinal") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "scan_result_item_details" ADD CONSTRAINT "scan_result_item_details_result_fkey" FOREIGN KEY ("tenant_id", "execution_id", "scan_result_id") REFERENCES "scan_results"("tenant_id", "execution_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "scan_result_item_details" ADD CONSTRAINT "scan_result_item_details_values_check" CHECK (
  "item_ordinal" >= 0 AND "schema_version" = 1
  AND char_length("dedup_key") BETWEEN 1 AND 600 AND "dedup_key" !~ '[[:cntrl:]]'
  AND "confidence" IN ('low', 'medium', 'high') AND "confidence_basis" IN ('tool', 'multi_tool', 'heuristic')
  AND qm_provenance_ok("provenance")
  AND jsonb_typeof("advisories") = 'array' AND jsonb_array_length("advisories") <= 20
  AND ("cwe" IS NULL OR cardinality("cwe") <= 10)
  AND ("evidence" IS NULL OR (jsonb_typeof("evidence") = 'object' AND octet_length("evidence"::text) <= 8192))
  AND ("scm_ref" IS NULL OR jsonb_typeof("scm_ref") = 'object')
  AND ("url" IS NULL OR (char_length("url") <= 2000 AND "url" ~ '^https://[^[:space:][:cntrl:]]+$'))
  AND jsonb_typeof("scope") = 'object' AND jsonb_typeof("extra") = 'object'
  AND (octet_length("dedup_key") + octet_length("provenance"::text) + octet_length("advisories"::text) + COALESCE(octet_length("evidence"::text), 0)
       + COALESCE(octet_length("scm_ref"::text), 0) + COALESCE(octet_length("url"), 0) + octet_length("scope"::text) + octet_length("extra"::text)) <= 16384
);
ALTER TABLE "scan_result_item_details" ADD CONSTRAINT "scan_result_item_details_no_credentials_check" CHECK (
  NOT qm_has_credential_shape("dedup_key" || ' ' || COALESCE("url", '') || ' ' || "provenance"::text || ' ' || "advisories"::text || ' ' || COALESCE("evidence"::text, '') || ' ' || COALESCE("scm_ref"::text, '') || ' ' || "scope"::text || ' ' || "extra"::text)
);

-- Insert for a terminal execution is refused (like scan_result_items); rows are insert-only.
CREATE FUNCTION guard_scan_result_item_detail_insert() RETURNS trigger LANGUAGE plpgsql AS $$
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

CREATE TRIGGER "scan_result_item_details_guard" BEFORE INSERT ON "scan_result_item_details" FOR EACH ROW EXECUTE FUNCTION guard_scan_result_item_detail_insert();
CREATE TRIGGER "scan_result_item_details_insert_only" BEFORE UPDATE ON "scan_result_item_details" FOR EACH ROW EXECUTE FUNCTION forbid_execution_child_update();
CREATE TRIGGER "scan_result_item_details_no_truncate" BEFORE TRUNCATE ON "scan_result_item_details" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

-- ---- 4. scan_results: the ensemble columns ----------------------------------------------------------------------------------
-- `schema_version` 2 marks a result produced by an ensemble engine (it exists since the first migration). `coverage` is
-- `{ state, coverageGaps[], toolsDegraded, tools: [{ toolId, status }] }`; a result with toolsDegraded > 0 must be `incomplete`
-- (SPEC 5.4 row 6, D-6), so a degraded result can never look complete or become resolution eligible.
ALTER TABLE "scan_results" ADD COLUMN "run_manifest_sha256" TEXT;
ALTER TABLE "scan_results" ADD COLUMN "coverage" JSONB;
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_ensemble_check" CHECK (
  "schema_version" IN (1, 2)
  AND ("run_manifest_sha256" IS NULL OR ("schema_version" = 2 AND "run_manifest_sha256" ~ '^[0-9a-f]{64}$'))
  AND ("coverage" IS NULL OR (
    "schema_version" = 2 AND jsonb_typeof("coverage") = 'object' AND octet_length("coverage"::text) <= 4096
    AND ("coverage"->>'state') IN ('complete', 'partial', 'degraded', 'nothing_to_scan', 'language_gap')
    AND jsonb_typeof("coverage"->'coverageGaps') = 'array' AND jsonb_typeof("coverage"->'tools') = 'array' AND jsonb_array_length("coverage"->'tools') <= 12
    AND CASE WHEN jsonb_typeof("coverage"->'toolsDegraded') = 'number'
         THEN ("coverage"->>'toolsDegraded')::numeric >= 0 AND (("coverage"->>'toolsDegraded')::numeric = 0 OR "completeness" = 'incomplete')
         ELSE false END
  ))
);
