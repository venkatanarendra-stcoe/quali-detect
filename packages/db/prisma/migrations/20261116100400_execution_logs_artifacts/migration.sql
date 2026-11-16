-- SPEC executions (docs/modules/executions/SPEC.md) section 17.ac, part E: capped Postgres tables behind the LogStore and
-- ArtifactStore interfaces (execution logs, log counters, execution artifacts). Additive: new tables, indexes, CHECKs and
-- triggers only; no existing table changes. The object-storage adapter is deferred (Open decision).
--
-- Every table carries the tenant and the chain (tenant, workspace, repository, pipeline, execution) with composite foreign
-- keys, so a row whose chain does not match its parent is refused by the database. The hard CEILINGS are here (CHECK); the
-- store's configured caps are lower and are enforced in code, with a truncation marker and the `truncated` flag.

-- ---- 1. execution_log_counters / execution_task_log_counters -----------------------------------------------------------
CREATE TABLE "execution_log_counters" (
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "line_count" INTEGER NOT NULL DEFAULT 0,
    "byte_count" INTEGER NOT NULL DEFAULT 0,
    "dropped_lines" INTEGER NOT NULL DEFAULT 0,
    "truncated" BOOLEAN NOT NULL DEFAULT false,
    "capped" BOOLEAN NOT NULL DEFAULT false,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "execution_log_counters_pkey" PRIMARY KEY ("tenant_id","execution_id")
);

CREATE TABLE "execution_task_log_counters" (
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "scan_task_id" UUID NOT NULL,
    "line_count" INTEGER NOT NULL DEFAULT 0,
    "byte_count" INTEGER NOT NULL DEFAULT 0,
    "dropped_lines" INTEGER NOT NULL DEFAULT 0,
    "truncated" BOOLEAN NOT NULL DEFAULT false,
    "capped" BOOLEAN NOT NULL DEFAULT false,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "execution_task_log_counters_pkey" PRIMARY KEY ("tenant_id","scan_task_id")
);

-- ---- 2. execution_logs ---------------------------------------------------------------------------------------------------
CREATE TABLE "execution_logs" (
    "id" BIGSERIAL NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "scan_task_id" UUID,
    "seq" BIGINT NOT NULL DEFAULT 0,
    "level" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "line_truncated" BOOLEAN NOT NULL DEFAULT false,
    "at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "execution_logs_pkey" PRIMARY KEY ("id")
);

-- ---- 3. execution_artifacts ----------------------------------------------------------------------------------------------
CREATE TABLE "execution_artifacts" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "media_type" TEXT NOT NULL,
    "size_bytes" INTEGER NOT NULL,
    "sha256" TEXT NOT NULL,
    "content" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "execution_artifacts_pkey" PRIMARY KEY ("id")
);

-- ---- 4. indexes ------------------------------------------------------------------------------------------------------------
CREATE INDEX "execution_log_counters_updated_at_idx" ON "execution_log_counters"("updated_at");
CREATE INDEX "execution_task_log_counters_tenant_id_execution_id_idx" ON "execution_task_log_counters"("tenant_id", "execution_id");
CREATE UNIQUE INDEX "execution_logs_tenant_id_execution_id_seq_key" ON "execution_logs"("tenant_id", "execution_id", "seq");
CREATE INDEX "execution_logs_tenant_id_execution_id_scan_task_id_seq_idx" ON "execution_logs"("tenant_id", "execution_id", "scan_task_id", "seq");
CREATE INDEX "execution_logs_at_id_idx" ON "execution_logs"("at", "id");
CREATE UNIQUE INDEX "execution_artifacts_tenant_id_execution_id_name_key" ON "execution_artifacts"("tenant_id", "execution_id", "name");
CREATE INDEX "execution_artifacts_created_at_id_idx" ON "execution_artifacts"("created_at", "id");

-- ---- 5. foreign keys (tenant-safe composite chains; nothing is ever deleted through them: RESTRICT) -------------------------
ALTER TABLE "execution_log_counters" ADD CONSTRAINT "execution_log_counters_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "execution_log_counters" ADD CONSTRAINT "execution_log_counters_execution_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id") REFERENCES "executions"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "execution_task_log_counters" ADD CONSTRAINT "execution_task_log_counters_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "execution_task_log_counters" ADD CONSTRAINT "execution_task_log_counters_task_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "scan_task_id") REFERENCES "scan_tasks"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "execution_logs" ADD CONSTRAINT "execution_logs_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "execution_logs" ADD CONSTRAINT "execution_logs_execution_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id") REFERENCES "executions"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;
-- with a null scan_task_id this key is not evaluated (MATCH SIMPLE); the execution key above always is
ALTER TABLE "execution_logs" ADD CONSTRAINT "execution_logs_task_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "scan_task_id") REFERENCES "scan_tasks"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "execution_artifacts" ADD CONSTRAINT "execution_artifacts_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "execution_artifacts" ADD CONSTRAINT "execution_artifacts_execution_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id") REFERENCES "executions"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ---- 6. CHECK constraints: the hard ceilings ---------------------------------------------------------------------------------
-- Ceilings (the store's configured caps are lower): execution 100000 lines / 8 MiB, task 50000 lines / 4 MiB, one line 2000
-- characters / 8000 bytes, one artifact 1 MiB (see the artifact trigger for count and total).
ALTER TABLE "execution_log_counters" ADD CONSTRAINT "execution_log_counters_caps_check" CHECK (
  "line_count" BETWEEN 0 AND 100000 AND "byte_count" BETWEEN 0 AND 8388608 AND "dropped_lines" >= 0
  AND ("dropped_lines" = 0 OR "truncated")
);
-- (the `capped` flag - the cap marker was written, later lines are dropped - needs no CHECK of its own: the store sets it in the
-- statement that records the first drop, and the guard trigger below never lets it be cleared)
ALTER TABLE "execution_task_log_counters" ADD CONSTRAINT "execution_task_log_counters_caps_check" CHECK (
  "line_count" BETWEEN 0 AND 50000 AND "byte_count" BETWEEN 0 AND 4194304 AND "dropped_lines" >= 0
  AND ("dropped_lines" = 0 OR "truncated")
);
-- (the `capped` flag - the cap marker was written, later lines are dropped - needs no CHECK of its own: the store sets it in the
-- statement that records the first drop, and the guard trigger below never lets it be cleared)
ALTER TABLE "execution_logs" ADD CONSTRAINT "execution_logs_values_check" CHECK (
  "level" IN ('debug', 'info', 'warn', 'error') AND "source" IN ('platform', 'fetch', 'scan') AND "seq" >= 0
  AND char_length("message") BETWEEN 1 AND 2000 AND octet_length("message") <= 8000
  AND "message" !~ '[[:cntrl:]]'
);
-- A second line of defence behind the LogStore's redaction: the credential shapes of packages/infra credential-guard.js
-- (findCredentials) can never be stored, whoever writes the row.
ALTER TABLE "execution_logs" ADD CONSTRAINT "execution_logs_no_credentials_check" CHECK (
  "message" !~ '\ygh[pousr]_[A-Za-z0-9_]{8,}'
  AND "message" !~ '\ygithub_pat_[A-Za-z0-9_]{8,}'
  AND "message" !~* '\yBearer\s+[A-Za-z0-9._~+/=-]{8,}'
  AND "message" !~ '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  AND "message" !~ '\yAKIA[0-9A-Z]{16}\y'
  AND "message" !~* '\y[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@'
  AND "message" !~* '[?&](access_token|token|X-Amz-Signature|sig)=[^&\s]{6,}'
);
ALTER TABLE "execution_artifacts" ADD CONSTRAINT "execution_artifacts_values_check" CHECK (
  "name" ~ '^[a-z][a-z0-9._-]{0,63}$' AND "name" !~ '\.\.' AND "name" !~ '\.$'
  AND "media_type" IN ('application/json', 'text/plain', 'application/octet-stream')
  AND "size_bytes" = octet_length("content") AND "size_bytes" BETWEEN 0 AND 1048576
  AND "sha256" ~ '^[0-9a-f]{64}$'
);

-- ---- 7. execution_logs: seq, counters, terminal refusal, insert-only -----------------------------------------------------------
-- Assigns `seq` (1, 2, ... per execution) from the per-execution counter and keeps both counters in the same statement, so
-- the CHECK ceilings bind every writer. The upsert serialises concurrent appends of one execution on the counter row. Inserts
-- for a terminal execution are refused (SPEC 7.3). The chain is matched against the execution row; a mismatch finds no parent
-- and is refused as a foreign key violation (before any unique index can see the row).
CREATE FUNCTION before_insert_execution_log() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  parent_status "execution_status";
BEGIN
  SELECT "status" INTO parent_status FROM "executions"
  WHERE "tenant_id" = NEW."tenant_id" AND "workspace_id" = NEW."workspace_id" AND "repository_id" = NEW."repository_id"
    AND "pipeline_id" = NEW."pipeline_id" AND "id" = NEW."execution_id" FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'INSERT on % names an execution that does not exist in this tenant, workspace, repository and pipeline', TG_TABLE_NAME
      USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'execution_logs_execution_fkey';
  END IF;
  IF execution_status_is_terminal(parent_status) THEN
    RAISE EXCEPTION 'INSERT on % is not allowed: the execution is % (terminal)', TG_TABLE_NAME, parent_status USING ERRCODE = 'restrict_violation';
  END IF;
  INSERT INTO "execution_log_counters" AS c ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "line_count", "byte_count")
  VALUES (NEW."tenant_id", NEW."workspace_id", NEW."repository_id", NEW."pipeline_id", NEW."execution_id", 1, octet_length(NEW."message"))
  ON CONFLICT ("tenant_id", "execution_id") DO UPDATE
    SET "line_count" = c."line_count" + 1, "byte_count" = c."byte_count" + EXCLUDED."byte_count", "updated_at" = now()
  RETURNING c."line_count" INTO NEW."seq";
  IF NEW."scan_task_id" IS NOT NULL THEN
    INSERT INTO "execution_task_log_counters" AS t ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id", "scan_task_id", "line_count", "byte_count")
    VALUES (NEW."tenant_id", NEW."workspace_id", NEW."repository_id", NEW."pipeline_id", NEW."execution_id", NEW."scan_task_id", 1, octet_length(NEW."message"))
    ON CONFLICT ("tenant_id", "scan_task_id") DO UPDATE
      SET "line_count" = t."line_count" + 1, "byte_count" = t."byte_count" + EXCLUDED."byte_count", "updated_at" = now();
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "execution_logs_before_insert" BEFORE INSERT ON "execution_logs" FOR EACH ROW EXECUTE FUNCTION before_insert_execution_log();
CREATE TRIGGER "execution_logs_insert_only" BEFORE UPDATE ON "execution_logs" FOR EACH ROW EXECUTE FUNCTION forbid_execution_child_update();
CREATE TRIGGER "execution_logs_no_truncate" BEFORE TRUNCATE ON "execution_logs" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

-- Counters: the key, the chain and the totals can only move forward (the totals are raised by the insert trigger, the dropped
-- count and the truncated flag by the store); DELETE is left to the retention purge; TRUNCATE is refused.
CREATE FUNCTION guard_execution_log_counter_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF to_jsonb(NEW) - ARRAY['line_count', 'byte_count', 'dropped_lines', 'truncated', 'capped', 'updated_at']
     IS DISTINCT FROM to_jsonb(OLD) - ARRAY['line_count', 'byte_count', 'dropped_lines', 'truncated', 'capped', 'updated_at'] THEN
    RAISE EXCEPTION 'UPDATE on % may only change the counters', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW."line_count" < OLD."line_count" OR NEW."byte_count" < OLD."byte_count" OR NEW."dropped_lines" < OLD."dropped_lines" OR (OLD."truncated" AND NOT NEW."truncated") OR (OLD."capped" AND NOT NEW."capped") THEN
    RAISE EXCEPTION 'UPDATE on % may not lower a counter or clear the truncated flag', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "execution_log_counters_guard" BEFORE UPDATE ON "execution_log_counters" FOR EACH ROW EXECUTE FUNCTION guard_execution_log_counter_update();
CREATE TRIGGER "execution_log_counters_no_truncate" BEFORE TRUNCATE ON "execution_log_counters" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();
CREATE TRIGGER "execution_task_log_counters_guard" BEFORE UPDATE ON "execution_task_log_counters" FOR EACH ROW EXECUTE FUNCTION guard_execution_log_counter_update();
CREATE TRIGGER "execution_task_log_counters_no_truncate" BEFORE TRUNCATE ON "execution_task_log_counters" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

-- ---- 8. execution_artifacts: caps per execution, terminal refusal, insert-only ------------------------------------------------
-- At most 20 artifacts and 8 MiB per execution; an advisory lock on the execution serialises concurrent inserts so the totals
-- cannot be overrun by a race. Inserts for a terminal execution are refused.
CREATE FUNCTION before_insert_execution_artifact() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  parent_status "execution_status";
  n integer;
  total bigint;
BEGIN
  SELECT "status" INTO parent_status FROM "executions"
  WHERE "tenant_id" = NEW."tenant_id" AND "workspace_id" = NEW."workspace_id" AND "repository_id" = NEW."repository_id"
    AND "pipeline_id" = NEW."pipeline_id" AND "id" = NEW."execution_id" FOR SHARE;
  IF NOT FOUND THEN
    RETURN NEW; -- the foreign key reports the missing parent
  END IF;
  IF execution_status_is_terminal(parent_status) THEN
    RAISE EXCEPTION 'INSERT on % is not allowed: the execution is % (terminal)', TG_TABLE_NAME, parent_status USING ERRCODE = 'restrict_violation';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('execution_artifacts:' || NEW."execution_id"::text, 0));
  SELECT count(*), COALESCE(sum("size_bytes"), 0) INTO n, total FROM "execution_artifacts"
  WHERE "tenant_id" = NEW."tenant_id" AND "execution_id" = NEW."execution_id";
  IF n + 1 > 20 OR total + NEW."size_bytes" > 8388608 THEN
    RAISE EXCEPTION 'INSERT on % exceeds the per-execution artifact cap (20 objects, 8 MiB)', TG_TABLE_NAME USING ERRCODE = 'check_violation', CONSTRAINT = 'execution_artifacts_execution_cap';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "execution_artifacts_before_insert" BEFORE INSERT ON "execution_artifacts" FOR EACH ROW EXECUTE FUNCTION before_insert_execution_artifact();
CREATE TRIGGER "execution_artifacts_insert_only" BEFORE UPDATE ON "execution_artifacts" FOR EACH ROW EXECUTE FUNCTION forbid_execution_child_update();
CREATE TRIGGER "execution_artifacts_no_truncate" BEFORE TRUNCATE ON "execution_artifacts" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();
