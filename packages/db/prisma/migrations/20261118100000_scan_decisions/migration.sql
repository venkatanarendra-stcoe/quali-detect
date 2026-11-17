-- SPEC scan-decisioning part E (docs/modules/scan-decisioning/SPEC.md 7.2, 5.6, 5.7; AP-3): the decision record of an execution,
-- the two decision event types, the zero-scan reason on `succeeded` and the one narrow quota-release exception that goes with it.
-- Additive except two replaced objects: the CHECKs `executions_status_reason_check` and `execution_events_type_check`, and the
-- function `guard_execution_update` (one block changed, marked below). The execution STATE GRAPH is unchanged.

-- ---- 1. event types ------------------------------------------------------------------------------------------------------
ALTER TABLE "execution_events" DROP CONSTRAINT "execution_events_type_check";
ALTER TABLE "execution_events" ADD CONSTRAINT "execution_events_type_check" CHECK ("type" IN ('transition', 'recovered', 'cancel_requested', 'limit_deferred', 'retry_requested', 'task_unsupported', 'decision_started', 'decision_completed'));

-- ---- 2. scan_decisions ----------------------------------------------------------------------------------------------------
CREATE TABLE "scan_decisions" (
    "id" UUID NOT NULL,
    "tenant_id" UUID NOT NULL,
    "workspace_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "pipeline_id" UUID NOT NULL,
    "execution_id" UUID NOT NULL,
    "schema_version" INTEGER NOT NULL DEFAULT 1,
    "scan_kind" "execution_scan_kind" NOT NULL,
    "trust" "execution_trust" NOT NULL,
    "diff_source" TEXT NOT NULL,
    "diff_status" TEXT NOT NULL,
    "changed_total" INTEGER NOT NULL DEFAULT 0,
    "change_summary" JSONB NOT NULL DEFAULT '{}',
    "secrets_rule" TEXT NOT NULL,
    "floor" JSONB NOT NULL,
    "agent_status" TEXT NOT NULL,
    "agent_provider" TEXT,
    "agent_model" TEXT,
    "agent_additions" JSONB NOT NULL DEFAULT '[]',
    "agent_summary" TEXT,
    "agent_usage" JSONB,
    "final_types" JSONB NOT NULL,
    "not_selected" JSONB NOT NULL DEFAULT '[]',
    "decided_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_decisions_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "scan_decisions_tenant_id_execution_id_key" ON "scan_decisions"("tenant_id", "execution_id");

ALTER TABLE "scan_decisions" ADD CONSTRAINT "scan_decisions_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "scan_decisions" ADD CONSTRAINT "scan_decisions_execution_fkey" FOREIGN KEY ("tenant_id", "workspace_id", "repository_id", "pipeline_id", "execution_id") REFERENCES "executions"("tenant_id", "workspace_id", "repository_id", "pipeline_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- The credential shapes of packages/infra credential-guard.js (the same list as execution_logs_no_credentials_check) as one function,
-- applied to every text-bearing column below.
CREATE FUNCTION text_has_credential_shape(value text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT value ~ '\ygh[pousr]_[A-Za-z0-9_]{8,}'
      OR value ~ '\ygithub_pat_[A-Za-z0-9_]{8,}'
      OR value ~* '\yBearer\s+[A-Za-z0-9._~+/=-]{8,}'
      OR value ~ '-----BEGIN [A-Z ]*PRIVATE KEY-----'
      OR value ~ '\yAKIA[0-9A-Z]{16}\y'
      OR value ~* '\y[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@'
      OR value ~* '[?&](access_token|token|X-Amz-Signature|sig)=[^&\s]{6,}'
      OR value ~ '\ysk-(ant-)?[A-Za-z0-9_-]{20,}'
$$;

ALTER TABLE "scan_decisions" ADD CONSTRAINT "scan_decisions_values_check" CHECK (
  "schema_version" = 1
  AND "diff_source" IN ('none', 'github_compare', 'github_pull_files', 'unavailable')
  AND "diff_status" IN ('not_needed', 'complete', 'truncated', 'unavailable')
  AND (("diff_status" = 'not_needed') = ("diff_source" = 'none'))
  AND (("diff_status" = 'unavailable') = ("diff_source" = 'unavailable'))
  AND (("scan_kind" = 'full') = ("diff_status" = 'not_needed'))
  AND "changed_total" BETWEEN 0 AND 100000
  AND ("diff_status" = 'complete' OR "changed_total" = 0)
  AND "secrets_rule" IN ('any_change', 'strict')
  AND "agent_status" IN ('not_configured', 'nothing_to_add', 'consent_required', 'skipped_fork', 'ok', 'timeout', 'error', 'invalid_output', 'interrupted', 'cancelled')
  AND ("agent_provider" IS NULL OR char_length("agent_provider") BETWEEN 1 AND 100)
  AND ("agent_model" IS NULL OR char_length("agent_model") BETWEEN 1 AND 200)
  AND ("agent_summary" IS NULL OR char_length("agent_summary") BETWEEN 1 AND 1000)
  AND ("agent_status" = 'ok' OR jsonb_typeof("agent_additions") = 'array' AND jsonb_array_length("agent_additions") = 0)
  AND ("agent_status" = 'ok' OR "agent_summary" IS NULL)
  AND ("agent_usage" IS NULL OR (jsonb_typeof("agent_usage") = 'object' AND octet_length("agent_usage"::text) <= 1024))
  AND jsonb_typeof("change_summary") = 'object' AND octet_length("change_summary"::text) <= 65536
  AND octet_length("floor"::text) <= 2048 AND octet_length("agent_additions"::text) <= 4096
  AND octet_length("final_types"::text) <= 256 AND octet_length("not_selected"::text) <= 2048
);
ALTER TABLE "scan_decisions" ADD CONSTRAINT "scan_decisions_no_credentials_check" CHECK (
  NOT text_has_credential_shape(
    concat_ws(' ', "agent_provider", "agent_model", "agent_summary", "change_summary"::text, "floor"::text,
              "agent_additions"::text, "not_selected"::text, "agent_usage"::text))
);

-- Structure and set rules that need the parent rows. A BEFORE trigger runs before the CHECKs, so it validates the JSON shapes
-- itself. Rules: only while the execution is preparing; scan kind and trust equal the execution's; floor, agent additions, final
-- set and not-selected set are arrays of known, unique scan types; the floor is inside the pipeline snapshot's enabled types;
-- additions are disjoint from the floor; final = floor union additions (so every floor type is in final and nothing unexplained is);
-- final and not_selected together are exactly the enabled types; final is in catalog order.
CREATE FUNCTION guard_scan_decision_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  exec_row RECORD;
  catalog text[] := ARRAY['sbom', 'sca', 'sast', 'secrets'];
  enabled text[];
  floor_types text[];
  add_types text[];
  final_arr text[];
  nsel_types text[];
  t text;
BEGIN
  SELECT e."status", e."scan_kind", e."trust", e."config_version_id", e."pipeline_id" INTO exec_row FROM "executions" e
  WHERE e."tenant_id" = NEW."tenant_id" AND e."workspace_id" = NEW."workspace_id" AND e."repository_id" = NEW."repository_id"
    AND e."pipeline_id" = NEW."pipeline_id" AND e."id" = NEW."execution_id" FOR SHARE;
  IF NOT FOUND THEN
    RETURN NEW; -- the composite foreign key reports the missing execution
  END IF;
  IF exec_row."status" <> 'preparing' THEN
    RAISE EXCEPTION 'INSERT on % is not allowed: the execution is % (a decision is recorded while it is preparing)', TG_TABLE_NAME, exec_row."status" USING ERRCODE = 'restrict_violation';
  END IF;
  IF exec_row."scan_kind" <> NEW."scan_kind" OR exec_row."trust" <> NEW."trust" THEN
    RAISE EXCEPTION 'INSERT on % refused: scan kind and trust must equal the execution''s', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
  END IF;
  IF jsonb_typeof(NEW."floor") <> 'array' OR jsonb_typeof(NEW."agent_additions") <> 'array' OR jsonb_typeof(NEW."final_types") <> 'array'
     OR jsonb_typeof(NEW."not_selected") <> 'array' THEN
    RAISE EXCEPTION 'INSERT on % refused: floor, agent_additions, final_types and not_selected must be JSON arrays', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  IF jsonb_array_length(NEW."floor") > 4 OR jsonb_array_length(NEW."agent_additions") > 4 OR jsonb_array_length(NEW."final_types") > 4
     OR jsonb_array_length(NEW."not_selected") > 4 THEN
    RAISE EXCEPTION 'INSERT on % refused: at most four scan types per set', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  IF EXISTS (SELECT 1 FROM jsonb_array_elements(NEW."floor") x WHERE jsonb_typeof(x) <> 'object' OR jsonb_typeof(x -> 'scanType') IS DISTINCT FROM 'string' OR jsonb_typeof(x -> 'ruleIds') IS DISTINCT FROM 'array')
     OR EXISTS (SELECT 1 FROM jsonb_array_elements(NEW."agent_additions") x WHERE jsonb_typeof(x) <> 'object' OR jsonb_typeof(x -> 'scanType') IS DISTINCT FROM 'string' OR jsonb_typeof(x -> 'reason') IS DISTINCT FROM 'string')
     OR EXISTS (SELECT 1 FROM jsonb_array_elements(NEW."not_selected") x WHERE jsonb_typeof(x) <> 'object' OR jsonb_typeof(x -> 'scanType') IS DISTINCT FROM 'string' OR jsonb_typeof(x -> 'reason') IS DISTINCT FROM 'string')
     OR EXISTS (SELECT 1 FROM jsonb_array_elements(NEW."final_types") x WHERE jsonb_typeof(x) <> 'string') THEN
    RAISE EXCEPTION 'INSERT on % refused: malformed set entries', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  floor_types := ARRAY(SELECT x ->> 'scanType' FROM jsonb_array_elements(NEW."floor") x);
  add_types := ARRAY(SELECT x ->> 'scanType' FROM jsonb_array_elements(NEW."agent_additions") x);
  final_arr := ARRAY(SELECT x FROM jsonb_array_elements_text(NEW."final_types") x);
  nsel_types := ARRAY(SELECT x ->> 'scanType' FROM jsonb_array_elements(NEW."not_selected") x);
  FOREACH t IN ARRAY (floor_types || add_types || final_arr || nsel_types) LOOP
    IF t IS NULL OR NOT (t = ANY (catalog)) THEN
      RAISE EXCEPTION 'INSERT on % refused: unknown scan type', TG_TABLE_NAME USING ERRCODE = 'check_violation';
    END IF;
  END LOOP;
  IF (SELECT count(DISTINCT x) FROM unnest(floor_types) x) <> cardinality(floor_types)
     OR (SELECT count(DISTINCT x) FROM unnest(add_types) x) <> cardinality(add_types)
     OR (SELECT count(DISTINCT x) FROM unnest(final_arr) x) <> cardinality(final_arr)
     OR (SELECT count(DISTINCT x) FROM unnest(nsel_types) x) <> cardinality(nsel_types) THEN
    RAISE EXCEPTION 'INSERT on % refused: a scan type appears twice in a set', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  IF floor_types && add_types THEN
    RAISE EXCEPTION 'INSERT on % refused: an agent addition is already in the floor', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  IF NOT (floor_types <@ final_arr) THEN
    RAISE EXCEPTION 'INSERT on % refused: the final set must contain every floor type', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  IF NOT (final_arr <@ (floor_types || add_types)) THEN
    RAISE EXCEPTION 'INSERT on % refused: the final set holds a type that is neither floor nor an addition', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  IF final_arr IS DISTINCT FROM ARRAY(SELECT c FROM unnest(catalog) c WHERE c = ANY (final_arr)) THEN
    RAISE EXCEPTION 'INSERT on % refused: the final set is not in catalog order', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  SELECT ARRAY(SELECT c FROM unnest(catalog) c WHERE COALESCE((v."config" -> 'scans' -> c ->> 'enabled')::boolean, false)) INTO enabled
  FROM "pipeline_config_versions" v WHERE v."tenant_id" = NEW."tenant_id" AND v."pipeline_id" = exec_row."pipeline_id" AND v."id" = exec_row."config_version_id";
  IF enabled IS NULL OR NOT ((final_arr || nsel_types) <@ enabled AND enabled <@ (final_arr || nsel_types)) OR final_arr && nsel_types THEN
    RAISE EXCEPTION 'INSERT on % refused: the final and not-selected sets must be exactly the enabled scan types of the execution''s snapshot', TG_TABLE_NAME USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "scan_decisions_guard" BEFORE INSERT ON "scan_decisions" FOR EACH ROW EXECUTE FUNCTION guard_scan_decision_insert();
CREATE TRIGGER "scan_decisions_insert_only" BEFORE UPDATE ON "scan_decisions" FOR EACH ROW EXECUTE FUNCTION forbid_execution_child_update();
CREATE TRIGGER "scan_decisions_no_truncate" BEFORE TRUNCATE ON "scan_decisions" FOR EACH STATEMENT EXECUTE FUNCTION forbid_execution_truncate();

-- ---- 3. status_reason: `succeeded` may carry the single reason `no_applicable_scans` (AP-3) ----------------------------------
-- Every other rule is kept: the six statuses below still require a reason; every other status has none, except this one pair.
ALTER TABLE "executions" DROP CONSTRAINT "executions_status_reason_check";
ALTER TABLE "executions" ADD CONSTRAINT "executions_status_reason_check" CHECK (
  ("status_reason" IS NULL OR "status_reason" ~ '^[a-z][a-z_:]{0,63}$')
  AND CASE
        WHEN "status" IN ('blocked', 'skipped', 'cancelled', 'failed', 'partial', 'timed_out') THEN "status_reason" IS NOT NULL
        WHEN "status" = 'succeeded' THEN "status_reason" IS NULL OR "status_reason" = 'no_applicable_scans'
        ELSE "status_reason" IS NULL
      END
  AND ("status_reason" IS DISTINCT FROM 'no_applicable_scans' OR "status" = 'succeeded')
);

-- ---- 4. executions_guard: the zero-scan quota release (the ONE changed block of the function) -----------------------------------
CREATE OR REPLACE FUNCTION guard_execution_update() RETURNS trigger LANGUAGE plpgsql AS $$
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
  -- A quota unit is given back only by the statement that ends an execution before any scan task started (section 5.9). Part E
  -- (scan-decisioning AP-3) adds exactly ONE more ending: running -> succeeded with the reason `no_applicable_scans`, which is
  -- itself accepted only when the decision recorded an EMPTY final set and no scan task exists (checked below).
  IF NEW."quota_released_at" IS DISTINCT FROM OLD."quota_released_at" THEN
    IF NOT ((OLD."status", NEW."status") IN (('queued', 'cancelled'), ('preparing', 'cancelled'), ('preparing', 'failed'))
            OR (OLD."status" = 'running' AND NEW."status" = 'succeeded' AND NEW."status_reason" IS NOT DISTINCT FROM 'no_applicable_scans')) THEN
      RAISE EXCEPTION 'quota_released_at is set only by queued -> cancelled, preparing -> cancelled, preparing -> failed or the zero-scan ending running -> succeeded (no_applicable_scans)' USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  -- The zero-scan ending (scan-decisioning 5.6): reason `no_applicable_scans` only from running, with a decision whose final set is
  -- empty, no scan task of the execution, zero task counts, and the quota unit given back in the same statement when one was taken.
  IF changing AND NEW."status_reason" = 'no_applicable_scans' THEN
    IF NOT (OLD."status" = 'running' AND NEW."status" = 'succeeded')
       OR EXISTS (SELECT 1 FROM "scan_tasks" t WHERE t."tenant_id" = NEW."tenant_id" AND t."execution_id" = NEW."id")
       OR NOT EXISTS (SELECT 1 FROM "scan_decisions" d WHERE d."tenant_id" = NEW."tenant_id" AND d."execution_id" = NEW."id" AND d."final_types" = '[]'::jsonb)
       OR NEW."task_counts" IS NULL OR (NEW."task_counts" ->> 'total') IS DISTINCT FROM '0'
       OR (NEW."quota_consumed" > 0 AND NEW."quota_released_at" IS NULL) THEN
      RAISE EXCEPTION 'no_applicable_scans ends a running execution as succeeded only after a decision with an empty final set, with no scan task, zero task counts and the quota unit given back' USING ERRCODE = 'restrict_violation';
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

