-- SPEC executions section 17.ab, SBOM engine part, step 2 of 2: the rules of the scan task status `unsupported`.
--  * allowed transitions `pending -> unsupported` and `queued -> unsupported` only (the orchestrator marks a task unsupported
--    at creation, before any queue message or attempt exists); `running -> unsupported` is NOT allowed: a task that ran is
--    never "unsupported";
--  * `unsupported` is terminal and immutable like every finished task status (finished_at is set by the guard trigger);
--  * a status_reason is required for it and must be exactly `engine_not_registered`;
--  * no attempt or result can ever exist for it (the attempt/result guards already require a RUNNING task).
-- The execution-level trigger needs no change: an execution status is not affected.

ALTER TABLE "scan_tasks" DROP CONSTRAINT "scan_tasks_status_reason_check";
ALTER TABLE "scan_tasks" ADD CONSTRAINT "scan_tasks_status_reason_check" CHECK (
  ("status_reason" IS NULL OR "status_reason" ~ '^[a-z][a-z_:]{0,63}$')
  AND (("status" IN ('failed', 'timed_out', 'cancelled', 'skipped', 'unsupported')) = ("status_reason" IS NOT NULL))
  AND ("status" <> 'unsupported' OR "status_reason" = 'engine_not_registered')
);

ALTER TABLE "scan_tasks" DROP CONSTRAINT "scan_tasks_finished_check";
ALTER TABLE "scan_tasks" ADD CONSTRAINT "scan_tasks_finished_check" CHECK (
  ("finished_at" IS NOT NULL) = ("status" IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'skipped', 'unsupported'))
);

CREATE OR REPLACE FUNCTION scan_task_transition_allowed(from_status "scan_task_status", to_status "scan_task_status") RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT (from_status::text, to_status::text) IN (
    ('pending', 'queued'), ('pending', 'cancelled'), ('pending', 'skipped'), ('pending', 'unsupported'),
    ('queued', 'running'), ('queued', 'cancelled'), ('queued', 'skipped'), ('queued', 'unsupported'),
    ('running', 'queued'), ('running', 'succeeded'), ('running', 'failed'), ('running', 'timed_out'), ('running', 'cancelled')
  );
$$;

CREATE OR REPLACE FUNCTION scan_task_status_is_terminal(s "scan_task_status") RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT s::text IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'skipped', 'unsupported');
$$;

-- The history row written when a task is marked unsupported (one `task_unsupported` row per task, system actor, details hold the
-- scan type and the reason; the execution status does not change, so it is not a `transition`).
ALTER TABLE "execution_events" DROP CONSTRAINT "execution_events_type_check";
ALTER TABLE "execution_events" ADD CONSTRAINT "execution_events_type_check" CHECK ("type" IN ('transition', 'recovered', 'cancel_requested', 'limit_deferred', 'retry_requested', 'task_unsupported'));
