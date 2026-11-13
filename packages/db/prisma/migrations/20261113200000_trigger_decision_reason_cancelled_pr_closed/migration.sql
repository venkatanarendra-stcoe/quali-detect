-- Pipelines and triggers, owner decision of 2026-11-13 (fix-list 4): a `pull_request.closed` event (merged or not) cancels the
-- still-`queued` executions of that pull request, per pipeline, and leaves one trigger decision row with the new reason
-- `cancelled_pr_closed` (SPEC pipelines-triggers §5.4, §5.9b, §7.8). The closed event itself still never creates an execution.
-- The reason is a PostgreSQL enum (no CHECK constraint lists it), so one value is added; existing rows are untouched.

-- AlterEnum
ALTER TYPE "trigger_decision_reason" ADD VALUE IF NOT EXISTS 'cancelled_pr_closed';
