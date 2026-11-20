-- SPEC scan-engines 5.9 SE-22/SE-23, owner decision D-7 (part K core): the decision of an INCREMENTAL execution records where the
-- capped list of changed paths was stored and whether it is usable. Additive and nullable: a decision written before this migration,
-- a full run and every decision made while the ensemble flag is off keep both columns NULL, so existing behaviour is unchanged.
--   changed_paths_status  complete    the whole list was stored (<= 3000 paths, <= 512 KiB) as the artifact `changed-paths.json`
--                         truncated   the diff was truncated, or the list exceeded a cap, or a path was unsafe: NO list, scan the whole tree
--                         unavailable the diff was unavailable or the artifact could not be written: NO list, scan the whole tree
--   changed_paths_ref     the artifact name, only for `complete` (the scan handler reads it by tenant and execution, never by this value alone)
ALTER TABLE "scan_decisions" ADD COLUMN "changed_paths_ref" TEXT;
ALTER TABLE "scan_decisions" ADD COLUMN "changed_paths_status" TEXT;

-- (a CHECK passes when it evaluates to NULL, so every comparison on the nullable columns is written to be true or false, never NULL)
ALTER TABLE "scan_decisions" ADD CONSTRAINT "scan_decisions_changed_paths_check" CHECK (
  ("changed_paths_status" IS NULL AND "changed_paths_ref" IS NULL)
  OR ("changed_paths_status" IS NOT NULL AND "changed_paths_status" = 'complete' AND "changed_paths_ref" IS NOT NULL AND "changed_paths_ref" = 'changed-paths.json' AND "scan_kind" = 'incremental' AND "diff_status" = 'complete')
  OR ("changed_paths_status" IS NOT NULL AND "changed_paths_status" IN ('truncated', 'unavailable') AND "changed_paths_ref" IS NULL AND "scan_kind" = 'incremental')
);
