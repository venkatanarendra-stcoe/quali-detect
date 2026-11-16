-- SPEC executions (docs/modules/executions/SPEC.md) section 17.ab, SBOM engine part, step 1 of 2: the scan task status
-- `unsupported` (a scan type is enabled in the snapshot but no engine is registered for it; reason `engine_not_registered`).
--
-- This file contains ONLY the enum change, on purpose (same reason as 20261116100000_execution_status_partial): PostgreSQL does
-- not allow a value added by `ALTER TYPE ... ADD VALUE` to be used in the transaction that adds it. The constraints and the
-- state-machine functions that mention `unsupported` are in the next migration, 20261116100300_scan_task_unsupported_rules.
ALTER TYPE "scan_task_status" ADD VALUE 'unsupported';
