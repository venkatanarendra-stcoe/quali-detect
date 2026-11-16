-- SPEC executions (docs/modules/executions/SPEC.md) §7.2, part B, step 1 of 2: the new execution status `partial`
-- (some scan tasks succeeded, some failed or timed out; CF-1, table 5.4).
--
-- This file contains ONLY the enum change, on purpose. PostgreSQL does not allow a value added by `ALTER TYPE ... ADD VALUE` to
-- be used in the transaction that adds it ("unsafe use of new value"), and Prisma applies one migration file as one multi-statement
-- command. Everything that mentions `partial` (CHECK constraints, the state-machine trigger) is in the next migration,
-- `20261116100100_executions_orchestration_schema`, which therefore runs after this one has committed.
ALTER TYPE "execution_status" ADD VALUE 'partial';
