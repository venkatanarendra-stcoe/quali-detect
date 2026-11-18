-- Owner decision 2026-11-18 (scan-decisioning SPEC AP-2 amended, option B): the Secrets rule `strict` is removed; `any_change` is the
-- only rule. The decision record's `secrets_rule` therefore accepts exactly `any_change`.
--
-- The earlier CHECK `scan_decisions_values_check` (migration 20261118100000_scan_decisions) still lists 'strict'; it is left as it is
-- (replacing a long multi-clause CHECK for one literal would only add risk) and this narrower CHECK is added next to it, so both
-- must hold. NOT VALID: the rule applies to every new row at once without a table scan and without failing the migration when a
-- row written under `strict` already exists (the table is insert-only, so such a row cannot be rewritten; no such row is expected
-- because the rule was never enabled by default). Additive: no column, no data and no trigger changes.

ALTER TABLE "scan_decisions"
  ADD CONSTRAINT "scan_decisions_secrets_rule_check" CHECK ("secrets_rule" = 'any_change') NOT VALID;
