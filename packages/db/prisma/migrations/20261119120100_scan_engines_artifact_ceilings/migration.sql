-- Scan engines, part D (docs/modules/scan-engines/SPEC.md 7.3 "Artifacts", owner decision D-8): a second artifact class for raw SBOM
-- documents (CycloneDX, SPDX) with higher ceilings. The ceilings of Executions SPEC 17.ac (1 MiB per object, 20 objects and 8 MiB
-- per execution) stay for every other object (class `standard`, the default for every existing row). Class `sbom_document`:
-- 16 MiB per document, 20 documents and 64 MiB per execution (the 16 and 64 MiB numbers are Recommended and are to be calibrated
-- by ENG-L10; the count of 20 is added here so the table cannot fill with tiny documents). Nothing writes the new class yet.
ALTER TABLE "execution_artifacts" ADD COLUMN "artifact_class" TEXT NOT NULL DEFAULT 'standard';

ALTER TABLE "execution_artifacts" DROP CONSTRAINT "execution_artifacts_values_check";
ALTER TABLE "execution_artifacts" ADD CONSTRAINT "execution_artifacts_values_check" CHECK (
  "name" ~ '^[a-z][a-z0-9._-]{0,63}$' AND "name" !~ '\.\.' AND "name" !~ '\.$'
  AND "media_type" IN ('application/json', 'text/plain', 'application/octet-stream')
  AND "artifact_class" IN ('standard', 'sbom_document')
  AND "size_bytes" = octet_length("content")
  AND "size_bytes" BETWEEN 0 AND (CASE WHEN "artifact_class" = 'sbom_document' THEN 16777216 ELSE 1048576 END)
  AND "sha256" ~ '^[0-9a-f]{64}$'
);

-- Caps per execution AND per class: the standard class counts only standard objects (20, 8 MiB), the sbom_document class only
-- documents (20, 64 MiB). The advisory lock of the execution still serialises concurrent inserts.
CREATE OR REPLACE FUNCTION before_insert_execution_artifact() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  parent_status "execution_status";
  n integer;
  total bigint;
  max_total bigint;
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
  WHERE "tenant_id" = NEW."tenant_id" AND "execution_id" = NEW."execution_id" AND "artifact_class" = NEW."artifact_class";
  max_total := CASE WHEN NEW."artifact_class" = 'sbom_document' THEN 67108864 ELSE 8388608 END;
  IF n + 1 > 20 OR total + NEW."size_bytes" > max_total THEN
    RAISE EXCEPTION 'INSERT on % exceeds the per-execution artifact cap of class % (20 objects, % bytes)', TG_TABLE_NAME, NEW."artifact_class", max_total USING ERRCODE = 'check_violation', CONSTRAINT = 'execution_artifacts_execution_cap';
  END IF;
  RETURN NEW;
END;
$$;
