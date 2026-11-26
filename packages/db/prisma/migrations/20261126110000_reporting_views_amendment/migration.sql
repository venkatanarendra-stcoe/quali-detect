-- Reporting and Dashboards, amendment AM (docs/modules/reporting-dashboards/AS_BUILT_AM.md, SPEC 17.5): three more redaction-safe views for the
-- reads Part B could not serve from the seven frozen ones (pipelines healthy, coverage reasons, per-pipeline enabled scan types, the GitHub
-- connection tile, the tenant's SLA targets). ADDITIVE ONLY: no table, column, constraint, function or existing view changes. Like the first
-- seven, each view runs with its OWNER's rights, so the two reporting roles need no privilege on any source table; the grants are SELECT on
-- the three views and nothing else. They expose ids, enums, booleans, counts and the repository and pipeline DISPLAY names only: never a
-- repository URL (html_url), the owner (owner_user_id, owner login), a sync error text, the pipeline configuration JSON, a trigger, a cron
-- expression or an e-mail address. The suite proves it against information_schema (RPTA0-05, RPTAM-01).

-- Repositories of a workspace and their GitHub connection state (C-4 tile, S-4 reasons).
CREATE VIEW "report_repositories_v" AS
SELECT
  r."tenant_id", r."workspace_id", r."id" AS "repository_id",
  r."full_name" AS "repository_name", r."provider"::text AS "provider",
  r."status"::text AS "connection_status", r."enabled", r."archived"
FROM "repositories" r;

-- Pipelines (soft-deleted ones included, flagged) with the scan types enabled in the CURRENT configuration version. The configuration JSON
-- itself is never exposed: only `scans.<type>.enabled` of the four scan types, folded into one array of scan type names.
CREATE VIEW "report_pipelines_v" AS
SELECT
  p."tenant_id", p."workspace_id", p."repository_id", p."id" AS "pipeline_id",
  p."name" AS "pipeline_name", p."enabled", (p."deleted_at" IS NOT NULL) AS "pipeline_deleted",
  ARRAY(
    SELECT t."type" FROM (VALUES ('sbom'), ('sca'), ('sast'), ('secrets')) AS t("type")
    WHERE v."config" #>> ARRAY['scans', t."type", 'enabled'] = 'true'
    ORDER BY t."type"
  )::text[] AS "scan_types_enabled"
FROM "pipelines" p
LEFT JOIN "pipeline_config_versions" v ON v."tenant_id" = p."tenant_id" AND v."pipeline_id" = p."id" AND v."id" = p."current_version_id";

-- The tenant's SLA hours per severity (no row = the shared default of @qmentisai/shared, applied by the reader).
CREATE VIEW "report_sla_targets_v" AS
SELECT s."tenant_id", s."severity", s."hours"
FROM "finding_sla_targets" s;

DO $$
DECLARE v text;
BEGIN
  FOREACH v IN ARRAY ARRAY['report_repositories_v', 'report_pipelines_v', 'report_sla_targets_v'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qm_reporting') THEN EXECUTE format('GRANT SELECT ON %I TO qm_reporting', v); END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qm_reporting_ro') THEN EXECUTE format('GRANT SELECT ON %I TO qm_reporting_ro', v); END IF;
  END LOOP;
END
$$;
