import { spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  ERROR_CODES,
  MESSAGE_TYPES,
  QUEUE_NAMES,
  createJobEnvelope,
  parseMessage,
} from "@qmentisai/contracts";
import {
  ReportingNotImplementedError,
  createReportingExportWorkerRepository,
  createReportingExportsRepository,
  createReportingReadRepository,
  createReportingRollupRepository,
  defineRepository,
} from "@qmentisai/db";
import { BROKER_TOPOLOGY, declareBrokerTopology } from "@qmentisai/infra";
import {
  BACKLOG_STATUSES,
  BREAKDOWN_DIMENSIONS,
  CSV_BOM,
  CSV_EOL,
  FINDING_STATUSES,
  FLOW_CLOSED_OTHER_TO_STATUSES,
  FLOW_FIXED_TO_STATUSES,
  FLOW_REOPENED_TO_STATUSES,
  FORBIDDEN_REPORTING_DTO_KEYS,
  LIFECYCLE_GROUPS,
  LIFECYCLE_GROUP_OF_STATUS,
  METRICS,
  METRIC_BY_ID,
  OPEN_FINDING_STATUSES,
  REPORTING_LIMITS,
  REPORTING_MESSAGE_TYPES,
  REPORTING_PERMISSION_BY_ROUTE,
  REPORTING_PERMISSION_KEYS,
  REPORTING_ROUTE_SCHEMAS,
  REPORT_EXCLUDED_FIELDS,
  REPORT_TEMPLATES,
  REPORT_TEMPLATE_BY_ID,
  REPORT_TEMPLATE_IDS,
  RISK_WEIGHTS,
  ReportPeriodError,
  WORK_IN_PROGRESS_STATUSES,
  addDays,
  compareTopRisk,
  computeRiskScore,
  createReportBodySchema,
  csvRow,
  csvSafeCell,
  dayCloseInstant,
  dayRange,
  dayStartInstant,
  isDayString,
  isPermissionKey,
  isValidTimeZone,
  listDays,
  listLocalDays,
  localDayOf,
  overviewQuerySchema,
  postureDtoSchema,
  postureQuerySchema,
  reportingTimezoneBodySchema,
  resolvePeriod,
  topRiskQuerySchema,
  trendsQuerySchema,
  workspacePeriodQuerySchema,
  workspaceQuerySchema,
} from "@qmentisai/shared";
import { ERROR_HTTP_STATUS } from "../../../../src/errors/app-error.js";
import { loadConfig } from "../../../../src/config/index.js";
import { reportingModule } from "../../../../src/modules/reporting/index.js";
import { reportingReadRoutes } from "../../../../src/modules/reporting/routes/read.routes.js";
import { reportingExportRoutes } from "../../../../src/modules/reporting/routes/export.routes.js";
import { loadWorkerConfig } from "../../../../../workers/src/config.js";
import { createReportingDispatcher } from "../../../../../workers/src/reporting/dispatch.js";
import { start as startReportingWorker } from "../../../../../workers/src/reporting/index.js";
import { attempt, mustAccept, mustReject, probe } from "../pipeline-db.js";

/**
 * Reporting, Part A0 (the contract freeze): the checks the SPEC assigns to the freeze (docs/modules/reporting-dashboards/SPEC.md 16.2, ADR-008
 * area 20) that need no service code: the shape of the single migration (tables, composite tenant keys, CHECKs), the redaction-safe views
 * (exact column lists and a canary planted in every excluded field), the two roles and their EXACT grants, the provisioning script and a
 * real login, the pure properties of the shared package (periods and DST, `csvSafeCell`, lifecycle groups, the risk formula, schemas,
 * metrics, templates, limits), the message schemas, the queue, the error codes, the flags and the frozen surface. They run in process
 * against the disposable database; every denial has a control. NOT proved here: any HTTP route, any rollup value, any export file (parts A,
 * B and C build them and add their own checks); the dev database or a production role provisioning (live tests).
 */

const same = (p, label, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want))
    p.push(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
};
const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const sorted = (a) => [...a].sort();

const DAILY_TABLES = [
  "report_daily_findings",
  "report_daily_executions",
  "report_daily_decisions",
  "report_daily_sbom",
];
const REPORT_TABLES = [...DAILY_TABLES, "report_rollup_runs", "report_exports"];
const ALL_NEW_TABLES = [...REPORT_TABLES, "tenant_reporting_settings"];
const VIEW_COLUMNS = {
  report_findings_v: [
    "tenant_id",
    "workspace_id",
    "repository_id",
    "pipeline_id",
    "id",
    "scan_type",
    "kind",
    "rule_id",
    "title",
    "severity",
    "severity_rank",
    "confidence",
    "cwe",
    "component_purl",
    "component_name",
    "component_version",
    "ecosystem",
    "path",
    "start_line",
    "end_line",
    "status",
    "status_changed_at",
    "assignee_user_id",
    "assignee_display_name",
    "exception_pending",
    "exception_expires_at",
    "correlation_key",
    "first_detected_at",
    "last_seen_at",
    "fix_claimed_at",
    "verified_at",
    "reopened_at",
    "reopen_count",
    "closed_at",
    "sla_started_at",
    "sla_due_at",
    "origin_trust",
    "created_at",
    "repository_name",
    "pipeline_name",
    "pipeline_deleted",
  ],
  report_status_events_v: [
    "tenant_id",
    "workspace_id",
    "repository_id",
    "pipeline_id",
    "id",
    "finding_id",
    "rev",
    "from_status",
    "to_status",
    "actor_type",
    "actor_code",
    "reason_code",
    "created_at",
    "scan_type",
    "rule_id",
  ],
  report_decisions_v: [
    "tenant_id",
    "workspace_id",
    "repository_id",
    "pipeline_id",
    "finding_id",
    "id",
    "source",
    "decision",
    "exception_kind",
    "state",
    "severity_override",
    "accepted_severity",
    "advisory_id_at_decision",
    "created_at",
    "decided_at",
    "ended_at",
    "expires_at",
    "scan_type",
    "rule_id",
  ],
  report_advisories_v: [
    "tenant_id",
    "workspace_id",
    "repository_id",
    "pipeline_id",
    "finding_id",
    "id",
    "status",
    "suggestion",
    "confidence",
    "egress_level",
    "provider",
    "model",
    "schema_version",
    "created_at",
    "scan_type",
  ],
  report_executions_v: [
    "tenant_id",
    "workspace_id",
    "repository_id",
    "pipeline_id",
    "id",
    "status",
    "trigger_type",
    "ref_type",
    "scan_kind",
    "trust",
    "requested_at",
    "started_at",
    "finished_at",
    "created_at",
    "repository_name",
    "pipeline_name",
    "pipeline_deleted",
    "results_complete",
    "results_incomplete",
    "ingested",
  ],
  report_sbom_latest_v: [
    "tenant_id",
    "workspace_id",
    "repository_id",
    "pipeline_id",
    "sbom_execution_id",
    "sbom_result_id",
    "result_completeness",
    "result_created_at",
    "component_purl",
    "component_version",
    "ecosystem",
    "repository_name",
    "pipeline_name",
  ],
  report_tenant_settings_v: ["tenant_id", "tenant_status", "reporting_timezone"],
  // amendment AM (migration 20261126110000_reporting_views_amendment)
  report_repositories_v: [
    "tenant_id",
    "workspace_id",
    "repository_id",
    "repository_name",
    "provider",
    "connection_status",
    "enabled",
    "archived",
  ],
  report_pipelines_v: [
    "tenant_id",
    "workspace_id",
    "repository_id",
    "pipeline_id",
    "pipeline_name",
    "enabled",
    "pipeline_deleted",
    "scan_types_enabled",
  ],
  report_sla_targets_v: ["tenant_id", "severity", "hours"],
};
const VIEWS = Object.keys(VIEW_COLUMNS);
/** Column names no reporting view may ever carry (SPEC 8.1): free text of reviews, comments, advisories, exceptions, evidence, e-mail. */
const FORBIDDEN_COLUMN =
  /snippet|rationale|comment|body|reasoning|justification|scm_ref|email|evidence|compensating|(^|_)note|input_hash|usage|fingerprint|password|secret|preview|prompt|token|(^|_)url($|_)/;
/** Source tables a reporting role must never touch. */
const SOURCE_TABLES = [
  "findings",
  "finding_evidence",
  "finding_status_history",
  "finding_reviews",
  "finding_exceptions",
  "finding_approvals",
  "finding_assignments",
  "remediation_records",
  "verification_records",
  "finding_comments",
  "finding_ai_advisories",
  "finding_sla_targets",
  "finding_pipeline_state",
  "finding_ingestions",
  "executions",
  "scan_results",
  "scan_result_items",
  "pipelines",
  "repositories",
  "workspaces",
  "tenants",
  "users",
  "tenant_llm_settings",
  "tenant_reporting_settings",
  "outbox_messages",
  "audit_logs",
];

/** Runs `fn(tx)` as a restricted group role in its own transaction, always rolled back (so a denial never poisons the next probe). */
const asRole = (db, role, fn) =>
  probe(db, async (tx) => {
    await tx.$executeRawUnsafe(`SET LOCAL ROLE ${role}`);
    return fn(tx);
  });

const privileges = async (db, role) => {
  const rels = await db.$queryRaw`
    SELECT c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'v', 'p')`;
  const out = {};
  for (const { name } of rels) {
    const [row] = await db.$queryRawUnsafe(
      `SELECT ${["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
        .map((p) => `has_table_privilege('${role}', '"${name}"', '${p}') AS "${p}"`)
        .join(", ")}`,
    );
    const held = Object.entries(row)
      .filter(([, v]) => v)
      .map(([k]) => k);
    if (held.length > 0) out[name] = held.sort();
  }
  return Object.fromEntries(Object.entries(out).sort());
};

const pgRole = (db, name) =>
  db.$queryRaw`SELECT rolname, rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolconfig FROM pg_roles WHERE rolname = ${name}`;

/** A pipeline chain of tenant A and the foreign ones, for the composite key probes. */
async function chains(c) {
  const pa = (await c.published(c.A, 0)).pipeline;
  const pa2 = (await c.published(c.A, 1)).pipeline;
  const pb = (await c.published(c.B, 0)).pipeline;
  const chain = (p) => ({
    tenantId: p.tenantId,
    workspaceId: p.workspaceId,
    repositoryId: p.repositoryId,
    pipelineId: p.id,
  });
  return { pa, pa2, pb, chain };
}

const dailyFindings = (chain, over = {}) => ({
  ...chain,
  day: new Date("2026-11-20T00:00:00Z"),
  scanType: "sast",
  severity: "high",
  openCount: 2,
  backlogCount: 1,
  wipCount: 1,
  ...over,
});

/** A minimal CSV parser (RFC 4180) used only to prove that a written row reads back to the cells that were meant. */
function parseCsvRecord(text) {
  const cells = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        cur += '"';
        i += 1;
      } else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      cells.push(cur);
      cur = "";
    } else cur += ch;
  }
  cells.push(cur);
  return cells;
}

/** Every property name a Zod schema can produce (objects, arrays, optionals, unions, records, effects). */
function schemaKeys(schema, out = new Set(), seen = new Set()) {
  if (!schema || seen.has(schema)) return out;
  seen.add(schema);
  const def = schema._def ?? {};
  if (typeof schema.shape === "object")
    for (const [k, v] of Object.entries(schema.shape)) {
      out.add(k);
      schemaKeys(v, out, seen);
    }
  for (const next of [
    def.innerType,
    def.schema,
    def.type,
    def.valueType,
    def.in,
    def.out,
    def.left,
    def.right,
  ])
    schemaKeys(next, out, seen);
  for (const next of def.options ?? []) schemaKeys(next, out, seen);
  return out;
}

const SUITE_DATABASE_URL = () => process.env.SECURITY_DATABASE_URL;

/** @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]} */
export const REPORTING_A0_CHECKS = [
  {
    id: "RPTA0-01",
    name: "Reporting migration shape (SPEC 8, ADR-003, ADR-015): the seven new tables exist and each carries a NOT NULL tenant_id that is part of its primary key (the settings table is keyed by it); the four daily tables carry a COMPOSITE foreign key over (tenant_id, workspace_id, repository_id, pipeline_id) to pipelines and a tenant foreign key, both ON DELETE CASCADE (derived data is disposable); every other foreign key of the seven tables carries tenant_id; NO foreign key reaches a finding, execution or scan row; the (tenant_id, workspace_id, day) and (tenant_id, pipeline_id, day) indexes exist on the four daily tables; the finding enums are reused, not copied; the report time zone is the only change to an existing structure (no existing table gained a column)",
    async run(c) {
      const p = [];
      const { db } = c;
      const cols =
        await db.$queryRaw`SELECT table_name, is_nullable FROM information_schema.columns WHERE column_name = 'tenant_id' AND table_name = ANY(${ALL_NEW_TABLES})`;
      same(
        p,
        "tables with tenant_id",
        sorted(cols.map((x) => x.table_name)),
        sorted(ALL_NEW_TABLES),
      );
      ok(
        p,
        cols.every((x) => x.is_nullable === "NO"),
        "a tenant_id column is nullable",
      );
      const pks = await db.$queryRaw`
        SELECT c.conrelid::regclass::text AS tbl, array_agg(a.attname ORDER BY a.attname) AS cols
        FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
        WHERE c.contype = 'p' AND c.conrelid::regclass::text = ANY(${ALL_NEW_TABLES}) GROUP BY c.conrelid`;
      same(p, "tables with a primary key", pks.length, 7);
      for (const pk of pks)
        ok(p, pk.cols.includes("tenant_id"), `primary key of ${pk.tbl} lacks tenant_id`);
      const fks = await db.$queryRaw`
        SELECT c.conname, c.conrelid::regclass::text AS tbl, c.confrelid::regclass::text AS ref, c.confdeltype AS del,
               (SELECT array_agg(a.attname ORDER BY a.attname) FROM pg_attribute a WHERE a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)) AS cols
        FROM pg_constraint c WHERE c.contype = 'f' AND c.conrelid::regclass::text = ANY(${ALL_NEW_TABLES})`;
      for (const t of DAILY_TABLES) {
        const pipeline = fks.find((x) => x.tbl === t && x.ref === "pipelines");
        same(p, `${t} pipeline foreign key columns`, pipeline?.cols, [
          "pipeline_id",
          "repository_id",
          "tenant_id",
          "workspace_id",
        ]);
        ok(p, pipeline?.del === "c", `${t} pipeline foreign key is not ON DELETE CASCADE`);
        const tenant = fks.find((x) => x.tbl === t && x.ref === "tenants");
        same(p, `${t} tenant foreign key`, tenant?.cols, ["tenant_id"]);
        ok(p, tenant?.del === "c", `${t} tenant foreign key is not ON DELETE CASCADE`);
      }
      for (const fk of fks) {
        if (fk.ref === "tenants") continue;
        ok(
          p,
          fk.cols.includes("tenant_id") && fk.cols.length >= 2,
          `${fk.conname} is not a composite foreign key with tenant_id`,
        );
        ok(
          p,
          !/^(findings?$|finding_|executions|execution_|scan_)/.test(fk.ref),
          `${fk.conname} references the source table ${fk.ref} (derived data must not pin a purgeable or transactional row)`,
        );
      }
      ok(
        p,
        fks.some((x) => x.tbl === "report_exports" && x.ref === "workspaces"),
        "report_exports has no workspace foreign key",
      );
      const idx =
        await db.$queryRaw`SELECT tablename, indexdef FROM pg_indexes WHERE tablename = ANY(${DAILY_TABLES})`;
      for (const t of DAILY_TABLES) {
        const defs = idx.filter((i) => i.tablename === t).map((i) => i.indexdef);
        ok(
          p,
          defs.some((d) => /\(tenant_id, workspace_id, day\)/.test(d)),
          `${t} lacks the (tenant_id, workspace_id, day) index`,
        );
        ok(
          p,
          defs.some((d) => /\(tenant_id, pipeline_id, day\)/.test(d)),
          `${t} lacks the (tenant_id, pipeline_id, day) index`,
        );
      }
      const dailyTypes =
        await db.$queryRaw`SELECT udt_name FROM information_schema.columns WHERE table_name = 'report_daily_findings' AND column_name IN ('scan_type', 'severity') ORDER BY column_name`;
      same(
        p,
        "the finding enums are reused",
        dailyTypes.map((r) => r.udt_name),
        ["finding_scan_type", "finding_severity"],
      );
      // the SPEC puts no column on any existing table: the time zone has its own table (the product has no tenant_settings table)
      const tenantsCols =
        await db.$queryRaw`SELECT column_name FROM information_schema.columns WHERE table_name = 'tenants' AND column_name LIKE '%report%'`;
      same(p, "tenants gained no reporting column", tenantsCols.length, 0);
      return p;
    },
  },
  {
    id: "RPTA0-02",
    name: "Reporting CHECK constraints (SPEC 8.2, 8.3): every counter of the four daily tables refuses a negative value (each with an accepted control); a daily findings row whose open count is not backlog plus work in progress, whose awaiting-verification share exceeds work in progress or whose SLA states exceed the open count is refused; the executions row refuses status counters above the total; the decisions row refuses agreement counters above the advisory count; the SBOM row refuses more vulnerable components than components; rollup runs refuse an unknown mode, status or error code, an error code on a non-failed run, a failed run without one and a running run with a finish time; report exports refuse an unknown format, status or error code, a ready report without its file facts, a running one with a file, a params object over 2048 bytes, a half period, a period together with an as-of day, a bad sha256 and an object key that is not exactly reports/<tenant>/<id>.<format>",
    async run(c) {
      const p = [];
      const { db } = c;
      const { pa, chain } = await chains(c);
      const ch = chain(pa);
      const create = (model, data) => probe(db, (tx) => tx[model].create({ data }));
      const accept = async (label, model, data) => mustAccept(p, label, await create(model, data));
      const refuse = async (label, model, data, needle = "check") =>
        mustReject(p, label, await create(model, data), needle);
      // daily findings
      await accept("daily findings control", "reportDailyFindings", dailyFindings(ch));
      for (const f of [
        "openCount",
        "backlogCount",
        "wipCount",
        "awaitingVerificationCount",
        "slaOnTrack",
        "slaDueSoon",
        "slaBreached",
        "exceptionsInForce",
        "openAgeSecondsSum",
        "newCount",
        "fixedCount",
        "closedOtherCount",
        "reopenedCount",
      ])
        await refuse(`negative ${f}`, "reportDailyFindings", dailyFindings(ch, { [f]: -1 }));
      await refuse(
        "open != backlog + wip",
        "reportDailyFindings",
        dailyFindings(ch, { openCount: 5 }),
      );
      await refuse(
        "awaiting verification above wip",
        "reportDailyFindings",
        dailyFindings(ch, { awaitingVerificationCount: 2 }),
      );
      await refuse(
        "sla states above open",
        "reportDailyFindings",
        dailyFindings(ch, { slaOnTrack: 2, slaBreached: 1 }),
      );
      await accept(
        "sla states within open",
        "reportDailyFindings",
        dailyFindings(ch, { slaOnTrack: 1, slaDueSoon: 1, awaitingVerificationCount: 1 }),
      );
      await refuse(
        "day before 2000",
        "reportDailyFindings",
        dailyFindings(ch, { day: new Date("1999-12-31T00:00:00Z") }),
      );
      // daily executions
      const exec = (over = {}) => ({
        ...ch,
        day: new Date("2026-11-20T00:00:00Z"),
        total: 3,
        succeededCount: 2,
        failedCount: 1,
        ...over,
      });
      await accept("daily executions control", "reportDailyExecutions", exec());
      await refuse(
        "negative total",
        "reportDailyExecutions",
        exec({ total: -1, succeededCount: 0, failedCount: 0 }),
      );
      await refuse("negative duration sum", "reportDailyExecutions", exec({ durationMsSum: -1 }));
      await refuse(
        "status counters above total",
        "reportDailyExecutions",
        exec({ succeededCount: 3 }),
      );
      await refuse("eligible above total", "reportDailyExecutions", exec({ eligibleCount: 4 }));
      // daily decisions
      const dec = (over = {}) => ({
        ...ch,
        day: new Date("2026-11-20T00:00:00Z"),
        scanType: "sca",
        tpCount: 3,
        fpCount: 2,
        withAdvisory: 4,
        agreeFp: 1,
        agreeTp: 2,
        ...over,
      });
      await accept("daily decisions control", "reportDailyDecisions", dec());
      await refuse("negative fp", "reportDailyDecisions", dec({ fpCount: -1 }));
      await refuse(
        "agreement above advisory count",
        "reportDailyDecisions",
        dec({ agreeFp: 3, agreeTp: 2 }),
      );
      await refuse(
        "advisory count above decisions",
        "reportDailyDecisions",
        dec({ withAdvisory: 6 }),
      );
      await refuse(
        "override above advisory count",
        "reportDailyDecisions",
        dec({ overrideConfident: 5 }),
      );
      // daily sbom
      const sbom = (over = {}) => ({
        ...ch,
        day: new Date("2026-11-20T00:00:00Z"),
        components: 10,
        componentsVulnerable: 2,
        ...over,
      });
      await accept("daily sbom control", "reportDailySbom", sbom());
      await refuse(
        "more vulnerable than components",
        "reportDailySbom",
        sbom({ componentsVulnerable: 11 }),
      );
      await refuse(
        "negative components",
        "reportDailySbom",
        sbom({ components: -1, componentsVulnerable: 0 }),
      );
      // rollup runs
      const run = (over = {}) => ({
        tenantId: ch.tenantId,
        day: new Date("2026-11-20T00:00:00Z"),
        mode: "incremental",
        ...over,
      });
      await accept("rollup run control", "reportRollupRun", run());
      await accept(
        "finished run control",
        "reportRollupRun",
        run({ status: "succeeded", finishedAt: new Date() }),
      );
      await accept(
        "failed run control",
        "reportRollupRun",
        run({ status: "failed", finishedAt: new Date(), errorCode: "timeout" }),
      );
      await refuse("unknown mode", "reportRollupRun", run({ mode: "nightly" }));
      await refuse("unknown status", "reportRollupRun", run({ status: "queued" }));
      await refuse(
        "unknown error code",
        "reportRollupRun",
        run({ status: "failed", finishedAt: new Date(), errorCode: "boom" }),
      );
      await refuse(
        "error code on a succeeded run",
        "reportRollupRun",
        run({ status: "succeeded", finishedAt: new Date(), errorCode: "timeout" }),
      );
      await refuse(
        "failed run without an error code",
        "reportRollupRun",
        run({ status: "failed", finishedAt: new Date() }),
      );
      await refuse(
        "running run with a finish time",
        "reportRollupRun",
        run({ finishedAt: new Date() }),
      );
      await refuse(
        "finished run without a finish time",
        "reportRollupRun",
        run({ status: "succeeded" }),
      );
      await refuse(
        "range before the day",
        "reportRollupRun",
        run({ rangeTo: new Date("2026-11-19T00:00:00Z") }),
      );
      // report exports
      const id = randomUUID();
      const key = (tenantId, rid, format = "csv") => `reports/${tenantId}/${rid}.${format}`;
      const exp = (over = {}) => ({
        id,
        tenantId: ch.tenantId,
        workspaceId: ch.workspaceId,
        template: "findings_by_pipeline",
        format: "csv",
        requestedByUserId: randomUUID(),
        ...over,
      });
      const ready = (over = {}) =>
        exp({
          status: "ready",
          objectKey: key(ch.tenantId, id),
          bytes: 10,
          sha256: "a".repeat(64),
          expiresAt: new Date(),
          ...over,
        });
      await accept("export control", "reportExport", exp());
      await accept("tenant-wide export control", "reportExport", exp({ workspaceId: null }));
      await accept("ready export control", "reportExport", ready());
      await accept(
        "failed export control",
        "reportExport",
        exp({ status: "failed", errorCode: "too_large" }),
      );
      await accept(
        "period export control",
        "reportExport",
        exp({
          periodFrom: new Date("2026-11-01T00:00:00Z"),
          periodTo: new Date("2026-11-20T00:00:00Z"),
        }),
      );
      await refuse("unknown format", "reportExport", exp({ format: "json" }));
      await refuse("unknown status", "reportExport", exp({ status: "done" }));
      await refuse(
        "unknown error code",
        "reportExport",
        exp({ status: "failed", errorCode: "oops" }),
      );
      await refuse("error code on a queued export", "reportExport", exp({ errorCode: "internal" }));
      await refuse("failed export without a code", "reportExport", exp({ status: "failed" }));
      await refuse("template with a path separator", "reportExport", exp({ template: "../x" }));
      await refuse("ready export without a key", "reportExport", ready({ objectKey: null }));
      await refuse("ready export without a hash", "reportExport", ready({ sha256: null }));
      await refuse("ready export without an expiry", "reportExport", ready({ expiresAt: null }));
      await refuse(
        "running export that has a file",
        "reportExport",
        exp({ status: "running", objectKey: key(ch.tenantId, id) }),
      );
      await refuse(
        "object key of another tenant",
        "reportExport",
        ready({ objectKey: key(randomUUID(), id) }),
      );
      await refuse(
        "object key of another report",
        "reportExport",
        ready({ objectKey: key(ch.tenantId, randomUUID()) }),
      );
      await refuse(
        "object key with the wrong extension",
        "reportExport",
        ready({ objectKey: key(ch.tenantId, id, "pdf") }),
      );
      await refuse(
        "object key with a traversal",
        "reportExport",
        ready({ objectKey: `reports/${ch.tenantId}/../${id}.csv` }),
      );
      await refuse("bad sha256", "reportExport", ready({ sha256: "xyz" }));
      await refuse(
        "params above 2048 bytes",
        "reportExport",
        exp({ params: { note: "x".repeat(2100) } }),
      );
      await refuse("params that is not an object", "reportExport", exp({ params: [1] }));
      await refuse(
        "half a period",
        "reportExport",
        exp({ periodFrom: new Date("2026-11-01T00:00:00Z") }),
      );
      await refuse(
        "period after its end",
        "reportExport",
        exp({
          periodFrom: new Date("2026-11-20T00:00:00Z"),
          periodTo: new Date("2026-11-01T00:00:00Z"),
        }),
      );
      await refuse(
        "period together with an as-of day",
        "reportExport",
        exp({
          periodFrom: new Date("2026-11-01T00:00:00Z"),
          periodTo: new Date("2026-11-02T00:00:00Z"),
          asOfDay: new Date("2026-11-02T00:00:00Z"),
        }),
      );
      await refuse("negative bytes", "reportExport", ready({ bytes: -1 }));
      return p;
    },
  },
  {
    id: "RPTA0-03",
    name: "Reporting composite keys make a cross-tenant or cross-pipeline row unrepresentable (ADR-003): a daily row for pipeline B under tenant A, for a pipeline of tenant A under another workspace or repository of the same tenant, and under a tenant that does not exist is refused by the database for all four daily tables; an export that names another tenant's workspace is refused while a tenant-wide one (no workspace) and one of the right workspace are accepted; a rollup run of an unknown tenant is refused; each denial has a control",
    async run(c) {
      const p = [];
      const { db } = c;
      const { pa, pa2, pb, chain } = await chains(c);
      const day = new Date("2026-11-21T00:00:00Z");
      const rows = {
        reportDailyFindings: (x) => dailyFindings(x, { day }),
        reportDailyExecutions: (x) => ({ ...x, day, total: 1 }),
        reportDailyDecisions: (x) => ({ ...x, day, scanType: "sast", tpCount: 1 }),
        reportDailySbom: (x) => ({ ...x, day, components: 1 }),
      };
      const create = (model, data) => probe(db, (tx) => tx[model].create({ data }));
      for (const [model, make] of Object.entries(rows)) {
        mustAccept(p, `${model} control`, await create(model, make(chain(pa))));
        mustReject(
          p,
          `${model}: pipeline of tenant B under tenant A`,
          await create(model, make({ ...chain(pb), tenantId: pa.tenantId })),
          "P2003",
        );
        mustReject(
          p,
          `${model}: pipeline of tenant A under tenant B`,
          await create(model, make({ ...chain(pa), tenantId: pb.tenantId })),
          "P2003",
        );
        mustReject(
          p,
          `${model}: another workspace of the same tenant`,
          await create(model, make({ ...chain(pa), workspaceId: pa2.workspaceId })),
          "P2003",
        );
        mustReject(
          p,
          `${model}: another repository of the same tenant`,
          await create(model, make({ ...chain(pa), repositoryId: pa2.repositoryId })),
          "P2003",
        );
        mustReject(
          p,
          `${model}: another pipeline id`,
          await create(model, make({ ...chain(pa), pipelineId: randomUUID() })),
          "P2003",
        );
        mustReject(
          p,
          `${model}: a tenant that does not exist`,
          await create(model, make({ ...chain(pa), tenantId: randomUUID() })),
          "P2003",
        );
      }
      const exp = (over) => ({
        tenantId: pa.tenantId,
        template: "findings_by_pipeline",
        format: "csv",
        requestedByUserId: randomUUID(),
        ...over,
      });
      mustAccept(
        p,
        "export of the right workspace",
        await create("reportExport", exp({ workspaceId: pa.workspaceId })),
      );
      mustAccept(p, "tenant-wide export", await create("reportExport", exp({ workspaceId: null })));
      mustReject(
        p,
        "export naming another tenant's workspace",
        await create("reportExport", exp({ workspaceId: pb.workspaceId })),
        "P2003",
      );
      mustReject(
        p,
        "rollup run of an unknown tenant",
        await create("reportRollupRun", { tenantId: randomUUID(), day, mode: "close" }),
        "P2003",
      );
      mustAccept(
        p,
        "rollup run control",
        await create("reportRollupRun", { tenantId: pa.tenantId, day, mode: "close" }),
      );
      return p;
    },
  },
  {
    id: "RPTA0-04",
    name: "Tenant reporting time zone (SPEC 8.4, D-5): the table is keyed by tenant (one row per tenant), the column defaults to UTC, an empty string, a name over 64 characters and a name with a space, a newline or an offset form are refused by the database (the IANA name itself is validated in code) with accepted controls; `report_tenant_settings_v` shows UTC for a tenant with no row and the stored zone for one with a row, and carries the tenant status; the code validator accepts real IANA names and refuses offsets, empty and unknown names",
    async run(c) {
      const p = [];
      const { db } = c;
      const col =
        await db.$queryRaw`SELECT column_default, is_nullable FROM information_schema.columns WHERE table_name = 'tenant_reporting_settings' AND column_name = 'reporting_timezone'`;
      ok(
        p,
        /UTC/.test(col[0]?.column_default ?? "") && col[0]?.is_nullable === "NO",
        "reporting_timezone is not NOT NULL DEFAULT 'UTC'",
      );
      const t = c.A.tenant.id;
      const create = (tenantId, reportingTimezone) =>
        probe(db, (tx) =>
          tx.tenantReportingSettings.create({ data: { tenantId, reportingTimezone } }),
        );
      mustAccept(p, "control, Europe/Berlin", await create(t, "Europe/Berlin"));
      mustAccept(
        p,
        "control, America/Argentina/Buenos_Aires",
        await create(t, "America/Argentina/Buenos_Aires"),
      );
      mustAccept(p, "control, UTC", await create(t, "UTC"));
      for (const bad of [
        "",
        "x".repeat(65),
        "Europe Berlin",
        "Europe/Berlin\n",
        "+01:00",
        "1Europe/Berlin",
        "Europe/Berlin;",
      ])
        mustReject(
          p,
          `time zone ${JSON.stringify(bad).slice(0, 30)}`,
          await create(t, bad),
          "check",
        );
      const before =
        await db.$queryRaw`SELECT reporting_timezone, tenant_status FROM report_tenant_settings_v WHERE tenant_id = ${c.B.tenant.id}::uuid`;
      same(
        p,
        "tenant without a row",
        before.map((r) => r.reporting_timezone),
        ["UTC"],
      );
      ok(p, before[0]?.tenant_status === "active", "the view does not carry the tenant status");
      await db.tenantReportingSettings.upsert({
        where: { tenantId: c.B.tenant.id },
        create: { tenantId: c.B.tenant.id, reportingTimezone: "Asia/Kolkata" },
        update: { reportingTimezone: "Asia/Kolkata" },
      });
      const after =
        await db.$queryRaw`SELECT reporting_timezone FROM report_tenant_settings_v WHERE tenant_id = ${c.B.tenant.id}::uuid`;
      same(
        p,
        "tenant with a row",
        after.map((r) => r.reporting_timezone),
        ["Asia/Kolkata"],
      );
      const dup = await attempt(() =>
        db.tenantReportingSettings.create({
          data: { tenantId: c.B.tenant.id, reportingTimezone: "UTC" },
        }),
      );
      mustReject(p, "a second settings row for one tenant", dup, "P2002");
      await db.tenantReportingSettings.delete({ where: { tenantId: c.B.tenant.id } });
      for (const good of [
        "UTC",
        "Europe/Berlin",
        "America/New_York",
        "America/Argentina/Buenos_Aires",
        "Asia/Kolkata",
        "Australia/Lord_Howe",
        "Etc/GMT+5",
      ])
        ok(p, isValidTimeZone(good), `isValidTimeZone refuses ${good}`);
      for (const bad of [
        "",
        " UTC",
        "UTC ",
        "+01:00",
        "Mars/Olympus_Mons",
        "../etc/passwd",
        "x".repeat(65),
        "Europe//Berlin",
        42,
        null,
        undefined,
      ])
        ok(p, !isValidTimeZone(bad), `isValidTimeZone accepts ${String(bad)}`);
      ok(
        p,
        reportingTimezoneBodySchema.safeParse({ timeZone: "Europe/Berlin" }).success,
        "the body schema refuses a real zone",
      );
      ok(
        p,
        !reportingTimezoneBodySchema.safeParse({ timeZone: "Nowhere/City" }).success,
        "the body schema accepts an unknown zone",
      );
      ok(
        p,
        !reportingTimezoneBodySchema.safeParse({ timeZone: "UTC", tenantId: randomUUID() }).success,
        "the body schema accepts a tenantId",
      );
      return p;
    },
  },
  {
    id: "RPTA0-05",
    name: "Reporting views expose ONLY non-sensitive columns (SPEC 8.1, RPT-011, ADR-015 item 5): exactly the ten views report_findings_v, report_status_events_v, report_decisions_v, report_advisories_v, report_executions_v, report_sbom_latest_v (and report_tenant_settings_v for the time zone, plus report_repositories_v, report_pipelines_v and report_sla_targets_v of the AM amendment) exist and no other report_*_v; the column list of each is EXACTLY the one frozen in this check (compared with information_schema); no column of any view has a name that is evidence, snippet, rationale, comment body, advisory reasoning, exception justification, compensating controls, scm_ref, a status-history note, an input hash, usage, a fingerprint, a token, a url or an e-mail; the only user reference is the assignee id and display name",
    async run(c) {
      const p = [];
      const { db } = c;
      const rows =
        await db.$queryRaw`SELECT table_name, column_name, ordinal_position FROM information_schema.columns WHERE table_schema = 'public' AND table_name LIKE 'report\\_%\\_v' ORDER BY table_name, ordinal_position`;
      same(
        p,
        "the set of views",
        sorted([...new Set(rows.map((r) => r.table_name))]),
        sorted(VIEWS),
      );
      for (const [view, want] of Object.entries(VIEW_COLUMNS)) {
        const got = rows.filter((r) => r.table_name === view).map((r) => r.column_name);
        same(p, `columns of ${view}`, got, want);
        for (const col of got)
          ok(p, !FORBIDDEN_COLUMN.test(col), `${view}.${col} looks like a forbidden column`);
      }
      const views =
        await db.$queryRaw`SELECT c.relname AS name, c.relkind AS kind, c.reloptions AS options FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname LIKE 'report\\_%\\_v'`;
      ok(
        p,
        views.every((v) => v.kind === "v"),
        "a report_*_v relation is not a plain view",
      );
      ok(
        p,
        views.every((v) => !(v.options ?? []).some((o) => /security_invoker/.test(o))),
        "a view is security_invoker (the roles would then need the source grants)",
      );
      const refs =
        await db.$queryRaw`SELECT column_name, table_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ANY(${DAILY_TABLES}) AND column_name ~ 'title|path|rule|name|email|user'`;
      same(
        p,
        "the rollup tables carry no text of a finding",
        refs.map((r) => r.column_name),
        [],
      );
      return p;
    },
  },
  {
    id: "RPTA0-06",
    name: "Reporting views leak nothing from a planted canary (RPT-011, SPEC 12 item 2): a secret finding and a code finding are created with a canary string in finding_evidence (snippet, scm_ref, url), finding_reviews.rationale, finding_comments.body, finding_ai_advisories.reasoning, finding_exceptions.justification and the status-history note; read as the restricted read role, SELECT * from EVERY view returns rows for the findings (control) and no cell of any row, serialised, contains a canary; the cross-pipeline key of a secret finding is NULL while a code finding keeps its key; the decisions view returns the review and the exception timeline without their free text",
    async run(c) {
      const p = [];
      const { db } = c;
      const pa = (await c.published(c.A, 0)).pipeline;
      const tag = randomBytes(4).toString("hex");
      const canary = (label) => `CANARY-${label}-${tag}`;
      const code = await c.finding(pa, { scanType: "sast", title: "Use of eval" });
      const sec = await c.finding(pa, {
        scanType: "secrets",
        kind: "secret",
        anchorKind: "masked_line",
        ruleId: "generic-api-key",
        title: "Hard-coded key",
      });
      await db.findingEvidence.create({
        data: {
          ...c.chainOf(code),
          kind: "block",
          capturedExecutionId: randomUUID(),
          capturedAt: new Date(),
          snippet: canary("snippet"),
          scmRef: { blob: canary("scmref") },
          url: `https://example.test/${canary("url")}`,
        },
      });
      await db.findingEvidence.create({
        data: {
          ...c.chainOf(sec),
          kind: "line",
          capturedExecutionId: randomUUID(),
          capturedAt: new Date(),
          snippet: canary("secretsnippet"),
        },
      });
      await c.review(code, { rationale: canary("rationale") });
      await c.exception(code, {
        justification: canary("justification"),
        compensatingControls: canary("controls"),
      });
      await db.findingComment.create({
        data: { ...c.chainOf(code), authorUserId: randomUUID(), body: canary("comment") },
      });
      await db.findingAiAdvisory.create({
        data: {
          ...c.chainOf(code),
          inputHash: randomBytes(32).toString("hex"),
          status: "ok",
          suggestion: "likely_false_positive",
          confidence: 80,
          reasoning: canary("reasoning"),
          egressLevel: "metadata",
          provider: "ollama",
          model: "m",
        },
      });
      await c.step(code, "in_review", { note: canary("note") });
      const seen = {};
      const r = await asRole(db, "qm_reporting_ro", async (tx) => {
        for (const view of VIEWS)
          seen[view] = await tx.$queryRawUnsafe(
            `SELECT * FROM ${view} WHERE tenant_id = '${pa.tenantId}'`,
          );
      });
      ok(
        p,
        seen.report_findings_v?.length >= 2,
        "the findings view does not show the two findings (control)",
      );
      ok(
        p,
        seen.report_status_events_v?.some(
          (e) => e.finding_id === code.id && e.to_status === "in_review",
        ),
        "the status events view lacks the transition (control)",
      );
      ok(
        p,
        seen.report_decisions_v?.some((d) => d.source === "review") &&
          seen.report_decisions_v?.some((d) => d.source === "exception"),
        "the decisions view lacks the review or the exception (control)",
      );
      ok(
        p,
        seen.report_advisories_v?.some((a) => a.suggestion === "likely_false_positive"),
        "the advisories view lacks the advisory (control)",
      );
      for (const [view, rowsOfView] of Object.entries(seen)) {
        const text = JSON.stringify(rowsOfView, (_k, v) =>
          typeof v === "bigint" ? v.toString() : v,
        );
        ok(p, !text.includes(tag), `${view} contains a canary`);
        ok(p, !/@pdb\.example/.test(text), `${view} contains an e-mail address`);
      }
      const f = (id) => seen.report_findings_v?.find((x) => x.id === id);
      ok(p, f(sec.id)?.correlation_key === null, "a secret finding exposes its correlation key");
      ok(
        p,
        typeof f(code.id)?.correlation_key === "string",
        "a code finding lost its correlation key",
      );
      ok(
        p,
        f(code.id)?.repository_name && f(code.id)?.pipeline_name,
        "the findings view lacks the repository or pipeline name",
      );
      mustAccept(p, "the read role selected every view", r);
      return p;
    },
  },
  {
    id: "RPTA0-07",
    name: "Reporting read role qm_reporting_ro (SPEC 12 item 7, owner ruling): a NOLOGIN group that is not a superuser; for EVERY table and view of the public schema its privileges are EXACTLY SELECT on the ten report views and the six report_* tables and nothing else (no INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES or TRIGGER anywhere), checked with has_table_privilege so inheritance and PUBLIC are counted; as the role SELECT works on every view and table and is DENIED on finding_evidence, finding_comments, finding_reviews, finding_ai_advisories, finding_exceptions, findings, the status history, tenant_llm_settings, users, tenants and every other source table; every write to a report table is denied and so is TRUNCATE and a call of the clear and purge functions; the role has default_transaction_read_only on and a 5 second statement timeout",
    async run(c) {
      const p = [];
      const { db } = c;
      const role = await pgRole(db, "qm_reporting_ro");
      same(
        p,
        "the read role exists, cannot log in, is not a superuser",
        [
          role.length,
          role[0]?.rolcanlogin,
          role[0]?.rolsuper,
          role[0]?.rolcreaterole,
          role[0]?.rolcreatedb,
        ],
        [1, false, false, false, false],
      );
      const cfg = (role[0]?.rolconfig ?? []).join(" ");
      ok(
        p,
        /default_transaction_read_only=on/.test(cfg),
        "default_transaction_read_only is not on",
      );
      ok(p, /statement_timeout=5s/.test(cfg), "statement_timeout is not 5s");
      ok(
        p,
        /idle_in_transaction_session_timeout=10s/.test(cfg),
        "idle_in_transaction_session_timeout is not 10s",
      );
      const held = await privileges(db, "qm_reporting_ro");
      const want = Object.fromEntries([...VIEWS, ...REPORT_TABLES].map((n) => [n, ["SELECT"]]));
      same(
        p,
        "the exact privilege set of qm_reporting_ro",
        held,
        Object.fromEntries(Object.entries(want).sort()),
      );
      const { pa } = await chains(c);
      for (const rel of [...VIEWS, ...REPORT_TABLES])
        mustAccept(
          p,
          `SELECT ${rel}`,
          await asRole(db, "qm_reporting_ro", (tx) =>
            tx.$queryRawUnsafe(`SELECT * FROM ${rel} LIMIT 1`),
          ),
        );
      for (const rel of SOURCE_TABLES)
        mustReject(
          p,
          `SELECT ${rel}`,
          await asRole(db, "qm_reporting_ro", (tx) =>
            tx.$queryRawUnsafe(`SELECT 1 FROM ${rel} LIMIT 1`),
          ),
          "permission denied",
        );
      for (const col of ["snippet", "scm_ref"])
        mustReject(
          p,
          `SELECT finding_evidence.${col}`,
          await asRole(db, "qm_reporting_ro", (tx) =>
            tx.$queryRawUnsafe(`SELECT ${col} FROM finding_evidence LIMIT 1`),
          ),
          "permission denied",
        );
      mustReject(
        p,
        "SELECT finding_reviews.rationale",
        await asRole(db, "qm_reporting_ro", (tx) =>
          tx.$queryRawUnsafe("SELECT rationale FROM finding_reviews LIMIT 1"),
        ),
        "permission denied",
      );
      mustReject(
        p,
        "SELECT users.email",
        await asRole(db, "qm_reporting_ro", (tx) =>
          tx.$queryRawUnsafe("SELECT email FROM users LIMIT 1"),
        ),
        "permission denied",
      );
      const ch = { t: pa.tenantId, w: pa.workspaceId, r: pa.repositoryId, p: pa.id };
      const writes = {
        "INSERT report_daily_findings": `INSERT INTO report_daily_findings (tenant_id, workspace_id, repository_id, pipeline_id, day, scan_type, severity) VALUES ('${ch.t}', '${ch.w}', '${ch.r}', '${ch.p}', '2026-11-22', 'sast', 'high')`,
        "INSERT report_exports": `INSERT INTO report_exports (id, tenant_id, template, format, requested_by_user_id) VALUES ('${randomUUID()}', '${ch.t}', 'x', 'csv', '${randomUUID()}')`,
        "UPDATE report_daily_findings": "UPDATE report_daily_findings SET open_count = 0",
        "UPDATE report_exports": "UPDATE report_exports SET status = 'failed'",
        "DELETE report_daily_findings": "DELETE FROM report_daily_findings",
        "DELETE report_rollup_runs": "DELETE FROM report_rollup_runs",
        "TRUNCATE report_daily_findings": "TRUNCATE report_daily_findings",
        "UPDATE findings": "UPDATE findings SET severity = 'low'",
        "INSERT finding_status_history": `INSERT INTO finding_status_history (id, tenant_id) VALUES ('${randomUUID()}', '${ch.t}')`,
        "clear function": `SELECT qm_reporting_clear_range('${ch.t}', '2026-01-01', '2026-12-31')`,
        "purge function": "SELECT qm_reporting_purge('2026-01-01', now(), now(), 10)",
      };
      for (const [label, sql] of Object.entries(writes))
        mustReject(
          p,
          label,
          await asRole(db, "qm_reporting_ro", (tx) => tx.$executeRawUnsafe(sql)),
          "permission denied",
        );
      // a control: the same insert is fine for the owner (so the denial above is the grant, not a malformed statement)
      mustAccept(
        p,
        "the same insert for the owner",
        await probe(db, (tx) => tx.$executeRawUnsafe(writes["INSERT report_daily_findings"])),
      );
      return p;
    },
  },
  {
    id: "RPTA0-08",
    name: "Reporting worker role qm_reporting (SPEC 12 item 7, owner ruling): a NOLOGIN group, not a superuser; for EVERY table and view of the public schema its privileges are EXACTLY SELECT on the ten views and the six report_* tables plus INSERT and UPDATE on the six report_* tables and nothing else (no DELETE or TRUNCATE; none on any source table, evidence, comment, review, advisory, exception, history, execution, scan result, user, tenant, tenant_llm_settings or tenant_reporting_settings); as the role INSERT and UPDATE of a daily row succeed (controls) and DELETE, TRUNCATE, every write to a source table and every read of a source table or of tenant_llm_settings are denied; it may run the clear and purge functions, which delete only what they are told to (a tenant's day range, an expired row), and the functions are NOT executable by PUBLIC or by the read role",
    async run(c) {
      const p = [];
      const { db } = c;
      const role = await pgRole(db, "qm_reporting");
      same(
        p,
        "the worker role exists, cannot log in, is not a superuser",
        [
          role.length,
          role[0]?.rolcanlogin,
          role[0]?.rolsuper,
          role[0]?.rolcreaterole,
          role[0]?.rolcreatedb,
        ],
        [1, false, false, false, false],
      );
      const held = await privileges(db, "qm_reporting");
      const want = {};
      for (const n of VIEWS) want[n] = ["SELECT"];
      for (const n of REPORT_TABLES) want[n] = ["INSERT", "SELECT", "UPDATE"];
      same(
        p,
        "the exact privilege set of qm_reporting",
        held,
        Object.fromEntries(Object.entries(want).sort()),
      );
      const { pa, pb } = await chains(c);
      const t = pa.tenantId;
      const ins = (day, tenant = pa) =>
        `INSERT INTO report_daily_findings (tenant_id, workspace_id, repository_id, pipeline_id, day, scan_type, severity, open_count, backlog_count) VALUES ('${tenant.tenantId}', '${tenant.workspaceId}', '${tenant.repositoryId}', '${tenant.id}', '${day}', 'sast', 'high', 1, 1)`;
      mustAccept(
        p,
        "INSERT a daily row as the worker",
        await asRole(db, "qm_reporting", (tx) => tx.$executeRawUnsafe(ins("2026-11-23"))),
      );
      mustAccept(
        p,
        "UPDATE a daily row as the worker",
        await asRole(db, "qm_reporting", async (tx) => {
          await tx.$executeRawUnsafe(ins("2026-11-23"));
          await tx.$executeRawUnsafe(
            "UPDATE report_daily_findings SET open_count = 3, backlog_count = 3 WHERE day = '2026-11-23'",
          );
        }),
      );
      mustAccept(
        p,
        "INSERT a rollup run as the worker",
        await asRole(db, "qm_reporting", (tx) =>
          tx.$executeRawUnsafe(
            `INSERT INTO report_rollup_runs (id, tenant_id, day, mode) VALUES ('${randomUUID()}', '${t}', '2026-11-23', 'close')`,
          ),
        ),
      );
      for (const view of VIEWS)
        mustAccept(
          p,
          `SELECT ${view} as the worker`,
          await asRole(db, "qm_reporting", (tx) =>
            tx.$queryRawUnsafe(`SELECT * FROM ${view} LIMIT 1`),
          ),
        );
      const denied = {
        "DELETE report_daily_findings": "DELETE FROM report_daily_findings",
        "DELETE report_exports": "DELETE FROM report_exports",
        "TRUNCATE report_daily_sbom": "TRUNCATE report_daily_sbom",
        "UPDATE findings": "UPDATE findings SET severity = 'low'",
        "DELETE findings": "DELETE FROM findings",
        "INSERT finding_status_history": `INSERT INTO finding_status_history (id, tenant_id) VALUES ('${randomUUID()}', '${t}')`,
        "UPDATE finding_reviews": "UPDATE finding_reviews SET decision = 'false_positive'",
        "UPDATE executions": "UPDATE executions SET status = 'failed'",
        "UPDATE tenant_reporting_settings":
          "UPDATE tenant_reporting_settings SET reporting_timezone = 'UTC'",
        "UPDATE tenants": "UPDATE tenants SET status = 'active'",
        "SELECT tenant_llm_settings": "SELECT * FROM tenant_llm_settings LIMIT 1",
        "SELECT finding_evidence": "SELECT * FROM finding_evidence LIMIT 1",
        "SELECT finding_comments": "SELECT * FROM finding_comments LIMIT 1",
        "SELECT finding_reviews": "SELECT * FROM finding_reviews LIMIT 1",
        "SELECT finding_ai_advisories": "SELECT * FROM finding_ai_advisories LIMIT 1",
        "SELECT finding_exceptions": "SELECT * FROM finding_exceptions LIMIT 1",
        "SELECT findings": "SELECT * FROM findings LIMIT 1",
        "SELECT users": "SELECT * FROM users LIMIT 1",
        "SELECT outbox": "SELECT * FROM outbox_messages LIMIT 1",
      };
      for (const [label, sql] of Object.entries(denied))
        mustReject(
          p,
          label,
          await asRole(db, "qm_reporting", (tx) => tx.$executeRawUnsafe(sql)),
          "permission denied",
        );
      // the functions: scoped, executable by the worker only
      await db.reportDailyFindings.createMany({
        data: [
          dailyFindings(
            {
              tenantId: pa.tenantId,
              workspaceId: pa.workspaceId,
              repositoryId: pa.repositoryId,
              pipelineId: pa.id,
            },
            { day: new Date("2026-01-10T00:00:00Z") },
          ),
          dailyFindings(
            {
              tenantId: pa.tenantId,
              workspaceId: pa.workspaceId,
              repositoryId: pa.repositoryId,
              pipelineId: pa.id,
            },
            { day: new Date("2026-03-10T00:00:00Z") },
          ),
          dailyFindings(
            {
              tenantId: pb.tenantId,
              workspaceId: pb.workspaceId,
              repositoryId: pb.repositoryId,
              pipelineId: pb.id,
            },
            { day: new Date("2026-01-10T00:00:00Z") },
          ),
        ],
      });
      const cleared = await attempt(() =>
        db.$transaction(async (tx) => {
          await tx.$executeRawUnsafe("SET LOCAL ROLE qm_reporting");
          const [{ n }] = await tx.$queryRawUnsafe(
            `SELECT qm_reporting_clear_range('${pa.tenantId}', '2026-01-01', '2026-02-01') AS n`,
          );
          const left = await tx.$queryRawUnsafe(
            `SELECT count(*)::int AS n FROM report_daily_findings WHERE tenant_id = '${pa.tenantId}' AND day IN ('2026-01-10', '2026-03-10')`,
          );
          const foreign = await tx.$queryRawUnsafe(
            `SELECT count(*)::int AS n FROM report_daily_findings WHERE tenant_id = '${pb.tenantId}' AND day = '2026-01-10'`,
          );
          throw new Error(`rollback ${n}/${left[0].n}/${foreign[0].n}`);
        }),
      );
      ok(
        p,
        cleared.message.includes("rollback 1/1/1"),
        `qm_reporting_clear_range removed the wrong rows (${cleared.message.slice(0, 80)})`,
      );
      const purged = await attempt(() =>
        db.$transaction(async (tx) => {
          await tx.$executeRawUnsafe("SET LOCAL ROLE qm_reporting");
          const [{ n }] = await tx.$queryRawUnsafe(
            "SELECT qm_reporting_purge('2026-02-01', now() - interval '1 day', now() - interval '1 day', 100) AS n",
          );
          throw new Error(`rollback ${n >= 2}`);
        }),
      );
      ok(
        p,
        purged.message.includes("rollback true"),
        "qm_reporting_purge did not remove the rows before the cutoff",
      );
      mustReject(
        p,
        "PUBLIC calls the clear function",
        await asRole(db, "qm_reporting_ro", (tx) =>
          tx.$executeRawUnsafe(
            `SELECT qm_reporting_clear_range('${t}', '2026-01-01', '2026-01-02')`,
          ),
        ),
        "permission denied",
      );
      const pub =
        await db.$queryRaw`SELECT has_function_privilege('public', 'qm_reporting_clear_range(uuid, date, date)', 'EXECUTE') AS a, has_function_privilege('public', 'qm_reporting_purge(date, timestamptz, timestamptz, integer)', 'EXECUTE') AS b`;
      same(p, "PUBLIC may execute the functions", [pub[0].a, pub[0].b], [false, false]);
      return p;
    },
  },
  {
    id: "RPTA0-09",
    name: "Reporting login provisioning (SPEC 12 item 7, the qm_fp_agent pattern): `provision-reporting-logins.js` refuses a missing, short (under 16 characters) or equal-named password configuration and a missing admin URL without touching the database; run against the disposable database it creates a LOGIN role that is a MEMBER of each group (not a superuser, no create-role, no create-db), is IDEMPOTENT (a second run succeeds and rotates the password), never prints a password, and the read login really connects and can SELECT a view but cannot read finding_evidence, cannot write, and has the read-only default and the 5 second timeout (role settings do not pass from a group to a member, so the script sets them on the login), while the worker login can insert a report row and cannot touch a source table",
    async run(c) {
      const p = [];
      const { db } = c;
      const script = fileURLToPath(
        new URL(
          "../../../../../../packages/db/scripts/provision-reporting-logins.js",
          import.meta.url,
        ),
      );
      const adminUrl = SUITE_DATABASE_URL();
      const pw = (n) => `${n}-${randomBytes(12).toString("hex")}`;
      const run = (env) =>
        spawnSync(process.execPath, [script], {
          env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
          encoding: "utf8",
          timeout: 60000,
        });
      const w = pw("worker");
      const r = pw("reader");
      const base = {
        DATABASE_URL: adminUrl,
        REPORTING_DB_PASSWORD: w,
        REPORTING_RO_DB_PASSWORD: r,
      };
      const nothing = run({ REPORTING_DB_PASSWORD: w, REPORTING_RO_DB_PASSWORD: r });
      ok(
        p,
        nothing.status === 2 && /DATABASE_URL/.test(nothing.stderr),
        "a missing admin URL is not refused",
      );
      const short = run({ ...base, REPORTING_RO_DB_PASSWORD: "short" });
      ok(
        p,
        short.status === 2 && /at least 16/.test(short.stderr),
        "a short password is not refused",
      );
      ok(
        p,
        !short.stderr.includes("short") && !short.stdout.includes("short"),
        "the refusal echoes the password",
      );
      const nopw = run({ DATABASE_URL: adminUrl });
      ok(p, nopw.status === 2, "missing passwords are not refused");
      const same2 = run({
        ...base,
        REPORTING_DB_LOGIN: "qm_same",
        REPORTING_RO_DB_LOGIN: "qm_same",
      });
      ok(p, same2.status === 2, "equal login names are not refused");
      const badName = run({ ...base, REPORTING_DB_LOGIN: "Bad Name;" });
      ok(p, badName.status === 2, "a bad login name is not refused");
      const names = {
        REPORTING_DB_LOGIN: `qm_rw_${randomBytes(3).toString("hex")}`,
        REPORTING_RO_DB_LOGIN: `qm_ro_${randomBytes(3).toString("hex")}`,
      };
      const first = run({ ...base, ...names });
      ok(
        p,
        first.status === 0,
        `the first run failed (${first.stderr.trim().split("\n").pop()?.slice(0, 120)})`,
      );
      const second = run({
        ...base,
        ...names,
        REPORTING_DB_PASSWORD: pw("rotated"),
        REPORTING_RO_DB_PASSWORD: pw("rotated"),
      });
      ok(
        p,
        second.status === 0,
        `the second run (idempotent) failed (${second.stderr.trim().split("\n").pop()?.slice(0, 120)})`,
      );
      for (const out of [first, second, nothing, short])
        for (const secret of [w, r])
          ok(
            p,
            !out.stdout.includes(secret) && !out.stderr.includes(secret),
            "a password was printed",
          );
      ok(
        p,
        /REPORTING_DATABASE_URL=.*<password>/.test(first.stdout) &&
          /REPORTING_RO_DATABASE_URL=.*<password>/.test(first.stdout),
        "the connection strings are not printed with a placeholder",
      );
      const members = await db.$queryRaw`
        SELECT m.rolname AS member, g.rolname AS grp, m.rolcanlogin, m.rolsuper, m.rolcreaterole, m.rolcreatedb
        FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
        WHERE m.rolname = ANY(${Object.values(names)})`;
      same(
        p,
        "memberships",
        members
          .map((m) => [m.member, m.grp, m.rolcanlogin, m.rolsuper, m.rolcreaterole, m.rolcreatedb])
          .sort(),
        [
          [names.REPORTING_DB_LOGIN, "qm_reporting", true, false, false, false],
          [names.REPORTING_RO_DB_LOGIN, "qm_reporting_ro", true, false, false, false],
        ].sort(),
      );
      const roCfg = (await pgRole(db, names.REPORTING_RO_DB_LOGIN))[0]?.rolconfig ?? [];
      ok(
        p,
        roCfg.includes("default_transaction_read_only=on") &&
          roCfg.includes("statement_timeout=5s"),
        "the read login lacks the read-only default or the timeout",
      );
      // connect as the logins with passwords this check holds (a third run rotates them again)
      const wp = pw("worker2");
      const rp = pw("reader2");
      const third = run({
        ...base,
        ...names,
        REPORTING_DB_PASSWORD: wp,
        REPORTING_RO_DB_PASSWORD: rp,
      });
      ok(p, third.status === 0, "the third run failed");
      const { createDbClient } = await import("@qmentisai/db");
      const as = (login, password) => {
        const u = new URL(adminUrl);
        u.username = login;
        u.password = password;
        return createDbClient({ datasourceUrl: u.toString() });
      };
      const ro = as(names.REPORTING_RO_DB_LOGIN, rp);
      const rw = as(names.REPORTING_DB_LOGIN, wp);
      try {
        const { pa } = await chains(c);
        const readView = await attempt(() =>
          ro.$queryRawUnsafe("SELECT count(*)::int AS n FROM report_findings_v"),
        );
        mustAccept(p, "the read login selects a view", readView);
        mustReject(
          p,
          "the read login reads evidence",
          await attempt(() => ro.$queryRawUnsafe("SELECT * FROM finding_evidence LIMIT 1")),
          "permission denied",
        );
        mustReject(
          p,
          "the read login reads findings",
          await attempt(() => ro.$queryRawUnsafe("SELECT * FROM findings LIMIT 1")),
          "permission denied",
        );
        mustReject(
          p,
          "the read login writes a report table",
          await attempt(() =>
            ro.$executeRawUnsafe(
              `INSERT INTO report_exports (id, tenant_id, template, format, requested_by_user_id) VALUES ('${randomUUID()}', '${pa.tenantId}', 'x', 'csv', '${randomUUID()}')`,
            ),
          ),
        );
        const show = await ro.$queryRawUnsafe("SHOW default_transaction_read_only");
        same(
          p,
          "the read login is read-only by default",
          show[0].default_transaction_read_only,
          "on",
        );
        const slow = await attempt(() => ro.$queryRawUnsafe("SELECT pg_sleep(7)"));
        mustReject(p, "a 7 second statement on the read login", slow, "statement timeout");
        const exportId = randomUUID();
        mustAccept(
          p,
          "the worker login inserts a report row",
          await attempt(() =>
            rw.$executeRawUnsafe(
              `INSERT INTO report_exports (id, tenant_id, template, format, requested_by_user_id) VALUES ('${exportId}', '${pa.tenantId}', 'x', 'csv', '${randomUUID()}')`,
            ),
          ),
        );
        mustAccept(
          p,
          "the worker login updates it",
          await attempt(() =>
            rw.$executeRawUnsafe(
              `UPDATE report_exports SET status = 'failed', error_code = 'internal' WHERE id = '${exportId}'`,
            ),
          ),
        );
        mustReject(
          p,
          "the worker login deletes it",
          await attempt(() =>
            rw.$executeRawUnsafe(`DELETE FROM report_exports WHERE id = '${exportId}'`),
          ),
          "permission denied",
        );
        mustReject(
          p,
          "the worker login updates a finding",
          await attempt(() => rw.$executeRawUnsafe("UPDATE findings SET severity = 'low'")),
          "permission denied",
        );
        mustReject(
          p,
          "the worker login reads tenant_llm_settings",
          await attempt(() => rw.$queryRawUnsafe("SELECT * FROM tenant_llm_settings LIMIT 1")),
          "permission denied",
        );
        await db.$executeRawUnsafe(`DELETE FROM report_exports WHERE id = '${exportId}'`);
      } finally {
        await ro.$disconnect();
        await rw.$disconnect();
        await db
          .$executeRawUnsafe(`REVOKE qm_reporting FROM ${names.REPORTING_DB_LOGIN}`)
          .catch(() => {});
        await db
          .$executeRawUnsafe(`REVOKE qm_reporting_ro FROM ${names.REPORTING_RO_DB_LOGIN}`)
          .catch(() => {});
        await db
          .$executeRawUnsafe(`DROP ROLE IF EXISTS ${names.REPORTING_DB_LOGIN}`)
          .catch(() => {});
        await db
          .$executeRawUnsafe(`DROP ROLE IF EXISTS ${names.REPORTING_RO_DB_LOGIN}`)
          .catch(() => {});
      }
      return p;
    },
  },
  {
    id: "RPTA0-10",
    name: "Reporting periods and tenant time zone, pure (SPEC 17 D-5, RPT-006, RPT-020): presets 7, 30 and 90 are N tenant-local days ending TODAY inclusive; a custom period is from..to inclusive, to not after today, at most 400 days (401 is REPORT_PERIOD_TOO_LONG), from after to, a half range, both a preset and a range, an unknown preset and a bad day are REPORT_PERIOD_INVALID; ranges are half-open [from 00:00, to+1 00:00) in the zone; DST is exact: 2026-03-08 in America/New_York is 23 hours and 2026-11-01 is 25 hours, Europe/London 2026-03-29 is 23 hours and 2026-10-25 is 25, Australia/Lord_Howe 2026-10-04 is 23.5 hours, an ordinary day and UTC are 24; the instant one millisecond before a local midnight belongs to the previous day and the midnight itself to the next, also on a DST day and in a zone that skips midnight (America/Havana, the day starts at 01:00); listLocalDays over the spring-forward and fall-back weeks lists every local day exactly once; the preset of the same instant differs by zone near midnight; dayCloseInstant is the last millisecond of the local day",
    async run() {
      const p = [];
      const range = (day, zone) => dayRange(day, zone);
      same(p, "NY spring forward hours", range("2026-03-08", "America/New_York").hours, 23);
      same(p, "NY fall back hours", range("2026-11-01", "America/New_York").hours, 25);
      same(p, "NY ordinary day hours", range("2026-06-15", "America/New_York").hours, 24);
      same(p, "London spring forward hours", range("2026-03-29", "Europe/London").hours, 23);
      same(p, "London fall back hours", range("2026-10-25", "Europe/London").hours, 25);
      same(p, "Lord Howe DST start hours", range("2026-10-04", "Australia/Lord_Howe").hours, 23.5);
      same(p, "UTC hours", range("2026-03-08", "UTC").hours, 24);
      same(
        p,
        "NY spring forward start",
        range("2026-03-08", "America/New_York").start.toISOString(),
        "2026-03-08T05:00:00.000Z",
      );
      same(
        p,
        "NY fall back start",
        range("2026-11-01", "America/New_York").start.toISOString(),
        "2026-11-01T04:00:00.000Z",
      );
      same(
        p,
        "NY day after fall back starts 25 hours later",
        range("2026-11-02", "America/New_York").start.toISOString(),
        "2026-11-02T05:00:00.000Z",
      );
      same(
        p,
        "Kolkata start",
        range("2026-06-01", "Asia/Kolkata").start.toISOString(),
        "2026-05-31T18:30:00.000Z",
      );
      // the boundary: 1 ms before local midnight is the previous day, the midnight is the next, on and off DST days
      for (const [day, zone] of [
        ["2026-03-08", "America/New_York"],
        ["2026-11-01", "America/New_York"],
        ["2026-03-29", "Europe/London"],
        ["2026-10-25", "Europe/London"],
        ["2026-06-15", "Asia/Kolkata"],
        ["2026-03-08", "America/Havana"],
        ["2026-10-04", "Australia/Lord_Howe"],
      ]) {
        const start = dayStartInstant(day, zone);
        same(p, `${zone} ${day} first instant belongs to the day`, localDayOf(start, zone), day);
        same(
          p,
          `${zone} ${day} 1 ms earlier belongs to the day before`,
          localDayOf(new Date(start.getTime() - 1), zone),
          addDays(day, -1),
        );
        same(
          p,
          `${zone} ${day} close instant`,
          [
            localDayOf(dayCloseInstant(day, zone), zone),
            localDayOf(new Date(dayCloseInstant(day, zone).getTime() + 1), zone),
          ],
          [day, addDays(day, 1)],
        );
      }
      const havana = dayStartInstant("2026-03-08", "America/Havana");
      const wall = new Intl.DateTimeFormat("en-GB", {
        timeZone: "America/Havana",
        hour: "2-digit",
        minute: "2-digit",
        hourCycle: "h23",
      }).format(havana);
      ok(
        p,
        wall === "01:00" || wall === "00:00",
        `a zone that skips midnight starts its day at ${wall}`,
      );
      // the days of a DST week
      same(
        p,
        "days across spring forward",
        listLocalDays(
          new Date("2026-03-07T05:00:00Z"),
          new Date("2026-03-10T04:00:00Z"),
          "America/New_York",
        ),
        ["2026-03-07", "2026-03-08", "2026-03-09"],
      );
      same(
        p,
        "days across fall back",
        listLocalDays(
          new Date("2026-10-31T04:00:00Z"),
          new Date("2026-11-03T05:00:00Z"),
          "America/New_York",
        ),
        ["2026-10-31", "2026-11-01", "2026-11-02"],
      );
      same(
        p,
        "an empty range lists nothing",
        listLocalDays(new Date("2026-03-07T05:00:00Z"), new Date("2026-03-07T05:00:00Z"), "UTC"),
        [],
      );
      same(p, "listDays inclusive", listDays("2026-02-27", "2026-03-02"), [
        "2026-02-27",
        "2026-02-28",
        "2026-03-01",
        "2026-03-02",
      ]);
      same(p, "leap day", listDays("2028-02-28", "2028-03-01"), [
        "2028-02-28",
        "2028-02-29",
        "2028-03-01",
      ]);
      same(p, "addDays across a year", addDays("2026-12-31", 1), "2027-01-01");
      // presets
      const now = new Date("2026-11-26T10:00:00Z");
      for (const n of [7, 30, 90]) {
        const r = resolvePeriod({ period: n }, { now, timeZone: "UTC" });
        same(
          p,
          `preset ${n}`,
          [r.dayCount, r.to, r.preset, r.endExclusive.toISOString()],
          [n, "2026-11-26", n, "2026-11-27T00:00:00.000Z"],
        );
        same(p, `preset ${n} from`, r.from, addDays("2026-11-26", -(n - 1)));
      }
      same(
        p,
        "preset from a string",
        resolvePeriod({ period: "30" }, { now, timeZone: "UTC" }).dayCount,
        30,
      );
      same(p, "the default preset", resolvePeriod({}, { now, timeZone: "UTC" }).dayCount, 30);
      // the same instant is a different tenant-local day in two zones: 2026-11-26T23:30Z is already the 27th in Kolkata and still the 26th in New York
      const edge = new Date("2026-11-26T23:30:00Z");
      same(
        p,
        "today in Kolkata",
        resolvePeriod({ period: 7 }, { now: edge, timeZone: "Asia/Kolkata" }).to,
        "2026-11-27",
      );
      same(
        p,
        "today in New York",
        resolvePeriod({ period: 7 }, { now: edge, timeZone: "America/New_York" }).to,
        "2026-11-26",
      );
      const ny = resolvePeriod({ period: 30 }, { now: edge, timeZone: "America/New_York" });
      same(
        p,
        "the New York range is half open on local midnights",
        [ny.start.toISOString(), ny.endExclusive.toISOString()],
        ["2026-10-28T04:00:00.000Z", "2026-11-27T05:00:00.000Z"],
      );
      // custom
      const custom = resolvePeriod(
        { from: "2026-11-01", to: "2026-11-26" },
        { now, timeZone: "UTC" },
      );
      same(p, "custom", [custom.dayCount, custom.preset], [26, null]);
      const longest = resolvePeriod(
        { from: addDays("2026-11-26", -399), to: "2026-11-26" },
        { now, timeZone: "UTC" },
      );
      same(p, "400 days accepted", longest.dayCount, 400);
      const code = (req, zone = "UTC") => {
        try {
          resolvePeriod(req, { now, timeZone: zone });
          return "accepted";
        } catch (error) {
          return error instanceof ReportPeriodError ? error.code : `other:${error.message}`;
        }
      };
      same(
        p,
        "401 days",
        code({ from: addDays("2026-11-26", -400), to: "2026-11-26" }),
        "REPORT_PERIOD_TOO_LONG",
      );
      same(
        p,
        "from after to",
        code({ from: "2026-11-20", to: "2026-11-19" }),
        "REPORT_PERIOD_INVALID",
      );
      same(
        p,
        "to in the future",
        code({ from: "2026-11-20", to: "2026-11-28" }),
        "REPORT_PERIOD_INVALID",
      );
      same(p, "only from", code({ from: "2026-11-20" }), "REPORT_PERIOD_INVALID");
      same(
        p,
        "preset and range",
        code({ period: 7, from: "2026-11-20", to: "2026-11-21" }),
        "REPORT_PERIOD_INVALID",
      );
      same(p, "unknown preset", code({ period: 14 }), "REPORT_PERIOD_INVALID");
      same(p, "a bad day", code({ from: "2026-02-30", to: "2026-03-01" }), "REPORT_PERIOD_INVALID");
      same(p, "a bad zone", code({ period: 7 }, "Mars/Base"), "REPORT_PERIOD_INVALID");
      same(
        p,
        "listDays above 400",
        (() => {
          try {
            listDays("2025-01-01", "2026-11-26");
            return "accepted";
          } catch (e) {
            return e.code;
          }
        })(),
        "REPORT_PERIOD_TOO_LONG",
      );
      ok(
        p,
        isDayString("2028-02-29") &&
          !isDayString("2026-02-29") &&
          !isDayString("2026-13-01") &&
          !isDayString("26-01-01") &&
          !isDayString(20260101),
        "isDayString is wrong",
      );
      return p;
    },
  },
  {
    id: "RPTA0-11",
    name: "Reporting csvSafeCell (SPEC 12 item 3, RPT-S06 vectors): a text cell whose first character, after any leading white space, is =, +, - or @ (and one that starts with a tab or a carriage return) is prefixed with a single quote and quoted, with every spelling of the classic payloads (=cmd|..., +SUM, -2+3, @SUM, =HYPERLINK, a leading space, a leading no-break space, a leading zero-width space); the SAME text as a finite NUMBER is written as a number (-5 stays -5); commas, double quotes, line feeds and carriage returns are quoted and the quotes doubled; NUL and other control characters are removed; null and undefined are empty; booleans and dates are written plainly; a record written by csvRow ends with CRLF and reads back, by an independent RFC 4180 parser, to the same cells (with the apostrophe on the neutralised ones); a hostile title cannot add a cell or a record",
    async run() {
      const p = [];
      const vectors = [
        ["=1+1", `"'=1+1"`],
        ["+SUM(A1:A9)", `"'+SUM(A1:A9)"`],
        ["-2+3", `"'-2+3"`],
        ["@SUM(A1)", `"'@SUM(A1)"`],
        ["=cmd|' /C calc'!A0", `"'=cmd|' /C calc'!A0"`],
        ['=HYPERLINK("http://evil.example","x")', `"'=HYPERLINK(""http://evil.example"",""x"")"`],
        ["\t=1", `"'\t=1"`],
        ["\r=1", `"'\r=1"`],
        [" =1+1", `"' =1+1"`],
        ["\u00A0=1+1", `"'\u00A0=1+1"`],
        ["\u200B=1+1", `"'\u200B=1+1"`],
        ["\uFEFF@x", `"'\uFEFF@x"`],
        ["-", `"'-"`],
        ["hello", "hello"],
        ["a-b", "a-b"],
        ["x=1", "x=1"],
        ["Use of eval", "Use of eval"],
        ["a,b", `"a,b"`],
        ['say "hi"', `"say ""hi"""`],
        ["line1\nline2", `"line1\nline2"`],
        ["a\r\nb", `"a\r\nb"`],
        [" padded ", `" padded "`],
        ["nul\u0000byte", "nulbyte"],
        ["bell\u0007x", "bellx"],
        ["", ""],
        [null, ""],
        [undefined, ""],
        [5, "5"],
        [-5, "-5"],
        [0, "0"],
        [1.5, "1.5"],
        [Number.NaN, ""],
        [Number.POSITIVE_INFINITY, ""],
        [true, "true"],
        [false, "false"],
        [12n, "12"],
        ["-5", `"'-5"`],
        [new Date("2026-11-26T10:00:00Z"), "2026-11-26T10:00:00.000Z"],
        [new Date(Number.NaN), ""],
        ["日本語", "日本語"],
      ];
      for (const [input, want] of vectors)
        same(
          p,
          `csvSafeCell(${String(typeof input === "string" ? JSON.stringify(input) : input).slice(0, 40)})`,
          csvSafeCell(input),
          want,
        );
      const hostile = ["=1+1", 'a","b', "x\ny", "=A1,=B1", "@evil\r\n=more", "plain", "-1,-2"];
      const row = csvRow(hostile);
      ok(p, row.endsWith(CSV_EOL) && CSV_EOL === "\r\n", "the record does not end with CRLF");
      const back = parseCsvRecord(row.slice(0, -2));
      same(p, "the record reads back to one cell per input", back.length, hostile.length);
      for (let i = 0; i < hostile.length; i += 1) {
        const dangerous = /^[\s]*[=+\-@]/.test(hostile[i]);
        same(p, `cell ${i} reads back`, back[i], dangerous ? `'${hostile[i]}` : hostile[i]);
      }
      ok(
        p,
        !back.some((cell) => /^[=+\-@]/.test(cell)),
        "a cell that starts with a formula character survives",
      );
      same(p, "the BOM is U+FEFF", CSV_BOM, "\uFEFF");
      same(p, "a record of numbers", csvRow([1, -2, 3.5]), "1,-2,3.5\r\n");
      return p;
    },
  },
  {
    id: "RPTA0-12",
    name: "Reporting lifecycle groups (SPEC 5 rule 3): the seven groups partition ALL 12 finding statuses exactly once (no status missing, none twice), written out independently here; the open groups are exactly OPEN_FINDING_STATUSES; backlog plus work in progress equals the open statuses and the two do not overlap; the status-to-group map is total; the flow classification (fixed, closed without a fix, reopened) is disjoint, covers verified_fixed, false_positive, suppressed, accepted_risk and reopened, and never mentions an open status other than reopened; the group ids are unique and the module imports the open set instead of redefining it",
    async run() {
      const p = [];
      const want = {
        needs_triage: ["new", "reopened"],
        in_review: ["in_review", "awaiting_approval"],
        confirmed_in_remediation: ["approved", "assigned", "in_remediation"],
        awaiting_verification: ["fixed_pending_verification"],
        accepted_or_suppressed: ["accepted_risk", "suppressed"],
        false_positive: ["false_positive"],
        fixed: ["verified_fixed"],
      };
      same(
        p,
        "group ids in order",
        LIFECYCLE_GROUPS.map((g) => g.id),
        Object.keys(want),
      );
      for (const g of LIFECYCLE_GROUPS)
        same(p, `group ${g.id}`, sorted(g.statuses), sorted(want[g.id]));
      const flat = LIFECYCLE_GROUPS.flatMap((g) => [...g.statuses]);
      same(p, "12 statuses grouped", flat.length, 12);
      same(p, "each status exactly once", sorted(flat), sorted(FINDING_STATUSES));
      ok(p, new Set(flat).size === 12, "a status is in two groups");
      same(
        p,
        "the open groups are the open statuses",
        sorted(LIFECYCLE_GROUPS.filter((g) => g.open).flatMap((g) => [...g.statuses])),
        sorted(OPEN_FINDING_STATUSES),
      );
      same(
        p,
        "the first four groups are open",
        LIFECYCLE_GROUPS.map((g) => g.open),
        [true, true, true, true, false, false, false],
      );
      same(
        p,
        "backlog plus work in progress is the open set",
        sorted([...BACKLOG_STATUSES, ...WORK_IN_PROGRESS_STATUSES]),
        sorted(OPEN_FINDING_STATUSES),
      );
      ok(
        p,
        BACKLOG_STATUSES.every((s) => !WORK_IN_PROGRESS_STATUSES.includes(s)),
        "backlog and work in progress overlap",
      );
      same(
        p,
        "backlog",
        sorted(BACKLOG_STATUSES),
        sorted(["new", "reopened", "in_review", "awaiting_approval", "approved"]),
      );
      same(
        p,
        "work in progress",
        sorted(WORK_IN_PROGRESS_STATUSES),
        sorted(["assigned", "in_remediation", "fixed_pending_verification"]),
      );
      for (const s of FINDING_STATUSES)
        ok(p, typeof LIFECYCLE_GROUP_OF_STATUS[s] === "string", `no group for ${s}`);
      same(p, "the group of verified_fixed", LIFECYCLE_GROUP_OF_STATUS.verified_fixed, "fixed");
      same(
        p,
        "the group of approved",
        LIFECYCLE_GROUP_OF_STATUS.approved,
        "confirmed_in_remediation",
      );
      ok(
        p,
        Object.isFrozen(LIFECYCLE_GROUPS) &&
          LIFECYCLE_GROUPS.every((g) => Object.isFrozen(g) && Object.isFrozen(g.statuses)),
        "the groups are not frozen",
      );
      same(p, "fixed flow", [...FLOW_FIXED_TO_STATUSES], ["verified_fixed"]);
      same(
        p,
        "closed without a fix flow",
        sorted(FLOW_CLOSED_OTHER_TO_STATUSES),
        sorted(["false_positive", "suppressed", "accepted_risk"]),
      );
      same(p, "reopened flow", [...FLOW_REOPENED_TO_STATUSES], ["reopened"]);
      const flow = [
        ...FLOW_FIXED_TO_STATUSES,
        ...FLOW_CLOSED_OTHER_TO_STATUSES,
        ...FLOW_REOPENED_TO_STATUSES,
      ];
      ok(p, new Set(flow).size === flow.length, "the flow classes overlap");
      ok(
        p,
        flow.every((s) => FINDING_STATUSES.includes(s)),
        "the flow classes name an unknown status",
      );
      return p;
    },
  },
  {
    id: "RPTA0-13",
    name: "Reporting risk formula (SPEC 6.6 B-4, owner ruling O-3): risk points are 10 x critical + 5 x high + 2 x medium + 1 x low over OPEN findings (info 0) plus 3 x breached critical or high, with exact values for hand-built cases, no contribution from negative, fractional-below-one, NaN, Infinity-free or missing counts, the weights frozen and equal to the ruled values; the top-risk comparator orders by score, then the OLDER oldest-open-critical, then name, is a total order on the cases below and sorts a repository with no critical after one that has",
    async run() {
      const p = [];
      same(
        p,
        "weights",
        { ...RISK_WEIGHTS },
        { critical: 10, high: 5, medium: 2, low: 1, info: 0 },
      );
      ok(p, Object.isFrozen(RISK_WEIGHTS), "the weights are not frozen");
      const cases = [
        [{}, 0],
        [{ critical: 1 }, 10],
        [{ high: 1 }, 5],
        [{ medium: 1 }, 2],
        [{ low: 1 }, 1],
        [{ info: 100 }, 0],
        [{ breachedCriticalHigh: 1 }, 3],
        [{ critical: 2, high: 3, medium: 1, low: 4, breachedCriticalHigh: 2 }, 20 + 15 + 2 + 4 + 6],
        [
          { critical: 1, high: 1, medium: 1, low: 1, info: 1, breachedCriticalHigh: 1 },
          10 + 5 + 2 + 1 + 3,
        ],
        [{ critical: 100000 }, 1000000],
        [{ critical: -3, high: Number.NaN, medium: undefined, low: 0.5 }, 0],
        [{ critical: 2.9 }, 20],
        [{ high: "5" }, 0],
        [{ critical: Number.POSITIVE_INFINITY }, 0],
      ];
      for (const [counts, expected] of cases)
        same(p, `score ${JSON.stringify(counts)}`, computeRiskScore(counts), expected);
      const older = new Date("2026-01-01T00:00:00Z");
      const newer = new Date("2026-06-01T00:00:00Z");
      const rows = [
        { name: "zeta", score: 30, oldestOpenCriticalAt: newer },
        { name: "alpha", score: 30, oldestOpenCriticalAt: older },
        { name: "beta", score: 30, oldestOpenCriticalAt: null },
        { name: "gamma", score: 30, oldestOpenCriticalAt: older },
        { name: "top", score: 99, oldestOpenCriticalAt: null },
        { name: "low", score: 1 },
      ];
      same(
        p,
        "the order",
        [...rows].sort(compareTopRisk).map((r) => r.name),
        ["top", "alpha", "gamma", "zeta", "beta", "low"],
      );
      same(
        p,
        "a shuffled input sorts the same",
        [...rows]
          .reverse()
          .sort(compareTopRisk)
          .map((r) => r.name),
        ["top", "alpha", "gamma", "zeta", "beta", "low"],
      );
      same(p, "equal rows compare equal", compareTopRisk(rows[0], { ...rows[0] }), 0);
      same(
        p,
        "antisymmetric",
        Math.sign(compareTopRisk(rows[0], rows[1])),
        -Math.sign(compareTopRisk(rows[1], rows[0])),
      );
      return p;
    },
  },
  {
    id: "RPTA0-14",
    name: "Reporting messages, queue and error codes (SPEC 9, 10, ADR-011): `reporting.rollup.requested` v1 and `reporting.export.requested` v1 are registered job messages with TENANT scope (a message without a tenant id is refused, a platform-level one too), their payloads are .strict() (an unknown key such as a snippet, a path or a second tenant is refused), a valid sample of each mode is accepted, the rollup payload refuses a close without a day, a backfill without a range, a range that is reversed, over 800 days or on a day that does not exist, a day on a backfill and a range on an incremental, a non-uuid tenant or report id; the `reporting` queue is in the queue catalogue and the broker topology declares its main queue, its dead-letter queue and the retry tiers (fake channel); the eight REPORT_* codes exist with their code as value and the HTTP statuses 400, 400, 409, 422, 429, 409, 410 and 400",
    async run() {
      const p = [];
      const id = () => randomUUID();
      const tenantId = id();
      same(p, "queue name", QUEUE_NAMES.REPORTING, "reporting");
      same(
        p,
        "message type names",
        { ...REPORTING_MESSAGE_TYPES },
        {
          ROLLUP_REQUESTED: "reporting.rollup.requested",
          EXPORT_REQUESTED: "reporting.export.requested",
        },
      );
      const samples = {
        "reporting.rollup.requested": [
          { tenantId, mode: "incremental" },
          { tenantId, mode: "incremental", day: "2026-11-26", reason: "scheduled" },
          { tenantId, mode: "close", day: "2026-11-25" },
          {
            tenantId,
            mode: "backfill",
            from: "2025-01-01",
            to: "2026-11-25",
            reason: "first_enablement",
          },
          {
            tenantId,
            mode: "backfill",
            from: "2026-11-01",
            to: "2026-11-01",
            reason: "timezone_changed",
          },
        ],
        "reporting.export.requested": [{ reportId: id() }],
      };
      for (const [type, payloads] of Object.entries(samples)) {
        const entry = MESSAGE_TYPES[type];
        if (!entry) {
          p.push(`${type}: not registered`);
          continue;
        }
        same(
          p,
          `${type} kind, scope, version`,
          [entry.kind, entry.scope, entry.schemaVersion],
          ["job", "tenant", 1],
        );
        const make = (payload, over = {}) =>
          createJobEnvelope({
            type,
            schemaVersion: 1,
            tenantId,
            payload,
            initiator: { type: "system", id: "reporting-suite" },
            ...over,
          });
        for (const payload of payloads) {
          try {
            parseMessage(make(payload));
          } catch (error) {
            p.push(
              `${type}: a valid sample is refused (${JSON.stringify(payload)}: ${String(error.message).slice(0, 80)})`,
            );
          }
          for (const extra of [
            { snippet: "x" },
            { path: "a/b" },
            { tenantId2: id() },
            { workspaceId: id() },
            { __proto__x: 1 },
          ]) {
            const refused = await attempt(async () => parseMessage(make({ ...payload, ...extra })));
            mustReject(p, `${type} with extra key ${Object.keys(extra)[0]}`, refused);
          }
        }
        mustReject(
          p,
          `${type} without a tenant id`,
          await attempt(async () =>
            parseMessage(
              createJobEnvelope({
                type,
                schemaVersion: 1,
                payload: payloads[0],
                initiator: { type: "system", id: "x" },
              }),
            ),
          ),
          "needs a tenantId",
        );
      }
      const bad = (payload) =>
        attempt(async () =>
          parseMessage(
            createJobEnvelope({
              type: "reporting.rollup.requested",
              schemaVersion: 1,
              tenantId,
              payload,
              initiator: { type: "system", id: "x" },
            }),
          ),
        );
      for (const [label, payload] of Object.entries({
        "close without a day": { tenantId, mode: "close" },
        "backfill without a range": { tenantId, mode: "backfill" },
        "backfill with only from": { tenantId, mode: "backfill", from: "2026-01-01" },
        "reversed range": { tenantId, mode: "backfill", from: "2026-02-01", to: "2026-01-01" },
        "range over 800 days": { tenantId, mode: "backfill", from: "2024-01-01", to: "2026-11-25" },
        "a day that does not exist": { tenantId, mode: "close", day: "2026-02-30" },
        "a day in the wrong format": { tenantId, mode: "close", day: "26-11-2026" },
        "a day on a backfill": {
          tenantId,
          mode: "backfill",
          from: "2026-01-01",
          to: "2026-01-02",
          day: "2026-01-01",
        },
        "a range on an incremental": {
          tenantId,
          mode: "incremental",
          from: "2026-01-01",
          to: "2026-01-02",
        },
        "an unknown mode": { tenantId, mode: "nightly" },
        "a non-uuid tenant": { tenantId: "tenant-1", mode: "incremental" },
        "no tenant in the payload": { mode: "incremental" },
        "an unknown reason": { tenantId, mode: "incremental", reason: "because" },
      }))
        mustReject(p, `rollup payload: ${label}`, await bad(payload));
      mustReject(
        p,
        "export payload with a non-uuid id",
        await attempt(async () =>
          parseMessage(
            createJobEnvelope({
              type: "reporting.export.requested",
              schemaVersion: 1,
              tenantId,
              payload: { reportId: "r1" },
              initiator: { type: "system", id: "x" },
            }),
          ),
        ),
      );
      mustReject(
        p,
        "export payload with the tenant in the body",
        await attempt(async () =>
          parseMessage(
            createJobEnvelope({
              type: "reporting.export.requested",
              schemaVersion: 1,
              tenantId,
              payload: { reportId: id(), tenantId },
              initiator: { type: "system", id: "x" },
            }),
          ),
        ),
      );
      // the topology declares the queue (a recording fake channel)
      ok(
        p,
        BROKER_TOPOLOGY.queues.some((q) => q.queue === "reporting"),
        "the broker topology has no reporting queue",
      );
      const asserted = [];
      const channel = {
        assertExchange: async () => {},
        assertQueue: async (name) => {
          asserted.push(name);
        },
        bindQueue: async () => {},
      };
      await declareBrokerTopology(channel, {
        retryPolicy: { maxAttempts: 4, baseDelayMs: 1000, maxDelayMs: 60000 },
      });
      for (const name of [
        "qmentis.reporting",
        "qmentis.reporting.dlq",
        "qmentis.reporting.retry.1",
        "qmentis.reporting.retry.2",
        "qmentis.reporting.retry.3",
      ])
        ok(p, asserted.includes(name), `the topology does not declare ${name}`);
      // error codes
      const codes = [
        "REPORT_PERIOD_INVALID",
        "REPORT_PERIOD_TOO_LONG",
        "REPORT_AS_OF_UNAVAILABLE",
        "REPORT_TOO_LARGE",
        "REPORT_LIMIT_REACHED",
        "REPORT_NOT_READY",
        "REPORT_EXPIRED",
        "REPORT_TEMPLATE_UNKNOWN",
      ];
      same(
        p,
        "REPORT_* codes",
        sorted(Object.keys(ERROR_CODES).filter((k) => k.startsWith("REPORT_"))),
        sorted(codes),
      );
      for (const k of codes) same(p, `${k} value`, ERROR_CODES[k], k);
      same(
        p,
        "HTTP statuses",
        codes.map((k) => ERROR_HTTP_STATUS[ERROR_CODES[k]]),
        [400, 400, 409, 422, 429, 409, 410, 400],
      );
      return p;
    },
  },
  {
    id: "RPTA0-15",
    name: "Reporting shared contracts (SPEC 6, 7.3, 9): the 43 metrics have unique ids P-1..10, T-1..5, R-1..8, S-1..8, Q-1..6, B-1..6, a mode of live, rollup or hybrid, an EXISTING catalogue permission key (no new key: every key of the route and section maps is a catalogue key) and a route that has a permission entry equal to the metric's; trend, breakdown and top-risk metrics are served by the routes the SPEC names; every query schema is .strict() and refuses tenantId; the workspace reads REQUIRE workspaceId and the overview REFUSES workspaceId; a preset together with a range, an unknown series, a limit over the cap and an unknown breakdown are refused; the create-report body refuses an unknown template, the deferred audit evidence pack, a format the template lacks, a missing or unexpected period or as-of day and a workspace-less request for a workspace-only template; DTO schemas are strict and no DTO schema has a key of the forbidden list (tenantId, objectKey, e-mail, evidence, snippet, rationale, comment, reasoning, justification, fingerprint, ...); the templates only list columns that exist in the views they read (information_schema), carry the exclusion notice and the SPEC formats; the limits are the ruled values (250000 rows, 3 concurrent, 20 per hour, 40 pages, 30 days, 24 hours, 25 and 13 months)",
    async run(c) {
      const p = [];
      const { db } = c;
      same(p, "metric count", METRICS.length, 43);
      const ids = METRICS.map((m) => m.id);
      ok(p, new Set(ids).size === ids.length, "duplicate metric ids");
      const range = (letter, n) => Array.from({ length: n }, (_, i) => `${letter}-${i + 1}`);
      same(p, "metric ids", ids, [
        ...range("P", 10),
        ...range("T", 5),
        ...range("R", 8),
        ...range("S", 8),
        ...range("Q", 6),
        ...range("B", 6),
      ]);
      for (const m of METRICS) {
        ok(p, ["live", "rollup", "hybrid"].includes(m.mode), `${m.id} mode ${m.mode}`);
        ok(p, isPermissionKey(m.permission), `${m.id} names an unknown permission ${m.permission}`);
        ok(
          p,
          REPORTING_PERMISSION_BY_ROUTE[m.route] === m.permission || m.id === "P-10",
          `${m.id}: the route ${m.route} needs ${REPORTING_PERMISSION_BY_ROUTE[m.route]}, the metric says ${m.permission}`,
        );
        ok(p, METRIC_BY_ID[m.id] === m, `${m.id} is not indexed`);
      }
      const mode = (id) => METRIC_BY_ID[id].mode;
      same(
        p,
        "trend metrics are rollups",
        ["T-1", "T-2", "T-3", "T-4", "T-5"].map(mode),
        Array(5).fill("rollup"),
      );
      same(p, "posture metrics are live", range("P", 10).map(mode), Array(10).fill("live"));
      same(
        p,
        "R-1 and R-3 are live (percentiles cannot be merged)",
        [mode("R-1"), mode("R-3")],
        ["live", "live"],
      );
      same(
        p,
        "keys",
        [
          METRIC_BY_ID["P-1"].permission,
          METRIC_BY_ID["P-10"].permission,
          METRIC_BY_ID["Q-1"].permission,
          METRIC_BY_ID["B-1"].permission,
          METRIC_BY_ID["B-6"].permission,
          METRIC_BY_ID["S-8"].permission,
        ],
        [
          "finding.view",
          "execution.view",
          "security_review.view",
          "dashboard.view",
          "finding.assign",
          "execution.view",
        ],
      );
      ok(
        p,
        REPORTING_PERMISSION_KEYS.every(isPermissionKey),
        "a key of the permission maps is not in the catalogue",
      );
      same(
        p,
        "route permission map",
        REPORTING_PERMISSION_BY_ROUTE["POST /reporting/reports"],
        "report.export",
      );
      same(p, "the route count of SPEC 9", Object.keys(REPORTING_PERMISSION_BY_ROUTE).length, 18);
      same(
        p,
        "every route has schemas",
        sorted(Object.keys(REPORTING_ROUTE_SCHEMAS)),
        sorted(Object.keys(REPORTING_PERMISSION_BY_ROUTE)),
      );
      const ws = randomUUID();
      const refuse = (label, schema, input) =>
        ok(p, !schema.safeParse(input).success, `${label} was accepted`);
      const accept = (label, schema, input) =>
        ok(
          p,
          schema.safeParse(input).success,
          `${label} was refused: ${JSON.stringify(schema.safeParse(input).error?.issues?.[0]?.message)}`,
        );
      accept("workspace query", workspaceQuerySchema, { workspaceId: ws });
      refuse("workspace query without a workspace", workspaceQuerySchema, {});
      refuse("workspace query with a tenant", workspaceQuerySchema, {
        workspaceId: ws,
        tenantId: randomUUID(),
      });
      refuse("workspace query with a non-uuid", workspaceQuerySchema, { workspaceId: "ws-1" });
      accept("period 30", workspacePeriodQuerySchema, { workspaceId: ws, period: "30" });
      accept("custom range", workspacePeriodQuerySchema, {
        workspaceId: ws,
        from: "2026-11-01",
        to: "2026-11-26",
      });
      refuse("preset 14", workspacePeriodQuerySchema, { workspaceId: ws, period: "14" });
      refuse("preset and range", workspacePeriodQuerySchema, {
        workspaceId: ws,
        period: "7",
        from: "2026-11-01",
        to: "2026-11-02",
      });
      refuse("only from", workspacePeriodQuerySchema, { workspaceId: ws, from: "2026-11-01" });
      refuse("reversed range", workspacePeriodQuerySchema, {
        workspaceId: ws,
        from: "2026-11-05",
        to: "2026-11-02",
      });
      refuse("a tenant on a period read", workspacePeriodQuerySchema, {
        workspaceId: ws,
        period: "7",
        tenantId: randomUUID(),
      });
      accept("trends default series", trendsQuerySchema, { workspaceId: ws, period: "90" });
      refuse("an unknown series", trendsQuerySchema, {
        workspaceId: ws,
        period: "7",
        series: "flow,secrets",
      });
      refuse("a repeated series", trendsQuerySchema, {
        workspaceId: ws,
        period: "7",
        series: "flow,flow",
      });
      accept("posture as of a day", postureQuerySchema, { workspaceId: ws, asOf: "2026-11-01" });
      refuse("posture as of a bad day", postureQuerySchema, { workspaceId: ws, asOf: "yesterday" });
      accept("top risk", topRiskQuerySchema, { workspaceId: ws, limit: "10" });
      refuse("top risk over the cap", topRiskQuerySchema, { workspaceId: ws, limit: "51" });
      accept("overview", overviewQuerySchema, { period: "30" });
      refuse("overview with a workspace", overviewQuerySchema, { period: "30", workspaceId: ws });
      refuse("overview with a tenant", overviewQuerySchema, {
        period: "30",
        tenantId: randomUUID(),
      });
      same(
        p,
        "breakdown dimensions",
        [...BREAKDOWN_DIMENSIONS],
        ["repository", "pipeline", "scan_type", "rule"],
      );
      const body = (over) => ({
        template: "findings_by_pipeline",
        format: "csv",
        workspaceId: ws,
        ...over,
      });
      accept("findings by pipeline csv", createReportBodySchema, body({}));
      accept(
        "executive summary with a period",
        createReportBodySchema,
        body({ template: "executive_summary", format: "pdf", period: "90" }),
      );
      accept(
        "snapshot with an as-of day",
        createReportBodySchema,
        body({ template: "point_in_time_snapshot", format: "pdf", asOfDay: "2026-11-01" }),
      );
      accept(
        "a tenant-wide report",
        createReportBodySchema,
        body({
          workspaceId: undefined,
          template: "executive_summary",
          format: "pdf",
          period: "30",
        }),
      );
      refuse("an unknown template", createReportBodySchema, body({ template: "all_the_data" }));
      refuse(
        "the deferred audit evidence pack",
        createReportBodySchema,
        body({ template: "audit_evidence_pack", format: "pdf", period: "30" }),
      );
      refuse(
        "a pdf of the SBOM inventory",
        createReportBodySchema,
        body({ template: "sbom_inventory", format: "pdf" }),
      );
      refuse(
        "a csv of the executive summary",
        createReportBodySchema,
        body({ template: "executive_summary", format: "csv", period: "30" }),
      );
      refuse("a missing period", createReportBodySchema, body({ template: "sla_compliance" }));
      refuse("a period on a template without one", createReportBodySchema, body({ period: "30" }));
      refuse(
        "a snapshot without its day",
        createReportBodySchema,
        body({ template: "point_in_time_snapshot", format: "csv" }),
      );
      refuse(
        "an as-of day on another template",
        createReportBodySchema,
        body({ asOfDay: "2026-11-01" }),
      );
      refuse("a tenant in the body", createReportBodySchema, body({ tenantId: randomUUID() }));
      refuse("free text in the options", createReportBodySchema, body({ options: { title: "x" } }));
      // DTO strictness and forbidden keys
      refuse("posture DTO with an extra key", postureDtoSchema, { tenantId: randomUUID() });
      const forbidden = new Set(FORBIDDEN_REPORTING_DTO_KEYS);
      for (const [route, schemas] of Object.entries(REPORTING_ROUTE_SCHEMAS)) {
        if (!schemas.data) continue;
        const keys = [...schemaKeys(schemas.data)].filter((k) => forbidden.has(k));
        same(p, `forbidden keys in the DTO of ${route}`, keys, []);
      }
      ok(
        p,
        [
          "tenantId",
          "objectKey",
          "email",
          "snippet",
          "rationale",
          "comment",
          "reasoning",
          "justification",
          "fingerprint",
        ].every((k) => forbidden.has(k)),
        "the forbidden list lost a key",
      );
      // templates
      same(
        p,
        "template ids",
        REPORT_TEMPLATES.map((t) => t.id),
        [
          "executive_summary",
          "findings_by_pipeline",
          "sla_compliance",
          "remediation_performance",
          "sbom_inventory",
          "detection_quality",
          "point_in_time_snapshot",
          "audit_evidence_pack",
        ],
      );
      same(
        p,
        "v1 template ids",
        [...REPORT_TEMPLATE_IDS],
        REPORT_TEMPLATES.filter((t) => t.id !== "audit_evidence_pack").map((t) => t.id),
      );
      ok(
        p,
        REPORT_TEMPLATE_BY_ID.audit_evidence_pack.v1 === false,
        "the audit evidence pack is not deferred",
      );
      same(
        p,
        "formats",
        REPORT_TEMPLATES.map((t) => t.formats.join("+")),
        ["pdf", "csv+pdf", "csv+pdf", "pdf+csv", "csv", "pdf", "csv+pdf", "pdf"],
      );
      for (const t of REPORT_TEMPLATES) {
        ok(
          p,
          t.formats.includes("csv") === t.csvColumns.length > 0,
          `${t.id}: csv columns and the csv format disagree`,
        );
        ok(
          p,
          t.formats.includes("pdf") ===
            (t.pdfSections.length > 0 || t.id === "audit_evidence_pack"),
          `${t.id}: pdf sections and the pdf format disagree`,
        );
        for (const section of t.pdfSections)
          for (const m of section.metrics) ok(p, METRIC_BY_ID[m], `${t.id}: unknown metric ${m}`);
        for (const m of t.metrics) ok(p, METRIC_BY_ID[m], `${t.id}: unknown metric ${m}`);
        for (const view of t.sources)
          ok(p, VIEWS.includes(view), `${t.id}: reads ${view}, which is not a reporting view`);
        const colsOf = (v) => VIEW_COLUMNS[v] ?? [];
        for (const col of t.csvColumns) {
          if (col.source.startsWith("derived:")) continue;
          ok(
            p,
            t.sources.some((v) => colsOf(v).includes(col.source)),
            `${t.id}.${col.key}: ${col.source} is in none of its views`,
          );
          ok(p, !FORBIDDEN_COLUMN.test(col.source), `${t.id}.${col.key} reads a forbidden column`);
        }
        ok(p, Object.isFrozen(t) && Object.isFrozen(t.csvColumns), `${t.id} is not frozen`);
      }
      const assignee = REPORT_TEMPLATE_BY_ID.findings_by_pipeline.csvColumns.find(
        (x) => x.key === "assignee",
      );
      same(
        p,
        "the assignee column",
        [assignee?.source, assignee?.requiresPermission],
        ["assignee_display_name", "finding.assign"],
      );
      ok(p, REPORT_EXCLUDED_FIELDS.length === 7, "the exclusion list changed");
      // the views really have the source columns (information_schema)
      const live =
        await db.$queryRaw`SELECT table_name, column_name FROM information_schema.columns WHERE table_name = ANY(${VIEWS})`;
      for (const t of REPORT_TEMPLATES)
        for (const col of t.csvColumns)
          if (!col.source.startsWith("derived:"))
            ok(
              p,
              live.some((r) => t.sources.includes(r.table_name) && r.column_name === col.source),
              `${t.id}.${col.key}: ${col.source} does not exist in the database views`,
            );
      const L = REPORTING_LIMITS;
      same(
        p,
        "limits",
        [
          L.csvMaxRows,
          L.maxConcurrentExportsPerTenant,
          L.exportRequestsPerUserPerHour,
          L.pdfMaxPages,
          L.fileRetentionDays,
          L.downloadValiditySeconds,
          L.rollupRetentionMonths,
          L.runRetentionMonths,
          L.staleAfterSeconds,
          L.minDecisionsForRate,
          [...L.agingBucketDays],
        ],
        [250000, 3, 20, 40, 30, 86400, 25, 13, 7200, 20, [7, 30, 90]],
      );
      ok(p, Object.isFrozen(L), "the limits are not frozen");
      return p;
    },
  },
  {
    id: "RPTA0-16",
    name: "Reporting frozen surface and flags (SPEC 10, 18): the four repository factories expose EXACTLY the frozen method names written out in this check (rollup 19, read 16, exports 6, export worker 7), frozen, and an implementation that adds a method outside the surface is refused at construction; every method that no part has built rejects with ReportingNotImplementedError (never a silent empty result); the API module `reporting` is registered with its two route files (read for Part B, export for Part C); the worker dispatcher dead-letters a message type without a handler as a non-retryable error and routes one with a handler; the worker entry does nothing while REPORTING_ENABLED is not true; REPORTING_ENABLED is OFF by default in the API and worker configuration, must be exactly true or false, and production with the flag on and no restricted database URL is a configuration error naming the variable (with the URL set it is not); the retention defaults are 25 months and 30 days; pdfkit is a dependency of the workers package only",
    async run() {
      const p = [];
      const surface = {
        rollup: [
          "getTenantSettings",
          "listActiveTenants",
          "listPipelineChains",
          "earliestHistoryAt",
          "startRun",
          "finishRun",
          "findLatestRun",
          "listRuns",
          "computeFindingsStateAsOf",
          "computeFindingsFlow",
          "computeExecutionsDays",
          "computeDecisionsDays",
          "computeSbomDays",
          "upsertFindingsDays",
          "upsertExecutionsDays",
          "upsertDecisionsDays",
          "upsertSbomDays",
          "clearRange",
          "purgeExpired",
        ],
        read: [
          "getTenantSettings",
          "getRollupFreshness",
          "getPosture",
          "getPostureAsOf",
          "getTrends",
          "getRemediation",
          "getSla",
          "getAging",
          "getScanActivity",
          "getCoverage",
          "getSbom",
          "getQuality",
          "getBreakdown",
          "getTopRisk",
          "getWorkload",
          "getOverview",
        ],
        exports: [
          "createExport",
          "countActiveExports",
          "countExportsByUserSince",
          "getExport",
          "listExports",
          "softDeleteExport",
        ],
        worker: [
          "claimExport",
          "getExportForWorker",
          "countExportRows",
          "readExportPage",
          "completeExport",
          "failExport",
          "expireExports",
        ],
      };
      same(
        p,
        "surface sizes",
        Object.values(surface).map((a) => a.length),
        [19, 16, 6, 7],
      );
      const repos = {
        rollup: createReportingRollupRepository({ db: null }),
        read: createReportingReadRepository({ db: null }),
        exports: createReportingExportsRepository({ db: null }),
        worker: createReportingExportWorkerRepository({ db: null }),
      };
      for (const [name, repo] of Object.entries(repos)) {
        same(p, `${name} repository methods`, Object.keys(repo), surface[name]);
        ok(p, Object.isFrozen(repo), `${name} repository is not frozen`);
        for (const method of surface[name]) {
          ok(p, typeof repo[method] === "function", `${name}.${method} is not a function`);
        }
      }
      const extra = (() => {
        try {
          defineRepository("A", ["a"], { a: () => 1, b: () => 2 });
          return "accepted";
        } catch (e) {
          return e.message;
        }
      })();
      ok(
        p,
        /outside the frozen surface: b/.test(extra),
        "a method outside the frozen surface is accepted",
      );
      const stub = defineRepository("Z", ["x"], {});
      const refused = await stub.x().then(
        () => null,
        (e) => e,
      );
      ok(
        p,
        refused instanceof ReportingNotImplementedError && refused.part === "Z",
        "an unbuilt method does not reject with ReportingNotImplementedError",
      );
      const built = defineRepository("Z", ["x"], { x: async () => 7 });
      same(p, "a built method runs", await built.x(), 7);
      // the API module
      ok(
        p,
        reportingModule.name === "reporting" &&
          reportingModule.prefix === "/api/v1" &&
          typeof reportingModule.plugin === "function",
        "the API module is not registered correctly",
      );
      ok(
        p,
        typeof reportingReadRoutes === "function" && typeof reportingExportRoutes === "function",
        "a route registrar is missing",
      );
      // the worker dispatcher
      const logs = [];
      const log = { warn: (...a) => logs.push(a) };
      const empty = createReportingDispatcher({
        "reporting.rollup.requested": null,
        "reporting.export.requested": undefined,
      });
      const dead = await empty({ type: "reporting.rollup.requested" }, { log }).then(
        () => null,
        (e) => e,
      );
      ok(
        p,
        dead?.name === "NonRetryableError" ||
          dead?.retryable === false ||
          /not-built/.test(dead?.message ?? ""),
        `a message type without a handler is not dead-lettered (${dead?.name}: ${dead?.message})`,
      );
      const calls = [];
      const full = createReportingDispatcher({
        "reporting.rollup.requested": async (m) => {
          calls.push(m.type);
        },
        "reporting.export.requested": null,
      });
      await full({ type: "reporting.rollup.requested" }, { log });
      same(p, "a handler is called", calls, ["reporting.rollup.requested"]);
      ok(
        p,
        (await full({ type: "reporting.export.requested" }, { log }).then(
          () => null,
          (e) => e,
        )) !== null,
        "an unbuilt type next to a built one is acknowledged",
      );
      ok(
        p,
        (await full({ type: "something.else" }, { log }).then(
          () => null,
          (e) => e,
        )) !== null,
        "an unknown type is acknowledged",
      );
      // the worker entry is inert while the flag is not true
      const off = await startReportingWorker({ REPORTING_ENABLED: "false" });
      ok(
        p,
        typeof off.stop === "function",
        "the disabled worker entry does not return a stop function",
      );
      await off.stop();
      const unset = await startReportingWorker({});
      await unset.stop();
      // flags: API
      const apiBase = {
        DATABASE_URL: "postgresql://u:p@localhost:5432/qm_test",
        NODE_ENV: "development",
        MOCK_AUTH_ENABLED: "false",
      };
      same(p, "API default", loadConfig(apiBase).reporting.enabled, false);
      same(
        p,
        "API on",
        loadConfig({ ...apiBase, REPORTING_ENABLED: "true" }).reporting.enabled,
        true,
      );
      same(p, "API read url default", loadConfig(apiBase).reporting.readDatabaseUrl, null);
      same(
        p,
        "API export retention default",
        loadConfig(apiBase).reporting.exportRetentionDays,
        30,
      );
      const bad = (() => {
        try {
          loadConfig({ ...apiBase, REPORTING_ENABLED: "yes" });
          return "accepted";
        } catch (e) {
          return e.name;
        }
      })();
      same(p, "API refuses yes", bad, "ConfigError");
      const prod = (extra) => {
        try {
          loadConfig({ ...apiBase, NODE_ENV: "production", REPORTING_ENABLED: "true", ...extra });
          return [];
        } catch (e) {
          return (e.problems ?? []).map((x) => x.variable);
        }
      };
      ok(
        p,
        prod({}).includes("REPORTING_RO_DATABASE_URL"),
        "production without the read URL does not name REPORTING_RO_DATABASE_URL",
      );
      ok(
        p,
        !prod({ REPORTING_RO_DATABASE_URL: "postgresql://ro:x@localhost:5432/qm" }).includes(
          "REPORTING_RO_DATABASE_URL",
        ),
        "production with the read URL still complains about it",
      );
      // flags: worker
      const wk = (extra = {}) =>
        loadWorkerConfig(
          {
            NODE_ENV: "development",
            RABBITMQ_URL: "amqp://localhost",
            DATABASE_URL: "postgresql://u:p@localhost/qm_test",
            ...extra,
          },
          { workerName: "reporting" },
        );
      same(p, "worker default", wk().reporting.enabled, false);
      same(p, "worker on", wk({ REPORTING_ENABLED: "true" }).reporting.enabled, true);
      same(
        p,
        "worker retention defaults",
        [wk().reporting.rollupRetentionMonths, wk().reporting.exportRetentionDays],
        [25, 30],
      );
      same(p, "worker database url default", wk().reporting.databaseUrl, null);
      const wbad = (() => {
        try {
          wk({ REPORTING_ENABLED: "1" });
          return "accepted";
        } catch (e) {
          return e.name;
        }
      })();
      same(p, "worker refuses 1", wbad, "ConfigError");
      const wprod = (extra) => {
        try {
          loadWorkerConfig(
            {
              NODE_ENV: "production",
              RABBITMQ_URL: "amqp://localhost",
              REDIS_URL: "redis://localhost",
              DATABASE_URL: "postgresql://u:p@localhost/qm",
              REPORTING_ENABLED: "true",
              ...extra,
            },
            { workerName: "reporting" },
          );
          return [];
        } catch (e) {
          return (e.problems ?? []).map((x) => x.variable);
        }
      };
      ok(
        p,
        wprod({}).includes("REPORTING_DATABASE_URL"),
        "the worker in production without the URL does not name REPORTING_DATABASE_URL",
      );
      ok(
        p,
        !wprod({ REPORTING_DATABASE_URL: "postgresql://w:x@localhost/qm" }).includes(
          "REPORTING_DATABASE_URL",
        ),
        "the worker in production with the URL still complains about it",
      );
      // the dependency is in the workers package only
      const { readFileSync } = await import("node:fs");
      const pkg = (rel) =>
        JSON.parse(readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8"));
      const workers = pkg("../../../../../workers/package.json");
      same(p, "pdfkit is pinned in the workers package", workers.dependencies.pdfkit, "0.21.0");
      for (const rel of [
        "../../../../package.json",
        "../../../../../../package.json",
        "../../../../../../packages/shared/package.json",
        "../../../../../../packages/db/package.json",
        "../../../../../../packages/contracts/package.json",
        "../../../../../../packages/infra/package.json",
      ])
        ok(p, !JSON.stringify(pkg(rel)).includes("pdfkit"), `pdfkit appears in ${rel}`);
      return p;
    },
  },
];
