/**
 * Provisions the two restricted LOGIN roles of the Reporting module (docs/modules/reporting-dashboards/SPEC.md 12 item 7, ADR-015 item 5; owner
 * ruling of 2026-11-26). The migration `20261126100000_reporting_core` creates the NOLOGIN group roles `qm_reporting` (the rollup and export
 * worker) and `qm_reporting_ro` (the API's read pool) and their grants when its user may create roles; this script creates a missing group
 * role and re-applies the same grants (the development database), then creates a LOGIN role that is a MEMBER of each group, so the worker
 * and the API can connect with them (`REPORTING_DATABASE_URL`, `REPORTING_RO_DATABASE_URL`). Development and production use the same script;
 * production operations may run the equivalent SQL.
 *
 * Needs an ADMIN connection (CREATEROLE): `DATABASE_URL`. The passwords come from `REPORTING_DB_PASSWORD` (worker login) and
 * `REPORTING_RO_DB_PASSWORD` (read login), each at least 16 characters; they are never printed, never put on a command line and never logged.
 * The login names default to `qm_reporting_login` and `qm_reporting_ro_login` (`REPORTING_DB_LOGIN`, `REPORTING_RO_DB_LOGIN`). Role-level
 * settings do not pass from a group to its members, so the login roles get them here: the read login is read-only by default with a 5 second
 * statement timeout. Idempotent: an existing login role gets the new password, the settings and the membership. It prints the connection strings
 * with the password replaced by `<password>` (host, port and database come from DATABASE_URL).
 *
 * Run: REPORTING_DB_PASSWORD=... REPORTING_RO_DB_PASSWORD=... pnpm --filter @qmentisai/db provision:reporting-logins
 */
import { PrismaClient } from "@prisma/client";

const WORKER_GROUP = "qm_reporting";
const READ_GROUP = "qm_reporting_ro";
const VIEWS = [
  "report_findings_v",
  "report_status_events_v",
  "report_decisions_v",
  "report_advisories_v",
  "report_executions_v",
  "report_sbom_latest_v",
  "report_tenant_settings_v",
];
const TABLES = [
  "report_daily_findings",
  "report_daily_executions",
  "report_daily_decisions",
  "report_daily_sbom",
  "report_rollup_runs",
  "report_exports",
];
/** The exact privileges of the two group roles (migration 20261126100000_reporting_core, section 5): nothing else is ever granted. */
const GROUP_GRANTS = [
  ...VIEWS.flatMap((v) => [
    `GRANT SELECT ON "${v}" TO ${WORKER_GROUP}`,
    `GRANT SELECT ON "${v}" TO ${READ_GROUP}`,
  ]),
  ...TABLES.flatMap((t) => [
    `GRANT SELECT, INSERT, UPDATE ON "${t}" TO ${WORKER_GROUP}`,
    `GRANT SELECT ON "${t}" TO ${READ_GROUP}`,
  ]),
  `GRANT EXECUTE ON FUNCTION qm_reporting_clear_range(uuid, date, date) TO ${WORKER_GROUP}`,
  `GRANT EXECUTE ON FUNCTION qm_reporting_purge(date, timestamptz, timestamptz, integer) TO ${WORKER_GROUP}`,
  `ALTER ROLE ${READ_GROUP} SET default_transaction_read_only = on`,
  `ALTER ROLE ${READ_GROUP} SET statement_timeout = '5s'`,
  `ALTER ROLE ${READ_GROUP} SET idle_in_transaction_session_timeout = '10s'`,
];
const LOGIN_NAME = /^[a-z][a-z0-9_]{2,62}$/;
const logins = [
  {
    group: WORKER_GROUP,
    login: process.env.REPORTING_DB_LOGIN ?? "qm_reporting_login",
    passwordVar: "REPORTING_DB_PASSWORD",
    password: process.env.REPORTING_DB_PASSWORD,
    urlVar: "REPORTING_DATABASE_URL",
    settings: [],
  },
  {
    group: READ_GROUP,
    login: process.env.REPORTING_RO_DB_LOGIN ?? "qm_reporting_ro_login",
    passwordVar: "REPORTING_RO_DB_PASSWORD",
    password: process.env.REPORTING_RO_DB_PASSWORD,
    urlVar: "REPORTING_RO_DATABASE_URL",
    settings: [
      "default_transaction_read_only = on",
      "statement_timeout = '5s'",
      "idle_in_transaction_session_timeout = '10s'",
    ],
  },
];
const adminUrl = process.env.DATABASE_URL;

for (const l of logins) {
  if (!LOGIN_NAME.test(l.login)) {
    console.error(`The login name of ${l.group} must match ^[a-z][a-z0-9_]{2,62}$.`);
    process.exit(2);
  }
  if (!l.password || l.password.length < 16) {
    console.error(`${l.passwordVar} is required (at least 16 characters; generate a random one).`);
    process.exit(2);
  }
}
if (logins[0].login === logins[1].login) {
  console.error("The two login names must differ.");
  process.exit(2);
}
if (!adminUrl) {
  console.error("DATABASE_URL (an admin connection with CREATEROLE) is required.");
  process.exit(2);
}

const prisma = new PrismaClient();
try {
  // The migration creates the group roles and their grants when the migration user may create roles; with a less privileged migration user
  // (the development database) this admin step does it, idempotently, with exactly the same grants.
  for (const group of [WORKER_GROUP, READ_GROUP]) {
    const found = await prisma.$queryRaw`SELECT 1 AS ok FROM pg_roles WHERE rolname = ${group}`;
    if (found.length === 0) await prisma.$executeRawUnsafe(`CREATE ROLE ${group} NOLOGIN`);
  }
  for (const grant of GROUP_GRANTS) await prisma.$executeRawUnsafe(grant);
  for (const l of logins) {
    const exists = await prisma.$queryRaw`SELECT 1 AS ok FROM pg_roles WHERE rolname = ${l.login}`;
    // format() quotes the identifier (%I) and the password literal (%L): nothing is concatenated by hand
    const [{ sql }] = await prisma.$queryRaw`
      SELECT format(${exists.length > 0 ? "ALTER ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE" : "CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE"}, ${l.login}, ${l.password}) AS sql`;
    await prisma.$executeRawUnsafe(sql);
    const [{ grantSql }] =
      await prisma.$queryRaw`SELECT format('GRANT %I TO %I', ${l.group}, ${l.login}) AS "grantSql"`;
    await prisma.$executeRawUnsafe(grantSql);
    for (const setting of l.settings) {
      const [{ alterSql }] =
        await prisma.$queryRaw`SELECT format('ALTER ROLE %I SET ' || ${setting}, ${l.login}) AS "alterSql"`;
      await prisma.$executeRawUnsafe(alterSql);
    }
    const url = new URL(adminUrl);
    url.username = l.login;
    url.password = "PASSWORD_PLACEHOLDER";
    console.log(`Login role ${l.login} is a member of ${l.group}.`);
    console.log(`${l.urlVar}=${url.toString().replace("PASSWORD_PLACEHOLDER", "<password>")}`);
  }
} finally {
  await prisma.$disconnect();
}
