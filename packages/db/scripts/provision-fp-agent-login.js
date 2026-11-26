/**
 * Provisions the restricted LOGIN role of the false-positive advisory agent (docs/modules/findings/SPEC.md 9.3.4 layer 1, OQ-6; owner
 * decision of 2026-11-23). The migration `20261123100000_findings_core` creates the NOLOGIN group role `qm_fp_agent` and its grants (select
 * on the view `fp_agent_findings`, select and insert on `finding_ai_advisories`, select on `tenant_llm_settings`, nothing else) when its
 * user may create roles; this script creates the group role and the same grants when it is missing (the development database). It then
 * creates a LOGIN role that is a MEMBER of the group, so the agent worker can connect with it (`FINDINGS_AGENT_DATABASE_URL`).
 * Development and production use the same script; production operations may run the equivalent SQL.
 *
 * Needs an ADMIN connection (CREATEROLE): `DATABASE_URL`. The new password comes from `FINDINGS_AGENT_DB_PASSWORD` (it is never printed,
 * never put on a command line and never logged). The login name defaults to `qm_fp_agent_login` (`FINDINGS_AGENT_DB_LOGIN`).
 * Idempotent: an existing login role gets the new password and membership. It prints the connection string with the password
 * replaced by `<password>` (host, port and database come from DATABASE_URL).
 *
 * Run: FINDINGS_AGENT_DB_PASSWORD=... pnpm --filter @qmentisai/db provision:fp-agent-login
 */
const GROUP_ROLE = "qm_fp_agent";
/** The exact privileges of the group role (migration 20261123100000_findings_core, section 17): nothing else is ever granted. */
const GROUP_GRANTS = [
  `GRANT SELECT ON "fp_agent_findings" TO ${GROUP_ROLE}`,
  `GRANT SELECT, INSERT ON "finding_ai_advisories" TO ${GROUP_ROLE}`,
  `GRANT SELECT ON "tenant_llm_settings" TO ${GROUP_ROLE}`,
];
const login = process.env.FINDINGS_AGENT_DB_LOGIN ?? "qm_fp_agent_login";
const password = process.env.FINDINGS_AGENT_DB_PASSWORD;
const adminUrl = process.env.DATABASE_URL;

if (!/^[a-z][a-z0-9_]{2,62}$/.test(login)) {
  console.error("FINDINGS_AGENT_DB_LOGIN must match ^[a-z][a-z0-9_]{2,62}$.");
  process.exit(2);
}
if (!password || password.length < 16) {
  console.error(
    "FINDINGS_AGENT_DB_PASSWORD is required (at least 16 characters; generate a random one).",
  );
  process.exit(2);
}
if (!adminUrl) {
  console.error("DATABASE_URL (an admin connection with CREATEROLE) is required.");
  process.exit(2);
}

// Imported only AFTER the checks above: importing @prisma/client loads a `.env` file that sits next to the schema into process.env, which
// would silently supply an admin URL the caller never passed (a suite run or a stray invocation would then reach whatever database that
// file names). The client also gets the admin URL EXPLICITLY, so no file can redirect it. Inert unless explicitly invoked with its inputs.
const { PrismaClient } = await import("@prisma/client");
const prisma = new PrismaClient({ datasourceUrl: adminUrl });
try {
  // The migration creates the group role and its grants when the migration user may create roles; with a less privileged migration user
  // (the development database) this admin step does it, idempotently, with exactly the same grants.
  const group = await prisma.$queryRaw`SELECT 1 AS ok FROM pg_roles WHERE rolname = ${GROUP_ROLE}`;
  if (group.length === 0) await prisma.$executeRawUnsafe(`CREATE ROLE ${GROUP_ROLE} NOLOGIN`);
  for (const grant of GROUP_GRANTS) await prisma.$executeRawUnsafe(grant);
  const exists = await prisma.$queryRaw`SELECT 1 AS ok FROM pg_roles WHERE rolname = ${login}`;
  // format() quotes the identifier (%I) and the password literal (%L): nothing is concatenated by hand
  const [{ sql }] = await prisma.$queryRaw`
    SELECT format(${exists.length > 0 ? "ALTER ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE" : "CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE"}, ${login}, ${password}) AS sql`;
  await prisma.$executeRawUnsafe(sql);
  const [{ grantSql }] =
    await prisma.$queryRaw`SELECT format('GRANT %I TO %I', ${GROUP_ROLE}, ${login}) AS "grantSql"`;
  await prisma.$executeRawUnsafe(grantSql);
  const url = new URL(adminUrl);
  url.username = login;
  url.password = "PASSWORD_PLACEHOLDER";
  console.log(`Login role ${login} is a member of ${GROUP_ROLE}.`);
  console.log(
    `FINDINGS_AGENT_DATABASE_URL=${url.toString().replace("PASSWORD_PLACEHOLDER", "<password>")}`,
  );
} finally {
  await prisma.$disconnect();
}
