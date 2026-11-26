/**
 * Operator command: queue the backfill of ONE tenant's reporting rollups (docs/modules/reporting-dashboards/SPEC.md 7.2, ADR-015). It does not
 * compute anything itself: it writes ONE `reporting.rollup.requested` job (`mode: "backfill"`) to the transactional outbox, exactly what the
 * hourly tick queues on first enablement, and the running reporting worker (role `qm_reporting`, throttled, resumable, one tenant at a time)
 * does the work. The flow, execution, decision and SBOM series are backfilled; the per-severity state series is FORWARD-ONLY and never is
 * (AS_BUILT_A.md).
 *
 *   REPORTING_ENABLED=true node packages/db/scripts/reporting-backfill.js --tenant <slug|id> [--from YYYY-MM-DD] [--to YYYY-MM-DD]
 *                                                                          [--reason first_enablement|repair|timezone_changed] [--allow]
 *
 * Refuses (exit 2) when `REPORTING_ENABLED` is not `true` (nothing is queued while the module is off), when `NODE_ENV=production` without
 * `--allow`, for an unknown tenant, or for a bad day or reason. Defaults: `from` the day of the tenant's oldest history row (capped at 25
 * months), `to` today in the tenant's reporting time zone, `reason` `first_enablement`. Idempotent per range and hour (the outbox is unique
 * per message id). Needs `DATABASE_URL`; prints ids and counts only, never a connection string or a secret.
 */
import { randomUUID } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { localDayOf, isDayString, isValidTimeZone, addDays } from "@qmentisai/shared";
import { createOutboxRepository } from "../src/outbox-repository.js";

const REASONS = new Set(["first_enablement", "repair", "timezone_changed"]);
const RETENTION_DAYS = 25 * 31;

const fail = (message) => {
  console.error(`reporting-backfill: ${message}`);
  process.exit(2);
};

function parseArgs(argv) {
  const out = { allow: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--") continue;
    if (a === "--allow") out.allow = true;
    else if (["--tenant", "--from", "--to", "--reason"].includes(a)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith("--")) fail(`${a} needs a value`);
      out[a.slice(2)] = v;
      i += 1;
    } else fail(`unknown argument ${a}`);
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (process.env.REPORTING_ENABLED !== "true")
  fail("REPORTING_ENABLED is not true: nothing is queued while the reporting module is off");
if (process.env.NODE_ENV === "production" && !args.allow)
  fail("NODE_ENV=production: pass --allow to queue a backfill in production");
if (!process.env.DATABASE_URL) fail("DATABASE_URL is required");
if (!args.tenant) fail("--tenant <slug|id> is required");
const reason = args.reason ?? "first_enablement";
if (!REASONS.has(reason)) fail("--reason must be first_enablement, repair or timezone_changed");
for (const key of ["from", "to"])
  if (args[key] !== undefined && !isDayString(args[key])) fail(`--${key} must be a day YYYY-MM-DD`);

const db = new PrismaClient();
try {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const tenant = await db.tenant.findFirst({
    where: UUID.test(args.tenant) ? { id: args.tenant } : { slug: args.tenant },
    select: { id: true, status: true },
  });
  if (!tenant) fail("unknown tenant");
  if (!["active", "trial"].includes(tenant.status)) fail("the tenant is not active");
  const zoneRow = await db.tenantReportingSettings.findUnique({ where: { tenantId: tenant.id } });
  const timeZone =
    zoneRow && isValidTimeZone(zoneRow.reportingTimezone) ? zoneRow.reportingTimezone : "UTC";
  const now = new Date();
  const today = localDayOf(now, timeZone);
  const earliest = (
    await db.$queryRaw`SELECT min(created_at) AS at FROM finding_status_history WHERE tenant_id = ${tenant.id}::uuid`
  )[0]?.at;
  if (!earliest && args.from === undefined)
    fail("the tenant has no history to backfill (pass --from to force a range)");
  const floor = addDays(today, -RETENTION_DAYS);
  const from =
    args.from ?? (localDayOf(earliest, timeZone) < floor ? floor : localDayOf(earliest, timeZone));
  const to = args.to ?? today;
  if (from > to) fail("--from is after --to");
  const hour = Math.floor(now.getTime() / 3_600_000);
  const messageId = `reporting-rollup-${tenant.id}-backfill-${from}_${to}-op${hour}`;
  const message = {
    envelopeVersion: 1,
    kind: "job",
    messageId,
    type: "reporting.rollup.requested",
    schemaVersion: 1,
    tenantId: tenant.id,
    correlationId: randomUUID(),
    occurredAt: now.toISOString(),
    initiator: { type: "system", id: "reporting-backfill-cli" },
    payload: { tenantId: tenant.id, mode: "backfill", from, to, reason },
  };
  const outbox = createOutboxRepository({ db });
  await db.$transaction((tx) => outbox.enqueue(tx, { queue: "reporting", message }));
  console.log(
    `queued: tenant ${tenant.id}, backfill ${from} to ${to} (${reason}), message ${messageId}`,
  );
} finally {
  await db.$disconnect();
}
