import { Prisma } from "@prisma/client";
import { OPEN_FINDING_STATUSES, REPORTING_LIMITS } from "@qmentisai/shared";

/**
 * Shared plumbing of the reporting READ queries (docs/modules/reporting-dashboards/SPEC.md 12 item 7, RPT-015): every read runs in ONE
 * read-only, repeatable-read transaction on the read pool (a consistent snapshot for the several queries of one endpoint, no locks), with the
 * role's `statement_timeout` (the same 5 seconds, set again so a development database that uses the shared pool is bounded too), and only
 * parameterized SQL over the redaction-safe `report_*_v` views and the `report_*` tables (never a source table: the role has no grant).
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** @param {string} name @param {unknown} value @returns {string} */
export function uuid(name, value) {
  if (typeof value !== "string" || !UUID.test(value)) throw new TypeError(`${name} must be a uuid`);
  return value;
}

/** @param {string} name @param {unknown} value @returns {string} */
export function day(name, value) {
  if (typeof value !== "string" || !DAY.test(value))
    throw new TypeError(`${name} must be a YYYY-MM-DD day`);
  return value;
}

/** A finite number or null (bigint, numeric strings and nulls from the driver). @param {unknown} v */
export const num = (v) => (v === null || v === undefined ? null : Number(v));
/** A count: never null. @param {unknown} v */
export const cnt = (v) => (v === null || v === undefined ? 0 : Number(v));
/** An ISO instant. @param {Date | string} v */
export const iso = (v) => new Date(v).toISOString();

/**
 * SQL list of enum literals built ONLY from an allow-listed vocabulary (constants, never input), so the Findings partial indexes can match it.
 * @param {readonly string[]} values @param {readonly string[]} vocabulary
 */
export function literals(values, vocabulary) {
  for (const v of values)
    if (!vocabulary.includes(v)) throw new TypeError(`unknown value ${String(v)}`);
  return Prisma.raw(values.map((v) => `'${v}'`).join(", "));
}

/** The eight open statuses (SPEC 5 rule 2) as a SQL list. */
export const OPEN_SQL = literals(OPEN_FINDING_STATUSES, OPEN_FINDING_STATUSES);

/**
 * Runs `fn(tx)` in a read-only repeatable-read transaction with a statement timeout.
 * @template T
 * @param {any} db the read client
 * @param {(tx: any) => Promise<T>} fn
 * @returns {Promise<T>}
 */
export function readTx(db, fn) {
  return db.$transaction(
    async (tx) => {
      await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
      await tx.$executeRawUnsafe(
        `SET LOCAL statement_timeout = ${Number(REPORTING_LIMITS.readStatementTimeoutSeconds) * 1000}`,
      );
      return fn(tx);
    },
    { maxWait: 5000, timeout: 30000 },
  );
}

export { Prisma };
