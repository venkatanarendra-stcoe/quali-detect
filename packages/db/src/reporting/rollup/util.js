import {
  addDays,
  dayStartInstant,
  isDayString,
  isValidTimeZone,
  listDays,
} from "@qmentisai/shared";

/**
 * Shared helpers of the rollup repository (docs/modules/reporting-dashboards/SPEC.md 7.2, ADR-015). Part A owns this directory.
 */

/** The statement timeout (milliseconds) of every rollup transaction; one runaway statement cannot hold a connection. */
export const ROLLUP_STATEMENT_TIMEOUT_MS = 60_000;
/** The Prisma interactive transaction ceiling, a little above the statement timeout times the statements of one call. */
const TRANSACTION_TIMEOUT_MS = 5 * 60_000;
/** Rows per upsert statement. */
export const UPSERT_BATCH = 2000;

/**
 * An input the repository refuses: carries a stable code of `ROLLUP_ERROR_CODES` (`invalid_range`, `ownership_mismatch`). The worker maps
 * it to a non-retryable failure; anything else is a database error and is classified there (transient or not).
 */
export class RollupInputError extends Error {
  /** @param {"invalid_range" | "ownership_mismatch"} rollupCode @param {string} message */
  constructor(rollupCode, message) {
    super(message);
    this.name = "RollupInputError";
    this.rollupCode = rollupCode;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
/** @param {unknown} value @param {string} name @returns {string} */
export function assertUuid(value, name) {
  if (typeof value !== "string" || !UUID.test(value))
    throw new RollupInputError("ownership_mismatch", `${name} is not a UUID`);
  return value;
}

/** @param {unknown} value @returns {number} a BigInt, a numeric string or a number as a number (counts here stay far below 2^53) */
export const num = (value) => (value === null || value === undefined ? 0 : Number(value));

/**
 * The tenant-local day thresholds of a day range: `days` and the epoch SECONDS of each day start plus the end of the last day, so
 * `width_bucket(epoch, thresholds)` is the 1-based index of the day an instant belongs to (0 before, n + 1 after). The day boundaries come
 * from the shared period helpers (one source of truth for DST), never from the database's own time zone data.
 * @param {string} from @param {string} to @param {string} timeZone
 * @returns {{ days: string[], thresholds: number[], start: Date, endExclusive: Date }}
 */
export function dayThresholds(from, to, timeZone) {
  if (!isDayString(from) || !isDayString(to) || !isValidTimeZone(timeZone))
    throw new RollupInputError("invalid_range", "invalid day range or time zone");
  const days = listDays(from, to);
  const starts = days.map((d) => dayStartInstant(d, timeZone));
  const end = dayStartInstant(addDays(to, 1), timeZone);
  return {
    days,
    thresholds: [...starts, end].map((d) => d.getTime() / 1000),
    start: starts[0],
    endExclusive: end,
  };
}

/**
 * Runs `fn` in ONE transaction with a statement timeout (`SET LOCAL`), the transaction-scoped way that survives a pooled connection.
 * @template T
 * @param {any} db @param {(tx: any) => Promise<T>} fn @param {number} [timeoutMs] @returns {Promise<T>}
 */
export function inTransaction(db, fn, timeoutMs = ROLLUP_STATEMENT_TIMEOUT_MS) {
  return db.$transaction(
    async (tx) => {
      // the value is a validated integer, not user input; SET LOCAL takes no bind parameter
      await tx.$executeRawUnsafe(`SET LOCAL statement_timeout = ${Math.trunc(timeoutMs)}`);
      return fn(tx);
    },
    { timeout: TRANSACTION_TIMEOUT_MS, maxWait: 10_000 },
  );
}
