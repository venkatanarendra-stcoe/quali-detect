import { createReportingReadRepository } from "@qmentisai/db";

/**
 * The reporting READ repository over the LAZY read client: `readDb()` (the separate `qm_reporting_ro` pool, created on its first call, so with the
 * module off nothing connects) is resolved per query, never at route registration. The repository only ever calls `$transaction`.
 * @param {{ readDb: () => any }} deps
 */
export function createRepositoryForReads({ readDb }) {
  const lazy = { $transaction: (...args) => readDb().$transaction(...args) };
  return createReportingReadRepository({ db: lazy });
}
