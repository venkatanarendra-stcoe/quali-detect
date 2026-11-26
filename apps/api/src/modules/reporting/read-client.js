import { createDbClient } from "@qmentisai/db";

const KEY = Symbol.for("qmentisai.reporting.read.client");

/**
 * The database client of the read API (docs/modules/reporting-dashboards/SPEC.md 12 item 7): a SEPARATE pool of the login role that is a member of
 * `qm_reporting_ro` (`REPORTING_RO_DATABASE_URL`: select on the report views only, read-only transactions, `statement_timeout` 5 s), so a
 * reporting read can never write, can never see evidence or free text, and cannot starve the transactional pool. In development, when the URL
 * is unset, the shared client is used (still only through the frozen read repository) and a warning is logged once; production refuses to
 * start without the URL while the module is enabled (the configuration check). The pool is created on first use and only when the module is
 * enabled, so with the flag off nothing connects. One pool per process (stored on `globalThis`, like `getDbClient`).
 * @param {{ config: any, log: import("pino").Logger, shared: any }} deps
 * @returns {any} the read client (a `PrismaClient`)
 */
export function getReportingReadClient({ config, log, shared }) {
  const url = config.reporting.readDatabaseUrl;
  if (!url) {
    if (!globalThis[KEY]?.warned) {
      globalThis[KEY] = { warned: true };
      log.warn(
        "REPORTING_RO_DATABASE_URL is not set: the reporting reads use the shared database pool (development only; production refuses to start)",
      );
    }
    return shared;
  }
  if (!globalThis[KEY]?.client)
    globalThis[KEY] = { client: createDbClient({ datasourceUrl: url }) };
  return globalThis[KEY].client;
}

/** Disconnects the read pool (graceful shutdown; the application's close hook calls it). */
export async function disconnectReportingReadClient() {
  const client = globalThis[KEY]?.client;
  delete globalThis[KEY];
  if (client) await client.$disconnect();
}
