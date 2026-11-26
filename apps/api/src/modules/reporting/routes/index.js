import { reportingExportRoutes } from "./export.routes.js";
import { reportingReadRoutes } from "./read.routes.js";
import { reportingSettingsRoutes } from "./settings.routes.js";

/**
 * Everything a route file may build its own wiring from. Part A0 fixes this shape; a part never adds a field here (it builds what it needs
 * from these). `readDb` is a function: the reporting READ client (a separate pool of the `qm_reporting_ro` login, see `../read-client.js`) is
 * created on first call, so with `REPORTING_ENABLED=false` nothing connects.
 * @typedef {object} ReportingRouteDeps
 * @property {any} db the API's normal Prisma client (the `report_exports` row and the outbox are written through it; repositories only)
 * @property {() => any} readDb the read-role client (lazy)
 * @property {{ authorize: Function, context: Function, scopes: any }} authz
 * @property {any} audit
 * @property {any} outbox
 * @property {any} entitlements
 * @property {any} config
 * @property {import("pino").Logger} log
 */

/**
 * Mounts the two route files in a fixed order. Each part fills its own file; this file is frozen by Part A0.
 * @param {ReportingRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const reportingRoutes = (deps) =>
  async function reporting(app) {
    await reportingReadRoutes(deps)(app);
    await reportingExportRoutes(deps)(app);
    await reportingSettingsRoutes(deps)(app);
  };
