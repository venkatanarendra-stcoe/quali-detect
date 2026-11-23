import { findingsAdvisoryRoutes } from "./advisory.routes.js";
import { findingsApprovalRoutes } from "./approval.routes.js";
import { findingsExceptionRoutes } from "./exceptions.routes.js";
import { findingsReadRoutes } from "./read.routes.js";
import { findingsRemediationRoutes } from "./remediation.routes.js";
import { findingsReviewRoutes } from "./review.routes.js";
import { findingsSettingsRoutes } from "./settings.routes.js";

/**
 * Everything a route file may build its own wiring from. Part A0 fixes this shape; a part never adds a field here (it builds what it
 * needs from `db`, `authz`, `audit`, `outbox`, `entitlements` and `config`).
 * @typedef {object} FindingsRouteDeps
 * @property {any} db the Prisma client (repositories only)
 * @property {{ authorize: Function, context: Function, scopes: any }} authz
 * @property {any} audit
 * @property {any} outbox
 * @property {any} entitlements
 * @property {any} config
 * @property {import("pino").Logger} log
 */

/**
 * Mounts every findings route file in a fixed order. Each part fills its own file; this file is frozen by Part A0.
 * @param {FindingsRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const findingsRoutes = (deps) =>
  async function findings(app) {
    await findingsReadRoutes(deps)(app);
    await findingsReviewRoutes(deps)(app);
    await findingsApprovalRoutes(deps)(app);
    await findingsExceptionRoutes(deps)(app);
    await findingsRemediationRoutes(deps)(app);
    await findingsSettingsRoutes(deps)(app);
    await findingsAdvisoryRoutes(deps)(app);
  };
