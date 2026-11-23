import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { findingsRoutes } from "./routes/index.js";

export { MODULE_NAME };

/** @param {import("../../runtime/modules.js").ModuleContext} app */
async function findingsPlugin(app) {
  await app.register(
    findingsRoutes({
      db: app.infra.db,
      authz: app.authz,
      audit: app.audit,
      outbox: app.outbox,
      entitlements: app.entitlements,
      config: app.config,
      log: app.log,
    }),
  );
}

/**
 * The Findings module (docs/modules/findings/SPEC.md, steps 7 to 12 of the workflow). Contract freeze (Part A0): the route files are
 * empty and are filled by the owning parts; no route is registered until then.
 * @type {import("../../runtime/modules.js").ApiModule}
 */
export const findingsModule = {
  name: MODULE_NAME,
  description:
    "Findings: lifecycle, review, approval, remediation, exceptions, SLA and the advisory false-positive agent (workspace scoped, SOD enforced).",
  prefix: API_PREFIX,
  plugin: findingsPlugin,
};
