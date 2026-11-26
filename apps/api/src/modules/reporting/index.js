import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { getReportingReadClient } from "./read-client.js";
import { reportingRoutes } from "./routes/index.js";

export { MODULE_NAME };
export { disconnectReportingReadClient } from "./read-client.js";

/** @param {import("../../runtime/modules.js").ModuleContext} app */
async function reportingPlugin(app) {
  await app.register(
    reportingRoutes({
      db: app.infra.db,
      readDb: () =>
        getReportingReadClient({ config: app.config, log: app.log, shared: app.infra.db }),
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
 * The Reporting and Dashboards module (docs/modules/reporting-dashboards/SPEC.md, ADR-015). Contract freeze (Part A0): the two route files are
 * empty and are filled by the owning parts (B: `routes/read.routes.js`, C: `routes/export.routes.js`); no route is registered until then.
 * Everything is off while `REPORTING_ENABLED=false`.
 * @type {import("../../runtime/modules.js").ApiModule}
 */
export const reportingModule = {
  name: MODULE_NAME,
  description:
    "Reporting and dashboards: posture, trends, remediation and scan metrics from live queries and daily rollups, and redacted CSV and PDF exports (workspace scoped).",
  prefix: API_PREFIX,
  plugin: reportingPlugin,
};
