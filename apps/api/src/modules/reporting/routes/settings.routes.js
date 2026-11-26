import { createSuccessSchema } from "@qmentisai/contracts";
import {
  REPORTING_PERMISSION_BY_ROUTE,
  reportingSettingsDtoSchema,
  updateReportingSettingsBodySchema,
} from "@qmentisai/shared";
import { z } from "zod";
import { NotFoundError } from "../../../errors/app-error.js";
import { OPENAPI_TAGS } from "../constants/index.js";
import { createReportingSettingsController } from "../controllers/settings.js";
import { bumpTenantReportingEpochs } from "../read-cache.js";
import { createReportingSettingsRepository } from "../repositories/settings.js";
import { createReportingSettingsService } from "../services/settings.js";

const settingsResponse = createSuccessSchema(reportingSettingsDtoSchema);
const noQuery = z.object({}).strict();

/**
 * Reporting settings routes: `GET /reporting/settings` and `PUT /reporting/settings` (the tenant reporting time zone; AS_BUILT_TZ.md).
 * Tenant scope, the tenant from the session only. Read with `tenant_settings.view`, change with `tenant_settings.manage` (the keys the
 * Organization Settings screen uses; no new key); another holder gets 403 (a tenant key hides no resource). While `REPORTING_ENABLED` is
 * not true both answer the identical 404 of every reporting route.
 * @param {import("./index.js").ReportingRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const reportingSettingsRoutes = (deps) =>
  async function register(app) {
    const { authz } = deps;
    const service = createReportingSettingsService({
      db: deps.db,
      repository: createReportingSettingsRepository({ db: deps.db }),
      audit: deps.audit,
      outbox: deps.outbox,
      bumpEpochs: (input) =>
        bumpTenantReportingEpochs({ config: deps.config, log: deps.log, ...input }),
      config: deps.config,
    });
    const controller = createReportingSettingsController({ service });
    const moduleEnabled = Object.assign(
      async function reportingEnabled(_req, _res, next) {
        if (deps.config?.reporting?.enabled !== true) throw new NotFoundError();
        next();
      },
      { permission: null },
    );
    const config = { audience: "tenant" };
    const tags = [OPENAPI_TAGS.reporting];

    app.get(
      "/reporting/settings",
      {
        config,
        rateLimit: "read",
        preHandler: [
          moduleEnabled,
          authz.authorize(REPORTING_PERMISSION_BY_ROUTE["GET /reporting/settings"]),
        ],
        schema: {
          tags,
          summary: "The tenant reporting time zone and whether a rebuild is running",
          querystring: noQuery,
          response: { 200: settingsResponse },
        },
      },
      controller.get,
    );
    app.put(
      "/reporting/settings",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: [
          moduleEnabled,
          authz.authorize(REPORTING_PERMISSION_BY_ROUTE["PUT /reporting/settings"]),
        ],
        schema: {
          tags,
          summary:
            "Set the tenant reporting time zone (audited). A real change rebuilds the trends in the new zone; the same zone is a no-op",
          querystring: noQuery,
          body: updateReportingSettingsBodySchema,
          response: { 200: settingsResponse },
        },
      },
      controller.update,
    );
  };
