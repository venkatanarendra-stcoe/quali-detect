import { OPENAPI_TAGS } from "../constants/index.js";
import { createFindingsSlaController } from "../controllers/sla.js";
import { createFindingsRemediationRepository } from "../repositories/remediation.js";
import { putSlaBodySchema } from "../schemas/index.js";
import { remediationResponses } from "../schemas/remediation.js";
import { createFindingsSlaService } from "../services/sla.js";

/**
 * Findings routes, part C: `GET` and `PUT /settings/findings-sla` (docs/modules/findings/SPEC.md 5.9 SL-1, 8.1, 8.2). Tenant audience:
 * the tenant comes from the session only (nothing in the request names one). Read with `tenant_settings.view`, change with
 * `tenant_settings.manage` (a tenant permission, so a caller without it gets 403, there is no hidden resource to 404). The PUT is audited
 * (`tenant.findings_sla_changed`) in the same transaction as the write.
 * @param {import("./index.js").FindingsRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const findingsSettingsRoutes = (deps) =>
  async function register(app) {
    const { authz } = deps;
    const repository = createFindingsRemediationRepository({ db: deps.db });
    const controller = createFindingsSlaController({
      sla: createFindingsSlaService({ repository }),
    });
    const tags = [OPENAPI_TAGS.findings];
    const config = { audience: "tenant" };
    app.get(
      "/settings/findings-sla",
      {
        config,
        rateLimit: "read",
        preHandler: authz.authorize("tenant_settings.view"),
        schema: {
          tags,
          summary:
            "The findings SLA targets of the organization (hours per severity, with the defaults)",
          response: { 200: remediationResponses.sla },
        },
      },
      controller.get,
    );
    app.put(
      "/settings/findings-sla",
      {
        config,
        rateLimit: "write",
        preHandler: authz.authorize("tenant_settings.manage"),
        schema: {
          tags,
          summary:
            "Replace the findings SLA targets (audited; a severity left out returns to its default)",
          body: putSlaBodySchema,
          response: { 200: remediationResponses.sla },
        },
      },
      controller.put,
    );
  };
