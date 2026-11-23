import { createFindingAdvisoriesRepository } from "@qmentisai/db";
import { OPENAPI_TAGS } from "../constants/index.js";
import { createAdvisoryController } from "../controllers/advisory.js";
import { findingScope } from "../repositories/read-scopes.js";
import { advisoryRequestBodySchema, findingParamsSchema } from "../schemas/index.js";
import { advisoryResponses } from "../schemas/advisory.js";
import { createAdvisoryService } from "../services/advisory.js";

/**
 * Findings routes, part D: `POST /findings/{id}/advisory/request` (docs/modules/findings/SPEC.md 8.2, 9.3). The finding is loaded by
 * TENANT and id and authorized in ITS workspace with `finding.review` (identical 404 for a foreign, hidden or missing finding, 403 for a
 * visible workspace without the permission). The advisory itself is read through the finding detail (`GET /findings/{id}`, the
 * `advisory` field): the frozen contract has no separate read route. The agent switch is `config.findings.agentEnabled` when a
 * configuration provides it, else `FINDINGS_AGENT_ENABLED`; off means nothing is queued.
 * @param {import("./index.js").FindingsRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const findingsAdvisoryRoutes = (deps) =>
  async function register(app) {
    const { authz } = deps;
    const inWorkspace = (key, scope) => authz.authorize(key, scope);
    const advisories = createAdvisoryService({
      repository: createFindingAdvisoriesRepository({ db: deps.db }),
      audit: deps.audit,
      enabled: () =>
        deps.config?.findings?.agentEnabled ?? process.env.FINDINGS_AGENT_ENABLED === "true",
    });
    const controller = createAdvisoryController({ advisories });
    app.post(
      "/findings/:id/advisory/request",
      {
        config: { audience: "tenant" },
        rateLimit: "write",
        idempotent: true,
        preHandler: inWorkspace("finding.review", findingScope()),
        schema: {
          tags: [OPENAPI_TAGS.findings],
          summary:
            "Ask the advisory agent for a fresh true/false-positive suggestion (advice only; never changes the finding)",
          params: findingParamsSchema,
          body: advisoryRequestBodySchema,
          response: { 202: advisoryResponses.request },
        },
      },
      controller.request,
    );
  };
