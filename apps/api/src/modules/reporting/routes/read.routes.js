import { createRepositoryForReads } from "../read-repository.js";
import { getReportingReadCache } from "../read-cache.js";
import { createReportingReadController } from "../controllers/read.js";
import {
  reportingEnabled,
  reportingTenantScope,
  reportingWorkspaceScope,
} from "../policies/read.js";
import { readQueries, readResponses } from "../schemas/read.js";
import { createReportingReadService } from "../services/read.js";
import { OPENAPI_TAGS } from "../constants/index.js";

/**
 * Reporting routes, Part B (read API): the thirteen `GET /reporting/*` read routes of docs/modules/reporting-dashboards/SPEC.md 9 (posture, trends,
 * remediation, sla, aging, scan-activity, coverage, sbom, quality, breakdown, top-risk, workload, overview). `workspaceId` is a REQUIRED query
 * parameter of the twelve workspace reads (the Findings pattern): the workspace is loaded by tenant and id, and a workspace of another tenant, a
 * hidden one or an unknown id is the same 404; a visible workspace without the section's key is 403. `GET /reporting/overview` is tenant scope
 * (`dashboard.view`), takes NO workspace or tenant parameter (the strict query answers 400) and aggregates only the workspaces the caller can see.
 * While `REPORTING_ENABLED` is not true every one of them is a 404 (the scope resolvers answer `null`). The route keys and permissions are the
 * frozen `REPORTING_PERMISSION_BY_ROUTE` of `@qmentisai/shared`; the queries and DTOs are `REPORTING_ROUTE_SCHEMAS`.
 * @param {import("./index.js").ReportingRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const reportingReadRoutes = (deps) =>
  async function register(app) {
    const { authz } = deps;
    const enabled = reportingEnabled(deps.config);
    const reads = createReportingReadService({
      // the read client is lazy: with the module off nothing connects (the first request after enabling creates the pool)
      repository: createRepositoryForReads({ readDb: deps.readDb }),
      cache: getReportingReadCache({ config: deps.config, log: deps.log }),
    });
    const controller = createReportingReadController({ reads });
    const tags = [OPENAPI_TAGS.reporting];
    const config = { audience: "tenant" };
    const workspaceScope = reportingWorkspaceScope(enabled);
    const inWorkspace = (key, scope) => authz.authorize(key, scope);

    app.get(
      "/reporting/posture",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", workspaceScope),
        schema: {
          tags,
          summary: "Current posture of one workspace (P-1 to P-10), or as of a past day",
          querystring: readQueries["GET /reporting/posture"],
          response: { 200: readResponses.posture },
        },
      },
      controller.posture,
    );
    app.get(
      "/reporting/trends",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", workspaceScope),
        schema: {
          tags,
          summary: "Daily trends of one workspace (T-1 to T-5), zero-filled, gaps marked",
          querystring: readQueries["GET /reporting/trends"],
          response: { 200: readResponses.trends },
        },
      },
      controller.trends,
    );
    app.get(
      "/reporting/remediation",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", workspaceScope),
        schema: {
          tags,
          summary: "Remediation performance (R-1 to R-3, R-7, R-8, velocity)",
          querystring: readQueries["GET /reporting/remediation"],
          response: { 200: readResponses.remediation },
        },
      },
      controller.remediation,
    );
    app.get(
      "/reporting/sla",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", workspaceScope),
        schema: {
          tags,
          summary: "SLA compliance of closed findings and SLA status of open ones (R-4, R-5)",
          querystring: readQueries["GET /reporting/sla"],
          response: { 200: readResponses.sla },
        },
      },
      controller.sla,
    );
    app.get(
      "/reporting/aging",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", workspaceScope),
        schema: {
          tags,
          summary: "Aging buckets and the ten oldest critical and high findings (R-6)",
          querystring: readQueries["GET /reporting/aging"],
          response: { 200: readResponses.aging },
        },
      },
      controller.aging,
    );
    app.get(
      "/reporting/scan-activity",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("execution.view", workspaceScope),
        schema: {
          tags,
          summary:
            "Executions per day, success rate, duration and ingestion share (S-1 to S-3, S-6, S-7)",
          querystring: readQueries["GET /reporting/scan-activity"],
          response: { 200: readResponses.scanActivity },
        },
      },
      controller.scanActivity,
    );
    app.get(
      "/reporting/coverage",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("execution.view", workspaceScope),
        schema: {
          tags,
          summary: "Repository and scan-type coverage with reasons (S-4, S-5)",
          querystring: readQueries["GET /reporting/coverage"],
          response: { 200: readResponses.coverage },
        },
      },
      controller.coverage,
    );
    app.get(
      "/reporting/sbom",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("execution.view", workspaceScope),
        schema: {
          tags,
          summary: "SBOM component counts and trend (S-8)",
          querystring: readQueries["GET /reporting/sbom"],
          response: { 200: readResponses.sbom },
        },
      },
      controller.sbom,
    );
    app.get(
      "/reporting/quality",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("security_review.view", workspaceScope),
        schema: {
          tags,
          summary:
            "Detection quality: false-positive rate, advisory agreement, noisiest rules (Q-1 to Q-6)",
          querystring: readQueries["GET /reporting/quality"],
          response: { 200: readResponses.quality },
        },
      },
      controller.quality,
    );
    app.get(
      "/reporting/breakdown",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", workspaceScope),
        schema: {
          tags,
          summary:
            "Open findings by repository, pipeline, scan type or rule (B-2, B-3, B-5; keyset pages)",
          querystring: readQueries["GET /reporting/breakdown"],
          response: { 200: readResponses.breakdown },
        },
      },
      controller.breakdown,
    );
    app.get(
      "/reporting/top-risk",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.view", workspaceScope),
        schema: {
          tags,
          summary: "Top risky repositories by risk points, formula in meta (B-4)",
          querystring: readQueries["GET /reporting/top-risk"],
          response: { 200: readResponses.topRisk },
        },
      },
      controller.topRisk,
    );
    app.get(
      "/reporting/workload",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("finding.assign", workspaceScope),
        schema: {
          tags,
          summary: "Per-assignee open, due-soon and breached counts, never ranked (B-6)",
          querystring: readQueries["GET /reporting/workload"],
          response: { 200: readResponses.workload },
        },
      },
      controller.workload,
    );
    app.get(
      "/reporting/overview",
      {
        config,
        rateLimit: "read",
        preHandler: authz.authorize("dashboard.view", reportingTenantScope(enabled)),
        schema: {
          tags,
          summary:
            "Organization overview across the workspaces the caller can see (B-1; tenant-scope dashboard.view; no workspace parameter)",
          querystring: readQueries["GET /reporting/overview"],
          response: { 200: readResponses.overview },
        },
      },
      controller.overview,
    );
  };
