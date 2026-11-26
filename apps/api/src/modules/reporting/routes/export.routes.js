import path from "node:path";
import {
  createReportingExportWorkerRepository,
  createReportingExportsRepository,
} from "@qmentisai/db";
import {
  createReportBodySchema,
  listReportsQuerySchema,
  reportIdParamsSchema,
} from "@qmentisai/shared";
import { OPENAPI_TAGS } from "../constants/index.js";
import { createReportExportController } from "../controllers/export.js";
import { createExportAuthorization } from "../export-authorization.js";
import { createReportObjectReader } from "../export-object-reader.js";
import { createReportExportSupport } from "../repositories/export.js";
import { createReportHeadersSchema, exportResponses } from "../schemas/export.js";
import { createReportExportService } from "../services/export.js";

/**
 * Reporting routes, Part C (exports): `POST /reporting/reports`, `GET /reporting/reports`, `GET /reporting/reports/{id}`,
 * `GET /reporting/reports/{id}/download` (an authenticated stream, `no-store`, audited) and `DELETE /reporting/reports/{id}`
 * (docs/modules/reporting-dashboards/SPEC.md 7.3, 9, 12). Part C owns this file and the files it adds next to it; Part A0 froze the signature
 * below and the route keys, permissions and schemas in `@qmentisai/shared`.
 *
 * Everything answers the identical 404 while `REPORTING_ENABLED` is off (the module is then not part of the product). The report files are
 * read from `ARTIFACT_STORE_ROOT` (the directory the reporting worker writes; an absolute path), and only through the read-only reader:
 * without it a download answers 503 and a request is still accepted (the worker will fail it when it cannot store the file).
 * @param {import("./index.js").ReportingRouteDeps} deps
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const reportingExportRoutes = (deps) =>
  async function register(app) {
    const { authz } = deps;
    const exports = createReportingExportsRepository({ db: deps.db });
    const support = createReportExportSupport({ db: deps.db, readDb: deps.readDb });
    // the row count of a template over the views, on the READ role (select on the views only): the same function the worker uses
    const counter = {
      countExportRows: (args) =>
        createReportingExportWorkerRepository({ db: deps.readDb() }).countExportRows(args),
    };
    const root = deps.config?.reporting?.artifactStoreRoot ?? process.env.ARTIFACT_STORE_ROOT;
    const reader = root && path.isAbsolute(root) ? createReportObjectReader({ root }) : null;
    const service = createReportExportService({
      db: deps.db,
      exports,
      counter,
      support,
      audit: deps.audit,
      outbox: deps.outbox,
      reader,
    });
    const controller = createReportExportController({ service });
    const gate = createExportAuthorization({ authz, exports, support, config: deps.config });
    const config = { audience: "tenant" };
    const tags = [OPENAPI_TAGS.reports];

    app.post(
      "/reporting/reports",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: [gate.moduleEnabled, gate.create],
        schema: {
          tags,
          summary:
            "Generate a report (CSV or PDF) asynchronously; 202 with the report id. Idempotency-Key is REQUIRED. Refused, never truncated, above 250,000 CSV rows",
          headers: createReportHeadersSchema,
          body: createReportBodySchema,
          response: { 202: exportResponses.create },
        },
      },
      controller.create,
    );
    app.get(
      "/reporting/reports",
      {
        config,
        rateLimit: "read",
        preHandler: [gate.moduleEnabled, gate.list],
        schema: {
          tags,
          summary:
            "The generated reports of a workspace (or the tenant-wide ones without workspaceId)",
          querystring: listReportsQuerySchema,
          response: { 200: exportResponses.list },
        },
      },
      controller.list,
    );
    app.get(
      "/reporting/reports/:id",
      {
        config,
        rateLimit: "read",
        preHandler: [gate.moduleEnabled, gate.item],
        schema: {
          tags,
          summary: "One report run: status, never the file",
          params: reportIdParamsSchema,
          response: { 200: exportResponses.one },
        },
      },
      controller.get,
    );
    app.get(
      "/reporting/reports/:id/download",
      {
        config,
        rateLimit: "write",
        preHandler: [gate.moduleEnabled, gate.item],
        schema: {
          tags,
          summary:
            "Download a ready report: an authenticated stream (attachment, no-store, audited); the requester or a report.export holder only",
          params: reportIdParamsSchema,
        },
      },
      controller.download,
    );
    app.delete(
      "/reporting/reports/:id",
      {
        config,
        rateLimit: "write",
        preHandler: [gate.moduleEnabled, gate.item],
        schema: {
          tags,
          summary:
            "Delete a finished report (the requester or a report.export holder; audited; the file is purged)",
          params: reportIdParamsSchema,
          response: { 200: exportResponses.deleted },
        },
      },
      controller.remove,
    );
  };
