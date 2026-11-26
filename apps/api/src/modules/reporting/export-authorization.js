import { can } from "@qmentisai/shared";
import { ForbiddenError, NotFoundError } from "../../errors/app-error.js";
import { holdsExport } from "./services/export.js";

/**
 * Authorization of the export routes (docs/modules/reporting-dashboards/SPEC.md 3, 9; docs/AUTHORIZATION.md 404 and 403). It composes the
 * CENTRAL engine (`authz.authorize`, `authz.loadPermissions`, the shared `can`) and never reads a role name:
 *  - another tenant's report, a workspace the caller cannot see, a deleted report and a random id all answer the IDENTICAL 404;
 *  - a visible workspace without the key answers 403;
 *  - the module switch (`REPORTING_ENABLED`) answers the same 404 as an unknown route while it is off, before any database access.
 *
 * A tenant-wide report (no workspace) is visible only to a holder of the tenant key `dashboard.view`; it may be requested only by a caller
 * who holds `dashboard.view` AND `report.export` in EVERY workspace of the tenant (the "tenant scope" reading of a workspace key).
 * @param {{ authz: any, exports: any, support: any, config: any }} deps
 */
export function createExportAuthorization({ authz, exports, support, config }) {
  /** First preHandler of every export route: the module is off, so the route does not exist for anyone. */
  const moduleEnabled = Object.assign(
    async function reportingEnabled(_req, _res, next) {
      if (config?.reporting?.enabled !== true) throw new NotFoundError();
      next();
    },
    { permission: null },
  );

  /** Workspace chosen by the BODY (`workspaceId`), loaded by tenant AND id. */
  const bodyWorkspace = Object.freeze({
    scopeType: "workspace",
    async resolve(request, { tenantId, db: client }) {
      const id = request.body?.workspaceId;
      if (typeof id !== "string") return null;
      const workspace = await client.workspace.findFirst({
        where: { tenantId, id },
        select: { id: true },
      });
      return workspace
        ? {
            scope: { type: "workspace", workspaceId: workspace.id },
            resource: { id: workspace.id },
          }
        : null;
    },
  });

  /** Workspace chosen by the QUERY (`workspaceId`), loaded by tenant AND id. */
  const queryWorkspace = Object.freeze({
    scopeType: "workspace",
    async resolve(request, { tenantId, db: client }) {
      const id = request.query?.workspaceId;
      if (typeof id !== "string") return null;
      const workspace = await client.workspace.findFirst({
        where: { tenantId, id },
        select: { id: true },
      });
      return workspace
        ? {
            scope: { type: "workspace", workspaceId: workspace.id },
            resource: { id: workspace.id },
          }
        : null;
    },
  });

  const exportInWorkspace = authz.authorize("report.export", bodyWorkspace);
  const viewInQueryWorkspace = authz.authorize("report.view", queryWorkspace);
  const dashboardView = authz.authorize("dashboard.view");
  const noop = () => {};

  /** `POST /reporting/reports`: `report.export` in the workspace, or the tenant-wide rule. */
  const create = Object.assign(
    async function authorizeCreate(req, res, next) {
      if (req.body?.workspaceId !== undefined) return exportInWorkspace(req, res, next);
      await dashboardView(req, res, noop); // 403 without the tenant key
      const count = await support.workspaceCount(req.principal.tenant.id);
      if (!holdsExport(req.authz.permissions, null, count)) throw new ForbiddenError();
      return next();
    },
    { permission: "report.export" },
  );

  /** `GET /reporting/reports`: `report.view` in the workspace, or (no `workspaceId`) the tenant-wide reports for a `dashboard.view` holder. */
  const list = Object.assign(
    async function authorizeList(req, res, next) {
      if (req.query?.workspaceId !== undefined) return viewInQueryWorkspace(req, res, next);
      return dashboardView(req, res, next);
    },
    { permission: "report.view" },
  );

  /**
   * A report named by the route (`:id`), loaded by TENANT and id: its workspace must be visible to the caller (else the identical 404) and
   * the caller must hold `report.view` there (else 403). The resource handed on is the minimal reference only.
   */
  const item = Object.assign(
    async function authorizeReport(req, _res, next) {
      const permissions = await authz.loadPermissions(req);
      const tenantId = req.principal.tenant.id;
      const row = await exports.getExport({ tenantId, id: req.params.id });
      if (!row || row.deletedAt) throw new NotFoundError();
      let scope;
      if (row.workspaceId) {
        if (!permissions.workspaces.some((w) => w.id === row.workspaceId))
          throw new NotFoundError();
        scope = { type: "workspace", workspaceId: row.workspaceId };
        if (!can(permissions, "report.view", scope)) throw new ForbiddenError();
      } else {
        // a tenant-wide report is not visible without the tenant key
        if (!can(permissions, "dashboard.view")) throw new NotFoundError();
        scope = { type: "tenant" };
      }
      req.authz = Object.freeze({
        permissions,
        scope,
        resource: Object.freeze({ id: row.id, workspaceId: row.workspaceId }),
        can: (key, s) => can(permissions, key, s),
      });
      return next();
    },
    { permission: "report.view" },
  );

  return Object.freeze({ moduleEnabled, create, list, item });
}
