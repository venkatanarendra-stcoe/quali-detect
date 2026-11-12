import { can, getPermission } from "@qmentisai/shared";
import { ForbiddenError, NotFoundError } from "../errors/app-error.js";
import { createAuthzRepository } from "../authz/repository.js";
import { pipelineScope, repositoryScope, tenantScope, workspaceScope } from "../authz/scopes.js";
import { createAuthzService } from "../authz/service.js";

/**
 * Enforcement of the central authorization engine (@qmentisai/shared) for tenant routes.
 *
 * `authz.authorize(permissionKey, scopeResolver = scopes.tenant)` returns route middleware:
 * 1. requires a tenant principal (routes declare `config.audience: "tenant"`);
 * 2. loads the target through the resolver, filtered by the session's tenant; nothing found -> 404;
 * 3. workspace scope: a workspace the caller cannot see (no `workspace.view`) -> the same 404;
 * 4. visible but `can()` is false -> 403.
 * It stores `req.authz = { permissions, scope, resource, can }` for the controller. The permission key and the
 * resolver's scope type are checked when the route is registered, so a mismatch fails at startup. The returned
 * middleware carries `.permission` so the route kit can record it in the contract.
 * Role names are never consulted. Collection endpoints of workspace data use `req.authz`/`loadPermissions` to filter
 * instead of failing. The platform surface has its own guard (`auth.requirePlatformPermission`).
 * @param {{ db: any }} deps
 */
export function createAuthorization({ db }) {
  const service = createAuthzService({ repository: createAuthzRepository({ db }) });
  const scopes = Object.freeze({
    tenant: tenantScope,
    workspace: workspaceScope,
    repository: repositoryScope,
    pipeline: pipelineScope,
  });

  /** Effective permissions of the request's principal (resolved once per request). */
  async function loadPermissions(req) {
    const principal = req.principal;
    if (!principal?.tenant)
      throw new TypeError(
        'loadPermissions requires a tenant principal (config.audience: "tenant").',
      );
    principal.permissions ??= await service.resolveFor({
      user: principal.user,
      tenant: principal.tenant,
      membership: principal.membership,
    });
    return principal.permissions;
  }

  function authorize(permissionKey, scopeResolver = tenantScope) {
    const catalogScope = getPermission(permissionKey)?.scope;
    if (!catalogScope || catalogScope === "platform")
      throw new TypeError(`"${permissionKey}" is not a tenant or workspace permission.`);
    if (catalogScope !== scopeResolver.scopeType) {
      throw new TypeError(
        `"${permissionKey}" is a ${catalogScope}-scope permission; use a ${catalogScope} scope resolver.`,
      );
    }
    return Object.assign(
      async function authorizeMiddleware(req, _res, next) {
        const permissions = await loadPermissions(req);
        const tenantId = req.principal.tenant.id;
        const target = await scopeResolver.resolve(req, { tenantId, db });
        if (!target) throw new NotFoundError();
        if (
          target.scope.type === "workspace" &&
          !permissions.workspaces.some((w) => w.id === target.scope.workspaceId)
        ) {
          req.log.info({ reason: "workspace_not_visible" }, "authorization: resource hidden");
          throw new NotFoundError();
        }
        if (!can(permissions, permissionKey, target.scope)) {
          req.log.info({ permissionKey, scope: target.scope }, "authorization: permission denied");
          throw new ForbiddenError();
        }
        req.authz = Object.freeze({
          permissions,
          scope: target.scope,
          resource: target.resource,
          can: (key, scope) => can(permissions, key, scope),
        });
        next();
      },
      { permission: permissionKey },
    );
  }

  /** Middleware for collection endpoints of workspace data: loads permissions without requiring one (callers filter). */
  async function context(req, _res, next) {
    const permissions = await loadPermissions(req);
    req.authz = Object.freeze({
      permissions,
      scope: { type: "tenant" },
      resource: null,
      can: (key, scope) => can(permissions, key, scope),
    });
    next();
  }

  return Object.freeze({ authorize, context, scopes, loadPermissions, service });
}
