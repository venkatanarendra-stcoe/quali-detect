import fp from "fastify-plugin";
import { can, getPermission } from "@qmentisai/shared";
import { ForbiddenError, NotFoundError } from "../errors/app-error.js";
import { createAuthzRepository } from "../authz/repository.js";
import { tenantScope, workspaceScope } from "../authz/scopes.js";
import { createAuthzService } from "../authz/service.js";

/**
 * Enforcement of the central authorization engine (@qmentisai/shared) for tenant routes.
 *
 * `app.authz.authorize(permissionKey, scopeResolver = scopes.tenant)` returns a route `preHandler`:
 * 1. requires a tenant principal (routes declare `config.audience: "tenant"`);
 * 2. loads the target through the resolver, filtered by the session's tenant; nothing found -> 404;
 * 3. workspace scope: a workspace the caller cannot see (no `workspace.view`) -> the same 404;
 * 4. visible but `can()` is false -> 403.
 * It stores `request.authz = { permissions, scope, resource, can }` for the controller. The permission key and the
 * resolver's scope type are checked when the route is registered, so a mismatch fails at startup.
 * Role names are never consulted. Collection endpoints of workspace data use `request.authz`/`loadPermissions` to filter
 * instead of failing. The platform surface has its own guard (`app.auth.requirePlatformPermission`).
 */
export default fp(
  async function authorizationPlugin(app) {
    const { db } = app.infra;
    const service = createAuthzService({ repository: createAuthzRepository({ db }) });
    const scopes = Object.freeze({ tenant: tenantScope, workspace: workspaceScope });

    /** Effective permissions of the request's principal (resolved once per request). */
    async function loadPermissions(request) {
      const principal = request.principal;
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
      return async function authorizeHook(request) {
        const permissions = await loadPermissions(request);
        const tenantId = request.principal.tenant.id;
        const target = await scopeResolver.resolve(request, { tenantId, db });
        if (!target) throw new NotFoundError();
        if (
          target.scope.type === "workspace" &&
          !permissions.workspaces.some((w) => w.id === target.scope.workspaceId)
        ) {
          request.log.info({ reason: "workspace_not_visible" }, "authorization: resource hidden");
          throw new NotFoundError();
        }
        if (!can(permissions, permissionKey, target.scope)) {
          request.log.info(
            { permissionKey, scope: target.scope },
            "authorization: permission denied",
          );
          throw new ForbiddenError();
        }
        request.authz = Object.freeze({
          permissions,
          scope: target.scope,
          resource: target.resource,
          can: (key, scope) => can(permissions, key, scope),
        });
      };
    }

    /** preHandler for collection endpoints of workspace data: loads permissions without requiring one (callers filter). */
    async function context(request) {
      const permissions = await loadPermissions(request);
      request.authz = Object.freeze({
        permissions,
        scope: { type: "tenant" },
        resource: null,
        can: (key, scope) => can(permissions, key, scope),
      });
    }

    app.decorate("authz", Object.freeze({ authorize, context, scopes, loadPermissions, service }));
    app.decorateRequest("authz", null);
  },
  { name: "authorization", dependencies: ["authentication"] },
);
