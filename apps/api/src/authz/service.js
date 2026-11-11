import { ERROR_CODES } from "@qmentisai/contracts";
import { resolveEffectivePermissions } from "@qmentisai/shared";
import { AppError } from "../errors/app-error.js";

/**
 * Loads assignments and runs the pure engine from @qmentisai/shared. No caching: permissions are resolved from the
 * database on each request, so a role or assignment change applies to the next request.
 * @param {{ repository: ReturnType<typeof import("./repository.js").createAuthzRepository>, clock?: () => Date }} deps
 */
export function createAuthzService({ repository, clock = () => new Date() }) {
  return Object.freeze({
    /**
     * Effective permissions of `user` in `tenant`, optionally limited to one workspace.
     * @param {{ user: { id: string, status: string }, tenant: { id: string, status: string }, membership: { status: string } | null }} subject
     * @param {string} [workspaceId]
     */
    async resolveFor({ user, tenant, membership }, workspaceId) {
      const now = clock();
      const groupIds = await repository.findGroupIds({ tenantId: tenant.id, userId: user.id });
      const [assignments, workspaces] = await Promise.all([
        repository.findAssignments({ tenantId: tenant.id, userId: user.id, groupIds, now }),
        repository.listWorkspaces({ tenantId: tenant.id }),
      ]);
      return resolveEffectivePermissions(
        { user: { ...user, groupIds }, tenant, membership, assignments, workspaces, now },
        workspaceId,
      );
    },

    /**
     * Explainable resolution for administrators: the effective permissions plus the assignments they come from.
     * @param {{ user: { id: string, status: string }, tenant: { id: string, status: string }, membership: { status: string } | null }} subject
     * @param {string} [workspaceId]
     */
    async explainFor({ user, tenant, membership }, workspaceId) {
      const now = clock();
      const groupIds = await repository.findGroupIds({ tenantId: tenant.id, userId: user.id });
      const [assignments, workspaces] = await Promise.all([
        repository.findAssignments({ tenantId: tenant.id, userId: user.id, groupIds, now }),
        repository.listWorkspaces({ tenantId: tenant.id }),
      ]);
      const permissions = resolveEffectivePermissions(
        { user: { ...user, groupIds }, tenant, membership, assignments, workspaces, now },
        workspaceId,
      );
      return {
        permissions,
        assignments: assignments
          .filter((a) => !workspaceId || a.scopeType === "tenant" || a.workspaceId === workspaceId)
          .map((a) => ({
            id: a.id,
            roleId: a.roleId,
            roleName: a.roleName,
            via: a.subjectType,
            scopeType: a.scopeType,
            workspaceId: a.workspaceId,
            expiresAt: a.expiresAt,
          })),
      };
    },

    /**
     * Runs `fn(tx)` in a transaction that preserves the "tenant always keeps an administrator" invariant (AUTHZ-010):
     * administrator changes of the tenant are serialized, and if the tenant had an administrator before and has none after,
     * everything rolls back with 409 LAST_TENANT_ADMIN.
     * @template T
     * @param {string} tenantId
     * @param {(tx: any) => Promise<T>} fn
     * @returns {Promise<T>}
     */
    transactionKeepingAdministrator(tenantId, fn) {
      return repository.transaction(async (tx) => {
        await repository.lockTenantAdministrators(tenantId, tx);
        const before = await repository.findTenantAdministratorIds({ tenantId, now: clock() }, tx);
        const result = await fn(tx);
        const after = await repository.findTenantAdministratorIds({ tenantId, now: clock() }, tx);
        if (before.size > 0 && after.size === 0) {
          throw new AppError(
            ERROR_CODES.LAST_TENANT_ADMIN,
            "The tenant must keep at least one administrator.",
          );
        }
        return result;
      });
    },

    /**
     * Like `transactionKeepingAdministrator` for one workspace: a workspace that had a workspace administrator assignment
     * (holder of `workspace.manage_members`) must keep one (docs/AUTHORIZATION.md §5.7, Recommended default).
     * @template T
     * @param {{ tenantId: string, workspaceId: string }} scope
     * @param {(tx: any) => Promise<T>} fn
     * @returns {Promise<T>}
     */
    transactionKeepingWorkspaceAdministrator({ tenantId, workspaceId }, fn) {
      return repository.transaction(async (tx) => {
        await repository.lockWorkspaceAdministrators(tenantId, workspaceId, tx);
        const count = () =>
          repository.countWorkspaceAdministratorAssignments(
            { tenantId, workspaceId, now: clock() },
            tx,
          );
        const before = await count();
        const result = await fn(tx);
        if (before > 0 && (await count()) === 0) {
          throw new AppError(
            ERROR_CODES.CONFLICT,
            "The workspace must keep at least one administrator.",
            { details: { reason: "last_workspace_administrator" } },
          );
        }
        return result;
      });
    },

    /** Plain transaction. @template T @param {(tx: any) => Promise<T>} fn @returns {Promise<T>} */
    transaction: (fn) => repository.transaction(fn),
  });
}
