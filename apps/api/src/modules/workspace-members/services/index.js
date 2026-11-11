import { NotFoundError } from "../../../errors/app-error.js";
import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import { toPage } from "../../../lib/http.js";
import { toWorkspaceMemberDto } from "../mappers/index.js";
import { workspaceMemberPolicy } from "../policies/index.js";

/**
 * Workspace roster use cases. A roster entry grants nothing by itself; access comes from role assignments.
 * @param {{ repository: ReturnType<typeof import("../repositories/index.js").createWorkspaceMemberRepository>, authz: any, audit: any }} deps
 */
export function createWorkspaceMemberService({ repository, authz, audit }) {
  const entry = (actor, workspace, action, userId, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "user",
    targetId: userId,
    workspaceId: workspace.id,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });
  return Object.freeze({
    async list(actor, workspace, query) {
      const page = await repository.list({
        tenantId: actor.tenantId,
        workspaceId: workspace.id,
        ...query,
      });
      return toPage(
        { items: page.items.map(toWorkspaceMemberDto), totalItems: page.totalItems },
        query,
      );
    },
    /** Adds (or reactivates) a member. The user must have an ACTIVE membership in the actor's tenant, else 404. */
    async add(actor, workspace, userId) {
      workspaceMemberPolicy.assertWorkspaceMutable(workspace);
      return toWorkspaceMemberDto(
        await authz.transaction(async (tx) => {
          if (!(await repository.findActiveMembership({ tenantId: actor.tenantId, userId }, tx)))
            throw new NotFoundError();
          const member = await repository.upsert(
            {
              tenantId: actor.tenantId,
              workspaceId: workspace.id,
              userId,
              addedByUserId: actor.userId,
            },
            tx,
          );
          await audit.tenant.record(
            entry(actor, workspace, AUDIT_ACTIONS.WORKSPACE_MEMBER_ADDED, userId),
            { tx },
          );
          return member;
        }),
      );
    },
    /** Removes a member and their direct workspace-scope assignments; the workspace must keep an administrator. */
    async remove(actor, workspace, userId) {
      workspaceMemberPolicy.assertWorkspaceMutable(workspace);
      return authz.transactionKeepingWorkspaceAdministrator(
        { tenantId: actor.tenantId, workspaceId: workspace.id },
        async (tx) => {
          if (
            (await repository.remove(
              { tenantId: actor.tenantId, workspaceId: workspace.id, userId },
              tx,
            )) === 0
          )
            throw new NotFoundError();
          const revokedAssignments = await repository.revokeWorkspaceAssignments(
            { tenantId: actor.tenantId, workspaceId: workspace.id, userId },
            tx,
          );
          await audit.tenant.record(
            entry(actor, workspace, AUDIT_ACTIONS.WORKSPACE_MEMBER_REMOVED, userId, {
              changes: { revokedAssignments },
            }),
            { tx },
          );
          return { removed: true, revokedAssignments };
        },
      );
    },
  });
}
