import { partitionPermissionKeys } from "@qmentisai/shared";
import { ConflictError, NotFoundError, ValidationError } from "../../../errors/app-error.js";
import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import { assertCanGrant } from "../../../authz/escalation.js";
import { isUniqueViolation, toPage } from "../../../lib/http.js";
import { toAssignmentDto } from "../mappers/index.js";
import { roleAssignmentPolicy } from "../policies/index.js";

/**
 * Role assignment use cases for tenant scope and workspace scope (docs/AUTHORIZATION.md §5.7, §6.2). Creating or
 * re-enabling an assignment is subject to the escalation guard; revoking must leave the tenant (or workspace) an
 * administrator. `scope` is `{ scopeType: "tenant" }` or `{ scopeType: "workspace", workspace }` (the loaded workspace).
 * @param {{ repository: ReturnType<typeof import("../repositories/index.js").createRoleAssignmentRepository>, authz: any, audit: any, clock?: () => Date }} deps
 */
export function createRoleAssignmentService({
  repository,
  authz,
  audit,
  clock = () => new Date(),
}) {
  const where = (actor, scope) => ({
    tenantId: actor.tenantId,
    scopeType: scope.scopeType,
    workspaceId: scope.workspace?.id,
  });
  const target = (scope) =>
    scope.scopeType === "tenant"
      ? { scope: "tenant" }
      : { scope: "workspace", workspaceId: scope.workspace.id };
  const keysOf = (role) => role.permissions.map((p) => p.permissionKey);
  const entry = (actor, scope, action, id, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "role_assignment",
    targetId: id,
    workspaceId: scope.workspace?.id,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });
  const summary = (kind, row) => ({
    subjectType: kind,
    subjectId: kind === "user" ? row.userId : row.groupId,
    roleId: row.roleId,
    role: row.role.name,
    scopeType: row.scopeType,
    workspaceId: row.workspaceId,
    status: row.status,
    expiresAt: row.expiresAt,
  });
  const guarded = (actor, scope, fn) =>
    scope.scopeType === "tenant"
      ? authz.transactionKeepingAdministrator(actor.tenantId, fn)
      : authz.transactionKeepingWorkspaceAdministrator(
          { tenantId: actor.tenantId, workspaceId: scope.workspace.id },
          fn,
        );
  async function requireAssignment(actor, scope, id, client) {
    const found = await repository.findById({ ...where(actor, scope), id }, client);
    if (!found) throw new NotFoundError();
    return found;
  }
  /** Whether the assignment would reach the actor themselves (their own user, or a group they belong to). */
  async function reachesActor(actor, kind, subjectId, client) {
    return kind === "user"
      ? subjectId === actor.userId
      : repository.isGroupMember(
          { tenantId: actor.tenantId, groupId: subjectId, userId: actor.userId },
          client,
        );
  }

  return Object.freeze({
    async list(actor, scope, query) {
      const page = await repository.list({ ...where(actor, scope), ...query });
      return toPage(
        {
          items: page.items.map(({ kind, row }) => toAssignmentDto(kind, row)),
          totalItems: page.totalItems,
        },
        query,
      );
    },

    /** @param {any} actor @param {any} scope @param {{ subjectType: "user" | "group", subjectId: string, roleId: string, expiresAt?: Date | null }} input */
    async create(actor, scope, input) {
      if (scope.workspace) roleAssignmentPolicy.assertWorkspaceMutable(scope.workspace);
      roleAssignmentPolicy.assertFutureExpiry(input.expiresAt, clock());
      const { subjectType: kind, subjectId } = input;
      try {
        const created = await authz.transaction(async (tx) => {
          const role = await repository.findVisibleRole(
            { tenantId: actor.tenantId, id: input.roleId },
            tx,
          );
          if (!role) throw new NotFoundError();
          const keys = keysOf(role);
          if (
            scope.scopeType === "workspace" &&
            partitionPermissionKeys(keys).workspaceKeys.length === 0
          ) {
            throw new ValidationError(
              [
                {
                  path: "roleId",
                  code: "invalid_role",
                  message: "This role has no workspace-scope permissions to assign in a workspace.",
                },
              ],
              { source: "body" },
            );
          }
          const subjectExists =
            kind === "user"
              ? await repository.findActiveMembership(
                  { tenantId: actor.tenantId, userId: subjectId },
                  tx,
                )
              : await repository.findGroup({ tenantId: actor.tenantId, id: subjectId }, tx);
          if (!subjectExists) throw new NotFoundError();
          assertCanGrant(actor.permissions, keys, target(scope), {
            self: await reachesActor(actor, kind, subjectId, tx),
          });
          const row = await repository.create(
            {
              kind,
              tenantId: actor.tenantId,
              subjectId,
              roleId: role.id,
              scopeType: scope.scopeType,
              workspaceId: scope.workspace?.id,
              expiresAt: input.expiresAt ?? null,
              createdByUserId: actor.userId,
            },
            tx,
          );
          if (kind === "user" && scope.workspace) {
            await repository.ensureWorkspaceMember(
              {
                tenantId: actor.tenantId,
                workspaceId: scope.workspace.id,
                userId: subjectId,
                addedByUserId: actor.userId,
              },
              tx,
            );
          }
          await audit.tenant.record(
            entry(actor, scope, AUDIT_ACTIONS.ROLE_ASSIGNMENT_CREATED, row.id, {
              changes: { after: summary(kind, row) },
            }),
            { tx },
          );
          return { kind, row };
        });
        return toAssignmentDto(created.kind, created.row);
      } catch (error) {
        if (isUniqueViolation(error))
          throw new ConflictError("This role is already assigned to the subject in this scope.");
        throw error;
      }
    },

    /** Change status (suspend/reactivate) or expiry. Anything that grants more (reactivate, extend) is escalation-checked again. */
    async update(actor, scope, id, patch) {
      if (scope.workspace) roleAssignmentPolicy.assertWorkspaceMutable(scope.workspace);
      if (patch.expiresAt) roleAssignmentPolicy.assertFutureExpiry(patch.expiresAt, clock());
      const updated = await guarded(actor, scope, async (tx) => {
        const { kind, row } = await requireAssignment(actor, scope, id, tx);
        const extends_ =
          (patch.status === "active" && row.status !== "active") ||
          (patch.expiresAt === null && row.expiresAt !== null) ||
          (patch.expiresAt && row.expiresAt && patch.expiresAt > row.expiresAt);
        if (extends_) {
          const subjectId = kind === "user" ? row.userId : row.groupId;
          assertCanGrant(actor.permissions, keysOf(row.role), target(scope), {
            self: await reachesActor(actor, kind, subjectId, tx),
          });
        }
        const next = await repository.update(
          {
            kind,
            tenantId: actor.tenantId,
            id,
            data: {
              ...(patch.status ? { status: patch.status } : {}),
              ...("expiresAt" in patch ? { expiresAt: patch.expiresAt } : {}),
            },
          },
          tx,
        );
        await audit.tenant.record(
          entry(actor, scope, AUDIT_ACTIONS.ROLE_ASSIGNMENT_UPDATED, id, {
            changes: {
              before: { status: row.status, expiresAt: row.expiresAt },
              after: { status: next.status, expiresAt: next.expiresAt },
            },
          }),
          { tx },
        );
        return { kind, row: next };
      });
      return toAssignmentDto(updated.kind, updated.row);
    },

    async revoke(actor, scope, id) {
      if (scope.workspace) roleAssignmentPolicy.assertWorkspaceMutable(scope.workspace);
      return guarded(actor, scope, async (tx) => {
        const { kind, row } = await requireAssignment(actor, scope, id, tx);
        await repository.delete({ kind, tenantId: actor.tenantId, id }, tx);
        await audit.tenant.record(
          entry(actor, scope, AUDIT_ACTIONS.ROLE_ASSIGNMENT_REVOKED, id, {
            changes: { before: summary(kind, row) },
          }),
          { tx },
        );
        return { revoked: true };
      });
    },
  });
}
