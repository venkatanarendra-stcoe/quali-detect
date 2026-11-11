import { ConflictError, NotFoundError } from "../../../errors/app-error.js";
import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import { assertCanGrant, targetOfAssignment } from "../../../authz/escalation.js";
import { isUniqueViolation, toPage } from "../../../lib/http.js";
import { toGroupDto, toGroupMemberDto } from "../mappers/index.js";

/**
 * Group use cases. Groups are flat and grant nothing by themselves; adding a member hands them the group's role
 * assignments, so it is subject to the escalation guard.
 * @param {{ repository: ReturnType<typeof import("../repositories/index.js").createGroupRepository>, authz: any, audit: any, clock?: () => Date }} deps
 */
export function createGroupService({ repository, authz, audit, clock = () => new Date() }) {
  const entry = (actor, action, groupId, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "group",
    targetId: groupId,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });
  const nameTaken = () =>
    new ConflictError("A group with this name already exists.", { details: { field: "name" } });
  const requireGroup = async (actor, groupId, client) => {
    const group = await repository.findById({ tenantId: actor.tenantId, id: groupId }, client);
    if (!group) throw new NotFoundError();
    return group;
  };

  return Object.freeze({
    async list(actor, query) {
      const page = await repository.list({ tenantId: actor.tenantId, ...query });
      return toPage({ items: page.items.map(toGroupDto), totalItems: page.totalItems }, query);
    },
    async get(actor, groupId) {
      return toGroupDto(await requireGroup(actor, groupId));
    },
    async create(actor, input) {
      try {
        return toGroupDto(
          await authz.transaction(async (tx) => {
            const group = await repository.create({ tenantId: actor.tenantId, data: input }, tx);
            await audit.tenant.record(
              entry(actor, AUDIT_ACTIONS.GROUP_CREATED, group.id, {
                changes: { after: { name: group.name, description: group.description } },
              }),
              { tx },
            );
            return group;
          }),
        );
      } catch (error) {
        throw isUniqueViolation(error) ? nameTaken() : error;
      }
    },
    async update(actor, groupId, patch) {
      try {
        return toGroupDto(
          await authz.transaction(async (tx) => {
            const before = await requireGroup(actor, groupId, tx);
            const after = await repository.update(
              { tenantId: actor.tenantId, id: groupId, data: patch },
              tx,
            );
            const fields = Object.keys(patch);
            const pick = (g) => Object.fromEntries(fields.map((f) => [f, g[f]]));
            await audit.tenant.record(
              entry(actor, AUDIT_ACTIONS.GROUP_UPDATED, groupId, {
                changes: { before: pick(before), after: pick(after) },
              }),
              { tx },
            );
            return after;
          }),
        );
      } catch (error) {
        throw isUniqueViolation(error) ? nameTaken() : error;
      }
    },
    /** Deleting a group removes the roles its members inherited, so the tenant must keep an administrator. */
    async delete(actor, groupId) {
      return authz.transactionKeepingAdministrator(actor.tenantId, async (tx) => {
        const group = await requireGroup(actor, groupId, tx);
        await repository.delete({ tenantId: actor.tenantId, id: groupId }, tx);
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.GROUP_DELETED, groupId, {
            changes: { before: { name: group.name, memberCount: group._count.members } },
          }),
          { tx },
        );
        return { deleted: true };
      });
    },
    async listMembers(actor, groupId, query) {
      await requireGroup(actor, groupId);
      const page = await repository.listMembers({ tenantId: actor.tenantId, groupId, ...query });
      return toPage(
        { items: page.items.map(toGroupMemberDto), totalItems: page.totalItems },
        query,
      );
    },
    /** Idempotent. The user must have an active tenant membership; the actor must be able to grant the group's roles. */
    async addMember(actor, groupId, userId) {
      return toGroupMemberDto(
        await authz.transaction(async (tx) => {
          await requireGroup(actor, groupId, tx);
          if (!(await repository.findActiveMembership({ tenantId: actor.tenantId, userId }, tx)))
            throw new NotFoundError();
          const assignments = await repository.listLiveAssignments(
            { tenantId: actor.tenantId, groupId, now: clock() },
            tx,
          );
          for (const a of assignments)
            assertCanGrant(actor.permissions, a.permissionKeys, targetOfAssignment(a), {
              self: userId === actor.userId,
            });
          const member = await repository.upsertMember(
            { tenantId: actor.tenantId, groupId, userId, addedByUserId: actor.userId },
            tx,
          );
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.GROUP_MEMBER_ADDED, groupId, { metadata: { userId } }),
            { tx },
          );
          return member;
        }),
      );
    },
    async removeMember(actor, groupId, userId) {
      return authz.transactionKeepingAdministrator(actor.tenantId, async (tx) => {
        await requireGroup(actor, groupId, tx);
        if (
          (await repository.removeMember({ tenantId: actor.tenantId, groupId, userId }, tx)) === 0
        )
          throw new NotFoundError();
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.GROUP_MEMBER_REMOVED, groupId, { metadata: { userId } }),
          { tx },
        );
        return { removed: true };
      });
    },
  });
}
