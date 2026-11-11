import { PERMISSION_CATALOG, partitionPermissionKeys } from "@qmentisai/shared";
import { ERROR_CODES } from "@qmentisai/contracts";
import {
  AppError,
  ConflictError,
  NotFoundError,
  ValidationError,
} from "../../../errors/app-error.js";
import { AUDIT_ACTIONS, diffKeys } from "../../../audit/actions.js";
import { assertCanGrant } from "../../../authz/escalation.js";
import { isUniqueViolation, toPage } from "../../../lib/http.js";
import { toPermissionDto, toRoleDto } from "../mappers/index.js";
import { rolePolicy } from "../policies/index.js";

const slugify = (name) =>
  name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60) || "role";

/**
 * Custom role use cases (docs/AUTHORIZATION.md §5.6, §6.3). A role holds catalog keys of tenant and workspace scope only;
 * the author may include only keys they hold (tenant administrators may include any), nobody may add keys to a role they
 * themselves hold unless they already have them (SOD-3), and every change is audited with a key diff.
 * @param {{ repository: ReturnType<typeof import("../repositories/index.js").createRoleRepository>, authz: any, audit: any, clock?: () => Date }} deps
 */
export function createRoleService({ repository, authz, audit, clock = () => new Date() }) {
  const entry = (actor, action, roleId, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "role",
    targetId: roleId,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });
  const keysOf = (role) => role.permissions.map((p) => p.permissionKey).sort();
  const nameTaken = () =>
    new ConflictError("A role with this name already exists.", { details: { field: "name" } });
  function validateKeys(keys) {
    const { platformKeys, unknownKeys } = partitionPermissionKeys(keys);
    if (platformKeys.length > 0 || unknownKeys.length > 0) {
      throw new ValidationError(
        [
          {
            path: "permissions",
            code: "invalid_permission",
            message: "Roles may only contain tenant and workspace permissions from the catalog.",
          },
        ],
        { source: "body" },
      );
    }
    if (keys.length === 0) {
      throw new ValidationError(
        [
          {
            path: "permissions",
            code: "too_small",
            message: "A role needs at least one permission.",
          },
        ],
        { source: "body" },
      );
    }
  }
  async function requireVisible(actor, roleId, client) {
    const role = await repository.findVisible({ tenantId: actor.tenantId, id: roleId }, client);
    if (!role) throw new NotFoundError();
    return role;
  }

  return Object.freeze({
    /** Read-only permission catalog for role editors (platform permissions are never exposed here). */
    listPermissions: () =>
      PERMISSION_CATALOG.filter((p) => p.scope !== "platform").map(toPermissionDto),

    async list(actor, query) {
      const page = await repository.list({ tenantId: actor.tenantId, ...query });
      return toPage({ items: page.items.map(toRoleDto), totalItems: page.totalItems }, query);
    },
    async get(actor, roleId) {
      return toRoleDto(await requireVisible(actor, roleId));
    },

    /** @param {any} actor @param {{ name: string, description: string, permissions?: string[], cloneFromRoleId?: string }} input */
    async create(actor, input) {
      const source = input.cloneFromRoleId
        ? await requireVisible(actor, input.cloneFromRoleId)
        : null;
      const keys = [...new Set(input.permissions ?? (source ? keysOf(source) : []))].sort();
      validateKeys(keys);
      assertCanGrant(actor.permissions, keys, { scope: "tenant" });
      try {
        const role = await authz.transaction(async (tx) => {
          const created = await repository.create(
            {
              tenantId: actor.tenantId,
              createdByUserId: actor.userId,
              key: slugify(input.name),
              name: input.name,
              description: input.description,
              permissionKeys: keys,
            },
            tx,
          );
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.ROLE_CREATED, created.id, {
              changes: {
                after: { name: created.name, permissions: keys },
                clonedFrom: source?.id ?? null,
              },
            }),
            { tx },
          );
          return created;
        });
        return toRoleDto(role);
      } catch (error) {
        throw isUniqueViolation(error) ? nameTaken() : error;
      }
    },

    /** Edits apply to every holder immediately; removing the last administrator capability is refused (409). */
    async update(actor, roleId, patch) {
      const role = await requireVisible(actor, roleId);
      rolePolicy.assertCustom(role);
      const before = keysOf(role);
      const after = patch.permissions ? [...new Set(patch.permissions)].sort() : before;
      if (patch.permissions) {
        validateKeys(after);
        const { added } = diffKeys(before, after);
        if (added.length > 0) {
          assertCanGrant(actor.permissions, added, { scope: "tenant" });
          // Adding keys to a role you hold would raise your own access: you must already hold them (even administrators).
          if (
            await repository.userHoldsRole({
              tenantId: actor.tenantId,
              userId: actor.userId,
              roleId,
              now: clock(),
            })
          ) {
            assertCanGrant(actor.permissions, added, { scope: "tenant" }, { self: true });
          }
        }
      }
      const data = {
        ...(patch.name ? { name: patch.name } : {}),
        ...(patch.description ? { description: patch.description } : {}),
      };
      try {
        const updated = await authz.transactionKeepingAdministrator(actor.tenantId, async (tx) => {
          const next = await repository.update(
            {
              tenantId: actor.tenantId,
              id: roleId,
              data,
              permissionKeys: patch.permissions ? after : undefined,
            },
            tx,
          );
          if (!next) throw new NotFoundError();
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.ROLE_UPDATED, roleId, {
              changes: {
                ...(patch.name || patch.description
                  ? {
                      before: { name: role.name, description: role.description },
                      after: { name: next.name, description: next.description },
                    }
                  : {}),
                permissions: diffKeys(before, after),
              },
            }),
            { tx },
          );
          return next;
        });
        return toRoleDto(updated);
      } catch (error) {
        throw isUniqueViolation(error) ? nameTaken() : error;
      }
    },

    /** Blocked with 409 ROLE_IN_USE while any assignment exists. */
    async delete(actor, roleId) {
      const role = await requireVisible(actor, roleId);
      rolePolicy.assertCustom(role);
      const inUse = () =>
        new AppError(
          ERROR_CODES.ROLE_IN_USE,
          "The role is still assigned. Reassign or revoke the assignments first.",
        );
      try {
        return await authz.transaction(async (tx) => {
          if ((await repository.countAssignments({ tenantId: actor.tenantId, roleId }, tx)) > 0)
            throw inUse();
          await repository.delete({ tenantId: actor.tenantId, id: roleId }, tx);
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.ROLE_DELETED, roleId, {
              changes: { before: { name: role.name, permissions: keysOf(role) } },
            }),
            { tx },
          );
          return { deleted: true };
        });
      } catch (error) {
        // An assignment created after the count hits the foreign key (ON DELETE RESTRICT).
        throw error?.code === "P2003" ? inUse() : error;
      }
    },
  });
}
