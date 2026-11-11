import { partitionPermissionKeys } from "@qmentisai/shared";

/** @param {any} role role with `permissions` and optional `_count` */
export const toRoleDto = (role) => {
  const keys = role.permissions.map((p) => p.permissionKey);
  const { tenantKeys, workspaceKeys } = partitionPermissionKeys(keys);
  return {
    id: role.id,
    key: role.key,
    name: role.name,
    description: role.description,
    kind: role.kind,
    tenantPermissions: tenantKeys.sort(),
    workspacePermissions: workspaceKeys.sort(),
    assignmentCount: role._count ? role._count.userAssignments + role._count.groupAssignments : 0,
    createdAt: role.createdAt,
    updatedAt: role.updatedAt,
  };
};

/** @param {{ key: string, scope: string, description: string }} permission */
export const toPermissionDto = ({ key, scope, description }) => ({ key, scope, description });
