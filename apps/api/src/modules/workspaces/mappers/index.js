/** @param {any} workspace */
export const toWorkspaceDto = (workspace) => ({
  id: workspace.id,
  name: workspace.name,
  description: workspace.description,
  businessUnit: workspace.businessUnit,
  ownerUserId: workspace.ownerUserId,
  ownerName: workspace.owner?.user?.name ?? null,
  memberCount: workspace._count?.members ?? 0,
  status: workspace.status,
  archivedAt: workspace.archivedAt,
  createdAt: workspace.createdAt,
  updatedAt: workspace.updatedAt,
});
