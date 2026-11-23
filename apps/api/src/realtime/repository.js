/**
 * Data access of the realtime layer (Prisma only here). Every tenant-owned read filters by the trusted tenant id; nothing is
 * looked up by id alone.
 * @param {{ db: any }} deps
 */
export function createRealtimeRepository({ db }) {
  return Object.freeze({
    /** @param {string} id */
    findSession: (id) =>
      db.session.findUnique({
        where: { id },
        select: {
          id: true,
          userId: true,
          activeTenantId: true,
          expiresAt: true,
          revokedAt: true,
          lastSeenAt: true,
        },
      }),
    /** @param {string} id */
    findUser: (id) =>
      db.user.findUnique({
        where: { id },
        select: { id: true, email: true, name: true, status: true },
      }),
    /** @param {string} id */
    findTenant: (id) =>
      db.tenant.findUnique({
        where: { id },
        select: { id: true, slug: true, name: true, status: true },
      }),
    /** @param {{ tenantId: string, userId: string }} input */
    findMembership: ({ tenantId, userId }) =>
      db.tenantMembership.findFirst({
        where: { tenantId, userId, status: "active" },
        select: { id: true, status: true, joinedAt: true },
      }),
    /** @param {{ tenantId: string, id: string }} input */
    findExecution: ({ tenantId, id }) =>
      db.execution.findFirst({
        where: { id, tenantId },
        select: { id: true, tenantId: true, workspaceId: true, pipelineId: true },
      }),
    /** A finding by tenant AND id (the findings room: the room comes from this row, never from a message). @param {{ tenantId: string, id: string }} input */
    findFinding: ({ tenantId, id }) =>
      db.finding.findFirst({
        where: { id, tenantId },
        select: { id: true, tenantId: true, workspaceId: true },
      }),
    /** @param {{ tenantId: string, executionId: string, id: string }} input */
    findTask: ({ tenantId, executionId, id }) =>
      db.scanTask.findFirst({
        where: { id, tenantId, executionId },
        select: { id: true, scanType: true },
      }),
  });
}
