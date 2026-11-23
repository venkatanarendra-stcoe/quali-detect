import {
  FindingNotFoundError,
  createFindingExceptionsRepository,
  createFindingReviewsRepository,
  createFindingsRepository,
  withTransaction,
} from "@qmentisai/db";

/**
 * Data access of the findings WRITE routes (Part B: docs/modules/findings/SPEC.md 8.2): the `@qmentisai/db` repositories bound to this
 * module's Prisma client (Prisma stays inside the repository layer), the transaction, and the few reads a write service needs (the
 * locked finding, the review or exception named by the route, the workspace status, the audit row of a refused decision).
 * Every method takes the trusted `{ tenantId, workspaceId }` scope of the request (FS-1): nothing here reaches a row by id alone.
 * @param {{ db: any }} deps
 */
export function createFindingsLifecycleRepository({ db }) {
  const reads = createFindingsRepository({ db });
  const reviews = createFindingReviewsRepository({ db });
  const exceptions = createFindingExceptionsRepository({ db });

  return Object.freeze({
    reads,
    reviews,
    exceptions,

    /** One transaction (the helper of `@qmentisai/db`); everything a write does commits together or not at all. @param {(tx: any) => Promise<any>} fn */
    transaction: (fn) => withTransaction(db, fn, { timeout: 30_000, maxWait: 10_000 }),

    /** Status of the workspace (`active` or `archived`): an archived workspace refuses every mutation (AUTHORIZATION 5.7). */
    async workspaceStatus(tx, scope) {
      const w = await tx.workspace.findFirst({
        where: { tenantId: scope.tenantId, id: scope.workspaceId },
        select: { status: true },
      });
      return w?.status ?? null;
    },

    /**
     * The finding row, LOCKED, by tenant AND workspace AND id. A row of another workspace is the same "not found" as a missing one.
     * @returns {Promise<any>} the Prisma finding row
     */
    async lockFinding(tx, scope, findingId) {
      const row = await reads.getForWrite(scope.tenantId, findingId, { forUpdate: true }, tx);
      if (!row || row.workspaceId !== scope.workspaceId) throw new FindingNotFoundError();
      return row;
    },

    /** A review of THIS finding (tenant, finding and id), or null. */
    findReview: (tx, scope, findingId, reviewId) =>
      tx.findingReview.findFirst({ where: { tenantId: scope.tenantId, findingId, id: reviewId } }),

    /** An exception of THIS finding (tenant, finding and id), or null. */
    findException: (tx, scope, findingId, exceptionId) =>
      tx.findingException.findFirst({
        where: { tenantId: scope.tenantId, findingId, id: exceptionId },
      }),

    /** The display name of a tenant member (the DTO's `{ id, displayName }`), or the neutral "Former member". */
    async displayNameOf(tenantId, userId) {
      const row = await db.tenantMembership.findFirst({
        where: { tenantId, userId },
        select: { user: { select: { name: true } } },
      });
      return row?.user.name ?? "Former member";
    },

    /**
     * For a page of the Approvals queue: finding id to the users who may NOT decide on it (every reviewer of any round and every
     * exception requester, SPEC SOD-1), so `canDecide` is computed per caller without one query per row.
     * @returns {Promise<Map<string, string[]>>}
     */
    async sodUserIdsByFinding(scope, findingIds) {
      if (findingIds.length === 0) return new Map();
      const where = {
        tenantId: scope.tenantId,
        workspaceId: scope.workspaceId,
        findingId: { in: findingIds },
      };
      const [reviewers, requesters] = await Promise.all([
        db.findingReview.findMany({ where, select: { findingId: true, reviewerUserId: true } }),
        db.findingException.findMany({
          where,
          select: { findingId: true, requestedByUserId: true },
        }),
      ]);
      /** @type {Map<string, Set<string>>} */
      const sets = new Map();
      const add = (id, user) => (sets.get(id) ?? sets.set(id, new Set()).get(id)).add(user);
      for (const r of reviewers) add(r.findingId, r.reviewerUserId);
      for (const r of requesters) add(r.findingId, r.requestedByUserId);
      return new Map([...sets].map(([id, set]) => [id, [...set]]));
    },

    /**
     * What the approver-hint check needs: the user, the tenant and the active membership (null when the user is not an active
     * member of this tenant). The permissions are resolved by the central authorization engine.
     */
    async memberContext(tenantId, userId) {
      const membership = await db.tenantMembership.findFirst({
        where: { tenantId, userId, status: "active" },
        select: { id: true, status: true, user: { select: { id: true, status: true } } },
      });
      if (!membership) return null;
      const tenant = await db.tenant.findUnique({
        where: { id: tenantId },
        select: { id: true, status: true },
      });
      if (!tenant) return null;
      return {
        user: { id: membership.user.id, status: membership.user.status },
        tenant,
        membership: { status: membership.status },
      };
    },

    /**
     * The audit row of a REFUSED decision (`finding.approval_denied`, SPEC SOD-4): written OUTSIDE the failed transaction, so it
     * survives the rollback. Ids and enums only, both user ids and the decision id.
     * @param {{ tenantId: string, workspaceId: string }} scope
     * @param {{ approverUserId: string, findingId: string, decisionId: string | null, kind: "review" | "exception", reason: string, counterpartUserId?: string | null, requestId?: string, ip?: string }} entry
     */
    async recordApprovalDenied(scope, entry) {
      await db.auditLog.create({
        data: {
          tenantId: scope.tenantId,
          actorType: "user",
          actorUserId: entry.approverUserId,
          action: "finding.approval_denied",
          targetType: "finding",
          targetId: entry.findingId,
          workspaceId: scope.workspaceId,
          metadata: {
            reason: entry.reason,
            kind: entry.kind,
            decisionId: entry.decisionId,
            approverUserId: entry.approverUserId,
            counterpartUserId: entry.counterpartUserId ?? null,
            ...(entry.requestId ? { requestId: entry.requestId } : {}),
          },
          ...(entry.ip ? { ipAddress: entry.ip } : {}),
        },
      });
    },
  });
}
