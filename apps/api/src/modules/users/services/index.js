import { ConflictError, NotFoundError } from "../../../errors/app-error.js";
import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import { toPage } from "../../../lib/http.js";
import { ENTITLEMENT_KEYS } from "../../../entitlements/keys.js";
import { toUserDto } from "../mappers/index.js";
import { userPolicy } from "../policies/index.js";

/**
 * User use cases (tenant view = membership). Invitations need the invitee's acceptance (`POST /me/invitations/{tenantId}/accept`)
 * before any access exists, which also keeps invitations from revealing whether an email already has an account.
 * @param {{ repository: ReturnType<typeof import("../repositories/index.js").createUserRepository>, authz: any, audit: any, entitlements: any }} deps
 */
export function createUserService({ repository, authz, audit, entitlements }) {
  const entry = (actor, action, userId, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "user",
    targetId: userId,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });
  async function requireMembership(actor, userId, client) {
    const membership = await repository.findMembership(
      { tenantId: actor.tenantId, userId },
      client,
    );
    if (!membership || membership.status === "removed") throw new NotFoundError();
    return membership;
  }

  return Object.freeze({
    async list(actor, query) {
      const page = await repository.list({ tenantId: actor.tenantId, ...query });
      return toPage({ items: page.items.map(toUserDto), totalItems: page.totalItems }, query);
    },
    async get(actor, userId) {
      return toUserDto(await requireMembership(actor, userId));
    },
    /** @param {any} actor @param {{ email: string, name: string }} input */
    async invite(actor, { email, name }) {
      return toUserDto(
        await authz.transaction(async (tx) => {
          await repository.lockSeats(actor.tenantId, tx);
          const user = await repository.upsertUser({ email, name }, tx);
          const existing = await repository.findMembership(
            { tenantId: actor.tenantId, userId: user.id },
            tx,
          );
          if (existing && existing.status !== "removed") {
            throw new ConflictError("This person is already a member or has a pending invitation.");
          }
          await entitlements.assertWithinLimit({
            tenantId: actor.tenantId,
            key: ENTITLEMENT_KEYS.USERS_MAX,
            currentCount: await repository.countSeats({ tenantId: actor.tenantId }, tx),
          });
          const invited = await repository.invite(
            { tenantId: actor.tenantId, userId: user.id, invitedByUserId: actor.userId },
            tx,
          );
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.USER_INVITED, user.id, { metadata: { email } }),
            { tx },
          );
          return invited;
        }),
      );
    },
    /** Suspend or reactivate an ACTIVE/SUSPENDED member. Invited members cannot be activated by the tenant. */
    async setStatus(actor, userId, status) {
      userPolicy.assertNotSelf(actor, userId);
      return toUserDto(
        await authz.transactionKeepingAdministrator(actor.tenantId, async (tx) => {
          const current = await requireMembership(actor, userId, tx);
          const from = status === "suspended" ? ["active"] : ["suspended"];
          if (!from.includes(current.status)) {
            throw new ConflictError(`A ${current.status} member cannot become ${status}.`, {
              details: { from: current.status, to: status },
            });
          }
          await repository.transition({ tenantId: actor.tenantId, userId, from, to: status }, tx);
          await audit.tenant.record(
            entry(
              actor,
              status === "suspended" ? AUDIT_ACTIONS.USER_SUSPENDED : AUDIT_ACTIONS.USER_ACTIVATED,
              userId,
              { changes: { before: { status: current.status }, after: { status } } },
            ),
            { tx },
          );
          return repository.findMembership({ tenantId: actor.tenantId, userId }, tx);
        }),
      );
    },
    /** Ends the membership (also cancels a pending invitation) and removes everything it granted. */
    async remove(actor, userId) {
      userPolicy.assertNotSelf(actor, userId);
      return authz.transactionKeepingAdministrator(actor.tenantId, async (tx) => {
        const current = await requireMembership(actor, userId, tx);
        await repository.removeMembership({ tenantId: actor.tenantId, userId }, tx);
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.USER_REMOVED, userId, {
            changes: { before: { status: current.status } },
          }),
          { tx },
        );
        return { removed: true };
      });
    },
    /** Explainable resolution (docs/AUTHORIZATION.md §8): effective permissions and the assignments behind them. */
    async explainPermissions(actor, tenant, userId, workspaceId) {
      const membership = await requireMembership(actor, userId);
      return authz.explainFor({ user: membership.user, tenant, membership }, workspaceId);
    },
  });
}
