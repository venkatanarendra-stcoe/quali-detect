import { ERROR_CODES } from "@qmentisai/contracts";
import { USABLE_TENANT_STATUSES } from "../../../auth/context.js";
import { AppError, NotFoundError } from "../../../errors/app-error.js";
import { PROVIDER_ID } from "../constants/index.js";
import { toMembershipDto, toSessionDto, toTenantDto, toUserDto } from "../mappers/index.js";
import { identityPolicy } from "../policies/index.js";

const INVALID_CREDENTIALS = "The email or password is incorrect.";

/**
 * Identity use cases: sign in/out, profile, tenant selection. HTTP-free (no request/reply objects).
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/index.js").createIdentityRepository>,
 *   auth: any,
 *   authz: ReturnType<typeof import("../../../authz/service.js").createAuthzService>,
 *   audit: ReturnType<typeof import("../../../audit/audit-service.js").createAuditService>,
 *   clock?: () => Date,
 * }} deps
 */
export function createIdentityService({
  repository,
  auth,
  authz,
  audit,
  clock = () => new Date(),
}) {
  const usable = (tenant) => USABLE_TENANT_STATUSES.includes(tenant.status);
  return Object.freeze({
    /**
     * Authenticates and starts a session. Every failure (unknown user, wrong password, inactive account) returns the same
     * 401. A previous session presented by the browser is revoked and a NEW token is issued (no session fixation).
     * The initial active tenant is the user's only usable tenant, or none when there are several (the user picks one).
     * @param {{ email: string, password: string, ip: string, userAgent?: string, requestId: string, previousSessionId?: string }} input
     */
    async login({ email, password, ip, userAgent, requestId, previousSessionId }) {
      identityPolicy.assertProviderAvailable(auth.providers, PROVIDER_ID);
      await auth.throttles.tenant.check({ ip, identifier: email });
      const result = await auth.providers
        .get(PROVIDER_ID)
        .authenticate({ audience: "tenant", identifier: email, secret: password });
      if (!result) {
        await auth.throttles.tenant.recordFailure({ ip, identifier: email });
        throw new AppError(ERROR_CODES.UNAUTHENTICATED, INVALID_CREDENTIALS);
      }
      await auth.throttles.tenant.recordSuccess({ identifier: email });

      if (previousSessionId) await auth.sessions.tenant.revoke(previousSessionId);
      const tenants = (await repository.listActiveTenants({ userId: result.subjectId })).filter(
        usable,
      );
      const tenant = tenants.length === 1 ? tenants[0] : null;
      const { token, session } = await auth.sessions.tenant.issue({
        subjectId: result.subjectId,
        activeTenantId: tenant?.id ?? null,
        userAgent,
        authMethod: result.authMethod,
        mfaVerifiedAt: result.mfaVerifiedAt,
      });
      await repository.touchLastLogin({ userId: result.subjectId, at: clock() });
      const user = await repository.findUser({ userId: result.subjectId });
      if (tenant)
        await auth.audit.tenant({
          tenantId: tenant.id,
          actorUserId: user.id,
          action: "auth.login",
          metadata: { authMethod: result.authMethod },
          correlationId: requestId,
          ipAddress: ip,
        });
      return {
        token,
        session,
        user: toUserDto(user),
        tenant: tenant ? toTenantDto(tenant) : null,
        tenants: tenants.map(toTenantDto),
        requiresTenantSelection: tenants.length > 1,
      };
    },

    /** Revokes the session (idempotent). @param {{ session: any | null, requestId: string, ip: string }} input */
    async logout({ session, requestId, ip }) {
      if (!session) return;
      await auth.sessions.tenant.revoke(session.id);
      if (session.activeTenantId)
        await auth.audit.tenant({
          tenantId: session.activeTenantId,
          actorUserId: session.userId,
          action: "auth.logout",
          correlationId: requestId,
          ipAddress: ip,
        });
    },

    /**
     * The signed-in user, the active tenant (when the session has one) and effective permissions per scope.
     * @param {{ principal: { user: any, session: any, tenant?: any, membership?: any } }} input
     */
    async getMe({ principal }) {
      const { user, session, tenant, membership } = principal;
      const permissions = tenant
        ? await authz.resolveFor({ user, tenant, membership })
        : { tenant: [], allWorkspaces: [], workspaces: [] };
      return {
        user: toUserDto(user),
        tenant: tenant ? toTenantDto(tenant) : null,
        membership: membership ? toMembershipDto(membership) : null,
        permissions,
        session: toSessionDto(session),
      };
    },

    /**
     * Effective permissions in the session's tenant, optionally for one workspace. Advisory for the UI; the backend
     * enforces every request independently.
     * @param {{ principal: { user: any, tenant: any, membership: any }, workspaceId?: string }} input
     */
    async getMyPermissions({ principal: { user, tenant, membership }, workspaceId }) {
      return authz.resolveFor({ user, tenant, membership }, workspaceId);
    },

    /** Pending invitations of the signed-in user. @param {{ userId: string }} input */
    async listInvitations({ userId }) {
      return (await repository.listInvitedTenants({ userId })).map(toTenantDto);
    },

    /**
     * The invitee accepts: the membership becomes active (only then do assignments and group membership matter).
     * Invitations of unusable tenants cannot be accepted; anything that is not a pending invitation of this user is a 404.
     * @param {{ userId: string, tenantId: string, requestId: string, ip: string }} input
     */
    async acceptInvitation({ userId, tenantId, requestId, ip }) {
      const tenant = await repository.findInvitedTenant({ userId, tenantId });
      if (!tenant) throw new NotFoundError();
      if (!usable(tenant)) {
        throw new AppError(ERROR_CODES.TENANT_SUSPENDED, "This tenant is not active.", {
          details: { reason: tenant.status },
        });
      }
      await repository.transaction(async (tx) => {
        if ((await repository.acceptInvitation({ userId, tenantId, at: clock() }, tx)) === 0)
          throw new NotFoundError();
        await audit.tenant.record(
          {
            tenantId,
            actorUserId: userId,
            action: "user.invitation_accepted",
            targetType: "user",
            targetId: userId,
            correlationId: requestId,
            ipAddress: ip,
          },
          { tx },
        );
      });
      return { tenant: toTenantDto(tenant) };
    },

    /** Tenants the user can switch to (active memberships; suspended ones are listed with their status). @param {{ userId: string }} input */
    async listTenants({ userId }) {
      return (await repository.listActiveTenants({ userId })).map(toTenantDto);
    },

    /**
     * Switches the session's active tenant. Requires an ACTIVE membership in the target (otherwise 404, indistinguishable from a
     * missing tenant) and a usable tenant. Permissions are re-resolved from the new tenant on the next request.
     * @param {{ session: any, userId: string, tenantId: string, requestId: string, ip: string }} input
     */
    async switchTenant({ session, userId, tenantId, requestId, ip }) {
      const membership = await repository.findActiveMembership({ tenantId, userId });
      const tenant = membership ? await repository.findTenant({ tenantId }) : null;
      if (!tenant) throw new NotFoundError();
      if (!usable(tenant))
        throw new AppError(ERROR_CODES.TENANT_SUSPENDED, "This tenant is not active.", {
          details: { reason: tenant.status },
        });
      await auth.sessions.tenant.setActiveTenant(session.id, tenant.id);
      await auth.audit.tenant({
        tenantId: tenant.id,
        actorUserId: userId,
        action: "auth.tenant_switched",
        metadata: { from: session.activeTenantId },
        correlationId: requestId,
        ipAddress: ip,
      });
      return { tenant: toTenantDto(tenant) };
    },
  });
}
