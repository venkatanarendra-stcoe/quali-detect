import { ERROR_CODES } from "@qmentisai/contracts";
import { PERMISSION_CATALOG, USABLE_TENANT_STATUSES } from "@qmentisai/shared";
import { AppError, ForbiddenError } from "../errors/app-error.js";
import { readSessionCookie } from "./cookies.js";
import { requiresMfa } from "./mfa-policy.js";

/** Tenant statuses that may use the application. Suspended and deactivated tenants are rejected. */
export { USABLE_TENANT_STATUSES };

const PLATFORM_KEYS = new Set(
  PERMISSION_CATALOG.filter((p) => p.scope === "platform").map((p) => p.key),
);

/**
 * Resolves who is calling and in which tenant. The tenant is derived ONLY from the authenticated session
 * (`session.activeTenantId`); nothing in the request (headers, query, params, body) is ever consulted.
 * @param {{ db: any, config: any, sessions: { tenant: any, platform: any } }} deps
 */
export function createAuthResolvers({ db, config, sessions }) {
  return Object.freeze({
    /**
     * Tenant-audience session -> `{ session, user }`, or null when there is no valid session or the user is not active.
     * @param {import("express").Request} request
     */
    async resolveUserSession(request) {
      const session = await sessions.tenant.resolve(readSessionCookie(request, "tenant", config));
      if (!session) return null;
      const user = await db.user.findUnique({
        where: { id: session.userId },
        select: { id: true, email: true, name: true, status: true },
      });
      if (!user || user.status !== "active") return null;
      if (requiresMfa({ audience: "tenant", subjectId: user.id }) && !session.mfaVerifiedAt) {
        throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Additional verification is required.", {
          details: { reason: "mfa_required" },
        });
      }
      return { session, user };
    },

    /**
     * Tenant context for a resolved user session. Throws 403 when the session has no active tenant
     * (TENANT_CONTEXT_REQUIRED), the tenant is suspended or deactivated (TENANT_SUSPENDED), or the user no longer has an
     * active membership in it (FORBIDDEN).
     * @param {{ session: any, user: any }} principal
     */
    async resolveTenantContext({ session, user }) {
      if (!session.activeTenantId)
        throw new AppError(ERROR_CODES.TENANT_CONTEXT_REQUIRED, "Select a tenant to continue.");
      const tenant = await db.tenant.findUnique({
        where: { id: session.activeTenantId },
        select: { id: true, slug: true, name: true, status: true },
      });
      if (!tenant)
        throw new AppError(ERROR_CODES.TENANT_CONTEXT_REQUIRED, "Select a tenant to continue.");
      if (!USABLE_TENANT_STATUSES.includes(tenant.status)) {
        throw new AppError(ERROR_CODES.TENANT_SUSPENDED, "This tenant is not active.", {
          details: { reason: tenant.status },
        });
      }
      const membership = await db.tenantMembership.findFirst({
        where: { tenantId: tenant.id, userId: user.id, status: "active" },
        select: { id: true, status: true, joinedAt: true },
      });
      if (!membership) throw new ForbiddenError("You do not have access to this tenant.");
      return { tenant, membership };
    },

    /**
     * Platform-audience session -> `{ session, platformUser, role, permissions }` or null. Reads only the platform cookie.
     * @param {import("express").Request} request
     */
    async resolvePlatformContext(request) {
      const session = await sessions.platform.resolve(
        readSessionCookie(request, "platform", config),
      );
      if (!session) return null;
      const platformUser = await db.platformUser.findUnique({
        where: { id: session.platformUserId },
        include: { role: { select: { key: true, name: true, permissions: true } } },
      });
      if (!platformUser || platformUser.status !== "active") return null;
      if (
        requiresMfa({ audience: "platform", subjectId: platformUser.id }) &&
        !session.mfaVerifiedAt
      ) {
        throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Additional verification is required.", {
          details: { reason: "mfa_required" },
        });
      }
      const permissions = platformUser.role.permissions
        .filter((key) => PLATFORM_KEYS.has(key))
        .sort();
      return {
        session,
        platformUser: {
          id: platformUser.id,
          email: platformUser.email,
          name: platformUser.name,
          status: platformUser.status,
        },
        role: { key: platformUser.role.key, name: platformUser.role.name },
        permissions,
      };
    },
  });
}
