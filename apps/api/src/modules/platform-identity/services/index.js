import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError } from "../../../errors/app-error.js";
import { PROVIDER_ID } from "../constants/index.js";
import { toPlatformSessionDto, toPlatformUserDto } from "../mappers/index.js";

/**
 * Root Console identity use cases. Platform sessions are stored in `platform_sessions` and never grant tenant access.
 * @param {{ repository: ReturnType<typeof import("../repositories/index.js").createPlatformIdentityRepository>, auth: any, clock?: () => Date }} deps
 */
export function createPlatformIdentityService({ repository, auth, clock = () => new Date() }) {
  return Object.freeze({
    /** @param {{ email: string, password: string, ip: string, userAgent?: string, requestId: string, previousSessionId?: string }} input */
    async login({ email, password, ip, userAgent, requestId, previousSessionId }) {
      if (!auth.providers.has(PROVIDER_ID))
        throw new AppError(ERROR_CODES.SERVICE_UNAVAILABLE, "No sign-in method is available.");
      await auth.throttles.platform.check({ ip, identifier: email });
      const result = await auth.providers
        .get(PROVIDER_ID)
        .authenticate({ audience: "platform", identifier: email, secret: password });
      if (!result) {
        await auth.throttles.platform.recordFailure({ ip, identifier: email });
        throw new AppError(ERROR_CODES.UNAUTHENTICATED, "The email or password is incorrect.");
      }
      await auth.throttles.platform.recordSuccess({ identifier: email });
      if (previousSessionId) await auth.sessions.platform.revoke(previousSessionId);
      const { token, session } = await auth.sessions.platform.issue({
        subjectId: result.subjectId,
        userAgent,
        authMethod: result.authMethod,
        mfaVerifiedAt: result.mfaVerifiedAt,
      });
      await repository.touchLastLogin({ platformUserId: result.subjectId, at: clock() });
      await auth.audit.platform({
        actorPlatformUserId: result.subjectId,
        action: "platform.auth.login",
        metadata: { authMethod: result.authMethod },
        correlationId: requestId,
        ipAddress: ip,
      });
      return {
        token,
        session,
        mfaRequired: true,
        platformUser: toPlatformUserDto(
          await repository.findPlatformUser({ platformUserId: result.subjectId }),
        ),
      };
    },
    /**
     * Completes the mandatory second factor. The unverified session is revoked and a NEW verified session is issued
     * (no fixation, and the pre-MFA token never becomes usable). Wrong codes are throttled per user and audited.
     * @param {{ session: any | null, code: string, ip: string, userAgent?: string, requestId: string }} input
     */
    async verifyMfa({ session, code, ip, userAgent, requestId }) {
      const provider = auth.providers.get(PROVIDER_ID);
      if (!provider?.verifyMfa)
        throw new AppError(ERROR_CODES.SERVICE_UNAVAILABLE, "No verification method is available.");
      if (!session) throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Sign in to continue.");
      await auth.throttles.platformMfa.check({ ip, identifier: session.platformUserId });
      const platformUser = await repository.findPlatformUser({
        platformUserId: session.platformUserId,
      });
      if (!platformUser || platformUser.status !== "active")
        throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Sign in to continue.");
      const audit = {
        actorPlatformUserId: session.platformUserId,
        correlationId: requestId,
        ipAddress: ip,
      };
      const verified = await provider.verifyMfa({
        audience: "platform",
        subjectId: session.platformUserId,
        code,
      });
      if (!verified) {
        await auth.throttles.platformMfa.recordFailure({ ip, identifier: session.platformUserId });
        await auth.audit.platform({ ...audit, action: "platform.auth.mfa_failed" });
        throw new AppError(ERROR_CODES.UNAUTHENTICATED, "The verification code is incorrect.", {
          details: { reason: "mfa_invalid" },
        });
      }
      await auth.throttles.platformMfa.recordSuccess({ identifier: session.platformUserId });
      await auth.sessions.platform.revoke(session.id);
      const issued = await auth.sessions.platform.issue({
        subjectId: session.platformUserId,
        userAgent,
        authMethod: session.authMethod,
        mfaVerifiedAt: clock(),
      });
      await auth.audit.platform({ ...audit, action: "platform.auth.mfa_verified" });
      return {
        token: issued.token,
        session: issued.session,
        mfaVerified: true,
        platformUser: toPlatformUserDto(platformUser),
      };
    },
    /** @param {{ session: any | null, requestId: string, ip: string }} input */
    async logout({ session, requestId, ip }) {
      if (!session) return;
      await auth.sessions.platform.revoke(session.id);
      await auth.audit.platform({
        actorPlatformUserId: session.platformUserId,
        action: "platform.auth.logout",
        correlationId: requestId,
        ipAddress: ip,
      });
    },
    /** @param {{ principal: { platform: { platformUser: any, role: any, permissions: string[], session: any } } }} input */
    getMe({ principal: { platform } }) {
      return {
        platformUser: toPlatformUserDto(platform.platformUser),
        role: platform.role,
        permissions: platform.permissions,
        session: toPlatformSessionDto(platform.session),
      };
    },
  });
}
