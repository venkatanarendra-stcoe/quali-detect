import { AUDIT_KEY_SPECS, rangeWhere, resultWhere } from "../../../lib/audit-view.js";
import { findKeysetPage, keyTerms } from "../../../lib/keyset.js";

/** Tie-breaker of the platform audit order: newest id first, as before cursor pagination. */
export const PLATFORM_AUDIT_TIE = "desc";

/**
 * Read access to the PLATFORM audit log (platform actions such as tenant lifecycle and platform sign-in). It never reads a
 * tenant's own audit log. Append-only; this repository never writes it.
 * @param {{ db: any }} deps
 */
export function createPlatformAuditLogRepository({ db }) {
  return Object.freeze({
    /** @param {Record<string, any>} input validated query; `terms` and `after` come from `cursorContext` */
    async list({
      actor,
      action,
      from,
      to,
      result,
      tenantId,
      sort,
      page,
      pageSize,
      limit,
      terms,
      after,
    }) {
      const where = {
        ...(actor ? { actorPlatformUserId: actor } : {}),
        ...(action ? { action } : {}),
        ...(tenantId ? { tenantId } : {}),
        ...rangeWhere(from, to),
        ...resultWhere(result),
      };
      return findKeysetPage(db.platformAuditLog, {
        where,
        args: { include: { actor: { select: { name: true, email: true } } } },
        terms: terms ?? keyTerms(sort, AUDIT_KEY_SPECS, PLATFORM_AUDIT_TIE),
        after: after ?? null,
        page,
        pageSize,
        limit,
      });
    },
  });
}
