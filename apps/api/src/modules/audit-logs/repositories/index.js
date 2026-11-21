import { rangeWhere, resultWhere } from "../../../lib/audit-view.js";
import { AUDIT_KEY_SPECS } from "../../../lib/audit-view.js";
import { findKeysetPage, keyTerms } from "../../../lib/keyset.js";

/** Tie-breaker of the audit order: newest id first, as before cursor pagination. */
export const AUDIT_TIE = "desc";

/**
 * Read access to a tenant's audit log. EVERY query carries the tenantId of the session; the audit table is append-only
 * (database triggers), this repository never writes it.
 * @param {{ db: any }} deps
 */
export function createAuditLogRepository({ db }) {
  return Object.freeze({
    /** @param {Record<string, any>} input validated query + tenantId; `after` (and `terms`) come from `cursorContext` */
    async list({
      tenantId,
      actor,
      action,
      from,
      to,
      result,
      sort,
      page,
      pageSize,
      limit,
      terms,
      after,
    }) {
      const where = {
        tenantId,
        ...(actor ? { actorUserId: actor } : {}),
        ...(action ? { action } : {}),
        ...rangeWhere(from, to),
        ...resultWhere(result),
      };
      return findKeysetPage(db.auditLog, {
        where,
        args: { include: { actor: { select: { name: true, email: true } } } },
        terms: terms ?? keyTerms(sort, AUDIT_KEY_SPECS, AUDIT_TIE),
        after: after ?? null,
        page,
        pageSize,
        limit,
        db,
        table: "audit_logs",
      });
    },
  });
}
