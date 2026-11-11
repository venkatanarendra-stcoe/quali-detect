import { rangeWhere, resultWhere } from "../../../lib/audit-view.js";
import { toPrismaOrderBy, toPrismaPaging } from "../../../lib/query.js";

/**
 * Read access to a tenant's audit log. EVERY query carries the tenantId of the session; the audit table is append-only
 * (database triggers), this repository never writes it.
 * @param {{ db: any }} deps
 */
export function createAuditLogRepository({ db }) {
  return Object.freeze({
    async list({ tenantId, actor, action, from, to, result, sort, page, pageSize }) {
      const where = {
        tenantId,
        ...(actor ? { actorUserId: actor } : {}),
        ...(action ? { action } : {}),
        ...rangeWhere(from, to),
        ...resultWhere(result),
      };
      const [items, totalItems] = await Promise.all([
        db.auditLog.findMany({
          where,
          include: { actor: { select: { name: true, email: true } } },
          orderBy: [...toPrismaOrderBy(sort), { id: "desc" }],
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.auditLog.count({ where }),
      ]);
      return { items, totalItems };
    },
  });
}
