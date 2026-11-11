import { rangeWhere, resultWhere } from "../../../lib/audit-view.js";
import { toPrismaOrderBy, toPrismaPaging } from "../../../lib/query.js";

/**
 * Read access to the PLATFORM audit log (platform actions such as tenant lifecycle and platform sign-in). It never reads a
 * tenant's own audit log. Append-only; this repository never writes it.
 * @param {{ db: any }} deps
 */
export function createPlatformAuditLogRepository({ db }) {
  return Object.freeze({
    async list({ actor, action, from, to, result, tenantId, sort, page, pageSize }) {
      const where = {
        ...(actor ? { actorPlatformUserId: actor } : {}),
        ...(action ? { action } : {}),
        ...(tenantId ? { tenantId } : {}),
        ...rangeWhere(from, to),
        ...resultWhere(result),
      };
      const [items, totalItems] = await Promise.all([
        db.platformAuditLog.findMany({
          where,
          include: { actor: { select: { name: true, email: true } } },
          orderBy: [...toPrismaOrderBy(sort), { id: "desc" }],
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.platformAuditLog.count({ where }),
      ]);
      return { items, totalItems };
    },
  });
}
