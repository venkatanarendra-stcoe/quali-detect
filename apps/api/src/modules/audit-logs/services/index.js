import { AUDIT_KEY_SPECS } from "../../../lib/audit-view.js";
import { toPage } from "../../../lib/http.js";
import { cursorContext } from "../../../lib/keyset.js";
import { toAuditEntryDto } from "../mappers/index.js";
import { AUDIT_TIE } from "../repositories/index.js";

/** @param {{ repository: ReturnType<typeof import("../repositories/index.js").createAuditLogRepository> }} deps */
export function createAuditLogService({ repository }) {
  return Object.freeze({
    /** @param {{ tenantId: string }} actor trusted context @param {Record<string, any>} query validated query */
    async list(actor, query) {
      const cursor = cursorContext({
        kind: "audit-logs",
        scope: `tenant:${actor.tenantId}`,
        query,
        specs: AUDIT_KEY_SPECS,
        tie: AUDIT_TIE,
      });
      const page = await repository.list({
        ...query,
        tenantId: actor.tenantId,
        terms: cursor.terms,
        after: cursor.after,
      });
      return toPage(
        {
          items: page.items.map(toAuditEntryDto),
          totalItems: page.totalItems,
          ...cursor.next(page),
        },
        query,
      );
    },
  });
}
