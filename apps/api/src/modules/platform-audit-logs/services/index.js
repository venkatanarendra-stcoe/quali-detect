import { AUDIT_KEY_SPECS } from "../../../lib/audit-view.js";
import { toPage } from "../../../lib/http.js";
import { cursorContext } from "../../../lib/keyset.js";
import { toPlatformAuditEntryDto } from "../mappers/index.js";
import { PLATFORM_AUDIT_TIE } from "../repositories/index.js";

/** @param {{ repository: ReturnType<typeof import("../repositories/index.js").createPlatformAuditLogRepository> }} deps */
export function createPlatformAuditLogService({ repository }) {
  return Object.freeze({
    /** @param {{ platformUserId: string }} actor trusted platform principal @param {Record<string, any>} query validated query */
    async list(actor, query) {
      const cursor = cursorContext({
        kind: "platform-audit-logs",
        scope: `platform:${actor.platformUserId}`,
        query,
        specs: AUDIT_KEY_SPECS,
        tie: PLATFORM_AUDIT_TIE,
      });
      const page = await repository.list({ ...query, terms: cursor.terms, after: cursor.after });
      return toPage(
        {
          items: page.items.map(toPlatformAuditEntryDto),
          totalItems: page.totalItems,
          ...cursor.next(page),
        },
        query,
      );
    },
  });
}
