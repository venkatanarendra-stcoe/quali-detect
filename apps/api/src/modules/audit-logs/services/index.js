import { toPage } from "../../../lib/http.js";
import { toAuditEntryDto } from "../mappers/index.js";

/** @param {{ repository: ReturnType<typeof import("../repositories/index.js").createAuditLogRepository> }} deps */
export function createAuditLogService({ repository }) {
  return Object.freeze({
    /** @param {{ tenantId: string }} actor trusted context @param {Record<string, any>} query validated query */
    async list(actor, query) {
      const page = await repository.list({ ...query, tenantId: actor.tenantId });
      return toPage({ items: page.items.map(toAuditEntryDto), totalItems: page.totalItems }, query);
    },
  });
}
