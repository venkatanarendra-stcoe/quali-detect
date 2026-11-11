import { toPage } from "../../../lib/http.js";
import { toPlatformAuditEntryDto } from "../mappers/index.js";

/** @param {{ repository: ReturnType<typeof import("../repositories/index.js").createPlatformAuditLogRepository> }} deps */
export function createPlatformAuditLogService({ repository }) {
  return Object.freeze({
    /** @param {Record<string, any>} query validated query */
    async list(query) {
      const page = await repository.list(query);
      return toPage(
        { items: page.items.map(toPlatformAuditEntryDto), totalItems: page.totalItems },
        query,
      );
    },
  });
}
