import { notImplemented } from "./not-implemented.js";

/**
 * @typedef {import("./transitions.js").FindingScope} FindingScope
 * @typedef {{ cursor?: string, limit?: number }} KeysetPage
 * @typedef {{ items: object[], totalItems?: number, nextCursor?: string | null }} Page
 */

/**
 * Finding reads and the row repository (Part A1). Every function takes a trusted `FindingScope` and reaches rows by tenant AND
 * workspace AND id, never by id alone (FS-1). Results are plain records; the DTO mappers live in the API module.
 * @param {{ db: any }} deps
 */
export function createFindingsRepository({ db }) {
  void db;
  return Object.freeze({
    /** `GET /findings`: the filters and sort of `listFindingsQuerySchema`; numbered or keyset pagination. @type {(scope: FindingScope, query: object, caller: { userId: string }) => Promise<Page>} */
    list: notImplemented("A1", "findings.list"),
    /** `GET /findings/summary`: counts only. @type {(scope: FindingScope, caller: { userId: string }) => Promise<object>} */
    summary: notImplemented("A1", "findings.summary"),
    /** One finding with its evidence, pipeline, repository and current decision rows, or null. @type {(scope: FindingScope, findingId: string) => Promise<object | null>} */
    getDetail: notImplemented("A1", "findings.getDetail"),
    /** The row for a write service by TENANT and id (the workspace is then authorized), locked when `forUpdate`; null when absent. @type {(tenantId: string, findingId: string, options?: { forUpdate?: boolean }, tx?: any) => Promise<object | null>} */
    getForWrite: notImplemented("A1", "findings.getForWrite"),
    /** The merged timeline, keyset paged. @type {(scope: FindingScope, findingId: string, page: KeysetPage) => Promise<{ items: object[], nextCursor: string | null }>} */
    history: notImplemented("A1", "findings.history"),
    /** Comments, keyset paged. @type {(scope: FindingScope, findingId: string, page: KeysetPage) => Promise<{ items: object[], nextCursor: string | null }>} */
    comments: notImplemented("A1", "findings.comments"),
    /** Findings with the same correlation key in OTHER pipelines of the workspace, at most 20, links only. @type {(scope: FindingScope, findingId: string) => Promise<object[]>} */
    similar: notImplemented("A1", "findings.similar"),
    /** `GET /review-queue`. @type {(scope: FindingScope, query: object) => Promise<Page>} */
    reviewQueue: notImplemented("A1", "findings.reviewQueue"),
  });
}
