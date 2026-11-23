import { createFindingsRepository } from "@qmentisai/db";

/**
 * Data access of the findings read routes: the reads of `@qmentisai/db` (Prisma stays inside that package), bound to this module's
 * Prisma client. Every method takes the trusted `{ tenantId, workspaceId }` scope (docs/modules/findings/SPEC.md FS-1).
 * @param {{ db: any }} deps
 */
export const createFindingsReadRepository = ({ db }) => createFindingsRepository({ db });
