import { z } from "zod";

/** Strict params schema of UUID path parameters: `uuidParams("workspaceId", "userId")`. @param {...string} names */
export const uuidParams = (...names) =>
  z.object(Object.fromEntries(names.map((name) => [name, z.string().uuid()]))).strict();

/** Trimmed, non-empty text with a maximum length. @param {number} max */
export const text = (max) => z.string().trim().min(1).max(max);

/** Query parameter for free-text search. */
export const searchText = text(100).optional();

/** Body schema rejecting an empty object (PATCH needs at least one field). @param {import("zod").ZodObject<any>} shape */
export const atLeastOne = (shape) =>
  shape.strict().refine((value) => Object.keys(value).length > 0, {
    message: "At least one field is required.",
  });

/**
 * Trusted context of the caller for services: tenant and user come from the authenticated session, the permissions
 * from the authorization engine. Never build this from request input.
 * @param {import("express").Request} request
 */
export const actorFrom = (request) => ({
  tenantId: request.principal.tenant.id,
  userId: request.principal.user.id,
  permissions: request.authz?.permissions ?? request.principal.permissions,
  requestId: request.id,
  ip: request.ip,
});

/** Whether a Prisma error is a unique-constraint violation. @param {unknown} error */
export const isUniqueViolation = (error) => error?.code === "P2002";

/**
 * Page of items for `reply.paginated`. Cursor-capable lists also pass `hasMore` and `nextCursor` (and may carry `limit` and
 * `cursor` in the query): `limit` replaces `pageSize`, and a cursor request reports page 1 (it has no page number).
 * @param {{ items: any[], totalItems: number, hasMore?: boolean, nextCursor?: string | null }} page
 * @param {{ page: number, pageSize: number, limit?: number, cursor?: string }} query
 */
export const toPage = ({ items, totalItems, hasMore, nextCursor }, query) => ({
  items,
  pagination: {
    page: query.cursor ? 1 : query.page,
    pageSize: query.limit ?? query.pageSize,
    totalItems,
    ...(hasMore === undefined ? {} : { hasMore, nextCursor: nextCursor ?? null }),
  },
});
