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
 * @param {import("fastify").FastifyRequest} request
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

/** Page of items for `reply.paginated`. @param {{ items: any[], totalItems: number }} page @param {{ page: number, pageSize: number }} query */
export const toPage = ({ items, totalItems }, { page, pageSize }) => ({
  items,
  pagination: { page, pageSize, totalItems },
});
