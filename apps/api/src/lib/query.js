import { z } from "zod";
import { cursorQueryShape } from "./keyset.js";

/**
 * Collection endpoint helpers: explicit pagination, allow-listed sorting and declared filters.
 * Query format: `?page=1&pageSize=25&sort=name:asc,createdAt:desc&<filters>`. Unknown parameters are rejected.
 */

export const DEFAULT_PAGE_SIZE = 25;
export const MAX_PAGE_SIZE = 100;

/**
 * Zod shape for `page` and `pageSize`.
 * @param {{ defaultPageSize?: number, maxPageSize?: number }} [options]
 */
export function paginationShape({
  defaultPageSize = DEFAULT_PAGE_SIZE,
  maxPageSize = MAX_PAGE_SIZE,
} = {}) {
  return {
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(maxPageSize).default(defaultPageSize),
  };
}

/**
 * Zod schema for `sort`: comma separated `field` or `field:asc|desc`, restricted to `sortableFields`.
 * @param {readonly string[]} sortableFields
 * @param {Array<{ field: string, direction: "asc" | "desc" }>} defaultSort
 */
export function sortSchema(sortableFields, defaultSort) {
  return z
    .string()
    .max(200)
    .optional()
    .transform((value, ctx) => {
      if (!value) return defaultSort;
      const sort = [];
      for (const part of value.split(",")) {
        const [field, direction = "asc", ...rest] = part.split(":");
        if (
          rest.length > 0 ||
          !sortableFields.includes(field) ||
          !["asc", "desc"].includes(direction) ||
          sort.some((s) => s.field === field)
        ) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `Sort must use ${sortableFields.join(", ")} with direction asc or desc, each field once.`,
          });
          return z.NEVER;
        }
        sort.push({ field, direction });
      }
      return sort;
    });
}

/**
 * Builds the strict query schema of a collection endpoint.
 * @param {{
 *   sortableFields: readonly string[],
 *   defaultSort: Array<{ field: string, direction: "asc" | "desc" }>,
 *   filters?: Record<string, import("zod").ZodTypeAny>,
 *   pagination?: { defaultPageSize?: number, maxPageSize?: number },
 *   cursor?: boolean,
 * }} options `cursor: true` adds the opt-in cursor parameters `cursor` and `limit` (see lib/keyset.js); the endpoint's
 * repository and service must then use `cursorContext` and `findKeysetPage`.
 */
export function createCollectionQuerySchema({
  sortableFields,
  defaultSort,
  filters = {},
  pagination,
  cursor = false,
}) {
  return z
    .object({
      ...paginationShape(pagination),
      ...(cursor ? cursorQueryShape(pagination?.maxPageSize ?? MAX_PAGE_SIZE) : {}),
      sort: sortSchema(sortableFields, defaultSort),
      ...filters,
    })
    .strict();
}

/**
 * Pagination block for response `meta`. `hasMore` and `nextCursor` are present only on cursor-capable collections.
 * @param {{ page: number, pageSize: number, totalItems: number, hasMore?: boolean, nextCursor?: string | null }} input
 */
export function buildPaginationMeta({ page, pageSize, totalItems, hasMore, nextCursor }) {
  return {
    page,
    pageSize,
    totalItems,
    totalPages: Math.ceil(totalItems / pageSize),
    ...(hasMore === undefined ? {} : { nextCursor: nextCursor ?? null, hasMore }),
  };
}

/**
 * Sorts a copy of `items` by `sort` using one accessor per field (in-memory data sources).
 * @template T
 * @param {T[]} items
 * @param {Array<{ field: string, direction: "asc" | "desc" }>} sort
 * @param {Record<string, (item: T) => string | number>} accessors
 */
export function sortItems(items, sort, accessors) {
  return [...items].sort((a, b) => {
    for (const { field, direction } of sort) {
      const get = accessors[field];
      const x = get(a);
      const y = get(b);
      if (x === y) continue;
      const order = typeof x === "string" ? x.localeCompare(y) : x - y;
      return direction === "desc" ? -order : order;
    }
    return 0;
  });
}

/**
 * Returns one page of `items` plus the pagination meta.
 * @template T
 * @param {T[]} items
 * @param {{ page: number, pageSize: number }} query
 */
export function paginateItems(items, { page, pageSize }) {
  const start = (page - 1) * pageSize;
  return {
    items: items.slice(start, start + pageSize),
    pagination: buildPaginationMeta({ page, pageSize, totalItems: items.length }),
  };
}

/**
 * Prisma `skip`/`take` for a validated query.
 * @param {{ page: number, pageSize: number }} query
 */
export const toPrismaPaging = ({ page, pageSize }) => ({
  skip: (page - 1) * pageSize,
  take: pageSize,
});

/**
 * Prisma `orderBy` for a validated sort (fields are already allow-listed by `sortSchema`).
 * @param {Array<{ field: string, direction: "asc" | "desc" }>} sort
 */
export const toPrismaOrderBy = (sort) =>
  sort.map(({ field, direction }) => ({ [field]: direction }));
