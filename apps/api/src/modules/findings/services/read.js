import { FindingNotFoundError, MAX_FINDINGS_LIST_OFFSET } from "@qmentisai/db";
import { FINDING_SEVERITIES, FINDINGS_LIMITS, can } from "@qmentisai/shared";
import { NotFoundError, ValidationError } from "../../../errors/app-error.js";
import { cursorContext, microDate } from "../../../lib/keyset.js";
import {
  toCommentDto,
  toDetailDto,
  toHistoryEntryDto,
  toListItemDto,
  toSimilarDto,
} from "../mappers/index.js";

/** Cursor kinds: a cursor minted for one endpoint is refused by every other (`INVALID_CURSOR`). */
const CURSOR_KINDS = Object.freeze({
  LIST: "findings.list",
  QUEUE: "findings.review_queue",
  HISTORY: "findings.history",
  COMMENTS: "findings.comments",
});

/** Default direction of each sort (SPEC 8.1: severity most severe first, SLA soonest first, dates newest first, title A to Z). */
const DEFAULT_DIRECTION = Object.freeze({
  severity: "desc",
  slaDueAt: "asc",
  firstDetectedAt: "desc",
  lastSeenAt: "desc",
  title: "asc",
});
const DATE_COLUMN = Object.freeze({
  slaDueAt: "sla_due_at",
  firstDetectedAt: "first_detected_at",
  lastSeenAt: "last_seen_at",
});

/**
 * The key terms of a list order (the sort term, then the row id), for the signed cursor. The severity term is an `enum` key in
 * DECLARATION order (critical first), as the keyset library requires.
 * @param {string} sort @param {"asc" | "desc"} direction
 */
function termsOf(sort, direction) {
  if (sort === "severity")
    return [
      // declaration order is critical first: "desc" (most severe first) is the enum's ascending order
      {
        field: "severity",
        direction: direction === "desc" ? "asc" : "desc",
        type: "enum",
        values: FINDING_SEVERITIES,
        nullable: false,
      },
      { field: "id", direction: "asc", type: "uuid", nullable: false },
    ];
  if (sort === "title")
    return [
      { field: "title", direction, type: "string", nullable: false },
      { field: "id", direction, type: "uuid", nullable: false },
    ];
  return [
    {
      field: sort,
      direction,
      type: "date",
      nullable: sort === "slaDueAt",
      column: DATE_COLUMN[sort],
    },
    { field: "id", direction, type: "uuid", nullable: false },
  ];
}

/** A page key from the repository (strings) to the values the signed cursor encodes (dates keep their microseconds). */
const toCursorKey = (sort, key) =>
  key === null
    ? null
    : [
        sort === "severity" || sort === "title"
          ? key[0]
          : key[0] === null
            ? null
            : microDate(key[0]),
        key[1],
      ];

/**
 * The read side of the findings API (docs/modules/findings/SPEC.md 8.1): list, summary, detail, history, comments, similar. The routes
 * have already authorized the caller in the right workspace (`finding.view`); this layer still reads by tenant, workspace and id and
 * never trusts an id alone. Cursors are signed and bound to endpoint, tenant, filters, sort and (for `assignee=me`) the user; they are
 * positions, never a scope.
 * @param {{ repository: ReturnType<typeof import("@qmentisai/db").createFindingsRepository>, clock?: () => Date }} deps
 */
export function createFindingsReadService({ repository, clock = () => new Date() }) {
  const scopeOf = (actor, workspaceId) => ({ tenantId: actor.tenantId, workspaceId });
  const guard = async (fn) => {
    try {
      return await fn();
    } catch (error) {
      if (error instanceof FindingNotFoundError) throw new NotFoundError();
      throw error;
    }
  };

  /** The paging every list shares: numbered (`page`, `pageSize`) or keyset (`cursor`, `limit`). */
  async function pagedList({ actor, query, kind, sort, direction, fetchPage, workspaceId }) {
    const numbered = query.page !== undefined || query.pageSize !== undefined;
    const limit = numbered
      ? (query.pageSize ?? FINDINGS_LIMITS.defaultPageSize)
      : (query.limit ?? FINDINGS_LIMITS.defaultPageSize);
    const page = query.page ?? 1;
    if (numbered && (page - 1) * limit > MAX_FINDINGS_LIST_OFFSET)
      throw new ValidationError(
        [
          {
            path: "page",
            code: "custom",
            message: "The requested page is too deep. Use a cursor or a filter.",
          },
        ],
        { source: "querystring" },
      );
    const terms = termsOf(sort, direction);
    const cursor = cursorContext({
      kind,
      scope: `tenant:${actor.tenantId}`,
      query: { ...query, sort: `${sort}:${direction}` },
      specs: {},
      terms,
      // `assignee=me` and the assigned-to-me view depend on the session: a cursor of another user is refused
      extra: { workspaceId, userId: actor.userId },
    });
    const result = await fetchPage({
      limit,
      offset: numbered ? (page - 1) * limit : 0,
      after: cursor.after,
      withTotal: numbered,
    });
    const next = cursor.next({
      hasMore: result.hasMore,
      nextKey: toCursorKey(sort, result.nextKey),
    });
    return {
      result,
      pagination: {
        limit,
        ...next,
        ...(numbered
          ? {
              page,
              pageSize: limit,
              totalItems: result.totalItems,
              totalPages: Math.ceil(result.totalItems / limit),
            }
          : {}),
      },
    };
  }

  return Object.freeze({
    /**
     * `GET /findings`. @param {{ tenantId: string, userId: string }} actor @param {any} query validated `listFindingsQuerySchema` output
     * @returns {Promise<{ items: object[], pagination: object }>}
     */
    async list(actor, query) {
      const sort = query.sort ?? "severity";
      const direction = query.direction ?? DEFAULT_DIRECTION[sort];
      const now = clock();
      const scope = scopeOf(actor, query.workspaceId);
      const { result, pagination } = await pagedList({
        actor,
        query,
        kind: CURSOR_KINDS.LIST,
        sort,
        direction,
        workspaceId: query.workspaceId,
        fetchPage: (paging) =>
          repository.list(
            scope,
            { ...query, sort, direction, now, ...paging },
            { userId: actor.userId },
          ),
      });
      return { items: result.items.map((entry) => toListItemDto(entry, now)), pagination };
    },

    /**
     * `GET /review-queue` (Part B routes it): `new` and `in_review`, oldest first by default. Same paging and cursor rules as the list.
     * @param {{ tenantId: string, userId: string }} actor @param {any} query validated `reviewQueueQuerySchema` output
     */
    async reviewQueue(actor, query) {
      const sort = query.sort === "severity" ? "severity" : "firstDetectedAt";
      const direction = sort === "severity" ? "desc" : "asc";
      const now = clock();
      const scope = scopeOf(actor, query.workspaceId);
      const { result, pagination } = await pagedList({
        actor,
        query,
        kind: CURSOR_KINDS.QUEUE,
        sort,
        direction,
        workspaceId: query.workspaceId,
        fetchPage: (paging) =>
          repository.reviewQueue(scope, { ...query, now, ...paging }, { userId: actor.userId }),
      });
      return { items: result.items.map((entry) => toListItemDto(entry, now)), pagination };
    },

    /** `GET /findings/summary`. @param {{ tenantId: string, userId: string }} actor @param {{ workspaceId: string }} query */
    summary: (actor, query) =>
      repository.summary(scopeOf(actor, query.workspaceId), { userId: actor.userId }),

    /**
     * `GET /findings/{id}`: `ref` is the authorized resource of the route (`id`, `workspaceId`); the row is re-read by tenant,
     * workspace and id. @param {{ tenantId: string, permissions: any }} actor @param {{ id: string, workspaceId: string }} ref
     */
    async get(actor, ref) {
      const detail = await repository.getDetail(scopeOf(actor, ref.workspaceId), ref.id);
      if (!detail) throw new NotFoundError();
      return toDetailDto(detail, {
        now: clock(),
        workspaceId: ref.workspaceId,
        can: (key) =>
          can(actor.permissions, key, { type: "workspace", workspaceId: ref.workspaceId }),
      });
    },

    /** `GET /findings/{id}/history`: newest first, keyset only. */
    async history(actor, ref, query) {
      return guard(async () => {
        const limit = query.limit ?? FINDINGS_LIMITS.defaultPageSize;
        const cursor = cursorContext({
          kind: CURSOR_KINDS.HISTORY,
          scope: `tenant:${actor.tenantId}`,
          query: { ...query, sort: "at:desc" },
          specs: {},
          terms: [
            { field: "at", direction: "desc", type: "date", nullable: false, column: "created_at" },
            { field: "id", direction: "desc", type: "uuid", nullable: false },
          ],
          extra: { findingId: ref.id },
        });
        const page = await repository.history(scopeOf(actor, ref.workspaceId), ref.id, {
          limit,
          after: cursor.after,
        });
        const next = cursor.next({
          hasMore: page.hasMore,
          nextKey: page.nextKey ? [microDate(page.nextKey[0]), page.nextKey[1]] : null,
        });
        return { items: page.items.map(toHistoryEntryDto), pagination: { limit, ...next } };
      });
    },

    /** `GET /findings/{id}/comments`: oldest first, keyset only. */
    async comments(actor, ref, query) {
      return guard(async () => {
        const limit = query.limit ?? FINDINGS_LIMITS.defaultPageSize;
        const cursor = cursorContext({
          kind: CURSOR_KINDS.COMMENTS,
          scope: `tenant:${actor.tenantId}`,
          query: { ...query, sort: "createdAt:asc" },
          specs: {},
          terms: [
            {
              field: "createdAt",
              direction: "asc",
              type: "date",
              nullable: false,
              column: "created_at",
            },
            { field: "id", direction: "asc", type: "uuid", nullable: false },
          ],
          extra: { findingId: ref.id },
        });
        const page = await repository.comments(scopeOf(actor, ref.workspaceId), ref.id, {
          limit,
          after: cursor.after,
        });
        const next = cursor.next({
          hasMore: page.hasMore,
          nextKey: page.nextKey ? [microDate(page.nextKey[0]), page.nextKey[1]] : null,
        });
        return { items: page.items.map(toCommentDto), pagination: { limit, ...next } };
      });
    },

    /** `GET /findings/{id}/similar`: links only, other pipelines of the same workspace, at most 20. */
    async similar(actor, ref) {
      return guard(async () => {
        const rows = await repository.similar(scopeOf(actor, ref.workspaceId), ref.id);
        const now = clock();
        return rows.map((r) => toSimilarDto(r, now));
      });
    },
  });
}
