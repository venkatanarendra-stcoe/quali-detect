import { FINDING_SEVERITIES, FINDINGS_LIMITS, can } from "@qmentisai/shared";
import { cursorContext } from "../../../lib/keyset.js";
import { toBoardCardDto } from "../mappers/board.js";

/** Cursor kind: a cursor minted for the board is refused by every other endpoint (`INVALID_CURSOR`). */
const CURSOR_KIND = "findings.board";

/** The board columns in display order (SPEC C-3: five columns, one status each). */
export const BOARD_COLUMN_ORDER = Object.freeze([
  "assigned",
  "in_remediation",
  "fixed_pending_verification",
  "verified_fixed",
  "reopened",
]);

/** The keyset order of a column: the most severe first (declaration order of the enum, ascending), then the id. */
const TERMS = Object.freeze([
  {
    field: "severity",
    direction: "asc",
    type: "enum",
    values: FINDING_SEVERITIES,
    nullable: false,
  },
  { field: "id", direction: "asc", type: "uuid", nullable: false },
]);

/**
 * The remediation board (Part C, docs/modules/findings/SPEC.md 8.1, SCREENS T-36): five columns, the first 25 cards of each with its
 * count and a signed cursor, and the paging of one column. Cursors are bound to the endpoint, tenant, workspace, caller, column and
 * filters, so one minted for another column, filter set, workspace or user is `INVALID_CURSOR`. Every query carries tenant AND
 * workspace; a `pipelineId` of another workspace narrows to nothing, never widens. The card carries `canRemediate`, computed here for
 * the caller (RM-1), and the PR link and ticket key of the latest submitted fix.
 * @param {{ repository: ReturnType<typeof import("../repositories/remediation.js").createFindingsRemediationRepository>, clock?: () => Date }} deps
 */
export function createFindingsBoardService({ repository, clock = () => new Date() }) {
  const filtersOf = (query) => ({
    severity: query.severity,
    assignee: query.assignee,
    pipelineId: query.pipelineId,
    sla: query.sla,
  });

  /** One column page with its signed `nextCursor`. */
  async function page(actor, query, column, { limit, cursor, withTotal }) {
    const now = clock();
    const scope = { tenantId: actor.tenantId, workspaceId: query.workspaceId };
    const bound = cursorContext({
      kind: CURSOR_KIND,
      scope: `tenant:${actor.tenantId}`,
      // the binding covers every filter and the column; `cursor` and `limit` are paging keys and are left out of it
      query: { ...query, column, cursor, sort: "severity:desc" },
      specs: {},
      terms: [...TERMS],
      extra: { workspaceId: query.workspaceId, userId: actor.userId },
    });
    const result = await repository.assignments.board(
      scope,
      { column, limit, after: bound.after, withTotal, now, ...filtersOf(query) },
      { userId: actor.userId },
    );
    const next = bound.next({ hasMore: result.hasMore, nextKey: result.nextKey });
    const context = {
      callerUserId: actor.userId,
      can: (key) =>
        can(actor.permissions, key, { type: "workspace", workspaceId: query.workspaceId }),
    };
    return {
      items: result.items.map((entry) => toBoardCardDto(entry, now, context)),
      totalItems: result.totalItems,
      limit,
      ...next,
    };
  }

  return Object.freeze({
    /**
     * `GET /remediation/board`: the five columns, each `{ count, items (first 25), nextCursor }`.
     * @param {{ tenantId: string, userId: string, permissions: any }} actor @param {any} query validated `boardQuerySchema` output
     */
    async board(actor, query) {
      const entries = await Promise.all(
        BOARD_COLUMN_ORDER.map(async (column) => {
          const p = await page(actor, query, column, {
            limit: FINDINGS_LIMITS.boardFirstItems,
            cursor: undefined,
            withTotal: true,
          });
          return [column, { count: p.totalItems ?? 0, items: p.items, nextCursor: p.nextCursor }];
        }),
      );
      return { columns: Object.fromEntries(entries) };
    },

    /**
     * `GET /remediation/board/{column}`: one column, keyset paged.
     * @param {{ tenantId: string, userId: string, permissions: any }} actor @param {string} column
     * @param {any} query validated `boardColumnQuerySchema` output
     * @returns {Promise<{ items: object[], pagination: { limit: number, hasMore: boolean, nextCursor: string | null } }>}
     */
    async column(actor, column, query) {
      const limit = query.limit ?? FINDINGS_LIMITS.boardFirstItems;
      const p = await page(actor, query, column, { limit, cursor: query.cursor, withTotal: false });
      return {
        items: p.items,
        pagination: { limit: p.limit, hasMore: p.hasMore, nextCursor: p.nextCursor },
      };
    },
  });
}
