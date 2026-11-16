import { Prisma } from "@prisma/client";

/** `requested_at` rendered at the column's full (microsecond) precision: the keyset position of the list. */
export const REQUESTED_AT_KEY_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Read side of the execution list (docs/modules/executions/SPEC.md §8.1). The page is ordered by `(requested_at, id)` and
 * positioned by the row's `requested_at` at MICROSECOND precision (a JavaScript Date only holds milliseconds, so a Date-based
 * keyset could skip or repeat rows that differ below the millisecond). EVERY query carries the trusted tenant and the caller's
 * accessible workspaces; a filter can narrow that set, never widen it, so a pipeline, repository or workspace id of another
 * tenant or of a hidden workspace yields the same empty page as a random id.
 * @param {{ db: any }} deps Prisma client
 */
export function createExecutionReadRepository({ db }) {
  return Object.freeze({
    /**
     * One page of execution ids in keyset order, plus whether another page follows (one extra row is fetched, no count).
     * @param {{
     *   tenantId: string, workspaceIds: string[], workspaceId?: string, pipelineId?: string, repositoryId?: string,
     *   statuses?: string[], triggerType?: string, from?: Date, to?: Date, direction: "asc" | "desc",
     *   after?: { requestedAtKey: string, id: string } | null, limit: number,
     * }} input `workspaceIds` is the set the caller may see (possibly empty: an empty page)
     * @param {any} [client]
     * @returns {Promise<{ rows: Array<{ id: string, requestedAtKey: string }>, hasMore: boolean }>}
     */
    async listPage(
      {
        tenantId,
        workspaceIds,
        workspaceId,
        pipelineId,
        repositoryId,
        statuses,
        triggerType,
        from,
        to,
        direction,
        after,
        limit,
      },
      client = db,
    ) {
      if (direction !== "asc" && direction !== "desc") throw new TypeError("direction");
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new TypeError("limit");
      if (after && (!REQUESTED_AT_KEY_PATTERN.test(after.requestedAtKey) || !UUID.test(after.id)))
        throw new TypeError("cursor position");
      const visible = workspaceId ? workspaceIds.filter((id) => id === workspaceId) : workspaceIds;
      if (visible.length === 0) return { rows: [], hasMore: false };
      const where = [
        Prisma.sql`e.tenant_id = ${tenantId}::uuid`,
        Prisma.sql`e.workspace_id = ANY(${visible}::uuid[])`,
      ];
      if (pipelineId) where.push(Prisma.sql`e.pipeline_id = ${pipelineId}::uuid`);
      if (repositoryId) where.push(Prisma.sql`e.repository_id = ${repositoryId}::uuid`);
      if (statuses?.length) where.push(Prisma.sql`e.status::text = ANY(${statuses}::text[])`);
      if (triggerType) where.push(Prisma.sql`e.trigger_type::text = ${triggerType}`);
      if (from) where.push(Prisma.sql`e.requested_at >= ${from}::timestamptz`);
      if (to) where.push(Prisma.sql`e.requested_at < ${to}::timestamptz`);
      if (after)
        where.push(
          direction === "desc"
            ? Prisma.sql`(e.requested_at, e.id) < (${after.requestedAtKey}::timestamptz, ${after.id}::uuid)`
            : Prisma.sql`(e.requested_at, e.id) > (${after.requestedAtKey}::timestamptz, ${after.id}::uuid)`,
        );
      const order = direction === "desc" ? Prisma.sql`DESC` : Prisma.sql`ASC`;
      const rows = await client.$queryRaw`
        SELECT e.id,
               to_char(e.requested_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "requestedAtKey"
        FROM executions e
        WHERE ${Prisma.join(where, " AND ")}
        ORDER BY e.requested_at ${order}, e.id ${order}
        LIMIT ${limit + 1}`;
      return { rows: rows.slice(0, limit), hasMore: rows.length > limit };
    },
  });
}
