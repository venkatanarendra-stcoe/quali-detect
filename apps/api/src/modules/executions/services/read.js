import { REQUESTED_AT_KEY_PATTERN } from "@qmentisai/db";
import { SCAN_TASK_ORDER, can, isResolutionEligible } from "@qmentisai/shared";
import { NotFoundError } from "../../../errors/app-error.js";
import { InvalidCursorError, cursorContext } from "../../../lib/keyset.js";
import { CURSOR_KINDS } from "../constants/index.js";
import {
  toEventDto,
  toExecutionDetailDto,
  toExecutionListDto,
  toLogLineDto,
} from "../mappers/index.js";

const inWorkspace = (actor, key, workspaceId) =>
  can(actor.permissions, key, { type: "workspace", workspaceId });

/**
 * The read side of the executions API (SPEC executions §8.1: list, detail, events, logs). The routes have already authorized
 * the item reads (`execution.view` through the execution's workspace); the list is a collection, so it is FILTERED to the
 * workspaces where the caller holds `execution.view` and never answers 403. Every query carries the trusted tenant; a filter
 * narrows the accessible set and cannot widen it. Cursors are signed and bound to endpoint, tenant scope, sort, filters and
 * parent (the execution id for events and logs); they are positions, never a scope.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/index.js").createExecutionsRepository>,
 *   logStore: { read: Function },
 * }} deps
 */
export function createExecutionReadService({ repository, logStore }) {
  const tenantScope = (actor) => `tenant:${actor.tenantId}`;

  return Object.freeze({
    /**
     * @param {{ tenantId: string, permissions: any }} actor
     * @param {any} query validated `listQuerySchema` output
     * @returns {Promise<{ items: any[], pagination: { limit: number, nextCursor: string | null, hasMore: boolean, page?: number, pageSize?: number, totalItems?: number, totalPages?: number } }>}
     */
    async list(actor, query) {
      const direction = query.sort[0].direction;
      const terms = [
        { field: "requestedAtKey", direction, type: "string", nullable: false },
        { field: "id", direction, type: "uuid", nullable: false },
      ];
      const cursor = cursorContext({
        kind: CURSOR_KINDS.LIST,
        scope: tenantScope(actor),
        query,
        specs: {},
        terms,
      });
      if (cursor.after && !REQUESTED_AT_KEY_PATTERN.test(cursor.after[0]))
        throw new InvalidCursorError();
      const workspaceIds = actor.permissions.workspaces
        .map((w) => w.id)
        .filter((workspaceId) => inWorkspace(actor, "execution.view", workspaceId));
      const filters = {
        tenantId: actor.tenantId,
        workspaceIds,
        workspaceId: query.workspaceId,
        pipelineId: query.pipelineId,
        repositoryId: query.repositoryId,
        statuses: query.status,
        triggerType: query.triggerType,
        from: query.from,
        to: query.to,
      };
      const numbered = query.page !== undefined;
      const [page, totalItems] = await Promise.all([
        repository.listPage({
          ...filters,
          direction,
          after: cursor.after ? { requestedAtKey: cursor.after[0], id: cursor.after[1] } : null,
          limit: query.limit,
          offset: numbered ? (query.page - 1) * query.limit : 0,
        }),
        // the count uses the same filters and accessible workspaces; only numbered pages pay for it
        numbered ? repository.countList(filters) : Promise.resolve(null),
      ]);
      const ids = page.rows.map((r) => r.id);
      const rows = ids.length
        ? await repository.findExecutions({ tenantId: actor.tenantId, workspaceIds, ids })
        : [];
      const byId = new Map(rows.map((r) => [r.id, r]));
      const ordered = ids.map((id) => byId.get(id)).filter(Boolean);
      const [pipelineNames, repositoryNames, taskCounts] = await Promise.all([
        repository.findPipelineNames({
          tenantId: actor.tenantId,
          pipelineIds: [...new Set(ordered.map((e) => e.pipelineId))],
        }),
        repository.findRepositoryNames({
          tenantId: actor.tenantId,
          repositoryIds: [...new Set(ordered.map((e) => e.repositoryId))],
        }),
        repository.countTasksByStatus({ tenantId: actor.tenantId, executionIds: ids }),
      ]);
      const items = ordered.map((e) =>
        toExecutionListDto(e, {
          pipelineName: inWorkspace(actor, "pipeline.view", e.workspaceId)
            ? pipelineNames.get(e.pipelineId)
            : null,
          repositoryName: inWorkspace(actor, "repository.view", e.workspaceId)
            ? repositoryNames.get(e.repositoryId)
            : null,
          taskCounts: taskCounts
            .filter((c) => c.executionId === e.id)
            .map((c) => ({ status: c.status, count: c._count._all })),
        }),
      );
      const last = page.rows.at(-1);
      const next = cursor.next({
        hasMore: page.hasMore,
        nextKey: last ? [last.requestedAtKey, last.id] : null,
      });
      return {
        items,
        pagination: {
          limit: query.limit,
          ...next,
          ...(numbered
            ? {
                page: query.page,
                pageSize: query.limit,
                totalItems,
                totalPages: Math.ceil(totalItems / query.limit),
              }
            : {}),
        },
      };
    },

    /** @param {any} actor @param {{ id: string, workspaceId: string }} ref the authorized scope of the route */
    async get(actor, ref) {
      const e = await repository.findExecutionDetail({
        tenantId: actor.tenantId,
        workspaceId: ref.workspaceId,
        id: ref.id,
      });
      if (!e) throw new NotFoundError();
      const [tasks, toolRuns, decision, enabledTypes, pipelineNames, repositoryNames, memberNames] =
        await Promise.all([
          repository.findTasks({ tenantId: actor.tenantId, executionId: e.id }),
          repository.findToolRuns({ tenantId: actor.tenantId, executionId: e.id }),
          repository.findDecision({
            tenantId: actor.tenantId,
            workspaceId: e.workspaceId,
            repositoryId: e.repositoryId,
            pipelineId: e.pipelineId,
            executionId: e.id,
          }),
          repository.findEnabledScanTypes({
            tenantId: actor.tenantId,
            pipelineId: e.pipelineId,
            configVersionId: e.configVersionId,
          }),
          repository.findPipelineNames({ tenantId: actor.tenantId, pipelineIds: [e.pipelineId] }),
          repository.findRepositoryNames({
            tenantId: actor.tenantId,
            repositoryIds: [e.repositoryId],
          }),
          repository.findMemberNames({
            tenantId: actor.tenantId,
            userIds: e.requestedByUserId ? [e.requestedByUserId] : [],
          }),
        ]);
      const enabled = SCAN_TASK_ORDER.filter((type) => enabledTypes.includes(type));
      const resolutionEligible = isResolutionEligible({
        status: e.status,
        scanKind: e.scanKind,
        trust: e.trust,
        enabledScanTypes: enabled,
        tasks: tasks.map((t) => ({
          scanType: t.scanType,
          status: t.status,
          completeness: t.results?.[0]?.completeness ?? null,
          truncated: t.results?.[0]?.truncated ?? false,
        })),
      });
      return toExecutionDetailDto(e, {
        pipelineName: inWorkspace(actor, "pipeline.view", e.workspaceId)
          ? pipelineNames.get(e.pipelineId)
          : null,
        repositoryName: inWorkspace(actor, "repository.view", e.workspaceId)
          ? repositoryNames.get(e.repositoryId)
          : null,
        requestedByName: memberNames.get(e.requestedByUserId) ?? null,
        tasks,
        toolRuns,
        decision,
        resolutionEligible,
      });
    },

    /** Status history, oldest first by `seq`, cursor-only; the cursor is bound to this execution. */
    async events(actor, ref, query) {
      const terms = [{ field: "seq", direction: "asc", type: "number", nullable: false }];
      const cursor = cursorContext({
        kind: CURSOR_KINDS.EVENTS,
        scope: tenantScope(actor),
        query: { ...query, sort: "seq:asc" },
        specs: {},
        terms,
        extra: { executionId: ref.id },
      });
      const rows = await repository.findEvents({
        tenantId: actor.tenantId,
        workspaceId: ref.workspaceId,
        executionId: ref.id,
        afterSeq: cursor.after ? cursor.after[0] : 0,
        limit: query.limit,
      });
      const hasMore = rows.length > query.limit;
      const items = hasMore ? rows.slice(0, query.limit) : rows;
      const next = cursor.next({ hasMore, nextKey: items.length ? [items.at(-1).seq] : null });
      return { items: items.map(toEventDto), pagination: { limit: query.limit, ...next } };
    },

    /**
     * Log lines through the `LogStore` (redacted at write time). `order=asc` continues after `afterSeq` (or the cursor),
     * `order=desc` walks the tail backwards with the cursor. The cursor is bound to this execution, the filters and the order.
     */
    async logs(actor, ref, query) {
      const terms = [{ field: "seq", direction: query.order, type: "number", nullable: false }];
      const cursor = cursorContext({
        kind: CURSOR_KINDS.LOGS,
        scope: tenantScope(actor),
        query: { ...query, afterSeq: undefined, sort: query.order },
        specs: {},
        terms,
        extra: { executionId: ref.id },
      });
      const position = cursor.after ? cursor.after[0] : null;
      const page = await logStore.read({
        tenantId: actor.tenantId,
        workspaceId: ref.workspaceId,
        executionId: ref.id,
        taskId: query.taskId,
        level: query.level,
        order: query.order,
        limit: query.limit,
        ...(query.order === "asc"
          ? { afterSeq: position ?? query.afterSeq ?? 0 }
          : position === null
            ? {}
            : { beforeSeq: position }),
      });
      const next = cursor.next({
        hasMore: page.hasMore,
        nextKey: page.items.length ? [page.items.at(-1).seq] : null,
      });
      return {
        lines: page.items.map(toLogLineDto),
        nextCursor: next.nextCursor,
        hasMore: page.hasMore,
        truncated: page.truncated,
      };
    },
  });
}
