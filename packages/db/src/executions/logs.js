import { Prisma } from "@prisma/client";
import { withTransaction } from "../transaction.js";
import { createExecutionRepository } from "./repository.js";

/** The database ceilings (CHECK constraints of migration 20261116100400); configured caps must stay below them. */
export const LOG_CEILINGS = Object.freeze({
  executionLines: 100000,
  executionBytes: 8388608,
  taskLines: 50000,
  taskBytes: 4194304,
});
/** Room kept free below each cap for the truncation marker itself. */
const MARKER_LINES = 1;
const MARKER_BYTES = 256;
/** Text of the truncation markers (written once per scope). */
export const TRUNCATION_MARKERS = Object.freeze({
  task: "log truncated: the per-task log cap was reached; later lines are dropped",
  execution: "log truncated: the per-execution log cap was reached; later lines are dropped",
});
const LEVELS = new Set(["debug", "info", "warn", "error"]);
const SOURCES = new Set(["platform", "fetch", "scan"]);
const MAX_PAGE = 500;

function checkLimits(limits) {
  const pairs = [
    ["maxLinesPerExecution", LOG_CEILINGS.executionLines],
    ["maxBytesPerExecution", LOG_CEILINGS.executionBytes],
    ["maxLinesPerTask", LOG_CEILINGS.taskLines],
    ["maxBytesPerTask", LOG_CEILINGS.taskBytes],
  ];
  for (const [key, ceiling] of pairs)
    if (!Number.isInteger(limits?.[key]) || limits[key] < 2 || limits[key] > ceiling)
      throw new TypeError(`The log limit ${key} must be an integer between 2 and ${ceiling}.`);
}

function checkLines(lines) {
  if (!Array.isArray(lines) || lines.length > MAX_PAGE)
    throw new TypeError(`Append at most ${MAX_PAGE} log lines at a time.`);
  for (const line of lines)
    if (
      !LEVELS.has(line?.level) ||
      !SOURCES.has(line?.source) ||
      typeof line?.message !== "string" ||
      line.message.length === 0
    )
      throw new TypeError("A log line needs a level, a source and a non-empty message.");
}

/**
 * Data access of execution logs (docs/modules/executions/SPEC.md §7.4, §17.ac). Called only through the `LogStore` of
 * `@qmentisai/infra`, which has already redacted and shortened every line; the database still refuses credential shapes,
 * control characters and anything above the hard ceilings. EVERYTHING is scoped by the trusted `tenantId` and the execution
 * (and the task): a log is never read or written by id alone, and the chain columns of a row always come from the execution row,
 * never from the caller. Writers are fenced: a task writer by `(task, attempt, worker)` while the task is `running`, an
 * execution writer by the lease epoch. The caps (per task, per execution) drop the surplus with ONE marker line per scope and
 * set the `truncated` flag; the counters are locked first, so concurrent writers of one execution are serialised.
 * @param {{ db: any }} deps Prisma client
 */
export function createExecutionLogRepository({ db }) {
  const executions = createExecutionRepository({ db });

  /**
   * The shared writer. Locks the counters, decides line by line, inserts, then records what was dropped.
   * `task` is null for execution-level lines.
   */
  async function writeLines(tx, chain, task, lines, limits) {
    const base = { tenantId: chain.tenantId, executionId: chain.executionId };
    await tx.$executeRaw`
      INSERT INTO execution_log_counters (tenant_id, workspace_id, repository_id, pipeline_id, execution_id)
      VALUES (${chain.tenantId}::uuid, ${chain.workspaceId}::uuid, ${chain.repositoryId}::uuid, ${chain.pipelineId}::uuid, ${chain.executionId}::uuid)
      ON CONFLICT (tenant_id, execution_id) DO NOTHING`;
    const [ex] = await tx.$queryRaw`
      SELECT line_count AS "lines", byte_count AS "bytes", capped FROM execution_log_counters
      WHERE tenant_id = ${base.tenantId}::uuid AND execution_id = ${base.executionId}::uuid FOR UPDATE`;
    let tk = null;
    if (task) {
      await tx.$executeRaw`
        INSERT INTO execution_task_log_counters (tenant_id, workspace_id, repository_id, pipeline_id, execution_id, scan_task_id)
        VALUES (${chain.tenantId}::uuid, ${chain.workspaceId}::uuid, ${chain.repositoryId}::uuid, ${chain.pipelineId}::uuid, ${chain.executionId}::uuid, ${task}::uuid)
        ON CONFLICT (tenant_id, scan_task_id) DO NOTHING`;
      [tk] = await tx.$queryRaw`
        SELECT line_count AS "lines", byte_count AS "bytes", capped FROM execution_task_log_counters
        WHERE tenant_id = ${base.tenantId}::uuid AND scan_task_id = ${task}::uuid FOR UPDATE`;
    }
    // `capped`: the cap marker of that scope was written, so every later line of the scope is dropped
    const state = {
      exLines: ex.lines,
      exBytes: ex.bytes,
      exCapped: ex.capped,
      tkLines: tk?.lines ?? 0,
      tkBytes: tk?.bytes ?? 0,
      tkCapped: tk?.capped ?? false,
    };
    const newlyCapped = { execution: false, task: false };
    const rows = [];
    let dropped = 0;
    const push = (line, scanTaskId) => {
      const bytes = Buffer.byteLength(line.message);
      rows.push({ ...line, scanTaskId, bytes });
      state.exLines += 1;
      state.exBytes += bytes;
      if (scanTaskId) {
        state.tkLines += 1;
        state.tkBytes += bytes;
      }
    };
    const marker = (text, scanTaskId) =>
      push(
        {
          level: "warn",
          source: scanTaskId ? "scan" : "platform",
          message: text,
          lineTruncated: false,
        },
        scanTaskId,
      );
    for (const line of lines) {
      const bytes = Buffer.byteLength(line.message);
      const executionFull =
        state.exLines + 1 > limits.maxLinesPerExecution - MARKER_LINES ||
        state.exBytes + bytes > limits.maxBytesPerExecution - MARKER_BYTES;
      const taskFull =
        task !== null &&
        (state.tkLines + 1 > limits.maxLinesPerTask - MARKER_LINES ||
          state.tkBytes + bytes > limits.maxBytesPerTask - MARKER_BYTES);
      if (state.exCapped || state.tkCapped) {
        dropped += 1;
      } else if (executionFull) {
        dropped += 1;
        state.exCapped = true;
        newlyCapped.execution = true;
        marker(TRUNCATION_MARKERS.execution, null);
      } else if (taskFull) {
        dropped += 1;
        state.tkCapped = true;
        newlyCapped.task = true;
        marker(TRUNCATION_MARKERS.task, task);
      } else {
        push(line, task);
      }
    }
    if (rows.length > 0) {
      await tx.executionLog.createMany({
        data: rows.map(({ bytes: _bytes, scanTaskId, ...line }) => ({
          tenantId: chain.tenantId,
          workspaceId: chain.workspaceId,
          repositoryId: chain.repositoryId,
          pipelineId: chain.pipelineId,
          executionId: chain.executionId,
          scanTaskId,
          ...line,
        })),
      });
    }
    if (dropped > 0) {
      await tx.$executeRaw`
        UPDATE execution_log_counters SET dropped_lines = dropped_lines + ${dropped}::int, truncated = true,
          capped = capped OR ${newlyCapped.execution}::boolean, updated_at = now()
        WHERE tenant_id = ${base.tenantId}::uuid AND execution_id = ${base.executionId}::uuid`;
      if (task)
        await tx.$executeRaw`
          UPDATE execution_task_log_counters SET dropped_lines = dropped_lines + ${dropped}::int, truncated = true,
            capped = capped OR ${newlyCapped.task}::boolean, updated_at = now()
          WHERE tenant_id = ${base.tenantId}::uuid AND scan_task_id = ${task}::uuid`;
    }
    return { appended: rows.length, dropped, truncated: dropped > 0, fenced: false };
  }

  return Object.freeze({
    /**
     * Appends already sanitized lines of a RUNNING task attempt. The fence: the execution is preparing/running, the task is
     * `running` exactly this `attempt` and its lease is held by `workerId`; otherwise nothing is written and `fenced` is true
     * (a zombie writer, a superseded attempt, a finished task, another tenant's ids).
     * @param {{ tenantId: string, executionId: string, taskId: string, attempt: number, workerId: string, lines: Array<{ level: string, source: string, message: string, lineTruncated?: boolean }>, limits: Record<string, number> }} input
     * @param {any} [client]
     * @returns {Promise<{ appended: number, dropped: number, truncated: boolean, fenced: boolean }>}
     */
    async appendTaskLines(
      { tenantId, executionId, taskId, attempt, workerId, lines, limits },
      client = db,
    ) {
      checkLimits(limits);
      checkLines(lines);
      if (!Number.isInteger(attempt) || attempt < 0)
        throw new TypeError("attempt must be a non-negative integer");
      if (typeof workerId !== "string" || workerId.length === 0)
        throw new TypeError("workerId is required");
      return withTransaction(client, async (tx) => {
        // lock order: execution, then task (the order every lease-holder write uses), both shared
        const [chain] = await tx.$queryRaw`
          SELECT e.tenant_id AS "tenantId", e.workspace_id AS "workspaceId", e.repository_id AS "repositoryId", e.pipeline_id AS "pipelineId", e.id AS "executionId"
          FROM executions e
          WHERE e.tenant_id = ${tenantId}::uuid AND e.id = ${executionId}::uuid AND e.status IN ('preparing', 'running')
          FOR SHARE`;
        const [task] = chain
          ? await tx.$queryRaw`
              SELECT id FROM scan_tasks
              WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND id = ${taskId}::uuid
                AND status = 'running' AND attempt = ${attempt}::int AND lease_owner = ${workerId}
              FOR SHARE`
          : [];
        if (!chain || !task) return { appended: 0, dropped: 0, truncated: false, fenced: true };
        if (lines.length === 0) return { appended: 0, dropped: 0, truncated: false, fenced: false };
        return writeLines(tx, chain, taskId, lines, limits);
      });
    },

    /**
     * Appends already sanitized execution-level lines (source `platform` or `fetch`) for the holder of the lease. Fenced by the
     * lease epoch like every lease-holder write: throws `LeaseLostError` when it is lost.
     * @param {{ tenantId: string, executionId: string, leaseEpoch: number, lines: Array<{ level: string, source: string, message: string, lineTruncated?: boolean }>, limits: Record<string, number> }} input
     * @param {any} [client]
     * @returns {Promise<{ appended: number, dropped: number, truncated: boolean, fenced: boolean }>}
     */
    async appendExecutionLines({ tenantId, executionId, leaseEpoch, lines, limits }, client = db) {
      checkLimits(limits);
      checkLines(lines);
      if (lines.some((line) => line.source === "scan"))
        throw new TypeError("Execution-level lines have the source platform or fetch.");
      return withTransaction(client, async (tx) => {
        await executions.fenceExecution({ tenantId, executionId, leaseEpoch }, tx);
        if (lines.length === 0) return { appended: 0, dropped: 0, truncated: false, fenced: false };
        const [chain] = await tx.$queryRaw`
          SELECT tenant_id AS "tenantId", workspace_id AS "workspaceId", repository_id AS "repositoryId", pipeline_id AS "pipelineId", id AS "executionId"
          FROM executions WHERE tenant_id = ${tenantId}::uuid AND id = ${executionId}::uuid`;
        return writeLines(tx, chain, null, lines, limits);
      });
    },

    /**
     * Lines of one execution in `seq` order (keyset on `seq`), scoped by tenant, and by workspace and task when given. `order`
     * `asc` (default) returns the lines AFTER `afterSeq`, oldest first; `desc` returns the lines BEFORE `beforeSeq` (all when
     * omitted), newest first (the tail). `level` keeps one level. `nextAfterSeq` is the `seq` of the last returned line, i.e. the
     * position to continue from in the same order (null when the page is empty); `hasMore` says another page exists. The
     * `truncated` flag and `droppedLines` come from the counters of the scope (task when `taskId` is given, else execution).
     * Another tenant's execution id answers an empty page.
     * @param {{ tenantId: string, workspaceId?: string, executionId: string, taskId?: string, afterSeq?: number, beforeSeq?: number, order?: "asc" | "desc", level?: string, limit?: number }} query
     * @param {any} [client]
     */
    async listLines(
      {
        tenantId,
        workspaceId,
        executionId,
        taskId,
        afterSeq = 0,
        beforeSeq,
        order = "asc",
        level,
        limit = 200,
      },
      client = db,
    ) {
      if (!Number.isInteger(afterSeq) || afterSeq < 0)
        throw new TypeError("afterSeq must be a non-negative integer");
      if (beforeSeq !== undefined && (!Number.isInteger(beforeSeq) || beforeSeq < 1))
        throw new TypeError("beforeSeq must be a positive integer");
      if (order !== "asc" && order !== "desc") throw new TypeError("order must be asc or desc");
      if (level !== undefined && !LEVELS.has(level)) throw new TypeError("unknown log level");
      const size = Math.min(Math.max(1, Math.floor(limit)), MAX_PAGE);
      const scope = Prisma.sql`l.tenant_id = ${tenantId}::uuid AND l.execution_id = ${executionId}::uuid
        ${workspaceId ? Prisma.sql`AND l.workspace_id = ${workspaceId}::uuid` : Prisma.empty}
        ${taskId ? Prisma.sql`AND l.scan_task_id = ${taskId}::uuid` : Prisma.empty}
        ${level ? Prisma.sql`AND l.level = ${level}` : Prisma.empty}`;
      const position =
        order === "asc"
          ? Prisma.sql`l.seq > ${afterSeq}::bigint`
          : beforeSeq === undefined
            ? Prisma.sql`TRUE`
            : Prisma.sql`l.seq < ${beforeSeq}::bigint`;
      const direction = order === "asc" ? Prisma.sql`ASC` : Prisma.sql`DESC`;
      const rows = await client.$queryRaw`
        SELECT l.seq::int AS seq, l.scan_task_id AS "taskId", l.level, l.source, l.message, l.line_truncated AS "lineTruncated", l.at
        FROM execution_logs l
        WHERE ${scope} AND ${position}
        ORDER BY l.seq ${direction}
        LIMIT ${size + 1}`;
      const items = rows.slice(0, size);
      const [counter] = taskId
        ? await client.$queryRaw`
            SELECT truncated, dropped_lines AS "droppedLines" FROM execution_task_log_counters
            WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND scan_task_id = ${taskId}::uuid
              ${workspaceId ? Prisma.sql`AND workspace_id = ${workspaceId}::uuid` : Prisma.empty}`
        : await client.$queryRaw`
            SELECT truncated, dropped_lines AS "droppedLines" FROM execution_log_counters
            WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid
              ${workspaceId ? Prisma.sql`AND workspace_id = ${workspaceId}::uuid` : Prisma.empty}`;
      return {
        items,
        nextAfterSeq: items.length > 0 ? items[items.length - 1].seq : null,
        hasMore: rows.length > size,
        truncated: counter?.truncated ?? false,
        droppedLines: counter?.droppedLines ?? 0,
      };
    },
  });
}
