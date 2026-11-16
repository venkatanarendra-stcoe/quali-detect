import { Prisma } from "@prisma/client";
import { createExecutionRepository } from "./repository.js";
import { withTransaction } from "../transaction.js";

/** Attempt status for each task outcome (`scan_task_attempts.status`). */
const ATTEMPT_STATUS = Object.freeze({
  succeeded: "succeeded",
  failed: "failed",
  timed_out: "timed_out",
  cancelled: "cancelled",
});

const TASK_COLUMNS = Prisma.sql`id, tenant_id AS "tenantId", workspace_id AS "workspaceId", repository_id AS "repositoryId", pipeline_id AS "pipelineId",
  execution_id AS "executionId", scan_type::text AS "scanType", ordinal, status::text AS status, status_rev AS "statusRev", attempt, max_attempts AS "maxAttempts",
  engine_id AS "engineId", engine_profile AS "engineProfile", severity_threshold AS "severityThreshold", timeout_seconds AS "timeoutSeconds"`;

/**
 * Data access of scan tasks, attempts and results (docs/modules/executions/SPEC.md §5.3, §7.4, ER-11 to ER-15, ER-30). Same
 * rules as the execution helpers: EVERYTHING is scoped by the trusted `tenantId`; the clock is the database's `now()`; every
 * write of a task holder carries the held `(task, attempt)` in its WHERE clause (0 rows means "not yours any more"), and the
 * database backs this up (a result or attempt close for any other attempt is refused). The helpers that change tasks of an
 * execution on behalf of its lease holder (`createTasks`, `queuePending`, `closeOutTasks`) take the lease epoch and fence it.
 * @param {{ db: any }} deps Prisma client
 */
export function createScanTaskRepository({ db }) {
  const executions = createExecutionRepository({ db });
  const positive = (value, name) => {
    if (!Number.isFinite(value) || value <= 0)
      throw new TypeError(`${name} must be a positive number`);
    return Number(value);
  };

  /** Locks the task row if it is running exactly `attempt`; null otherwise. */
  async function lockRunning(tx, { tenantId, taskId, attempt }) {
    const rows = await tx.$queryRaw`
      SELECT ${TASK_COLUMNS}, extract(epoch FROM (now() - started_at))::float AS "elapsedSeconds"
      FROM scan_tasks
      WHERE id = ${taskId}::uuid AND tenant_id = ${tenantId}::uuid AND status = 'running' AND attempt = ${attempt}::int
      FOR UPDATE`;
    return rows[0] ?? null;
  }

  async function closeAttempt(tx, task, { status, errorClass = null, errorCode = null }) {
    const rows = await tx.$queryRaw`
      UPDATE scan_task_attempts
      SET status = ${status}, error_class = ${errorClass}, error_code = ${errorCode}, finished_at = now(),
          duration_ms = GREATEST(0, (extract(epoch FROM (now() - started_at)) * 1000)::int)
      WHERE tenant_id = ${task.tenantId}::uuid AND scan_task_id = ${task.id}::uuid AND attempt = ${task.attempt}::int AND status = 'running'
      RETURNING id`;
    return rows.length === 1;
  }

  return Object.freeze({
    /**
     * Creates the tasks of an execution once, from the snapshot (ER-11), `pending`. Fenced by the lease; replay-safe (unique
     * `(tenant, execution, scan_type)`: an existing task is kept). Call inside the transaction that also moves the execution
     * to `running`.
     * @param {{ tenantId: string, executionId: string, leaseEpoch: number, tasks: Array<{ scanType: string, ordinal: number, engineId: string, engineProfile: string, severityThreshold: string, timeoutSeconds: number, maxAttempts: number }> }} input
     * @param {any} tx The caller's TRANSACTION client.
     */
    async createTasks({ tenantId, executionId, leaseEpoch, tasks }, tx) {
      await executions.fenceExecution({ tenantId, executionId, leaseEpoch }, tx);
      const exec = await tx.execution.findFirst({
        where: { id: executionId, tenantId },
        select: { workspaceId: true, repositoryId: true, pipelineId: true },
      });
      if (!exec) return { created: 0 };
      const result = await tx.scanTask.createMany({
        data: tasks.map((t) => ({ tenantId, ...exec, executionId, status: "pending", ...t })),
        skipDuplicates: true,
      });
      return { created: result.count };
    },

    /** The tasks of one execution in dispatch order. @param {{ tenantId: string, executionId: string }} input @param {any} [client] */
    listTasks: ({ tenantId, executionId }, client = db) =>
      client.scanTask.findMany({ where: { tenantId, executionId }, orderBy: { ordinal: "asc" } }),

    /** Results of one execution (tenant and execution scoped). @param {{ tenantId: string, executionId: string }} input @param {any} [client] */
    listResults: ({ tenantId, executionId }, client = db) =>
      client.scanResult.findMany({ where: { tenantId, executionId } }),

    /**
     * Moves up to `limit` `pending` tasks (lowest ordinal first) to `queued` (ER-12: the caller passes the free parallelism).
     * Fenced by the lease; each task is moved by compare-and-set, so a replay moves nothing twice.
     * @param {{ tenantId: string, executionId: string, leaseEpoch: number, limit: number }} input
     * @param {any} tx The caller's TRANSACTION client.
     * @returns {Promise<Array<{ id: string, scanType: string, attempt: number, statusRev: number }>>}
     */
    async queuePending({ tenantId, executionId, leaseEpoch, limit }, tx) {
      await executions.fenceExecution({ tenantId, executionId, leaseEpoch }, tx);
      if (limit < 1) return [];
      // MATERIALIZED: a plain `id IN (SELECT ... LIMIT n FOR UPDATE)` can be re-evaluated per row and move more than n tasks
      return tx.$queryRaw`
        WITH picked AS MATERIALIZED (
          SELECT id FROM scan_tasks WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND status = 'pending'
          ORDER BY ordinal LIMIT ${Math.floor(limit)} FOR UPDATE)
        UPDATE scan_tasks t SET status = 'queued', updated_at = now()
        FROM picked
        WHERE t.id = picked.id AND t.tenant_id = ${tenantId}::uuid AND t.status = 'pending'
        RETURNING t.id, t.scan_type::text AS "scanType", t.attempt, t.status_rev AS "statusRev"`;
    },

    /**
     * The task claim of the scan worker: compare-and-set `queued -> running` for exactly this attempt, only while the
     * execution is `running`, with the task lease, a deadline of `min(now + task timeout, execution deadline)` and the attempt
     * row, in one transaction. Returns null when someone else holds it, the attempt is stale, the execution is not running or
     * a cancel was requested for it (ER-14: no task starts after the request; the holder cancels the unstarted tasks).
     * @param {{ tenantId: string, executionId: string, taskId: string, attempt: number, workerId: string, leaseTtlSeconds: number }} input
     * @param {any} [client]
     */
    async claimTask(
      { tenantId, executionId, taskId, attempt, workerId, leaseTtlSeconds },
      client = db,
    ) {
      const ttl = positive(leaseTtlSeconds, "leaseTtlSeconds");
      return withTransaction(client, async (tx) => {
        const rows = await tx.$queryRaw`
          UPDATE scan_tasks t
          SET status = 'running', lease_owner = ${workerId}, heartbeat_at = now(), lease_expires_at = now() + make_interval(secs => ${ttl}::double precision),
              deadline_at = LEAST(now() + make_interval(secs => t.timeout_seconds::double precision), e.deadline_at), updated_at = now()
          FROM executions e
          WHERE t.id = ${taskId}::uuid AND t.tenant_id = ${tenantId}::uuid AND t.execution_id = ${executionId}::uuid
            AND t.status = 'queued' AND t.attempt = ${attempt}::int
            AND e.tenant_id = t.tenant_id AND e.id = t.execution_id AND e.status = 'running' AND e.cancel_requested_at IS NULL
          RETURNING t.id, t.tenant_id AS "tenantId", t.workspace_id AS "workspaceId", t.repository_id AS "repositoryId", t.pipeline_id AS "pipelineId",
            t.execution_id AS "executionId", t.scan_type::text AS "scanType", t.attempt, t.max_attempts AS "maxAttempts", t.engine_id AS "engineId",
            t.engine_profile AS "engineProfile", t.severity_threshold AS "severityThreshold", t.timeout_seconds AS "timeoutSeconds",
            extract(epoch FROM (t.deadline_at - now()))::float AS "secondsToDeadline",
            (e.deadline_at <= now() + make_interval(secs => t.timeout_seconds::double precision)) AS "limitedByExecution"`;
        const task = rows[0];
        if (!task) return null;
        await tx.scanTaskAttempt.create({
          data: {
            tenantId,
            workspaceId: task.workspaceId,
            repositoryId: task.repositoryId,
            pipelineId: task.pipelineId,
            executionId,
            scanTaskId: taskId,
            attempt,
            workerId,
          },
        });
        return task;
      });
    },

    /**
     * Heartbeat of a task holder. `renewed: false` means the attempt is not ours any more: stop and write nothing else.
     * @param {{ tenantId: string, taskId: string, attempt: number, workerId: string, leaseTtlSeconds: number }} input
     * @param {any} [client]
     */
    async renewTaskLease({ tenantId, taskId, attempt, workerId, leaseTtlSeconds }, client = db) {
      const ttl = positive(leaseTtlSeconds, "leaseTtlSeconds");
      const rows = await client.$queryRaw`
        UPDATE scan_tasks SET heartbeat_at = GREATEST(heartbeat_at, now()),
          lease_expires_at = GREATEST(lease_expires_at, now() + make_interval(secs => ${ttl}::double precision))
        WHERE id = ${taskId}::uuid AND tenant_id = ${tenantId}::uuid AND status = 'running' AND attempt = ${attempt}::int AND lease_owner = ${workerId}
        RETURNING id`;
      return { renewed: rows.length === 1 };
    },

    /**
     * Finishes an attempt exactly once (ER-15): result (optional) + items, the attempt close and the terminal task status in
     * ONE transaction, all for exactly `(task, attempt)` while the task runs it. A late write of a superseded attempt finds
     * nothing and records nothing (`finished: false`). `result.items` are already validated and capped by the caller.
     * @param {{ tenantId: string, taskId: string, attempt: number, status: "succeeded" | "failed" | "timed_out" | "cancelled", reason?: string | null, errorClass?: string | null, errorCode?: string | null, result?: { engineId: string, engineVersion: string, completeness: "complete" | "incomplete", truncated: boolean, severityCounts: Record<string, number>, items: Array<Record<string, any>> } }} input
     * @param {any} [client]
     * @returns {Promise<{ finished: boolean, resultId: string | null, task: null | { id: string, executionId: string, workspaceId: string, scanType: string, statusRev: number } }>}
     */
    async finishTask(input, client = db) {
      const {
        tenantId,
        taskId,
        attempt,
        status,
        reason = null,
        errorClass = null,
        errorCode = null,
        result,
      } = input;
      if (!ATTEMPT_STATUS[status])
        throw new TypeError("finishTask ends a task as succeeded, failed, timed_out or cancelled");
      if (status !== "succeeded" && !reason)
        throw new TypeError("an unsuccessful task needs a reason");
      return withTransaction(client, async (tx) => {
        const task = await lockRunning(tx, { tenantId, taskId, attempt });
        if (!task) return { finished: false, resultId: null, task: null };
        let resultId = null;
        if (result) {
          const row = await tx.scanResult.create({
            data: {
              tenantId,
              workspaceId: task.workspaceId,
              repositoryId: task.repositoryId,
              pipelineId: task.pipelineId,
              executionId: task.executionId,
              scanTaskId: task.id,
              attempt,
              scanType: task.scanType,
              engineId: result.engineId,
              engineVersion: result.engineVersion,
              completeness: result.completeness,
              truncated: result.truncated,
              itemCount: result.items.length,
              severityCounts: result.severityCounts,
            },
          });
          resultId = row.id;
          if (result.items.length > 0)
            await tx.scanResultItem.createMany({
              data: result.items.map((item, ordinal) => ({
                tenantId,
                executionId: task.executionId,
                scanResultId: row.id,
                ordinal,
                ...item,
              })),
            });
        }
        await closeAttempt(tx, task, { status: ATTEMPT_STATUS[status], errorClass, errorCode });
        await tx.$executeRaw`
          UPDATE scan_tasks SET status = ${status}::scan_task_status, status_reason = ${status === "succeeded" ? null : reason},
            lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL, updated_at = now()
          WHERE id = ${task.id}::uuid AND tenant_id = ${tenantId}::uuid AND status = 'running' AND attempt = ${attempt}::int`;
        return {
          finished: true,
          resultId,
          task: {
            id: task.id,
            executionId: task.executionId,
            workspaceId: task.workspaceId,
            scanType: task.scanType,
            statusRev: task.statusRev + 1,
          },
        };
      });
    },

    /**
     * A retry (ER-13): closes the superseded attempt row FIRST, then raises the attempt by one and puts the task back to
     * `queued`, in one transaction. Only while `attempt + 1 < max_attempts` and no cancel was requested for the execution (the
     * safe point between attempts, ER-14). Returns the new attempt, or null when the attempt is not the task's running one, no
     * attempt is left or the execution is being cancelled.
     * @param {{ tenantId: string, taskId: string, attempt: number, errorClass: "transient" | "lease_expired", errorCode: string }} input
     * @param {any} [client]
     * @returns {Promise<null | { attempt: number, task: { id: string, executionId: string, scanType: string, workspaceId: string, statusRev: number } }>}
     */
    async requeueTask({ tenantId, taskId, attempt, errorClass, errorCode }, client = db) {
      return withTransaction(client, async (tx) => {
        const task = await lockRunning(tx, { tenantId, taskId, attempt });
        if (!task || attempt + 1 >= task.maxAttempts) return null;
        const cancelling = await tx.$queryRaw`
          SELECT 1 FROM executions WHERE tenant_id = ${tenantId}::uuid AND id = ${task.executionId}::uuid AND cancel_requested_at IS NOT NULL`;
        if (cancelling.length > 0) return null;
        await closeAttempt(tx, task, { status: "failed", errorClass, errorCode });
        await tx.$executeRaw`
          UPDATE scan_tasks SET status = 'queued', attempt = ${attempt + 1}::int, lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL, updated_at = now()
          WHERE id = ${task.id}::uuid AND tenant_id = ${tenantId}::uuid AND status = 'running' AND attempt = ${attempt}::int`;
        return {
          attempt: attempt + 1,
          task: {
            id: task.id,
            executionId: task.executionId,
            scanType: task.scanType,
            workspaceId: task.workspaceId,
            statusRev: task.statusRev + 1,
          },
        };
      });
    },

    /**
     * A cancel request was recorded: the tasks that have not started (`pending`, `queued`) become `cancelled` so none starts
     * (ER-14, both modes). Running tasks are not touched here. Fenced by the lease, replay-safe (a second call finds none).
     * @param {{ tenantId: string, executionId: string, leaseEpoch: number, reason: string }} input
     * @param {any} tx The caller's TRANSACTION client.
     * @returns {Promise<Array<{ id: string, scanType: string, statusRev: number }>>}
     */
    async cancelUnstarted({ tenantId, executionId, leaseEpoch, reason }, tx) {
      await executions.fenceExecution({ tenantId, executionId, leaseEpoch }, tx);
      return tx.$queryRaw`
        UPDATE scan_tasks SET status = 'cancelled', status_reason = ${reason}, updated_at = now()
        WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND status IN ('pending', 'queued')
        RETURNING id, scan_type::text AS "scanType", status_rev AS "statusRev"`;
    },

    /**
     * Running tasks whose lease expired (the scan worker died), for the lease holder of the execution. Tenant and execution scoped.
     * @param {{ tenantId: string, executionId: string }} input
     * @param {any} [client]
     * @returns {Promise<Array<{ id: string, attempt: number, maxAttempts: number, scanType: string, engineId: string }>>}
     */
    listExpiredTaskLeases: ({ tenantId, executionId }, client = db) =>
      client.$queryRaw`
        SELECT id, attempt, max_attempts AS "maxAttempts", scan_type::text AS "scanType", engine_id AS "engineId" FROM scan_tasks
        WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND status = 'running' AND lease_expires_at < now()`,

    /**
     * Ends every task that is not finished because the EXECUTION ends first (deadline, cancel, worker lost): a running task is
     * closed (its attempt row too) as `runningTo`, queued and pending tasks become `pendingTo`. Results already ingested stay.
     * Fenced by the lease; call inside the transaction of the terminal transition.
     * @param {{ tenantId: string, executionId: string, leaseEpoch: number, runningTo: "timed_out" | "cancelled" | "failed", pendingTo: "cancelled" | "skipped", reason: string, errorClass: string, errorCode: string }} input
     * @param {any} tx The caller's TRANSACTION client.
     * @returns {Promise<{ closed: number }>}
     */
    async closeOutTasks(
      { tenantId, executionId, leaseEpoch, runningTo, pendingTo, reason, errorClass, errorCode },
      tx,
    ) {
      await executions.fenceExecution({ tenantId, executionId, leaseEpoch }, tx);
      let closed = 0;
      const open = await tx.$queryRaw`
        SELECT id, attempt, status::text AS status FROM scan_tasks
        WHERE tenant_id = ${tenantId}::uuid AND execution_id = ${executionId}::uuid AND status IN ('pending', 'queued', 'running') ORDER BY ordinal FOR UPDATE`;
      for (const task of open) {
        if (task.status === "running") {
          await closeAttempt(
            tx,
            { tenantId, id: task.id, attempt: task.attempt },
            { status: ATTEMPT_STATUS[runningTo], errorClass, errorCode },
          );
          await tx.$executeRaw`
            UPDATE scan_tasks SET status = ${runningTo}::scan_task_status, status_reason = ${reason}, lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL, updated_at = now()
            WHERE id = ${task.id}::uuid AND tenant_id = ${tenantId}::uuid AND status = 'running'`;
        } else {
          await tx.$executeRaw`
            UPDATE scan_tasks SET status = ${pendingTo}::scan_task_status, status_reason = ${reason}, updated_at = now()
            WHERE id = ${task.id}::uuid AND tenant_id = ${tenantId}::uuid AND status = ${task.status}::scan_task_status`;
        }
        closed += 1;
      }
      return { closed };
    },
  });
}
