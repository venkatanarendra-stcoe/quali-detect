import { Prisma } from "@prisma/client";
import {
  EXECUTION_ACTIVE_STATUSES,
  EXECUTION_EVENT_TYPES,
  canReleaseQuotaOnTransition,
  canTransitionExecution,
  isTerminalExecutionStatus,
} from "@qmentisai/shared";
import { createEntitlementRepository } from "../entitlements/repository.js";
import { QUOTA_KEYS } from "../entitlements/keys.js";
import { createEntitlementService } from "../entitlements/service.js";
import { withTransaction } from "../transaction.js";
import { LeaseLostError } from "./errors.js";

/**
 * Data access of the execution state machine (docs/modules/executions/SPEC.md §6, ER-4, ER-27 to ER-30, §5.9). Part B:
 * helpers only, no orchestrator. The database trigger `executions_guard` is the last line of defence; these functions are the
 * compare-and-set statements that make a transition happen exactly once.
 *
 * Rules every function follows:
 * - EVERYTHING is scoped by the trusted `tenantId` (and the execution id): an execution is never read or changed by id alone.
 *   The two platform-wide peeks (`peekQueued`, `peekExpiredLeases`) look across tenants on purpose, return identifiers only, and
 *   must be followed by a tenant-scoped re-read, like `peekDue` of the scheduler.
 * - Time is the database's `now()`, never the worker's clock.
 * - Every write of a lease holder carries the held `leaseEpoch` in its WHERE clause (fencing): 0 rows means the lease is lost,
 *   and nothing is recorded.
 * - `client` is the Prisma client or a transaction client; functions that write several rows join the caller's transaction or
 *   open their own.
 * @param {{ db: any, entitlements?: ReturnType<typeof createEntitlementService> }} deps Prisma client; `entitlements` defaults
 * to the entitlement service over the same client.
 */
export function createExecutionRepository({ db, entitlements }) {
  const quota =
    entitlements ?? createEntitlementService({ repository: createEntitlementRepository({ db }) });
  const seconds = (value, name) => {
    if (!Number.isFinite(value) || value <= 0)
      throw new TypeError(`${name} must be a positive number of seconds`);
    return Number(value);
  };
  const isTransaction = (client) => typeof client.$transaction !== "function";
  const requireTransaction = (client, fn) => {
    if (!isTransaction(client))
      throw new TypeError(`${fn} must run inside the caller's transaction`);
  };

  /**
   * Sets the actor of the `transition` event the trigger writes for the next status change IN THIS TRANSACTION (the settings
   * are transaction-local, so they cannot leak to another statement or connection user).
   */
  async function setEventContext(tx, { actor, correlationId, details }) {
    const actorType = actor?.type ?? "system";
    if (actorType !== "system" && actorType !== "user")
      throw new TypeError("actor.type must be system or user");
    if (actorType === "user" && !actor?.userId) throw new TypeError("a user actor needs userId");
    await tx.$executeRaw`
      SELECT set_config('qm.actor_type', ${actorType}, true), set_config('qm.actor_user_id', ${actor?.userId ?? ""}, true),
             set_config('qm.correlation_id', ${correlationId ?? ""}, true), set_config('qm.event_details', ${JSON.stringify(details ?? {})}, true)`;
  }

  /**
   * The write fence (ER-30). Call it FIRST inside the transaction of every write a lease holder makes (tasks, results, logs,
   * outbox, audit, quota): it takes a shared row lock on the execution while checking that it is still preparing/running at
   * the held epoch, so a reclaim cannot slip in between the check and the writes. Throws `LeaseLostError` otherwise.
   * @param {{ tenantId: string, executionId: string, leaseEpoch: number }} input
   * @param {any} tx The caller's TRANSACTION client.
   */
  async function fenceExecution({ tenantId, executionId, leaseEpoch }, tx) {
    requireTransaction(tx, "fenceExecution");
    const rows = await tx.$queryRaw`
      SELECT id FROM executions
      WHERE tenant_id = ${tenantId}::uuid AND id = ${executionId}::uuid AND lease_epoch = ${leaseEpoch}::int AND status IN ('preparing', 'running')
      FOR SHARE`;
    if (rows.length !== 1) throw new LeaseLostError({ executionId, leaseEpoch });
  }

  const LEASE_COLUMNS = Prisma.sql`id, tenant_id AS "tenantId", workspace_id AS "workspaceId", repository_id AS "repositoryId", pipeline_id AS "pipelineId",
    status::text AS status, status_rev AS "statusRev", lease_owner AS "leaseOwner", lease_epoch AS "leaseEpoch", lease_expires_at AS "leaseExpiresAt",
    heartbeat_at AS "heartbeatAt", claimed_at AS "claimedAt", deadline_at AS "deadlineAt", requested_at AS "requestedAt"`;

  return Object.freeze({
    /**
     * One execution by tenant AND id (the only way to load one).
     * @param {{ tenantId: string, executionId: string }} input
     * @param {any} [client]
     */
    findExecution: ({ tenantId, executionId }, client = db) =>
      client.execution.findFirst({ where: { id: executionId, tenantId } }),

    /**
     * Candidates for a claim: the oldest `queued` executions platform-wide (at most `maxPerTenant` per tenant, so one tenant
     * cannot starve the others), selected with `FOR UPDATE ... SKIP LOCKED` so concurrent sweepers peek different rows. PLATFORM
     * scan on purpose: it returns identifiers only. The locks last only until `client`'s transaction ends, so exactly-once is
     * the job of the compare-and-set in `claimQueued`, after a tenant-scoped re-read and the gates (ER-4).
     * @param {{ limit?: number, maxPerTenant?: number }} [input]
     * @param {any} [client]
     * @returns {Promise<Array<{ id: string, tenantId: string, requestedAt: Date }>>}
     */
    async peekQueued({ limit = 20, maxPerTenant = 5 } = {}, client = db) {
      return client.$queryRaw`
        SELECT e.id, e.tenant_id AS "tenantId", e.requested_at AS "requestedAt"
        FROM executions e
        WHERE e.status = 'queued' AND e.id IN (
          SELECT q.id FROM (
            SELECT id, row_number() OVER (PARTITION BY tenant_id ORDER BY requested_at, id) AS rn FROM executions WHERE status = 'queued'
          ) q WHERE q.rn <= ${Math.max(1, Math.floor(maxPerTenant))}
        )
        ORDER BY e.requested_at, e.id
        LIMIT ${Math.max(1, Math.floor(limit))}
        FOR UPDATE OF e SKIP LOCKED`;
    },

    /**
     * The claim: compare-and-set `queued -> preparing` (EXEC-004). Exactly one caller gets the row; every other gets `null`
     * and does nothing. Creates the lease (`lease_epoch` + 1, owner, heartbeat, expiry) and the deadline in the same statement.
     * The statement itself refuses a request older than `staleThresholdSeconds` (ER-32), so even a race between the age gate
     * and the claim cannot start a stale run. The caller has re-read the row by tenant and id and run the gates (section 6.2).
     * @param {{ tenantId: string, executionId: string, workerId: string, leaseTtlSeconds: number, deadlineSeconds: number, staleThresholdSeconds: number, correlationId?: string }} input
     * @param {any} [client]
     * @returns {Promise<null | { id: string, tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, status: string, statusRev: number, leaseOwner: string, leaseEpoch: number, leaseExpiresAt: Date, heartbeatAt: Date, claimedAt: Date, deadlineAt: Date, requestedAt: Date }>}
     */
    async claimQueued(
      {
        tenantId,
        executionId,
        workerId,
        leaseTtlSeconds,
        deadlineSeconds,
        staleThresholdSeconds,
        correlationId,
      },
      client = db,
    ) {
      const ttl = seconds(leaseTtlSeconds, "leaseTtlSeconds");
      const deadline = seconds(deadlineSeconds, "deadlineSeconds");
      const stale = seconds(staleThresholdSeconds, "staleThresholdSeconds");
      return withTransaction(client, async (tx) => {
        await setEventContext(tx, {
          actor: { type: "system" },
          correlationId,
          details: { workerId },
        });
        const rows = await tx.$queryRaw`
          UPDATE executions
          SET status = 'preparing', claimed_at = now(), deadline_at = now() + make_interval(secs => ${deadline}::double precision),
              lease_owner = ${workerId}, lease_epoch = lease_epoch + 1, heartbeat_at = now(),
              lease_expires_at = now() + make_interval(secs => ${ttl}::double precision), updated_at = now()
          WHERE id = ${executionId}::uuid AND tenant_id = ${tenantId}::uuid AND status = 'queued'
            AND requested_at >= now() - make_interval(secs => ${stale}::double precision)
          RETURNING ${LEASE_COLUMNS}`;
        return rows[0] ?? null;
      });
    },

    /**
     * Heartbeat (ER-27): extends the lease of the holder (never shortens it: the expiry and the heartbeat only move forward). `renewed: false` means the lease is lost (reclaimed, wrong owner,
     * execution ended): the caller stops at once and writes nothing else. Not a transition: no `status_rev` change, no event,
     * no audit entry.
     * @param {{ tenantId: string, executionId: string, workerId: string, leaseEpoch: number, leaseTtlSeconds: number }} input
     * @param {any} [client]
     * @returns {Promise<{ renewed: boolean, leaseExpiresAt: Date | null }>}
     */
    async renewLease(
      { tenantId, executionId, workerId, leaseEpoch, leaseTtlSeconds },
      client = db,
    ) {
      const ttl = seconds(leaseTtlSeconds, "leaseTtlSeconds");
      const rows = await client.$queryRaw`
        UPDATE executions
        SET heartbeat_at = GREATEST(heartbeat_at, now()),
            lease_expires_at = GREATEST(lease_expires_at, now() + make_interval(secs => ${ttl}::double precision))
        WHERE id = ${executionId}::uuid AND tenant_id = ${tenantId}::uuid AND lease_epoch = ${leaseEpoch}::int
          AND lease_owner = ${workerId} AND status IN ('preparing', 'running')
        RETURNING lease_expires_at AS "leaseExpiresAt"`;
      return { renewed: rows.length === 1, leaseExpiresAt: rows[0]?.leaseExpiresAt ?? null };
    },

    /**
     * Executions whose lease expired (`lease_expires_at < now()` while preparing/running), oldest expiry first, selected with
     * `FOR UPDATE ... SKIP LOCKED`. PLATFORM scan on purpose, identifiers and the observed epoch only; follow with a
     * tenant-scoped re-read and `reclaimLease`.
     * @param {{ limit?: number }} [input]
     * @param {any} [client]
     * @returns {Promise<Array<{ id: string, tenantId: string, leaseEpoch: number }>>}
     */
    async peekExpiredLeases({ limit = 20 } = {}, client = db) {
      return client.$queryRaw`
        SELECT id, tenant_id AS "tenantId", lease_epoch AS "leaseEpoch"
        FROM executions
        WHERE status IN ('preparing', 'running') AND lease_expires_at < now()
        ORDER BY lease_expires_at, id
        LIMIT ${Math.max(1, Math.floor(limit))}
        FOR UPDATE SKIP LOCKED`;
    },

    /**
     * Reclaim of an expired lease (ER-28): compare-and-set on `(id, tenant_id, lease_epoch = observed)` that also requires the
     * lease to be expired NOW and increments the epoch. Exactly one concurrent reclaimer gets the row; every other gets `null`.
     * The winner may record the `recovered` event in the same transaction (`event.details`: epoch, step, decision; no secret).
     * The audit entry `execution.lease_reclaimed` is the caller's, in the same transaction.
     * @param {{ tenantId: string, executionId: string, workerId: string, observedEpoch: number, leaseTtlSeconds: number, event?: { details?: Record<string, unknown>, correlationId?: string } }} input
     * @param {any} [client]
     * @returns {Promise<null | { id: string, tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, status: string, statusRev: number, leaseOwner: string, leaseEpoch: number, leaseExpiresAt: Date, heartbeatAt: Date, claimedAt: Date, deadlineAt: Date, requestedAt: Date }>}
     */
    async reclaimLease(
      { tenantId, executionId, workerId, observedEpoch, leaseTtlSeconds, event },
      client = db,
    ) {
      const ttl = seconds(leaseTtlSeconds, "leaseTtlSeconds");
      return withTransaction(client, async (tx) => {
        const rows = await tx.$queryRaw`
          UPDATE executions
          SET lease_owner = ${workerId}, lease_epoch = lease_epoch + 1, heartbeat_at = now(),
              lease_expires_at = now() + make_interval(secs => ${ttl}::double precision)
          WHERE id = ${executionId}::uuid AND tenant_id = ${tenantId}::uuid AND lease_epoch = ${observedEpoch}::int
            AND lease_expires_at < now() AND status IN ('preparing', 'running')
          RETURNING ${LEASE_COLUMNS}`;
        const row = rows[0] ?? null;
        if (row && event) {
          await tx.executionEvent.create({
            data: {
              tenantId: row.tenantId,
              workspaceId: row.workspaceId,
              repositoryId: row.repositoryId,
              pipelineId: row.pipelineId,
              executionId: row.id,
              type: "recovered",
              actorType: "system",
              correlationId: event.correlationId ?? null,
              details: { epoch: row.leaseEpoch, workerId, ...event.details },
            },
          });
        }
        return row;
      });
    },

    fenceExecution,

    /**
     * A status change by compare-and-set (EXEC-003, ER-20): the statement matches only `from` (and, for `preparing`/`running`,
     * the held `leaseEpoch`), so of two racing terminal transitions exactly one wins and the loser changes nothing and records
     * nothing. A lease is cleared in the statement that makes the row terminal. The `transition` event row is written by the
     * database in the same statement, with `actor`, `correlationId` and `eventDetails`. With `releaseQuota` the statement also
     * sets `quota_released_at` (once, only when a unit was consumed) and, in the same transaction, gives the unit back with the
     * STORED period and amount; only the transitions of section 5.9 may release (`queued`/`preparing` -> `cancelled`,
     * `preparing` -> `failed`). Audit entries and outbox messages are the caller's, in the same transaction.
     * @param {{ tenantId: string, executionId: string, from: string, to: string, reason?: string | null, leaseEpoch?: number, actor?: { type: "system" | "user", userId?: string }, correlationId?: string, eventDetails?: Record<string, unknown>, taskCounts?: Record<string, number>, releaseQuota?: boolean }} input
     * @param {any} [client] Prisma client or the caller's transaction client (a transaction is opened when needed).
     * @returns {Promise<{ transitioned: boolean, execution: null | { id: string, status: string, statusRev: number, leaseEpoch: number }, quotaReleased: boolean }>}
     */
    async transitionExecution(input, client = db) {
      const {
        tenantId,
        executionId,
        from,
        to,
        reason = null,
        leaseEpoch,
        releaseQuota = false,
      } = input;
      if (!canTransitionExecution(from, to))
        throw new TypeError(`transition ${from} -> ${to} is not allowed`);
      const active = EXECUTION_ACTIVE_STATUSES.includes(from);
      if (active && !Number.isInteger(leaseEpoch))
        throw new TypeError("a transition out of preparing/running needs the held leaseEpoch");
      if (releaseQuota && !canReleaseQuotaOnTransition(from, to))
        throw new TypeError(`${from} -> ${to} never gives the quota unit back`);
      const terminal = isTerminalExecutionStatus(to);
      return withTransaction(client, async (tx) => {
        await setEventContext(tx, {
          actor: input.actor,
          correlationId: input.correlationId,
          details: input.eventDetails,
        });
        const lease = terminal
          ? Prisma.sql`, lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL`
          : Prisma.empty;
        const counts = input.taskCounts
          ? Prisma.sql`, task_counts = ${JSON.stringify(input.taskCounts)}::jsonb`
          : Prisma.empty;
        const release = releaseQuota
          ? Prisma.sql`, quota_released_at = CASE WHEN quota_consumed > 0 THEN now() END`
          : Prisma.empty;
        const fence = active ? Prisma.sql`AND lease_epoch = ${leaseEpoch}::int` : Prisma.empty;
        const rows = await tx.$queryRaw`
          UPDATE executions
          SET status = ${to}::execution_status, status_reason = ${reason}, updated_at = now()${lease}${counts}${release}
          WHERE id = ${executionId}::uuid AND tenant_id = ${tenantId}::uuid AND status = ${from}::execution_status ${fence}
          RETURNING id, status::text AS status, status_rev AS "statusRev", lease_epoch AS "leaseEpoch",
                    quota_period AS "quotaPeriod", quota_consumed AS "quotaConsumed", quota_released_at AS "quotaReleasedAt"`;
        const row = rows[0];
        if (!row) return { transitioned: false, execution: null, quotaReleased: false };
        const quotaReleased = Boolean(row.quotaReleasedAt);
        if (quotaReleased)
          await quota.releaseQuota(
            {
              tenantId,
              quotaKey: QUOTA_KEYS.SCANS_MONTHLY,
              amount: row.quotaConsumed,
              periodKey: row.quotaPeriod,
            },
            tx,
          );
        return {
          transitioned: true,
          execution: {
            id: row.id,
            status: row.status,
            statusRev: row.statusRev,
            leaseEpoch: row.leaseEpoch,
          },
          quotaReleased,
        };
      });
    },

    /**
     * Appends a NON-transition history row (`recovered`, `cancel_requested`, `limit_deferred`, `retry_requested`); `transition`
     * rows are written by the database. With `leaseEpoch` the write is fenced (a lease holder's write). The sequence number
     * is assigned by the database. Returns `null` when the execution is not the tenant's, or terminal (the database refuses
     * events of a finished execution).
     * @param {{ tenantId: string, executionId: string, type: string, reason?: string | null, actor?: { type: "system" | "user", userId?: string }, correlationId?: string, details?: Record<string, unknown>, leaseEpoch?: number }} input
     * @param {any} [client]
     */
    async recordEvent(input, client = db) {
      const { tenantId, executionId, type, reason = null, leaseEpoch } = input;
      if (type === "transition" || !EXECUTION_EVENT_TYPES.includes(type))
        throw new TypeError(
          "recordEvent writes recovered, cancel_requested, limit_deferred or retry_requested rows",
        );
      return withTransaction(client, async (tx) => {
        if (Number.isInteger(leaseEpoch))
          await fenceExecution({ tenantId, executionId, leaseEpoch }, tx);
        const exec = await tx.execution.findFirst({
          where: { id: executionId, tenantId },
          select: { workspaceId: true, repositoryId: true, pipelineId: true },
        });
        if (!exec) return null;
        return tx.executionEvent.create({
          data: {
            tenantId,
            ...exec,
            executionId,
            type,
            reason,
            actorType: input.actor?.type ?? "system",
            actorUserId: input.actor?.userId ?? null,
            correlationId: input.correlationId ?? null,
            details: input.details ?? {},
          },
        });
      });
    },

    /**
     * The history of one execution, oldest first. Tenant AND execution scoped.
     * @param {{ tenantId: string, executionId: string, afterSeq?: number, limit?: number }} input
     * @param {any} [client]
     */
    listEvents: ({ tenantId, executionId, afterSeq = 0, limit = 100 }, client = db) =>
      client.executionEvent.findMany({
        where: { tenantId, executionId, seq: { gt: afterSeq } },
        orderBy: { seq: "asc" },
        take: Math.min(Math.max(1, limit), 500),
      }),
  });
}
