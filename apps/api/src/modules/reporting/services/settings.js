import { createHash, randomUUID } from "node:crypto";
import { QUEUE_NAMES, createJobEnvelope, parseMessage } from "@qmentisai/contracts";
import { REPORTING_LIMITS, addDays, localDayOf } from "@qmentisai/shared";
import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import { toReportingSettingsDto } from "../mappers/settings.js";

/** A rebuild that shows no finished run after this long is no longer reported as "recomputing" (the worker may be off). */
export const RECOMPUTING_WINDOW_MS = 24 * 3600 * 1000;
const DEFAULT_ZONE = "UTC";

/**
 * The id of the rebuild message of ONE change: the new zone plus a part that is distinct per change (a hash of the Idempotency-Key when
 * the request has one, so a replay is the same id and the outbox queues it once; a random part otherwise). It carries NO hour bucket, so
 * two real changes inside one hour queue two messages. Only characters of the envelope's safe id.
 * @param {{ tenantId: string, zone: string, idempotencyKey?: string | null }} input
 */
export function rebuildMessageId({ tenantId, zone, idempotencyKey }) {
  const part = idempotencyKey
    ? createHash("sha256").update(`${tenantId}:${idempotencyKey}`).digest("hex").slice(0, 16)
    : randomUUID().replaceAll("-", "").slice(0, 16);
  return `reporting-rollup-${tenantId}-tz-${zone.replace(/[^A-Za-z0-9._-]/g, "-")}-${part}`;
}

/**
 * Tenant reporting time zone use cases (SPEC 8.4, 17.1 D-5). The tenant and the user come from the session only.
 * @param {{ db: any, repository: ReturnType<typeof import("../repositories/settings.js").createReportingSettingsRepository>, audit: any, outbox: any,
 *   bumpEpochs: (input: { tenantId: string, workspaceIds: string[] }) => Promise<void>, config?: any, now?: () => Date }} deps
 */
export function createReportingSettingsService({
  db,
  repository,
  audit,
  outbox,
  bumpEpochs,
  config,
  now = () => new Date(),
}) {
  /** A rebuild was requested through this route and no run of the new zone covering the range has finished (and it is not stale). */
  async function isRecomputing(tenantId, row) {
    if (!row || !row.updatedByUserId) return false;
    if (now().getTime() - row.updatedAt.getTime() > RECOMPUTING_WINDOW_MS) return false;
    const finished = await repository.hasFinishedRebuild({
      tenantId,
      zone: row.reportingTimezone,
      since: row.updatedAt,
      reachesDay: localDayOf(row.updatedAt, row.reportingTimezone),
    });
    return !finished;
  }

  async function dto(tenantId, row) {
    const [name, recomputing] = await Promise.all([
      repository.memberName(tenantId, row?.updatedByUserId ?? null),
      isRecomputing(tenantId, row),
    ]);
    return toReportingSettingsDto(row, name, recomputing);
  }

  return Object.freeze({
    /** @param {{ tenantId: string }} actor */
    async get(actor) {
      return dto(actor.tenantId, await repository.findSettings(actor.tenantId));
    },

    /**
     * Sets the zone. Saving the zone the tenant already has is a no-op (no write, no audit entry, no rebuild). A real change writes the
     * settings row, the audit entry and the rebuild message in ONE transaction (the transactional outbox), under a per-tenant lock; the
     * cache epochs are bumped after the commit.
     * @param {{ tenantId: string, userId: string, requestId?: string, ip?: string }} actor
     * @param {{ reportingTimezone: string }} body @param {{ idempotencyKey?: string | null }} [options]
     */
    async update(actor, { reportingTimezone: zone }, { idempotencyKey = null } = {}) {
      const { tenantId, userId } = actor;
      let changed = false;
      const row = await db.$transaction(async (tx) => {
        await repository.lockTenant(tx, tenantId);
        const current = await repository.findSettings(tenantId, tx);
        const previous = current?.reportingTimezone ?? DEFAULT_ZONE;
        if (previous === zone) return current;
        const at = now();
        const stored = await repository.upsertZone({ tenantId, zone, userId, now: at }, tx);
        await audit.tenant.record(
          {
            tenantId,
            actorUserId: userId,
            action: AUDIT_ACTIONS.TENANT_REPORTING_TIMEZONE_CHANGED,
            targetType: "tenant_reporting_settings",
            targetId: tenantId,
            correlationId: actor.requestId,
            ipAddress: actor.ip,
            metadata: { previous, new: zone },
          },
          { tx },
        );
        // rebuild range: the tenant's earliest history day (capped at the rollup retention) to today, both in the NEW zone
        const months =
          config?.reporting?.rollupRetentionMonths ?? REPORTING_LIMITS.rollupRetentionMonths;
        const today = localDayOf(at, zone);
        const floor = addDays(today, -Math.min(months * 31, 790));
        const earliest = await repository.earliestHistoryAt(tenantId, tx);
        const first = earliest ? localDayOf(earliest, zone) : today;
        const message = parseMessage(
          createJobEnvelope({
            messageId: rebuildMessageId({ tenantId, zone, idempotencyKey }),
            type: "reporting.rollup.requested",
            schemaVersion: 1,
            tenantId,
            correlationId:
              actor.requestId && /^[A-Za-z0-9._-]{1,128}$/.test(actor.requestId)
                ? actor.requestId
                : undefined,
            initiator: { type: "user", id: userId },
            payload: {
              tenantId,
              mode: "backfill",
              from: first < floor ? floor : first,
              to: today,
              reason: "timezone_changed",
            },
          }),
        );
        await outbox.enqueue(tx, { queue: QUEUE_NAMES.REPORTING, message });
        changed = true;
        return stored;
      });
      if (changed) {
        // after the commit: a reader that re-caches between the bump and the commit would keep the old zone's numbers
        await bumpEpochs({ tenantId, workspaceIds: await repository.workspaceIds(tenantId) });
      }
      return dto(tenantId, row);
    },
  });
}
