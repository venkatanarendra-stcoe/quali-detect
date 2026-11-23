import { Prisma } from "@prisma/client";
import {
  FINDING_SEVERITIES,
  FINDINGS_LIMITS,
  OPEN_FINDING_STATUSES,
  SLA_DEFAULT_HOURS,
} from "@qmentisai/shared";
import { FindingConflictError } from "./errors.js";
import { createFindingsRepository } from "./findings.js";
import { emitFindingEvent } from "./lifecycle-support.js";
import { transitionFinding } from "./transitions.js";

/**
 * @typedef {import("./transitions.js").FindingScope} FindingScope
 */

/** The statuses of the five board columns (SPEC C-3). A column is one status. */
const BOARD_COLUMN_STATUSES = Object.freeze([
  "assigned",
  "in_remediation",
  "fixed_pending_verification",
  "verified_fixed",
  "reopened",
]);
const DAY_MS = 86_400_000;
/** The "Verified fixed" column shows the last 30 days only (SPEC 8.1). */
export const BOARD_VERIFIED_WINDOW_DAYS = 30;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SEVERITIES = Object.freeze([...FINDING_SEVERITIES]);

/**
 * Assignment rows, the remediation board and the SLA settings and sweep (Part C, docs/modules/findings/SPEC.md 5.7, 5.9, 8.1, 8.2).
 * EVERY write method runs inside the caller's transaction `tx` with the finding row ALREADY locked and re-checked by the service; the
 * status always changes through `transitionFinding` with the actor set (a USER here), so the history row, the audit entry and the
 * realtime hint are written by the one central function, and this repository adds the assignment row and the domain event in the same
 * transaction. The database is the second lock (the assignee-while-assigned CHECK, the SM-10 trigger, the assignment guard).
 * @param {{ db: any }} deps
 */
export function createFindingAssignmentsRepository({ db }) {
  const reads = createFindingsRepository({ db });

  /** Ends the open assignment of the finding (at most one is open), by tenant AND finding. @returns {Promise<string | null>} the ended assignment's id */
  async function endOpenAssignment(tx, tenantId, findingId, reason) {
    const open = await tx.findingAssignment.findFirst({
      where: { tenantId, findingId, endedAt: null },
      select: { id: true },
      orderBy: { createdAt: "desc" },
    });
    if (!open) return null;
    await tx.findingAssignment.update({
      where: { tenantId_id: { tenantId, id: open.id } },
      data: { endedAt: new Date(), endedReason: reason },
    });
    return open.id;
  }

  return Object.freeze({
    /**
     * AS-1, SM-9, SM-10, SM-17: assigns (from `approved` or `reopened`) or reassigns (from `assigned` or `in_remediation`, the status
     * stays, SM-10) the finding. The previous open assignment is ended, a new row is inserted and the finding's assignee is set with the
     * transition (history `assigned` or `reassigned`, audit `finding.assigned`). Event `finding.assigned`.
     * @type {(tx: any, input: { scope: FindingScope, finding: any, assigneeUserId: string, assignedByUserId: string, note?: string | null, expectedRev?: number }) => Promise<{ assignmentId: string, rev: number, reassigned: boolean }>}
     */
    async assign(tx, { scope, finding, assigneeUserId, assignedByUserId, note, expectedRev }) {
      const actor = { type: /** @type {const} */ ("user"), userId: assignedByUserId };
      const reassigned = finding.status === "assigned" || finding.status === "in_remediation";
      if (!reassigned && finding.status !== "approved" && finding.status !== "reopened")
        throw new FindingConflictError("transition_not_allowed");
      // moving a finding to the person who already has it changes nothing: refused, not recorded as a reassignment
      if (reassigned && finding.assigneeUserId === assigneeUserId)
        throw new FindingConflictError("transition_not_allowed");
      await endOpenAssignment(
        tx,
        scope.tenantId,
        finding.id,
        reassigned ? "reassigned" : "superseded",
      );
      const assignment = await tx.findingAssignment.create({
        data: {
          tenantId: scope.tenantId,
          workspaceId: scope.workspaceId,
          repositoryId: finding.repositoryId,
          pipelineId: finding.pipelineId,
          findingId: finding.id,
          assigneeUserId,
          assignedByUserId,
          note: note ?? null,
        },
        select: { id: true },
      });
      const done = await transitionFinding(tx, {
        scope,
        findingId: finding.id,
        expectedRev,
        to: reassigned ? null : "assigned",
        actor,
        reasonCode: reassigned ? "reassigned" : "assigned",
        ...(note ? { note } : {}),
        columns: { assigneeUserId, assignedAt: new Date() },
      });
      await emitFindingEvent(
        tx,
        scope,
        finding,
        actor,
        "finding.assigned",
        `finding-assigned-${finding.id}-${done.rev}`,
        {
          findingId: finding.id,
          workspaceId: scope.workspaceId,
          assignmentId: assignment.id,
          assigneeUserId,
          rev: done.rev,
        },
      );
      return { assignmentId: assignment.id, rev: done.rev, reassigned };
    },

    /**
     * AS-2, SM-11: unassigns (`assigned` or `in_remediation` back to `approved`). The open assignment is ended and the assignee cleared
     * with the transition (history `unassigned`, audit `finding.unassigned`). Event `finding.assigned` with no assignee.
     * @type {(tx: any, input: { scope: FindingScope, finding: any, userId: string, note?: string | null, expectedRev?: number }) => Promise<{ rev: number }>}
     */
    async clear(tx, { scope, finding, userId, note, expectedRev }) {
      const actor = { type: /** @type {const} */ ("user"), userId };
      if (finding.status !== "assigned" && finding.status !== "in_remediation")
        throw new FindingConflictError("transition_not_allowed");
      await endOpenAssignment(tx, scope.tenantId, finding.id, "unassigned");
      const done = await transitionFinding(tx, {
        scope,
        findingId: finding.id,
        expectedRev,
        to: "approved",
        actor,
        reasonCode: "unassigned",
        ...(note ? { note } : {}),
        columns: { assigneeUserId: null, assignedAt: null },
      });
      await emitFindingEvent(
        tx,
        scope,
        finding,
        actor,
        "finding.assigned",
        `finding-assigned-${finding.id}-${done.rev}`,
        {
          findingId: finding.id,
          workspaceId: scope.workspaceId,
          assignmentId: null,
          assigneeUserId: null,
          rev: done.rev,
        },
      );
      return { rev: done.rev };
    },

    /**
     * `GET /remediation/board` and one column page (SPEC 8.1). `query.column` names the column; `query.after` is the decoded keyset
     * position `[severity, id]` (most severe first, the id ascending); filters `assignee`, `severity`, `pipelineId`, `sla` narrow the
     * column, never widen it. Every query carries tenant AND workspace. Returns `{ items, totalItems, hasMore, nextKey }` where each item
     * is a list entry (`{ finding, pipeline, repository, claimedBy, assignee, advisoryHint }`) plus `remediation` (the latest submitted
     * fix of the finding: `{ pullRequestUrl, ticketKey }` or null), fetched with ONE extra query for the page.
     * @type {(scope: FindingScope, query: { column: string, limit: number, after?: Array<string | null> | null, withTotal?: boolean, severity?: string[], assignee?: string, pipelineId?: string, sla?: string[], now?: Date }, caller: { userId: string }) => Promise<{ items: object[], totalItems: number | null, hasMore: boolean, nextKey: Array<string | null> | null }>}
     */
    async board(scope, query, caller) {
      if (!BOARD_COLUMN_STATUSES.includes(query.column)) throw new TypeError("unknown column");
      const now = query.now ?? new Date();
      const page = await reads.list(
        scope,
        {
          status: [query.column],
          severity: query.severity,
          assignee: query.assignee,
          pipelineId: query.pipelineId,
          sla: query.sla,
          ...(query.column === "verified_fixed"
            ? { verifiedSince: new Date(now.getTime() - BOARD_VERIFIED_WINDOW_DAYS * DAY_MS) }
            : {}),
          sort: "severity",
          direction: "desc",
          limit: query.limit,
          after: query.after ?? undefined,
          withTotal: query.withTotal === true,
          now,
        },
        caller,
      );
      const ids = page.items.map((e) => e.finding.id);
      /** @type {Map<string, { pullRequestUrl: string | null, ticketKey: string | null }>} */
      const fixes = new Map();
      if (ids.length > 0) {
        const rows = await db.remediationRecord.findMany({
          where: {
            tenantId: scope.tenantId,
            workspaceId: scope.workspaceId,
            kind: "fix_submitted",
            findingId: { in: ids },
          },
          orderBy: { createdAt: "desc" },
          select: { findingId: true, pullRequestUrl: true, ticketKey: true },
        });
        for (const r of rows)
          if (!fixes.has(r.findingId))
            fixes.set(r.findingId, { pullRequestUrl: r.pullRequestUrl, ticketKey: r.ticketKey });
      }
      return {
        items: page.items.map((e) => ({ ...e, remediation: fixes.get(e.finding.id) ?? null })),
        totalItems: page.totalItems,
        hasMore: page.hasMore,
        nextKey: page.nextKey,
      };
    },

    /**
     * Counts of the five columns under the same filters (one grouped query), by tenant AND workspace.
     * @type {(scope: FindingScope, query: { severity?: string[], assignee?: string, pipelineId?: string, sla?: string[], now?: Date }, caller: { userId: string }) => Promise<Record<string, number>>}
     */
    async boardCounts(scope, query, caller) {
      const now = query.now ?? new Date();
      const entries = await Promise.all(
        BOARD_COLUMN_STATUSES.map(async (column) => {
          const page = await reads.list(
            scope,
            {
              status: [column],
              severity: query.severity,
              assignee: query.assignee,
              pipelineId: query.pipelineId,
              sla: query.sla,
              ...(column === "verified_fixed"
                ? { verifiedSince: new Date(now.getTime() - BOARD_VERIFIED_WINDOW_DAYS * DAY_MS) }
                : {}),
              sort: "severity",
              limit: 1,
              withTotal: true,
              now,
            },
            caller,
          );
          return [column, page.totalItems ?? 0];
        }),
      );
      return Object.fromEntries(entries);
    },

    /**
     * The tenant's SLA targets with the defaults (SL-1): one entry per severity in declaration order, `hours: null` for a severity with
     * no target (info), `isDefault` when the tenant has no row of its own.
     * @type {(scope: { tenantId: string }) => Promise<Array<{ severity: string, hours: number | null, isDefault: boolean }>>}
     */
    async readSlaTargets({ tenantId }, tx = db) {
      const rows = await tx.findingSlaTarget.findMany({
        where: { tenantId },
        select: { severity: true, hours: true },
      });
      const own = new Map(rows.map((r) => [r.severity, r.hours]));
      return SEVERITIES.map((severity) => ({
        severity,
        hours: own.has(severity) ? own.get(severity) : (SLA_DEFAULT_HOURS[severity] ?? null),
        isDefault: !own.has(severity),
      }));
    },

    /**
     * Replaces the tenant's SLA targets (PUT semantics, SL-1): the severities in `targets` get their own row, every other severity goes
     * back to the shared default (its row is removed). A target equal to the default is still stored (the tenant chose it). The
     * caller audits (`tenant.findings_sla_changed`) with the returned `changes` and rolls back with its own transaction. Running
     * findings keep the due date their clock was started with (SL-1: a change is not retroactive).
     * @type {(tx: any, scope: { tenantId: string }, targets: Array<{ severity: string, hours: number }>, userId: string) => Promise<{ changes: Array<{ severity: string, previous: number | null, next: number | null }> }>}
     */
    async writeSlaTargets(tx, { tenantId }, targets, userId) {
      if (!UUID.test(tenantId) || !UUID.test(userId)) throw new TypeError("a trusted scope");
      for (const t of targets)
        if (
          !SEVERITIES.includes(t.severity) ||
          t.severity === "info" ||
          !Number.isInteger(t.hours) ||
          t.hours < 1 ||
          t.hours > FINDINGS_LIMITS.slaHoursMax
        )
          throw new TypeError("an SLA target is out of range");
      const before = new Map(
        (await tx.findingSlaTarget.findMany({ where: { tenantId } })).map((r) => [
          r.severity,
          r.hours,
        ]),
      );
      const effective = (severity, map) =>
        map.has(severity) ? map.get(severity) : (SLA_DEFAULT_HOURS[severity] ?? null);
      const after = new Map(targets.map((t) => [t.severity, t.hours]));
      const changes = [];
      for (const severity of SEVERITIES) {
        const was = before.has(severity);
        const will = after.has(severity);
        if (will) {
          if (!was || before.get(severity) !== after.get(severity)) {
            await tx.findingSlaTarget.upsert({
              where: { tenantId_severity: { tenantId, severity } },
              create: { tenantId, severity, hours: after.get(severity), updatedByUserId: userId },
              update: {
                hours: after.get(severity),
                updatedByUserId: userId,
                updatedAt: new Date(),
              },
            });
          }
        } else if (was) {
          await tx.findingSlaTarget.delete({
            where: { tenantId_severity: { tenantId, severity } },
          });
        }
        const previous = effective(severity, before);
        const next = effective(severity, after);
        if (was !== will || previous !== next) changes.push({ severity, previous, next });
      }
      return { changes };
    },

    /**
     * The SLA sweep's work list (SL-4), bounded: open findings with a running clock that crossed `due_soon` or `breached` and were NOT
     * yet notified for it in this cycle. `phase` is the strongest crossed state (`breached` wins over `due_soon`). Ordered oldest due
     * first so a backlog drains in order. Rows carry ids and the due date only.
     * @type {(now: Date, limit: number) => Promise<Array<{ tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, id: string, severity: string, rev: number, slaDueAt: Date, phase: "due_soon" | "breached" }>>}
     */
    async dueForSweep(now, limit) {
      if (!(now instanceof Date) || !Number.isInteger(limit) || limit < 1 || limit > 2000)
        throw new TypeError("a clock and a bounded limit");
      const open = Prisma.raw(OPEN_FINDING_STATUSES.map((s) => `'${s}'`).join(", "));
      // `due_soon` is the last quarter of the target (SL-3), the same arithmetic as `deriveSlaState`
      const rows = await db.$queryRaw`
        SELECT f.tenant_id::text AS "tenantId", f.workspace_id::text AS "workspaceId", f.repository_id::text AS "repositoryId",
               f.pipeline_id::text AS "pipelineId", f.id::text AS id, f.severity::text AS severity, f.rev, f.sla_due_at AS "slaDueAt",
               CASE WHEN f.sla_due_at < ${now}::timestamptz THEN 'breached' ELSE 'due_soon' END AS phase
        FROM findings f
        WHERE f.status IN (${open}) AND f.sla_due_at IS NOT NULL AND f.sla_started_at IS NOT NULL
          AND (
            (f.sla_due_at < ${now}::timestamptz AND (f.sla_breach_notified_at IS NULL OR f.sla_breach_notified_at < f.sla_started_at))
            OR (f.sla_due_at >= ${now}::timestamptz AND (f.sla_due_soon_notified_at IS NULL OR f.sla_due_soon_notified_at < f.sla_started_at)
                AND (f.sla_breach_notified_at IS NULL OR f.sla_breach_notified_at < f.sla_started_at) AND f.sla_due_at > f.sla_started_at
                AND (f.sla_due_at - ${now}::timestamptz) <= (f.sla_due_at - f.sla_started_at) * 0.25::float8)
          )
        ORDER BY f.sla_due_at ASC, f.id ASC
        LIMIT ${limit}`;
      return rows;
    },

    /**
     * Marks ONE finding's SLA threshold as notified and writes the event, in the caller's transaction (SL-4). The finding is locked by
     * tenant, workspace and id and re-checked: still open, clock still running, the same due date, not yet notified for this phase;
     * otherwise nothing is written (a replay, another sweep instance or a changed clock). A marker older than the clock's start is from
     * an EARLIER cycle (a reopening restarts the clock), so each cycle notifies once. Returns whether it notified. The marker
     * columns are not status columns: `rev` rises by one as the trigger demands, no history row (a status or assignee did not change).
     * `breached` also marks `due_soon` as notified (a clock that was never swept in its last quarter does not announce both).
     * @type {(tx: any, ref: { tenantId: string, workspaceId: string, id: string, phase: "due_soon" | "breached", dueAt: Date }, now: Date) => Promise<{ notified: boolean }>}
     */
    async notifySla(tx, { tenantId, workspaceId, id, phase, dueAt }, now) {
      if (phase !== "due_soon" && phase !== "breached") throw new TypeError("phase");
      const rows = await tx.$queryRaw`
        SELECT f.repository_id::text AS "repositoryId", f.pipeline_id::text AS "pipelineId", f.status::text AS status, f.severity::text AS severity,
               f.rev, f.sla_due_at AS "slaDueAt", f.sla_started_at AS "slaStartedAt",
               f.sla_due_soon_notified_at AS "dueSoonAt", f.sla_breach_notified_at AS "breachAt"
        FROM findings f
        WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid AND f.id = ${id}::uuid
        FOR UPDATE`;
      const row = rows[0];
      if (
        !row ||
        !OPEN_FINDING_STATUSES.includes(row.status) ||
        !row.slaDueAt ||
        new Date(row.slaDueAt).getTime() !== new Date(dueAt).getTime()
      )
        return { notified: false };
      // "once per cycle": a marker older than the clock's start belongs to an earlier cycle (a reopening restarts the clock)
      const started = new Date(row.slaStartedAt).getTime();
      const marked = (at) => at !== null && at !== undefined && new Date(at).getTime() >= started;
      if (phase === "breached") {
        if (marked(row.breachAt) || new Date(row.slaDueAt).getTime() >= now.getTime())
          return { notified: false };
      } else if (
        marked(row.dueSoonAt) ||
        marked(row.breachAt) ||
        new Date(row.slaDueAt).getTime() < now.getTime()
      ) {
        return { notified: false };
      }
      const rev = row.rev + 1;
      await tx.$executeRaw`SELECT set_config('qm.finding_actor_type', 'system', true)`;
      await tx.finding.update({
        where: { tenantId_id: { tenantId, id } },
        data:
          phase === "breached"
            ? {
                slaBreachNotifiedAt: now,
                slaDueSoonNotifiedAt: marked(row.dueSoonAt) ? row.dueSoonAt : now,
                rev,
              }
            : { slaDueSoonNotifiedAt: now, rev },
      });
      const type = phase === "breached" ? "finding.sla_breached" : "finding.sla_due_soon";
      await emitFindingEvent(
        tx,
        { tenantId, workspaceId },
        { id, repositoryId: row.repositoryId, pipelineId: row.pipelineId },
        { type: "system", code: "sla" },
        type,
        `${type.replace(".", "-").replace("_", "-")}-${id}-${new Date(row.slaDueAt).getTime()}`,
        {
          findingId: id,
          workspaceId,
          severity: row.severity,
          dueAt: new Date(row.slaDueAt).toISOString(),
        },
      );
      return { notified: true };
    },
  });
}
