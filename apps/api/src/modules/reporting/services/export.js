import { randomUUID } from "node:crypto";
import { ERROR_CODES, QUEUE_NAMES, createJobEnvelope, parseMessage } from "@qmentisai/contracts";
import { withTransaction } from "@qmentisai/db";
import {
  REPORTING_LIMITS,
  REPORT_TEMPLATE_BY_ID,
  ReportPeriodError,
  can,
  localDayOf,
  resolvePeriod,
} from "@qmentisai/shared";
import {
  AppError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
} from "../../../errors/app-error.js";
import { toReportDto } from "../mappers/export.js";

const HOUR_MS = 60 * 60 * 1000;

/** The period error of the shared helpers as the stable API error. @param {unknown} error */
const asAppError = (error) =>
  error instanceof ReportPeriodError
    ? new AppError(ERROR_CODES[error.code] ?? ERROR_CODES.REPORT_PERIOD_INVALID, error.message)
    : error;

/**
 * Whether the permission set holds `report.export` for the report's scope: in its workspace, or (tenant-wide) in EVERY workspace of the
 * tenant together with `dashboard.view` (SPEC 3: a tenant-wide report needs `dashboard.view` and `report.export` at tenant scope).
 * @param {any} permissions @param {string | null} workspaceId @param {number} workspaceCount
 */
export function holdsExport(permissions, workspaceId, workspaceCount) {
  if (workspaceId) return can(permissions, "report.export", { type: "workspace", workspaceId });
  const visible = permissions?.workspaces ?? [];
  return (
    can(permissions, "dashboard.view") &&
    visible.length > 0 &&
    visible.length === workspaceCount &&
    visible.every((w) =>
      can(permissions, "report.export", { type: "workspace", workspaceId: w.id }),
    )
  );
}

/**
 * The export use cases (docs/modules/reporting-dashboards/SPEC.md 7.3, 7.4, 9, 12). The tenant and the user come from the SESSION only (the
 * `actor`), never from the body; every report is loaded by tenant AND id; the `report_exports` row, the outbox message and the audit entry
 * of a request are written in ONE transaction, under a per-tenant advisory lock so the limits cannot be raced.
 * @param {{
 *   db: any,
 *   exports: ReturnType<typeof import("@qmentisai/db").createReportingExportsRepository>,
 *   counter: { countExportRows: Function },
 *   support: ReturnType<typeof import("../repositories/export.js").createReportExportSupport>,
 *   audit: any, outbox: any, reader: { size: Function, open: Function, keyFor: Function } | null,
 *   now?: () => Date,
 * }} deps `counter` is a worker-repository built on the READ client: it counts the rows of a template over the views for the cap check
 */
export function createReportExportService({
  db,
  exports,
  counter,
  support,
  audit,
  outbox,
  reader,
  now = () => new Date(),
}) {
  /** @param {any} actor @param {string} id */
  async function loadReport(actor, id) {
    const row = await exports.getExport({ tenantId: actor.tenantId, id });
    if (!row || row.deletedAt) throw new NotFoundError();
    return row;
  }

  const audited = (actor, action, row, metadata, tx) =>
    audit.tenant.record(
      {
        tenantId: actor.tenantId,
        actorUserId: actor.userId,
        action,
        targetType: "report",
        targetId: row.id,
        workspaceId: row.workspaceId ?? undefined,
        correlationId: actor.requestId,
        ipAddress: actor.ip,
        metadata,
      },
      tx ? { tx } : undefined,
    );

  /** The facts of a report that are safe to audit: ids, enums and days; never a value. */
  const facts = (row) => ({
    template: row.template,
    format: row.format,
    scope: row.workspaceId ? "workspace" : "tenant",
    ...(row.periodFrom ? { periodFrom: row.periodFrom, periodTo: row.periodTo } : {}),
    ...(row.asOfDay ? { asOfDay: row.asOfDay } : {}),
  });

  const downloadable = (row, at) =>
    row.status === "ready" && row.expiresAt !== null && row.expiresAt.getTime() > at.getTime();

  return Object.freeze({
    /**
     * `POST /reporting/reports`: validates, applies the limits BEFORE queuing, and queues.
     * @param {{ tenantId: string, userId: string, permissions: any, requestId?: string, ip?: string }} actor
     * @param {import("zod").infer<typeof import("@qmentisai/shared").createReportBodySchema>} body
     * @returns {Promise<{ reportId: string }>}
     */
    async create(actor, body) {
      const at = now();
      const template = REPORT_TEMPLATE_BY_ID[body.template];
      if (!template?.v1 || !template.formats.includes(body.format))
        throw new AppError(ERROR_CODES.REPORT_TEMPLATE_UNKNOWN, "Unknown report template.");
      const workspaceId = body.workspaceId ?? null;
      const timeZone = await support.tenantTimeZone(actor.tenantId);

      let periodFrom = null;
      let periodTo = null;
      let asOfDay = null;
      try {
        if (template.periodMode === "period") {
          const p = resolvePeriod(
            { period: body.period, from: body.from, to: body.to },
            { now: at, timeZone },
          );
          periodFrom = p.from;
          periodTo = p.to;
        } else if (template.periodMode === "asOfDay") {
          if (/** @type {string} */ (body.asOfDay) > localDayOf(at, timeZone))
            throw new ReportPeriodError("REPORT_PERIOD_INVALID", "the day is in the future");
          asOfDay = /** @type {string} */ (body.asOfDay);
        }
      } catch (error) {
        throw asAppError(error);
      }
      if (asOfDay) {
        // a day before the first history row of the scope cannot be reconstructed (REPORT_AS_OF_UNAVAILABLE); an empty history is an empty report
        const earliest = await support.earliestHistoryAt({ tenantId: actor.tenantId, workspaceId });
        if (earliest && asOfDay < localDayOf(earliest, timeZone))
          throw new AppError(
            ERROR_CODES.REPORT_AS_OF_UNAVAILABLE,
            "No history exists for that day.",
          );
      }

      // the requester's `finding.assign` decides whether the assignee column exists in the file (O-6); the worker cannot evaluate permissions
      const visible = actor.permissions?.workspaces ?? [];
      const includeAssignee = workspaceId
        ? can(actor.permissions, "finding.assign", { type: "workspace", workspaceId })
        : visible.length > 0 &&
          visible.every((w) =>
            can(actor.permissions, "finding.assign", { type: "workspace", workspaceId: w.id }),
          );
      const params = {
        ...(body.options?.distinctIssues ? { distinctIssues: true } : {}),
        ...(template.csvColumns.some((c) => c.requiresPermission) ? { includeAssignee } : {}),
      };

      // the row cap, BEFORE anything is queued: a request over the cap is refused, never truncated (SPEC 7.3, ruling 2026-11-26)
      let estimatedRows = null;
      if (body.format === "csv") {
        try {
          estimatedRows = await counter.countExportRows({
            tenantId: actor.tenantId,
            template: template.id,
            workspaceId,
            params,
            periodFrom,
            periodTo,
            asOfDay,
            timeZone,
          });
        } catch (error) {
          // the read role's 5 second statement timeout: a count that slow is a request far above the cap
          if (
            /57014|statement timeout|canceling statement/i.test(`${error?.code} ${error?.message}`)
          )
            throw new AppError(
              ERROR_CODES.REPORT_TOO_LARGE,
              "The report is too large. Narrow the scope or the period.",
              { details: { reason: "estimate_timeout" } },
            );
          throw error;
        }
        if (estimatedRows > REPORTING_LIMITS.csvMaxRows)
          throw new AppError(
            ERROR_CODES.REPORT_TOO_LARGE,
            "The report is too large. Narrow the scope or the period.",
            {
              details: { reason: "csv_rows", limit: REPORTING_LIMITS.csvMaxRows },
            },
          );
      }

      const id = randomUUID();
      await withTransaction(db, async (tx) => {
        await support.lockTenantExports(tx, actor.tenantId);
        if (
          (await exports.countActiveExports({ tenantId: actor.tenantId }, tx)) >=
          REPORTING_LIMITS.maxConcurrentExportsPerTenant
        )
          throw new AppError(
            ERROR_CODES.REPORT_LIMIT_REACHED,
            "Too many reports are being generated. Try again when one has finished.",
            { details: { reason: "tenant_concurrent" } },
          );
        if (
          (await exports.countExportsByUserSince(
            {
              tenantId: actor.tenantId,
              userId: actor.userId,
              since: new Date(at.getTime() - HOUR_MS),
            },
            tx,
          )) >= REPORTING_LIMITS.exportRequestsPerUserPerHour
        )
          throw new AppError(
            ERROR_CODES.REPORT_LIMIT_REACHED,
            "Too many report requests. Try again later.",
            { details: { reason: "user_hourly" } },
          );
        const row = await exports.createExport(
          {
            tenantId: actor.tenantId,
            id,
            workspaceId,
            template: template.id,
            format: body.format,
            params,
            periodFrom,
            periodTo,
            asOfDay,
            requestedByUserId: actor.userId,
            now: at,
          },
          tx,
        );
        // the message carries the report id ONLY: the worker loads the row by tenant and id
        const message = parseMessage(
          createJobEnvelope({
            messageId: `reporting-export-${id}`,
            type: "reporting.export.requested",
            schemaVersion: 1,
            tenantId: actor.tenantId,
            ...(workspaceId ? { workspaceId } : {}),
            correlationId:
              actor.requestId && /^[A-Za-z0-9._-]{1,128}$/.test(actor.requestId)
                ? actor.requestId
                : `reporting-export-${id}`,
            initiator: { type: "user", id: actor.userId },
            payload: { reportId: id },
          }),
        );
        await outbox.enqueue(tx, { queue: QUEUE_NAMES.REPORTING, message });
        await audited(
          actor,
          "report.generated",
          row,
          { ...facts(row), ...(estimatedRows === null ? {} : { estimatedRows }) },
          tx,
        );
      });
      return { reportId: id };
    },

    /**
     * `GET /reporting/reports`: one workspace's reports, or (no workspace) the tenant-wide ones. The caller's rights were checked by the route.
     * @param {any} actor @param {{ workspaceId?: string, status?: string, limit: number }} query @param {{ createdAt: Date, id: string } | null} after
     */
    async list(actor, query, after) {
      const { items, next } = await exports.listExports({
        tenantId: actor.tenantId,
        workspaceId: query.workspaceId ?? null,
        status: query.status,
        limit: query.limit,
        after,
      });
      const names = await support.memberNames(actor.tenantId, [
        ...new Set(items.map((r) => r.requestedByUserId)),
      ]);
      const count = await support.workspaceCount(actor.tenantId);
      const at = now();
      return {
        items: items.map((r) =>
          toReportDto(r, {
            names,
            at,
            canDownload:
              downloadable(r, at) &&
              (r.requestedByUserId === actor.userId ||
                holdsExport(actor.permissions, r.workspaceId, count)),
          }),
        ),
        next,
      };
    },

    /** `GET /reporting/reports/{id}` (status, never the file). @param {any} actor @param {string} id */
    async get(actor, id) {
      const row = await loadReport(actor, id);
      const names = await support.memberNames(actor.tenantId, [row.requestedByUserId]);
      const at = now();
      const count = await support.workspaceCount(actor.tenantId);
      return toReportDto(row, {
        names,
        at,
        canDownload:
          downloadable(row, at) &&
          (row.requestedByUserId === actor.userId ||
            holdsExport(actor.permissions, row.workspaceId, count)),
      });
    },

    /**
     * `GET /reporting/reports/{id}/download`: re-checks tenant (the load), workspace and `report.view` (the route's gate), the requester or
     * `report.export` holder, status, expiry and the object itself, audits, and returns what the controller streams.
     * @param {any} actor @param {string} id
     * @returns {Promise<{ stream: import("node:stream").Readable, bytes: number, filename: string, contentType: string }>}
     */
    async download(actor, id) {
      const row = await loadReport(actor, id);
      const count = await support.workspaceCount(actor.tenantId);
      if (
        row.requestedByUserId !== actor.userId &&
        !holdsExport(actor.permissions, row.workspaceId, count)
      )
        throw new ForbiddenError();
      const at = now();
      if (
        row.status === "expired" ||
        (row.status === "ready" && row.expiresAt && row.expiresAt.getTime() <= at.getTime())
      )
        throw new AppError(
          ERROR_CODES.REPORT_EXPIRED,
          "The report file has expired. Generate it again.",
        );
      if (row.status !== "ready")
        throw new AppError(ERROR_CODES.REPORT_NOT_READY, "The report is not ready.", {
          details: { status: row.status },
        });
      if (!reader)
        throw new AppError(ERROR_CODES.SERVICE_UNAVAILABLE, "Report storage is not available.");
      // the object name is built from the row's own ids and format (never from `object_key`, a request or a user)
      const ref = { tenantId: row.tenantId, reportId: row.id, format: row.format };
      const size = await reader.size(ref);
      if (size === null)
        throw new AppError(
          ERROR_CODES.REPORT_EXPIRED,
          "The report file is no longer available. Generate it again.",
        );
      if (row.bytes !== null && size !== row.bytes)
        throw new AppError(ERROR_CODES.SERVICE_UNAVAILABLE, "The report file is not available.");
      await audited(actor, "report.downloaded", row, {
        ...facts(row),
        bytes: row.bytes,
        rowCount: row.rowCount,
      });
      const day = row.createdAt.toISOString().slice(0, 10).replaceAll("-", "");
      return {
        stream: reader.open(ref),
        bytes: size,
        // built by the server from the template id (a-z and underscore), the creation day and the report id: never from a user string
        filename: `qmentisai-${row.template.replaceAll("_", "-")}-${day}-${row.id.slice(0, 8)}.${row.format}`,
        contentType: row.format === "csv" ? "text/csv; charset=utf-8" : "application/pdf",
      };
    },

    /** `DELETE /reporting/reports/{id}`: the requester or a `report.export` holder; a soft delete (the worker purges the file). @param {any} actor @param {string} id */
    async remove(actor, id) {
      const row = await loadReport(actor, id);
      const count = await support.workspaceCount(actor.tenantId);
      if (
        row.requestedByUserId !== actor.userId &&
        !holdsExport(actor.permissions, row.workspaceId, count)
      )
        throw new ForbiddenError();
      if (row.status === "queued" || row.status === "running")
        throw new ConflictError("The report is still being generated.", {
          details: { reason: "report_not_finished" },
        });
      await withTransaction(db, async (tx) => {
        // the audit row is written first, in a transaction that rolls back when the delete finds nothing to delete
        await audited(actor, "report.deleted", row, facts(row), tx);
        const done = await exports.softDeleteExport({ tenantId: actor.tenantId, id, now: now() });
        if (!done) throw new NotFoundError();
      });
    },
  });
}
