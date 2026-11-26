import { ArtifactTooLargeError, NonRetryableError } from "@qmentisai/infra";
import {
  REPORTING_LIMITS,
  REPORT_TEMPLATE_BY_ID,
  REPORT_DEFAULT_TIME_ZONE,
  isValidTimeZone,
} from "@qmentisai/shared";
import { createCsvStream, csvColumnsFor } from "./csv-writer.js";
import { createReportObjectStore, reportObjectKey } from "./object-store.js";
import { ReportTooLargeError, createPdfReport } from "./pdf-kit.js";
import { CSV_RECORDS, PDF_SECTIONS } from "./templates.js";

/** A job that runs longer than this is failed with `timeout` (and a `running` row older than this is failed when its message is redelivered). */
export const EXPORT_TIMEOUT_MS = 15 * 60 * 1000;
/** The largest file a store accepts: a 250,000 row CSV is well below it, a 40 page PDF far below. */
const MAX_BYTES = { csv: 512 * 1024 * 1024, pdf: 64 * 1024 * 1024 };

/** Carries a stable failure code (one of `REPORT_FAILURE_CODES`). */
class ExportFailure extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "ExportFailure";
    this.code = code;
  }
}

/**
 * The stable failure code of an error (SPEC 7.4): `too_large`, `timeout`, `source_unavailable` or `internal`. Never a message: a database
 * error text could carry a value, so only the code is stored and only the code is logged.
 * @param {any} error
 */
export function failureCodeOf(error) {
  if (error instanceof ExportFailure) return error.code;
  if (error instanceof ReportTooLargeError || error instanceof ArtifactTooLargeError)
    return "too_large";
  if (error?.name === "TimeoutError" || error?.name === "AbortError") return "timeout";
  const code = String(error?.code ?? "");
  const text = String(error?.message ?? "");
  if (code === "57014" || /statement timeout|canceling statement/i.test(text)) return "timeout";
  if (
    ["P1001", "P1002", "P1008", "P1017", "P2024"].includes(code) ||
    /ECONNREFUSED|ECONNRESET|Can't reach database/i.test(text)
  )
    return "source_unavailable";
  return "internal";
}

/**
 * The source the template builders read: pages of a dataset through the export repository (the views only).
 * @param {{ repository: any, row: any, timeZone: string, now: Date, signal?: AbortSignal }} deps
 */
function createSource({ repository, row, timeZone, now, signal }) {
  const base = {
    tenantId: row.tenantId,
    template: row.template,
    workspaceId: row.workspaceId,
    periodFrom: row.periodFrom,
    periodTo: row.periodTo,
    asOfDay: row.asOfDay,
    timeZone,
  };
  const params = { ...row.params, now: now.toISOString() };
  const page = (dataset, after, limit) =>
    repository.readExportPage({ ...base, params: { ...params, dataset }, after, limit });
  async function* stream(dataset, pageSize = 2000) {
    let after = null;
    do {
      if (signal?.aborted) throw new ExportFailure("timeout");
      const { rows, next } = await page(dataset, after, pageSize);
      yield* rows;
      after = next;
    } while (after);
  }
  const all = async (dataset) => {
    const out = [];
    for await (const r of stream(dataset, 5000)) out.push(r);
    return out;
  };
  return {
    base: { ...base, params },
    stream,
    all,
    view: {
      from: row.periodFrom,
      to: row.periodTo,
      asOfDay: row.asOfDay,
      timeZone,
      now,
      distinct: row.params?.distinctIssues === true,
    },
  };
}

/**
 * The handler of `reporting.export.requested` (docs/modules/reporting-dashboards/SPEC.md 7.3, 10, 12). The message carries ONLY a report
 * id: the handler loads the `report_exports` row BY TENANT (the verified envelope's) AND id, claims it atomically (a repeated message does
 * nothing), checks the row cap BEFORE writing a file, builds the file from the `report_*_v` views only through the worker repository
 * (a page at a time, streamed to the store, so memory is bounded by the page size), stores it under `reports/<tenantId>/<reportId>.<ext>`,
 * records size and SHA-256 and completes the run, or fails it with a stable code. A tenant in the message body is refused.
 * @param {{ exportRepository: any, config: any, logger: any, now?: () => Date, store?: ReturnType<typeof createReportObjectStore> }} deps
 * @returns {(message: any, context?: { log?: any, attempt?: number, signal?: AbortSignal }) => Promise<void>}
 */
export function buildExportHandler(deps) {
  const repository = deps.exportRepository;
  const clock = deps.now ?? (() => new Date());
  const root = deps.config?.execution?.artifactStoreRoot ?? null;
  const retentionDays =
    deps.config?.reporting?.exportRetentionDays ?? REPORTING_LIMITS.fileRetentionDays;
  /** @type {ReturnType<typeof createReportObjectStore> | null} */
  const store = deps.store ?? (root ? createReportObjectStore({ root }) : null);

  return async function handleExport(message, context = {}) {
    const log = context.log ?? deps.logger;
    const tenantId = message?.tenantId;
    const reportId = message?.payload?.reportId;
    if (typeof tenantId !== "string" || typeof reportId !== "string")
      throw new NonRetryableError("report-reference-missing");
    // the payload schema is strict, so a tenant here cannot arrive; if one does, it is never trusted and never differs silently
    if (message.payload.tenantId !== undefined && message.payload.tenantId !== tenantId)
      throw new NonRetryableError("tenant-in-body-refused");

    const started = clock();
    const claimed = await repository.claimExport({ tenantId, id: reportId, now: started });
    if (!claimed) {
      // a replay, a deleted or unknown report: nothing to do, except a `running` row a crashed worker left behind
      const existing = await repository.getExportForWorker({ tenantId, id: reportId });
      if (
        existing?.status === "running" &&
        existing.startedAt &&
        started.getTime() - new Date(existing.startedAt).getTime() > EXPORT_TIMEOUT_MS
      ) {
        await repository.failExport({ tenantId, id: reportId, errorCode: "timeout", now: started });
        log.warn({ tenantId, reportId }, "reporting export: a stale running report was failed");
      } else
        log.info(
          { tenantId, reportId, status: existing?.status ?? "absent" },
          "reporting export: nothing to claim",
        );
      return;
    }

    const row = claimed;
    const timeZone = isValidTimeZone(row.timeZone) ? row.timeZone : REPORT_DEFAULT_TIME_ZONE;
    const ref = { tenantId: row.tenantId, reportId: row.id, format: row.format };
    const signal = AbortSignal.any([
      AbortSignal.timeout(EXPORT_TIMEOUT_MS),
      ...(context.signal ? [context.signal] : []),
    ]);
    let stored = false;
    try {
      const template = REPORT_TEMPLATE_BY_ID[row.template];
      if (!template?.v1 || !template.formats.includes(row.format))
        throw new ExportFailure("internal");
      if (!store) throw new ExportFailure("internal");
      reportObjectKey(ref); // throws for anything that is not two canonical ids and a known format
      const source = createSource({ repository, row, timeZone, now: started, signal });
      const count = await repository.countExportRows({ ...source.base });
      if (row.format === "csv" && count > REPORTING_LIMITS.csvMaxRows)
        throw new ExportFailure("too_large");

      let rowCount = count;
      let put;
      if (row.format === "csv") {
        let written = 0;
        const stream = createCsvStream({
          columns: csvColumnsFor(row.template, {
            includeAssignee: row.params?.includeAssignee === true,
          }),
          records: CSV_RECORDS[row.template](source),
          bom: row.params?.bom === true,
          onRow: () => {
            written += 1;
            if (written > REPORTING_LIMITS.csvMaxRows) throw new ExportFailure("too_large");
          },
        });
        put = await store.put(ref, stream, { maxBytes: MAX_BYTES.csv });
        rowCount = written;
      } else {
        const kit = createPdfReport({
          title: `QmentisAI ${template.title} report`,
          subtitle: reportSubtitle(row, timeZone, started, template.title),
          generatedAt: started,
        });
        const putting = store.put(ref, kit.doc, { maxBytes: MAX_BYTES.pdf });
        try {
          kit.begin();
          await PDF_SECTIONS[row.template](kit, source);
          if (kit.state.truncatedCells > 0)
            kit.paragraph(
              `${kit.state.truncatedCells} table cell${kit.state.truncatedCells === 1 ? " was" : "s were"} shortened to fit; the CSV export holds the full text.`,
              { muted: true, size: 8 },
            );
          kit.finish(template.title);
        } catch (error) {
          kit.doc.destroy();
          await putting.catch(() => {});
          throw error;
        }
        put = await putting;
      }
      stored = true;
      const finished = clock();
      const done = await repository.completeExport({
        tenantId: row.tenantId,
        id: row.id,
        objectKey: put.key,
        bytes: put.bytes,
        sha256: put.sha256,
        rowCount,
        expiresAt: new Date(finished.getTime() + retentionDays * 86400000),
        now: finished,
      });
      if (!done) {
        await store.delete(ref); // no longer running (failed by a redelivery): the file would be orphaned
        log.warn(
          { tenantId, reportId },
          "reporting export: the run was no longer running; the file was removed",
        );
      } else
        log.info(
          {
            tenantId,
            reportId,
            template: row.template,
            format: row.format,
            rows: rowCount,
            bytes: put.bytes,
            ms: finished.getTime() - started.getTime(),
          },
          "reporting export: ready",
        );
    } catch (error) {
      const errorCode = failureCodeOf(error);
      if (stored) await store?.delete(ref).catch(() => {});
      await repository.failExport({ tenantId, id: row.id, errorCode, now: clock() });
      // ids, the template and the code only: an error message could carry a value
      log.warn(
        { tenantId, reportId, template: row.template, format: row.format, errorCode },
        "reporting export: failed",
      );
    }
  };
}

/** @param {any} row @param {string} timeZone @param {Date} at @param {string} title @returns {string[]} */
function reportSubtitle(row, timeZone, at, title) {
  const lines = [
    title,
    row.workspaceId ? "Scope: one workspace" : "Scope: every workspace of the organization",
  ];
  if (row.periodFrom && row.periodTo)
    lines.push(`Period: ${row.periodFrom} to ${row.periodTo} (${timeZone})`);
  if (row.asOfDay) lines.push(`As of the end of ${row.asOfDay} (${timeZone})`);
  lines.push(`Generated ${at.toISOString().slice(0, 16).replace("T", " ")} UTC`);
  return lines;
}
