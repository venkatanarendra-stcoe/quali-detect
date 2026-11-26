import { toExportRow } from "./mappers.js";

const ACTIVE = ["queued", "running"];

/** `YYYY-MM-DD` to a `Date` at UTC midnight (a Prisma `DATE`). @param {string | null} day */
const dateOnly = (day) => (day ? new Date(`${day}T00:00:00.000Z`) : null);

/**
 * The API side of an export (the API's normal client): the run row, its limits and its lifecycle reads. Every method scopes by TENANT; a
 * report is never loaded by id alone. `createExport` and the counts take the caller's transaction (`tx`), so the row and the outbox
 * message commit together.
 * @param {{ db: any }} deps the API's normal Prisma client
 * @returns {Record<string, (...args: any[]) => any>}
 */
export function buildExportMethods({ db }) {
  const client = (tx) => tx ?? db;
  return {
    async createExport(args, tx) {
      const row = await client(tx).reportExport.create({
        data: {
          id: args.id,
          tenantId: args.tenantId,
          workspaceId: args.workspaceId ?? null,
          template: args.template,
          format: args.format,
          params: args.params ?? {},
          periodFrom: dateOnly(args.periodFrom),
          periodTo: dateOnly(args.periodTo),
          asOfDay: dateOnly(args.asOfDay),
          status: "queued",
          requestedByUserId: args.requestedByUserId,
          createdAt: args.now,
        },
      });
      return toExportRow(row);
    },

    countActiveExports: ({ tenantId }, tx) =>
      client(tx).reportExport.count({ where: { tenantId, status: { in: ACTIVE } } }),

    countExportsByUserSince: ({ tenantId, userId, since }, tx) =>
      client(tx).reportExport.count({
        where: { tenantId, requestedByUserId: userId, createdAt: { gte: since } },
      }),

    async getExport({ tenantId, id }) {
      const row = await db.reportExport.findFirst({ where: { tenantId, id } });
      return row ? toExportRow(row) : null;
    },

    async listExports({ tenantId, workspaceId, requestedByUserId, status, limit, after }) {
      const where = {
        tenantId,
        deletedAt: null,
        // `undefined` means "any workspace"; `null` means the tenant-wide reports only
        ...(workspaceId === undefined ? {} : { workspaceId }),
        ...(requestedByUserId ? { requestedByUserId } : {}),
        ...(status ? { status } : {}),
        ...(after
          ? {
              OR: [
                { createdAt: { lt: after.createdAt } },
                { createdAt: after.createdAt, id: { lt: after.id } },
              ],
            }
          : {}),
      };
      const rows = await db.reportExport.findMany({
        where,
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: limit + 1,
      });
      const page = rows.slice(0, limit).map(toExportRow);
      const last = page[page.length - 1];
      return {
        items: page,
        next:
          rows.length > limit && last
            ? { createdAt: /** @type {Date} */ (last.createdAt), id: last.id }
            : null,
      };
    },

    async softDeleteExport({ tenantId, id, now }) {
      // a queued or running report is not deleted (the worker owns it until it is ready or failed)
      const done = await db.reportExport.updateMany({
        where: { tenantId, id, deletedAt: null, status: { notIn: ACTIVE } },
        data: { deletedAt: now },
      });
      if (done.count === 0) return null;
      const row = await db.reportExport.findFirst({ where: { tenantId, id } });
      return row ? toExportRow(row) : null;
    },
  };
}
