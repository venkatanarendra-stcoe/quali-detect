import { Readable } from "node:stream";
import {
  CSV_BOM,
  CSV_EOL,
  REPORT_TEMPLATE_BY_ID,
  csvSafeCell,
  redactCredentialShapes,
} from "@qmentisai/shared";

/**
 * The CSV writer of the exports (docs/modules/reporting-dashboards/SPEC.md 7.3, 12 item 3): RFC 4180 (CRLF, quoted when needed, embedded
 * quotes doubled), UTF-8, an optional byte order mark, a header row taken from the template catalogue, and EVERY cell through the shared
 * `csvSafeCell` (a cell that starts with `=`, `+`, `-`, `@`, tab or carriage return is neutralised with a quote). Text cells also pass the
 * credential redaction once more: ingestion already redacts titles and rules (IN-7), so this is defence in depth for a value that reached a
 * view some other way. It streams: records are pulled one page at a time and written in 64 KiB chunks.
 */

/** Characters per chunk handed to the store. */
const CHUNK_CHARS = 64 * 1024;

/**
 * The columns a template's CSV may carry for this requester (a column with `requiresPermission` is omitted unless the caller held it when
 * the report was requested, O-6). Nothing outside the template's catalogue can ever be a column.
 * @param {string} template
 * @param {{ includeAssignee?: boolean }} [options]
 * @returns {ReadonlyArray<import("@qmentisai/shared").ReportColumn>}
 */
export function csvColumnsFor(template, { includeAssignee = false } = {}) {
  const t = REPORT_TEMPLATE_BY_ID[template];
  if (!t) throw new Error("unknown report template");
  return t.csvColumns.filter((c) => !c.requiresPermission || includeAssignee);
}

/** @param {import("@qmentisai/shared").ReportColumn} column @param {unknown} value */
function cell(column, value) {
  if (column.type === "text" && typeof value === "string")
    return csvSafeCell(redactCredentialShapes(value));
  return csvSafeCell(value);
}

/**
 * A readable stream of the CSV file. `onRow` is called once per data row (the count of the report).
 * @param {{
 *   columns: ReadonlyArray<import("@qmentisai/shared").ReportColumn>,
 *   records: AsyncIterable<Record<string, unknown>>,
 *   bom?: boolean,
 *   onRow?: () => void,
 * }} options `records` map a column `key` to a value; keys outside `columns` are ignored
 * @returns {Readable}
 */
export function createCsvStream({ columns, records, bom = false, onRow }) {
  async function* generate() {
    let buffer = bom ? CSV_BOM : "";
    buffer += columns.map((c) => csvSafeCell(c.header)).join(",") + CSV_EOL;
    for await (const record of records) {
      buffer += columns.map((c) => cell(c, record[c.key])).join(",") + CSV_EOL;
      onRow?.();
      if (buffer.length >= CHUNK_CHARS) {
        yield Buffer.from(buffer, "utf8");
        buffer = "";
      }
    }
    if (buffer.length > 0) yield Buffer.from(buffer, "utf8");
  }
  return Readable.from(generate(), { objectMode: false });
}
