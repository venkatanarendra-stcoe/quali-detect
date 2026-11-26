/**
 * CSV cell writer of the exports (SPEC 12 item 3). Titles, rule names, repository and pipeline names are attacker influenced (a scanned
 * repository chooses file names and rule messages), so every text cell is neutralised for spreadsheet formula injection: a cell that
 * starts (after any leading white space) with `=`, `+`, `-` or `@`, or with a tab or carriage return, is prefixed with a single quote
 * and quoted; embedded quotes are doubled; control characters (NUL and the C0 range except tab, line feed and carriage return) are
 * removed. Pure; no I/O. Finite numbers and booleans are written as they are; a `Date` as ISO 8601 UTC; null and undefined as an empty
 * cell. A number is never prefixed (`-5` as a number is a number); the same text as a STRING is neutralised.
 */

/** UTF-8 byte order mark (optional, for Excel). */
export const CSV_BOM = "\uFEFF";
/** Record separator (RFC 4180). */
export const CSV_EOL = "\r\n";

// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
const FORMULA_START_RE = /^[\s\u00A0\u200B\uFEFF]*[=+\-@]/;
const NEEDS_QUOTES_RE = /[",\r\n\t]|^\s|\s$/;

/**
 * One CSV cell, safe to write.
 * @param {unknown} value
 * @returns {string} the cell text (quoted when needed), without separators
 */
export function csvSafeCell(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "bigint") return value.toString();
  let text =
    value instanceof Date
      ? Number.isNaN(value.getTime())
        ? ""
        : value.toISOString()
      : String(value);
  text = text.replace(CONTROL_RE, "");
  const first = text.charAt(0);
  const dangerous = first === "\t" || first === "\r" || FORMULA_START_RE.test(text);
  if (dangerous) text = `'${text}`;
  if (dangerous || NEEDS_QUOTES_RE.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

/**
 * One CSV record with its terminator.
 * @param {ReadonlyArray<unknown>} cells @returns {string}
 */
export function csvRow(cells) {
  return cells.map(csvSafeCell).join(",") + CSV_EOL;
}
