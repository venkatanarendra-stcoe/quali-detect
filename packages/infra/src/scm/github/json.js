/**
 * GitHub identifiers are 64-bit integers. `JSON.parse` turns any integer above 2^53 into an imprecise Number (for example
 * 3853579981959463001 becomes 3853579981959463000), so an id that is later used as a key or in a URL silently addresses a
 * different object. Everything that parses GitHub JSON (API responses and webhook payloads) therefore quotes the integer
 * values of id-like keys (`id`, `node`-less `*_id`, `*Id`) with 16 or more digits BEFORE parsing; downstream code handles all
 * GitHub ids as strings. Smaller ids stay numbers and are converted with String() at the boundary.
 * @param {string} text
 */
export const quoteBigIds = (text) =>
  text.replace(/("(?:[A-Za-z0-9_]*(?:_id|Id|ID)|id)"\s*:\s*)(\d{16,})/g, '$1"$2"');

/** `JSON.parse` that keeps 64-bit GitHub ids exact (as strings). Throws like JSON.parse on invalid JSON. @param {string} text */
export const parseJsonPreservingIds = (text) => JSON.parse(quoteBigIds(text));
