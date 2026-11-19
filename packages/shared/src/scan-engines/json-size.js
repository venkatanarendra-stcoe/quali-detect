/**
 * The size, in bytes, of the text PostgreSQL prints for a `jsonb` value (`jsonb::text`): `{"a": 1, "b": [1, 2]}`, that is one
 * space after each `:` and each `,`. The database CHECK constraints of the ensemble tables measure `octet_length(col::text)`, so the
 * application measures the same way and a value that passes the application check can never be refused by the database for size
 * (docs/modules/scan-engines/SPEC.md 7.3). Pure; refuses (throws) a value deeper than 32 levels.
 * @param {unknown} value a JSON-compatible value
 * @param {number} [depth]
 * @returns {number}
 */
export function jsonbTextBytes(value, depth = 0) {
  if (depth > 32) throw new RangeError("value too deep");
  if (value === null || value === undefined) return 4;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean")
    return Buffer.byteLength(JSON.stringify(value));
  if (Array.isArray(value)) {
    let total = 2 + 2 * Math.max(value.length - 1, 0);
    for (const item of value) total += jsonbTextBytes(item, depth + 1);
    return total;
  }
  const entries = Object.entries(/** @type {object} */ (value)).filter(([, v]) => v !== undefined);
  let total = 2 + 2 * Math.max(entries.length - 1, 0);
  for (const [k, v] of entries)
    total += Buffer.byteLength(JSON.stringify(k)) + 2 + jsonbTextBytes(v, depth + 1);
  return total;
}
