import { createHash } from "node:crypto";
import { z } from "zod";
import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError, ValidationError } from "../errors/app-error.js";
import { signCursor, verifyCursor } from "./cursor-signing.js";

/**
 * Cursor (keyset) pagination for collection endpoints (docs/technical/API_STANDARDS.md "Cursor pagination").
 *
 * The cursor is OPAQUE to clients: base64url of a binary token `[format][key id][HMAC-SHA256][JSON key values]` (see
 * `cursor-signing.js`). The values are the sort key of the last returned row (one per sort field plus the row id). The MAC is
 * keyed with a purpose-specific subkey of the server secret `CURSOR_SIGNING_SECRET` and covers the format, the key id, the
 * payload AND a binding hash of everything the position depends on (endpoint, scope (tenant or platform principal), sort,
 * filters, parent), which is recomputed from the request, never read from the token. It is a position marker, NOT an
 * authorization token: the tenant, workspace and permission scope are ALWAYS re-applied from the session on every request,
 * so even a valid cursor can only choose where in the caller's own, already-scoped result the page starts. A cursor that
 * does not parse, fails its MAC (tampered, forged, signed with another or a retired key, minted for another endpoint, scope,
 * sort, filter set or parent), or carries values of the wrong type answers 400 `INVALID_CURSOR`.
 *
 * Ordering: every supported sort is made total by appending the row `id` as the last term, so pages never overlap or skip
 * rows, even when rows are inserted while a client pages. Postgres puts NULLs last for `asc` and first for `desc`, which the
 * keyset predicate mirrors.
 */

export const MAX_CURSOR_LENGTH = 1024;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** 400 for a cursor that is malformed, tampered with or minted for another request shape. */
export class InvalidCursorError extends AppError {
  constructor() {
    super(
      ERROR_CODES.INVALID_CURSOR,
      "The cursor is invalid for this request. Start again without a cursor.",
    );
  }
}

/**
 * @typedef {{ type: "string" | "date" | "number" | "enum", nullable?: boolean, values?: readonly string[] }} KeySpec
 * `enum` is a Postgres enum column: it sorts in DECLARATION order (`values` must list it in that order) and Prisma has no
 * range filter for it, so the keyset predicate uses `in` with the values before or after the position.
 * @typedef {{ field: string, direction: "asc" | "desc", type: "string" | "date" | "number" | "uuid" | "enum", nullable: boolean, values?: readonly string[] }} KeyTerm
 */

/** Query keys that choose the page, not the result set. */
const PAGING_KEYS = new Set(["page", "pageSize", "limit", "cursor", "sort"]);

/**
 * Zod shape of the opt-in cursor parameters.
 * @param {number} [maxLimit]
 */
export const cursorQueryShape = (maxLimit = 100) => ({
  cursor: z.string().min(1).max(MAX_CURSOR_LENGTH).optional(),
  limit: z.coerce.number().int().min(1).max(maxLimit).optional(),
});

/**
 * Ordered key terms of a sort: the requested fields, then the unique `id` tie-breaker.
 * @param {Array<{ field: string, direction: "asc" | "desc" }>} sort
 * @param {Record<string, KeySpec>} specs one entry per sortable field
 * @param {"asc" | "desc"} tie direction of the `id` tie-breaker
 * @returns {KeyTerm[]}
 */
export function keyTerms(sort, specs, tie) {
  return [
    ...sort.map(({ field, direction }) => ({
      field,
      direction,
      type: specs[field].type,
      nullable: specs[field].nullable === true,
      ...(specs[field].values ? { values: specs[field].values } : {}),
    })),
    { field: "id", direction: tie, type: "uuid", nullable: false },
  ];
}

/** Prisma `orderBy` of a term list (the sort plus the id tie-breaker). @param {KeyTerm[]} terms */
export const keysetOrderBy = (terms) => terms.map((t) => ({ [t.field]: t.direction }));

const sha = (text) => createHash("sha256").update(text).digest("hex");
const canonical = (value) =>
  JSON.stringify(value, (_key, v) =>
    v && typeof v === "object" && !Array.isArray(v) && !(v instanceof Date)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : 1)))
      : v,
  );

/**
 * Hash of everything a position depends on. `filters` are the validated query parameters that select rows (all but paging
 * and sort), so a cursor cannot be replayed under another filter set, sort, endpoint, scope or parent.
 * @param {{ kind: string, scope: string, query: Record<string, any>, sort: any, terms: KeyTerm[], extra?: Record<string, any> }} input
 */
export function cursorBinding({ kind, scope, query, sort, terms, extra = {} }) {
  const filters = Object.fromEntries(
    Object.entries(query).filter(([key, value]) => !PAGING_KEYS.has(key) && value !== undefined),
  );
  return sha(
    canonical({ kind, scope, sort, filters, extra, shape: terms.map((t) => t.field) }),
  ).slice(0, 24);
}

/**
 * @param {{ binding: string, values: Array<string | number | Date | null> }} input
 * @returns {string} opaque, signed cursor
 */
export function encodeCursor({ binding, values }) {
  return signCursor({ binding, payload: Buffer.from(JSON.stringify(values), "utf8") });
}

function reviveValue(term, raw) {
  if (raw === null) {
    if (!term.nullable) throw new InvalidCursorError();
    return null;
  }
  switch (term.type) {
    case "date": {
      if (typeof raw !== "string" || !ISO_DATE.test(raw)) throw new InvalidCursorError();
      const date = new Date(raw);
      if (Number.isNaN(date.getTime())) throw new InvalidCursorError();
      return date;
    }
    case "number":
      if (typeof raw !== "number" || !Number.isFinite(raw)) throw new InvalidCursorError();
      return raw;
    case "enum":
      if (typeof raw !== "string" || !term.values?.includes(raw)) throw new InvalidCursorError();
      return raw;
    case "uuid":
      if (typeof raw !== "string" || !UUID.test(raw)) throw new InvalidCursorError();
      return raw;
    default:
      if (typeof raw !== "string" || raw.length > 400) throw new InvalidCursorError();
      return raw;
  }
}

/**
 * Parses and verifies a cursor. Throws InvalidCursorError for anything that is not a cursor minted by `encodeCursor` for
 * exactly this binding and key shape.
 * @param {string} token
 * @param {{ binding: string, terms: KeyTerm[] }} expected
 * @returns {Array<string | number | Date | null>} the key values of the last row of the previous page
 */
export function decodeCursor(token, { binding, terms }) {
  if (token.length > MAX_CURSOR_LENGTH || !/^[A-Za-z0-9_-]+$/.test(token))
    throw new InvalidCursorError();
  const payload = verifyCursor({ token, binding });
  let values;
  try {
    values = JSON.parse(payload.toString("utf8"));
  } catch {
    throw new InvalidCursorError();
  }
  if (!Array.isArray(values) || values.length !== terms.length) throw new InvalidCursorError();
  return values.map((raw, index) => reviveValue(terms[index], raw));
}

/**
 * Prisma `where` fragment selecting the rows strictly AFTER the position `values` in the order of `terms`. Combine it with
 * the tenant-scoped base filter (never replace it): `{ ...base, AND: [keysetWhere(...)] }`.
 * @param {KeyTerm[]} terms
 * @param {Array<string | number | Date | null>} values
 */
export function keysetWhere(terms, values) {
  const equal = (term, value) => ({ [term.field]: value });
  const after = (term, value) => {
    const { field, direction, nullable } = term;
    if (value === null) {
      // NULLs sort last ascending (nothing follows them) and first descending (every non-null row follows them).
      return direction === "asc" ? null : { [field]: { not: null } };
    }
    if (term.type === "enum") {
      const at = term.values.indexOf(value);
      const ahead = direction === "asc" ? term.values.slice(at + 1) : term.values.slice(0, at);
      return nullable && direction === "asc"
        ? { OR: [{ [field]: { in: ahead } }, { [field]: null }] }
        : { [field]: { in: ahead } };
    }
    if (direction === "desc") return { [field]: { lt: value } };
    return nullable
      ? { OR: [{ [field]: { gt: value } }, { [field]: null }] }
      : { [field]: { gt: value } };
  };
  const branches = [];
  terms.forEach((term, index) => {
    const here = after(term, values[index]);
    if (!here) return;
    branches.push({
      AND: [...terms.slice(0, index).map((t, i) => equal(t, values[i])), here],
    });
  });
  // No row can follow the position (only possible when every term is an ascending NULL): match nothing.
  return branches.length > 0 ? { OR: branches } : { id: { in: [] } };
}

/** Sort key of a row, in `terms` order (Dates stay Dates; `encodeCursor` serializes them). @param {any} row @param {KeyTerm[]} terms */
export const keyOf = (row, terms) => terms.map((t) => row[t.field] ?? null);

/**
 * In-memory comparison in the order of `terms` (for result sets ordered in memory). Strings use `localeCompare`.
 * @param {KeyTerm[]} terms
 * @param {Array<any>} a
 * @param {Array<any>} b
 */
export function compareKeys(terms, a, b) {
  for (let i = 0; i < terms.length; i += 1) {
    const x = a[i];
    const y = b[i];
    if (x === y) continue;
    if (x === null) return terms[i].direction === "asc" ? 1 : -1;
    if (y === null) return terms[i].direction === "asc" ? -1 : 1;
    const order =
      typeof x === "string"
        ? x.localeCompare(y)
        : x instanceof Date
          ? x.getTime() - y.getTime()
          : x - y;
    if (order !== 0) return terms[i].direction === "desc" ? -order : order;
  }
  return 0;
}

/**
 * Cursor handling of one list request: validates the cursor against the request, and mints the next one. `scope` is
 * `tenant:<tenantId>` for tenant lists and `platform:<platformUserId>` for Root Console lists (never request input).
 * @param {{ kind: string, scope: string, query: Record<string, any>, specs: Record<string, KeySpec>, tie?: "asc" | "desc", terms?: KeyTerm[], extra?: Record<string, any> }} input
 * `terms` replaces the spec-derived terms for lists ordered in memory.
 * @throws {InvalidCursorError | ValidationError}
 */
export function cursorContext({ kind, scope, query, specs, tie = "asc", terms, extra }) {
  const keyTermList = terms ?? keyTerms(query.sort, specs, tie);
  if (query.cursor && query.page > 1)
    throw new ValidationError(
      [{ path: "page", code: "custom", message: "page cannot be combined with cursor." }],
      { source: "querystring" },
    );
  const binding = cursorBinding({
    kind,
    scope,
    query,
    sort: query.sort,
    terms: keyTermList,
    extra,
  });
  const after = query.cursor ? decodeCursor(query.cursor, { binding, terms: keyTermList }) : null;
  return {
    terms: keyTermList,
    after,
    /** Fields to add to the page: `hasMore` and the opaque `nextCursor` (null on the last page). @param {{ hasMore: boolean, nextKey: any[] | null }} page */
    next: (page) => ({
      hasMore: page.hasMore,
      nextCursor:
        page.hasMore && page.nextKey ? encodeCursor({ binding, values: page.nextKey }) : null,
    }),
  };
}

/**
 * One page of a Prisma model in keyset order, plus the filtered total. Offset mode (`after` null) keeps `page`/`pageSize`;
 * cursor mode ignores `page`. One extra row is fetched to learn whether more follow.
 * @param {any} delegate Prisma model delegate (`db.repository`)
 * @param {{ where: Record<string, any>, args?: Record<string, any>, terms: KeyTerm[], after: any[] | null, page: number, pageSize: number, limit?: number }} input
 * `where` MUST already carry the tenant scope.
 */
export async function findKeysetPage(
  delegate,
  { where, args = {}, terms, after, page, pageSize, limit },
) {
  const take = limit ?? pageSize;
  const [rows, totalItems] = await Promise.all([
    delegate.findMany({
      ...args,
      where: after ? { ...where, AND: [keysetWhere(terms, after)] } : where,
      orderBy: keysetOrderBy(terms),
      take: take + 1,
      ...(after ? {} : { skip: (page - 1) * take }),
    }),
    delegate.count({ where }),
  ]);
  const hasMore = rows.length > take;
  const items = hasMore ? rows.slice(0, take) : rows;
  return { items, totalItems, hasMore, nextKey: hasMore ? keyOf(items.at(-1), terms) : null };
}
