import { createHash } from "node:crypto";

/**
 * Canonical JSON: keys sorted at every depth, dates as ISO strings (what `JSON.stringify` does), so equal DTOs give equal text
 * whatever the order the mapper built them in.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === "object")
      return Object.fromEntries(
        Object.keys(v)
          .sort()
          .map((k) => [k, sort(v[k])]),
      );
    return v;
  };
  return JSON.stringify(sort(JSON.parse(JSON.stringify(value ?? null))));
}

/**
 * The weak ETag of a finding detail DTO (SPEC 8.3, D-F4 / S-1 fixed 2026-11-24): `W/"finding-<rev>-<hash>"`, where `<hash>` is the first
 * 32 hex characters of the SHA-256 of the canonical JSON of the WHOLE DTO as the CALLER sees it. The advisory card, the caller's
 * `lifecycle.allowedActions` and the SLA state therefore move the tag even when `rev` does not. It is computed over the caller's own DTO
 * only and sent only to that caller, so it reveals nothing the body does not (no raw value is in the tag; another user's fields never enter
 * it); the `rev` in the tag is the one the body carries. Reads and writes that return the detail share this one function.
 * @param {{ rev: number } & Record<string, unknown>} dto
 * @returns {string}
 */
export const findingEtag = (dto) =>
  `W/"finding-${dto.rev}-${createHash("sha256").update(canonicalJson(dto)).digest("hex").slice(0, 32)}"`;
