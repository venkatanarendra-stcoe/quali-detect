/**
 * Conditional GET support (RFC 9110 section 13.1.2, weak comparison): whether a request's `If-None-Match` already names the current
 * ETag, so the answer is `304 Not Modified` with no body. Pure. Bounded: a header over 2000 characters or a list over 50 entries is
 * treated as not matching (the full answer is sent), so a hostile header costs nothing.
 *
 * `Cache-Control: no-cache` on the request does NOT prevent a 304: a request that carries a validator IS the revalidation that directive asks
 * for (and `fetch` adds that directive to every conditional request, which is why Express's `req.fresh` never matched in this suite).
 * @param {{ method?: string, headers?: Record<string, string | string[] | undefined> }} request
 * @param {string} etag the current strong ETag, quotes included
 * @returns {boolean}
 */
export function isNotModified(request, etag) {
  if (request?.method !== "GET" && request?.method !== "HEAD") return false;
  const raw = request.headers?.["if-none-match"];
  const header = Array.isArray(raw) ? raw.join(",") : raw;
  if (typeof header !== "string" || header.length === 0 || header.length > 2000) return false;
  const candidates = header.split(",").map((part) => part.trim());
  if (candidates.length > 50) return false;
  if (candidates.includes("*")) return true;
  const strip = (tag) => (tag.startsWith("W/") ? tag.slice(2) : tag);
  return candidates.some((tag) => tag !== "" && strip(tag) === etag);
}
