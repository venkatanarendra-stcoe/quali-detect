/**
 * Bridges the URL sort value (`field:asc|desc`) and the TanStack sorting state used by `DataTable`.
 * @param {string | undefined} sort
 * @returns {Array<{ id: string, desc: boolean }>}
 */
export function sortingFromParam(sort) {
  const [id, dir] = (sort ?? "").split(":");
  return id ? [{ id, desc: dir === "desc" }] : [];
}

/**
 * Next URL sort value from a TanStack sorting updater. Columns use `sortDescFirst: false`; when TanStack would clear the
 * sort (third click) the direction flips back to ascending instead, so a column toggles asc/desc like the old header.
 * @param {Array<{ id: string, desc: boolean }> | ((old: Array<{ id: string, desc: boolean }>) => Array<{ id: string, desc: boolean }>)} updater
 * @param {Array<{ id: string, desc: boolean }>} current
 * @returns {string}
 */
export function sortParamFromUpdater(updater, current) {
  const next = typeof updater === "function" ? updater(current) : updater;
  const entry = next[0] ?? { id: current[0]?.id, desc: false };
  return `${entry.id}:${entry.desc ? "desc" : "asc"}`;
}
