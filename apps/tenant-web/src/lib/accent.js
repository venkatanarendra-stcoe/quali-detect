import { ACCENT_KEYS, DEFAULT_ACCENT } from "@qmentisai/shared";
import { safeStorage } from "./safe-storage.js";

/** localStorage key of the last known accent (a per-viewer cache that avoids a flash before the preferences fetch resolves). */
export const ACCENT_CACHE_KEY = "qm-accent";

/** @param {unknown} value @returns {value is string} */
export const isAccentKey = (value) => typeof value === "string" && ACCENT_KEYS.includes(value);

/** The cached accent, or null when absent, invalid or storage is unavailable. */
export function readCachedAccent() {
  const value = safeStorage.getItem(ACCENT_CACHE_KEY);
  return isAccentKey(value) ? value : null;
}

/** Remembers the accent for the next page load (best effort). @param {string} key */
export const writeCachedAccent = (key) => safeStorage.setItem(ACCENT_CACHE_KEY, key);

/** Forgets the cached accent (sign-out). */
export const clearCachedAccent = () => safeStorage.removeItem(ACCENT_CACHE_KEY);

/**
 * Applies an accent by setting `data-accent` on <html>; the colours come from `@qmentisai/ui/accents.css`. Unknown keys fall
 * back to the default (mint). @param {string | null | undefined} key
 */
export function applyAccent(key) {
  document.documentElement.setAttribute("data-accent", isAccentKey(key) ? key : DEFAULT_ACCENT);
}
