import { useSyncExternalStore } from "react";

/**
 * Whether a CSS media query matches (the narrow card layouts of SCREENS 4 and 9 swap whole components, which CSS alone cannot).
 * @param {string} query for example `(min-width: 768px)`
 * @param {boolean} [fallback] value on the server or without `matchMedia`
 */
export function useMediaQuery(query, fallback = true) {
  const subscribe = (notify) => {
    const list = globalThis.matchMedia?.(query);
    list?.addEventListener?.("change", notify);
    return () => list?.removeEventListener?.("change", notify);
  };
  return useSyncExternalStore(
    subscribe,
    () => globalThis.matchMedia?.(query).matches ?? fallback,
    () => fallback,
  );
}
