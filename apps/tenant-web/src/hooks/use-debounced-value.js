import { useEffect, useState } from "react";

/** The value after it has stopped changing for `delayMs` (search boxes). @template T @param {T} value @param {number} [delayMs] */
export function useDebouncedValue(value, delayMs = 250) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(id);
  }, [value, delayMs]);
  return debounced;
}
