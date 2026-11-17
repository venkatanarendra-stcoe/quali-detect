import { ACCENT_KEYS, DEFAULT_ACCENT } from "@qmentisai/shared";

/**
 * Preferences DTO. Never exposes the row (ids, timestamps). A missing row, a null column or a stored value that is no longer
 * in the palette reads as the default.
 * @param {{ accent?: string | null } | null | undefined} row
 * @returns {{ accent: string }}
 */
export const toPreferencesDto = (row) => ({
  accent: ACCENT_KEYS.includes(row?.accent) ? row.accent : DEFAULT_ACCENT,
});
