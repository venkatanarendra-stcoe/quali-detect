import { ACCENT_KEYS, DEFAULT_ACCENT } from "@qmentisai/shared";

/**
 * Preferences DTO. Never exposes the row (ids, timestamps). A missing row, a null column or a stored value that is no longer
 * in the palette reads as the default. The stored default workspace is returned only while the caller can still see it
 * (`visibleWorkspaceIds`): a stale pointer reads as null here and is NOT cleared in the database (it applies again if the
 * access comes back), so the response never confirms anything about a workspace the caller cannot see.
 * @param {{ accent?: string | null, defaultWorkspaceId?: string | null } | null | undefined} row
 * @param {ReadonlyArray<string>} [visibleWorkspaceIds]
 * @returns {{ accent: string, defaultWorkspaceId: string | null }}
 */
export const toPreferencesDto = (row, visibleWorkspaceIds = []) => ({
  accent: ACCENT_KEYS.includes(row?.accent) ? row.accent : DEFAULT_ACCENT,
  defaultWorkspaceId:
    row?.defaultWorkspaceId && visibleWorkspaceIds.includes(row.defaultWorkspaceId)
      ? row.defaultWorkspaceId
      : null,
});
