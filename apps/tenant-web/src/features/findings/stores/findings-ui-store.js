import { create } from "zustand";
import { BULK_MAX } from "../constants/index.js";

/**
 * Client/UI state of the Findings screens only, never server data (SCREENS 1): the list selection (id -> status, at most 50, one
 * workspace at a time), whether the review queue's keyboard shortcuts are on, and the board's "Table" density is the URL's.
 */
export const useFindingsUiStore = create((set, get) => ({
  workspaceId: null,
  /** @type {Record<string, { status: string, title: string }>} finding id -> status and title when it was selected */
  selected: {},
  shortcuts: true,
  /** Selection belongs to one workspace: entering another one clears it. @param {string} workspaceId */
  scope: (workspaceId) => {
    if (get().workspaceId !== workspaceId) set({ workspaceId, selected: {} });
  },
  /** @returns {boolean} false when the 50 cap blocks a new selection */
  toggle: (id, info) => {
    const { selected } = get();
    if (id in selected) {
      const { [id]: _removed, ...rest } = selected;
      set({ selected: rest });
      return true;
    }
    if (Object.keys(selected).length >= BULK_MAX) return false;
    set({ selected: { ...selected, [id]: info } });
    return true;
  },
  clear: () => set({ selected: {} }),
  setShortcuts: (shortcuts) => set({ shortcuts }),
}));
