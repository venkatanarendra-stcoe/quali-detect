import { create } from "zustand";

/**
 * Client/UI state of the execution detail only (never server data): the log "Follow" choice (`null` = default, which is on
 * while the execution is active) and the selected log level. The task filter lives in the URL (`?task=`).
 */
export const useExecutionUiStore = create((set) => ({
  follow: null,
  level: "",
  setFollow: (follow) => set({ follow }),
  setLevel: (level) => set({ level }),
  reset: () => set({ follow: null, level: "" }),
}));
