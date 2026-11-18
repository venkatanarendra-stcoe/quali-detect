import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import { safeStorage } from "@/lib/safe-storage.js";

/**
 * Browser-only choice for the "Analysis and decision" card of T-29 (SCREENS 1): `open` is `null` until the person chooses
 * (then the default applies: expanded while the execution is preparing or running, collapsed once it has finished),
 * `true`/`false` after. UI state only (never server data, never the URL), kept in this browser.
 */
export const useAnalysisCardStore = create()(
  persist(
    (set) => ({
      open: null,
      setOpen: (open) => set({ open }),
    }),
    {
      name: "qm-analysis-card",
      storage: createJSONStorage(() => safeStorage),
      partialize: (state) => ({ open: state.open }),
    },
  ),
);
