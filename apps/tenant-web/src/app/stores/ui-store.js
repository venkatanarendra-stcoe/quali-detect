import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import { safeStorage } from "@/lib/safe-storage.js";

/**
 * UI preferences only (Zustand holds client state, never server data): theme choice and the mobile navigation drawer.
 * Only `theme` is persisted.
 */
export const useUiStore = create()(
  persist(
    (set) => ({
      theme: "system",
      mobileNavOpen: false,
      setTheme: (theme) => set({ theme }),
      setMobileNavOpen: (mobileNavOpen) => set({ mobileNavOpen }),
    }),
    {
      name: "qm-ui",
      storage: createJSONStorage(() => safeStorage),
      partialize: (state) => ({ theme: state.theme }),
    },
  ),
);
