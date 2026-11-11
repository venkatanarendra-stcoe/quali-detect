import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import { safeStorage } from "@/lib/safe-storage.js";

/** UI preferences only: theme (persisted) and the mobile navigation drawer. Server data never lives here. */
export const useUiStore = create()(
  persist(
    (set) => ({
      theme: "system",
      mobileNavOpen: false,
      setTheme: (theme) => set({ theme }),
      setMobileNavOpen: (mobileNavOpen) => set({ mobileNavOpen }),
    }),
    {
      name: "qm-root-ui",
      storage: createJSONStorage(() => safeStorage),
      partialize: (state) => ({ theme: state.theme }),
    },
  ),
);
