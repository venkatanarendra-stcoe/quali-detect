import { create } from "zustand";

/**
 * Wizard UI state that is NOT form data: which steps the user has opened (errors of untouched steps stay quiet until
 * Review) and whether a save is in flight (disables the unsaved-changes prompt). Form values live in React Hook Form,
 * the current step in the URL.
 */
export const useWizardStore = create((set) => ({
  visited: {},
  saving: false,
  visit: (step) => set((s) => (s.visited[step] ? s : { visited: { ...s.visited, [step]: true } })),
  setSaving: (saving) => set({ saving }),
  reset: () => set({ visited: {}, saving: false }),
}));
