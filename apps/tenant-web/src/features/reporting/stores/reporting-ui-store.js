import { create } from "zustand";

/**
 * Client and UI state of the reporting screens only, never server data (SCREENS 1): which charts are shown as a table, and which
 * series a person switched off. Nothing is persisted (no data is kept in local storage).
 */
export const useReportingUiStore = create((set, get) => ({
  /** @type {Record<string, boolean>} chart id -> shown as a table */
  tables: {},
  /** @type {Record<string, string[]>} chart id -> series keys switched off */
  hidden: {},
  setTable: (chartId, value) => set({ tables: { ...get().tables, [chartId]: value } }),
  toggleSeries: (chartId, key) => {
    const current = get().hidden[chartId] ?? [];
    set({
      hidden: {
        ...get().hidden,
        [chartId]: current.includes(key) ? current.filter((k) => k !== key) : [...current, key],
      },
    });
  },
}));
