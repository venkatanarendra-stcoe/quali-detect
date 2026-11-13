import { api } from "@/lib/api/index.js";

/** Query key of the signed-in user's preferences (`GET /me/preferences`). */
export const PREFERENCES_KEY = Object.freeze(["account", "preferences"]);

export const preferencesService = {
  /** @returns {Promise<{ accent: string }>} */
  get: ({ signal } = {}) => api.get("/me/preferences", { signal }),
  /** @param {{ accent?: string }} patch @returns {Promise<{ accent: string }>} the stored preferences */
  update: (patch) => api.put("/me/preferences", patch),
};
