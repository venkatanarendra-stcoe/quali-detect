import { api } from "@/lib/api/index.js";

/** Query key of the signed-in user's preferences (`GET /me/preferences`). */
export const PREFERENCES_KEY = Object.freeze(["account", "preferences"]);

export const preferencesService = {
  /** @returns {Promise<{ accent: string, defaultWorkspaceId: string | null }>} */
  get: ({ signal } = {}) => api.get("/me/preferences", { signal }),
  /**
   * @param {{ accent?: string, defaultWorkspaceId?: string | null }} patch
   * @returns {Promise<{ accent: string, defaultWorkspaceId: string | null }>} the stored preferences
   */
  update: (patch) => api.put("/me/preferences", patch),
  /**
   * Where to land after sign-in, decided by the server from the CURRENT permissions (never from this client's cache).
   * @returns {Promise<{ target: "workspace" | "overview" | "none", workspaceId: string | null }>}
   */
  landing: ({ signal } = {}) => api.get("/me/landing", { signal }),
};
