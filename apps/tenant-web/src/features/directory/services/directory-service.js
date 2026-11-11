import { api } from "@/lib/api/index.js";

/** Tenant directory lookups used by pickers. The API requires `user.view`, `role.view` and `group.view` respectively. */
export const directoryService = {
  users: (params, { signal } = {}) => api.getPage("/users", { query: params, signal }),
  groups: (params, { signal } = {}) => api.getPage("/groups", { query: params, signal }),
  roles: (params, { signal } = {}) => api.getPage("/roles", { query: params, signal }),
};
