import { api } from "@/lib/api/index.js";

/** `GET /overview`: organization overview data. The API requires the tenant-scope `dashboard.view` (Admin-only by default). */
export const overviewService = {
  get: ({ signal } = {}) => api.get("/overview", { signal }),
};
