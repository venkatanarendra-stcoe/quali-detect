import { api } from "@/lib/api/index.js";

/**
 * The tenant reporting time zone (`GET/PUT /reporting/settings`). The tenant is the session's: no tenant id is ever sent. The body is
 * strict, `{ reportingTimezone }` (a canonical IANA name or UTC); a real change is audited and queues a rebuild of the trends on the
 * server, a repeat of the current zone does nothing. A PUT carries an Idempotency-Key so a retry never queues a second rebuild.
 */
export const reportingSettingsService = {
  get: ({ signal } = {}) => api.get("/reporting/settings", { signal }),
  /** @param {{ reportingTimezone: string }} body @param {string} key */
  update: (body, key) =>
    api.put("/reporting/settings", body, { headers: { "Idempotency-Key": key } }),
};
