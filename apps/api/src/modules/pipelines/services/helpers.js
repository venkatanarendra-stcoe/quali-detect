import { createHash } from "node:crypto";
import { canonicalJson } from "@qmentisai/shared";

/** SHA-256 over the canonical JSON of `{ schemaVersion, config }` (SPEC §5.7). @param {any} config */
export const hashConfig = (config) =>
  createHash("sha256")
    .update(canonicalJson({ schemaVersion: config.schemaVersion, config }))
    .digest("hex");

/** Case-insensitive uniqueness key of a pipeline name (the database index relies on it). @param {string} name */
export const normalizeName = (name) => name.trim().toLowerCase();

/** Compact identity of a schedule trigger for the `schedule_changed` audit comparison. @param {any} config */
export const scheduleSignature = (config) =>
  canonicalJson(
    (config?.triggers ?? [])
      .filter((t) => t.type === "schedule")
      .map(({ key, enabled, cron, timezone, ref, scanKind, missedPolicy }) => ({
        key,
        enabled,
        cron,
        timezone,
        ref,
        scanKind,
        missedPolicy,
      })),
  );
