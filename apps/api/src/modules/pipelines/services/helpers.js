import { createHash } from "node:crypto";
import { canonicalJson } from "@qmentisai/shared";

/** SHA-256 over the canonical JSON of `{ schemaVersion, config }` (SPEC §5.7). @param {any} config */
export const hashConfig = (config) =>
  createHash("sha256")
    .update(canonicalJson({ schemaVersion: config.schemaVersion, config }))
    .digest("hex");

/** Deterministic per-trigger offset `hash(triggerId) mod jitterSeconds` (SPEC §5.6). @param {string} triggerId @param {number} jitterSeconds */
export const jitterFor = (triggerId, jitterSeconds) =>
  jitterSeconds > 0
    ? Number.parseInt(createHash("sha256").update(triggerId).digest("hex").slice(0, 8), 16) %
      jitterSeconds
    : 0;

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
