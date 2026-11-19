import { createHmac, randomBytes } from "node:crypto";

/**
 * The in-task secret fingerprint (docs/modules/scan-engines/SPEC.md 5.6.4): HMAC-SHA-256 of the value under a key of 32 random
 * bytes generated here, held only in this closure for one task attempt, truncated to 16 bytes (32 hex characters). The key is
 * never stored, logged or transmitted and cannot be read back; the fingerprint is used only to decide a merge inside the task and
 * never reaches a finding (owner decision D-5: nothing derived from a secret is stored in v1).
 * @returns {(value: string) => string}
 */
export function createTaskFingerprinter() {
  const key = randomBytes(32);
  return (value) =>
    createHmac("sha256", key).update(String(value)).digest().subarray(0, 16).toString("hex");
}
