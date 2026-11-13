import { z } from "zod";

/**
 * Per-user interface preferences (module `user-preferences`, docs/modules/user-preferences/SPEC.md).
 *
 * Accent: the fixed palette of choosable accent colours. Only the KEYS live here; the colour values per key (light and dark
 * mode) are defined by the UI package. The palette deliberately has no indigo, no black or white and no severity or status
 * colour (critical, high, warning, success, ...), so an accent can never be mistaken for a finding severity or a status.
 */
export const ACCENT_KEYS = Object.freeze([
  "mint",
  "violet",
  "blue",
  "cyan",
  "teal",
  "emerald",
  "amber",
  "orange",
  "rose",
]);

/** The accent every user has until they choose another one (the design system's primary mint). */
export const DEFAULT_ACCENT = "mint";

/** Zod enum of the accent keys. */
export const accentKeySchema = z.enum(ACCENT_KEYS);
